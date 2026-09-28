//! hCaptcha 处理 (对齐原版 captcha.py): sitekey 网络捕获 + 打码平台 + token 注入。
//!
//! 事件回调全部写静态变量 (注册流程单浏览器串行, 无并发冲突), 避免闭包捕获的生命周期问题。

use serde_json::Value;
use std::sync::Mutex;

pub struct SolverConfig {
    pub mode: String, // yescaptcha | captcharun
    pub yescaptcha_key: String,
    pub yescaptcha_url: String,
    pub captcharun_token: String,
    pub captcharun_url: String,
    pub poll_interval_secs: u64,
    pub timeout_secs: u64,
}

fn http() -> reqwest::Client {
    reqwest::Client::new()
}

// ---------------------------------------------------------------------------
// 静态事件槽 (单浏览器串行)
// ---------------------------------------------------------------------------

static SITEKEY: Mutex<Option<String>> = Mutex::new(None);

/// getcaptcha 响应体嗅探槽 — 挑战提示词 + tile 图 URL 全在里面。
static GETCAPTCHA: Mutex<Option<Value>> = Mutex::new(None);
static REGISTER_STATUS: Mutex<Option<u16>> = Mutex::new(None);

pub fn reset_sitekey() {
    *SITEKEY.lock().unwrap() = None;
}

pub fn reset_register_status() {
    *REGISTER_STATUS.lock().unwrap() = None;
}

/// 挂 register 接口响应监听 (点击提交前调用)。
pub async fn watch_register_response(page: &playwright_rs::Page) {
    reset_register_status();
    let _ = page
        .on_response(|resp| async move {
            let url = resp.url().to_string();
            if url.contains("oauth/user/register") {
                let status = resp.status();
                let mut g = REGISTER_STATUS.lock().unwrap();
                if g.is_none() {
                    *g = Some(status);
                }
            }
            Ok(())
        })
        .await;
}

pub async fn wait_register_response(timeout_secs: u64) -> Option<u16> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        if let Some(st) = REGISTER_STATUS.lock().unwrap().clone() {
            return Some(st);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    None
}

/// sitekey 从 checksiteconfig 网络请求 URL 中捕获 (render=explicit 模式 DOM 无 sitekey)。
pub async fn capture_sitekey(page: &playwright_rs::Page) -> Option<String> {
    reset_sitekey();
    let _ = page
        .on_request(|req| async move {
            let url = req.url().to_string();
            if url.contains("checksiteconfig") && url.contains("sitekey=") && SITEKEY.lock().unwrap().is_none() {
                if let Some(idx) = url.find("sitekey=") {
                    let rest = &url[idx + 8..];
                    let sk: String = rest.split('&').next().unwrap_or("").to_string();
                    if !sk.is_empty() {
                        *SITEKEY.lock().unwrap() = Some(sk);
                    }
                }
            }
            Ok(())
        })
        .await;
    // 等待捕获 (hCaptcha iframe 加载可能要几十秒)
    for _ in 0..30 {
        if let Some(sk) = SITEKEY.lock().unwrap().clone() {
            return Some(sk);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    None
}

/// 在 create-account 页加载前注入 hCaptcha 拦截 hook (对齐原版 _ensure_hcaptcha_hook)。
pub async fn ensure_hcaptcha_hook(page: &playwright_rs::Page) {
    const HOOK: &str = r#"(() => {
        window.__hCaptchaInjectedToken = null;
        const suppressWhenInjected = (originalCallback, callbackName) => function(...args) {
            if (window.__hCaptchaInjectedToken) {
                console.debug('[hook] suppressed hCaptcha ' + callbackName);
                return undefined;
            }
            return originalCallback.apply(this, args);
        };
        let _realHcaptcha = null;
        Object.defineProperty(window, 'hcaptcha', {
            configurable: true,
            enumerable: true,
            get() { return _realHcaptcha; },
            set(val) {
                _realHcaptcha = val;
                if (!val) { return; }
                if (typeof val.render === 'function') {
                    const origRender = val.render.bind(val);
                    val.render = function(el, opts) {
                        if (opts && typeof opts.callback === 'function') {
                            window.__hCaptchaCallback = opts.callback;
                        }
                        if (opts && typeof opts['expired-callback'] === 'function') {
                            opts['expired-callback'] = suppressWhenInjected(opts['expired-callback'], 'expired-callback');
                        }
                        if (opts && typeof opts['error-callback'] === 'function') {
                            opts['error-callback'] = suppressWhenInjected(opts['error-callback'], 'error-callback');
                        }
                        if (opts && typeof opts['chalexpired-callback'] === 'function') {
                            opts['chalexpired-callback'] = suppressWhenInjected(opts['chalexpired-callback'], 'chalexpired-callback');
                        }
                        return origRender(el, opts);
                    };
                }
                if (typeof val.getResponse === 'function') {
                    const origGetResponse = val.getResponse.bind(val);
                    val.getResponse = function(...args) {
                        if (window.__hCaptchaInjectedToken) {
                            return window.__hCaptchaInjectedToken;
                        }
                        return origGetResponse(...args);
                    };
                }
            }
        });
    })()"#;
    let _ = page.add_init_script(HOOK).await;
}

/// YesCaptcha: HCaptchaTaskProxyless。
async fn solve_yescaptcha(cfg: &SolverConfig, page_url: &str, site_key: &str) -> Option<String> {
    let client = http();
    let resp = client
        .post(format!("{}/createTask", cfg.yescaptcha_url))
        .json(&serde_json::json!({
            "clientKey": cfg.yescaptcha_key,
            "task": {
                "type": "HCaptchaTaskProxyless",
                "websiteURL": page_url,
                "websiteKey": site_key,
            }
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .ok()?;
    let data: Value = resp.json().await.ok()?;
    if data["errorId"].as_i64().unwrap_or(0) != 0 {
        return None;
    }
    let task_id = data["taskId"].as_str()?.to_string();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(cfg.timeout_secs);
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = client
            .post(format!("{}/getTaskResult", cfg.yescaptcha_url))
            .json(&serde_json::json!({"clientKey": cfg.yescaptcha_key, "taskId": task_id}))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
        {
            if let Ok(data) = resp.json::<Value>().await {
                if data["errorId"].as_i64().unwrap_or(0) != 0 {
                    return None;
                }
                if data["status"].as_str() == Some("ready") {
                    let sol = &data["solution"];
                    let token = sol["gRecaptchaResponse"].as_str().or_else(|| sol["token"].as_str());
                    if let Some(t) = token {
                        return Some(t.to_string());
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(cfg.poll_interval_secs.max(1))).await;
    }
    None
}

/// CaptchaRun: /v2/tasks。
async fn solve_captcharun(cfg: &SolverConfig, page_url: &str, site_key: &str, user_agent: &str) -> Option<String> {
    let client = http();
    let referer = {
        let parts: Vec<&str> = page_url.splitn(3, '/').collect();
        if parts.len() >= 2 {
            format!("{}//{}", parts[0], parts[1])
        } else {
            page_url.to_string()
        }
    };
    let resp = client
        .post(format!("{}/v2/tasks", cfg.captcharun_url))
        .bearer_auth(&cfg.captcharun_token)
        .json(&serde_json::json!({
            "captchaType": "HCaptcha",
            "siteKey": site_key,
            "siteReferer": referer,
            "userAgent": user_agent,
            "fallbackToActualUA": true,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .ok()?;
    let data: Value = resp.json().await.ok()?;
    let task_id = data["taskId"].as_str().map(String::from);
    let token = data["result"]["token"].as_str().map(String::from);
    if let Some(t) = token {
        return Some(t);
    }
    let task_id = task_id?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(cfg.timeout_secs);
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = client
            .get(format!("{}/v2/tasks/{task_id}", cfg.captcharun_url))
            .bearer_auth(&cfg.captcharun_token)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
        {
            if let Ok(data) = resp.json::<Value>().await {
                let status = data["status"].as_str().unwrap_or("").to_lowercase();
                match status.as_str() {
                    "success" => {
                        let token = data["response"]["token"].as_str().or_else(|| data["result"]["token"].as_str());
                        if let Some(t) = token {
                            return Some(t.to_string());
                        }
                        return None;
                    }
                    "fail" => return None,
                    _ => {}
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(cfg.poll_interval_secs.max(1))).await;
    }
    None
}

/// 注入 token 并等 #register_button enable (对齐原版 _inject_hcaptcha_token)。
async fn inject_token(page: &playwright_rs::Page, token: &str) -> bool {
    let js = format!(
        r#"(() => {{
            window.__hCaptchaInjectedToken = {token};
            let textareaCount = 0;
            for (const name of ['h-captcha-response', 'g-recaptcha-response']) {{
                for (const field of document.querySelectorAll(`textarea[name="${{name}}"]`)) {{
                    field.value = window.__hCaptchaInjectedToken;
                    field.dispatchEvent(new Event('input', {{bubbles: true}}));
                    field.dispatchEvent(new Event('change', {{bubbles: true}}));
                    textareaCount += 1;
                }}
            }}
            let callbackInvoked = false;
            if (typeof window.__hCaptchaCallback === 'function') {{
                window.__hCaptchaCallback(window.__hCaptchaInjectedToken);
                callbackInvoked = true;
            }}
            return callbackInvoked + '|' + textareaCount;
        }})()"#,
        token = serde_json::to_string(token).unwrap_or_default()
    );
    let _ = page.evaluate::<Value, String>(&js, None).await;
    // 等 #register_button enable (最多 20s)
    let btn = page.locator("#register_button");
    for _ in 0..20 {
        if btn.count().await.unwrap_or(0) > 0 && btn.is_enabled().await.unwrap_or(false) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    false
}

/// 自动点击 hCaptcha 复选框 — 三级路线。
/// playwright-rs 的 frame 树对动态插入的 cross-origin iframe 不同步 (实测 frames 恒为 1),
/// 因此不能依赖 page.frames() 找 checkbox frame:
/// 1. window.hcaptcha.execute() — hCaptcha 官方 JS API, 程序化触发验证
/// 2. 鼠标物理点击 checkbox iframe 中心 (主 frame DOM 拿 bounding rect)
/// 3. frame 遍历兜底 (iframe 已 attach 的场景)
async fn try_click_hcaptcha_checkbox(page: &playwright_rs::Page) -> bool {
    // 路线 1: hCaptcha JS API
    let js_execute = "(() => { if (window.hcaptcha && typeof hcaptcha.execute === 'function') { try { hcaptcha.execute(); return 'executed'; } catch(e) { return 'err'; } } return 'no-api'; })()";
    if let Ok(v) = page.evaluate::<Value, Value>(js_execute, None).await {
        if v.as_str() == Some("executed") {
            println!("[vision] checkbox: hcaptcha.execute() 触发");
            return true;
        }
    }

    // 路线 2: 鼠标点击 checkbox iframe 中心
    let js_rect = r#"(() => {
        const fs = [...document.querySelectorAll('iframe')].filter(f => (f.src||'').includes('hcaptcha'));
        if (!fs.length) return null;
        // checkbox iframe 通常在前, 且 URL 含 frame=checkbox
        const cb = fs.find(f => (f.src||'').includes('frame=checkbox')) || fs[0];
        const r = cb.getBoundingClientRect();
        if (r.width <= 0) return null;
        return JSON.stringify([r.x, r.y, r.width, r.height]);
    })()"#;
    if let Ok(v) = page.evaluate::<Value, Value>(js_rect, None).await {
        if let Some(s) = v.as_str() {
            if let Ok(arr) = serde_json::from_str::<Vec<f64>>(s) {
                if arr.len() == 4 && arr[2] > 10.0 {
                    let (x, y, w, h) = (arr[0], arr[1], arr[2], arr[3]);
                    let mouse = page.mouse();
                    let opts = playwright_rs::protocol::MouseOptions::default();
                    if mouse.click(x + w / 2.0, y + h / 2.0, Some(opts)).await.is_ok() {
                        println!("[vision] checkbox: 鼠标点击 iframe 中心 ({:.0},{:.0})", x + w / 2.0, y + h / 2.0);
                        return true;
                    }
                }
            }
        }
    }

    // 路线 3: frame 遍历兜底
    if let Ok(frames) = page.frames().await {
        for frame in frames {
            let cb = frame.locator("#checkbox");
            if cb.count().await.unwrap_or(0) > 0 {
                let opts = playwright_rs::protocol::ClickOptions::builder()
                    .timeout(3000.0)
                    .build();
                if cb.click(Some(opts)).await.is_ok() {
                    return true;
                }
            }
        }
    }
    false
}

/// local 模式: 本地浏览器全自动过盾 — 每 6s 一轮 (重置 widget + 点击 checkbox),
/// 跨 frame 轮询响应框 token (hCaptcha 响应在 challenge iframe 内), 全程无人工。
async fn solve_local(page: &playwright_rs::Page, timeout_secs: u64) -> Option<String> {
    let js = "(() => { const t = document.querySelector('textarea[name=\"h-captcha-response\"], [name=\"g-recaptcha-response\"]'); return (t && t.value) ? t.value : ''; })()";
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut round = 0u32;
    while tokio::time::Instant::now() < deadline {
        if let Ok(frames) = page.frames().await {
            for f in frames {
                // Frame::evaluate 固定返回 Value (1 泛型)
                if let Ok(v) = f.evaluate::<Value>(js, None).await {
                    if let Some(tok) = v.as_str() {
                        if !tok.is_empty() {
                            return Some(tok.to_string());
                        }
                    }
                }
            }
        }
        if round % 6 == 0 {
            reset_widget(page).await;
        }
        let _ = try_click_hcaptcha_checkbox(page).await;
        round += 1;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    None
}

/// sidecar 模式: 调本地 CloakBrowser 侧车 (:8877) 求解 hCaptcha。
/// 侧车在反检测浏览器里解挑战拿 token; token 与 sitekey+IP 绑定, 注入本会话即有效。
async fn solve_sidecar(page: &playwright_rs::Page, timeout_secs: u64) -> Result<String, String> {
    let Some(site_key) = capture_sitekey(page).await else {
        return Err("hcaptcha sitekey not captured".into());
    };
    let page_url = page.url();
    let body = serde_json::json!({
        "type": "hcaptcha",
        "sitekey": site_key,
        "url": page_url,
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut last_err = String::from("sidecar 求解超时");
    while tokio::time::Instant::now() < deadline {
        let remaining = (deadline - tokio::time::Instant::now()).as_secs().max(30);
        let resp = http()
            .post("http://127.0.0.1:8877/solve")
            .json(&body)
            // 侧车单次求解实测 ~70-105s, 上限压到 110s 给重试留预算
            .timeout(std::time::Duration::from_secs(remaining.min(110)))
            .send()
            .await;
        match resp {
            Ok(r) => match r.json::<Value>().await {
                Ok(d) => {
                    let tok = d["token"].as_str().unwrap_or("");
                    if !tok.is_empty() {
                        return Ok(tok.to_string());
                    }
                    last_err = format!("sidecar solved=false: {d}");
                }
                Err(e) => last_err = format!("sidecar 响应非 JSON (408/超时?): {e}"),
            },
            Err(e) => {
                last_err = format!("sidecar 请求失败: {e}");
                // 仅连接被拒=侧车真没起; 重置/超时视为瞬时故障继续重试
                if e.is_connect() {
                    return Err(format!("sidecar unreachable (需启动 :8877 侧车): {e}"));
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    Err(last_err)
}

/// 求解 + 注入。返回 token 是否成功生效。
pub async fn solve_and_inject(page: &playwright_rs::Page, cfg: &SolverConfig) -> Result<(), String> {
    if cfg.mode == "onnx" {
        return match solve_onnx(page, 180).await {
            Ok(t) if inject_token(page, &t).await => Ok(()),
            Ok(_) => Err("onnx token injected but register button stayed disabled".into()),
            Err(e) => Err(e),
        };
    }
    if cfg.mode == "sidecar" {
        return match solve_sidecar(page, 180).await {
            Ok(t) if inject_token(page, &t).await => Ok(()),
            Ok(_) => Err("sidecar token injected but register button stayed disabled".into()),
            Err(e) => Err(e),
        };
    }
    if cfg.mode == "local" {
        return match solve_local(page, 180).await {
            Some(t) if inject_token(page, &t).await => Ok(()),
            Some(_) => Err("local token injected but register button stayed disabled".into()),
            None => Err("local 自动过盾超时: hCaptcha 判定环境可疑 (可换打码平台模式)".into()),
        };
    }
    let Some(site_key) = capture_sitekey(page).await else {
        return Err("hcaptcha sitekey not captured".into());
    };
    let page_url = page.url();
    let user_agent = page
        .evaluate::<Value, String>("navigator.userAgent", None)
        .await
        .unwrap_or_default();
    let token = match cfg.mode.as_str() {
        "yescaptcha" => solve_yescaptcha(cfg, &page_url, &site_key).await,
        "captcharun" => solve_captcharun(cfg, &page_url, &site_key, &user_agent).await,
        _ => None,
    };
    let Some(token) = token else {
        return Err(format!("captcha solve failed (mode={})", cfg.mode));
    };
    if inject_token(page, &token).await {
        Ok(())
    } else {
        Err("token injected but register button stayed disabled".into())
    }
}

/// 挂 getcaptcha 响应嗅探 (onnx 模式用) — 挑战数据落 GETCAPTCHA 槽。
async fn watch_getcaptcha(page: &playwright_rs::Page) {
    *GETCAPTCHA.lock().unwrap() = None;
    let _ = page
        .on_response(|resp| async move {
            if resp.url().contains("getcaptcha") {
                println!("[vision] getcaptcha 响应捕获 status={}", resp.status());
                match resp.body().await {
                    Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                        Ok(v) => {
                            let n = v["tasklist"].as_array().map(|a| a.len()).unwrap_or(0);
                            println!("[vision] getcaptcha 解析成功 tasklist={n} prompt={:?}", extract_prompt(&v));
                            *GETCAPTCHA.lock().unwrap() = Some(v);
                        }
                        Err(e) => println!("[vision] getcaptcha JSON 解析失败: {e}"),
                    },
                    Err(e) => println!("[vision] getcaptcha body 读取失败: {e}"),
                }
            }
            Ok(())
        })
        .await;
}

/// 挑战指纹: prompt + 首图 URL 的 sha256 短摘要 (答错刷新后指纹必变)。
fn challenge_fingerprint(data: &Value) -> String {
    use sha2::Digest;
    let prompt = extract_prompt(data);
    let first = data["tasklist"]
        .as_array()
        .and_then(|l| l.first())
        .and_then(|t| t["datapoint_uri"].as_str())
        .unwrap_or("");
    let mut h = sha2::Sha256::new();
    h.update(prompt.as_bytes());
    h.update(first.as_bytes());
    hex::encode(&h.finalize()[..8])
}

/// 从 getcaptcha 响应提取提示词 (requester_question.en 兜底遍历)。
fn extract_prompt(data: &Value) -> String {
    let rq = &data["requester_question"];
    for key in ["en", "en-US", "text"] {
        if let Some(s) = rq[key].as_str() {
            return s.to_string();
        }
    }
    if let Some(s) = rq.as_str() {
        return s.to_string();
    }
    if let Some(m) = rq.as_object() {
        for v in m.values() {
            if let Some(s) = v.as_str() {
                return s.to_string();
            }
        }
    }
    String::new()
}

/// challenge iframe: URL 含 frame=challenge 或 newassets.hcaptcha.com。
async fn find_challenge_frame(page: &playwright_rs::Page) -> Option<playwright_rs::protocol::Frame> {
    let Ok(frames) = page.frames().await else {
        return None;
    };
    for f in frames {
        let u = f.url();
        if u.contains("frame=challenge") || u.contains("newassets.hcaptcha.com") {
            return Some(f);
        }
    }
    None
}

/// 下载一张 tile 图 (2 次重试, 浏览器 UA)。
async fn download_tile(client: &reqwest::Client, url: &str, ua: &str) -> Option<Vec<u8>> {
    for _ in 0..2 {
        if let Ok(resp) = client
            .get(url)
            .header("user-agent", ua)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await
        {
            if let Ok(bytes) = resp.bytes().await {
                if !bytes.is_empty() {
                    return Some(bytes.to_vec());
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    None
}

/// 取 9 张 tile 图 — 三级来源: getcaptcha tasklist → background-image CSS → 元素截图。
async fn fetch_tile_images(
    page: &playwright_rs::Page,
    data: &Value,
    ua: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let client = http();

    // 来源 1: getcaptcha tasklist (全分辨率原图)
    let urls: Vec<String> = data["tasklist"]
        .as_array()
        .map(|l| {
            l.iter()
                .filter_map(|t| t["datapoint_uri"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if !urls.is_empty() {
        let mut out = Vec::new();
        let mut ok = true;
        for (i, u) in urls.iter().enumerate() {
            match download_tile(&client, u, ua).await {
                Some(b) => out.push((format!("tasklist-{i}"), b)),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && !out.is_empty() {
            println!("[vision] tile 来源: getcaptcha tasklist ({}张)", out.len());
            return Ok(out);
        }
        println!("[vision] tasklist 下载失败, 降级 CSS 来源");
    }

    // 来源 2: challenge frame 里 .task-image .image 的 background-image CSS
    if let Some(frame) = find_challenge_frame(page).await {
        let js = r#"(() => {
            const els = document.querySelectorAll('.task-image .image, .task-image');
            const out = [];
            for (const el of els) {
                const bg = (el.style && el.style.backgroundImage) || '';
                const m = bg.match(/url\(["']?([^"')]+)["']?\)/);
                out.push(m ? m[1] : '');
            }
            return JSON.stringify(out);
        })()"#;
        if let Ok(v) = frame.evaluate::<Value>(js, None).await {
            if let Some(s) = v.as_str() {
            if let Ok(list) = serde_json::from_str::<Vec<String>>(s) {
                let mut out = Vec::new();
                let mut ok = true;
                for (i, u) in list.iter().enumerate() {
                    if u.is_empty() {
                        ok = false;
                        break;
                    }
                    match download_tile(&client, u, ua).await {
                        Some(b) => out.push((format!("css-{i}"), b)),
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok && !out.is_empty() {
                    return Ok(out);
                }
            }
            }
        }

        // 来源 3: 逐 tile 元素截图 (最后兜底)
        let sel = if frame.locator(".task-image .image").count().await.unwrap_or(0) > 0 {
            ".task-image .image"
        } else {
            ".task-image"
        };
        let n = frame.locator(sel).count().await.unwrap_or(0);
        if n > 0 {
            let mut out = Vec::new();
            for i in 0..n {
                if let Ok(bytes) = frame.locator(sel).nth(i as i32).screenshot(None).await {
                    out.push((format!("shot-{i}"), bytes));
                }
            }
            if !out.is_empty() {
                return Ok(out);
            }
        }
    }
    Err("tile images unavailable (tasklist/css/screenshot 全失败)".into())
}

/// 处理一轮挑战: 路由题型 → 取图 → 分类 → 点 tile → 提交。
async fn solve_challenge_round(page: &playwright_rs::Page, data: &Value) -> Result<(), String> {
    let prompt = extract_prompt(data);
    let type_key = super::vision::route_type(&prompt)
        .ok_or_else(|| format!("unsupported prompt: {prompt}"))?;
    println!("[vision] 路由题型: {type_key} (prompt={prompt:?})");
    let spec = super::vision::spec_of(type_key).ok_or("spec missing")?;

    let ua = page
        .evaluate::<Value, String>("navigator.userAgent", None)
        .await
        .unwrap_or_else(|_| "Mozilla/5.0".into());
    let tiles = fetch_tile_images(page, data, &ua).await?;
    println!("[vision] tile 图就绪 {} 张 (来源={})", tiles.len(), tiles.first().map(|(n, _)| n.clone()).unwrap_or_default());
    let embeds = super::vision::embed_images(&tiles)?;
    let scores = super::vision::classify(type_key, &embeds)?;
    for (i, s) in scores.iter().enumerate().take(9) {
        println!("[vision] tile{i}: pos={:.3} neg={:.3} margin={:.3}", s.positive_score, s.negative_score, s.margin);
    }
    let sets = super::vision::build_click_sets(&scores, spec.singular, spec.threshold);
    let Some(set) = sets.first() else {
        return Err("no click set generated".into());
    };
    println!("[vision] 点击集1: {set:?} (共{}套候选)", sets.len());

    let frame = find_challenge_frame(page)
        .await
        .ok_or("challenge frame not found")?;
    let count = frame.locator(".task-image .image").count().await.unwrap_or(0);
    let sel = if count > 0 { ".task-image .image" } else { ".task-image" };

    for &i in set {
        if (i as i32) < count as i32 || count == 0 {
            let _ = frame.locator(sel).nth(i as i32).click(None).await;
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    let submit = frame.locator(".button-submit");
    for _ in 0..10 {
        if submit.count().await.unwrap_or(0) > 0 && submit.is_enabled().await.unwrap_or(false) {
            let _ = submit.click(None).await;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    Ok(())
}

/// 解不了时刷新换题 (对齐 Impulse 的 refresh 循环)。
async fn refresh_challenge(page: &playwright_rs::Page) -> bool {
    let Some(frame) = find_challenge_frame(page).await else {
        return false;
    };
    let r = frame.locator(".refresh.button");
    if r.count().await.unwrap_or(0) > 0 {
        return r.click(None).await.is_ok();
    }
    false
}

/// onnx 模式: 本地 CLIP 视觉求解 — 全离线。
/// checkbox 由现有基建点过; 挑战出现后嗅探 getcaptcha → 分类 → 点击循环。
async fn solve_onnx(page: &playwright_rs::Page, timeout_secs: u64) -> Result<String, String> {
    super::vision::ensure_engine()?;
    println!("[vision] 引擎就绪, 挂 getcaptcha 嗅探器");
    watch_getcaptcha(page).await;
    // hCaptcha 资源加载追踪 — 判断 widget 不渲染是脚本未加载还是初始化失败
    let _ = page
        .on_request(|req| async move {
            let u = req.url();
            if u.contains("hcaptcha.com") || u.contains("newassets.hcaptcha") {
                println!("[vision] hcaptcha 请求: {}", &u[..u.len().min(90)]);
            }
            Ok(())
        })
        .await;
    let _ = page
        .on_request_failed(|req| async move {
            let u = req.url();
            if u.contains("hcaptcha") || u.contains("nvgs.nvidia.com") {
                println!("[vision] 请求失败: {}", &u[..u.len().min(90)]);
            }
            Ok(())
        })
        .await;

    let js_token = "(() => { const t = document.querySelector('textarea[name=\"h-captcha-response\"], [name=\"g-recaptcha-response\"]'); return (t && t.value) ? t.value : ''; })()";
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut last_fp = String::new();
    let mut same_rounds = 0u32;
    let mut checkbox_ticks = 0u32;

    while tokio::time::Instant::now() < deadline {
        // 1. 已有 token 直接返回 (答对后 challenge 关闭, token 落 textarea)
        if let Ok(frames) = page.frames().await {
            for f in &frames {
                if let Ok(v) = f.evaluate::<Value>(js_token, None).await {
                    if let Some(tok) = v.as_str() {
                        if !tok.is_empty() {
                            println!("[vision] token 已出现 (len={})", tok.len());
                            return Ok(tok.to_string());
                        }
                    }
                }
            }
        }

        // 2. 无挑战数据 → 点 checkbox 等挑战弹出
        let data = GETCAPTCHA.lock().unwrap().clone();
        let Some(data) = data else {
            checkbox_ticks += 1;
            if checkbox_ticks % 5 == 1 {
                let urls: Vec<String> = page
                    .frames()
                    .await
                    .map(|fs| fs.iter().map(|f| f.url().chars().take(70).collect()).collect())
                    .unwrap_or_default();
                println!("[vision] 无挑战数据, 点 checkbox (第{checkbox_ticks}次, frames={urls:?})");
                if checkbox_ticks % 15 == 1 {
                    // widget 状态深探: 脚本是否加载 / 容器是否存在
                    let js = r#"(() => JSON.stringify({
                        iframes: [...document.querySelectorAll('iframe')].map(f => (f.src||'').slice(0,60)),
                        hcaptchaDivs: document.querySelectorAll('.h-captcha, [data-hcaptcha-widget-id], [class*=hcaptcha]').length,
                        hcaptchaScript: [...document.querySelectorAll('script')].some(s => (s.src||'').includes('hcaptcha')),
                        hasObj: typeof window.hcaptcha,
                        registerBtn: !!document.querySelector('#register_button'),
                        passwordFilled: !!document.querySelector('#registration_password'),
                    }))()"#;
                    if let Ok(v) = page.evaluate::<Value, Value>(js, None).await {
                        println!("[vision] DOM 探针: {v}");
                    }
                }
            }
            try_click_hcaptcha_checkbox(page).await;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        };

        // 3. 指纹去重 — 同一挑战不重复处理; 卡 15s 无变化则 refresh 换题
        let fp = challenge_fingerprint(&data);
        if fp == last_fp {
            same_rounds += 1;
            if same_rounds >= 15 {
                refresh_challenge(page).await;
                last_fp.clear();
                same_rounds = 0;
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
            continue;
        }
        last_fp = fp;
        same_rounds = 0;

        match solve_challenge_round(page, &data).await {
            Ok(()) => println!("[vision] 本轮点击+提交完成, 等待结果"),
            Err(e) => {
                println!("[vision] 本轮失败: {e}");
                let _ = refresh_challenge(page).await;
                last_fp.clear();
                same_rounds = 0;
                // 单轮失败不放弃 — 刷新后继续尝试 (180s 预算内)
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err("onnx 求解超时".into())
}

/// 重置上次注入 (对齐原版 _reset_hcaptcha_widget)。
pub async fn reset_widget(page: &playwright_rs::Page) {
    let _ = page
        .evaluate::<Value, Value>(
            "(() => { window.__hCaptchaInjectedToken = null; if (window.hcaptcha && typeof window.hcaptcha.reset === 'function') { try { window.hcaptcha.reset(); } catch(_) {} } return null; })()",
            None,
        )
        .await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
}
