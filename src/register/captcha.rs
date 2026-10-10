//! hCaptcha 处理 (对齐原版 captcha.py): sitekey 网络捕获 + 打码平台 + token 注入。
//!
//! 事件回调全部写静态变量 (注册流程单浏览器串行, 无并发冲突), 避免闭包捕获的生命周期问题。

use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
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
/// 截图模式最近一次的网格参数 [rx, ry, gx, gy, tile] — 点击路线 B 与切图同坐标系
static LAST_GRID: Mutex<Option<[f64; 5]>> = Mutex::new(None);
/// debug 存图只做一次
static DEBUG_SAVED: AtomicBool = AtomicBool::new(false);
static DEBUG_FAIL_SAVED: AtomicBool = AtomicBool::new(false);
/// hCaptcha "Maximum requests" 限流时间戳 (unix ms) — 期间跳过 refresh/checkbox 点击
static RATE_LIMITED: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
/// checkcaptcha 判定嗅探 — Some(true)=答对, Some(false)=答错; take() 读走即清, 提交前手动清防残留误判
static LAST_VERDICT: Mutex<Option<bool>> = Mutex::new(None);
/// drag 同题防刷 — (画布w,h,from,to) 与上次完全一致 = 答错后同题重弹, 再提交只会死循环
static LAST_DRAG: Mutex<Option<((usize, usize, i64, i64, i64, i64), u32)>> = Mutex::new(None);

fn drag_repeat_check(w: usize, h: usize, fx: f64, fy: f64, tx: f64, ty: f64) -> Result<(), String> {
    let key = (w, h, fx as i64, fy as i64, tx as i64, ty as i64);
    let mut slot = LAST_DRAG.lock().unwrap();
    match &mut *slot {
        Some((k, cnt)) if *k == key => {
            *cnt += 1;
            let c = *cnt;
            if c >= 2 {
                *slot = None;
                return Err(format!("drag 同答案第 {} 次出现 (题未变=答错), refresh 换题", c + 1));
            }
            println!("[vision] drag 防刷: 同答案第 2 次求解 (可能重弹), 本轮仍提交");
        }
        _ => {
            *slot = Some((key, 1));
        }
    }
    Ok(())
}

fn rate_limited_until() -> i64 {
    RATE_LIMITED.load(std::sync::atomic::Ordering::Relaxed)
}

fn is_rate_limited() -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    now < rate_limited_until()
}

fn mark_rate_limited(cooldown_ms: i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    RATE_LIMITED.store(now + cooldown_ms, std::sync::atomic::Ordering::Relaxed);
}

fn take_verdict() -> Option<bool> {
    LAST_VERDICT.lock().unwrap().take()
}

fn clear_verdict() {
    *LAST_VERDICT.lock().unwrap() = None;
}

/// 响应体 gzip 透明解压 (魔数 1f 8b) — getcaptcha/checkcaptcha 嗅探共用
fn maybe_gunzip(raw: Vec<u8>) -> Vec<u8> {
    if raw.starts_with(&[0x1f, 0x8b]) {
        use std::io::Read;
        let mut d = flate2::read::GzDecoder::new(&raw[..]);
        let mut out = Vec::new();
        match d.read_to_end(&mut out) {
            Ok(_) => {
                println!("[vision] gzip 解压成功 {}→{}B", raw.len(), out.len());
                out
            }
            Err(e) => {
                println!("[vision] gzip 解压失败: {e}");
                raw
            }
        }
    } else {
        raw
    }
}

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
        // ---- stealth 指纹伪装 (hCaptcha checkbox 无响应的根因修复) ----
        // navigator.webdriver 隐藏 (disable-blink-features 不移除属性本身, 必查项)
        try { Object.defineProperty(navigator, 'webdriver', {get: () => undefined}); } catch (e) {}
        // languages / plugins (0 plugins 是 headless 特征)
        try { Object.defineProperty(navigator, 'languages', {get: () => ['zh-CN', 'zh', 'en-US', 'en']}); } catch (e) {}
        try {
            const fakePlugins = {length: 5, 0: {name: 'Chrome PDF Viewer'}, 1: {name: 'Chromium PDF Viewer'},
                2: {name: 'Native Client'}, 3: {name: 'Chromium PDF Plugin'}, 4: {name: 'Chromium PDF Viewer'},
                item: function(i) { return this[i]; }, namedItem: function(n) { return null; },
                refresh: function() {}};
            Object.defineProperty(navigator, 'plugins', {get: () => fakePlugins});
        } catch (e) {}
        // chrome runtime 对象 (chromium 缺失是可检测特征)
        try {
            window.chrome = window.chrome || {};
            window.chrome.runtime = window.chrome.runtime || {connect: function() {}, sendMessage: function() {}};
            window.chrome.loadTimes = window.chrome.loadTimes || function() { return {}; };
            window.chrome.csi = window.chrome.csi || function() { return {}; };
        } catch (e) {}
        // WebGL vendor/renderer 伪装 (ARM 无 GPU → SwiftShader 是大特征)
        try {
            const fakeVendor = 'Intel Inc.', fakeRenderer = 'Intel Iris OpenGL Engine';
            const wrap = (proto) => {
                const orig = proto.getParameter;
                proto.getParameter = function(p) {
                    if (p === 37445) return fakeVendor;
                    if (p === 37446) return fakeRenderer;
                    return orig.call(this, p);
                };
            };
            if (window.WebGLRenderingContext) wrap(WebGLRenderingContext.prototype);
            if (window.WebGL2RenderingContext) wrap(WebGL2RenderingContext.prototype);
        } catch (e) {}
        // permissions.query 伪装 (notifications 默认 prompt, 自动化常返回 denied)
        try {
            const origQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = function(p) {
                if (p && p.name === 'notifications') {
                    return Promise.resolve({state: Notification.permission, onchange: null});
                }
                return origQuery.call(this, p);
            };
        } catch (e) {}

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
    // 现场诊断: callback 是否调用 / textarea 注入数 — 全 0 说明注入目标缺失 (页面改版/iframe 结构变化)
    match page.evaluate::<Value, String>(&js, None).await {
        Ok(r) => println!("[vision] inject_token: callback|textarea = {r:?}"),
        Err(e) => println!("[vision] inject_token evaluate 失败: {e}"),
    }
    // 等 #register_button enable (最多 20s)
    let btn = page.locator("#register_button");
    for waited in 0..20 {
        if btn.count().await.unwrap_or(0) > 0 && btn.is_enabled().await.unwrap_or(false) {
            println!("[vision] inject_token: register_button 已 enable (第 {}s)", waited + 1);
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    // 20s 未 enable — DOM 现场快照 (按钮在不在/disabled 属性/hcaptcha 隐藏字段)
    let js_probe = r#"(() => JSON.stringify({
        btn: !!document.querySelector('#register_button'),
        btnDisabled: document.querySelector('#register_button')?.disabled,
        hcResp: (document.querySelector('textarea[name=\"h-captcha-response\"]')||{}).value?.length || 0,
        iframes: [...document.querySelectorAll('iframe')].map(f => (f.src||'').slice(0,50)),
    }))()"#;
    match page.evaluate::<Value, Value>(js_probe, None).await {
        Ok(v) => println!("[vision] inject_token: 按钮 20s 未 enable, 现场={v}"),
        Err(e) => println!("[vision] inject_token: 现场探针失败: {e}"),
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
        return JSON.stringify([r.x + (window.scrollX||0), r.y + (window.scrollY||0), r.width, r.height]);
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
            if resp.url().contains("checkcaptcha") {
                // Phase3-D: 判定嗅探 — 答对/答错立即感知, 求解器不空等
                match resp.body().await {
                    Ok(raw) => {
                        let bytes = maybe_gunzip(raw);
                        match serde_json::from_slice::<Value>(&bytes) {
                            Ok(v) => match v["pass"].as_bool() {
                                Some(true) => {
                                    let t = v["generated_pass_UUID"].as_str().unwrap_or("");
                                    println!("[vision] checkcaptcha: 答对 ✓ (token={}…)", &t[..t.len().min(6)]);
                                    *LAST_VERDICT.lock().unwrap() = Some(true);
                                }
                                Some(false) => {
                                    println!("[vision] checkcaptcha: 答错 ✗ — 新题将自动弹出");
                                    *LAST_VERDICT.lock().unwrap() = Some(false);
                                }
                                None => println!(
                                    "[vision] checkcaptcha 无 pass 字段: keys={:?}",
                                    v.as_object().map(|o| o.keys().collect::<Vec<_>>())
                                ),
                            },
                            Err(e) => println!("[vision] checkcaptcha JSON 解析失败: {e}"),
                        }
                    }
                    Err(e) => println!("[vision] checkcaptcha body 读取失败: {e}"),
                }
            } else if resp.url().contains("getcaptcha") {
                let st = resp.status();
                println!("[vision] getcaptcha 响应捕获 status={st}");
                // HTTP 429 限流: Oracle 段实测为 ~60s 分钟级短窗 throttle → 冷却 90s
                // (曾 180s: 比 solve 整体预算还长, 原地等待重试永远轮不到)
                if st == 429 {
                    mark_rate_limited(90_000);
                }
                match resp.body().await {
                    Ok(raw) => {
                        let head: String = raw.iter().take(16).map(|b| format!("{b:02x}")).collect();
                        println!("[vision] getcaptcha body len={} head={head}", raw.len());
                        let bytes: Vec<u8> = maybe_gunzip(raw);
                        match serde_json::from_slice::<Value>(&bytes) {
                            Ok(v) => {
                                let n = v["tasklist"].as_array().map(|a| a.len()).unwrap_or(0);
                                println!("[vision] getcaptcha 解析成功 tasklist={n} prompt={:?}", extract_prompt(&v));
                                *GETCAPTCHA.lock().unwrap() = Some(v);
                            }
                            Err(e) => {
                                // "Maximum requests" = hCaptcha 限流 — 期间点击/refresh 全部无效, 冷却 60s
                                let txt = String::from_utf8_lossy(&bytes);
                                if txt.contains("Maximum requests") {
                                    println!("[vision] hCaptcha 限流 (Maximum requests), 冷却 60s");
                                    mark_rate_limited(60_000);
                                } else {
                                    println!("[vision] getcaptcha JSON 解析失败: {e}");
                                }
                            }
                        }
                    }
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
    // 加密轮: prompt 拿不到 — 复用最近一次明文轮的 prompt
    // (同一挑战的加密/明文轮交替, 题目相同)
    LAST_PROMPT.lock().unwrap().clone().unwrap_or_default()
}

static LAST_PROMPT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// challenge iframe: URL 含 frame=challenge 或 newassets.hcaptcha.com。
/// wait_ms > 0 时轮询等待 — playwright 的 frame 树对动态 cross-origin iframe
/// 同步有延迟 (实测), 一次快照可能拿不到。
async fn find_challenge_frame(page: &playwright_rs::Page) -> Option<playwright_rs::protocol::Frame> {
    find_challenge_frame_wait(page, 0).await
}

async fn find_challenge_frame_wait(
    page: &playwright_rs::Page,
    wait_ms: u64,
) -> Option<playwright_rs::protocol::Frame> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
    loop {
        // 主路径: page.frames() 快照
        if let Ok(frames) = page.frames().await {
            for f in &frames {
                let u = f.url();
                if u.contains("frame=challenge") || u.contains("newassets.hcaptcha.com") {
                    return Some(f.clone());
                }
            }
            // 备用路径: 主 frame 的 child_frames (frame 树的另一条视图)
            if let Some(main) = frames.iter().find(|f| f.parent_frame().is_none()) {
                for cf in main.child_frames() {
                    let u = cf.url();
                    if u.contains("frame=challenge") || u.contains("newassets.hcaptcha.com") {
                        return Some(cf);
                    }
                }
            }
        }
        if wait_ms == 0 || tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
}

/// 下载一张 tile 图 (2 次重试, 浏览器 UA)。
async fn download_tile(client: &reqwest::Client, url: &str, ua: &str) -> Option<Vec<u8>> {
    // 网络抖动常态 (设备 Wi-Fi 波动): 重试 4 次 + 间隔递增
    for attempt in 0..4 {
        match client
            .get(url)
            .header("user-agent", ua)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await
        {
            Ok(resp) => match resp.bytes().await {
                Ok(bytes) if !bytes.is_empty() => return Some(bytes.to_vec()),
                Ok(_) => eprintln!("[tile] 空响应: {url}"),
                Err(e) => eprintln!("[tile] body 失败: {e}: {url}"),
            },
            Err(e) => eprintln!("[tile] 请求失败: {e}: {url}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(500 * (attempt as u64 + 1))).await;
    }
    None
}

/// 取 9 张 tile 图 — 多级来源: tasklist → 全页截图切图 → CSS → 元素截图。
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
    // 实测坑: 新 widget 的 tasklist 可能是类别标签 (gaming/sports=2, drag=1),
    // datapoint_uri ≠ 网格 tile; 只有恰好 9 张才与 3×3 网格一一对应 (animals 9/9 实证)。
    // 误信 2/1 张会让 VLM 看图错位, 且跳过来源1.5 → LAST_GRID 无标定 → 路线B 常量乱点
    if urls.len() != 9 && !urls.is_empty() {
        println!("[vision] tasklist datapoint_uri={} 张 ≠9 (类别标签非网格), 跳过, 走截图切图", urls.len());
    }
    if urls.len() == 9 {
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
        println!("[vision] tasklist 下载失败, 降级");
    }

    // 来源 1.5: 全页截图切 3x3 (不依赖 challenge frame — 加密响应时的主力)
    if let Ok((tiles, grid)) = capture_challenge_tiles(page).await {
        println!("[vision] tile 来源: 页面截图 ({}张)", tiles.len());
        if grid.is_some() {
            *LAST_GRID.lock().unwrap() = grid;
        }
        return Ok(tiles);
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
/// 拖拽题走 drag::solve (canvas CV + 人类化拖拽), 网格题走 CLIP 分类。
/// VLM 截图区域缓存 (拖拽归一化坐标 → 页面坐标换算用)
static VLM_REGION: Mutex<Option<[f64; 4]>> = Mutex::new(None);

fn last_vlm_region() -> ((), [f64; 4]) {
    (
        (),
        VLM_REGION.lock().unwrap().unwrap_or([0.0, 0.0, 480.0, 480.0]),
    )
}

/// 题图采集: tasklist 格图按 prompt 题族存档 (data/train/<slug>/img_<md5>.png)。
/// hCaptcha 题图固定循环 — 攒图后建特征库做格级精确匹配 (人工标注一次, 永久有效)。
fn collect_training(tiles: &[Vec<u8>], prompt: &str, data: &Value) {
    let slug: String = prompt
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase()
        .chars()
        .take(48)
        .collect();
    let dir = std::path::Path::new("data/train").join(&slug);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // prompt 侧元数据 (每族一份)
    let meta = dir.join("_prompt.json");
    if !meta.exists() {
        let _ = std::fs::write(
            &meta,
            serde_json::json!({"prompt": prompt, "requester": data["requester"], "first_seen": ts}).to_string(),
        );
    }
    for (i, t) in tiles.iter().enumerate() {
        // 简易内容指纹 (len + 头尾采样) — 去重用, 避免引入哈希 crate 的名字冲突
        let mut h: u64 = t.len() as u64;
        for chunk in [t.first().copied().unwrap_or(0), t[t.len() / 2], *t.last().unwrap_or(&0)] {
            h = h.wrapping_mul(0x100000001b3).wrapping_add(chunk as u64);
        }
        let path = dir.join(format!("{i:02}_{h:016x}.png"));
        if path.exists() {
            continue;
        }
        let _ = std::fs::write(&path, t);
    }
}

/// point 类 prompt: 单场景点物体 (非格子选择, 答案=物体中心坐标)。
fn is_point_prompt(prompt: &str) -> bool {
    let p = prompt.to_lowercase();
    (p.contains("click the") || p.contains("click on the"))
        && (p.contains("character") || p.contains("object") || p.contains("animal")
            || p.contains("creature") || p.contains("person") || p.contains("one that"))
        && !p.contains("select all") && !p.contains("click all")
}

/// challenge iframe 页面坐标 (轻量, 只跑 rect js 不截图)。
async fn challenge_iframe_rect(page: &playwright_rs::Page) -> Option<[f64; 4]> {
    let js = r#"(() => {
        const fs = [...document.querySelectorAll('iframe')].filter(f => {
            if (!(f.src||'').includes('hcaptcha')) return false;
            const r = f.getBoundingClientRect();
            return r.width > 250 && r.height > 400;
        });
        if (!fs.length) return null;
        let best = fs[0];
        for (const f of fs) { if (f.getBoundingClientRect().width > best.getBoundingClientRect().width) best = f; }
        const r = best.getBoundingClientRect();
        return JSON.stringify([r.x + (window.scrollX||0), r.y + (window.scrollY||0), r.width, r.height]);
    })()"#;
    let v = page.evaluate::<Value, Value>(js, None).await.ok()?;
    let s = v.as_str()?;
    let arr: Vec<f64> = serde_json::from_str(s).ok()?;
    if arr.len() == 4 {
        Some([arr[0], arr[1], arr[2], arr[3]])
    } else {
        None
    }
}

/// VLM 主路径 (gpt-pp-team 第 1 层): 整幅挑战图直出答案。
/// 返回 None = VLM 未配置 (调用方落回 CLIP 启发式)。
async fn vlm_solve_round(
    _page: &playwright_rs::Page,
    _data: &Value,
    _prompt: &str,
) -> Option<Result<(), String>> {
    None
}

async fn inner_vlm_solve(
    page: &playwright_rs::Page,
    data: &Value,
    prompt: &str,
    cfg: &super::vlm::VlmConfig,
) -> Result<(), String> {
    // 取整幅挑战图: tasklist 拼 3x3 → challenge canvas 截图 → 全页裁 iframe
    let ua = page
        .evaluate::<Value, String>("navigator.userAgent", None)
        .await
        .unwrap_or_else(|_| "Mozilla/5.0".into());
    let client = http();
    let urls: Vec<String> = data["tasklist"]
        .as_array()
        .map(|l| {
            l.iter()
                .filter_map(|t| t["datapoint_uri"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let point_mode = is_point_prompt(prompt);
    if point_mode {
        println!("[vision] point 类 prompt: 单图模式 (不拼格子)");
    }

    let mut grid_png: Option<Vec<u8>> = None;
    // tasklist 2-9 张全部下载原图拼动态网格 (明文轮数据完整喂 VLM; 截图轮常是加载中)
    // point 类不拼格子 — 第一张原图即完整场景, 拼了 VLM 会按选格子答必错
    if !point_mode && urls.len() >= 2 && urls.len() <= 9 {
        let mut tiles: Vec<Option<Vec<u8>>> = Vec::new();
        for u in urls.iter().take(9) {
            tiles.push(download_tile(&client, u, &ua).await);
        }
        // 采集放宽: 部分 tile 成功也存档 (网络抖动常态, 9 张全成才采会漏题族);
        // 拼图仍要求全 (VLM 输入需完整网格)
        let got: Vec<(usize, Vec<u8>)> = tiles
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.clone().map(|b| (i, b)))
            .collect();
        if !got.is_empty() {
            let refs: Vec<Vec<u8>> = got.iter().map(|(_, b)| b.clone()).collect();
            collect_training(&refs, prompt, data);
        }
        if tiles.iter().all(|t| t.is_some()) {
            let bytes: Vec<Vec<u8>> = tiles.iter().map(|t| t.clone().unwrap()).collect();
            if let Some(png) = compose_grid_dynamic(&bytes) {
                println!("[vlm] 挑战图来源: tasklist {} 张拼图", bytes.len());
                grid_png = Some(png);
            }
        }
    }
    if grid_png.is_none() {
        if point_mode {
            // point 类: 第一张原图即场景 (datapoint_uri 全图)
            // VLM_REGION 设为挑战图显示区 (iframe rect + 网格偏移), 供 point 坐标换算
            if let Some(u) = urls.first() {
                if let Some(t) = download_tile(&client, u, &ua).await {
                    println!("[vlm] 挑战图来源: point 单原图");
                    if let Some([rx, ry, rw, _rh]) = challenge_iframe_rect(page).await {
                        let tile = (rw - 40.0) / 3.0;
                        *VLM_REGION.lock().unwrap() = Some([rx + 20.0, ry + 90.0, tile * 3.0, tile * 3.0]);
                    }
                    grid_png = Some(t);
                }
            }
        }
    }
    if grid_png.is_none() {
        // canvas / 全页裁剪
        if let Ok((png, rect)) = capture_challenge_full(page).await {
            println!("[vlm] 挑战图来源: 页面截图");
            *VLM_REGION.lock().unwrap() = Some(rect);
            grid_png = Some(png);
        }
    }
    let Some(png) = grid_png else {
        return Err("vlm 取挑战图失败".into());
    };

    // debug: VLM 实际看到的挑战图 (人工核对答题质量)
    let dir = std::path::Path::new("data/debug");
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join("vlm_grid.png");
    match std::fs::write(&path, &png) {
        Ok(()) => println!(
            "[vlm] debug 图已存: {}",
            path.canonicalize().map(|p| p.display().to_string()).unwrap_or_default()
        ),
        Err(e) => println!("[vlm] debug 图写入失败: {e}"),
    }

    // 主路径: 候选框 overlay 模式 (gpt-pp-team 实证: 编号选择比坐标直出准)
    // 3x3 网格天然 9 个候选 (G1-G9 row-major), 480x480 拼图或截图均适用。
    // drag 类画布无网格格子, overlay 编号必点错 (实测 letter 题 overlay 选中
    // [1] 无效点击) → 跳过, 直落 solve_adaptive 的 drag 语义
    let overlay_result = if super::drag::route_drag(prompt).is_some() {
        println!("[vlm] drag 类 prompt, 跳过 overlay → solve_adaptive");
        Ok(None)
    } else {
        try_vlm_overlay(cfg, &png, prompt).await
    };
    match overlay_result {
        Ok(Some(indices)) => {
            if indices.is_empty() {
                return Err("vlm 判定无匹配项".into());
            }
            return click_tiles_and_submit(page, &indices).await;
        }
        Ok(None) => {} // VLM 判非网格题, 落到题型自适应
        Err(e) => println!("[vlm] overlay 模式失败: {e}, 落到题型自适应"),
    }

    match super::vlm::solve_adaptive(cfg, &png, prompt).await? {
        Ok(indices) => {
            if indices.is_empty() {
                return Err("vlm 判定无匹配项".into());
            }
            click_tiles_and_submit(page, &indices).await
        }
        Err(((fx, fy), (tx, ty))) => {
            // 拖拽/点选: 归一化坐标 → 物理坐标
            // VLM 看到的图可能是 tasklist 原图 (宽高不定) 或截图区域 — 统一按 VLM_REGION rect:
            // rect=[x,y,w,h] 是挑战图在页面上的区域, 归一化坐标 × (w,h) + (x,y) 即点击点
            let (_, [rx, ry, rw, rh]) = last_vlm_region();
            let (sx, sy) = (rx + fx * rw.max(1.0), ry + fy * rh.max(1.0));
            let (ex, ey) = (rx + tx * rw.max(1.0), ry + ty * rh.max(1.0));
            // from == to → point 题型 (单场景点物体): 单击目标中心
            if ((sx - ex).abs() + (sy - ey).abs()) < 20.0 {
                println!("[vision] point 题型: 单击 ({sx:.0},{sy:.0}) rect=({rx:.0},{ry:.0},{rw:.0},{rh:.0})");
                return human_click_xy(page, sx, sy).await;
            }
            human_drag(page, sx, sy, ex, ey).await
        }
    }
}

/// 候选框 overlay 求解: 9 个 G 编号候选 → VLM 选 ID → tile indices。
/// Ok(None) = VLM 判定不是网格挑战 (drag 等)。
async fn try_vlm_overlay(
    cfg: &super::vlm::VlmConfig,
    png: &[u8],
    prompt: &str,
) -> Result<Option<Vec<usize>>, String> {
    let img = image::load_from_memory(png)
        .map_err(|e| format!("解码: {e}"))?
        .to_rgb8();
    let (w, h) = (img.width() as f64, img.height() as f64);
    // 动态网格布局 (与 compose_grid_dynamic 同算法): 按宽高比推 cols
    let cols = ((w / h).round() as usize).clamp(1, 3);
    let rows = ((h / 160.0).round() as usize).clamp(1, 3);
    let n = (cols * rows).min(9);
    let mut candidates = Vec::new();
    for idx in 0..n {
        let col = (idx % cols) as f64;
        let row = (idx / cols) as f64;
        candidates.push(super::vlm::CandidateBox {
            id: format!("G{}", idx + 1),
            kind: "grid",
            x: col * w / cols as f64,
            y: row * h / rows as f64,
            w: w / cols as f64,
            h: h / rows as f64,
        });
    }
    let ids = super::vlm::click_decision(cfg, &img, &candidates, prompt, "").await?;
    if ids.is_empty() {
        return Ok(None);
    }
    let mut indices = Vec::new();
    for id in &ids {
        if let Some(num) = id.strip_prefix('G').and_then(|n| n.parse::<usize>().ok()) {
            if (1..=9).contains(&num) {
                indices.push(num - 1);
            }
        }
    }
    println!("[vlm] overlay 模式选中: {indices:?}");
    Ok(Some(indices))
}

/// 2-9 张 tile → 动态网格拼图 (每张 160px; cols=ceil(sqrt(n)))
fn compose_grid_dynamic(tiles: &[Vec<u8>]) -> Option<Vec<u8>> {
    const S: u32 = 160;
    let n = tiles.len();
    if n == 0 || n > 9 {
        return None;
    }
    let cols = (n as f64).sqrt().ceil() as u32;
    let cols = cols.clamp(1, 3);
    let rows = ((n as u32) + cols - 1) / cols;
    let mut canvas = image::RgbImage::new(cols * S, rows * S);
    for (idx, bytes) in tiles.iter().enumerate() {
        let img = image::load_from_memory(bytes).ok()?;
        let resized = img.resize_exact(S, S, image::imageops::FilterType::Lanczos3).to_rgb8();
        let col = ((idx as u32) % cols) * S;
        let row = ((idx as u32) / cols) * S;
        image::imageops::replace(&mut canvas, &resized, col as i64, row as i64);
    }
    let mut buf = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(canvas)
        .write_to(&mut buf, image::ImageFormat::Png)
        .ok()?;
    Some(buf.into_inner())
}

/// 9 张 tile bytes → 3x3 拼图 PNG (每张 160px, 整图 480x480)
fn compose_grid_3x3(tiles: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    const S: u32 = 160;
    let mut canvas = image::RgbImage::new(S * 3, S * 3);
    for (idx, bytes) in tiles.iter().enumerate() {
        let img = image::load_from_memory(bytes).ok()?;
        let resized = img.resize_exact(S, S, image::imageops::FilterType::Lanczos3).to_rgb8();
        let col = (idx % 3) as u32 * S;
        let row = (idx / 3) as u32 * S;
        image::imageops::replace(&mut canvas, &resized, col as i64, row as i64);
    }
    let mut buf = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(canvas)
        .write_to(&mut buf, image::ImageFormat::Png)
        .ok()?;
    Some(buf.into_inner())
}

/// 空图检测 — 全黑/全白截图 (跨域 iframe 合成层丢失) 直接报错
fn raster_is_empty(px: &[u8]) -> bool {
    if px.is_empty() {
        return true;
    }
    let mut sum = 0f64;
    let mut sum2 = 0f64;
    let n = (px.len() / 3) as f64;
    let step = (px.len() / 3 / 500).max(1) * 3;
    let mut cnt = 0f64;
    let mut i = 0;
    while i + 2 < px.len() {
        let g = 0.299 * px[i] as f64 + 0.587 * px[i + 1] as f64 + 0.114 * px[i + 2] as f64;
        sum += g;
        sum2 += g * g;
        cnt += 1.0;
        i += step;
    }
    if cnt < 10.0 {
        return true;
    }
    let mean = sum / cnt;
    let std = ((sum2 / cnt - mean * mean).max(0.0)).sqrt();
    // 均值极端 (全黑<8 或 全白>247) 或方差极低 (纯色) → 空
    mean < 8.0 || mean > 247.0 || std < 3.0
}

/// 采样比较两帧: 差异像素比例 >2% = 画面在动 (加载中/动画)
fn raster_differs(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return true;
    }
    let step = (a.len() / 3 / 400).max(1) * 3;
    let mut diff = 0f64;
    let mut total = 0f64;
    let mut i = 0;
    while i + 2 < a.len() {
        if (a[i] as i32 - b[i] as i32).abs() > 24
            || (a[i + 1] as i32 - b[i + 1] as i32).abs() > 24
            || (a[i + 2] as i32 - b[i + 2] as i32).abs() > 24
        {
            diff += 1.0;
        }
        total += 1.0;
        i += step;
    }
    total > 0.0 && diff / total > 0.02
}

/// 全页截图裁 challenge iframe (返回 PNG bytes + [x,y,w,h]);
/// 全页截图黑层时回退 iframe 元素级截图。
async fn capture_challenge_full(
    page: &playwright_rs::Page,
) -> Result<(Vec<u8>, [f64; 4]), String> {
    let js = r#"(() => {
        const fs = [...document.querySelectorAll('iframe')].filter(f => {
            if (!(f.src||'').includes('hcaptcha')) return false;
            const r = f.getBoundingClientRect();
            return r.width > 250 && r.height > 400;
        });
        if (!fs.length) return null;
        let best = fs[0];
        for (const f of fs) { if (f.getBoundingClientRect().width > best.getBoundingClientRect().width) best = f; }
        const r = best.getBoundingClientRect();
        return JSON.stringify([r.x + (window.scrollX||0), r.y + (window.scrollY||0), r.width, r.height]);
    })()"#;
    let v = page
        .evaluate::<Value, Value>(js, None)
        .await
        .map_err(|e| format!("iframe rect: {e}"))?;
    let s = v.as_str().ok_or("challenge iframe 未找到")?;
    let arr: Vec<f64> = serde_json::from_str(s).map_err(|e| format!("rect: {e}"))?;
    if arr.len() != 4 {
        return Err("rect 不完整".into());
    }
    let (rx, ry, rw, rh) = (arr[0], arr[1], arr[2], arr[3]);

    let crop_from = |png: &[u8]| -> Option<(Vec<u8>, usize, usize)> {
        let (px, pw, ph) = super::drag::decode_png(png).ok()?;
        let img = image::RgbImage::from_raw(pw as u32, ph as u32, px)?;
        let crop = image::imageops::crop_imm(
            &img,
            rx.clamp(0.0, pw as f64 - 1.0) as u32,
            ry.clamp(0.0, ph as f64 - 1.0) as u32,
            rw.min(pw as f64 - rx.max(0.0)) as u32,
            rh.min(ph as f64 - ry.max(0.0)) as u32,
        )
        .to_image();
        let mut buf = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(crop)
            .write_to(&mut buf, image::ImageFormat::Png)
            .ok()?;
        Some((buf.into_inner(), pw, ph))
    };

    // 路径 1: iframe 元素级截图 — E1 中间框干扰 (302x76), 遍历按尺寸过滤
    // width>250 && height>400 才是 challenge 框 (checkbox/E1 均 ~74-76 高)
    // + 帧稳定检测: 连续两帧像素一致才接受 (VLM reasoning 实锤 "加载中状态" 问题)
    let frames = page.locator("iframe[src*='hcaptcha']");
    let count = frames.count().await.unwrap_or(0);
    let mut png_opt: Option<Vec<u8>> = None;
    'outer: for i in 0..count {
        let f = frames.nth(i as i32);
        let Ok(Some(b)) = f.bounding_box().await else {
            continue;
        };
        if b.width <= 250.0 || b.height <= 400.0 {
            continue;
        }
        let mut last: Option<(Vec<u8>, usize, usize)> = None;
        for attempt in 0..5 {
            let Ok(png) = f.screenshot(None).await else {
                break;
            };
            let Ok((px, pw, ph)) = super::drag::decode_png(&png) else {
                break;
            };
            if raster_is_empty(&px) {
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                continue;
            }
            if let Some((lpx, lw, lh)) = &last {
                if lw == &pw && lh == &ph && !raster_differs(lpx, &px) {
                    println!(
                        "[vlm] 元素截图稳定 (第{}次, {}x{}, iframe {i})",
                        attempt + 1,
                        pw,
                        ph
                    );
                    png_opt = Some(png);
                    break 'outer;
                }
            }
            last = Some((px, pw, ph));
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        }
        if png_opt.is_none() {
            println!("[vlm] iframe {i} 画面 5 次尝试未稳定");
        }
    }
    if let Some(png) = png_opt {
        return Ok((png, [rx, ry, rw, rh]));
    }
    println!("[vlm] 元素截图全部失败/空, 回退全页裁剪");

    // 路径 2: 全页截图裁剪 (回退)
    if let Ok(png) = page.screenshot(None).await {
        if let Some((cropped, pw, ph)) = crop_from(&png) {
            let (px, _, _) = super::drag::decode_png(&cropped)?;
            if !raster_is_empty(&px) {
                return Ok((cropped, [rx, ry, rw, rh]));
            }
            println!("[vlm] 全页截图空图 ({pw}x{ph})");
        }
    }
    Err("取挑战图失败 (元素与全页均空/失败)".into())
}

async fn solve_challenge_round(page: &playwright_rs::Page, data: &Value) -> Result<(), String> {
    let mut prompt = extract_prompt(data);
    // 加密轮: getcaptcha JSON 层加密, 但 challenge iframe 顶部渲染给用户的 prompt 文字是明文
    // → playwright frame.evaluate 直接抓 DOM (零成本); canvas 渲染时后续再走 OCR 兜底
    if prompt.is_empty() {
        let js_prompt = r#"(() => {
            const sels = ['.prompt-text', '.challenge-view .prompt-text', '[class*="prompt-text"]'];
            for (const s of sels) {
                for (const el of document.querySelectorAll(s)) {
                    const t = (el.textContent || '').trim();
                    if (t.length > 5) return t;
                }
            }
            return '';
        })()"#;
        if let Some(frame) = find_challenge_frame_wait(page, 2_000).await {
            if let Ok(v) = frame.evaluate::<Value>(js_prompt, None).await {
                if let Some(t) = v.as_str() {
                    if !t.is_empty() && t.len() > 5 {
                        println!("[vision] 加密轮 DOM prompt 抓取成功: {t:?}");
                        prompt = t.to_string();
                        *LAST_PROMPT.lock().unwrap() = Some(prompt.clone());
                    }
                }
            }
        }
    }
    // OCR 兜底 (prompt 为 canvas 渲染或 DOM 抓取失败): 截 .prompt-text 元素 → ddddocr 本地推理 (毫秒级)
    if prompt.is_empty() {
        if let Some(frame) = find_challenge_frame_wait(page, 2_000).await {
            let loc = frame.locator(".prompt-text, [class*='prompt-text']").first();
            match loc.screenshot(None).await {
                Ok(shot) if shot.len() > 200 => {
                    match super::ddddocr::ensure_ocr() {
                        Ok(()) => {
                            let raw = super::ddddocr::recognize(&shot);
                            let norm = super::ddddocr::normalize_prompt(&raw);
                            // 模板匹配优先还原原文 (空格+完整句), 失败用 OCR 原文
                            let final_prompt = super::ddddocr::match_known_prompt(&raw)
                                .or_else(|| super::ddddocr::match_known_prompt(&norm))
                                .unwrap_or(norm);
                            if !final_prompt.is_empty() {
                                println!("[vision] 加密轮 OCR prompt: {final_prompt:?} (raw={raw:?})");
                                prompt = final_prompt;
                            } else {
                                println!("[vision] 加密轮 OCR 无有效结果 (raw={raw:?})");
                            }
                        }
                        Err(e) => println!("[vision] OCR 引擎初始化失败: {e}"),
                    }
                }
                Ok(_) => println!("[vision] 加密轮 prompt 元素截图过小"),
                Err(e) => println!("[vision] 加密轮 prompt 元素截图失败: {e}"),
            }
        }
    }
    if !prompt.is_empty() {
        *LAST_PROMPT.lock().unwrap() = Some(prompt.clone());
    }
    // drag 类 prompt — 截图 CV 求解 (Phase2 拼图/配对算法), 失败回落 VLM, 再 refresh 换题
    if super::drag::route_drag(&prompt).is_some() {
        println!("[vision] drag 类 prompt: 走截图 CV 求解");
        match solve_drag_screenshot(page, &prompt).await {
            Ok(()) => return Ok(()),
            Err(e) => println!("[vision] drag CV 失败: {e}, 回落 VLM"),
        }
        if let Some(cfg) = super::vlm::config() {
            match inner_vlm_solve(page, data, &prompt, &cfg).await {
                Ok(()) => return Ok(()),
                Err(e) => println!("[vision] drag VLM 兜底失败: {e}, refresh 换题"),
            }
        }
        return Err("drag failed, refresh".into());
    }
    // 题库精确匹配优先 — "Select all" 类静态标注题, 全 tile 命中直接用标注答案 (零延迟+确定性)
    if super::feature_lib::static_labelable(&prompt) {
        let urls: Vec<String> = data["tasklist"]
            .as_array()
            .map(|l| {
                l.iter()
                    .filter_map(|t| t["datapoint_uri"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !urls.is_empty() && urls.len() <= 9 {
            let client = http();
            let ua = page
                .evaluate::<Value, String>("navigator.userAgent", None)
                .await
                .unwrap_or_else(|_| "Mozilla/5.0".into());
            let mut tiles = Vec::new();
            let mut all = true;
            for u in &urls {
                match download_tile(&client, u, &ua).await {
                    Some(b) => tiles.push(b),
                    None => {
                        all = false;
                        break;
                    }
                }
            }
            if all {
                if let Some(lib_idx) = super::feature_lib::lookup(&tiles, &prompt) {
                    if let Err(e) = click_tiles_and_submit(page, &lib_idx).await {
                        println!("[lib] 题库答案点击失败: {e}, 落回 VLM");
                    } else {
                        println!("[lib] 题库精确匹配完成 (跳过 VLM)");
                        return Ok(());
                    }
                }
            }
        }
    }
    if prompt.is_empty() {
        // 加密响应轮次: prompt 拿不到, 画面可见 — 默认热食语义组 (最常见题型),
        // 置信度低会走 refresh/多轮, 不至于完全躺平
        println!("[vision] prompt 未知 (加密轮次), 默认 hot_food 语义组");
        prompt = "Select items safe for a hot oven".to_string();
    }
    let type_key = match super::vision::route_type(&prompt) {
        Some(k) => k,
        None => {
            // 题型表未覆盖的新题 (如 "Choose 2 arrows outliers"/circuit-completion) —
            // 回落 VLM 直出 (overlay G1-G9 + adaptive grid/point/drag)。此前这些题
            // 100% unsupported→refresh 空转烧额度; VLM 兜底严格更优 (错则等同现状)。
            if let Some(cfg) = super::vlm::config() {
                println!("[vision] route_type 未命中 → VLM 兜底 (prompt={prompt:?})");
                match inner_vlm_solve(page, data, &prompt, &cfg).await {
                    Ok(()) => return Ok(()),
                    Err(e) => println!("[vision] VLM 兜底失败: {e}"),
                }
            }
            return Err(format!("unsupported prompt: {prompt}"));
        }
    };
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
    click_tiles_and_submit(page, &set).await
}

/// 截图模式取 tile — 嗅探器被封 (加密响应) 时的兜底取图:
/// challenge iframe 在主 DOM 的 light DOM (实测), 拿 bounding rect →
/// Page::screenshot 全页 PNG → 裁 iframe 区域 → 按标准网格布局切 3x3。
/// 坐标系与路线 B (物理点击) 完全一致。
async fn capture_challenge_tiles(
    page: &playwright_rs::Page,
) -> Result<(Vec<(String, Vec<u8>)>, Option<[f64; 5]>), String> {
    let js = r#"(() => {
        const fs = [...document.querySelectorAll('iframe')].filter(f => {
            if (!(f.src||'').includes('hcaptcha')) return false;
            const r = f.getBoundingClientRect();
            // challenge iframe 高度 >400; checkbox 只有 ~74 高
            return r.width > 250 && r.height > 400;
        });
        if (!fs.length) return null;
        let best = fs[0];
        for (const f of fs) { if (f.getBoundingClientRect().width > best.getBoundingClientRect().width) best = f; }
        const r = best.getBoundingClientRect();
        return JSON.stringify([r.x + (window.scrollX||0), r.y + (window.scrollY||0), r.width, r.height]);
    })()"#;
    let v = page
        .evaluate::<Value, Value>(js, None)
        .await
        .map_err(|e| format!("iframe rect: {e}"))?;
    let s = v.as_str().ok_or("challenge iframe 未找到 (截图模式)")?;
    let arr: Vec<f64> = serde_json::from_str(s).map_err(|e| format!("rect 解析: {e}"))?;
    if arr.len() != 4 {
        return Err("rect 数据不完整".into());
    }
    let (rx, ry, rw, rh) = (arr[0], arr[1], arr[2], arr[3]);

    // 慢线路实测: 截图常拍在 tile 未加载完时 — 网格式灰占位块 (亮度恒 128, 03:14 样张 8/9 灰),
    // 检测器拿空图必失败, VLM 拿灰图必乱答。tile 区占位符占比过高就等 1.5s 重拍 (最多 5 次)。
    let (mut cpx, mut cw, mut ch) = (Vec::new(), 0usize, 0usize);
    let mut shot = 0u32;
    loop {
        shot += 1;
        let png = page
            .screenshot(None)
            .await
            .map_err(|e| format!("全页截图: {e}"))?;
        let (px, pw, ph) = super::drag::decode_png(&png)?;
        if shot == 1 {
            println!("[vision] 截图模式: 页面{pw}x{ph} iframe=({rx:.0},{ry:.0} {rw:.0}x{rh:.0})");
        }
        let img = image::RgbImage::from_raw(pw as u32, ph as u32, px).ok_or("页面图重建失败")?;
        // 裁 iframe 区域 (检测与切图都在此坐标系)
        let crop = image::imageops::crop_imm(
            &img,
            rx.clamp(0.0, pw as f64 - 1.0) as u32,
            ry.clamp(0.0, ph as f64 - 1.0) as u32,
            rw.min(pw as f64 - rx.max(0.0)) as u32,
            rh.min(ph as f64 - ry.max(0.0)) as u32,
        )
        .to_image();
        cw = crop.width() as usize;
        ch = crop.height() as usize;
        cpx = crop.into_raw();
        // 占位判定: 底部 45%~90% 带 (tile 区, 避开底部彩条按钮) 中 |亮度-128|<=2 的占比
        let (y0, y1) = (ch * 45 / 100, ch * 90 / 100);
        let (mut total, mut gray) = (0u64, 0u64);
        for y in y0..y1.max(y0) {
            for x in 0..cw {
                let i = (y * cw + x) * 3;
                if i + 2 >= cpx.len() {
                    break;
                }
                let v = (cpx[i] as u16 + cpx[i + 1] as u16 + cpx[i + 2] as u16) / 3;
                total += 1;
                if (v as i32 - 128).abs() <= 2 {
                    gray += 1;
                }
            }
        }
        let pct = if total > 0 { gray * 100 / total } else { 100 };
        if pct < 78 || shot >= 5 {
            println!("[vision] shot#{shot} tile 区灰占位 {pct}%");
            break;
        }
        println!("[vision] tile 未加载完 (灰占位 {pct}%), 等 1.5s 重拍");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    }

    // 自动网格检测 (实测 tile 位置), 失败退回常量猜测
    let (gx, gy, gt, measured) = match super::drag::detect_grid_3x3(&cpx, cw, ch) {
        Some((gx, gy, gt)) => {
            println!("[vision] 网格实测: 起点=({gx:.0},{gy:.0}) tile={gt:.0}px");
            (gx, gy, gt, true)
        }
        None => {
            let g = (rw - 40.0) / 3.0;
            println!("[vision] 网格检测失败, 常量回退 pad=20 top=90 tile={g:.0}");
            (20.0, 90.0, g, false)
        }
    };

    // debug: 每进程存一次 iframe 裁剪原图 + 一张切图, 供人工校准
    if !DEBUG_SAVED.swap(true, Ordering::Relaxed) {
        let dir = std::path::Path::new("data/debug");
        let _ = std::fs::create_dir_all(dir);
        if let Some(im) = image::RgbImage::from_raw(cw as u32, ch as u32, cpx.clone()) {
            let _ = im.save(dir.join("iframe_crop.png"));
            println!("[vision] debug 图已存: data/debug/iframe_crop.png ({}x{})", cw, ch);
        }
    }
    // 只有实测网格才可进 LAST_GRID: 常量回退曾被当作"复用实测网格"跨轮缓存, 永远点同一组错格
    let grid = if measured { Some([rx, ry, gx, gy, gt]) } else { None };

    let crop_img = image::RgbImage::from_raw(cw as u32, ch as u32, cpx).ok_or("裁剪重建失败")?;
    let mut out = Vec::new();
    for idx in 0..9usize {
        let col = (idx % 3) as f64;
        let row = (idx / 3) as f64;
        let x0 = (gx + col * gt).clamp(0.0, cw as f64 - 1.0) as u32;
        let y0 = (gy + row * gt).clamp(0.0, ch as f64 - 1.0) as u32;
        let tw = gt.min(cw as f64 - x0 as f64) as u32;
        let th = gt.min(ch as f64 - y0 as f64) as u32;
        if tw < 10 || th < 10 {
            continue;
        }
        let sub = image::imageops::crop_imm(&crop_img, x0, y0, tw, th).to_image();
        let mut buf = std::io::Cursor::new(Vec::new());
        if sub.write_to(&mut buf, image::ImageFormat::Png).is_ok() {
            out.push((format!("shot-{idx}"), buf.into_inner()));
        }
    }
    if out.is_empty() {
        return Err("截图模式切图失败".into());
    }
    Ok((out, grid))
}

/// 点击 tile + 提交 — 两级路线:
/// A. challenge frame (locator 精确点击)
/// B. frame 树失效时物理坐标: challenge iframe 的 bounding rect + 标准网格布局推算 tile 中心
///    (hCaptcha challenge iframe 内部布局: 左右 padding~20, prompt 高~90, tile 均分剩余宽度)
/// C. 新 widget (e97a50d7+): challenge DOM 疑在嵌套 iframe, 旧选择器全空 (实测 anchor:3 其余 0)。
/// 扫描全部 frame 找大 img 元素, 页内 JS 原生 click() 提交。
async fn try_js_click_new_widget(page: &playwright_rs::Page, set: &[usize]) -> bool {
    let Ok(frames) = page.frames().await else { return false };
    let set_json = serde_json::to_string(set).unwrap_or_else(|_| "[]".into());
    for f in &frames {
        // 仅限 hcaptcha 域 frame — 主页面大 img (banner/产品图) 会误触发
        let url = f.url();
        if !(url.contains("hcaptcha") || url.contains("newassets")) {
            continue;
        }
        let Ok(nv) = f
            .evaluate::<Value>(
                "(() => [...document.querySelectorAll('img')].filter(i => i.offsetWidth > 40 && i.offsetHeight > 40).length)()",
                None,
            )
            .await
        else {
            continue;
        };
        let Some(n) = nv.as_u64() else { continue };
        if n < 2 {
            continue;
        }
        println!("[vision] 路线C 命中 frame: {} imgs={n}", f.url().chars().take(60).collect::<String>());
        let js_click = format!(
            "(() => {{ const g=[...document.querySelectorAll('img')].filter(i => i.offsetWidth > 40 && i.offsetHeight > 40); {set_json}.forEach(i => g[i] && g[i].click()); return g.length }})()"
        );
        match f.evaluate::<Value>(&js_click, None).await {
            Ok(v) => {
                let gi = v.as_u64().unwrap_or(0);
                if let Some(&mx) = set.iter().max() {
                    if (mx as u64) >= gi {
                        println!("[vision] 路线C 索引越界: set={set:?} 但只有 {gi} imgs");
                    }
                }
                println!("[vision] 路线C tile 点击完成 set={set:?} imgs={gi}");
            }
            Err(e) => {
                println!("[vision] 路线C tile 点击失败: {e}");
                continue;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let js_submit = "(() => { const s = document.querySelector('.button-submit, [class*=submit], [class*=arrow]'); if (s) { s.click(); return 1 } const bs=[...document.querySelectorAll('div,button')].filter(b => b.offsetWidth>20&&b.offsetHeight>20&&b.getBoundingClientRect().bottom > window.innerHeight-120); if (bs.length) { bs[bs.length-1].click(); return 2 } return 0 })()";
        match f.evaluate::<Value>(js_submit, None).await {
            Ok(v) => println!("[vision] 路线C submit: {v}"),
            Err(e) => println!("[vision] 路线C submit 失败: {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        return true;
    }
    println!("[vision] 路线C: 无任何 frame 含 >=2 大 img (新 widget 或为 canvas/背景图渲染)");
    false
}

async fn click_tiles_and_submit(page: &playwright_rs::Page, set: &[usize]) -> Result<(), String> {
    if let Some(frame) = find_challenge_frame_wait(page, 5_000).await {
        println!("[vision] 点击路线 A: challenge frame");
        let count = frame.locator(".task-image .image").count().await.unwrap_or(0);
        let sel = if count > 0 { ".task-image .image" } else { ".task-image" };
        let tcount = if count > 0 { count } else { frame.locator(".task-image").count().await.unwrap_or(0) };
        println!("[vision] task-image count={tcount} (sel={sel})");
        if tcount == 0 {
            // widget 改版 (.task-image 不存在, 实测 e97a50d7 版): 探结构 + 回落路线 B
            if let Ok(v) = frame
                .evaluate::<Value>(
                    "(() => { const q=s=>document.querySelectorAll(s).length; return JSON.stringify({task:q('.task-image'),img:q('.image'),canvas:q('canvas'),tile:q('[class*=tile]'),anchor:q('[class*=anchor]'),submit:q('.button-submit'),arrow:q('[class*=submit]')}); })()",
                    None,
                )
                .await
            {
                println!("[vision] widget 结构探针: {v}");
            }
            // 一次性 DOM 地形图: 所有 60-300px 的可见元素 tag.class + 尺寸, 定位真实 tile 选择器
            if let Ok(v) = frame
                .evaluate::<Value>(
                    r#"(() => {
  const out = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width >= 60 && r.width <= 300 && r.height >= 60 && r.height <= 300 && r.y > 0) {
      const cls = (typeof el.className === 'string' ? el.className : '').trim().replace(/\s+/g, '.').slice(0, 40);
      const bg = (getComputedStyle(el).backgroundImage || '').slice(0, 30);
      out.push(el.tagName + '.' + cls + '|' + Math.round(r.width) + 'x' + Math.round(r.height) + '@' + Math.round(r.x) + ',' + Math.round(r.y) + (bg !== 'none' ? '|bg' : ''));
    }
  }
  return out.slice(0, 30).join('\n');
})()"#,
                    None,
                )
                .await
            {
                println!("[vision] DOM 地形图: {v:?}");
            }
            if try_js_click_new_widget(page, set).await {
                return Ok(());
            }
            println!("[vision] .task-image 缺失且路线C未中, 回落路线 B 物理坐标");
        } else {
            // 实测: hCaptcha 九宫格 tile 有 hover 动画, 默认 actionability 检查
            // (元素稳定) 会挂死到 30s 超时烧光求解预算 → force + 短超时
            let click_opts = playwright_rs::protocol::ClickOptions::builder()
                .force(true)
                .timeout(4000.0)
                .build();
            // set 是 tasklist 数组索引, DOM .task-image 顺序与之无一致性保证 —
            // 读 DOM 每格图 URL, 按文件名映射回真实 nth (顺序一致时=恒等)
            let remapped: Vec<usize> = {
                let tl_urls: Vec<String> = GETCAPTCHA.lock().unwrap().as_ref().map(|v| {
                    v["tasklist"].as_array().map(|a| {
                        a.iter().filter_map(|t| t["datapoint_uri"].as_str().map(String::from)).collect()
                    }).unwrap_or_default()
                }).unwrap_or_default();
                let dom_urls: Vec<String> = frame
                    .evaluate::<Value>(
                        r#"(() => [...document.querySelectorAll('.task-image')].map(el => {
  const im = el.tagName === 'IMG' ? el : el.querySelector('img');
  if (im && im.src) return im.src;
  const q = el.querySelector('.image');
  if (q) { const bg = (q.style && q.style.backgroundImage) || getComputedStyle(q).backgroundImage || ''; const m = bg.match(/url\(["']?([^"')]+)["']?\)/); if (m) return m[1]; }
  const bg2 = (el.style && el.style.backgroundImage) || getComputedStyle(el).backgroundImage || '';
  const m2 = bg2.match(/url\(["']?([^"')]+)["']?\)/);
  return m2 ? m2[1] : '';
}))()"#,
                        None,
                    )
                    .await
                    .ok()
                    .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
                    .unwrap_or_default();
                let key = |u: &str| -> String {
                    let u = u.split('?').next().unwrap_or(u);
                    u.rsplit('/').next().unwrap_or("").to_string()
                };
                let mut dom_idx: std::collections::HashMap<String, usize> = Default::default();
                for (d, u) in dom_urls.iter().enumerate() {
                    let k = key(u);
                    if !k.is_empty() {
                        dom_idx.entry(k).or_insert(d);
                    }
                }
                if tl_urls.len() >= set.len().max(1) && !dom_idx.is_empty() {
                    set.iter()
                        .map(|&i| {
                            tl_urls.get(i).and_then(|u| dom_idx.get(&key(u))).copied().unwrap_or(i)
                        })
                        .collect()
                } else {
                    set.to_vec()
                }
            };
            if remapped != set.to_vec() {
                println!("[vision] tile 索引 URL 对齐重映射: {set:?} → {remapped:?}");
            }
            for &i in &remapped {
                if (i as i32) < tcount as i32 {
                    let loc = frame.locator(sel).nth(i as i32);
                    // force 点击不做滚动, widget 高于窗口时报 outside of viewport
                    if let Err(e) = loc.scroll_into_view_if_needed().await {
                        println!("[vision] tile{i} 滚动失败: {e}");
                    }
                    if let Err(e) = loc.click(click_opts.clone()).await {
                        println!("[vision] tile{i} 点击失败: {e}");
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
            let submit = frame.locator(".button-submit");
            let mut submitted = false;
            for _ in 0..10 {
                if submit.count().await.unwrap_or(0) > 0 && submit.is_enabled().await.unwrap_or(false) {
                    let _ = submit.scroll_into_view_if_needed().await;
                    match submit.click(click_opts.clone()).await {
                        Ok(()) => submitted = true,
                        Err(e) => println!("[vision] submit 点击失败: {e}"),
                    }
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
            println!("[vision] submit 已点击: {submitted}");
            if !submitted {
                return Err(".button-submit 未找到或未启用".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
            return Ok(());
        }
    }

    // 路线 B: 物理坐标
    println!("[vision] 点击路线 B: 物理坐标 (frame 树未 attach)");
    // 实测坑: challenge iframe 弹出前停靠在 y=-9999 (不可见), 选中它点击=全打屏幕外
    let js = r#"(() => {
        const fs = [...document.querySelectorAll('iframe')].filter(f => {
            if (!(f.src||'').includes('hcaptcha')) return false;
            const r = f.getBoundingClientRect();
            // challenge iframe 高度 >400; checkbox 仅 ~74 高
            return r.width > 250 && r.height > 400;
        });
        const vis = fs.filter(f => f.getBoundingClientRect().y > -100);
        if (!vis.length) return null;
        let best = vis[0];
        for (const f of vis) { if (f.getBoundingClientRect().width > best.getBoundingClientRect().width) best = f; }
        const r = best.getBoundingClientRect();
        return JSON.stringify([r.x + (window.scrollX||0), r.y + (window.scrollY||0), r.width, r.height]);
    })()"#;
    let mut arr: Option<Vec<f64>> = None;
    for attempt in 0..5 {
        let v = page
            .evaluate::<Value, Value>(js, None)
            .await
            .map_err(|e| format!("iframe rect: {e}"))?;
        if let Some(s) = v.as_str() {
            if let Ok(a) = serde_json::from_str::<Vec<f64>>(s) {
                if a.len() == 4 {
                    arr = Some(a);
                    break;
                }
            }
        }
        println!("[vision] 路线B 可见 challenge iframe 未就绪 (第{}次), 等待弹出", attempt + 1);
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    }
    let arr = arr.ok_or("challenge iframe 未弹出可见区 (路线B)")?;
    let (rx, ry, rw, _rh) = (arr[0], arr[1], arr[2], arr[3]);
    println!("[vision] challenge iframe rect=({rx:.0},{ry:.0} {rw:.0}x{_rh:.0})");
    // 优先用截图模式实测的网格 (同坐标系), 无则常量回退
    let (gx, gy, tile) = match *LAST_GRID.lock().unwrap() {
        Some([lrx, lry, gx, gy, gt]) if (lrx - rx).abs() < 2.0 && (lry - ry).abs() < 2.0 => {
            println!("[vision] 复用实测网格: 起点=({gx:.0},{gy:.0}) tile={gt:.0}");
            (gx, gy, gt)
        }
        _ => {
            let t = (rw - 40.0) / 3.0;
            println!("[vision] 网格缓存不可用, 常量回退 tile={t:.0}");
            (20.0, 90.0, t)
        }
    };
    let mouse = page.mouse();
    for &i in set {
        let col = (i % 3) as f64;
        let row = (i / 3) as f64;
        let x = rx + gx + col * tile + tile / 2.0;
        let y = ry + gy + row * tile + tile / 2.0;
        println!("[vision] 物理 tile{i} @ ({x:.0},{y:.0})");
        let _ = mouse.click(x, y, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    // submit 按钮: iframe 底部中央
    let sy = ry + _rh - 45.0;
    println!("[vision] 物理 submit @ ({:.0},{sy:.0})", rx + rw / 2.0);
    let _ = mouse.click(rx + rw / 2.0, sy, None).await;
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    Ok(())
}

/// 加密轮次的 drag 画布求解: challenge iframe 裁剪图直接喂 pair_drag CV。
/// (加密时 frame 树未 attach 拿不到 canvas 元素, 但 iframe 画面完整可见)
async fn solve_drag_screenshot(page: &playwright_rs::Page, prompt: &str) -> Result<(), String> {
    let js = r#"(() => {
        const fs = [...document.querySelectorAll('iframe')].filter(f => {
            if (!(f.src||'').includes('hcaptcha')) return false;
            const r = f.getBoundingClientRect();
            return r.width > 250 && r.height > 400;
        });
        const vis = fs.filter(f => f.getBoundingClientRect().y > -100);
        if (!vis.length) return null;
        let best = vis[0];
        for (const f of vis) { if (f.getBoundingClientRect().width > best.getBoundingClientRect().width) best = f; }
        const r = best.getBoundingClientRect();
        return JSON.stringify([r.x + (window.scrollX||0), r.y + (window.scrollY||0), r.width, r.height]);
    })()"#;
    let v = page
        .evaluate::<Value, Value>(js, None)
        .await
        .map_err(|e| format!("iframe rect: {e}"))?;
    let s = v.as_str().ok_or("challenge iframe 未找到 (drag截图)")?;
    let arr: Vec<f64> = serde_json::from_str(s).map_err(|e| format!("rect 解析: {e}"))?;
    if arr.len() != 4 {
        return Err("rect 数据不完整".into());
    }
    let (rx, ry, rw, rh) = (arr[0], arr[1], arr[2], arr[3]);

    let png = page
        .screenshot(None)
        .await
        .map_err(|e| format!("全页截图: {e}"))?;
    let (px, pw, ph) = super::drag::decode_png(&png)?;
    let img = image::RgbImage::from_raw(pw as u32, ph as u32, px).ok_or("页面图重建失败")?;
    let crop = image::imageops::crop_imm(
        &img,
        rx.clamp(0.0, pw as f64 - 1.0) as u32,
        ry.clamp(0.0, ph as f64 - 1.0) as u32,
        rw.min(pw as f64 - rx.max(0.0)) as u32,
        rh.min(ph as f64 - ry.max(0.0)) as u32,
    )
    .to_image();
    let (cw, ch) = (crop.width() as usize, crop.height() as usize);
    let cpx = crop.into_raw();
    println!("[vision] drag 截图模式: 画布{}x{}", cw, ch);

    // 按路由分派子算法 (拼图 missing_pieces / 配对 pair_drag / letter_fill)
    let sol = match super::drag::solve(prompt, &cpx, cw, ch) {
        Ok(s) => s,
        Err(e) => {
            // 失败也存一次干净裁剪图 (无标注) — 否则 solve() 提前 return 永远看不到失败现场
            if !DEBUG_FAIL_SAVED.swap(true, Ordering::Relaxed) {
                let dir = std::path::Path::new("data/debug");
                let _ = std::fs::create_dir_all(dir);
                if let Some(v) = image::RgbImage::from_raw(cw as u32, ch as u32, cpx.clone()) {
                    let _ = v.save(dir.join("drag_fail.png"));
                    println!("[vision] drag 失败现场已存: data/debug/drag_fail.png (prompt={prompt:?})");
                }
            }
            return Err(e);
        }
    };
    println!("[vision] drag 截图: from=({:.0},{:.0}) → to=({:.0},{:.0})", sol.from.0, sol.from.1, sol.to.0, sol.to.1);
    drag_repeat_check(cw, ch, sol.from.0, sol.from.1, sol.to.0, sol.to.1)?;

    // debug 标注
    if !DEBUG_SAVED.swap(true, Ordering::Relaxed) {
        let dir = std::path::Path::new("data/debug");
        let _ = std::fs::create_dir_all(dir);
        let mut img2 = cpx.clone();
        let cross = |img: &mut [u8], cx: f64, cy: f64, rgb: [u8; 3]| {
            let (cx, cy) = (cx as isize, cy as isize);
            for d in -12..=12isize {
                for (dx, dy) in [(d, 0isize), (0isize, d)] {
                    let (x, y) = (cx + dx, cy + dy);
                    if x >= 0 && y >= 0 && (x as usize) < cw && (y as usize) < ch {
                        let i = (y as usize * cw + x as usize) * 3;
                        img[i] = rgb[0];
                        img[i + 1] = rgb[1];
                        img[i + 2] = rgb[2];
                    }
                }
            }
        };
        cross(&mut img2, sol.from.0, sol.from.1, [255, 0, 0]);
        cross(&mut img2, sol.to.0, sol.to.1, [0, 100, 255]);
        if let Some(v) = image::RgbImage::from_raw(cw as u32, ch as u32, img2) {
            let _ = v.save(dir.join("drag_screenshot.png"));
            println!("[vision] debug 图已存: data/debug/drag_screenshot.png");
        }
    }

    // 画布内像素 → 页面坐标 (1:1, 截图即 CSS 尺寸)
    human_drag(
        page,
        rx + sol.from.0,
        ry + sol.from.1,
        rx + sol.to.0,
        ry + sol.to.1,
    )
    .await
}

/// 拖拽题: challenge canvas 截图 → CV 求解 → 人类化拖拽手势。
async fn solve_drag_round(page: &playwright_rs::Page, prompt: &str) -> Result<(), String> {
    let frame = find_challenge_frame_wait(page, 10_000)
        .await
        .ok_or("challenge frame not found (等10s)")?;
    let canvas = frame.locator("canvas");
    if canvas.count().await.unwrap_or(0) == 0 {
        return Err("challenge canvas 未找到".into());
    }
    let rect = canvas
        .bounding_box()
        .await
        .map_err(|e| format!("bounding_box: {e}"))?
        .ok_or("canvas 无 bounding box")?;

    let shot = canvas
        .screenshot(None)
        .await
        .map_err(|e| format!("canvas 截图: {e}"))?;
    let (px, pw, ph) = super::drag::decode_png(&shot)?;
    println!("[vision] drag 画布: 截图{pw}x{ph} rect=({:.0},{:.0},{:.0}x{:.0})", rect.x, rect.y, rect.width, rect.height);
    let sol = super::drag::solve(prompt, &px, pw, ph)?;
    drag_repeat_check(pw, ph, sol.from.0, sol.from.1, sol.to.0, sol.to.1)?;

    // debug: 每进程存一次 canvas 原图 + from/to 十字标注
    if !DEBUG_SAVED.swap(true, Ordering::Relaxed) {
        let dir = std::path::Path::new("data/debug");
        let _ = std::fs::create_dir_all(dir);
        let mut img = px.clone();
        let cross = |img: &mut [u8], cx: f64, cy: f64, rgb: [u8; 3]| {
            let (cx, cy) = (cx as isize, cy as isize);
            for d in -12..=12isize {
                for (dx, dy) in [(d, 0isize), (0isize, d)] {
                    let (x, y) = (cx + dx, cy + dy);
                    if x >= 0 && y >= 0 && (x as usize) < pw && (y as usize) < ph {
                        let i = (y as usize * pw + x as usize) * 3;
                        img[i] = rgb[0];
                        img[i + 1] = rgb[1];
                        img[i + 2] = rgb[2];
                    }
                }
            }
        };
        cross(&mut img, sol.from.0, sol.from.1, [255, 0, 0]);
        cross(&mut img, sol.to.0, sol.to.1, [0, 100, 255]);
        if let Some(v) = image::RgbImage::from_raw(pw as u32, ph as u32, img) {
            let _ = v.save(dir.join("drag_canvas.png"));
            println!("[vision] debug 图已存: data/debug/drag_canvas.png (红=from 蓝=to)");
        }
    }

    // 截图像素 → 页面坐标 (等比换算)
    let scale = rect.width / pw as f64;
    let sx = rect.x + sol.from.0 * scale;
    let sy = rect.y + sol.from.1 * scale;
    let ex = rect.x + sol.to.0 * scale;
    let ey = rect.y + sol.to.1 * scale;
    println!("[vision] drag: from=({sx:.0},{sy:.0}) → to=({ex:.0},{ey:.0})");
    human_drag(page, sx, sy, ex, ey).await?;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    Ok(())
}

/// 人类化拖拽手势 (对齐原版 _human_drag: 预悬停 → 按下 → 三段贝塞尔 → 释放)。
/// headless Linux 下 down→move→up 可能挂死 (crate 文档), 每次 move 用 tokio timeout 防护。
async fn safe_mouse_move(
    page: &playwright_rs::Page,
    x: f64,
    y: f64,
    steps: u32,
    hover_ms: u64,
) -> Result<(), String> {
    let opts = playwright_rs::protocol::MouseOptions::builder().steps(steps).build();
    let mouse = page.mouse();
    match tokio::time::timeout(
        std::time::Duration::from_millis(2500),
        mouse.move_to(x, y, Some(opts)),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("mouse move: {e}")),
        Err(_) => println!("[vision] mouse move 超时(挂死防护), 继续"),
    }
    tokio::time::sleep(std::time::Duration::from_millis(hover_ms)).await;
    Ok(())
}

/// 曲线移动 (human_drag 三段贝塞尔的泛化): 两个控制点带随机抖动,
/// 每段独立 steps — 轨迹熵远高于 move_to 的线性插值。
async fn bezier_move(
    page: &playwright_rs::Page,
    sx: f64,
    sy: f64,
    ex: f64,
    ey: f64,
) -> Result<(), String> {
    // 控制点: 垂直于连线的随机偏移 (±30% 距离), 每次曲线不同
    let dx = ex - sx;
    let dy = ey - sy;
    let dist = (dx * dx + dy * dy).sqrt().max(1.0);
    let ox = -dy / dist;
    let oy = dx / dist;
    let w1 = (rand::random::<f64>() - 0.5) * dist * 0.6;
    let w2 = (rand::random::<f64>() - 0.5) * dist * 0.4;
    let (mx1, my1) = (sx + dx * 0.35 + ox * w1, sy + dy * 0.35 + oy * w1);
    let (mx2, my2) = (sx + dx * 0.72 + ox * w2, sy + dy * 0.72 + oy * w2);
    safe_mouse_move(page, mx1, my1, 10, 25).await?;
    safe_mouse_move(page, mx2, my2, 12, 25).await?;
    safe_mouse_move(page, ex, ey, 10, 45).await?;
    Ok(())
}

/// 人类化点击 (公共, flow 表单交互用): bounding_box → 中心随机偏移 →
/// 曲线轨迹移动 → 物理 down/up (isTrusted)。失败回退不动 (调用方自行 locator.click 兜底)。
pub async fn human_click_locator(
    page: &playwright_rs::Page,
    loc: &playwright_rs::protocol::Locator,
) -> Result<(), String> {
    let b = loc
        .bounding_box()
        .await
        .map_err(|e| format!("bounding_box: {e}"))?
        .ok_or("bounding_box None")?;
    // 命中点: 中心区域随机 (30%-70%), 避免每次都正中心
    let cx = b.x + b.width * (0.3 + rand::random::<f64>() * 0.4);
    let cy = b.y + b.height * (0.3 + rand::random::<f64>() * 0.4);
    // 起点: 屏幕边缘一侧随机进入 (每页首次点击的起始位有自然差异)
    let start_x = if rand::random::<bool>() { 8.0 } else { 1270.0 };
    let start_y = 12.0 + rand::random::<f64>() * 80.0;
    safe_mouse_move(page, start_x, start_y, 4, 20).await?;
    bezier_move(page, start_x, start_y, cx, cy).await?;
    let mouse = page.mouse();
    mouse
        .down(None)
        .await
        .map_err(|e| format!("down: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(70 + (rand::random::<f64>() * 60.0) as u64)).await;
    mouse.up(None).await.map_err(|e| format!("up: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(120 + (rand::random::<f64>() * 120.0) as u64)).await;
    Ok(())
}

/// 人类化打字: 键间隔对数正态分布 (快慢混合+偶发思考停顿) + 5% 打错退格重打
/// (均匀随机间隔可被卡方检验识破; fill 是瞬间注入, 无键间隔熵)
pub async fn human_type(
    page: &playwright_rs::Page,
    text: &str,
) -> Result<(), String> {
    let keyboard = page.keyboard();
    // 简易 Box-Muller: 正态随机 → exp() = 对数正态间隔 (中位 75ms, 长尾到 ~400ms)
    let lognormal_ms = || -> u64 {
        let u1 = rand::random::<f64>().max(1e-9);
        let u2 = rand::random::<f64>();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        (75.0 * (0.55 * z).exp()).clamp(28.0, 420.0) as u64
    };
    for ch in text.chars() {
        // 5% 打错: 随机相邻键 → 停顿 → Backspace → 正确字符
        if rand::random::<f64>() < 0.05 {
            let wrong = if ch.is_ascii_alphabetic() {
                ((b'a' + rand::random::<u8>() % 26) as char).to_string()
            } else {
                ((b'0' + rand::random::<u8>() % 10) as char).to_string()
            };
            if keyboard.press(wrong.as_str(), None).await.is_ok() {
                tokio::time::sleep(std::time::Duration::from_millis(180 + lognormal_ms() / 2)).await;
                let _ = keyboard.press("Backspace", None).await;
                tokio::time::sleep(std::time::Duration::from_millis(90 + lognormal_ms() / 3)).await;
            }
        }
        keyboard
            .press(ch.to_string().as_str(), None)
            .await
            .map_err(|e| format!("press: {e}"))?;
        tokio::time::sleep(std::time::Duration::from_millis(lognormal_ms())).await;
        // 3% 概率思考停顿 (300-800ms)
        if rand::random::<f64>() < 0.03 {
            tokio::time::sleep(std::time::Duration::from_millis(300 + (rand::random::<f64>() * 500.0) as u64)).await;
        }
    }
    Ok(())
}

async fn human_drag(
    page: &playwright_rs::Page,
    sx: f64,
    sy: f64,
    ex: f64,
    ey: f64,
) -> Result<(), String> {
    safe_mouse_move(page, sx - 12.0, sy - 8.0, 8, 35).await?;
    safe_mouse_move(page, sx, sy, 6, 60).await?;
    let mouse = page.mouse();
    mouse
        .down(None)
        .await
        .map_err(|e| format!("mouse down: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(90)).await;
    let (mx1, my1) = (sx + (ex - sx) * 0.35, sy + (ey - sy) * 0.18);
    let (mx2, my2) = (sx + (ex - sx) * 0.72, sy + (ey - sy) * 0.82);
    safe_mouse_move(page, mx1, my1, 12, 45).await?;
    safe_mouse_move(page, mx2, my2, 14, 45).await?;
    safe_mouse_move(page, ex, ey, 12, 110).await?;
    mouse
        .up(None)
        .await
        .map_err(|e| format!("mouse up: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(220)).await;
    Ok(())
}

/// 人类化单击 (point 题型: 悬停→按下→抬起, 带 1px 抖动)。
async fn human_click_xy(page: &playwright_rs::Page, x: f64, y: f64) -> Result<(), String> {
    safe_mouse_move(page, x - 8.0, y - 5.0, 7, 40).await?;
    safe_mouse_move(page, x, y, 5, 70).await?;
    let mouse = page.mouse();
    mouse
        .down(None)
        .await
        .map_err(|e| format!("mouse down: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(85)).await;
    mouse
        .up(None)
        .await
        .map_err(|e| format!("mouse up: {e}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(240)).await;
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
    let mut fail_rounds = 0u32;
    let mut rate_waits = 0u32;

    while tokio::time::Instant::now() < deadline {
        // 1. 已有 token 直接返回 (答对后 challenge 关闭, token 落 textarea)
        //    注意: checkbox 点击后 widget 会先写 E1_ 开头的 challenge key (中间值),
        //    真正的 pass token 是 P0_/P1_ 开头的长串 — 只认后者
        if let Ok(frames) = page.frames().await {
            for f in &frames {
                if let Ok(v) = f.evaluate::<Value>(js_token, None).await {
                    if let Some(tok) = v.as_str() {
                        if !tok.is_empty() && !tok.starts_with("E1_") && tok.len() > 50 {
                            println!("[vision] pass token 已出现 (len={}, prefix={})", tok.len(), &tok[..2]);
                            return Ok(tok.to_string());
                        }
                    }
                }
            }
        }

        // 2. 限流冷却期 — 点击/refresh 都无效, 只等 token 或冷却结束
        if is_rate_limited() {
            let remain = (rate_limited_until()
                - std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0))
                / 1000;
            println!("[vision] 限流冷却中, 剩余 {remain}s (跳过点击/refresh)");
            // 澳/巴/韩订阅出口全是 Oracle AS31898, hCaptcha 是对 ASN 的分钟级短窗节流 —
            // 换节点仍是中毒段, 原地等过窗口再点 checkbox 才是正解; 两次等完仍被掐才放弃
            if GETCAPTCHA.lock().unwrap().is_none() {
                rate_waits += 1;
                if rate_waits > 2 {
                    return Err(format!("hcaptcha 限流冷却 (剩余{remain}s), 原地等待{}/2 后仍被掐, 放弃", rate_waits - 1));
                }
                let wait = remain.clamp(3, 100) as u64 + 2;
                println!("[vision] 限流原地等待 {rate_waits}/2: {wait}s 后重点 checkbox…");
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                continue;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        // 3. 无挑战数据 → 点 checkbox 等挑战弹出
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
                    // checkbox 卡死现场截图 (frames() 看不到 iframe 但 DOM 有 — 看渲染真相)
                    if checkbox_ticks == 16 {
                        let shot = page.screenshot(None).await;
                        if let Ok(bytes) = shot {
                            let p = std::path::Path::new("data/debug/checkbox_stuck.png");
                            let _ = std::fs::create_dir_all(p.parent().unwrap());
                            match std::fs::write(p, &bytes) {
                                Ok(_) => println!("[vision] checkbox 卡死截图已存: {} ({}B)", p.display(), bytes.len()),
                                Err(e) => println!("[vision] 截图写入失败: {e}"),
                            }
                        } else if let Err(e) = shot {
                            println!("[vision] 截图失败: {e}");
                        }
                    }
                }
                // 加密响应轮次: 槽空但挑战画面存在 → 截图模式直接分类
                // (prompt 未知, 先用最常见的热食语义组; 置信度低会走 refresh 换题)
                if checkbox_ticks % 3 == 0 {
                    let challenge_visible = page
                        .evaluate::<Value, Value>(
                            r#"(() => {
                        const fs = [...document.querySelectorAll('iframe')].filter(f => (f.src||'').includes('hcaptcha'));
                        // challenge iframe 高度 >400 (checkbox 仅 ~74)
                        return fs.some(f => { const r = f.getBoundingClientRect(); return r.width > 250 && r.height > 400; });
                    })()"#,
                            None,
                        )
                        .await
                        .map(|v| v.as_bool().unwrap_or(false))
                        .unwrap_or(false);
                    if challenge_visible {
                        println!("[vision] 加密轮次检测到挑战画面, 本地链路求解");
                        // 1) ddddocr OCR prompt (DOM 已在 solve_challenge_round 内先抓) → 拿到 prompt 走标准链路
                        match solve_challenge_round(page, &serde_json::json!({"tasklist": []})).await {
                            Ok(()) => {
                                println!("[vision] 加密轮次本地求解完成");
                                tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                                continue;
                            }
                            Err(e) => println!("[vision] 加密轮次标准链路失败: {e}, drag CV 兜底"),
                        }
                        // 2) drag 画布 CV 求解 (prompt 未知, 按画面结构走 pair 路由)
                        match solve_drag_screenshot(page, "Drag the letter to the place where it fits").await {
                            Ok(()) => {
                                println!("[vision] 加密轮次 drag 截图求解完成");
                                tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                            }
                            Err(e) => {
                                println!("[vision] 加密轮次 drag 求解失败: {e}, 回退 3x3 分类");
                                let placeholder = serde_json::json!({"tasklist": []});
                                match solve_challenge_round(page, &placeholder).await {
                                    Ok(()) => println!("[vision] 加密轮次截图求解完成"),
                                    Err(e) => println!("[vision] 加密轮次求解失败: {e}"),
                                }
                            }
                        }
                    }
                }
            }
            // 加密 getcaptcha 体解析失败会让挑战永远弹不出 (checkbox 在但点了没反应)
            // → 定期 reload widget, 重新走一次明文 getcaptcha
            if checkbox_ticks % 20 == 8 {
                println!("[vision] checkbox 长期无响应, 重载 widget 重取 getcaptcha");
                reset_widget(page).await;
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

        clear_verdict();
        match solve_challenge_round(page, &data).await {
            Ok(()) => println!("[vision] 本轮点击+提交完成, 等待结果"),
            Err(e) => {
                println!("[vision] 本轮失败: {e}");
                // unsupported prompt 也要 refresh 换题 — 题型池新题不断出现(VLM 可解),
                // 换题可能换到可解题型, 终止账号 = 白烧一次完整注册流程
                let _ = refresh_challenge(page).await;
                last_fp.clear();
                same_rounds = 0;
                // 失败退避: 连续失败越多等越久 (减少 getcaptcha 请求密度, 防限流)
                fail_rounds += 1;
                let backoff = std::cmp::min(2u64.saturating_pow(fail_rounds.min(5)), 32);
                tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                continue;
            }
        }
        // checkcaptcha 判定轮询 (3s): 答错立即感知 (新题由 hCaptcha 自动弹出, 嗅探器落槽后
        // fingerprint 变化自然重解); 答对等 token; 无判定 (被限流掐掉) 不阻塞原有时序
        for _ in 0..6 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            match take_verdict() {
                Some(false) => {
                    println!("[vision] 判定: 答错 — 清指纹等新题");
                    last_fp.clear();
                    same_rounds = 0;
                    break;
                }
                Some(true) => {
                    println!("[vision] 判定: 答对 — pass token 马上落 textarea");
                    break;
                }
                None => {}
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
