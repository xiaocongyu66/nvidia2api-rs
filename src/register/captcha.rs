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

/// 求解 + 注入。返回 token 是否成功生效。
pub async fn solve_and_inject(page: &playwright_rs::Page, cfg: &SolverConfig) -> Result<(), String> {
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
