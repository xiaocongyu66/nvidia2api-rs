//! 注册浏览器流程 (对齐原版 main.py register_account + finalize_and_create_key)。

use super::captcha::{self, SolverConfig};
use super::email::{CloudflareTempEmail, DuckMail, Inbox};
use playwright_rs::{AriaRole, GetByRoleOptions, Playwright};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct FlowConfig {
    pub headless: bool,
    pub org_name: String,
    pub key_name: String,
    pub key_expiry: String,
    pub email_provider: String,
    pub cf_api_url: String,
    pub cf_admin_auth: String,
    pub cf_domain: String,
    pub duck_api_url: String,
    pub duck_domain: String,
    pub duck_api_key: String,
    pub solver: SolverConfig,
}

fn now() -> std::time::Instant {
    std::time::Instant::now()
}

type LogFn = Arc<dyn Fn(String) + Send + Sync>;

fn log(s: &LogFn, msg: &str) {
    s(msg.to_string());
}

/// 点击按可访问名匹配的按钮 (依次尝试)。
async fn click_by_names(
    page: &playwright_rs::Page,
    names: &[&str],
    timeout_ms: u64,
) -> Option<String> {
    for name in names {
        let btn = page.get_by_role(
            AriaRole::Button,
            Some(GetByRoleOptions::default().name(*name)),
        );
        let _ = btn.wait_for(None).await; // visible 默认
        for _ in 0..(timeout_ms / 500).max(1) {
            if btn.count().await.unwrap_or(0) > 0 && btn.is_enabled().await.unwrap_or(false) {
                if btn.click(None).await.is_ok() {
                    return Some((*name).to_string());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    None
}

/// 单账号完整注册流程。成功返回 nvapi- key。
pub async fn register_one(
    cfg: &FlowConfig,
    logf: LogFn,
    stop: Arc<AtomicBool>,
) -> Result<(String, String), String> {
    log(&logf, "[1] 创建临时邮箱…");
    let inbox: Inbox = match cfg.email_provider.as_str() {
        "duckmail" => {
            let dm = DuckMail {
                api_url: cfg.duck_api_url.clone(),
                domain: cfg.duck_domain.clone(),
                api_key: cfg.duck_api_key.clone(),
            };
            dm.create_inbox(&format!("nv{}", super::rand_hex(8))).await?
        }
        _ => {
            let cf = CloudflareTempEmail {
                api_url: cfg.cf_api_url.clone(),
                admin_auth: cfg.cf_admin_auth.clone(),
                domain: cfg.cf_domain.clone(),
            };
            cf.create_inbox(&format!("nv{}", super::rand_hex(8))).await?
        }
    };
    let email = inbox.address.clone();
    log(&logf, &format!("[1] 邮箱: {email}"));
    let password = super::rand_password(12);

    let pw = Playwright::launch().await.map_err(|e| format!("playwright launch: {e}"))?;
    let browser = pw
        .chromium()
        .launch_with_options(
            playwright_rs::LaunchOptions::new()
                .headless(cfg.headless)
                .args(vec![
                    "--no-sandbox".into(),
                    "--disable-blink-features=AutomationControlled".into(),
                ]),
        )
        .await
        .map_err(|e| format!("chromium launch: {e}"))?;
    let page = browser.new_page().await.map_err(|e| format!("new_page: {e}"))?;

    let result: Result<String, String> = async {
        // [2] build.nvidia.com
        log(&logf, "[2] 打开 build.nvidia.com…");
        let _ = page.goto("https://build.nvidia.com/", None).await;
        let cookie = page.locator("#onetrust-accept-btn-handler");
        if cookie.count().await.unwrap_or(0) > 0 {
            let _ = cookie.click(None).await;
        }
        if stop.load(Ordering::Relaxed) {
            return Err("stopped".into());
        }

        // [3] 打开登录弹窗
        log(&logf, "[3] 打开 signin 弹窗…");
        let login = page.get_by_role(AriaRole::Button, Some(GetByRoleOptions::default().name("Login")));
        if login.count().await.unwrap_or(0) > 0 {
            let _ = login.first().click(None).await;
        }
        // 等弹窗自动刷新稳定 (原版: 等第二个弹窗)
        let email_input = page.locator("input[name=\"email\"]");
        let deadline = now() + std::time::Duration::from_secs(15);
        while now() < deadline {
            if email_input.count().await.unwrap_or(0) >= 1 {
                tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        if email_input.count().await.unwrap_or(0) == 0 {
            return Err("email input not found".into());
        }

        // [4] 提交邮箱 → Next
        log(&logf, "[4] 提交邮箱…");
        captcha::ensure_hcaptcha_hook(&page).await;
        let email_input = page.locator("input[name=\"email\"]").first();
        let _ = email_input.click(None).await;
        let _ = email_input.press_sequentially(&email, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        if click_by_names(&page, &["Next"], 5000).await.is_none() {
            return Err("Next button not clickable".into());
        }
        let _ = page
            .wait_for_url("**/login.nvgs.nvidia.com/**", None)
            .await;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // [5] 填密码
        log(&logf, "[5] 填写密码…");
        let pw_field = page.locator("#registration_password");
        let deadline = now() + std::time::Duration::from_secs(30);
        let mut appeared = false;
        while now() < deadline {
            if pw_field.count().await.unwrap_or(0) > 0 {
                appeared = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        if !appeared {
            return Err("password field never appeared".into());
        }
        let _ = pw_field.fill(&password, None).await;
        let _ = page.locator("#registration_passwordConfirm").fill(&password, None).await;

        // [6] hCaptcha + 提交 (最多 3 次重试, 监听 register 响应)
        let mut accepted = false;
        for attempt in 1..=3 {
            if stop.load(Ordering::Relaxed) {
                return Err("stopped".into());
            }
            if attempt > 1 {
                log(&logf, &format!("[6] 重新求解 hCaptcha (第 {attempt}/3 次)…"));
                captcha::reset_widget(&page).await;
            }
            if let Err(e) = captcha::solve_and_inject(&page, &cfg.solver).await {
                log(&logf, &format!("[6] captcha: {e}"));
                continue;
            }
            // 挂响应监听再点击
            captcha::watch_register_response(&page).await;
            let btn = page.locator("#register_button");
            let mut clicked = false;
            for _ in 0..30 {
                if btn.count().await.unwrap_or(0) > 0 && btn.is_enabled().await.unwrap_or(false) {
                    if btn.click(None).await.is_ok() {
                        clicked = true;
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            if !clicked {
                log(&logf, "[6] #register_button not clickable");
                continue;
            }
            log(&logf, "[6] 已提交注册, 等待响应…");
            let st = captcha::wait_register_response(45).await.unwrap_or(0);
            if (200..300).contains(&st) {
                log(&logf, &format!("[6] register accepted ({st})"));
                accepted = true;
                break;
            }
            if st == 409 {
                return Err("email already registered".into());
            }
            log(&logf, &format!("[6] register rejected ({st}), 重试…"));
        }
        if !accepted {
            return Err("register submit failed after 3 attempts".into());
        }

        // [7] 邮箱验证码 (重试 3 次)
        log(&logf, "[7] 等待验证码邮件…");
        let mut code = poll_code(cfg, &inbox, 180).await;
        let mut ok_code = false;
        for attempt in 1..=3 {
            let Some(c) = code.clone() else {
                log(&logf, "[7] 未收到验证码");
                return Err("no verification code".into());
            };
            if attempt > 1 {
                log(&logf, &format!("[7] 请求新验证码 (第 {attempt}/3 次)…"));
                let link_texts = ["请求新验证码", "重新请求新验证码", "request new code", "resend code"];
                let mut clicked = false;
                for t in link_texts {
                    let link = page.get_by_text(t, false).first();
                    if link.count().await.unwrap_or(0) > 0 {
                        let _ = link.click(None).await;
                        clicked = true;
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        break;
                    }
                }
                if !clicked {
                    return Err("cannot request new code".into());
                }
                code = poll_code(cfg, &inbox, 60).await;
                let Some(c) = code.clone() else {
                    return Err("no new code".into());
                };
                log(&logf, &format!("[7] 新验证码: {c}"));
                let _ = c;
            }
            let c = code.clone().unwrap();
            // 等 6 个数字输入框
            let inputs = page.locator("input[type=\"number\"]");
            let deadline = now() + std::time::Duration::from_secs(45);
            let mut ready = false;
            while now() < deadline {
                if inputs.count().await.unwrap_or(0) >= 6 {
                    ready = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            if !ready {
                return Err("verification inputs not detected".into());
            }
            // 逐位真实键盘输入
            for (i, digit) in c.chars().take(6).enumerate() {
                let _ = inputs.nth(i as i32).click(None).await;
                let _ = inputs.nth(i as i32).press_sequentially(&digit.to_string(), None).await;
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let _ = click_by_names(&page, &["继续", "提交", "Continue", "Submit"], 5000).await;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            // 错误检测
            let err_texts = ["验证码无效", "验证码错误", "invalid code", "incorrect code", "code is invalid"];
            let mut has_err = false;
            for t in err_texts {
                if page.get_by_text(t, false).count().await.unwrap_or(0) > 0 {
                    has_err = true;
                    break;
                }
            }
            if has_err {
                log(&logf, "[7] 验证码无效, 重新请求");
                continue;
            }
            ok_code = true;
            break;
        }
        if !ok_code {
            return Err("verification code attempts exhausted".into());
        }

        // 跳过 passkey 引导
        skip_passkey(&page, &logf).await;

        // [8] 状态机: 直到 session 有效并建 key (最长 240s)
        log(&logf, "[8] 处理注册后跳转…");
        let deadline = now() + std::time::Duration::from_secs(240);
        let mut last_url = String::new();
        loop {
            if stop.load(Ordering::Relaxed) {
                return Err("stopped".into());
            }
            // 尝试直接建 key
            if let Some(org) = get_org_name(&page).await {
                log(&logf, &format!("[8] session 有效, org: {org}"));
                return create_key(&page, &org, cfg).await;
            }
            let url_now = page.url();
            if url_now != last_url {
                log(&logf, &format!("[8] 页面: {}", &url_now[..url_now.len().min(90)]));
                last_url = url_now.clone();
            }
            if url_now.contains("passkey") {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                skip_passkey(&page, &logf).await;
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            if url_now.contains("select-account") || url_now.contains("cloudaccounts.nvidia.com") {
                log(&logf, "[8] 创建组织页…");
                create_org(&page, &cfg.org_name).await;
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                continue;
            }
            if url_now.contains("consent") || url_now.contains("static-login.nvidia.com") {
                let _ = click_by_names(&page, &["继续", "提交", "Continue", "Submit"], 5000).await;
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            if now() > deadline {
                return Err("finalize timeout".into());
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    .await;

    let _ = browser.close().await;
    drop(pw);
    match result {
        Ok(key) => {
            log(&logf, &format!("[✓] {email} → {}…", &key[..key.len().min(30)]));
            Ok((email, key))
        }
        Err(e) => {
            log(&logf, &format!("[✗] {email}: {e}"));
            Err(e)
        }
    }
}

async fn poll_code(cfg: &FlowConfig, inbox: &Inbox, timeout_secs: u64) -> Option<String> {
    match cfg.email_provider.as_str() {
        "duckmail" => {
            let dm = DuckMail {
                api_url: cfg.duck_api_url.clone(),
                domain: cfg.duck_domain.clone(),
                api_key: cfg.duck_api_key.clone(),
            };
            dm.poll_code(inbox, timeout_secs).await
        }
        _ => {
            let cf = CloudflareTempEmail {
                api_url: cfg.cf_api_url.clone(),
                admin_auth: cfg.cf_admin_auth.clone(),
                domain: cfg.cf_domain.clone(),
            };
            cf.poll_code(inbox, timeout_secs).await
        }
    }
}

async fn skip_passkey(page: &playwright_rs::Page, logf: &LogFn) {
    let skip_btn = page.locator("#cancelSetupSelect_btn");
    if skip_btn.count().await.unwrap_or(0) > 0 {
        let _ = skip_btn.first().click(None).await;
        logf("  passkey: 已点击稍后再说".into());
        // 确认对话框
        for _ in 0..10 {
            if click_by_names(page, &["确定", "OK", "Confirm", "Yes", "是"], 3000).await.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
}

async fn get_org_name(page: &playwright_rs::Page) -> Option<String> {
    let result = page
        .evaluate::<serde_json::Value, serde_json::Value>(
            r#"async () => {
                try {
                    const resp = await fetch('https://api.ngc.nvidia.com/user-context', {
                        credentials: 'include',
                        headers: {'accept': 'application/json'}
                    });
                    if (!resp.ok) return {ok: false, status: resp.status};
                    const data = await resp.json();
                    return {ok: true, orgName: data.orgName || null};
                } catch (e) {
                    return {ok: false, error: String(e)};
                }
            }"#,
            None,
        )
        .await
        .ok()?;
    if result["ok"].as_bool().unwrap_or(false) {
        return result["orgName"].as_str().map(String::from);
    }
    None
}

async fn create_org(page: &playwright_rs::Page, org_name: &str) -> bool {
    let text_input = page.locator("input[type=\"text\"]").first();
    if text_input.count().await.unwrap_or(0) == 0 {
        return false;
    }
    let _ = text_input.click(None).await;
    let _ = text_input.fill(org_name, None).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let btn = page
        .get_by_role(AriaRole::Button, Some(GetByRoleOptions::default().name("Create NVIDIA Cloud Account")))
        .first();
    for _ in 0..10 {
        if btn.count().await.unwrap_or(0) > 0 && btn.is_enabled().await.unwrap_or(false) {
            if btn.click(None).await.is_ok() {
                return true;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    false
}

async fn create_key(page: &playwright_rs::Page, org_name: &str, cfg: &FlowConfig) -> Result<String, String> {
    let payload = serde_json::json!({
        "expiryDate": cfg.key_expiry,
        "name": cfg.key_name,
        "type": "AI_PLAYGROUNDS_KEY",
        "policies": [{
            "product": "nv-cloud-functions",
            "scopes": ["invoke_function"],
            "resources": [{"id": "*", "type": "account-functions"}],
        }],
    });
    let arg = serde_json::json!({"orgName": org_name, "payload": payload});
    let result = page
        .evaluate::<serde_json::Value, serde_json::Value>(
            r#"async (ctx) => {
                try {
                    const resp = await fetch(
                        `https://api.ngc.nvidia.com/v3/orgs/${ctx.orgName}/keys/type/AI_PLAYGROUNDS_KEY`,
                        {
                            method: 'POST',
                            credentials: 'include',
                            headers: {'content-type': 'application/json', 'accept': '*/*'},
                            body: JSON.stringify(ctx.payload)
                        }
                    );
                    const text = await resp.text();
                    let data = null;
                    try { data = JSON.parse(text); } catch (_) {}
                    return {status: resp.status, data};
                } catch (e) {
                    return {status: 0, error: String(e)};
                }
            }"#,
            Some(&arg),
        )
        .await
        .map_err(|e| format!("create key evaluate: {e}"))?;
    let status = result["status"].as_i64().unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(format!("create key failed: {status}"));
    }
    let key = result["data"]["apiKey"]["value"]
        .as_str()
        .or_else(|| result["data"]["result"]["apiKey"]["value"].as_str())
        .unwrap_or("");
    if key.is_empty() {
        return Err("no apiKey.value in response".into());
    }
    Ok(key.to_string())
}
