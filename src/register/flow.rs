//! 注册浏览器流程 (对齐原版 main.py register_account + finalize_and_create_key)。

use super::captcha::{self, SolverConfig};
use super::email::{CloudflareTempEmail, DuckMail, Inbox, MoeMail};
use playwright_rs::{AriaRole, GetByRoleOptions, GotoOptions, Playwright, WaitUntil};
use serde_json::Value;
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
    pub mo_api_url: String,
    pub mo_api_key: String,
    pub mo_domain: String,
    pub solver: SolverConfig,
}

fn now() -> std::time::Instant {
    std::time::Instant::now()
}

type LogFn = Arc<dyn Fn(String) + Send + Sync>;

fn log(s: &LogFn, msg: &str) {
    // 镜像到 stdout → server.log, 否则 [7] 之后的链路在 grep 里是盲区
    println!("[flow-log] {msg}");
    s(msg.to_string());
}

/// 点击按可访问名匹配的按钮 (依次尝试)。
/// 在页面所有 frame 中找持有 selector 的 frame (SSO 登录表单在 iframe 里)。
async fn find_frame_with(page: &playwright_rs::Page, selector: &str) -> Option<playwright_rs::protocol::Frame> {
    let Ok(frames) = page.frames().await else {
        return None;
    };
    for f in frames {
        if f.locator(selector).count().await.unwrap_or(0) > 0 {
            return Some(f);
        }
    }
    None
}

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

/// consent 页推进: 遍历主 frame + 所有 iframe — 先勾协议 checkbox, 再按中英文案点按钮;
/// 全不中时打印各 frame 可见按钮文本 (诊断, 下次失败有确切线索)
async fn consent_advance(page: &playwright_rs::Page, logf: &LogFn) {
    let js = r#"(() => {
        document.querySelectorAll('input[type="checkbox"]:not(:checked)').forEach(c => c.click());
        const want = ['继续','同意并继续','同意','接受','提交','Continue','Accept','Agree','Submit','Join','开始','Start'];
        const els = [...document.querySelectorAll('button, input[type="submit"], a[role="button"], a.btn')];
        for (const w of want) {
            const hit = els.find(e => !e.disabled && ((e.textContent||'').trim().includes(w) || (e.value||'').includes(w)));
            if (hit) { hit.click(); return 'clicked:' + ((hit.textContent||hit.value||w)+'').trim().slice(0,30); }
        }
        const texts = els.map(e => ((e.textContent||e.value||'')+'').trim()).filter(t => t).slice(0,8);
        return 'buttons:' + JSON.stringify(texts);
    })()"#;
    if let Ok(frames) = page.frames().await {
        for f in frames {
            if let Ok(v) = f.evaluate::<Value>(js, None).await {
                let s = v.as_str().unwrap_or("").to_string();
                if s.is_empty() || s == "buttons:[]" {
                    continue;
                }
                logf(format!("  consent: {s}"));
                if s.starts_with("clicked:") {
                    return;
                }
            }
        }
    }
}

/// 单账号完整注册流程。成功返回 nvapi- key。
pub async fn register_one(
    cfg: &FlowConfig,
    logf: LogFn,
    stop: Arc<AtomicBool>,
) -> Result<(String, String), String> {
    log(&logf, "[1] 创建临时邮箱…");
    // 本机 TLS/网络抖动频繁, 第一步瞬时失败不该烧掉整轮 — 5s 后重试, 最多 3 次
    let mut attempt = 0u32;
    let inbox: Inbox = loop {
        attempt += 1;
        let r: Result<Inbox, String> = match cfg.email_provider.as_str() {
            "moemail" => {
                let mo = MoeMail {
                    api_url: cfg.mo_api_url.clone(),
                    api_key: cfg.mo_api_key.clone(),
                    domain: cfg.mo_domain.clone(),
                };
                mo.create_inbox(&format!("nv{}", super::rand_hex(8))).await
            }
            "duckmail" => {
                let dm = DuckMail {
                    api_url: cfg.duck_api_url.clone(),
                    domain: cfg.duck_domain.clone(),
                    api_key: cfg.duck_api_key.clone(),
                };
                dm.create_inbox(&format!("nv{}", super::rand_hex(8))).await
            }
            _ => {
                let cf = CloudflareTempEmail {
                    api_url: cfg.cf_api_url.clone(),
                    admin_auth: cfg.cf_admin_auth.clone(),
                    domain: cfg.cf_domain.clone(),
                };
                cf.create_inbox(&format!("nv{}", super::rand_hex(8))).await
            }
        };
        match r {
            Ok(v) => break v,
            Err(e) if attempt < 3 => {
                log(&logf, &format!("[1] 创建邮箱失败 ({e}), 5s 后重试 {attempt}/2…"));
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            Err(e) => return Err(e),
        }
    };
    let email = inbox.address.clone();
    log(&logf, &format!("[1] 邮箱: {email}"));
    let password = super::rand_password(12);

    let pw = match Playwright::launch().await {
        Ok(v) => v,
        Err(e) => {
            let m = format!("[✗] playwright 启动失败: {e} (需安装 playwright 驱动与浏览器)");
            log(&logf, &m);
            return Err(m);
        }
    };
    // 代理: 代理池有 enabled 线路 → chromium 全局走代理 (隧道/常规自动识别)
    let mut args = vec![
        "--no-sandbox".to_string(),
        "--disable-blink-features=AutomationControlled".to_string(),
        "--lang=zh-CN".to_string(),
        "--disable-dev-shm-usage".to_string(),
        // 防自动化特征 (与 init script 配合)
        "--disable-features=IsolateOrigins,site-per-process".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-infobars".to_string(),
        "--window-size=1280,1024".to_string(),
        "--start-maximized".to_string(),
    ];
    let mut used_proxy: Option<String> = None;
    if let Some(p) = crate::proxy_pool::chromium_proxy_arg() {
        log(&logf, &format!("[proxy] chromium 走代理: {p}"));
        args.push(p.clone());
        used_proxy = Some(p);
    }
    // headed 真浏览器 (Xvfb 虚拟显示) — headless 的 UA/plugins/chrome 对象/permissions
    // 全是可检测特征 (sannysoft 10 项 FAIL), headed 全 PASS。有 DISPLAY 即 headed。
    let display = std::env::var("DISPLAY").is_ok();
    let headless = !display && cfg.headless;
    if display {
        log(&logf, "[browser] Xvfb headed 模式 (真浏览器特征)");
    }
    let browser = match pw
        .chromium()
        .launch_with_options(
            playwright_rs::LaunchOptions::new()
                .headless(headless)
                .args(args),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            let m = format!("[✗] chromium 启动失败: {e} (需 playwright install chromium)");
            log(&logf, &m);
            return Err(m);
        }
    };
    let page = match browser.new_page().await {
        Ok(v) => v,
        Err(e) => {
            let m = format!("[✗] new_page 失败: {e}");
            log(&logf, &m);
            return Err(m);
        }
    };

    let result: Result<String, String> = async {
        // [2] build.nvidia.com
        log(&logf, "[2] 打开 build.nvidia.com…");
        goto_guarded(&page, "https://build.nvidia.com/").await;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let cookie = page.locator("#onetrust-accept-btn-handler");
        if cookie.count().await.unwrap_or(0) > 0 {
            let _ = cookie.click(None).await;
        }
        if stop.load(Ordering::Relaxed) {
            return Err("stopped".into());
        }

        // [3] 打开登录弹窗
        log(&logf, "[3] 打开 signin 弹窗…");
        // 多语言: 英文 Login / 中文 登录 / 文本兜底
        let mut login_opened = false;
        for name in ["Login", "登录", "Sign in", "Sign In"] {
            let btn = page.get_by_role(AriaRole::Button, Some(GetByRoleOptions::default().name(name)));
            if btn.count().await.unwrap_or(0) > 0 {
                let _ = btn.first().click(None).await;
                login_opened = true;
                break;
            }
        }
        if !login_opened {
            let txt = page.get_by_text("登录", false);
            if txt.count().await.unwrap_or(0) > 0 {
                let _ = txt.first().click(None).await;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        // 兜底: 登录入口常为 <a> 链接 (role=button 匹配不到) — href 含 login 的直接跳
        if find_frame_with(&page, "input[name=\"email\"]").await.is_none() {
            let js = r#"(() => { const a = [...document.querySelectorAll('a')].find(x => /login|signin|auth/i.test((x.href||'') + (x.innerText||''))); if (a) { a.click(); return a.href; } return ''; })()"#;
            if let Ok(href) = page.evaluate::<serde_json::Value, String>(js, None).await {
                if !href.is_empty() {
                    log(&logf, &format!("[3] <a> 登录链接点击: {href}"));
                }
            }
        }
        // 二次兜底: <a> 点击不弹时直接导航 ?modal=signin (实测成功轮的 URL 形态)
        if find_frame_with(&page, "input[name=\"email\"]").await.is_none() {
            log(&logf, "[3] 弹窗未现, 直接导航 ?modal=signin");
            let _ = page
                .goto(
                    "https://build.nvidia.com/?modal=signin",
                    Some(GotoOptions::default().wait_until(WaitUntil::DomContentLoaded)),
                )
                .await;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        // 等弹窗 (SSO iframe) 渲染: 跨 frame 找 email input (慢代理线路页资源 12KB/s, 20s 不够)
        let deadline = now() + std::time::Duration::from_secs(40);
        let mut form_frame: Option<playwright_rs::protocol::Frame> = None;
        while now() < deadline {
            if let Some(f) = find_frame_with(&page, "input[name=\"email\"]").await {
                form_frame = Some(f);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        let form_frame = match form_frame {
            Some(f) => f,
            None => {
            let url = page.url();
            log(&logf, &format!("[diag] url: {url}"));
            let btns = page
                .evaluate::<serde_json::Value, serde_json::Value>(
                    "(() => { const els = [...document.querySelectorAll('button, a')]; return els.slice(0, 40).map(e => (e.innerText || e.getAttribute('aria-label') || '').trim()).filter(Boolean); })()",
                    None,
                )
                .await;
            let body_len = page
                .evaluate::<serde_json::Value, String>(
                    "(() => document.body ? String(document.body.innerText.length) : '-1')()",
                    None,
                )
                .await
                .unwrap_or_default();
            log(&logf, &format!("[diag] body 文本长度: {body_len}"));
            let head = page
                .evaluate::<serde_json::Value, String>(
                    "(() => document.body ? document.body.innerText.replace(/\\s+/g,' ').slice(0, 180) : '')()",
                    None,
                )
                .await
                .unwrap_or_default();
            log(&logf, &format!("[diag] body 开头: {head}"));
            match btns {
                Ok(v) => log(&logf, &format!("[diag] 页面元素: {}", v)),
                Err(e) => log(&logf, &format!("[diag] dump 失败: {e}")),
            }
                return Err("email input not found".into());
            }
        };

        // [4] 提交邮箱 → Next (iframe 内) — 人类化: 轨迹点击 + 逐字打字
        log(&logf, "[4] 提交邮箱…");
        captcha::ensure_hcaptcha_hook(&page).await;
        let email_input = form_frame.locator("input[name=\"email\"]").first();
        if captcha::human_click_locator(&page, &email_input).await.is_err() {
            let _ = email_input.click(None).await;
        }
        if captcha::human_type(&page, &email).await.is_err() {
            let _ = email_input.press_sequentially(&email, None).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let next_btn = form_frame.get_by_role(AriaRole::Button, Some(GetByRoleOptions::default().name("Next")));
        if next_btn.count().await.unwrap_or(0) == 0 {
            return Err("Next button not found".into());
        }
        if captcha::human_click_locator(&page, &next_btn.first()).await.is_err() {
            let _ = next_btn.first().click(None).await;
        }
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;

        // [5] 填密码 — 两坑: ①风控下表单 30s 才渲染(实测), 等 75s ②邮箱提交后整页跳转
        //      login.nvgs.nvidia.com, 密码表单在新主页面, 必须跨 frame 重找(旧 form_frame 已消亡)
        log(&logf, "[5] 填写密码…");
        // 慢线路 (12KB/s) SPA bundle 可能 80-160s 才跑完, 75s 窗口实测不够 (BR 轮 body 全空)
        let deadline = now() + std::time::Duration::from_secs(150);
        let t5 = now();
        let mut pw_frame: Option<playwright_rs::protocol::Frame> = None;
        let mut resent = false;
        let mut reloaded = false;
        while now() < deadline {
            // 登录页多变体 (实测 BR 出口轮: login.nvgs.nvidia.com 渲染出的密码框 id 不是 #registration_password)
            // — 通用 input[type=password] 兜底
            if let Some(f) = find_frame_with(&page, "#registration_password")
                .await
                .or(find_frame_with(&page, "input[type=\"password\"]").await)
            {
                pw_frame = Some(f);
                break;
            }
            // 慢线路实测: Next 点击丢失后表单卡回 email 页, 只等不自救必超时 — 25s 未前进则重发
            if !resent && now() >= t5 + std::time::Duration::from_secs(25) {
                resent = true;
                if form_frame.locator("input[name=\"email\"]").first().count().await.unwrap_or(0) > 0 {
                    log(&logf, "[5] 25s 表单未前进, 重发 Next…");
                    let nb = form_frame.get_by_role(AriaRole::Button, Some(GetByRoleOptions::default().name("Next")));
                    if captcha::human_click_locator(&page, &nb.first()).await.is_err() {
                        let _ = nb.first().click(None).await;
                    }
                }
            }
            // 80s 仍无密码框 → SPA 资源大概率没跑完 (body 空, 无 input) — 重拉登录文档一次。
            // 登录页若在顶层 reload 即保留 URL key 参数; 若在 iframe 则对 frame 自身 goto (顶层 reload 会丢 OTP 状态)
            if !reloaded && now() >= t5 + std::time::Duration::from_secs(80) {
                reloaded = true;
                let lu = page.url();
                if lu.contains("login.") {
                    log(&logf, "[5] 80s 未出密码框, reload 登录页 (顶层)…");
                    let _ = page.reload(None::<GotoOptions>).await;
                } else if let Ok(fs) = page.frames().await {
                    let mut done = false;
                    for f in fs.iter() {
                        let u = f.url();
                        if u.contains("login.") {
                            log(&logf, &format!("[5] 80s 未出密码框, iframe 重拉登录页…"));
                            let _ = f.goto(&u, None).await;
                            done = true;
                            break;
                        }
                    }
                    if !done {
                        log(&logf, "[5] 80s 未出密码框, 未见登录页 frame, 干等…");
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        let Some(pw_frame) = pw_frame else {
            // 超时诊断快照: dump 每个 frame 的 URL + 可见文本, 定位卡在哪个环节
            if let Ok(frames) = page.frames().await {
                for f in frames {
                    let url = f.url();
                    let text: String = f
                        .evaluate::<Value>(
                            "(() => document.body ? document.body.innerText.replace(/\\s+/g,' ').slice(0,300) : '')()",
                            None,
                        )
                        .await
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_default();
                    let inputs: String = f
                        .evaluate::<Value>(
                            "(() => JSON.stringify([...document.querySelectorAll('input')].slice(0,6).map(i => i.id || i.name || i.type)))()",
                            None,
                        )
                        .await
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_default();
                    log(&logf, &format!("[5-diag] frame {url} | inputs={inputs} | {text}"));
                }
            }
            return Err("password field never appeared".into());
        };
        // 变体兜底: id 缺失的登录页用通用密码框选择器
        let pw_input = if pw_frame.locator("#registration_password").count().await.unwrap_or(0) > 0 {
            pw_frame.locator("#registration_password").first()
        } else {
            log(&logf, "[5] 非标准密码框变体 (无 #registration_password), 走通用选择器");
            pw_frame.locator("input[type=\"password\"]").first()
        };
        if captcha::human_click_locator(&page, &pw_input).await.is_err() {
            let _ = pw_input.click(None).await;
        }
        if captcha::human_type(&page, &password).await.is_err() {
            let _ = pw_input.fill(&password, None).await;
        }
        let pw_confirm = if pw_frame.locator("#registration_passwordConfirm").count().await.unwrap_or(0) > 0 {
            pw_frame.locator("#registration_passwordConfirm").first()
        } else {
            // 单密码框变体: 无确认框时 nth(1) 计数为 0, 后续点击/填值失败自然跳过
            pw_frame.locator("input[type=\"password\"]").nth(1)
        };
        if captcha::human_click_locator(&page, &pw_confirm).await.is_err() {
            let _ = pw_confirm.click(None).await;
        }
        if captcha::human_type(&page, &password).await.is_err() {
            let _ = pw_confirm.fill(&password, None).await;
        }

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
                // hCaptcha IP 限流: 继续重试只会刷新限流窗口, 直接放弃本轮
                if e.contains("限流") {
                    return Err("hcaptcha IP 限流, 本轮放弃".into());
                }
                // 不 continue — create-account 的 hCaptcha 常为静默模式 (无挑战弹出,
                // 表单提交时自动验证): 直接点注册按钮让页面自己拿 token
                log(&logf, "[6] captcha 未过, 尝试静默模式直接提交…");
            }
            // 挂响应监听再点击
            captcha::watch_register_response(&page).await;
            // form_frame 可能已消亡 (密码后页面跳转) — 重找含注册按钮的 frame
            let btn_frame = find_frame_with(&page, "#register_button")
                .await
                .unwrap_or_else(|| form_frame.clone());
            let btn = btn_frame.locator("#register_button");
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
                log_eprintln(&format!("[flow] register accepted ({st})"));
                accepted = true;
                break;
            }
            if st == 409 {
                return Err("email already registered".into());
            }
            // 镜像到 server.log — rejected 状态码是定位"答对但提交被拒"的唯一线索
            log_eprintln(&format!("[flow] register rejected (st={st})"));
            log(&logf, &format!("[6] register rejected ({st}), 重试…"));
        }
        if !accepted {
            return Err("register submit failed after 3 attempts".into());
        }

        // [7] 邮箱验证码 (重试 3 次); NVIDIA 邮件实测可迟于 180s 到达, 首轮 240s + 补轮 120s
        log(&logf, "[7] 等待验证码邮件…");
        let mut code = poll_code(cfg, &inbox, 240).await;
        if code.is_none() {
            log(&logf, "[7] 首轮未收到, 补一轮 120s 轮询…");
            code = poll_code(cfg, &inbox, 120).await;
        }
        let mut ok_code = false;
        for attempt in 1..=3 {
            let Some(c) = code.clone() else {
                log(&logf, "[7] 未收到验证码");
                return Err("no verification code".into());
            };
            log_eprintln(&format!("[flow] got verification code: {c}"));
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
            // chrome-error 页 = 跳转链某跳加载失败, 重导航把流程接回去 (对齐 zseek)
            if url_now.starts_with("chrome-error") || url_now.contains("chrome-error://") {
                log(&logf, "[8] 页面加载失败, 重开 build.nvidia.com 恢复流程…");
                goto_guarded(&page, "https://build.nvidia.com/").await;
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                last_url.clear();
                continue;
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
                consent_advance(&page, &logf).await;
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
            if let Some(ref pa) = used_proxy {
                crate::proxy_pool::mark_proxy_success(pa);
            }
            Ok((email, key))
        }
        Err(e) => {
            log(&logf, &format!("[✗] {email}: {e}"));
            // 注册失败计入节点统计: 限流类单败即冷却, 其余连败满 2 次才冷却
            if let Some(ref pa) = used_proxy {
                crate::proxy_pool::mark_proxy_fail(pa, &e.to_string());
            }
            Err(e)
        }
    }
}

/// goto 挂死防护: proot 下 CDP 导航可能永久挂起 (实测批次冻死 8.5h), 60s 强制超时
async fn goto_guarded(page: &playwright_rs::Page, url: &str) {
    match tokio::time::timeout(std::time::Duration::from_secs(60), page.goto(url, None)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => log_eprintln(&format!("[warn] goto 失败: {e}")),
        Err(_) => log_eprintln("[warn] goto 60s 超时 (挂死防护), 继续"),
    }
}

fn log_eprintln(msg: &str) {
    eprintln!("{msg}");
}

async fn poll_code(cfg: &FlowConfig, inbox: &Inbox, timeout_secs: u64) -> Option<String> {
    match cfg.email_provider.as_str() {
        "moemail" => {
            let mo = MoeMail {
                api_url: cfg.mo_api_url.clone(),
                api_key: cfg.mo_api_key.clone(),
                domain: cfg.mo_domain.clone(),
            };
            mo.poll_code(inbox, timeout_secs).await
        }
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
