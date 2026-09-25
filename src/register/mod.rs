//! 注册机: NVIDIA BUILD 账号自动注册 + nvapi- key 自动入库 (移植自 zseek/nvidia-register, playwright-rs 原生实现)。

pub mod captcha;
pub mod email;
pub mod flow;

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::storage::db;

// ---------------------------------------------------------------------------
// 随机生成
// ---------------------------------------------------------------------------

pub fn rand_hex(n: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..n).map(|_| format!("{:x}", rng.gen_range(0..16))).collect()
}

/// 12 位随机密码 (大小写+数字, 对齐原版 passwords.py)。
pub fn rand_password(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut chars: Vec<char> = Vec::new();
    chars.push(('a' as u8 + rng.gen_range(0..26)) as char);
    chars.push(('A' as u8 + rng.gen_range(0..26)) as char);
    chars.push(('0' as u8 + rng.gen_range(0..10)) as char);
    while chars.len() < len {
        match rng.gen_range(0..3) {
            0 => chars.push(('a' as u8 + rng.gen_range(0..26)) as char),
            1 => chars.push(('A' as u8 + rng.gen_range(0..26)) as char),
            _ => chars.push(('0' as u8 + rng.gen_range(0..10)) as char),
        }
    }
    // 打乱
    for i in (1..chars.len()).rev() {
        let j = rng.gen_range(0..=i);
        chars.swap(i, j);
    }
    chars.into_iter().collect()
}

// ---------------------------------------------------------------------------
// 注册配置 (system_setting 表)
// ---------------------------------------------------------------------------

pub struct RegConfig {
    pub email_provider: String, // cloudflare_temp_email | duckmail
    pub cf_api_url: String,
    pub cf_admin_auth: String,
    pub cf_domain: String,
    pub duck_api_url: String,
    pub duck_domain: String,
    pub duck_api_key: String,
    pub captcha_mode: String, // yescaptcha | captcharun
    pub yescaptcha_key: String,
    pub captcharun_token: String,
    pub headless: bool,
    pub org_name: String,
    pub key_name: String,
    pub key_expiry: String,
    pub key_rpm: i64,
}

fn setting(key: &str, default: &str) -> String {
    db()
        .query_row("SELECT value FROM system_setting WHERE key = ?1", [key], |r| {
            r.get::<_, String>(0)
        })
        .unwrap_or_else(|_| default.to_string())
}

pub fn load_config() -> RegConfig {
    RegConfig {
        email_provider: setting("reg_email_provider", "cloudflare_temp_email"),
        cf_api_url: setting("reg_cf_api_url", ""),
        cf_admin_auth: setting("reg_cf_admin_auth", ""),
        cf_domain: setting("reg_cf_domain", ""),
        duck_api_url: setting("reg_duck_api_url", ""),
        duck_domain: setting("reg_duck_domain", ""),
        duck_api_key: setting("reg_duck_api_key", ""),
        captcha_mode: setting("reg_captcha_mode", "yescaptcha"),
        yescaptcha_key: setting("reg_yescaptcha_key", ""),
        captcharun_token: setting("reg_captcharun_token", ""),
        headless: setting("reg_headless", "true") == "true",
        org_name: setting("reg_org_name", "nvidia2api-org"),
        key_name: setting("reg_key_name", "AI_PLAYGROUNDS_KEY"),
        key_expiry: setting("reg_key_expiry", "2028-01-01"),
        key_rpm: setting("reg_key_rpm", "40").parse().unwrap_or(40),
    }
}

pub fn save_config(cfg: &RegConfig) {
    let pairs: [(&str, String); 14] = [
        ("reg_email_provider", cfg.email_provider.clone()),
        ("reg_cf_api_url", cfg.cf_api_url.clone()),
        ("reg_cf_admin_auth", cfg.cf_admin_auth.clone()),
        ("reg_cf_domain", cfg.cf_domain.clone()),
        ("reg_duck_api_url", cfg.duck_api_url.clone()),
        ("reg_duck_domain", cfg.duck_domain.clone()),
        ("reg_duck_api_key", cfg.duck_api_key.clone()),
        ("reg_captcha_mode", cfg.captcha_mode.clone()),
        ("reg_yescaptcha_key", cfg.yescaptcha_key.clone()),
        ("reg_captcharun_token", cfg.captcharun_token.clone()),
        ("reg_headless", if cfg.headless { "true".into() } else { "false".into() }),
        ("reg_org_name", cfg.org_name.clone()),
        ("reg_key_name", cfg.key_name.clone()),
        ("reg_key_expiry", cfg.key_expiry.clone()),
    ];
    for (k, v) in pairs {
        let _ = db().execute(
            "INSERT INTO system_setting (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
            rusqlite::params![k, v],
        );
    }
}

fn to_flow_config(cfg: &RegConfig) -> flow::FlowConfig {
    flow::FlowConfig {
        headless: cfg.headless,
        org_name: cfg.org_name.clone(),
        key_name: cfg.key_name.clone(),
        key_expiry: cfg.key_expiry.clone(),
        email_provider: cfg.email_provider.clone(),
        cf_api_url: cfg.cf_api_url.clone(),
        cf_admin_auth: cfg.cf_admin_auth.clone(),
        cf_domain: cfg.cf_domain.clone(),
        duck_api_url: cfg.duck_api_url.clone(),
        duck_domain: cfg.duck_domain.clone(),
        duck_api_key: cfg.duck_api_key.clone(),
        solver: captcha::SolverConfig {
            mode: cfg.captcha_mode.clone(),
            yescaptcha_key: cfg.yescaptcha_key.clone(),
            yescaptcha_url: "https://api.yescaptcha.com".into(),
            captcharun_token: cfg.captcharun_token.clone(),
            captcharun_url: "https://api.captcha-run.com".into(),
            poll_interval_secs: 3,
            timeout_secs: 180,
        },
    }
}

// ---------------------------------------------------------------------------
// 任务状态
// ---------------------------------------------------------------------------

struct RegState {
    running: bool,
    stop_flag: Arc<AtomicBool>,
    count: u32,
    done: u32,
    ok: u32,
    fail: u32,
    imported: u32,
    started_at: String,
    logs: VecDeque<String>,
}

static REG: OnceLock<Mutex<RegState>> = OnceLock::new();

fn reg() -> &'static Mutex<RegState> {
    REG.get_or_init(|| {
        Mutex::new(RegState {
            running: false,
            stop_flag: Arc::new(AtomicBool::new(false)),
            count: 0,
            done: 0,
            ok: 0,
            fail: 0,
            imported: 0,
            started_at: String::new(),
            logs: VecDeque::new(),
        })
    })
}

const LOG_CAP: usize = 400;

fn push_log(msg: String) {
    let mut st = reg().lock().unwrap();
    if st.logs.len() >= LOG_CAP {
        st.logs.pop_front();
    }
    st.logs.push_back(msg);
}

/// 批量注册: 异步逐个注册, 成功即入库 Key 池 (以邮箱命名)。
pub fn start(count: u32) -> Result<(), String> {
    let cfg = load_config();
    // 前置校验
    match cfg.email_provider.as_str() {
        "duckmail" if cfg.duck_api_url.is_empty() || cfg.duck_domain.is_empty() => {
            return Err("duckmail: api_url / domain 未配置".into())
        }
        "cloudflare_temp_email" if cfg.cf_api_url.is_empty() || cfg.cf_admin_auth.is_empty() || cfg.cf_domain.is_empty() => {
            return Err("cloudflare_temp_email: api_url / admin_auth / domain 未配置".into())
        }
        _ => {}
    }
    match cfg.captcha_mode.as_str() {
        "yescaptcha" if cfg.yescaptcha_key.is_empty() => return Err("yescaptcha_key 未配置".into()),
        "captcharun" if cfg.captcharun_token.is_empty() => return Err("captcharun_token 未配置".into()),
        m if m != "yescaptcha" && m != "captcharun" => return Err(format!("不支持的验证码模式: {m} (仅 yescaptcha/captcharun)")),
        _ => {}
    }
    {
        let mut st = reg().lock().unwrap();
        if st.running {
            return Err("注册任务已在运行".into());
        }
        st.running = true;
        st.stop_flag = Arc::new(AtomicBool::new(false));
        st.count = count;
        st.done = 0;
        st.ok = 0;
        st.fail = 0;
        st.imported = 0;
        st.started_at = crate::storage::now_iso();
        st.logs.clear();
    }
    let stop = reg().lock().unwrap().stop_flag.clone();
    tokio::spawn(async move {
        let flow_cfg = to_flow_config(&cfg);
        let logf: Arc<dyn Fn(String) + Send + Sync> =
            Arc::new(|m: String| push_log(m));
        for i in 1..=count {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            push_log(format!("===== 账号 {i}/{count} ====="));
            match flow::register_one(&flow_cfg, logf.clone(), stop.clone()).await {
                Ok((email, api_key)) => {
                    let imported = crate::key_pool::insert_named(&email, &api_key, cfg.key_rpm);
                    let mut st = reg().lock().unwrap();
                    st.done += 1;
                    st.ok += 1;
                    if imported {
                        st.imported += 1;
                    }
                    append_csv(&email, &api_key);
                }
                Err(_) => {
                    let mut st = reg().lock().unwrap();
                    st.done += 1;
                    st.fail += 1;
                }
            }
            if i < count {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
        push_log("===== 批次结束 =====".into());
        reg().lock().unwrap().running = false;
    });
    Ok(())
}

pub fn stop() {
    let st = reg();
    st.lock().unwrap().stop_flag.store(true, Ordering::Relaxed);
}

pub fn snapshot() -> Value {
    let st = reg().lock().unwrap();
    json!({
        "running": st.running,
        "count": st.count,
        "done": st.done,
        "ok": st.ok,
        "fail": st.fail,
        "imported": st.imported,
        "started_at": st.started_at,
        "logs": st.logs.iter().collect::<Vec<_>>(),
    })
}

fn append_csv(email: &str, api_key: &str) {
    let path = crate::storage::data_dir().join("register_accounts.csv");
    let line = format!("{email},,{api_key}\n");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        use std::io::Write;
        let _ = f.write_all(line.as_bytes());
    }
}
