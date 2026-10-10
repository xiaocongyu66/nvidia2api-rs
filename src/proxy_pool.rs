//! 代理池: 状态机 + 测速(延迟+公网IP) + 连败 unhealthy + 冷却 (原版 proxy_service/proxy_checker 语义)。
//! 隧道协议 (trojan/vless/ss/hy2, 自 freebuff-rs 移植): 完整分享链接存 host 列,
//! 运行时按需拉起 127.0.0.1 本地 mixed 监听, chromium 走本地口。

use crate::config::Config;
use std::time::Duration;
use crate::models::Proxy;
use crate::storage::{db, now_iso};

pub const IMPORT_PROTOCOLS: [&str; 8] = ["socks5", "socks5h", "http", "https", "trojan", "vless", "ss", "hy2"];

/// 隧道协议 (分享链接型, 与 host:port 型区分)
pub const TUNNEL_PROTOCOLS: [&str; 4] = ["trojan", "vless", "ss", "hy2"];

pub fn is_tunnel_protocol(p: &str) -> bool {
    TUNNEL_PROTOCOLS.contains(&p)
}

// 隧道本地监听缓存: proxy_id → (端口, 已拉起)
static TUNNEL_PORTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<i64, u16>>> =
    std::sync::OnceLock::new();

fn tunnels() -> &'static std::sync::Mutex<std::collections::HashMap<i64, u16>> {
    TUNNEL_PORTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 为隧道代理拉起本地 mixed (幂等)。返回 127.0.0.1 端口; 非隧道或失败返回 None。
pub fn tunnel_port_for(proxy: &Proxy) -> Option<u16> {
    if !is_tunnel_protocol(&proxy.protocol) {
        return None;
    }
    let mut map = tunnels().lock().unwrap();
    if let Some(&port) = map.get(&proxy.id) {
        return Some(port);
    }
    let link = &proxy.host; // host 列存完整分享链接
    // 解析校验 + 端口分配 (16000 + id)
    let port = (16000i64 + proxy.id) as u16;
    let ob = match crate::tunnel::outbound::Outbound::from_link(link) {
        Ok(v) => std::sync::Arc::new(v),
        Err(e) => {
            eprintln!("[tunnel] 链接解析失败: {e}");
            return None;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = crate::tunnel::spawn_mixed(port, ob).await {
            eprintln!("[tunnel] mixed 启动失败: {e}");
        }
    });
    map.insert(proxy.id, port);
    Some(port)
}

/// 轮换计数器: 每次取代理 +1, 批次间自动换节点 (不再固定第一条)
static NEXT_PROXY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// chromium --proxy-server 参数: enabled 节点中轮换选择, 跳过冷却中的;
/// 隧道走本地 mixed 口, 常规代理直填。
pub fn chromium_proxy_arg() -> Option<String> {
    use std::sync::atomic::Ordering;
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    // 只考虑 enabled 且未在冷却中的 (cooldown_until 为 ISO 字符串, 字典序=时间序)
    let candidates: Vec<Proxy> = list_all()
        .into_iter()
        .filter(|p| p.enabled && p.cooldown_until.as_deref().map(|c| c <= now.as_str()).unwrap_or(true))
        .collect();
    // 全在冷却时仍走代理轮换: 直连国内 IP 会撞 hCaptcha 配额墙 (日级限流), 比冷却节点更毒
    let pool: Vec<Proxy> = if candidates.is_empty() {
        println!("[proxy] 全部节点冷却中, 仍走代理轮换 (拒走直连)");
        list_all().into_iter().filter(|p| p.enabled).collect()
    } else {
        candidates
    };
    if pool.is_empty() {
        return None;
    }
    let idx = NEXT_PROXY.fetch_add(1, Ordering::Relaxed) % pool.len();
    let p = &pool[idx];
    if is_tunnel_protocol(&p.protocol) {
        if let Some(port) = tunnel_port_for(p) {
            return Some(format!("--proxy-server=socks5://127.0.0.1:{port}"));
        }
        return None;
    }
    let auth = if p.username.is_empty() {
        String::new()
    } else {
        format!("{}:{}@", p.username, p.password)
    };
    Some(format!("--proxy-server={}://{}{}:{}", p.protocol, auth, p.host, p.port))
}

/// 从 chromium proxy_arg 反查节点 id。隧道端口规则与 tunnel_port_for 一致: 16000 + id
/// (旧实现按 enabled 列表下标反查 — 停用节点后整体错位, 高 id 节点永远罚不到/罚错人)
fn proxy_id_of(proxy_arg: &str) -> Option<i64> {
    let port = proxy_arg
        .strip_prefix("--proxy-server=socks5://127.0.0.1:")?
        .parse::<i64>()
        .ok()?;
    port.checked_sub(16000)
}

/// 注册成功: 清连败与冷却 (否则一次偶发页面故障会持续拖累该节点)
pub fn mark_proxy_success(proxy_arg: &str) {
    let Some(proxy_id) = proxy_id_of(proxy_arg) else { return };
    let _ = db().execute(
        "UPDATE proxy SET consecutive_failures = 0, cooldown_until = NULL, status = 'healthy', \
         success_count = success_count + 1 WHERE id = ?1",
        rusqlite::params![proxy_id],
    );
}

/// 注册批次节点失败: 记入统计; 连败 >=2 才冷却 30min
/// (弹窗超时/验证码类失败与 IP 无关, 单败就冷却会白白抽干节点池)
pub fn mark_proxy_fail(proxy_arg: &str) {
    let Some(proxy_id) = proxy_id_of(proxy_arg) else { return };
    // 单一 db() guard — std Mutex 不可重入, 再调 db() 即自死锁
    let _ = db().execute(
        "UPDATE proxy SET failure_count = failure_count + 1, consecutive_failures = consecutive_failures + 1, \
         status = CASE WHEN consecutive_failures + 1 >= 2 THEN 'cooling' ELSE status END, \
         cooldown_until = CASE WHEN consecutive_failures + 1 >= 2 THEN datetime('now', '+1800 seconds') ELSE cooldown_until END \
         WHERE id = ?1",
        rusqlite::params![proxy_id],
    );
    eprintln!("[proxy] 节点 {proxy_id} 注册失败 (连败满 2 次才冷却 30min)");
}

/// 服务启动预热: 拉起所有 enabled 隧道的本地 mixed 监听
/// (否则服务重启后监听丢失, 需等下一次 check/批次才恢复)。
pub fn prewarm_tunnels() {
    for p in list_all() {
        if p.enabled && is_tunnel_protocol(&p.protocol) {
            if let Some(port) = tunnel_port_for(&p) {
                eprintln!("[tunnel] 预热 {} -> 127.0.0.1:{port}", p.name);
            }
        }
    }
}

fn row_to_proxy(r: &rusqlite::Row) -> rusqlite::Result<Proxy> {
    Ok(Proxy {
        id: r.get("id")?,
        name: r.get("name")?,
        protocol: r.get("protocol")?,
        host: r.get("host")?,
        port: r.get("port")?,
        username: r.get("username")?,
        password: r.get("password")?,
        group_id: r.get("group_id")?,
        country: r.get("country")?,
        region: r.get("region")?,
        city: r.get("city")?,
        isp: r.get("isp")?,
        enabled: r.get::<_, i64>("enabled")? != 0,
        status: r.get("status")?,
        latency_ms: r.get("latency_ms")?,
        public_ip: r.get("public_ip")?,
        last_check_at: r.get("last_check_at")?,
        success_count: r.get("success_count")?,
        failure_count: r.get("failure_count")?,
        consecutive_failures: r.get("consecutive_failures")?,
        cooldown_until: r.get("cooldown_until")?,
        created_at: r.get("created_at")?,
    })
}

const P_COLS: &str = "id, name, protocol, host, port, username, password, group_id, country, region, city, isp, \
    enabled, status, latency_ms, public_ip, last_check_at, success_count, failure_count, consecutive_failures, cooldown_until, created_at";

pub fn list_all() -> Vec<Proxy> {
    let conn = db();
    let mut stmt = conn.prepare(&format!("SELECT {P_COLS} FROM proxy ORDER BY id")).unwrap();
    stmt.query_map([], row_to_proxy).unwrap().filter_map(|r| r.ok()).collect()
}

pub fn get_by_id(id: i64) -> Option<Proxy> {
    let conn = db();
    let mut stmt = conn.prepare(&format!("SELECT {P_COLS} FROM proxy WHERE id = ?1")).ok()?;
    stmt.query_row([id], row_to_proxy).ok()
}

/// 导入一行: `socks5://user:pass@host:port` 或隧道分享链接 (trojan:// vless:// ss:// hy2://)。
/// 隧道: 返回 (name, protocol, 0, 完整链接, "", "") — host 列承载完整链接。
pub fn parse_proxy_line(line: &str) -> Option<(String, String, i64, String, String, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (protocol, rest) = if let Some(idx) = line.find("://") {
        let p = line[..idx].to_lowercase();
        // 别名归一: hysteria2 → hy2
        let p = if p == "hysteria2" { "hy2".to_string() } else { p };
        if !IMPORT_PROTOCOLS.contains(&p.as_str()) {
            return None;
        }
        (p, &line[idx + 3..])
    } else {
        ("socks5".to_string(), line)
    };
    if is_tunnel_protocol(&protocol) {
        let name = format!("{}-tunnel", protocol);
        return Some((name, protocol, 0, line.to_string(), String::new(), String::new()));
    }
    // 去掉路径部分
    let rest = rest.split('/').next().unwrap_or(rest);
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => (String::new(), rest.to_string()),
    };
    let (username, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        _ if userinfo.is_empty() => (String::new(), String::new()),
        _ => (userinfo, String::new()),
    };
    let (host, port) = hostport.rsplit_once(':')?;
    let port: i64 = port.trim().parse().ok()?;
    if host.is_empty() || !(1..=65535).contains(&port) {
        return None;
    }
    let name = format!("{host}:{port}");
    Some((name, protocol, port, host.to_string(), username, password))
}

/// 批量导入 (自动去重)。
pub fn bulk_import(text: &str, protocol_default: &str) -> (u32, u32) {
    let mut ok = 0;
    let mut dup = 0;
    let conn = db();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let full = if line.contains("://") {
            line.to_string()
        } else {
            // 裸 host:port[:user:pass] → 默认协议
            format!("{protocol_default}://{line}")
        };
        let Some((name, protocol, port, host, username, password)) = parse_proxy_line(&full) else { continue };
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO proxy (name, protocol, host, port, username, password) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![name, protocol, host, port, username, password],
            )
            .unwrap_or(0);
        if inserted > 0 {
            ok += 1;
        } else {
            dup += 1;
        }
    }
    (ok, dup)
}

/// 测速 + 拉公网 IP + geo。返回 (延迟ms, 公网ip, country, region, city, isp)。
pub async fn check_proxy(proxy: &Proxy, timeout: Duration) -> Result<(f64, String, String, String, String, String), String> {
    let t0 = std::time::Instant::now();
    // 隧道型: 经本地 mixed 口测 (tunnel_port_for 负责拉起)
    let proxy_url = if is_tunnel_protocol(&proxy.protocol) {
        let port = tunnel_port_for(proxy).ok_or("隧道解析失败")?;
        format!("socks5://127.0.0.1:{port}")
    } else {
        proxy.url()
    };
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).map_err(|e| e.to_string())?)
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get("http://ip-api.com/json/?fields=query,country,regionName,city,isp")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let latency = t0.elapsed().as_secs_f64() * 1000.0;
    Ok((
        latency,
        data["query"].as_str().unwrap_or("").to_string(),
        data["country"].as_str().unwrap_or("").to_string(),
        data["regionName"].as_str().unwrap_or("").to_string(),
        data["city"].as_str().unwrap_or("").to_string(),
        data["isp"].as_str().unwrap_or("").to_string(),
    ))
}

/// 结果上报 (含状态机): 成功→healthy; 失败→连败计数, 达阈值→unhealthy, 否则冷却。
pub async fn report_result(proxy_id: i64, ok: bool, latency_ms: f64) {
    let cfg = Config::from_env();
    let conn = db();
    if ok {
        let _ = conn.execute(
            "UPDATE proxy SET status = 'healthy', consecutive_failures = 0, success_count = success_count + 1, \
             latency_ms = ?1, last_check_at = ?2, cooldown_until = NULL, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![latency_ms, now_iso(), proxy_id],
        );
    } else {
        let _ = conn.execute(
            "UPDATE proxy SET failure_count = failure_count + 1, consecutive_failures = consecutive_failures + 1, \
             last_check_at = ?1, updated_at = ?1, \
             status = CASE WHEN consecutive_failures + 1 >= ?2 THEN 'unhealthy' ELSE 'cooling' END, \
             cooldown_until = CASE WHEN consecutive_failures + 1 < ?2 \
               THEN datetime('now', '+' || ?3 || ' seconds') ELSE cooldown_until END \
             WHERE id = ?4",
            rusqlite::params![now_iso(), cfg_proxy_threshold(&cfg), cfg_proxy_cooldown(&cfg), proxy_id],
        );
    }
}

fn cfg_proxy_threshold(cfg: &Config) -> i64 {
    setting_i64("proxy_unhealthy_threshold", 3, cfg)
}

fn cfg_proxy_cooldown(cfg: &Config) -> i64 {
    setting_i64("proxy_failure_cooldown_seconds", 60, cfg)
}

/// 运行时设置读取 (system_setting 表, 缺省回退默认值)。
pub fn setting_i64(key: &str, default: i64, _cfg: &Config) -> i64 {
    let conn = db();
    conn.query_row("SELECT value FROM system_setting WHERE key = ?1", [key], |r| {
        r.get::<_, String>(0)
    })
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(default)
}

pub fn setting_str(key: &str, default: &str) -> String {
    let conn = db();
    conn.query_row("SELECT value FROM system_setting WHERE key = ?1", [key], |r| {
        r.get::<_, String>(0)
    })
    .unwrap_or_else(|_| default.to_string())
}

pub fn set_setting(key: &str, value: &str) {
    let _ = db().execute(
        "INSERT INTO system_setting (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
        rusqlite::params![key, value],
    );
}

pub fn set_enabled(proxy_id: i64, enabled: bool) -> Result<(), String> {
    let cfg = Config::from_env();
    if enabled {
        // 强制上限: 启用代理数 ≤ 可调度 Key 数 - 1 (原版规则)
        let keys: i64 = db()
            .query_row(
                "SELECT COUNT(*) FROM nvidia_api_key WHERE status NOT IN ('disabled','invalid')",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let enabled_count: i64 = db()
            .query_row("SELECT COUNT(*) FROM proxy WHERE enabled = 1", [], |r| r.get(0))
            .unwrap_or(0);
        let cap = crate::balancer::max_proxies_for_keys(keys.max(0) as usize) as i64;
        // 保底 1 条: 注册机需要代理绕 IP 风控, 不能因 Key 池空而禁用代理
        let cap = cap.max(1);
        if enabled_count >= cap {
            return Err(format!("proxy_limit: {enabled_count}/{cap} (N keys → N-1 proxies max, floor 1)"));
        }
    }
    let _ = &cfg;
    let _ = db().execute(
        "UPDATE proxy SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![enabled as i64, now_iso(), proxy_id],
    );
    Ok(())
}

pub fn delete(proxy_id: i64) -> bool {
    db().execute("DELETE FROM proxy WHERE id = ?1", [proxy_id]).unwrap_or(0) > 0
}
