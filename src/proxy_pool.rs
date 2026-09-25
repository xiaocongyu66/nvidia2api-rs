//! 代理池: 状态机 + 测速(延迟+公网IP) + 连败 unhealthy + 冷却 (原版 proxy_service/proxy_checker 语义)。

use crate::config::Config;
use std::time::Duration;
use crate::models::Proxy;
use crate::storage::{db, now_iso};

pub const IMPORT_PROTOCOLS: [&str; 4] = ["socks5", "socks5h", "http", "https"];

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

/// 导入一行: `socks5://user:pass@host:port`。返回 (name, protocol, port, host, username, password)。
pub fn parse_proxy_line(line: &str) -> Option<(String, String, i64, String, String, String)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (protocol, rest) = if let Some(idx) = line.find("://") {
        let p = line[..idx].to_lowercase();
        if !IMPORT_PROTOCOLS.contains(&p.as_str()) {
            return None;
        }
        (p, &line[idx + 3..])
    } else {
        ("socks5".to_string(), line)
    };
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
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy.url()).map_err(|e| e.to_string())?)
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
        if enabled_count >= cap.max(0) {
            return Err(format!("proxy_limit: {enabled_count}/{cap} (N keys → N-1 proxies max)"));
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
