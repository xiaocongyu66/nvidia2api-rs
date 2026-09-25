//! 线路构建——Key 与代理的配对调度 (原版 load_balancer.py 语义)。
//!
//! 规则:
//! - 线路数 = min(启用代理数 + 1 直连, 可用 Key 数, max_routes_per_request)
//! - 每条线路绑定**不同**的 NVIDIA Key (RPM 槽位原子抢占, 抢不到则跳过)
//! - 代理占用前 route_count-1 条线路, 最后一条必为直连

use crate::key_pool;
use crate::models::Proxy;
use crate::race::Route;

/// 可调度代理: 启用 + 健康/未知 + 不在冷却, 按延迟升序。
pub fn schedulable_proxies() -> Vec<Proxy> {
    let now = crate::storage::now_iso();
    let conn = crate::storage::db();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, protocol, host, port, username, password, group_id, country, region, city, isp, \
             enabled, status, latency_ms, public_ip, last_check_at, success_count, failure_count, \
             consecutive_failures, cooldown_until, created_at \
             FROM proxy WHERE enabled = 1 AND status != 'unhealthy' \
             AND (cooldown_until IS NULL OR cooldown_until <= ?1) \
             ORDER BY CASE WHEN latency_ms IS NULL THEN 1 ELSE 0 END, latency_ms ASC",
        )
        .unwrap();
    let rows = stmt.query_map([&now], |r| {
        Ok(Proxy {
            id: r.get(0)?,
            name: r.get(1)?,
            protocol: r.get(2)?,
            host: r.get(3)?,
            port: r.get(4)?,
            username: r.get(5)?,
            password: r.get(6)?,
            group_id: r.get(7)?,
            country: r.get(8)?,
            region: r.get(9)?,
            city: r.get(10)?,
            isp: r.get(11)?,
            enabled: r.get::<_, i64>(12)? != 0,
            status: r.get(13)?,
            latency_ms: r.get(14)?,
            public_ip: r.get(15)?,
            last_check_at: r.get(16)?,
            success_count: r.get(17)?,
            failure_count: r.get(18)?,
            consecutive_failures: r.get(19)?,
            cooldown_until: r.get(20)?,
            created_at: r.get(21)?,
        })
    });
    match rows {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    }
}

pub fn build_routes(max_routes: Option<usize>, cfg_max: usize) -> Vec<Route> {
    let cap = max_routes.unwrap_or(cfg_max).min(cfg_max);
    let proxies = schedulable_proxies();
    let keys = key_pool::available_keys();

    let route_count = (proxies.len() + 1).min(keys.len()).min(cap);
    if route_count == 0 {
        return vec![];
    }
    let proxies = &proxies[..(route_count - 1).min(proxies.len())];

    let mut routes = Vec::with_capacity(route_count);
    for i in 0..route_count {
        let key = &keys[i];
        if !key_pool::claim_rpm_slot(key.id) {
            continue; // RPM 槽位被并发抢走 → 跳过该线
        }
        let proxy = proxies.get(i).cloned();
        routes.push(Route {
            key: key.clone(),
            proxy,
        });
    }
    routes
}

/// 启用代理上限校验: N 个 Key → 最多 N-1 代理 (原版强制规则)。
pub fn max_proxies_for_keys(total_schedulable_keys: usize) -> usize {
    total_schedulable_keys.saturating_sub(1)
}
