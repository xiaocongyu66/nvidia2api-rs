//! 域名解析: 系统 DNS 失败时走 DoH (阿里公共 DNS, 墙内可达)。
use std::net::IpAddr;

/// 解析域名 → IP 列表。系统解析失败时用 DoH 兜底。
pub async fn resolve(host: &str) -> Result<Vec<std::net::IpAddr>, String> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![ip]);
    }
    use tokio::net::ToSocketAddrs;
    if let Ok(addrs) = tokio::net::lookup_host((host, 0u16)).await {
        let ips: Vec<std::net::IpAddr> = addrs.map(|a| a.ip()).collect();
        if !ips.is_empty() {
            return Ok(ips);
        }
    }
    doh_resolve(host).await
}

/// DoH 查询 (RFC8484 JSON API, 阿里 223.5.5.5)。
async fn doh_resolve(host: &str) -> Result<Vec<std::net::IpAddr>, String> {
    let url = format!("http://223.5.5.5/resolve?name={host}&type=A");
    let resp = reqwest::get(&url).await.map_err(|e| format!("doh: {e}"))?;
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("doh json: {e}"))?;
    let mut ips = Vec::new();
    if let Some(answers) = v["Answer"].as_array() {
        for a in answers {
            if a["type"].as_u64() == Some(1) {
                if let Ok(ip) = a["data"].as_str().unwrap_or("").parse::<std::net::IpAddr>() {
                    ips.push(ip);
                }
            }
        }
    }
    if ips.is_empty() {
        return Err(format!("doh: no A record for {host}"));
    }
    Ok(ips)
}

/// 取第一个可用 IP (每次轮换入口)。
pub async fn resolve_one(host: &str) -> Result<std::net::IpAddr, String> {
    Ok(resolve(host).await?.remove(0))
}
