//! 出站抽象: 按分享链接构造, 统一 connect(host, port) → 双向流。
use crate::tunnel::stream::BoxStream;
use crate::tunnel::{hy2, socks5, ss, trojan, vless};

pub enum Outbound {
    Socks5(socks5::Socks5Target),
    Trojan(trojan::TrojanTarget),
    Vless(vless::VlessTarget, String),
    Shadowsocks(ss::SsTarget),
    Hy2(hy2::Hy2Target),
}

impl Outbound {
    pub fn from_link(link: &str) -> Result<Outbound, String> {
        let (scheme_raw, rest) = link.split_once("://").ok_or("missing scheme")?;
        let scheme = scheme_raw.to_ascii_lowercase();
        match scheme.as_str() {
            "socks" | "socks5" | "socks5h" => Ok(Outbound::Socks5(socks5::Socks5Target::parse(rest)?)),
            "trojan" | "tj" => Ok(Outbound::Trojan(trojan::TrojanTarget::parse(rest)?)),
            "vless" => Ok(Outbound::Vless(vless::VlessTarget::parse(rest)?, rest.to_string())),
            "ss" => Ok(Outbound::Shadowsocks(ss::SsTarget::parse(rest)?)),
            "hy2" | "hysteria2" => Ok(Outbound::Hy2(hy2::Hy2Target::parse(rest)?)),
            "http" | "https" => {
                // 上游 http 代理: 复用 SOCKS5 通道没有意义, reqwest 直连支持 — 这里按
                // mixed 入站架构退化为直接 tcp 直连 (上游为透明网关场景)。
                let (server, port) = parse_host_port(rest)?;
                Ok(Outbound::Socks5(socks5::Socks5Target::direct(server, port)))
            }
            other => Err(format!("unsupported scheme: {other}")),
        }
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<BoxStream, String> {
        match self {
            Outbound::Socks5(t) => Ok(Box::new(t.dial(host, port).await?)),
            Outbound::Trojan(t) => t.dial(host, port).await,
            Outbound::Vless(t, hint) => t.dial(hint, host, port).await,
            Outbound::Shadowsocks(t) => t.dial(host, port).await,
            Outbound::Hy2(t) => t.dial(host, port).await,
        }
    }
}

/// 百分号解码 (来自 relay, 无循环依赖复制一份轻量实现)。
pub fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn parse_host_port(rest: &str) -> Result<(String, u16), String> {
    let hostpart = rest.rsplit('@').next().unwrap_or(rest);
    let hostpart = hostpart.split(['/', '?', '#']).next().unwrap_or(hostpart);
    match hostpart.rsplit_once(':') {
        Some((h, p)) => Ok((
            h.trim_matches(|c| c == '[' || c == ']').to_string(),
            p.parse().map_err(|_| "bad port")?,
        )),
        None => Err("missing port".into()),
    }
}

/// SOCKS5 地址块编码 (ATYP + addr + port), 供 trojan/vless/ss 共用。
pub fn socks_addr_block(host: &str, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        out.push(0x01);
        out.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        out.push(0x04);
        out.extend_from_slice(&ip.octets());
    } else {
        out.push(0x03);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}
