//! VLESS 出站 (手写: [version]uuid[addon]cmd addr + payload)。
use crate::tunnel::stream::BoxStream;
use crate::tunnel::trojan::query_param;
use tokio::io::AsyncWriteExt;

pub struct VlessTarget {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub sni: Option<String>,
    pub insecure: bool,
}

impl VlessTarget {
    pub fn parse(rest: &str) -> Result<VlessTarget, String> {
        let (server, port) = crate::tunnel::outbound::parse_host_port(rest)?;
        let uuid = match rest.rsplit_once('@') {
            Some((creds, _)) => crate::tunnel::outbound::pct_decode(creds),
            None => return Err("vless link missing uuid".into()),
        };
        let sni = query_param(rest, "sni");
        let insecure = query_param(rest, "allowInsecure").as_deref() == Some("1");
        Ok(VlessTarget { server, port, uuid, sni, insecure })
    }

    pub async fn dial(&self, rest_hint: &str, host: &str, port: u16) -> Result<BoxStream, String> {
        let uid = parse_uuid(&self.uuid)?;
        // 请求: version(1)=0 + uuid(16) + addon_len(1)=0 + command(1)=1(tcp) + port(2BE) + addr
        let mut req = Vec::with_capacity(24);
        req.push(0x00);
        req.extend_from_slice(&uid);
        req.push(0x00); // addon len
        req.push(0x01); // TCP
        req.extend_from_slice(&port.to_be_bytes());
        req.extend(crate::tunnel::outbound::socks_addr_block(host, port));
        // type=ws → TLS + WebSocket 升级, vless 帧在 binary 帧内
        let transport = query_param(rest_hint, "type").unwrap_or_default();
        let tls = crate::tunnel::tls_util::tls_connect(&self.server, self.port, self.sni.as_deref(), self.insecure).await?;
        if transport == "ws" {
            let path = query_param(rest_hint, "path").unwrap_or_else(|| "/".to_string());
            let ws_host = query_param(rest_hint, "host").unwrap_or_else(|| self.server.clone());
            let mut ws = crate::tunnel::ws::handshake(Box::new(tls), &ws_host, &path).await?;
            ws.write_all(&req).await.map_err(|e| e.to_string())?;
            Ok(ws)
        } else {
            let mut tls = tls;
            tls.write_all(&req).await.map_err(|e| e.to_string())?;
            Ok(Box::new(tls))
        }
    }
}

pub(crate) fn parse_uuid(s: &str) -> Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return Err(format!("invalid uuid: {s}"));
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).ok_or("uuid")? as u8;
        let lo = (chunk[1] as char).to_digit(16).ok_or("uuid")? as u8;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}
