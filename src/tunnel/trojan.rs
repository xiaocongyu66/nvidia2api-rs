//! Trojan 出站 (手写: TLS + sha224 密码 + CRLF 定界帧)。
use crate::tunnel::stream::BoxStream;
use tokio::io::AsyncWriteExt;

pub struct TrojanTarget {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
}

impl TrojanTarget {
    pub fn parse(rest: &str) -> Result<TrojanTarget, String> {
        let (server, port) = crate::tunnel::outbound::parse_host_port(rest)?;
        let password = match rest.rsplit_once('@') {
            Some((creds, _)) => crate::tunnel::outbound::pct_decode(creds),
            None => return Err("trojan link missing password".into()),
        };
        let sni = query_param(rest, "sni");
        let insecure = query_param(rest, "allowInsecure").as_deref() == Some("1")
            || query_param(rest, "insecure").as_deref() == Some("1");
        Ok(TrojanTarget { server, port, password, sni, insecure })
    }

    pub async fn dial(&self, host: &str, port: u16) -> Result<BoxStream, String> {
        let mut tls =
            crate::tunnel::tls_util::tls_connect(&self.server, self.port, self.sni.as_deref(), self.insecure).await?;
        let hash = {
            use sha2::Digest;
            let h = sha2::Sha224::digest(self.password.as_bytes());
            h.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        let mut head = Vec::with_capacity(64);
        head.extend_from_slice(hash.as_bytes());
        head.extend_from_slice(b"\r\n");
        head.extend(crate::tunnel::outbound::socks_addr_block(host, port));
        head.extend_from_slice(b"\r\n");
        tls.write_all(&head).await.map_err(|e| e.to_string())?;
        Ok(Box::new(tls))
    }
}

pub(crate) fn query_param(rest: &str, key: &str) -> Option<String> {
    let query = rest.split_once('?').map(|(_, q)| q)?;
    let query = query.split('#').next().unwrap_or(query); // 剥 fragment
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return Some(crate::tunnel::outbound::pct_decode(v));
            }
        }
    }
    None
}
