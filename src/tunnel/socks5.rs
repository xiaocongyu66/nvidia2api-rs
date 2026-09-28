//! SOCKS5 客户端出站 (手写协议: greeting + connect 请求)。
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Socks5Target {
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// direct: 不经上游代理, 直接 TCP 连目标 (本地直连/透明网关场景)。
    pub direct: bool,
}

impl Socks5Target {
    pub fn parse(rest: &str) -> Result<Socks5Target, String> {
        let (server, port) = crate::tunnel::outbound::parse_host_port(rest)?;
        let (username, password) = match rest.rsplit_once('@') {
            Some((creds, _)) => {
                let d = crate::tunnel::outbound::pct_decode(creds);
                match d.split_once(':') {
                    Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
                    None => (Some(d), None),
                }
            }
            None => (None, None),
        };
        Ok(Socks5Target { server, port, username, password, direct: false })
    }

    pub fn direct(server: String, port: u16) -> Socks5Target {
        Socks5Target { server, port, username: None, password: None, direct: true }
    }

    pub async fn dial(&self, host: &str, port: u16) -> Result<TcpStream, String> {
        if self.direct {
            return TcpStream::connect((host, port))
                .await
                .map_err(|e| format!("dial {host}:{port}: {e}"));
        }
        let mut s = TcpStream::connect((&self.server as &str, self.port))
            .await
            .map_err(|e| format!("connect proxy {}:{}: {e}", self.server, self.port))?;
        // greeting
        if self.username.is_some() {
            s.write_all(&[0x05, 0x02, 0x00, 0x02]).await.map_err(|e| e.to_string())?;
        } else {
            s.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| e.to_string())?;
        }
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await.map_err(|e| e.to_string())?;
        if resp[1] == 0x02 {
            let u = self.username.clone().unwrap_or_default();
            let p = self.password.clone().unwrap_or_default();
            let mut auth = vec![0x01, u.len() as u8];
            auth.extend_from_slice(u.as_bytes());
            auth.push(p.len() as u8);
            auth.extend_from_slice(p.as_bytes());
            s.write_all(&auth).await.map_err(|e| e.to_string())?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await.map_err(|e| e.to_string())?;
            if ar[1] != 0x00 {
                return Err("socks auth failed".into());
            }
        } else if resp[1] != 0x00 {
            return Err("socks no acceptable auth".into());
        }
        // connect
        let mut req = vec![0x05, 0x01, 0x00];
        req.extend(crate::tunnel::outbound::socks_addr_block(host, port));
        s.write_all(&req).await.map_err(|e| e.to_string())?;
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.map_err(|e| e.to_string())?;
        if head[1] != 0x00 {
            return Err(format!("socks connect refused ({})", head[1]));
        }
        // 跳过绑定地址
        match head[3] {
            0x01 => {
                let mut rest = [0u8; 6];
                s.read_exact(&mut rest).await.map_err(|e| e.to_string())?;
            }
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.map_err(|e| e.to_string())?;
                let mut rest = vec![0u8; l[0] as usize + 2];
                s.read_exact(&mut rest).await.map_err(|e| e.to_string())?;
            }
            0x04 => {
                let mut rest = [0u8; 18];
                s.read_exact(&mut rest).await.map_err(|e| e.to_string())?;
            }
            _ => {}
        }
        Ok(s)
    }
}
