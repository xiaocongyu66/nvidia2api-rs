//! Salamander QUIC 混淆 (对齐 apernet/hysteria extras/obfs/salamander)。
//! 线格式: [8字节随机盐][payload XOR key], key = BLAKE2b-256(PSK || salt)。
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct Salamander {
    psk: Vec<u8>,
}

impl Salamander {
    pub fn new(psk: &str) -> Result<Salamander, String> {
        if psk.len() < 4 {
            return Err("salamander PSK too short".into());
        }
        Ok(Salamander { psk: psk.as_bytes().to_vec() })
    }

    fn key(&self, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).expect("blake2b256");
        hasher.update(&self.psk);
        hasher.update(salt);
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).expect("blake2b256 finalize");
        out
    }

    pub fn obfuscate(&self, plain: &[u8], salt: &[u8; 8]) -> Vec<u8> {
        let key = self.key(salt);
        let mut out = Vec::with_capacity(8 + plain.len());
        out.extend_from_slice(salt);
        for (i, b) in plain.iter().enumerate() {
            out.push(b ^ key[i % 32]);
        }
        out
    }

    pub fn deobfuscate(&self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() <= 8 {
            return None;
        }
        let key = self.key(&wire[..8]);
        Some(wire[8..].iter().enumerate().map(|(i, b)| b ^ key[i % 32]).collect())
    }
}

/// 本地 UDP 中继: quinn → [relay_sock] 混淆 → [wire_sock] → 服务器; 回程反向。
/// 返回 quinn 应连接并绑定的地址 (quinn bind 在返回值 127.0.0.1:0, connect 到 relay)。
pub async fn spawn_relay(sm: Salamander, server: SocketAddr) -> Result<SocketAddr, String> {
    let relay_sock = UdpSocket::bind("127.0.0.1:0").await.map_err(|e| format!("bind relay: {e}"))?;
    let relay_addr = relay_sock.local_addr().map_err(|e| e.to_string())?;
    let wire_sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| format!("bind wire: {e}"))?;
    let quinn_peer = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));
    tokio::spawn(async move {
        let mut buf_a = vec![0u8; 65536];
        let mut buf_b = vec![0u8; 65536];
        loop {
            tokio::select! {
                // quinn → 服务器: 记录 quinn 源地址, 混淆后从 wire 发出
                r = relay_sock.recv_from(&mut buf_a) => {
                    match r {
                        Ok((n, from)) => {
                            *quinn_peer.lock().unwrap() = Some(from);
                            let salt = rand_salt();
                            let wire = sm.obfuscate(&buf_a[..n], &salt);
                            let _ = wire_sock.send_to(&wire, server).await;
                        }
                        Err(_) => break,
                    }
                }
                // 服务器 → quinn: 去混淆后送回 quinn 源地址
                r = wire_sock.recv_from(&mut buf_b) => {
                    match r {
                        Ok((n, from)) => {
                            if from == server {
                                if let Some(plain) = sm.deobfuscate(&buf_b[..n]) {
                                    let q = *quinn_peer.lock().unwrap();
                                    if let Some(q) = q {
                                        let _ = relay_sock.send_to(&plain, q).await;
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });
    Ok(relay_addr)
}

fn rand_salt() -> [u8; 8] {
    use rand::RngCore;
    let mut s = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

fn local_addr_pair(a: &SocketAddr) -> Option<SocketAddr> {
    Some(*a)
}

fn loopback_of(a: &SocketAddr) -> SocketAddr {
    *a
}
