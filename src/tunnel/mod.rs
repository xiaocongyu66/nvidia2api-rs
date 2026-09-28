//! 纯 Rust 自实现的代理数据面: 本地 mixed 入站 (HTTP CONNECT + SOCKS5) → 隧道出站。
//! 无外部进程依赖 (不使用 sing-box); 加密/QUIC 仅用原语级 crate。
pub mod hy2;
pub mod resolve;
pub mod salamander;
pub mod stream;
pub mod outbound;
pub mod socks5;
pub mod ss;
pub mod tls_util;
pub mod trojan;
pub mod vless;
pub mod ws;

use crate::tunnel::outbound::Outbound;
use crate::tunnel::stream::BoxStream;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 从入站流读取 CONNECT 目标 (host, port)。
/// is_http: HTTP CONNECT (首行 "CONNECT host:port HTTP/1.1")；否则 SOCKS5。
pub async fn read_target(is_http: bool, sock: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<(String, u16), String> {
    if is_http {
        let mut buf = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            sock.read_exact(&mut byte).await.map_err(|e| e.to_string())?;
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() > 8 * 1024 {
                return Err("http request too large".into());
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let line = head.lines().next().unwrap_or("");
        let mut parts = line.split_whitespace();
        let _method = parts.next().ok_or("bad request")?;
        let target = parts.next().ok_or("missing target")?;
        // 两种形式: authority-form "host:port" (CONNECT) / absolute-form "http://host:port/path" (普通代理 GET)
        // 默认端口: https→443, 其余→80
        let (authority, default_port) = if let Some(rest) = target.strip_prefix("https://") {
            (rest.split('/').next().unwrap_or(rest), 443u16)
        } else if let Some(rest) = target.strip_prefix("http://") {
            (rest.split('/').next().unwrap_or(rest), 80u16)
        } else {
            (target, 80u16)
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "bad port")?),
            None => (authority.to_string(), default_port),
        };
        Ok((host, port))
    } else {
        // SOCKS5: 跳过握手(入站握手在 handler 完成), 读请求头
        let mut hdr = [0u8; 4];
        sock.read_exact(&mut hdr).await.map_err(|e| e.to_string())?;
        // hdr = VER CMD RSV ATYP
        let atyp = hdr[3];
        let host = match atyp {
            0x01 => {
                let mut ip = [0u8; 4];
                sock.read_exact(&mut ip).await.map_err(|e| e.to_string())?;
                std::net::Ipv4Addr::from(ip).to_string()
            }
            0x03 => {
                let mut len = [0u8; 1];
                sock.read_exact(&mut len).await.map_err(|e| e.to_string())?;
                let mut name = vec![0u8; len[0] as usize];
                sock.read_exact(&mut name).await.map_err(|e| e.to_string())?;
                String::from_utf8_lossy(&name).to_string()
            }
            0x04 => {
                let mut ip = [0u8; 16];
                sock.read_exact(&mut ip).await.map_err(|e| e.to_string())?;
                std::net::Ipv6Addr::from(ip).to_string()
            }
            other => return Err(format!("bad atyp {other}")),
        };
        let mut port = [0u8; 2];
        sock.read_exact(&mut port).await.map_err(|e| e.to_string())?;
        Ok((host, u16::from_be_bytes(port)))
    }
}

/// 处理一条入站连接: 目标解析 → 出站拨号 → 双向拷贝。
pub async fn serve_inbound_conn(is_http: bool, mut sock: tokio::net::TcpStream, ob: Arc<Outbound>) {
    eprintln!("[tunnel] serve: is_http={is_http}");
    let result: Result<(), String> = async {
        if is_http {
            // 读完整请求头, 解析目标
            let (host, port, head_bytes) = read_http_head(&mut sock).await?;
            eprintln!("[tunnel] head: {host}:{port} ({} bytes)", head_bytes.len());
            // 先拨号 — 失败回 502
            let mut remote = match ob.connect(&host, port).await {
                Ok(r) => r,
                Err(e) => {
                    sock.write_all(format!("HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n").as_bytes()).await.ok();
                    return Err(e);
                }
            };
            if head_is_connect(&head_bytes) {
                sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.ok();
            } else {
                // 普通代理 GET: 原样转发请求 (改写 Host 已在原头里)
                remote.write_all(&head_bytes).await.map_err(|e| e.to_string())?;
            }
            bidirectional(&mut sock, &mut remote).await;
            Ok(())
        } else {
            // SOCKS5 握手: 支持无认证
            let mut n = [0u8; 2];
            sock.read_exact(&mut n).await.map_err(|e| e.to_string())?;
            let mut methods = vec![0u8; n[1] as usize];
            sock.read_exact(&mut methods).await.map_err(|e| e.to_string())?;
            sock.write_all(&[0x05, 0x00]).await.ok();
            let (host, port) = read_target(false, &mut sock).await?;
            // 尝试拨号, 失败回 0x05
            match ob.connect(&host, port).await {
                Ok(mut remote) => {
                    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.ok();
                    bidirectional(&mut sock, &mut remote).await;
                    Ok(())
                }
                Err(_) => {
                    sock.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.ok();
                    Err(format!("dial {host}:{port} failed"))
                }
            }
        }
    }
    .await;
    if let Err(e) = result {
        eprintln!("[tunnel] conn ended: {e}");
    }
}

/// 读完整 HTTP 请求头, 返回 (host, port, 原始头字节)。
pub async fn read_http_head(sock: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<(String, u16, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        sock.read_exact(&mut byte).await.map_err(|e| e.to_string())?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 32 * 1024 {
            return Err("http request too large".into());
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let line = head.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let _method = parts.next().ok_or("bad request")?;
    let target = parts.next().ok_or("missing target")?;
    let (authority, default_port) = if let Some(rest) = target.strip_prefix("https://") {
        (rest.split('/').next().unwrap_or(rest), 443u16)
    } else if let Some(rest) = target.strip_prefix("http://") {
        (rest.split('/').next().unwrap_or(rest), 80u16)
    } else {
        (target, 80u16)
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "bad port")?),
        None => (authority.to_string(), default_port),
    };
    Ok((host, port, buf))
}

fn head_is_connect(head: &[u8]) -> bool {
    head.starts_with(b"CONNECT ")
}

pub async fn bidirectional(a: &mut tokio::net::TcpStream, b: &mut crate::tunnel::stream::BoxStream) {
    let (mut ar, mut aw) = tokio::io::split(a);
    let b = std::mem::replace(b, Box::new(tokio::io::duplex(64).0));
    let (mut br, mut bw) = tokio::io::split(b);
    let up = tokio::io::copy(&mut ar, &mut bw);
    let down = tokio::io::copy(&mut br, &mut aw);
    let (up_res, down_res) = tokio::join!(up, down);
    eprintln!(
        "[tunnel] copy done: up={} ({}) down={} ({})",
        up_res.as_ref().unwrap_or(&0),
        if up_res.is_ok() { "ok" } else { "err" },
        down_res.as_ref().unwrap_or(&0),
        if down_res.is_ok() { "ok" } else { "err" },
    );
    let _ = aw.shutdown().await;
    let _ = bw.shutdown().await;
}

/// 本地 mixed 监听 (127.0.0.1:port): peek 首字节判协议 —
/// 0x05 = SOCKS5, 大写 ASCII = HTTP (CONNECT / 普通代理 GET)。
pub async fn spawn_mixed(port: u16, ob: Arc<Outbound>) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("bind {port}: {e}"))?;
    eprintln!("[tunnel] mixed 入站已监听 127.0.0.1:{port}");
    loop {
        let Ok((sock, _)) = listener.accept().await else {
            continue;
        };
        let ob = ob.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1];
            let mut sock = sock;
            if sock.peek(&mut buf).await.unwrap_or(0) == 0 {
                return;
            }
            let is_http = buf[0] != 0x05;
            serve_inbound_conn(is_http, sock, ob).await;
        });
    }
}
