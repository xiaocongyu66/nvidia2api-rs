//! 极简 WebSocket 客户端流 (binary only, 手写帧, 用于 vless+ws)。
//! 握手: TLS 之上 HTTP Upgrade; 之后双向透传 binary 帧 payload。
use crate::tunnel::stream::BoxStream;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct WsStream<S> {
    sock: S,
    r_buf: Vec<u8>,
    pending_frame: Option<(Vec<u8>, usize)>, // (帧, 已写偏移)
    closed: bool,
}

/// 在已建立的 TLS 流上执行 ws 握手并返回帧流。
pub async fn handshake(
    mut tls: crate::tunnel::stream::BoxStream,
    host: &str,
    path: &str,
) -> Result<BoxStream, String> {
    // 握手请求
    let mut key_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let path = if path.is_empty() { "/" } else { path };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    // 读响应头
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        tls.read_exact(&mut byte).await.map_err(|e| e.to_string())?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 16 * 1024 {
            return Err("ws handshake response too large".into());
        }
    }
    let head_str = String::from_utf8_lossy(&head);
    let status = head_str.lines().next().unwrap_or("");
    if !status.contains("101") {
        return Err(format!("ws handshake failed: {status}"));
    }
    Ok(Box::new(WsStream { sock: Unbox(tls), r_buf: Vec::new(), pending_frame: None, closed: false }))
}

/// 把 Box<dyn ProxyStream> 包装回具体类型 (ws 帧解析需要 owned)。
struct Unbox(crate::tunnel::stream::BoxStream);

impl tokio::io::AsyncRead for Unbox {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::pin!(&mut *self.0).poll_read(cx, out)
    }
}

impl tokio::io::AsyncWrite for Unbox {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::pin!(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::pin!(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::pin!(&mut *self.0).poll_shutdown(cx)
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> tokio::io::AsyncRead for WsStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // 已拆帧数据直接交付
        if !this.r_buf.is_empty() {
            let n = std::cmp::min(this.r_buf.len(), out.remaining());
            let data: Vec<u8> = this.r_buf.drain(..n).collect();
            out.put_slice(&data);
            return std::task::Poll::Ready(Ok(()));
        }
        if this.closed {
            return std::task::Poll::Ready(Ok(()));
        }
        // 读一帧
        use futures::FutureExt;
        let fut = read_frame(&mut this.sock);
        let mut fut = Box::pin(fut);
        match fut.poll_unpin(cx) {
            std::task::Poll::Ready(Ok(payload)) => {
                if payload.is_empty() {
                    this.closed = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                let n = std::cmp::min(payload.len(), out.remaining());
                out.put_slice(&payload[..n]);
                this.r_buf.extend_from_slice(&payload[n..]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> tokio::io::AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        // 先把上一帧残余写完
        if this.pending_frame.is_some() {
            std::task::ready!(Self::flush_pending(this, cx))?;
        }
        // 组 binary 帧 (客户端必须 mask)
        let mut frame = Vec::with_capacity(buf.len() + 14);
        frame.push(0x82); // FIN + binary
        let len = buf.len();
        let mask_key = {
            let mut k = [0u8; 4];
            rand::thread_rng().fill_bytes(&mut k);
            k
        };
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= 0xFFFF {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask_key);
        for (i, b) in buf.iter().enumerate() {
            frame.push(b ^ mask_key[i % 4]);
        }
        this.pending_frame = Some((frame, 0));
        // 立即尝试写
        std::task::ready!(Self::flush_pending(this, cx))?;
        std::task::Poll::Ready(Ok(len))
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(Self::flush_pending(self.get_mut(), cx))?;
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.closed = true;
        std::task::Poll::Ready(Ok(()))
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> WsStream<S> {
    fn flush_pending(this: &mut Self, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let Some((frame, pos)) = &mut this.pending_frame else {
            return std::task::Poll::Ready(Ok(()));
        };
        loop {
            match std::pin::Pin::new(&mut this.sock).poll_write(cx, &frame[*pos..]) {
                std::task::Poll::Ready(Ok(n)) => {
                    *pos += n;
                    if *pos >= frame.len() {
                        this.pending_frame = None;
                        return std::task::Poll::Ready(Ok(()));
                    }
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

/// 读一帧 payload (合并分片; 控制帧 ping 回 pong, close → EOF)。
async fn read_frame<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(sock: &mut S) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    let fin = hdr[0] & 0x80 != 0;
    let opcode = hdr[0] & 0x0F;
    let masked = hdr[1] & 0x80 != 0;
    let mut len = (hdr[1] & 0x7F) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        sock.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        sock.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext) as usize;
    }
    let mask_key = if masked {
        let mut k = [0u8; 4];
        sock.read_exact(&mut k).await?;
        Some(k)
    } else {
        None
    };
    let mut payload = vec![0u8; len];
    if len > 0 {
        sock.read_exact(&mut payload).await?;
    }
    if let Some(k) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= k[i % 4];
        }
    }
    match opcode {
        0x1 | 0x2 => Ok(payload), // text/binary
        0x9 => {
            // ping → pong
            let mut pong = vec![0x8A, 0x80];
            pong.extend_from_slice(&[0, 0, 0, 0]);
            pong.extend_from_slice(&payload);
            let _ = sock.write_all(&pong).await;
            Ok(Vec::new())
        }
        0x8 => Ok(Vec::new()), // close
        _ => {
            if fin {
                Ok(Vec::new())
            } else {
                Ok(Vec::new())
            }
        }
    }
}
