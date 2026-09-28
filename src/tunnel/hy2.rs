//! Hysteria2 出站 — 完整协议还原 (对齐 apernet/hysteria v2)。
//! 1. QUIC 连接 (可选 salamander 混淆, ALPN h3)
//! 2. HTTP/3 POST hysteria/auth, 头 Hysteria-Auth / Hysteria-CC-RX; 成功码 233
//! 3. TCP: bi 流上 varint 帧 [0x401][addrLen][socks地址块][padLen]
use crate::tunnel::outbound::{parse_host_port, pct_decode, socks_addr_block};
use crate::tunnel::stream::BoxStream;
use crate::tunnel::trojan::query_param;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FRAME_TCP_REQUEST: u64 = 0x401;
const AUTH_OK_STATUS: u16 = 233;

pub struct Hy2Target {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
}

impl Hy2Target {
    pub fn parse(rest: &str) -> Result<Hy2Target, String> {
        let (server, port) = parse_host_port(rest)?;
        let password = match rest.rsplit_once('@') {
            Some((creds, _)) => pct_decode(creds),
            None => String::new(),
        };
        let sni = query_param(rest, "sni").or_else(|| query_param(rest, "peer"));
        let insecure = query_param(rest, "insecure").as_deref() == Some("1")
            || query_param(rest, "allowInsecure").as_deref() == Some("1");
        let obfs = query_param(rest, "obfs").filter(|s| s != "none");
        let obfs_password = query_param(rest, "obfs-password")
            .or_else(|| query_param(rest, "obfsParam"))
            .map(|s| pct_decode(&s));
        Ok(Hy2Target { server, port, password, sni, insecure, obfs, obfs_password })
    }

    pub async fn dial(&self, host: &str, port: u16) -> Result<BoxStream, String> {
        let (conn, ctrl) = pooled_conn(self).await?;
        // TCP 请求帧: varint 0x401 + varint addrLen + "host:port" 文本 + varint padLen(0)
        // (hysteria2 传 txthinking socks5 Request.Address() = 文本形式; IPv6 需方括号)
        let addr = text_addr(host, port);
        let mut w = Vec::with_capacity(addr.len() + 16);
        write_varint(&mut w, FRAME_TCP_REQUEST);
        write_varint(&mut w, addr.len() as u64);
        w.extend_from_slice(addr.as_bytes());
        write_varint(&mut w, 0); // padding len
        let (mut tx, mut rx) = conn.open_bi().await.map_err(|e| format!("open_bi: {e}"))?;
        eprintln!("[hy2] tcp frame: {} bytes to {host}:{port}", w.len());
        tx.write_all(&w).await.map_err(|e| e.to_string())?;
        // 响应: status(1) + varint msgLen + msg + varint padLen (10s 兜底)
        let mut status = [0u8; 1];
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx.read_exact(&mut status)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("tcp resp: {e}")),
            Err(_) => return Err("tcp resp: timeout (10s), 服务端未回帧".into()),
        }
        eprintln!("[hy2] tcp resp status={}", status[0]);
        let msg_len = read_varint(&mut rx).await? as usize;
        if msg_len > 0 {
            let mut msg = vec![0u8; msg_len];
            rx.read_exact(&mut msg).await.map_err(|e| e.to_string())?;
        }
        let pad_len = read_varint(&mut rx).await?;
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len as usize];
            rx.read_exact(&mut pad).await.map_err(|e| e.to_string())?;
        }
        if status[0] != 0 {
            return Err(format!("hy2 dial refused ({})", status[0]));
        }
        Ok(Box::new(Hy2Io {
            tx: Some(tx),
            rx: Some(rx),
            conn,
            _ctrl: ctrl,
            write_fut: None,
            read_fut: None,
        }))
    }
}

pub struct Hy2Io {
    /// poll 期间被 future 暂时取走, 用 Option 承载
    tx: Option<quinn::SendStream>,
    rx: Option<quinn::RecvStream>,
    conn: quinn::Connection,
    /// 保持 h3 SendRequest 存活 (Drop 会关连接)
    _ctrl: H3Ctrl,
    write_fut: Option<Pin<Box<dyn std::future::Future<Output = (Result<usize, quinn::WriteError>, quinn::SendStream)> + Send>>>,
    read_fut: Option<Pin<Box<dyn std::future::Future<Output = (Result<Vec<u8>, String>, quinn::RecvStream)> + Send>>>,
}

// 流结束不再 close 整个连接! conn 是池内共享的, close 会杀死池 (每次请求完关一次=池失效=反复握手=抖动真凶)
// bi-stream 的 tx/rx Drop 时自然关闭单条流, 连接生命周期由池的空闲过期管理

impl tokio::io::AsyncWrite for Hy2Io {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // 关键: future 持有被 take 出的 tx 并在完成后归还; poll 用真实 cx —
        // now_or_never 会丢 waker (quinn 缓冲一满就永久挂起)
        let this = self.get_mut();
        if this.write_fut.is_none() {
            let tx = this.tx.take().expect("hy2 tx taken twice");
            let b = buf.to_vec();
            this.write_fut = Some(Box::pin(async move {
                let mut tx = tx;
                let r = tx.write(&b).await;
                (r, tx)
            }));
        }
        match this.write_fut.as_mut().unwrap().as_mut().poll(cx) {
            std::task::Poll::Ready((Ok(n), tx)) => {
                this.tx = Some(tx);
                this.write_fut = None;
                std::task::Poll::Ready(Ok(n))
            }
            std::task::Poll::Ready((Err(e), tx)) => {
                this.tx = Some(tx);
                this.write_fut = None;
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(mut tx) = this.tx.take() {
            let _ = tx.finish();
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncRead for Hy2Io {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.read_fut.is_none() {
            let rx = this.rx.take().expect("hy2 rx taken twice");
            let want = out.remaining().max(1);
            this.read_fut = Some(Box::pin(async move {
                let mut rx = rx;
                let mut buf = vec![0u8; want];
                let r = match rx.read(&mut buf).await {
                    Ok(n) => {
                        let n = n.unwrap_or(0);
                        buf.truncate(n);
                        Ok(buf)
                    }
                    Err(e) => Err(e.to_string()),
                };
                (r, rx)
            }));
        }
        match this.read_fut.as_mut().unwrap().as_mut().poll(cx) {
            std::task::Poll::Ready((Ok(data), rx)) => {
                this.rx = Some(rx);
                this.read_fut = None;
                out.put_slice(&data);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready((Err(e), rx)) => {
                this.rx = Some(rx);
                this.read_fut = None;
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// hysteria2 地址文本形式: "host:port" (IPv6 加方括号)。
fn text_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// --- QUIC varint (hysteria 帧同 QUIC varint 编码) ---
pub(crate) fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v <= 63 {
        out.push(v as u8);
    } else if v <= 16383 {
        out.push(0x40 | (v >> 8) as u8);
        out.push(v as u8);
    } else if v <= 1073741823 {
        out.push(0x80 | (v >> 24) as u8);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    } else {
        out.push(0xc0 | (v >> 56) as u8);
        out.push((v >> 48) as u8);
        out.push((v >> 40) as u8);
        out.push((v >> 32) as u8);
        out.push((v >> 24) as u8);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    }
}

pub(crate) async fn read_varint(r: &mut quinn::RecvStream) -> Result<u64, String> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first).await.map_err(|e| e.to_string())?;
    let prefix = first[0] >> 6;
    let mut v = (first[0] & 0x3f) as u64;
    let extra = match prefix {
        0 => 0,
        1 => 1,
        2 => 3,
        _ => 7,
    };
    if extra > 0 {
        let mut rest = vec![0u8; extra];
        r.read_exact(&mut rest).await.map_err(|e| e.to_string())?;
        for b in rest {
            v = (v << 8) | b as u64;
        }
    }
    Ok(v)
}

// --- QUIC 连接 + HTTP/3 auth ---
type H3Ctrl = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

/// hy2 连接池: 同 target 复用 QUIC 连接 (避免每请求重握手 — 抖动大头)
/// key = "server:port:password" ; 值持 conn + ctrl (ctrl 保活计数)
static POOL: std::sync::OnceLock<tokio::sync::Mutex<std::collections::HashMap<String, (quinn::Connection, H3Ctrl, std::time::Instant)>>> =
    std::sync::OnceLock::new();
const POOL_IDLE_SECS: u64 = 240;

fn pool() -> &'static tokio::sync::Mutex<std::collections::HashMap<String, (quinn::Connection, H3Ctrl, std::time::Instant)>> {
    POOL.get_or_init(|| tokio::sync::Mutex::new(std::collections::HashMap::new()))
}

async fn pooled_conn(t: &Hy2Target) -> Result<(quinn::Connection, H3Ctrl), String> {
    let key = format!("{}:{}:{}", t.server, t.port, t.password);
    // 快路径: 池内有活连接 (校验 RTT: closed 判定用 stat, 失败即重建)
    {
        let mut m = pool().lock().await;
        // 清过期
        m.retain(|_, (_, _, at)| at.elapsed() < std::time::Duration::from_secs(POOL_IDLE_SECS));
        if let Some((conn, ctrl, at)) = m.get_mut(&key) {
            if conn.close_reason().is_none() {
                *at = std::time::Instant::now();
                return Ok((conn.clone(), ctrl.clone()));
            }
            m.remove(&key);
        }
    }
    // 慢路径: 新建 (持锁重查防并发重复建)
    let mut m = pool().lock().await;
    if let Some((conn, ctrl, at)) = m.get_mut(&key) {
        if conn.close_reason().is_none() {
            *at = std::time::Instant::now();
            return Ok((conn.clone(), ctrl.clone()));
        }
        m.remove(&key);
    }
    let (conn, ctrl) = open_conn(t).await?;
    m.insert(key, (conn.clone(), ctrl.clone(), std::time::Instant::now()));
    Ok((conn, ctrl))
}

async fn open_conn(t: &Hy2Target) -> Result<(quinn::Connection, H3Ctrl), String> {
    let (conn, _endpoint) = match (&t.obfs, &t.obfs_password) {
        (Some(o), Some(pw)) if o == "salamander" => {
            let sm = crate::tunnel::salamander::Salamander::new(pw)?;
            use tokio::net::ToSocketAddrs;
            let server_addr = tokio::net::lookup_host((t.server.as_str(), t.port))
                .await
                .map_err(|e| format!("resolve {}: {e}", t.server))?
                .next()
                .ok_or("resolve: no addr")?;
            let relay_addr = crate::tunnel::salamander::spawn_relay(sm, server_addr).await?;
            let mut endpoint =
                quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).map_err(|e| format!("endpoint: {e}"))?;
            let tls = make_tls(t.insecure)?;
            let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
                .map_err(|e| format!("quic tls: {e}"))?;
            let mut transport = quinn::TransportConfig::default();
            transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
            let mut client_cfg = quinn::ClientConfig::new(Arc::new(qcc));
            client_cfg.transport_config(Arc::new(transport));
            endpoint.set_default_client_config(client_cfg);
            let conn = endpoint
                .connect(relay_addr, &server_name_of(t))
                .map_err(|e| format!("connect: {e}"))?
                .await
                .map_err(|e| format!("quic handshake: {e}"))?;
            (conn, endpoint)
        }
        _ => {
            let addr = std::net::SocketAddr::new(
                crate::tunnel::resolve::resolve_one(&t.server).await?,
                t.port,
            );
            let mut endpoint =
                quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(|e| format!("endpoint: {e}"))?;
            let tls = make_tls(t.insecure)?;
            let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
                .map_err(|e| format!("quic tls: {e}"))?;
            let mut transport = quinn::TransportConfig::default();
            transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
            let mut client_cfg = quinn::ClientConfig::new(Arc::new(qcc));
            client_cfg.transport_config(Arc::new(transport));
            endpoint.set_default_client_config(client_cfg);
            let conn = endpoint
                .connect(addr, &server_name_of(t))
                .map_err(|e| format!("connect: {e}"))?
                .await
                .map_err(|e| format!("quic handshake: {e}"))?;
            (conn, endpoint)
        }
    };
    let ctrl = auth_h3(t, &conn).await.map_err(|e| format!("h3 auth: {e}"))?;
    Ok((conn, ctrl))
}

fn server_name_of(t: &Hy2Target) -> String {
    t.sni.clone().unwrap_or_else(|| t.server.clone())
}

/// HTTP/3 auth: POST https://hysteria/auth, 头 Hysteria-Auth / Hysteria-CC-RX; 成功 = 233。
async fn auth_h3(t: &Hy2Target, conn: &quinn::Connection) -> Result<H3Ctrl, String> {
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut ctrl): (_, H3Ctrl) =
        h3::client::builder().build(h3_conn).await.map_err(|e| e.to_string())?;
    // Connection 驱动循环: poll_closed
    tokio::spawn(async move {
        let err = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
        eprintln!("[hy2] h3 driver ended: {err:?}");
    });
    let uri = http::Uri::builder()
        .scheme("https")
        .authority("hysteria")
        .path_and_query("/auth")
        .build()
        .map_err(|e| e.to_string())?;
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("hysteria-auth", t.password.as_str())
        .header("hysteria-cc-rx", "0")
        .body(())
        .map_err(|e| e.to_string())?;
    let mut stream = ctrl.send_request(req).await.map_err(|e| e.to_string())?;
    let _ = stream.finish().await;
    let resp: http::Response<()> = stream.recv_response().await.map_err(|e| e.to_string())?;
    eprintln!("[hy2] auth status: {} headers: {:?}", resp.status(), resp.headers().get("hysteria-cc-rx"));
    if resp.status().as_u16() != AUTH_OK_STATUS {
        return Err(format!("auth rejected: status {}", resp.status()));
    }
    Ok(ctrl) // 必须持有: Drop 会关闭整个连接 (sender_count 归零)
}

fn make_tls(insecure: bool) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let mut tls = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    tls.alpn_protocols = vec![b"h3".to_vec()]; // hysteria2 v2 auth 走 HTTP/3
    Ok(tls)
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ED25519]
    }
}
