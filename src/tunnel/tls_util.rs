//! TLS 工具: 自实现出站的 TLS 连接 (rustls, 默认校验/不校验两种配置)。
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

fn tls_config(insecure: bool) -> Result<Arc<rustls::ClientConfig>, String> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?;
    let cfg = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoVerify))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(root_store()).with_no_client_auth()
    };
    Ok(Arc::new(cfg))
}

fn root_store() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }
}

/// 建立 TLS 连接。insecure=true 时跳过证书校验 (自签/中转节点常用)。
/// 对已有流做 TLS 客户端握手 (隧道出口场景: 连接已在隧道里建好)。
pub async fn tls_wrap<I>(io: I, host: &str, sni: Option<&str>, insecure: bool) -> Result<TlsStream<I>, String>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let cfg = tls_config(insecure)?;
    let connect_host = sni.unwrap_or(host);
    let server_name = ServerName::try_from(connect_host.to_string()).map_err(|e| format!("sni: {e}"))?;
    let stream = tokio_rustls::TlsConnector::from(cfg)
        .connect(server_name, io)
        .await
        .map_err(|e| format!("tls handshake: {e}"))?;
    Ok(stream)
}

pub async fn tls_connect(host: &str, port: u16, sni: Option<&str>, insecure: bool) -> Result<TlsStream<TcpStream>, String> {
    // DNS 污染兜底: TCP 连解析后的 IP, SNI 仍用域名
    let ip = crate::tunnel::resolve::resolve_one(host).await?;
    let tcp = TcpStream::connect((ip, port)).await.map_err(|e| format!("tcp {ip}:{port}: {e}"))?;
    tls_wrap(tcp, host, sni, insecure).await
}
