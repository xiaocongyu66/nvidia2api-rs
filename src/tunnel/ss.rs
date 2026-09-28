//! Shadowsocks AEAD 出站 (纯 Rust 手写)。
//! 线格式: [salt][enc(len 2BE)][enc(body)]... body <= 0x3FFF, counter 每块递增。
use crate::tunnel::outbound::{parse_host_port, socks_addr_block};
use crate::tunnel::stream::BoxStream;
use aes_gcm::aead::{Aead, KeyInit};
use chacha20poly1305::aead::{Aead as ChaAead, KeyInit as ChaKeyInit};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// base64url 解码 (自包含, 直接字节操作)
fn b64_url_decode_pub(input: &str) -> Result<Vec<u8>, String> {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let dec = |c: u8| -> Option<u32> { TBL.iter().position(|&t| t == c).map(|p| p as u32) };
    let bytes: Vec<u8> = input
        .trim()
        .bytes()
        .map(|c| match c {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        })
        .filter(|&c| c != b'=' && c != b'\n' && c != b'\r' && c != b' ')
        .collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= dec(c).ok_or_else(|| format!("base64 bad char {:?}", c as char))? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() >= 3 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() >= 4 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

const MAX_CHUNK: usize = 0x3FFF;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Clone, Copy)]
pub enum SsCipher {
    Aes256Gcm,
    ChaCha20IetfPoly1305,
}

/// 密文算法统一封装 (存算法 + 主密钥, 每次构造实例)。
#[derive(Clone)]
pub struct AeadWrap {
    cipher: SsCipher,
    key: Vec<u8>,
}

impl AeadWrap {
    pub fn new(cipher: SsCipher, key: &[u8]) -> AeadWrap {
        AeadWrap { cipher, key: key.to_vec() }
    }

    fn nonce(counter: u64) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[..8].copy_from_slice(&counter.to_be_bytes());
        n
    }

    pub fn seal(&self, counter: u64, plain: &[u8]) -> Result<Vec<u8>, String> {
        let n = Self::nonce(counter);
        match self.cipher {
            SsCipher::Aes256Gcm => {
                let c = aes_gcm::Aes256Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                c.encrypt((&n).into(), plain).map_err(|e| e.to_string())
            }
            SsCipher::ChaCha20IetfPoly1305 => {
                let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                c.encrypt((&n).into(), plain).map_err(|e| e.to_string())
            }
        }
    }

    pub fn open(&self, counter: u64, ct: &[u8]) -> Result<Vec<u8>, String> {
        let n = Self::nonce(counter);
        match self.cipher {
            SsCipher::Aes256Gcm => {
                let c = aes_gcm::Aes256Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                c.decrypt((&n).into(), ct).map_err(|e| e.to_string())
            }
            SsCipher::ChaCha20IetfPoly1305 => {
                let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                c.decrypt((&n).into(), ct).map_err(|e| e.to_string())
            }
        }
    }
}

pub struct SsTarget {
    pub server: String,
    pub port: u16,
    pub cipher: SsCipher,
    pub password: String,
}

impl SsTarget {
    pub fn parse(rest: &str) -> Result<SsTarget, String> {
        let (server, port) = parse_host_port(rest)?;
        let creds = match rest.split_once('@') {
            Some((c, _)) => c.to_string(),
            None => {
                let body = rest.split(['?', '#']).next().unwrap_or(rest);
                String::from_utf8(b64_url_decode_pub(body)?).map_err(|e| e.to_string())?
            }
        };
        let (method, password) = creds.split_once(':').ok_or("invalid ss credentials")?;
        let cipher = match method {
            "aes-256-gcm" => SsCipher::Aes256Gcm,
            "chacha20-ietf-poly1305" => SsCipher::ChaCha20IetfPoly1305,
            other => return Err(format!("unsupported ss method: {other}")),
        };
        Ok(SsTarget { server, port, cipher, password: password.to_string() })
    }

    pub async fn dial(&self, host: &str, port: u16) -> Result<BoxStream, String> {
        let main_key = evp_bytes_to_key(self.password.as_bytes(), 32);
        let mut salt = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let subkey_w = derive_subkey(&main_key, &salt);
        let w_aead = AeadWrap::new(self.cipher, &subkey_w);

        let mut tcp = tokio::net::TcpStream::connect((self.server.as_str(), self.port))
            .await
            .map_err(|e| format!("ss tcp: {e}"))?;
        // salt
        tcp.write_all(&salt).await.map_err(|e| e.to_string())?;
        // 首块: 目标地址 (可拆多片)
        let target = socks_addr_block(host, port);
        write_chunks(&mut tcp, &w_aead, &target, &mut 0).await?;

        // 读方向: 对端 salt → 派生子密钥
        let mut r_salt = vec![0u8; 32];
        tcp.read_exact(&mut r_salt).await.map_err(|e| e.to_string())?;
        let subkey_r = derive_subkey(&main_key, &r_salt);
        Ok(Box::new(SsIo {
            tcp,
            r_aead: AeadWrap::new(self.cipher, &subkey_r),
            w_aead,
            w_counter: 0,
            r_counter: 0,
            r_buf: Vec::new(),
            r_done: false,
        }))
    }
}

/// 写若干分片 (内部再按 MAX_CHUNK 切), counter 连续递增。
async fn write_chunks(tcp: &mut tokio::net::TcpStream, aead: &AeadWrap, data: &[u8], counter: &mut u64) -> Result<(), String> {
    let mut out = Vec::with_capacity(data.len() + 64);
    for piece in data.chunks(MAX_CHUNK) {
        let enc_len = aead.seal(*counter, &(piece.len() as u16).to_be_bytes()).map_err(|e| e.to_string())?;
        *counter += 1;
        let enc_body = aead.seal(*counter, piece).map_err(|e| e.to_string())?;
        *counter += 1;
        out.extend_from_slice(&enc_len);
        out.extend_from_slice(&enc_body);
    }
    tcp.write_all(&out).await.map_err(|e| e.to_string())
}

/// EVP_BytesToKey (MD5 迭代, OpenSSL 兼容)。
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut out = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

/// HKDF-SHA1, info = "ss-subkey" (Shadowsocks AEAD 规范)。
fn derive_subkey(main_key: &[u8], salt: &[u8]) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), main_key);
    let mut okm = vec![0u8; main_key.len()];
    hk.expand(b"ss-subkey", &mut okm).expect("hkdf");
    okm
}

pub struct SsIo {
    tcp: tokio::net::TcpStream,
    w_aead: AeadWrap,
    r_aead: AeadWrap,
    w_counter: u64,
    r_counter: u64,
    r_buf: Vec<u8>,
    r_done: bool,
}

impl tokio::io::AsyncWrite for SsIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut out = Vec::with_capacity(buf.len() + 64);
        for piece in buf.chunks(MAX_CHUNK) {
            let enc_len = match this.w_aead.seal(this.w_counter, &(piece.len() as u16).to_be_bytes()) {
                Ok(v) => v,
                Err(e) => return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
            };
            this.w_counter += 1;
            let enc_body = match this.w_aead.seal(this.w_counter, piece) {
                Ok(v) => v,
                Err(e) => return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
            };
            this.w_counter += 1;
            out.extend_from_slice(&enc_len);
            out.extend_from_slice(&enc_body);
        }
        match this.tcp.try_write(&out) {
            Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::task::Poll::Pending,
            Err(e) => std::task::Poll::Ready(Err(e)),
        }
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncRead for SsIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.r_buf.is_empty() {
            let n = std::cmp::min(this.r_buf.len(), out.remaining());
            let data: Vec<u8> = this.r_buf.drain(..n).collect();
            out.put_slice(&data);
            return std::task::Poll::Ready(Ok(()));
        }
        if this.r_done {
            return std::task::Poll::Ready(Ok(()));
        }
        use futures::FutureExt;
        let fut = read_one_chunk(&mut this.tcp, &this.r_aead, this.r_counter);
        let mut fut = Box::pin(fut);
        match fut.poll_unpin(cx) {
            std::task::Poll::Ready(Ok(data)) => {
                if data.is_empty() {
                    this.r_done = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                let n = std::cmp::min(data.len(), out.remaining());
                out.put_slice(&data[..n]);
                this.r_buf.extend_from_slice(&data[n..]);
                this.r_counter += 2; // len 块 + body 块各占一个 counter
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// 读并解密一个 chunk (enc_len + enc_body)。
async fn read_one_chunk(tcp: &mut tokio::net::TcpStream, aead: &AeadWrap, counter: u64) -> Result<Vec<u8>, String> {
    let mut enc_len = vec![0u8; 2 + TAG_LEN];
    tcp.read_exact(&mut enc_len).await.map_err(|e| e.to_string())?;
    let len_hdr = aead.open(counter, &enc_len).map_err(|e| e.to_string())?;
    let len = u16::from_be_bytes([*len_hdr.first().unwrap_or(&0), *len_hdr.get(1).unwrap_or(&0)]) as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut enc_body = vec![0u8; len + TAG_LEN];
    tcp.read_exact(&mut enc_body).await.map_err(|e| e.to_string())?;
    aead.open(counter + 1, &enc_body).map_err(|e| e.to_string())
}
