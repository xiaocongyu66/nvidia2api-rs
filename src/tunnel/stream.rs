//! 统一代理流: 出站拨号返回 Box<dyn ProxyStream>, 双向拷贝泛型化。
use tokio::io::{AsyncRead, AsyncWrite};

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}

pub type BoxStream = Box<dyn ProxyStream + Unpin + Send>;
