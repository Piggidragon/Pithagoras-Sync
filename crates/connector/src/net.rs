//! Opening a connection to the portal: TLS, except to a portal on this machine.
//!
//! Plain HTTP is allowed only when every address the connection may use is a
//! loopback address, checked after name resolution, so a name that resolves to
//! another machine cannot get a plaintext link (which would hand a man in the middle
//! a shell on this device).

use std::net::SocketAddr;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::url::PortalUrl;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The addresses a connection may use. Without TLS only loopback ones, and none
/// at all if the name resolves to anything else.
pub fn usable_addrs(tls: bool, addrs: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, String> {
    if tls {
        return Ok(addrs);
    }
    if addrs.is_empty() || addrs.iter().any(|a| !a.ip().to_canonical().is_loopback()) {
        return Err(
            "plain http is only allowed to a portal on this machine (loopback); use https".into(),
        );
    }
    Ok(addrs)
}

pub async fn open(url: &PortalUrl, pin: Option<&str>) -> Result<BoxIo, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((url.host.as_str(), url.port))
        .await
        .map_err(|e| format!("cannot resolve {}: {e}", url.host))?
        .collect();
    let addrs = usable_addrs(url.tls, addrs)?;
    let mut last = String::from("no address");
    let mut tcp = None;
    for a in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                tcp = Some(s);
                break;
            }
            Ok(Err(e)) => last = format!("{a}: {e}"),
            Err(_) => last = format!("{a}: timed out"),
        }
    }
    let tcp = tcp.ok_or_else(|| format!("cannot connect to {url}: {last}"))?;
    let _ = tcp.set_nodelay(true);
    if !url.tls {
        return Ok(Box::new(tcp));
    }
    let config = crate::tls::client_config(pin)?;
    let name = ServerName::try_from(url.host.clone())
        .map_err(|_| format!("bad TLS server name {}", url.host))?;
    let tls = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(config).connect(name, tcp),
    )
    .await
    .map_err(|_| format!("TLS handshake with {url} timed out"))?
    .map_err(|e| format!("TLS with {url}: {e}"))?;
    Ok(Box::new(tls))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn plain_http_only_reaches_loopback() {
        assert!(usable_addrs(false, vec![a("127.0.0.1:80"), a("[::1]:80")]).is_ok());
        assert!(usable_addrs(false, vec![a("[::ffff:127.0.0.1]:80")]).is_ok());
        // A name that resolves to loopback and to another machine is refused whole.
        assert!(usable_addrs(false, vec![a("127.0.0.1:80"), a("192.0.2.7:80")]).is_err());
        assert!(usable_addrs(false, vec![a("192.0.2.7:80")]).is_err());
        assert!(usable_addrs(false, vec![]).is_err());
        assert!(usable_addrs(true, vec![a("192.0.2.7:443")]).is_ok());
    }
}
