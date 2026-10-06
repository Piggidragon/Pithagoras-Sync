//! Opening a connection to the portal: TLS, except to a portal on this machine.
//!
//! Plain HTTP is allowed only when every address the connection may use is a
//! loopback address, checked after name resolution, so a name that resolves to
//! another machine cannot get a plaintext link (which would hand a man in the middle
//! a shell on this device).
//!
//! Loopback is not a channel between two users: any local account may listen on a
//! free port, and gets the pairing code and the token. So a name (`localhost`)
//! takes only its IPv4 loopback addresses (the portal listens on IPv4, which leaves
//! `[::1]` on its port free for anyone), and on Linux the program that accepted the
//! connection must belong to this user or root. What remains: on Windows plain HTTP
//! trusts every local account; use https with a pinned certificate there.

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
/// at all if the name resolves to anything else; for a name rather than an
/// address (`named`), only its IPv4 loopback addresses.
pub fn usable_addrs(
    tls: bool,
    named: bool,
    addrs: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, String> {
    if tls {
        return Ok(addrs);
    }
    if addrs.is_empty() || addrs.iter().any(|a| !a.ip().to_canonical().is_loopback()) {
        return Err(
            "plain http is only allowed to a portal on this machine (loopback); use https".into(),
        );
    }
    if named {
        // `localhost` resolves to ::1 first; a portal listening on IPv4 only
        // leaves [::1] on its port to whoever binds it.
        let v4: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| a.ip().to_canonical().is_ipv4())
            .collect();
        if v4.is_empty() {
            return Err(
                "plain http to a host name uses its IPv4 loopback address only, and this one has none: name the address (http://[::1]:<port>)".into(),
            );
        }
        return Ok(v4);
    }
    Ok(addrs)
}

/// The uid owning the socket at the other end of a loopback connection from
/// `local` to `peer`: the server's accepted socket, which carries the uid of the
/// program that listens. From `/proc/net/tcp` (or `tcp6`).
///
/// The server's socket has the family of its listener, not of the client's: a
/// listener on `[::]` (dual-stack) accepts an IPv4 connection on an IPv6 socket,
/// listed in `tcp6` under v4-mapped addresses, and a client that names
/// `[::ffff:127.0.0.1]` reaches an IPv4 listener, listed in `tcp`. So an IPv4
/// connection, in either form, is looked up in both tables.
#[cfg(target_os = "linux")]
pub fn peer_owner(local: SocketAddr, peer: SocketAddr) -> Option<u32> {
    use std::net::IpAddr;
    let v4 = |a: SocketAddr| SocketAddr::new(a.ip().to_canonical(), a.port());
    let mapped = |a: SocketAddr| match a.ip().to_canonical() {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V6(ip.to_ipv6_mapped()), a.port()),
        ip => SocketAddr::new(ip, a.port()),
    };
    let mut tries = Vec::new();
    if v4(peer).is_ipv4() {
        tries.push(("tcp", v4(peer), v4(local)));
    }
    tries.push(("tcp6", mapped(peer), mapped(local)));
    tries
        .into_iter()
        .find_map(|(file, peer, local)| owner_in(file, peer, local))
}

/// The uid of the socket in `/proc/net/<file>` whose own address is `peer` and
/// whose far end is `local`.
#[cfg(target_os = "linux")]
fn owner_in(file: &str, peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let table = std::fs::read_to_string(format!("/proc/net/{file}")).ok()?;
    let (want_local, want_remote) = (proc_addr(peer), proc_addr(local));
    table.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (l, r, uid) = (f.get(1)?, f.get(2)?, f.get(7)?);
        (l.eq_ignore_ascii_case(&want_local) && r.eq_ignore_ascii_case(&want_remote))
            .then(|| uid.parse().ok())
            .flatten()
    })
}

/// An address as `/proc/net/tcp` writes it: the address words in the kernel's
/// byte order, then the port.
#[cfg(target_os = "linux")]
fn proc_addr(a: SocketAddr) -> String {
    let ip = match a.ip() {
        std::net::IpAddr::V4(v4) => format!("{:08X}", u32::from_ne_bytes(v4.octets())),
        std::net::IpAddr::V6(v6) => v6
            .octets()
            .chunks(4)
            .map(|w| format!("{:08X}", u32::from_ne_bytes([w[0], w[1], w[2], w[3]])))
            .collect(),
    };
    format!("{ip}:{:04X}", a.port())
}

/// Plain http on Linux: the program that accepted the connection must belong to
/// this user or root, or it is not the portal this user paired with, and would
/// get the pairing code and the token.
#[cfg(target_os = "linux")]
fn check_local_peer(tcp: &TcpStream) -> Result<(), String> {
    let (local, peer) = (
        tcp.local_addr().map_err(|e| e.to_string())?,
        tcp.peer_addr().map_err(|e| e.to_string())?,
    );
    // A test plays the listener of another user, which needs a second account.
    #[cfg(test)]
    if let Some(owner) = tests::FAKE_OWNER.with(std::cell::Cell::get) {
        return owner_verdict(owner, sync_ops::info::euid(), peer);
    }
    owner_verdict(peer_owner(local, peer), sync_ops::info::euid(), peer)
}

#[cfg(target_os = "linux")]
fn owner_verdict(owner: Option<u32>, me: u32, peer: SocketAddr) -> Result<(), String> {
    match owner {
        Some(uid) if uid == me || uid == 0 => Ok(()),
        Some(uid) => Err(format!(
            "{peer} is answered by a program of another user (uid {uid}), not of this user or root: plain http would hand it the pairing code and the token. If the portal runs as another user, use https with its certificate pinned"
        )),
        None => Err(format!(
            "cannot tell which user's program answers on {peer}, so plain http sends nothing there; use https with a pinned certificate"
        )),
    }
}

pub async fn open(url: &PortalUrl, pin: Option<&str>) -> Result<BoxIo, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((url.host.as_str(), url.port))
        .await
        .map_err(|e| format!("cannot resolve {}: {e}", url.host))?
        .collect();
    let named = url.host.parse::<std::net::IpAddr>().is_err();
    let addrs = usable_addrs(url.tls, named, addrs)?;
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
        #[cfg(target_os = "linux")]
        check_local_peer(&tcp)?;
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

    #[cfg(target_os = "linux")]
    thread_local! {
        /// The owner `check_local_peer` finds instead of the real one, on this
        /// thread (a `#[tokio::test]` runs on one): `Some(None)` for an owner it
        /// cannot tell.
        pub(super) static FAKE_OWNER: std::cell::Cell<Option<Option<u32>>> =
            const { std::cell::Cell::new(None) };
    }

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn plain_http_only_reaches_loopback() {
        assert!(usable_addrs(false, false, vec![a("127.0.0.1:80")]).is_ok());
        assert!(usable_addrs(false, false, vec![a("[::1]:80")]).is_ok());
        assert!(usable_addrs(false, false, vec![a("[::ffff:127.0.0.1]:80")]).is_ok());
        // A name that resolves to loopback and to another machine is refused whole.
        assert!(usable_addrs(false, true, vec![a("127.0.0.1:80"), a("192.0.2.7:80")]).is_err());
        assert!(usable_addrs(false, true, vec![a("192.0.2.7:80")]).is_err());
        assert!(usable_addrs(false, true, vec![]).is_err());
        assert!(usable_addrs(true, true, vec![a("192.0.2.7:443")]).is_ok());
    }

    #[test]
    fn a_name_takes_only_its_ipv4_loopback_address() {
        // `localhost` as getaddrinfo gives it: ::1 first.
        assert_eq!(
            usable_addrs(false, true, vec![a("[::1]:80"), a("127.0.0.1:80")]).unwrap(),
            vec![a("127.0.0.1:80")]
        );
        assert!(usable_addrs(false, true, vec![a("[::1]:80")]).is_err());
    }

    /// The reviewer's probe: the portal on 127.0.0.1, another user's program on
    /// [::1] at the same port. `localhost` reaches the portal.
    #[tokio::test]
    async fn localhost_reaches_the_ipv4_portal_not_a_listener_on_ipv6() {
        let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = v4.local_addr().unwrap().port();
        let Ok(v6) = tokio::net::TcpListener::bind(("::1", port)).await else {
            eprintln!("  (no IPv6 loopback here; nothing to show)");
            return;
        };
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host(("localhost", port))
            .await
            .unwrap()
            .collect();
        if !resolved.iter().any(SocketAddr::is_ipv6) {
            eprintln!("  (localhost has no IPv6 address here; nothing to show)");
            return;
        }
        let url = PortalUrl::parse(&format!("http://localhost:{port}")).unwrap();
        let _io = open(&url, None).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), v4.accept()).await;
        assert!(got.is_ok(), "the IPv4 listener was not reached");
        let other = tokio::time::timeout(Duration::from_millis(200), v6.accept()).await;
        assert!(other.is_err(), "the IPv6 listener got the connection");
    }

    /// The owner of the far end of a loopback connection is read right: here this
    /// process, so this user.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_far_end_of_a_loopback_connection_has_an_owner() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (local, peer) = (c.local_addr().unwrap(), c.peer_addr().unwrap());
        assert_eq!(peer_owner(local, peer), Some(sync_ops::info::euid()));
        assert!(check_local_peer(&c).is_ok());
        // Another connection's addresses are not this one.
        let other = SocketAddr::new(local.ip(), local.port().wrapping_add(1).max(1));
        assert_eq!(peer_owner(other, peer), None);
        // A program of another user is refused, one of root taken.
        let me = sync_ops::info::euid();
        assert!(owner_verdict(Some(me + 1), me, peer).is_err());
        assert!(owner_verdict(None, me, peer).is_err());
        assert!(owner_verdict(Some(0), me, peer).is_ok());
        if let Ok(l6) = tokio::net::TcpListener::bind("[::1]:0").await {
            let c = TcpStream::connect(l6.local_addr().unwrap()).await.unwrap();
            let (local, peer) = (c.local_addr().unwrap(), c.peer_addr().unwrap());
            assert_eq!(peer_owner(local, peer), Some(sync_ops::info::euid()));
        }
    }

    /// A portal of this user that listens dual-stack on `[::]` (Node's bare
    /// `listen(port)`, Go's `":port"`) is reached over IPv4, and one on IPv4
    /// through the v4-mapped form of its address: the owner is found in the
    /// other table, and plain http goes through.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn plain_http_reaches_this_users_portal_in_either_address_family() {
        let open_ok = |url: String| async move {
            let url = PortalUrl::parse(&url).unwrap();
            open(&url, None).await.map(|_| ())
        };
        if let Ok(dual) = tokio::net::TcpListener::bind("[::]:0").await {
            let port = dual.local_addr().unwrap().port();
            // Dual-stack unless the system set `net.ipv6.bindv6only`.
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                assert_eq!(open_ok(format!("http://127.0.0.1:{port}")).await, Ok(()));
                assert_eq!(open_ok(format!("http://localhost:{port}")).await, Ok(()));
                assert_eq!(
                    open_ok(format!("http://[::ffff:127.0.0.1]:{port}")).await,
                    Ok(())
                );
            } else {
                eprintln!("  (IPv6 sockets are IPv6 only here; no dual-stack listener)");
            }
        }
        let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = v4.local_addr().unwrap().port();
        assert_eq!(
            open_ok(format!("http://[::ffff:127.0.0.1]:{port}")).await,
            Ok(())
        );
        assert_eq!(open_ok(format!("http://127.0.0.1:{port}")).await, Ok(()));
    }

    /// `open` hands out no plain-http connection that another user's program
    /// answers, or one whose owner it cannot tell; TLS is not checked.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn plain_http_is_refused_when_another_user_answers() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = PortalUrl::parse(&format!(
            "http://127.0.0.1:{}",
            l.local_addr().unwrap().port()
        ))
        .unwrap();
        let me = sync_ops::info::euid();
        for (owner, refused) in [
            (Some(me + 1), true),
            (None, true),
            (Some(me), false),
            (Some(0), false),
        ] {
            FAKE_OWNER.with(|f| f.set(Some(owner)));
            let got = open(&url, None).await;
            FAKE_OWNER.with(|f| f.set(None));
            assert_eq!(got.is_err(), refused, "owner {owner:?}");
        }
    }
}
