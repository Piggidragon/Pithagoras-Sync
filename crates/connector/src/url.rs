//! The portal's base URL and the pairing URI the portal shows.
//!
//! Both are parsed by hand: they are small, and a strict parser that refuses user
//! info, queries and odd schemes is easier to reason about than a general one.

use std::fmt;

/// `https://host[:port][/base]`, or `http://` for a portal on the same machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalUrl {
    pub tls: bool,
    /// Host name or IP address, IPv6 without brackets.
    pub host: String,
    pub port: u16,
    /// Path prefix when the portal is served below `/`, without a trailing slash.
    pub base: String,
}

impl PortalUrl {
    pub fn parse(s: &str) -> Result<PortalUrl, String> {
        let bad = |why: &str| format!("portal URL {s:?}: {why}");
        let (tls, rest) = if let Some(r) = strip_prefix_ci(s, "https://") {
            (true, r)
        } else if let Some(r) = strip_prefix_ci(s, "http://") {
            (false, r)
        } else {
            return Err(bad(
                "must start with https:// (or http:// for a local portal)",
            ));
        };
        if rest.contains(['?', '#']) {
            return Err(bad("no query or fragment allowed"));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(bad("no user name or password allowed"));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let end = v6.find(']').ok_or_else(|| bad("unclosed ["))?;
            let host = &v6[..end];
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(bad("bad IPv6 address"));
            }
            let after = &v6[end + 1..];
            let port = match after.strip_prefix(':') {
                Some(p) => Some(p),
                None if after.is_empty() => None,
                None => return Err(bad("junk after the IPv6 address")),
            };
            (host.to_string(), port)
        } else {
            let (h, p) = match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            };
            if h.contains(':') {
                return Err(bad("an IPv6 address needs brackets"));
            }
            (h.to_ascii_lowercase(), p)
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
        {
            return Err(bad("bad host"));
        }
        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| bad("bad port"))?,
            None if tls => 443,
            None => 80,
        };
        let base = path.trim_end_matches('/').to_string();
        if base.split('/').any(|c| c == ".." || c == ".") {
            return Err(bad("no . or .. in the path"));
        }
        Ok(PortalUrl {
            tls,
            host,
            port,
            base,
        })
    }

    /// `host[:port]` for the `Host` header, the port left out when it is the default.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The WebSocket URL of `path` (`/sync/v1/connect`).
    pub fn ws(&self, path: &str) -> String {
        let scheme = if self.tls { "wss" } else { "ws" };
        format!("{scheme}://{}{}{path}", self.authority(), self.base)
    }
}

impl fmt::Display for PortalUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.tls { "https" } else { "http" };
        write!(f, "{scheme}://{}{}", self.authority(), self.base)
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// `pithagoras-sync://pair?portal=<url>&code=<code>[&spki=<pin>]`, as the portal
/// shows it as text and QR code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairUri {
    pub portal: PortalUrl,
    pub code: String,
    /// base64url (no padding) sha256 of the certificate's SubjectPublicKeyInfo.
    pub spki: Option<String>,
}

impl PairUri {
    pub fn parse(s: &str) -> Result<PairUri, String> {
        let query = strip_prefix_ci(s.trim(), "pithagoras-sync://pair?")
            .ok_or("a pairing URI starts with pithagoras-sync://pair?")?;
        let (mut portal, mut code, mut spki) = (None, None, None);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = pct_decode(v).ok_or_else(|| format!("bad escape in {k}"))?;
            let slot = match k {
                "portal" => &mut portal,
                "code" => &mut code,
                "spki" => &mut spki,
                // Unknown keys are refused rather than ignored: a URI from a newer
                // portal should fail loudly, not pair with half its meaning.
                _ => return Err(format!("unknown key {k:?} in the pairing URI")),
            };
            if slot.replace(v).is_some() {
                return Err(format!("{k} given twice"));
            }
        }
        let portal = PortalUrl::parse(&portal.ok_or("the pairing URI has no portal")?)?;
        let code = code.ok_or("the pairing URI has no code")?;
        if code.is_empty() || code.len() > 64 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("bad pairing code".into());
        }
        if let Some(p) = &spki {
            crate::tls::decode_pin(p)?;
        }
        Ok(PairUri {
            portal,
            code,
            spki: spki.filter(|p| !p.is_empty()),
        })
    }
}

fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_portal_urls() {
        let u = PortalUrl::parse("https://Portal.example").unwrap();
        assert_eq!(
            (u.tls, u.host.as_str(), u.port),
            (true, "portal.example", 443)
        );
        assert_eq!(
            u.ws("/sync/v1/connect"),
            "wss://portal.example/sync/v1/connect"
        );
        let u = PortalUrl::parse("http://127.0.0.1:3000/pitha/").unwrap();
        assert_eq!(u.base, "/pitha");
        assert_eq!(u.to_string(), "http://127.0.0.1:3000/pitha");
        let u = PortalUrl::parse("https://[::1]:8443").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 8443));
        assert_eq!(u.authority(), "[::1]:8443");
        for bad in [
            "ftp://x",
            "portal.example",
            "https://user:pw@x",
            "https://x/?a=1",
            "https://x:0",
            "https://x:99999",
            "https://",
            "https://x/../y",
            "https://[nope]",
        ] {
            assert!(PortalUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_pairing_uris() {
        let pin = "A".repeat(43);
        let p = PairUri::parse(&format!(
            "pithagoras-sync://pair?portal=https%3A%2F%2Fportal.example%3A8443&code=AB12CD34&spki={pin}"
        ))
        .unwrap();
        assert_eq!(p.portal.port, 8443);
        assert_eq!(p.code, "AB12CD34");
        assert_eq!(p.spki.as_deref(), Some(pin.as_str()));
        let p =
            PairUri::parse("pithagoras-sync://pair?portal=http://127.0.0.1:3000&code=x1").unwrap();
        assert!(p.spki.is_none());
        for bad in [
            "https://portal.example",
            "pithagoras-sync://pair?code=AB",
            "pithagoras-sync://pair?portal=https://x",
            "pithagoras-sync://pair?portal=https://x&code=A B",
            "pithagoras-sync://pair?portal=https://x&code=AB&code=CD",
            "pithagoras-sync://pair?portal=https://x&code=AB&mode=full",
            "pithagoras-sync://pair?portal=https://x&code=AB&spki=short",
        ] {
            assert!(PairUri::parse(bad).is_err(), "{bad}");
        }
    }
}
