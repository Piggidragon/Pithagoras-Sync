//! One HTTP/1.1 request over an open connection: the pairing POST, and the GETs of
//! the updater. The client needs no other HTTP, so this stays a few lines instead
//! of a client library.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::net::BoxIo;
use crate::url::PortalUrl;

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    /// The `Location` header of a redirect.
    pub location: Option<String>,
}

/// POSTs a JSON body to `path` below the portal's base and reads the answer.
pub async fn post_json(
    io: &mut BoxIo,
    url: &PortalUrl,
    path: &str,
    body: &[u8],
) -> Result<Response, String> {
    tokio::time::timeout(TIMEOUT, post_inner(io, url, path, body))
        .await
        .map_err(|_| format!("{url}{path}: no answer within {}s", TIMEOUT.as_secs()))?
}

async fn post_inner(
    io: &mut BoxIo,
    url: &PortalUrl,
    path: &str,
    body: &[u8],
) -> Result<Response, String> {
    let head = format!(
        "POST {}{path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json\r\nUser-Agent: pithagoras-sync/{}\r\nConnection: close\r\n\r\n",
        url.base,
        url.authority(),
        body.len(),
        env!("CARGO_PKG_VERSION"),
    );
    let io_err = |e: std::io::Error| format!("{url}{path}: {e}");
    io.write_all(head.as_bytes()).await.map_err(io_err)?;
    io.write_all(body).await.map_err(io_err)?;
    io.flush().await.map_err(io_err)?;
    read_response(io, &format!("{url}{path}"), MAX_BODY).await
}

/// GETs `url` (https, or http to this machine only), following up to five
/// redirects, and returns the body of a 200 answer of at most `max` bytes.
pub async fn get(url: &str, max: usize) -> Result<Vec<u8>, String> {
    get_checked(url, max, &|_| Ok(())).await
}

/// `get`, with `allowed` asked about the URL and every redirect before it is
/// opened: a download pinned to some hosts cannot be sent to another.
pub async fn get_checked(
    url: &str,
    max: usize,
    allowed: &(dyn Fn(&str) -> Result<(), String> + Sync),
) -> Result<Vec<u8>, String> {
    let mut url = url.to_string();
    for _ in 0..=5 {
        allowed(&url)?;
        let (origin, target) = split_url(&url)?;
        let mut io = crate::net::open(&origin, None).await?;
        let head = format!(
            "GET {target} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nUser-Agent: pithagoras-sync/{}\r\nConnection: close\r\n\r\n",
            origin.authority(),
            env!("CARGO_PKG_VERSION"),
        );
        let io_err = |e: std::io::Error| format!("{url}: {e}");
        io.write_all(head.as_bytes()).await.map_err(io_err)?;
        io.flush().await.map_err(io_err)?;
        let r = tokio::time::timeout(Duration::from_secs(300), read_response(&mut io, &url, max))
            .await
            .map_err(|_| format!("{url}: no complete answer within 300s"))??;
        match (r.status, r.location) {
            (200, _) => return Ok(r.body),
            (301 | 302 | 303 | 307 | 308, Some(loc)) => {
                url = if loc.starts_with('/') {
                    format!("{origin}{loc}")
                } else {
                    loc
                };
            }
            (s, _) => return Err(format!("{url}: HTTP {s}")),
        }
    }
    Err(format!("{url}: too many redirects"))
}

/// `https://host[:port]` and the request target (path and query) of a URL.
fn split_url(url: &str) -> Result<(PortalUrl, String), String> {
    let url = url.split('#').next().unwrap_or("");
    let after_scheme = url
        .find("://")
        .map(|i| i + 3)
        .ok_or_else(|| format!("{url:?}: not a URL"))?;
    let end = url[after_scheme..]
        .find(['/', '?'])
        .map_or(url.len(), |i| after_scheme + i);
    let origin = PortalUrl::parse(&url[..end])?;
    let target = match &url[end..] {
        "" => "/".to_string(),
        t if t.starts_with('?') => format!("/{t}"),
        t => t.to_string(),
    };
    if target.chars().any(|c| c.is_ascii_control() || c == ' ') {
        return Err(format!("{url:?}: bad characters in the path"));
    }
    Ok((origin, target))
}

async fn read_response(io: &mut BoxIo, what: &str, max: usize) -> Result<Response, String> {
    let io_err = |e: std::io::Error| format!("{what}: {e}");

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let (status, head_len, length, chunked, location) = loop {
        let n = io.read(&mut chunk).await.map_err(io_err)?;
        if n == 0 {
            return Err(format!("{what}: connection closed before the answer"));
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(len)) => {
                let mut length = None;
                let mut chunked = false;
                let mut location = None;
                for h in resp.headers.iter() {
                    if h.name.eq_ignore_ascii_case("location") {
                        location = std::str::from_utf8(h.value).ok().map(str::to_string);
                    }
                    if h.name.eq_ignore_ascii_case("content-length") {
                        length = std::str::from_utf8(h.value)
                            .ok()
                            .and_then(|v| v.trim().parse::<usize>().ok());
                    } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                        chunked = String::from_utf8_lossy(h.value)
                            .to_ascii_lowercase()
                            .contains("chunked");
                    }
                }
                break (resp.code.unwrap_or(0), len, length, chunked, location);
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => {}
            Ok(httparse::Status::Partial) => return Err(format!("{what}: header too long")),
            Err(e) => return Err(format!("{what}: bad answer: {e}")),
        }
    };
    let mut body = buf.split_off(head_len);
    if length.is_some_and(|l| l > max) {
        return Err(format!("{what}: answer too long"));
    }
    loop {
        if let Some(len) = length
            && !chunked
            && body.len() >= len
        {
            body.truncate(len);
            break;
        }
        if chunked && let Some(done) = dechunk(&body, max)? {
            body = done;
            break;
        }
        // Chunk framing on top of the body itself.
        if body.len() > max + max / 8 + 1024 {
            return Err(format!("{what}: answer too long"));
        }
        let n = io.read(&mut chunk).await.map_err(io_err)?;
        if n == 0 {
            if length.is_some() || chunked {
                return Err(format!("{what}: answer cut short"));
            }
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if body.len() > max {
        return Err(format!("{what}: answer too long"));
    }
    Ok(Response {
        status,
        body,
        location,
    })
}

/// Decodes a complete chunked body of at most `max` bytes; `None` while more is
/// needed. A chunk size is the server's word: checked before any arithmetic.
fn dechunk(data: &[u8], max: usize) -> Result<Option<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let Some(eol) = data[i..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&data[i..i + eol]).map_err(|_| "bad chunk size")?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| "bad chunk size")?;
        i += eol + 2;
        if size == 0 {
            return Ok(Some(out));
        }
        if size > max.saturating_sub(out.len()) {
            return Err(format!("the answer is larger than {max} bytes"));
        }
        let end = i
            .checked_add(size)
            .and_then(|e| e.checked_add(2))
            .ok_or("bad chunk size")?;
        if data.len() < end {
            return Ok(None);
        }
        out.extend_from_slice(&data[i..i + size]);
        i += size + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_urls_into_origin_and_target() {
        let (o, t) = split_url("https://example.org/a/b?x=1#frag").unwrap();
        assert_eq!(
            (o.to_string(), t.as_str()),
            ("https://example.org".into(), "/a/b?x=1")
        );
        let (o, t) = split_url("http://127.0.0.1:8080").unwrap();
        assert_eq!((o.port, t.as_str()), (8080, "/"));
        let (_, t) = split_url("https://h?q").unwrap();
        assert_eq!(t, "/?q");
        assert!(split_url("https://u@h/x").is_err());
        assert!(split_url("https://h/a b").is_err());
        assert!(split_url("ftp-ish").is_err());
    }

    #[test]
    fn dechunks() {
        assert_eq!(
            dechunk(b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n", 100).unwrap(),
            Some(b"abcde".to_vec())
        );
        assert_eq!(dechunk(b"3\r\nab", 100).unwrap(), None);
        assert!(dechunk(b"zz\r\n", 100).is_err());
    }

    #[test]
    fn a_huge_chunk_size_is_an_error_not_a_panic() {
        assert!(dechunk(b"ffffffffffffffff\r\nabc\r\n", 100).is_err());
        assert!(dechunk(b"fffffffffffffffe\r\nabc\r\n", usize::MAX).is_err());
        // Over the answer's limit, in one chunk or across several.
        assert!(dechunk(b"65\r\n", 100).is_err());
        assert!(dechunk(b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n", 5).is_err());
        assert!(dechunk(b"3\r\nabc\r\n0\r\n\r\n", 3).unwrap().is_some());
    }
}
