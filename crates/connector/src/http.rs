//! One HTTP/1.1 request over an open connection, for pairing. The client needs no
//! other HTTP, so this stays a few lines instead of a client library.

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

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let (status, head_len, length, chunked) = loop {
        let n = io.read(&mut chunk).await.map_err(io_err)?;
        if n == 0 {
            return Err(format!("{url}{path}: connection closed before the answer"));
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(len)) => {
                let mut length = None;
                let mut chunked = false;
                for h in resp.headers.iter() {
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
                break (resp.code.unwrap_or(0), len, length, chunked);
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD => {}
            Ok(httparse::Status::Partial) => return Err(format!("{url}{path}: header too long")),
            Err(e) => return Err(format!("{url}{path}: bad answer: {e}")),
        }
    };
    let mut body = buf.split_off(head_len);
    loop {
        if let Some(len) = length
            && !chunked
            && body.len() >= len
        {
            body.truncate(len);
            break;
        }
        if chunked && let Some(done) = dechunk(&body)? {
            body = done;
            break;
        }
        if body.len() > MAX_BODY {
            return Err(format!("{url}{path}: answer too long"));
        }
        let n = io.read(&mut chunk).await.map_err(io_err)?;
        if n == 0 {
            if length.is_some() || chunked {
                return Err(format!("{url}{path}: answer cut short"));
            }
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(Response { status, body })
}

/// Decodes a complete chunked body; `None` while more is needed.
fn dechunk(data: &[u8]) -> Result<Option<Vec<u8>>, String> {
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
        if data.len() < i + size + 2 {
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
    fn dechunks() {
        assert_eq!(
            dechunk(b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n").unwrap(),
            Some(b"abcde".to_vec())
        );
        assert_eq!(dechunk(b"3\r\nab").unwrap(), None);
        assert!(dechunk(b"zz\r\n").is_err());
    }
}
