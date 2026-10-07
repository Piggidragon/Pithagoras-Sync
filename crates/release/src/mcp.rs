//! The signed pins document of computer use (`mcp.json`, docs/mcp-pins.md):
//! made from a small input file that names each server's version, files and
//! tools. Every file is downloaded and hashed here, the next serial is taken,
//! and the result is checked with the client's own rules before it is
//! written, so a document the client would ignore is never made. It is signed
//! like the release manifest (`sync-release sign`) and checked the way the
//! client checks it (`mcp-verify`).

use serde_json::Value;
use sync_mcp::pins::{self, Document};

/// The serial of an existing document.
pub fn serial_of(text: &str) -> Result<u64, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("the previous document: {e}"))?;
    v.get("serial")
        .and_then(Value::as_u64)
        .ok_or_else(|| "the previous document has no serial".into())
}

/// The document for `input`: `{"servers": [...]}` with each file's `url`,
/// `path`, `kind` and optional `arch`, but no `sha256` or `size` (they are
/// measured here). The serial is above `previous` (and at least `serial`).
pub async fn build(
    input: &str,
    previous: Option<u64>,
    serial: Option<u64>,
    now_ms: i64,
    say: &mut dyn FnMut(String),
) -> Result<String, String> {
    let mut v: Value = serde_json::from_str(input).map_err(|e| format!("the input: {e}"))?;
    let obj = v.as_object().ok_or("the input is not an object")?;
    if let Some(k) = obj.keys().find(|k| *k != "servers") {
        return Err(format!("the input has an unknown field {k:?}"));
    }
    let next = previous
        .map_or(1, |p| p + 1)
        .max(serial.unwrap_or(0))
        .max(1);
    if let (Some(p), Some(s)) = (previous, serial)
        && s <= p
    {
        return Err(format!(
            "--serial {s} is not above the previous document's {p}"
        ));
    }
    let servers = v["servers"]
        .as_array_mut()
        .ok_or("the input has no servers list")?;
    for s in servers.iter_mut() {
        let name = s["name"].as_str().unwrap_or("?").to_string();
        // A forbidden tool is an error here, not a quiet drop in the client.
        if let Some(allow) = s["allow"].as_array() {
            let denied: Vec<&str> = allow
                .iter()
                .filter_map(Value::as_str)
                .filter(|t| pins::hard_denied(t))
                .collect();
            if !denied.is_empty() {
                return Err(format!(
                    "{name}: the client's hard deny-list forbids {}; take them off the allow-list",
                    denied.join(", ")
                ));
            }
        }
        let files = s["files"]
            .as_array_mut()
            .ok_or(format!("{name}: no files"))?;
        for f in files.iter_mut() {
            let url = f["url"]
                .as_str()
                .ok_or(format!("{name}: a file without a url"))?
                .to_string();
            if url.contains(pins::TODO_PIN) {
                return Err(format!("{name}: {url} still holds {}", pins::TODO_PIN));
            }
            say(format!("download {url}"));
            let data = pins::fetch(&url, pins::MAX_FILE as usize, true).await?;
            let sha = sync_mcp::fsutil::sha256_hex(&data);
            say(format!("  {} bytes, sha256 {sha}", data.len()));
            f["sha256"] = Value::String(sha);
            f["size"] = Value::from(data.len());
        }
    }
    let doc = serde_json::json!({"serial": next, "issued_ms": now_ms, "servers": v["servers"]});
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())? + "\n";
    Document::parse(text.as_bytes(), false)?;
    Ok(text)
}

/// Checks a signed document as the client does; a summary of it.
pub fn verify(data: &[u8], sig: &str, public_key: &str) -> Result<String, String> {
    let d = pins::verify(data, sig, public_key)?;
    let mut out = format!("the pins document verifies: serial {}", d.serial);
    for s in &d.servers {
        out.push_str(&format!(
            "\n  {} {} ({}): {} files, allows {}",
            s.name,
            s.version,
            s.platform,
            s.files.len(),
            s.allowed().join(", ")
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minisign::SigningKey;
    use sync_testkit::files::{FileServer, Reply};

    fn input(url: &str, allow: &[&str]) -> String {
        serde_json::json!({"servers": [{
            "name": "computer-use-linux", "platform": "linux", "version": "1.2.3",
            "files": [{"arch": "x86_64", "kind": "executable", "path": "computer-use-linux", "url": url}],
            "run": {"program": "computer-use-linux"},
            "allow": allow, "observe": [],
            "focus": {"windows": {"tool": "list_windows"}},
            "selftest": {"screenshot": {"tool": "screenshot"}}
        }]})
        .to_string()
    }

    #[tokio::test]
    async fn builds_signs_and_verifies_as_the_client_does() {
        let files = FileServer::start().await;
        let url = files.put("/srv", Reply::Body(b"server bytes".to_vec()));
        let text = build(&input(&url, &["screenshot"]), Some(4), None, 1, &mut |_| {})
            .await
            .unwrap();
        let d: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(d["serial"], 5);
        assert_eq!(d["servers"][0]["files"][0]["size"], 12);
        assert_eq!(
            d["servers"][0]["files"][0]["sha256"],
            sync_mcp::fsutil::sha256_hex(b"server bytes")
        );
        let key = SigningKey::generate();
        let sig = key.sign(text.as_bytes(), "file:mcp.json");
        let out = verify(text.as_bytes(), &sig, &key.public_base64()).unwrap();
        assert!(out.contains("serial 5"), "{out}");
        assert!(
            verify(
                text.as_bytes(),
                &sig,
                &SigningKey::generate().public_base64()
            )
            .is_err()
        );
        assert_eq!(serial_of(&text).unwrap(), 5);
    }

    #[tokio::test]
    async fn refuses_what_the_client_would_not_take() {
        let files = FileServer::start().await;
        let url = files.put("/srv", Reply::Body(b"x".to_vec()));
        let e = build(
            &input(&url, &["screenshot", "PowerShell"]),
            None,
            None,
            1,
            &mut |_| {},
        )
        .await
        .unwrap_err();
        assert!(e.contains("PowerShell"), "{e}");
        let e = build(
            &input("https://evil.example/srv", &["screenshot"]),
            None,
            None,
            1,
            &mut |_| {},
        )
        .await
        .unwrap_err();
        assert!(e.contains("downloads"), "{e}");
        let e = build(
            &input(&url, &["screenshot"]),
            Some(4),
            Some(3),
            1,
            &mut |_| {},
        )
        .await
        .unwrap_err();
        assert!(e.contains("serial"), "{e}");
        let e = build(
            &input("https://github.com/TODO-PIN", &["screenshot"]),
            None,
            None,
            1,
            &mut |_| {},
        )
        .await
        .unwrap_err();
        assert!(e.contains("TODO-PIN"), "{e}");
    }
}
