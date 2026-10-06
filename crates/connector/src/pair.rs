//! Pairing: trade the one-time code for a connector token, and keep the token.
//!
//! Only the connector token is stored, in a 0600 file. The overlay token the portal
//! also returns is for the phase 2 GUI and is dropped here.

use std::path::Path;

use sync_policy::PortalConfig;
use sync_policy::config::write_private;
use sync_proto::methods::{PairRequest, PairResponse};

use crate::url::PairUri;

pub struct Paired {
    pub portal: PortalConfig,
    pub token: String,
}

/// Device names the portal reserves for itself.
const RESERVED: &[&str] = &["server", "portal"];

/// A device name as the portal expects it: `[a-z0-9-]{1,24}`, not reserved.
pub fn valid_name(name: &str) -> bool {
    (1..=24).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !RESERVED.contains(&name)
}

/// A device name made from the host name.
pub fn name_from_hostname(host: &str) -> String {
    let mut out = String::new();
    for c in host.split('.').next().unwrap_or("").chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let mut out: String = out.trim_matches('-').chars().take(24).collect();
    while out.ends_with('-') {
        out.pop();
    }
    if valid_name(&out) {
        out
    } else {
        "device".into()
    }
}

/// A token the device will put in an `Authorization` header.
pub fn valid_token(t: &str) -> bool {
    (16..=512).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_graphic())
}

pub async fn pair(uri: &str, name: &str) -> Result<Paired, String> {
    let uri = PairUri::parse(uri)?;
    if !valid_name(name) {
        return Err(format!(
            "device name {name:?}: use 1 to 24 of a-z, 0-9 and -, not server or portal"
        ));
    }
    let mut io = crate::net::open(&uri.portal, uri.spki.as_deref()).await?;
    let req = PairRequest {
        code: uri.code.clone(),
        name: name.to_string(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
    };
    let body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    let resp = crate::http::post_json(&mut io, &uri.portal, sync_proto::PAIR_PATH, &body).await?;
    if !(200..300).contains(&resp.status) {
        return Err(refusal(resp.status, &resp.body));
    }
    let r: PairResponse = serde_json::from_slice(&resp.body)
        .map_err(|e| format!("the portal's pairing answer is not understood: {e}"))?;
    if !valid_token(&r.connector_token) {
        return Err("the portal sent an unusable token".into());
    }
    // Shown by `status`: printable text only.
    if r.device_id.is_empty()
        || r.device_id.len() > 128
        || sync_policy::approve::visible(&r.device_id) != r.device_id
    {
        return Err("the portal sent an unusable device id".into());
    }
    Ok(Paired {
        portal: PortalConfig {
            url: uri.portal.to_string(),
            spki_sha256: uri.spki,
            device_id: r.device_id,
            name: name.to_string(),
        },
        token: r.connector_token,
    })
}

pub fn save_token(path: &Path, token: &str) -> Result<(), String> {
    write_private(path, token.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
}

/// Reads the token; refuses a file others can read, since the token opens a shell
/// on this device for whoever holds it.
pub fn load_token(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.mode() & 0o077 != 0 {
            return Err(format!(
                "{} is readable by other users; run chmod 600 on it",
                path.display()
            ));
        }
    }
    let t = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let t = t.trim().to_string();
    if !valid_token(&t) {
        return Err(format!("{} holds no usable token", path.display()));
    }
    Ok(t)
}

/// The portal's refusal as the terminal shows it: its `error` (or the start of
/// its body), cut and with every control character escaped.
fn refusal(status: u16, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let msg = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| text.into_owned());
    let mut cut: String = msg.chars().take(200).collect();
    if cut.len() < msg.len() {
        cut.push('…');
    }
    format!(
        "the portal refused pairing ({status}): {}",
        sync_policy::approve::visible(&cut)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_cannot_redraw_the_terminal() {
        let e = refusal(
            403,
            br#"{"error": "no\u001b[1A\u001b[2KPaired with portal"}"#,
        );
        assert_eq!(
            e,
            "the portal refused pairing (403): no\\u{1b}[1A\\u{1b}[2KPaired with portal"
        );
        let long = format!("{{\"error\": \"{}\"}}", "x".repeat(5000));
        assert!(refusal(400, long.as_bytes()).len() < 300);
        let e = refusal(502, b"<html>\x1b]0;title\x07");
        assert!(!e.chars().any(char::is_control), "{e:?}");
    }

    #[test]
    fn names() {
        assert_eq!(name_from_hostname("My-Laptop.local"), "my-laptop");
        assert_eq!(name_from_hostname("ZORIN_box 2"), "zorin-box-2");
        assert_eq!(name_from_hostname("server"), "device");
        assert_eq!(name_from_hostname("---"), "device");
        assert_eq!(name_from_hostname(&"a".repeat(40)).len(), 24);
        assert!(!valid_name("portal"));
        assert!(!valid_name("Laptop"));
        assert!(valid_name("laptop-2"));
    }

    #[cfg(unix)]
    #[test]
    fn a_token_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("c/token");
        save_token(&p, &"t".repeat(43)).unwrap();
        assert_eq!(load_token(&p).unwrap(), "t".repeat(43));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_token(&p).unwrap_err().contains("chmod"));
    }
}
