//! What a release of Pithagoras Sync publishes besides its binaries: the update
//! manifest (`manifest.json`: the version and, per target, each binary's URL, size
//! and sha256), its minisign signature by the release key, and `SHA256SUMS`.
//! `pithagoras-sync update` checks the signature against the public key compiled
//! into the client, then each binary against the manifest (`docs/releasing.md`).

pub mod minisign;

use std::path::Path;

/// `major.minor.patch`, numbers only: what the client's updater takes.
pub fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// A target as the client names its own (`x86_64-linux`, `aarch64-linux`,
/// `x86_64-windows`): Rust's architecture and OS.
pub fn valid_target(t: &str) -> bool {
    let mut parts = t.split('-');
    let ok = |p: Option<&str>| {
        p.is_some_and(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
    };
    ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
}

pub fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One binary of the release and the target it is for.
pub struct Binary<'a> {
    pub path: &'a Path,
    pub target: &'a str,
}

/// The manifest for `binaries`. Each URL is `base_url/<file name>`, or the bare
/// file name without a base (resolved against the manifest's own location, as for
/// a release in a local folder).
pub fn manifest(
    version: &str,
    base_url: Option<&str>,
    binaries: &[Binary],
) -> Result<String, String> {
    if !valid_version(version) {
        return Err(format!("version {version:?} is not x.y.z"));
    }
    if binaries.is_empty() {
        return Err("a release needs at least one binary".into());
    }
    let mut artifacts = serde_json::Map::new();
    for b in binaries {
        if !valid_target(b.target) {
            return Err(format!(
                "target {:?} is not <arch>-<os> (x86_64-linux)",
                b.target
            ));
        }
        if artifacts.contains_key(b.target) {
            return Err(format!("two binaries for {}", b.target));
        }
        let data = std::fs::read(b.path).map_err(|e| format!("{}: {e}", b.path.display()))?;
        if data.is_empty() {
            return Err(format!("{} is empty", b.path.display()));
        }
        let name = b
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{}: no file name", b.path.display()))?;
        let url = match base_url {
            Some(base) => format!("{}/{name}", base.trim_end_matches('/')),
            None => name.to_string(),
        };
        artifacts.insert(
            b.target.to_string(),
            serde_json::json!({
                "url": url,
                "size": data.len(),
                "sha256": sha256_hex(&data),
            }),
        );
    }
    let m = serde_json::json!({"version": version, "artifacts": artifacts});
    Ok(serde_json::to_string_pretty(&m).map_err(|e| e.to_string())? + "\n")
}

/// `SHA256SUMS` for `files`, in the format `sha256sum -c` reads.
pub fn sha256sums(files: &[&Path]) -> Result<String, String> {
    let mut out = String::new();
    for f in files {
        let data = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
        let name = f
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        out.push_str(&format!("{}  {name}\n", sha256_hex(&data)));
    }
    Ok(out)
}

/// Checks a `.minisig` for `data` against a minisign public key (base64), as the
/// client will.
pub fn verify(data: &[u8], sig: &str, public_key: &str) -> Result<(), String> {
    let key = minisign_verify::PublicKey::from_base64(public_key.trim())
        .map_err(|e| format!("the public key is unusable: {e}"))?;
    let sig = minisign_verify::Signature::decode(sig)
        .map_err(|e| format!("the signature is unreadable: {e}"))?;
    key.verify(data, &sig, true)
        .map_err(|e| format!("the signature does not verify: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use minisign::SigningKey;

    #[test]
    fn a_manifest_names_each_binary_with_its_size_and_hash() {
        let dir = tempfile::tempdir().unwrap();
        let linux = dir.path().join("pithagoras-sync-x86_64-linux");
        let win = dir.path().join("pithagoras-sync-x86_64-windows.exe");
        std::fs::write(&linux, b"linux binary").unwrap();
        std::fs::write(&win, b"windows binary!").unwrap();
        let text = manifest(
            "1.2.3",
            Some("https://example.org/releases/download/v1.2.3/"),
            &[
                Binary {
                    path: &linux,
                    target: "x86_64-linux",
                },
                Binary {
                    path: &win,
                    target: "x86_64-windows",
                },
            ],
        )
        .unwrap();
        let m: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(m["version"], "1.2.3");
        let a = &m["artifacts"]["x86_64-linux"];
        assert_eq!(
            a["url"],
            "https://example.org/releases/download/v1.2.3/pithagoras-sync-x86_64-linux"
        );
        assert_eq!(a["size"], 12);
        assert_eq!(a["sha256"], sha256_hex(b"linux binary"));
        assert_eq!(m["artifacts"]["x86_64-windows"]["size"], 15);
        let local = manifest(
            "1.2.3",
            None,
            &[Binary {
                path: &linux,
                target: "x86_64-linux",
            }],
        )
        .unwrap();
        assert!(local.contains("\"url\": \"pithagoras-sync-x86_64-linux\""));
        let sums = sha256sums(&[&linux]).unwrap();
        assert_eq!(
            sums,
            format!(
                "{}  pithagoras-sync-x86_64-linux\n",
                sha256_hex(b"linux binary")
            )
        );
    }

    #[test]
    fn refuses_what_the_client_would_not_take() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("bin");
        std::fs::write(&f, b"x").unwrap();
        let one = |target| [Binary { path: &f, target }];
        for v in ["v1.2.3", "1.2", "1.2.3-rc1"] {
            assert!(manifest(v, None, &one("x86_64-linux")).is_err(), "{v}");
        }
        for t in ["x86_64", "x86_64-linux-musl", "X86_64-Linux", ""] {
            assert!(manifest("1.2.3", None, &one(t)).is_err(), "{t}");
        }
        assert!(manifest("1.2.3", None, &[]).is_err());
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(
            manifest(
                "1.2.3",
                None,
                &[Binary {
                    path: &empty,
                    target: "x86_64-linux"
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn signatures_verify_with_the_public_key_only() {
        let key = SigningKey::generate();
        let other = SigningKey::generate();
        let sig = key.sign(b"manifest", "file:manifest.json");
        assert!(verify(b"manifest", &sig, &key.public_base64()).is_ok());
        assert!(verify(b"manifest!", &sig, &key.public_base64()).is_err());
        assert!(verify(b"manifest", &sig, &other.public_base64()).is_err());
        // A key survives its file.
        let again = SigningKey::import(&key.export()).unwrap();
        assert_eq!(again.public_base64(), key.public_base64());
    }
}
