//! `pithagoras-sync update`: a newer release, if there is one, replaces this
//! program.
//!
//! A release publishes `manifest.json` and its minisign signature
//! `manifest.json.minisig`. The manifest names the version and, per target, the
//! binary's URL, size and sha256; the signature over the manifest is checked
//! against the public key compiled into this build, the binary against the
//! manifest. Only a newer version is taken (no downgrades). The new binary must
//! report that version, then it replaces this one in one rename, and the running
//! client restarts with it. An update touches nothing but the program file: the
//! config, the policy and the pairing stay as they are.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The release key (minisign public key, base64), set when a release is built.
/// A build without it cannot update itself.
pub const PUBLIC_KEY: Option<&str> = option_env!("PITHAGORAS_SYNC_UPDATE_KEY");

/// Where releases publish their manifest, set when a release is built.
pub const DEFAULT_MANIFEST: Option<&str> = option_env!("PITHAGORAS_SYNC_UPDATE_URL");

/// The largest binary taken.
const MAX_BINARY: u64 = 256 << 20;
const MAX_MANIFEST: usize = 64 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: String,
    /// By target, as `target()` names it (`x86_64-linux`, `x86_64-windows`).
    pub artifacts: BTreeMap<String, Artifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Absolute, or relative to the manifest's location.
    pub url: String,
    pub size: u64,
    /// Hex.
    pub sha256: String,
}

pub fn target() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// `major.minor.patch`, numbers only.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.split('.').map(|p| {
        (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .then(|| p.parse::<u64>().ok())
            .flatten()
    });
    let r = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(r)
}

/// The manifest, if `sig` is a valid signature of `data` by `key`.
pub fn verify(data: &[u8], sig: &str, key: &str) -> Result<Manifest, String> {
    let key = minisign_verify::PublicKey::from_base64(key.trim())
        .map_err(|e| format!("the update key of this build is unusable: {e}"))?;
    let sig = minisign_verify::Signature::decode(sig)
        .map_err(|e| format!("the manifest's signature is unreadable: {e}"))?;
    // Legacy (non-prehashed) signatures are taken too: the manifest is small, and
    // Ed25519 over the whole of it is as strong.
    key.verify(data, &sig, true)
        .map_err(|e| format!("the manifest's signature does not verify: {e}"))?;
    serde_json::from_slice(data).map_err(|e| format!("the manifest is unreadable: {e}"))
}

/// What `update` would install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub version: String,
    pub artifact: Artifact,
    /// The artifact's URL or path, resolved against the manifest's.
    pub source: String,
}

/// Fetches and checks the manifest at `source` (an https URL, or a local path
/// for tests and offline updates). `None` when it offers nothing newer.
pub async fn check(source: &str, key: &str, current: &str) -> Result<Option<Plan>, String> {
    let data = fetch(source, MAX_MANIFEST as u64).await?;
    let sig = fetch(&format!("{source}.minisig"), 4096).await?;
    let sig = String::from_utf8(sig).map_err(|_| "the signature is not text".to_string())?;
    let manifest = verify(&data, &sig, key)?;
    let new = parse_version(&manifest.version)
        .ok_or_else(|| format!("the manifest's version {:?} is not x.y.z", manifest.version))?;
    let cur = parse_version(current).ok_or("this build's version is not x.y.z")?;
    if new <= cur {
        return Ok(None);
    }
    let t = target();
    let artifact = manifest
        .artifacts
        .get(&t)
        .cloned()
        .ok_or_else(|| format!("release {} has no build for {t}", manifest.version))?;
    if artifact.size == 0 || artifact.size > MAX_BINARY {
        return Err(format!("release {}: bad size", manifest.version));
    }
    if artifact.sha256.len() != 64 || !artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("release {}: bad sha256", manifest.version));
    }
    Ok(Some(Plan {
        version: manifest.version,
        source: resolve(source, &artifact.url),
        artifact,
    }))
}

fn is_url(s: &str) -> bool {
    s.starts_with("https://") || s.starts_with("http://")
}

fn resolve(manifest: &str, url: &str) -> String {
    if is_url(url) || Path::new(url).is_absolute() {
        return url.to_string();
    }
    match manifest.rfind('/') {
        Some(i) => format!("{}/{url}", &manifest[..i]),
        None => url.to_string(),
    }
}

async fn fetch(source: &str, max: u64) -> Result<Vec<u8>, String> {
    if is_url(source) {
        return sync_connector::http::get(source, max as usize).await;
    }
    let path = source.strip_prefix("file://").unwrap_or(source);
    let len = std::fs::metadata(path)
        .map_err(|e| format!("{path}: {e}"))?
        .len();
    if len > max {
        return Err(format!("{path}: too large"));
    }
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

/// Downloads the binary, checks it against the manifest and that it runs and
/// reports the new version, then puts it in place of `exe` in one rename. On
/// Windows, where a running program cannot be replaced, the old one is moved
/// aside to `<exe>.old` first.
pub async fn install(plan: &Plan, exe: &Path) -> Result<(), String> {
    let data = fetch(&plan.source, plan.artifact.size).await?;
    if data.len() as u64 != plan.artifact.size {
        return Err(format!(
            "the download has {} bytes, the manifest says {}",
            data.len(),
            plan.artifact.size
        ));
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, &data);
    let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    if !hex.eq_ignore_ascii_case(&plan.artifact.sha256) {
        return Err("the download does not match the manifest's sha256".into());
    }
    let dir = exe.parent().ok_or("this program has no folder")?;
    let tmp = dir.join(format!(".pithagoras-sync.update.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let written = write_new(&tmp, &data).and_then(|()| check_runs(&tmp, &plan.version));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    replace(&tmp, exe).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

fn write_new(path: &Path, data: &[u8]) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o755);
    }
    let mut f = opts.open(path).map_err(err)?;
    f.write_all(data).map_err(err)?;
    f.sync_all().map_err(err)
}

/// The new program must start and name the version the manifest promised.
fn check_runs(path: &Path, version: &str) -> Result<(), String> {
    let out = std::process::Command::new(path)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("the new program does not start: {e}"))?;
    let said = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || said.trim() != format!("pithagoras-sync {version}") {
        return Err(format!(
            "the new program reports {:?}, not version {version}",
            said.trim()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn replace(new: &Path, exe: &Path) -> Result<(), String> {
    std::fs::rename(new, exe).map_err(|e| format!("cannot replace {}: {e}", exe.display()))?;
    if let Some(dir) = exe.parent()
        && let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(windows)]
fn replace(new: &Path, exe: &Path) -> Result<(), String> {
    let old = old_path(exe);
    let _ = std::fs::remove_file(&old);
    std::fs::rename(exe, &old).map_err(|e| format!("cannot move {} aside: {e}", exe.display()))?;
    if let Err(e) = std::fs::rename(new, exe) {
        let _ = std::fs::rename(&old, exe);
        return Err(format!("cannot replace {}: {e}", exe.display()));
    }
    Ok(())
}

/// Where Windows keeps the replaced program until the next update.
pub fn old_path(exe: &Path) -> PathBuf {
    let mut s = exe.as_os_str().to_owned();
    s.push(".old");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_three_numbers() {
        assert_eq!(parse_version("1.20.3"), Some((1, 20, 3)));
        assert!(parse_version("0.2.0") > parse_version("0.1.9"));
        assert!(parse_version("0.10.0") > parse_version("0.9.0"));
        for bad in ["1.2", "1.2.3.4", "1.2.x", "v1.2.3", "1.2.3-rc1", "1..3", ""] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
    }

    #[test]
    fn artifact_urls_resolve_against_the_manifest() {
        assert_eq!(
            resolve("https://h/r/1/manifest.json", "pithagoras-sync-x86_64"),
            "https://h/r/1/pithagoras-sync-x86_64"
        );
        assert_eq!(resolve("https://h/m.json", "https://o/x"), "https://o/x");
        assert_eq!(resolve("/srv/rel/manifest.json", "bin"), "/srv/rel/bin");
    }
}
