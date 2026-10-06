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
//!
//! The manifest says when it was released (signed with the rest). The client keeps
//! the newest release time it has taken and refuses a manifest released before it,
//! so whoever controls the release listing but not the key cannot serve an older
//! signed manifest again to a client that already saw a newer one.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The release key (minisign public key, base64), set when a release is built.
/// A build without it cannot update itself.
pub const PUBLIC_KEY: Option<&str> = option_env!("PITHAGORAS_SYNC_UPDATE_KEY");

/// The stable release channel: the manifest of the newest GitHub release that is
/// not a pre-release (`.github/workflows/release.yml` publishes it).
pub const STABLE_MANIFEST: &str = concat!(
    env!("CARGO_PKG_REPOSITORY"),
    "/releases/latest/download/manifest.json"
);

/// Where `update` looks without `--manifest`: the stable channel, unless a build
/// names another (`PITHAGORAS_SYNC_UPDATE_URL`).
pub const DEFAULT_MANIFEST: &str = match option_env!("PITHAGORAS_SYNC_UPDATE_URL") {
    Some(url) => url,
    None => STABLE_MANIFEST,
};

/// The largest binary taken.
const MAX_BINARY: u64 = 256 << 20;
const MAX_MANIFEST: usize = 64 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: String,
    /// When the release tool made it (Unix seconds, UTC).
    pub released: u64,
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

/// What a checked manifest offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// When it was released (Unix seconds).
    pub released: u64,
    /// `None` when it offers nothing newer than this build.
    pub plan: Option<Plan>,
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
/// for tests and offline updates). `seen` is the file with the newest release
/// time this client took: a manifest released before it is refused, a newer one
/// is written there.
pub async fn check(
    source: &str,
    key: &str,
    current: &str,
    seen: Option<&Path>,
) -> Result<Offer, String> {
    let data = fetch(source, MAX_MANIFEST as u64).await?;
    let sig = fetch(&format!("{source}.minisig"), 4096).await?;
    let sig = String::from_utf8(sig).map_err(|_| "the signature is not text".to_string())?;
    let manifest = verify(&data, &sig, key)?;
    let new = parse_version(&manifest.version)
        .ok_or_else(|| format!("the manifest's version {:?} is not x.y.z", manifest.version))?;
    let cur = parse_version(current).ok_or("this build's version is not x.y.z")?;
    if let Some(seen) = seen {
        let last = read_seen(seen);
        if manifest.released < last {
            return Err(format!(
                "the manifest (version {}, released {}) is older than one this client already took (released {}): an older release is being served again, so nothing is installed",
                manifest.version,
                utc(manifest.released),
                utc(last)
            ));
        }
        if manifest.released > last {
            write_seen(seen, manifest.released)?;
        }
    }
    let released = manifest.released;
    if new <= cur {
        return Ok(Offer {
            released,
            plan: None,
        });
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
    Ok(Offer {
        released,
        plan: Some(Plan {
            version: manifest.version,
            source: resolve(source, &artifact.url),
            artifact,
        }),
    })
}

/// The newest release time taken so far; 0 when none (or the file is unreadable,
/// which only weakens this check, never an update's other checks).
fn read_seen(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_seen(path: &Path, released: u64) -> Result<(), String> {
    let err =
        |e: std::io::Error| format!("cannot record the release time in {}: {e}", path.display());
    if let Some(dir) = path.parent() {
        sync_policy::private::private_dir(dir).map_err(err)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{released}\n")).map_err(err)?;
    std::fs::rename(&tmp, path).map_err(err)
}

/// `secs` as `YYYY-MM-DD HH:MM UTC`.
pub fn utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

fn is_url(s: &str) -> bool {
    s.starts_with("https://") || s.starts_with("http://")
}

fn resolve(manifest: &str, url: &str) -> String {
    if is_url(url) || Path::new(url).is_absolute() {
        return url.to_string();
    }
    // A local manifest: its folder as the platform reads paths, so `C:\rel\` too.
    if !is_url(manifest) {
        let path = manifest.strip_prefix("file://").unwrap_or(manifest);
        return match Path::new(path).parent() {
            Some(dir) => dir.join(url).to_string_lossy().into_owned(),
            None => url.to_string(),
        };
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

/// The program `update` replaces: the one the running client was started from
/// when a client runs (`running`, from its status), else this one (`me`).
pub fn target_exe(running: Option<&Path>, me: &Path) -> PathBuf {
    match running {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        _ => me.to_path_buf(),
    }
}

/// Whether two paths name the same program file.
pub fn same_program(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The copy `install` puts in place for the current user (the one its unit or
/// logon task starts), when it exists and is not `me`.
pub fn installed_copy(me: &Path) -> Option<PathBuf> {
    #[cfg(windows)]
    let p = PathBuf::from(std::env::var_os("LOCALAPPDATA")?)
        .join(r"Programs\pithagoras-sync\pithagoras-sync.exe");
    #[cfg(not(windows))]
    let p = PathBuf::from(std::env::var_os("HOME")?).join(".local/bin/pithagoras-sync");
    (p.is_file() && !same_program(&p, me)).then_some(p)
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
    let mut tries = 0;
    let out = loop {
        match std::process::Command::new(path)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .output()
        {
            // A process forked by another thread while the file was open for
            // writing holds it open until it execs: try again shortly.
            Err(e) if text_busy(&e) && tries < 50 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            r => break r.map_err(|e| format!("the new program does not start: {e}"))?,
        }
    };
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
fn text_busy(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ETXTBSY)
}

#[cfg(windows)]
fn text_busy(_e: &std::io::Error) -> bool {
    false
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
    fn update_replaces_the_program_the_running_client_was_started_from() {
        let me = Path::new("/home/u/Downloads/pithagoras-sync");
        let installed = Path::new("/home/u/.local/bin/pithagoras-sync");
        assert_eq!(target_exe(Some(installed), me), installed);
        assert_eq!(target_exe(None, me), me);
        // An old client that does not say where it runs from.
        assert_eq!(target_exe(Some(Path::new("")), me), me);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_the_program_is_the_same_program() {
        let t = tempfile::tempdir().unwrap();
        let a = t.path().join("a");
        std::fs::write(&a, "x").unwrap();
        std::os::unix::fs::symlink(&a, t.path().join("b")).unwrap();
        assert!(same_program(&a, &t.path().join("b")));
        std::fs::write(t.path().join("c"), "x").unwrap();
        assert!(!same_program(&a, &t.path().join("c")));
    }

    #[test]
    fn updates_come_from_the_stable_release_channel() {
        assert_eq!(
            STABLE_MANIFEST,
            "https://github.com/Piggidragon/Pithagoras-Sync/releases/latest/download/manifest.json"
        );
        if option_env!("PITHAGORAS_SYNC_UPDATE_URL").is_none() {
            assert_eq!(DEFAULT_MANIFEST, STABLE_MANIFEST);
        }
    }

    #[test]
    fn release_times_read_as_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(951_782_400 + 3_660), "2000-02-29 01:01 UTC");
        assert_eq!(utc(1_791_244_800), "2026-10-06 00:00 UTC");
    }

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
        assert_eq!(resolve("manifest.json", "bin"), "bin");
        #[cfg(unix)]
        {
            assert_eq!(resolve("/srv/rel/manifest.json", "bin"), "/srv/rel/bin");
            assert_eq!(
                resolve("file:///srv/rel/manifest.json", "bin"),
                "/srv/rel/bin"
            );
        }
        #[cfg(windows)]
        assert_eq!(resolve(r"C:\rel\manifest.json", "bin"), r"C:\rel\bin");
    }
}
