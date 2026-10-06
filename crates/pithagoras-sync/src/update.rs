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
//! the newest release time it has seen for each program and the newest one its
//! user installed, and refuses a manifest released before either, so whoever
//! controls the release listing but not the key cannot serve an older signed
//! manifest again to a client that already saw or took a newer one.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::actions::{Runner, argv};
use crate::install::UNIT_NAME;

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
/// for tests and offline updates). `records` are the files with the newest
/// release times taken (the program's own, then this user's): a manifest
/// released before the highest is refused, and a newer time is written to the
/// first. `record` raises this user's once a release is installed.
pub async fn check(
    source: &str,
    key: &str,
    current: &str,
    records: &[&Path],
) -> Result<Offer, String> {
    let data = fetch(source, MAX_MANIFEST as u64).await?;
    let sig = fetch(&format!("{source}.minisig"), 4096).await?;
    let sig = String::from_utf8(sig).map_err(|_| "the signature is not text".to_string())?;
    let manifest = verify(&data, &sig, key)?;
    let new = parse_version(&manifest.version)
        .ok_or_else(|| format!("the manifest's version {:?} is not x.y.z", manifest.version))?;
    let cur = parse_version(current).ok_or("this build's version is not x.y.z")?;
    if let Some(own) = records.first() {
        let last = records.iter().map(|p| read_seen(p)).max().unwrap_or(0);
        if manifest.released < last {
            return Err(format!(
                "the manifest (version {}, released {}) is older than one this client already took (released {}): an older release is being served again, so nothing is installed",
                manifest.version,
                utc(manifest.released),
                utc(last)
            ));
        }
        if manifest.released > read_seen(own) {
            write_seen(own, manifest.released)?;
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

/// Raises the record at `path` to `released`, if that is newer.
pub fn record(path: &Path, released: u64) -> Result<(), String> {
    if released > read_seen(path) {
        write_seen(path, released)?;
    }
    Ok(())
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
/// when a client runs (`running`, from its status), else this one (`me`). As
/// root, `system` is the program the system unit starts (the dedicated user's of
/// `setup`): it is replaced when it is the one run here or root runs no client of
/// its own, so `sudo pithagoras-sync update` updates that unit's client, not a
/// client root runs from elsewhere.
pub fn target_exe(running: Option<&Path>, system: Option<&Path>, me: &Path) -> PathBuf {
    let running = running.filter(|p| p.is_absolute());
    if let Some(s) = system
        && (running.is_none() || same_program(s, me))
    {
        return s.to_path_buf();
    }
    running.unwrap_or(me).to_path_buf()
}

/// The version the program file at `exe` reports, as it is on disk now: what
/// `update` would replace.
pub fn version_of(exe: &Path) -> Option<String> {
    let (ok, said) = run_version(exe).ok()?;
    let v = said.trim().strip_prefix("pithagoras-sync ")?;
    (ok && parse_version(v).is_some()).then(|| v.to_string())
}

/// The version a release is compared with: that of the program `update`
/// replaces. The running client's (`running`: its program and version, from its
/// status) when `target_exe` picks its program, else this one's (`me`).
pub fn current_version<'a>(running: Option<(&Path, &'a str)>, me: &'a str) -> &'a str {
    match running {
        Some((exe, version)) if exe.is_absolute() && parse_version(version).is_some() => version,
        _ => me,
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

/// The system unit `setup` and `install --system` write.
pub fn system_unit_file() -> PathBuf {
    Path::new("/etc/systemd/system").join(UNIT_NAME)
}

/// The program a systemd unit starts: the first word of its `ExecStart=`.
pub fn unit_program(unit: &str) -> Option<PathBuf> {
    unit.lines()
        .find_map(|l| l.trim().strip_prefix("ExecStart="))
        .and_then(|cmd| cmd.split_whitespace().next())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Whether only root can change `exe`: the file and every folder above it
/// belong to root and are not writable by group or others. Root runs and
/// replaces the system unit's program only then: one another user can change
/// would let that user, and the agent's commands running as it, run code as root.
#[cfg(unix)]
pub fn only_root_changes(exe: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    only_owner_changes(exe, 0, |p| {
        std::fs::symlink_metadata(p).map(|m| (m.uid(), m.mode(), m.file_type().is_symlink()))
    })
}

/// `only_root_changes` for an `owner` and a way to `lstat` a path (uid, mode,
/// whether it is a symbolic link). The path is resolved first, then every part
/// of it is checked as it is, so no link can lead elsewhere.
#[cfg(unix)]
fn only_owner_changes(
    exe: &Path,
    owner: u32,
    lstat: impl Fn(&Path) -> std::io::Result<(u32, u32, bool)>,
) -> Result<(), String> {
    let real = std::fs::canonicalize(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    for p in real.ancestors() {
        let (uid, mode, link) = lstat(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let why = if link {
            "is a symbolic link".to_string()
        } else if uid != owner {
            format!("belongs to uid {uid}")
        } else if mode & 0o022 != 0 {
            "is writable by its group or by others".to_string()
        } else {
            continue;
        };
        return Err(format!("{} {why}", p.display()));
    }
    Ok(())
}

/// After `update` as root, for the system unit that starts `exe`: restarts it
/// when it runs and `stale` says its process runs an older file than `exe` is
/// now. A system unit's client cannot be asked to restart itself (its control
/// socket answers its own user only), so systemd does it. What happened, for the
/// owner; `None` when the unit does not run or runs `exe` as it is.
pub fn restart_system_unit(
    runner: &dyn Runner,
    exe: &Path,
    stale: impl Fn(u32) -> bool,
) -> Option<String> {
    let pid = runner
        .run(&argv(&[
            "systemctl",
            "show",
            "-p",
            "MainPID",
            "--value",
            UNIT_NAME,
        ]))
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|p| *p != 0)?;
    if !stale(pid) {
        return None;
    }
    Some(
        match runner.run(&argv(&["systemctl", "restart", UNIT_NAME])) {
            Ok(_) => format!(
                "Restarted {UNIT_NAME}, so its client runs {} as it is now.",
                exe.display()
            ),
            Err(e) => format!(
                "{UNIT_NAME} still runs the program it had and did not restart ({e}): systemctl restart {UNIT_NAME}"
            ),
        },
    )
}

/// Whether process `pid` runs another file than the one at `exe` now: one that
/// was replaced after it started (by this update, or by hand before it).
#[cfg(target_os = "linux")]
pub fn runs_other_file(pid: u32, exe: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // /proc/PID/exe leads to the file the process runs, even once it is deleted.
    match (
        std::fs::metadata(format!("/proc/{pid}/exe")),
        std::fs::metadata(exe),
    ) {
        (Ok(a), Ok(b)) => (a.dev(), a.ino()) != (b.dev(), b.ino()),
        _ => false,
    }
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
    let written = write_new(&tmp, &data)
        .map_err(|e| write_error(e, &tmp, exe))
        .and_then(|()| check_runs(&tmp, &plan.version));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    replace(&tmp, exe).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

fn write_new(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o755);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// A folder this user may not write to holds a program someone else installed:
/// say who updates it rather than a bare errno.
fn write_error(e: std::io::Error, path: &Path, exe: &Path) -> String {
    if e.kind() != std::io::ErrorKind::PermissionDenied {
        return format!("{}: {e}", path.display());
    }
    let dir = exe.parent().unwrap_or(exe).display();
    if cfg!(windows) {
        format!(
            "{} cannot be replaced by this account ({dir} is not writable here): run `update` as the account that installed it, or in an elevated PowerShell",
            exe.display()
        )
    } else {
        format!(
            "{} cannot be replaced by this user ({dir} is not writable here): it was installed by root, as `setup` and `install --system` do, so root updates it: sudo pithagoras-sync update",
            exe.display()
        )
    }
}

/// The new program must start and name the version the manifest promised.
fn check_runs(path: &Path, version: &str) -> Result<(), String> {
    let (ok, said) =
        run_version(path).map_err(|e| format!("the new program does not start: {e}"))?;
    if !ok || said.trim() != format!("pithagoras-sync {version}") {
        return Err(format!(
            "the new program reports {:?}, not version {version}",
            said.trim()
        ));
    }
    Ok(())
}

/// Runs `path --version`: whether it succeeded, and what it printed.
fn run_version(path: &Path) -> std::io::Result<(bool, String)> {
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
            r => break r?,
        }
    };
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
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
        // Absolute on every platform (`/home/u/...` is not on Windows).
        let home = std::env::temp_dir().join("u");
        let me = home.join("Downloads").join("pithagoras-sync");
        let installed = home.join("bin").join("pithagoras-sync");
        assert_eq!(target_exe(Some(&installed), None, &me), installed);
        assert_eq!(target_exe(None, None, &me), me);
        // An old client that does not say where it runs from.
        assert_eq!(target_exe(Some(Path::new("")), None, &me), me);
    }

    #[test]
    fn as_root_update_replaces_the_program_of_the_system_unit() {
        let t = tempfile::tempdir().unwrap();
        let system = t.path().join("usr-local-bin").join("pithagoras-sync");
        let roots = t.path().join("root").join("pithagoras-sync");
        let download = t.path().join("Downloads").join("pithagoras-sync");
        for p in [&system, &roots, &download] {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
        }
        // `sudo pithagoras-sync update` runs the unit's program: that one is
        // replaced, even while root runs a client of its own from elsewhere.
        assert_eq!(target_exe(Some(&roots), Some(&system), &system), system);
        // Run from a download, with no client of root's own: the unit's program.
        assert_eq!(target_exe(None, Some(&system), &download), system);
        // Root's own client, updated with its own program or a download, stays
        // the one replaced.
        assert_eq!(target_exe(Some(&roots), Some(&system), &roots), roots);
        assert_eq!(target_exe(Some(&roots), Some(&system), &download), roots);
    }

    #[cfg(unix)]
    #[test]
    fn the_version_counted_is_that_of_the_file_on_disk() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("pithagoras-sync");
        write_script(&exe, "echo 'pithagoras-sync 0.0.1'");
        assert_eq!(version_of(&exe).as_deref(), Some("0.0.1"));
        write_script(&exe, "echo 'something else 0.0.1'");
        assert_eq!(version_of(&exe), None);
        write_script(&exe, "echo 'pithagoras-sync 0.0.1'; exit 1");
        assert_eq!(version_of(&exe), None);
        assert_eq!(version_of(&t.path().join("missing")), None);
    }

    /// A program that runs `body` (the file replaced in one rename, as `update`
    /// does, so a program still running keeps the old one).
    #[cfg(unix)]
    fn write_script(path: &Path, body: &str) {
        let tmp = path.with_extension("new");
        write_new(&tmp, format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
        std::fs::rename(&tmp, path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn root_takes_only_a_program_no_one_else_can_change() {
        let t = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(t.path()).unwrap();
        let exe = base.join("bin").join("pithagoras-sync");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "x").unwrap();
        std::os::unix::fs::symlink(&exe, base.join("link")).unwrap();
        // Owners and modes as given here, for every path.
        let check = |at: &Path, uid: u32, mode: u32| {
            only_owner_changes(&base.join("link"), 0, |p| {
                Ok(if p == at {
                    (uid, mode, false)
                } else {
                    (0, 0o755, false)
                })
            })
        };
        assert_eq!(check(Path::new("/nowhere"), 0, 0o755), Ok(()));
        // The link is followed, and the file it leads to is what counts.
        let e = check(&exe, 1000, 0o755).unwrap_err();
        assert!(e.contains("pithagoras-sync belongs to uid 1000"), "{e}");
        let e = check(exe.parent().unwrap(), 0, 0o775).unwrap_err();
        assert!(
            e.ends_with("bin is writable by its group or by others"),
            "{e}"
        );
        let e = check(&base, 0, 0o1777).unwrap_err();
        assert!(e.contains("writable by its group or by others"), "{e}");
        assert!(check(Path::new("/"), 0, 0o757).is_err());
        // A part that is a link when checked (swapped in meanwhile).
        let e = only_owner_changes(&exe, 0, |p| Ok((0, 0o755, p == exe.parent().unwrap())))
            .unwrap_err();
        assert!(e.contains("is a symbolic link"), "{e}");
        // For real: a file of this test's user, below /var/tmp or /tmp.
        if unsafe { libc::geteuid() } != 0 {
            assert!(only_root_changes(&exe).is_err());
        }
    }

    #[test]
    fn the_program_of_a_unit_is_its_exec_start() {
        assert_eq!(
            unit_program(&crate::install::system_unit(Some("pithagoras-sync"))),
            Some(PathBuf::from(crate::install::SYSTEM_BIN))
        );
        assert_eq!(
            unit_program("[Service]\nExecStart=/opt/ps/pithagoras-sync run --x\n"),
            Some(PathBuf::from("/opt/ps/pithagoras-sync"))
        );
        assert_eq!(
            unit_program("[Service]\nExecStart=-pithagoras-sync run\n"),
            None
        );
        assert_eq!(unit_program("[Service]\n"), None);
    }

    #[test]
    fn the_system_unit_restarts_when_it_runs_an_older_file() {
        let exe = Path::new("/usr/local/bin/pithagoras-sync");
        let runner = |pid: &str| crate::actions::Fake {
            answers: vec![("systemctl show".into(), Ok(format!("{pid}\n")))],
            ..Default::default()
        };
        let restarts = |r: &crate::actions::Fake| {
            r.ran
                .lock()
                .unwrap()
                .iter()
                .filter(|a| a.get(1).map(String::as_str) == Some("restart"))
                .count()
        };
        // Running an older file: restarted.
        let r = runner("4242");
        let said = restart_system_unit(&r, exe, |pid| pid == 4242).unwrap();
        assert!(
            said.starts_with("Restarted pithagoras-sync.service"),
            "{said}"
        );
        assert_eq!(restarts(&r), 1);
        assert_eq!(
            r.ran.lock().unwrap()[1],
            crate::actions::argv(&["systemctl", "restart", UNIT_NAME])
        );
        // Running the file as it is, or not running: left alone.
        let r = runner("4242");
        assert_eq!(restart_system_unit(&r, exe, |_| false), None);
        assert_eq!(restarts(&r), 0);
        let r = runner("0");
        assert_eq!(restart_system_unit(&r, exe, |_| true), None);
        assert_eq!(restarts(&r), 0);
        // The restart fails: the owner is told how to do it.
        let r = crate::actions::Fake {
            answers: vec![
                ("systemctl show".into(), Ok("7\n".into())),
                ("systemctl restart".into(), Err("denied".into())),
            ],
            ..Default::default()
        };
        let said = restart_system_unit(&r, exe, |_| true).unwrap();
        assert!(
            said.contains("systemctl restart pithagoras-sync.service"),
            "{said}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_running_a_replaced_file_is_seen() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("prog");
        std::fs::write(&exe, std::fs::read("/bin/sh").unwrap()).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut tries = 0;
        let mut child = loop {
            // `; :` keeps the shell from exec'ing sleep in its place.
            match std::process::Command::new(&exe)
                .args(["-c", "sleep 30; :"])
                .spawn()
            {
                Err(e) if text_busy(&e) && tries < 50 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                r => break r.unwrap(),
            }
        };
        let pid = child.id();
        assert!(!runs_other_file(pid, &exe));
        let new = t.path().join("prog.new");
        std::fs::copy(&exe, &new).unwrap();
        std::fs::rename(&new, &exe).unwrap();
        assert!(runs_other_file(pid, &exe));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_release_is_compared_with_the_program_it_replaces() {
        let home = std::env::temp_dir().join("u");
        let installed = home.join("bin").join("pithagoras-sync");
        // A newer download run over an older client: the client's version counts,
        // so the release is due; an older download over a newer client: the same.
        assert_eq!(
            current_version(Some((&installed, "0.0.1")), "0.0.2"),
            "0.0.1"
        );
        assert_eq!(
            current_version(Some((&installed, "0.0.3")), "0.0.2"),
            "0.0.3"
        );
        // No client, or one that does not say its program or a usable version:
        // the program run here is replaced, and its version counts.
        assert_eq!(current_version(None, "0.0.2"), "0.0.2");
        assert_eq!(
            current_version(Some((Path::new(""), "0.0.1")), "0.0.2"),
            "0.0.2"
        );
        assert_eq!(current_version(Some((&installed, "dev")), "0.0.2"), "0.0.2");
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
