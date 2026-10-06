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

/// Private like the other state files: a new 0600 file replaces the old one,
/// so one written before with a looser mode is tightened too.
fn write_seen(path: &Path, released: u64) -> Result<(), String> {
    sync_policy::config::write_private(path, format!("{released}\n").as_bytes())
        .map_err(|e| format!("cannot record the release time in {}: {e}", path.display()))
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

/// Whether version `a` is older than `b` (both `x.y.z`).
pub fn is_older(a: &str, b: &str) -> bool {
    matches!((parse_version(a), parse_version(b)), (Some(a), Some(b)) if a < b)
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

/// The program the system unit starts, as systemd has it: drop-ins and an
/// `ExecStart=` reset included, which the unit file alone does not show.
pub fn unit_program(runner: &dyn Runner) -> Option<PathBuf> {
    let show = runner
        .run(&argv(&[
            "systemctl",
            "show",
            "-p",
            "ExecStart",
            "--value",
            UNIT_NAME,
        ]))
        .ok()?;
    exec_start_path(&show)
}

/// The `path=` of what `systemctl show -p ExecStart --value` prints:
/// `{ path=/usr/local/bin/pithagoras-sync ; argv[]=... ; ... }`.
fn exec_start_path(show: &str) -> Option<PathBuf> {
    let rest = &show[show.find("path=")? + "path=".len()..];
    let path = rest.split(" ;").next()?.trim();
    Some(PathBuf::from(path)).filter(|p| p.is_absolute())
}

/// What a process runs, seen against the program file at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runs {
    /// That file, as it is now.
    Same,
    /// The file that was at that path before it was replaced.
    Replaced,
    /// Another program.
    Other(PathBuf),
}

/// What `lstat` tells about one path, for `root_program`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    /// Where it leads, when it is a symbolic link.
    pub link: Option<PathBuf>,
}

/// The file system as `root_program` sees it, so tests can give owners and
/// modes a test cannot make for real.
pub trait Fs {
    /// `None` when nothing is at `path`.
    fn lstat(&self, path: &Path) -> std::io::Result<Option<Node>>;
    fn user_name(&self, uid: u32) -> Option<String>;
    fn group_name(&self, gid: u32) -> Option<String>;
}

/// The real file system.
pub struct RealFs;

impl Fs for RealFs {
    #[cfg(unix)]
    fn lstat(&self, path: &Path) -> std::io::Result<Option<Node>> {
        use std::os::unix::fs::MetadataExt;
        let m = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let link = if m.file_type().is_symlink() {
            Some(std::fs::read_link(path)?)
        } else {
            None
        };
        Ok(Some(Node {
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            link,
        }))
    }

    #[cfg(not(unix))]
    fn lstat(&self, _path: &Path) -> std::io::Result<Option<Node>> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    #[cfg(unix)]
    fn user_name(&self, uid: u32) -> Option<String> {
        let mut buf = vec![0 as libc::c_char; 4096];
        // SAFETY: zeroed passwd struct; getpwuid_r writes into `pw` and `buf`.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
        if r != 0 || out.is_null() {
            return None;
        }
        // SAFETY: on success pw_name points to a NUL-terminated string in `buf`.
        let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) };
        Some(name.to_string_lossy().into_owned())
    }

    #[cfg(unix)]
    fn group_name(&self, gid: u32) -> Option<String> {
        let mut buf = vec![0 as libc::c_char; 4096];
        // SAFETY: zeroed group struct; getgrgid_r writes into `gr` and `buf`.
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::group = std::ptr::null_mut();
        let r = unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr(), buf.len(), &mut out) };
        if r != 0 || out.is_null() {
            return None;
        }
        // SAFETY: on success gr_name points to a NUL-terminated string in `buf`.
        let name = unsafe { std::ffi::CStr::from_ptr(gr.gr_name) };
        Some(name.to_string_lossy().into_owned())
    }

    #[cfg(not(unix))]
    fn user_name(&self, _uid: u32) -> Option<String> {
        None
    }

    #[cfg(not(unix))]
    fn group_name(&self, _gid: u32) -> Option<String> {
        None
    }
}

/// The program `update` replaces, and whether it is the system unit's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub exe: PathBuf,
    pub unit: bool,
}

/// `target_exe`, and when that is the system unit's program (`system`, as
/// root), the path `root_program` checked and resolved: only that path is run,
/// replaced and compared from then on, so no link can be turned elsewhere
/// between the check and its use.
pub fn choose_target(
    running: Option<&Path>,
    system: Option<&Path>,
    me: &Path,
    fs: &dyn Fs,
) -> Result<Target, String> {
    let exe = target_exe(running, system, me);
    let Some(s) = system else {
        return Ok(Target { exe, unit: false });
    };
    let checked = root_program(s, fs);
    // The unit's program is the path `target_exe` took from it as given. A second
    // look at the file system must not decide that: a link its user turns between
    // two looks would make the two answers differ and skip the check.
    let is_unit = exe == s
        || match &checked {
            Ok(resolved) => std::fs::canonicalize(&exe).is_ok_and(|e| &e == resolved),
            Err(_) => same_program(s, &exe),
        };
    if !is_unit {
        return Ok(Target { exe, unit: false });
    }
    Ok(Target {
        exe: checked?,
        unit: true,
    })
}

/// The system unit's program `given` with every link resolved, if only root can
/// change what it leads to: every folder on the way, every folder that holds a
/// link on the way, and the file belong to root and are not writable by group
/// or others. Root runs and replaces the unit's program only then: one another
/// user can change (or a link they can turn) would let that user, and the
/// agent's commands running as it, run code as root.
pub fn root_program(given: &Path, fs: &dyn Fs) -> Result<PathBuf, String> {
    use std::path::Component;
    enum Part {
        Up,
        Name(std::ffi::OsString),
    }
    let parts = |p: &Path| -> Vec<Part> {
        p.components()
            .filter_map(|c| match c {
                Component::ParentDir => Some(Part::Up),
                Component::Normal(n) => Some(Part::Name(n.to_owned())),
                _ => None,
            })
            .collect()
    };
    let refuse = |part: &Path, why: &str, cure: &str| {
        format!(
            "the system unit starts {}, but {} {why}, so another user could change what root runs: root neither runs nor replaces it. To fix it: {cure}",
            given.display(),
            part.display()
        )
    };
    // A name comes from the account database and goes to root's terminal.
    let named = |name: Option<String>, id: u32| match name {
        Some(n) => format!("{} ({id})", sync_policy::approve::visible(&n)),
        None => id.to_string(),
    };
    let stat = |p: &Path| fs.lstat(p).map_err(|e| format!("{}: {e}", p.display()));
    // Each refusal names the cure for the part that failed, never another
    // place to put the program that may fail the same way.
    let root_only = |p: &Path, n: &Node| -> Result<(), String> {
        let at = p.display();
        if n.uid != 0 {
            Err(refuse(
                p,
                &format!(
                    "belongs to user {}, not root",
                    named(fs.user_name(n.uid), n.uid)
                ),
                &format!(
                    "sudo chown root {at}, or let the unit start a copy in folders only root can change"
                ),
            ))
        } else if n.mode & 0o002 != 0 && n.mode & 0o1000 != 0 {
            Err(refuse(
                p,
                "is a folder every user can write to",
                "keep the program out of it",
            ))
        } else if n.mode & 0o002 != 0 {
            Err(refuse(
                p,
                "is writable by every user",
                &format!("sudo chmod o-w {at}"),
            ))
        } else if n.mode & 0o020 != 0 {
            Err(refuse(
                p,
                &format!(
                    "is writable by group {}",
                    named(fs.group_name(n.gid), n.gid)
                ),
                &format!("sudo chmod g-w {at}"),
            ))
        } else {
            Ok(())
        }
    };
    if !given.is_absolute() {
        return Err(format!(
            "the system unit's program {} is not an absolute path",
            given.display()
        ));
    }
    let mut cur = PathBuf::from("/");
    let top = stat(&cur)?.ok_or("/ is missing")?;
    root_only(&cur, &top)?;
    let mut todo: std::collections::VecDeque<Part> = parts(given).into();
    let mut links = 0;
    while let Some(part) = todo.pop_front() {
        let name = match part {
            // `cur` is a real folder already checked, and so is its parent.
            Part::Up => {
                cur.pop();
                continue;
            }
            Part::Name(n) => n,
        };
        let p = cur.join(&name);
        let Some(node) = stat(&p)? else {
            // The program itself may be missing (deleted by hand): its folder
            // passed, so `update` may put a release there again.
            if todo.is_empty() {
                return Ok(p);
            }
            return Err(format!(
                "the system unit starts {}, but {} does not exist: install the program again with `sudo pithagoras-sync install --system --user <name>` or `setup`",
                given.display(),
                p.display()
            ));
        };
        match node.link {
            // The link's folder, `cur`, passed: only root can turn it.
            Some(to) => {
                links += 1;
                if links > 40 {
                    return Err(format!("{}: too many links", given.display()));
                }
                if to.is_absolute() {
                    cur = PathBuf::from("/");
                }
                for (i, part) in parts(&to).into_iter().enumerate() {
                    todo.insert(i, part);
                }
            }
            None => {
                root_only(&p, &node)?;
                cur = p;
            }
        }
    }
    Ok(cur)
}

/// After `setup` or `install --system`: what `update` will refuse about the
/// program the system unit starts, so the owner learns it now and not at the
/// first update.
pub fn installed_warning(fs: &dyn Fs) -> Option<String> {
    root_program(Path::new(crate::install::SYSTEM_BIN), fs)
        .err()
        .map(|e| format!("warning: {e}; until then, `update` refuses it"))
}

/// After `update` as root, for the system unit that starts `exe`: restarts it
/// when its process runs the file that was at `exe` before (`look` tells what
/// it runs; when it cannot, `replaced` says whether this update replaced the
/// file). A system unit's client cannot be asked to restart itself (its control
/// socket answers its own user only), so systemd does it, unless its process is
/// `restarting` (this user's client, already asked to restart). A unit that runs
/// another program is left alone and the owner told, so `update` never restarts
/// it over and over without effect. What happened, for the owner; `None` when
/// there is nothing to say.
pub fn restart_system_unit(
    runner: &dyn Runner,
    exe: &Path,
    replaced: bool,
    restarting: Option<u32>,
    look: impl Fn(u32) -> Option<Runs>,
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
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|p| *p != 0);
    let Some(pid) = pid else {
        // A client that was just asked to restart has exited, and systemd
        // starts it again after RestartSec: no main process meanwhile.
        return (replaced && restarting.is_none()).then(|| {
            format!(
                "{UNIT_NAME} is not running; it starts {} as it is now when it starts.",
                exe.display()
            )
        });
    };
    if restarting == Some(pid) {
        return None;
    }
    match look(pid) {
        Some(Runs::Replaced) => {}
        None if replaced => {}
        Some(Runs::Other(p)) => {
            return Some(format!(
                "{UNIT_NAME} runs {}, not {}, so it was not restarted. Once it should run {}: sudo systemctl restart {UNIT_NAME}",
                // Named by the unit's process, so escaped like other text from
                // outside: it cannot redraw root's terminal.
                sync_policy::approve::visible(&p.to_string_lossy()),
                exe.display(),
                exe.display()
            ));
        }
        Some(Runs::Same) | None => return None,
    }
    Some(
        match runner.run(&argv(&["systemctl", "restart", UNIT_NAME])) {
            Ok(_) => format!(
                "Restarted {UNIT_NAME}, so its client runs {} as it is now.",
                exe.display()
            ),
            Err(e) => format!(
                "{UNIT_NAME} still runs the program it had and did not restart ({e}): sudo systemctl restart {UNIT_NAME}"
            ),
        },
    )
}

/// What process `pid` runs, seen against the file at `exe`: that file, the one
/// that was there before it was replaced (by this update, or by hand before
/// it), or another program. `None` when it cannot be told.
#[cfg(target_os = "linux")]
pub fn what_runs(pid: u32, exe: &Path) -> Option<Runs> {
    use std::os::unix::fs::MetadataExt;
    let proc_exe = format!("/proc/{pid}/exe");
    // The link names the path the program was started from, marked once the
    // file is deleted (replaced); the link itself leads to the running file.
    let named = std::fs::read_link(&proc_exe).ok()?;
    let named = named.to_string_lossy();
    let path = PathBuf::from(named.strip_suffix(" (deleted)").unwrap_or(&named));
    let exe_real = std::fs::canonicalize(exe).ok()?;
    if path != exe_real {
        return Some(Runs::Other(path));
    }
    let (a, b) = (
        std::fs::metadata(&proc_exe).ok()?,
        std::fs::metadata(exe).ok()?,
    );
    Some(if (a.dev(), a.ino()) == (b.dev(), b.ino()) {
        Runs::Same
    } else {
        Runs::Replaced
    })
}

/// Downloads the binary, checks it against the manifest and that it runs and
/// reports the new version, then puts it in place of `exe` in one rename. On
/// Windows, where a running program cannot be replaced, the old one is moved
/// aside to `<exe>.old` first. A link to the program stays a link: the file it
/// leads to is replaced, so the program keeps its path, and with it its record
/// of the releases taken. On failure the program is left as it was, and the
/// error says so: no client is restarted either.
pub async fn install(plan: &Plan, exe: &Path) -> Result<(), String> {
    put_in_place(plan, exe).await.map_err(Failed::text)
}

/// Why an install failed: before the program was touched, or halfway (on
/// Windows, moved aside and not back), which the owner must hear about.
#[derive(Debug)]
enum Failed {
    Before(String),
    #[cfg_attr(not(windows), allow(dead_code))]
    Halfway(String),
}

impl Failed {
    fn text(self) -> String {
        match self {
            Failed::Before(e) => format!("{e} (nothing was replaced, and no client was restarted)"),
            Failed::Halfway(e) => e,
        }
    }
}

impl From<String> for Failed {
    fn from(e: String) -> Failed {
        Failed::Before(e)
    }
}

impl From<&str> for Failed {
    fn from(e: &str) -> Failed {
        Failed::Before(e.to_string())
    }
}

/// The program was moved aside to `old` and the new one did not take its place
/// (`e`), and moving it back failed too (`back`): it is gone from `exe`.
#[cfg_attr(not(windows), allow(dead_code))]
fn not_moved_back(exe: &Path, old: &Path, e: &std::io::Error, back: &std::io::Error) -> Failed {
    Failed::Halfway(format!(
        "cannot replace {}: {e}; moving the old program back failed as well ({back}), so it is now {}: move it back to {} by hand, or its logon task finds no program (no client was restarted)",
        exe.display(),
        old.display(),
        exe.display()
    ))
}

async fn put_in_place(plan: &Plan, exe: &Path) -> Result<(), Failed> {
    // A missing program (put back by this update) resolves through its folder.
    #[cfg(unix)]
    let exe = &match std::fs::canonicalize(exe) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && exe.file_name().is_some() => {
            let dir = exe.parent().ok_or("this program has no folder")?;
            std::fs::canonicalize(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?
                .join(exe.file_name().unwrap_or_default())
        }
        Err(e) => return Err(format!("{}: {e}", exe.display()).into()),
    };
    let data = fetch(&plan.source, plan.artifact.size).await?;
    if data.len() as u64 != plan.artifact.size {
        return Err(format!(
            "the download has {} bytes, the manifest says {}",
            data.len(),
            plan.artifact.size
        )
        .into());
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
        .map_err(|e| write_error(e, &tmp, exe, &RealFs, my_uid()))
        .and_then(|()| check_runs(&tmp, &plan.version));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
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
    // The umask masks the mode above: under root's 077 the dedicated user could
    // not start the program.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
    }
    f.write_all(data)?;
    f.sync_all()
}

/// This user's uid; on Windows, where `write_error` does not look at owners, 0.
fn my_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    0
}

/// A folder this user may not write to: say why and who can update the program
/// in it rather than a bare errno. Only a folder of root's is root's to update.
fn write_error(e: std::io::Error, path: &Path, exe: &Path, fs: &dyn Fs, me: u32) -> String {
    if e.kind() != std::io::ErrorKind::PermissionDenied {
        return format!("{}: {e}", path.display());
    }
    let folder = exe.parent().unwrap_or(exe);
    let dir = folder.display();
    let head = format!(
        "{} cannot be replaced by this {} ({dir} is not writable here)",
        exe.display(),
        if cfg!(windows) { "account" } else { "user" }
    );
    if cfg!(windows) {
        return format!(
            "{head}: run `update` as the account that installed it, or in an elevated PowerShell"
        );
    }
    match fs.lstat(folder).ok().flatten().map(|n| n.uid) {
        Some(0) => format!(
            "{head}: it was installed by root, as `setup` and `install --system` do, so root updates it: sudo pithagoras-sync update"
        ),
        Some(uid) if uid == me => {
            format!("{head}: the folder is this user's own, so make it writable: chmod u+w {dir}")
        }
        Some(uid) => {
            let who = fs
                .user_name(uid)
                .map_or(format!("uid {uid}"), |n| format!("user {n} ({uid})"));
            format!("{head}: it belongs to {who}, so run `update` as that user")
        }
        None => head,
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
fn replace(new: &Path, exe: &Path) -> Result<(), Failed> {
    std::fs::rename(new, exe).map_err(|e| format!("cannot replace {}: {e}", exe.display()))?;
    if let Some(dir) = exe.parent()
        && let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(windows)]
fn replace(new: &Path, exe: &Path) -> Result<(), Failed> {
    let old = old_path(exe);
    let _ = std::fs::remove_file(&old);
    std::fs::rename(exe, &old).map_err(|e| format!("cannot move {} aside: {e}", exe.display()))?;
    if let Err(e) = std::fs::rename(new, exe) {
        if let Err(back) = std::fs::rename(&old, exe) {
            return Err(not_moved_back(exe, &old, &e, &back));
        }
        return Err(format!("cannot replace {}: {e}", exe.display()).into());
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

    /// A file system given as (path, uid, gid, mode, link) rows.
    #[cfg(unix)]
    struct FakeFs(Vec<(&'static str, u32, u32, u32, Option<&'static str>)>);

    #[cfg(unix)]
    impl Fs for FakeFs {
        fn lstat(&self, path: &Path) -> std::io::Result<Option<Node>> {
            Ok(self
                .0
                .iter()
                .find(|r| Path::new(r.0) == path)
                .map(|&(_, uid, gid, mode, link)| Node {
                    uid,
                    gid,
                    mode,
                    link: link.map(PathBuf::from),
                }))
        }

        fn user_name(&self, uid: u32) -> Option<String> {
            (uid == 1000).then(|| "svc".to_string())
        }

        fn group_name(&self, gid: u32) -> Option<String> {
            (gid == 50).then(|| "staff".to_string())
        }
    }

    /// The layout `setup` makes, plus `extra` rows (which come first).
    #[cfg(unix)]
    fn layout(extra: &[(&'static str, u32, u32, u32, Option<&'static str>)]) -> FakeFs {
        let mut v = extra.to_vec();
        v.extend([
            ("/", 0, 0, 0o40755, None),
            ("/usr", 0, 0, 0o40755, None),
            ("/usr/local", 0, 0, 0o40755, None),
            ("/usr/local/bin", 0, 0, 0o40755, None),
            ("/usr/local/bin/pithagoras-sync", 0, 0, 0o100755, None),
            ("/opt", 0, 0, 0o40755, None),
            ("/home", 0, 0, 0o40755, None),
            ("/home/svc", 1000, 1000, 0o40700, None),
            ("/home/svc/bin", 1000, 1000, 0o40755, None),
        ]);
        FakeFs(v)
    }

    #[cfg(unix)]
    #[test]
    fn root_takes_only_a_program_no_one_else_can_change() {
        let bin = Path::new("/usr/local/bin/pithagoras-sync");
        assert_eq!(root_program(bin, &layout(&[])), Ok(bin.to_path_buf()));
        // The file, or a folder above it, of another user or writable by others.
        for (row, part) in [
            (
                ("/usr/local/bin/pithagoras-sync", 1000, 0, 0o100755, None),
                "pithagoras-sync belongs to user svc (1000)",
            ),
            (
                ("/usr/local/bin", 0, 50, 0o42775, None),
                "/usr/local/bin is writable",
            ),
            (("/usr", 0, 0, 0o40757, None), "/usr is writable"),
        ] {
            let e = root_program(bin, &layout(&[row])).unwrap_err();
            assert!(e.contains(part), "{e}");
        }
        // A link in a folder of uid 1000 leading to a root-only file: that user
        // could turn the link anywhere, so it is refused.
        let fs = layout(&[(
            "/home/svc/bin/pithagoras-sync",
            1000,
            1000,
            0o120777,
            Some("/usr/local/bin/pithagoras-sync"),
        )]);
        let e = root_program(Path::new("/home/svc/bin/pithagoras-sync"), &fs).unwrap_err();
        assert!(e.contains("/home/svc belongs to user svc (1000)"), "{e}");
        // A link in root's folders is followed, and the file it leads to is
        // what root runs and replaces; relative links and `..` too.
        let fs = layout(&[
            ("/opt/ps", 0, 0, 0o40755, None),
            ("/opt/ps/pithagoras-sync", 0, 0, 0o100755, None),
            (
                "/usr/local/bin/pithagoras-sync",
                0,
                0,
                0o120777,
                Some("../../../opt/ps/pithagoras-sync"),
            ),
        ]);
        assert_eq!(
            root_program(bin, &fs),
            Ok(PathBuf::from("/opt/ps/pithagoras-sync"))
        );
        // ... but a link that leads into another user's folder is refused there.
        let fs = layout(&[
            ("/home/svc/bin/pithagoras-sync", 1000, 1000, 0o100755, None),
            (
                "/usr/local/bin/pithagoras-sync",
                0,
                0,
                0o120777,
                Some("/home/svc/bin/pithagoras-sync"),
            ),
        ]);
        let e = root_program(bin, &fs).unwrap_err();
        assert!(e.contains("/home/svc belongs to user svc (1000)"), "{e}");
        // The program itself missing: its folder passed, so a release may go
        // there; a missing folder is said plainly.
        let fs = FakeFs(
            layout(&[])
                .0
                .into_iter()
                .filter(|r| r.0 != "/usr/local/bin/pithagoras-sync")
                .collect(),
        );
        assert_eq!(root_program(bin, &fs), Ok(bin.to_path_buf()));
        let e = root_program(Path::new("/usr/local/sbin/pithagoras-sync"), &fs).unwrap_err();
        assert!(
            e.contains("/usr/local/sbin does not exist: install the program again"),
            "{e}"
        );
        assert!(!e.contains("another user"), "{e}");
        // A loop of links ends.
        let fs = layout(&[(
            "/usr/local/bin/pithagoras-sync",
            0,
            0,
            0o120777,
            Some("pithagoras-sync"),
        )]);
        assert!(
            root_program(bin, &fs)
                .unwrap_err()
                .contains("too many links")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_refusal_names_who_can_write_and_the_cure() {
        let bin = Path::new("/usr/local/bin/pithagoras-sync");
        // Debian's old root:staff 2775 /usr/local/bin.
        let e =
            root_program(bin, &layout(&[("/usr/local/bin", 0, 50, 0o42775, None)])).unwrap_err();
        assert!(
            e.contains("/usr/local/bin is writable by group staff (50)"),
            "{e}"
        );
        assert!(
            e.ends_with("To fix it: sudo chmod g-w /usr/local/bin"),
            "{e}"
        );
        // It does not send the owner to the folder that failed.
        assert!(!e.contains("where `setup`"), "{e}");
        let e = root_program(bin, &layout(&[("/usr/local", 0, 0, 0o40757, None)])).unwrap_err();
        assert!(e.ends_with("is writable by every user, so another user could change what root runs: root neither runs nor replaces it. To fix it: sudo chmod o-w /usr/local"), "{e}");
        let e = root_program(
            bin,
            &layout(&[("/usr/local/bin/pithagoras-sync", 1000, 1000, 0o100755, None)]),
        )
        .unwrap_err();
        assert!(e.contains("belongs to user svc (1000), not root"), "{e}");
        assert!(
            e.contains("sudo chown root /usr/local/bin/pithagoras-sync"),
            "{e}"
        );
        let e = root_program(bin, &layout(&[("/usr/local/bin", 0, 0, 0o41777, None)])).unwrap_err();
        assert!(e.contains("is a folder every user can write to"), "{e}");
        // `setup` and `install --system` warn about it right away.
        assert!(installed_warning(&layout(&[])).is_none());
        let w = installed_warning(&layout(&[("/usr/local/bin", 0, 50, 0o42775, None)])).unwrap();
        assert!(w.starts_with("warning: the system unit starts /usr/local/bin/pithagoras-sync, but /usr/local/bin is writable by group staff"), "{w}");
    }

    #[cfg(unix)]
    #[test]
    fn root_uses_only_the_checked_path_of_the_units_program() {
        let fs = layout(&[
            ("/opt/ps", 0, 0, 0o40755, None),
            ("/opt/ps/pithagoras-sync", 0, 0, 0o100755, None),
            (
                "/usr/local/bin/pithagoras-sync",
                0,
                0,
                0o120777,
                Some("/opt/ps/pithagoras-sync"),
            ),
        ]);
        let unit = Path::new("/usr/local/bin/pithagoras-sync");
        let me = Path::new("/nowhere/pithagoras-sync");
        // `sudo pithagoras-sync update` with no client of root's own: the unit's
        // program, checked and resolved.
        assert_eq!(
            choose_target(None, Some(unit), me, &fs),
            Ok(Target {
                exe: PathBuf::from("/opt/ps/pithagoras-sync"),
                unit: true
            })
        );
        // Refused before anything runs it.
        let bad = layout(&[("/usr/local/bin", 0, 50, 0o42775, None)]);
        assert!(choose_target(None, Some(unit), me, &bad).is_err());
        // Root's own client from elsewhere, not the unit's: not checked.
        let roots = Path::new("/root/pithagoras-sync");
        assert_eq!(
            choose_target(Some(roots), Some(unit), roots, &bad),
            Ok(Target {
                exe: roots.to_path_buf(),
                unit: false
            })
        );
        assert_eq!(
            choose_target(None, None, me, &bad),
            Ok(Target {
                exe: me.to_path_buf(),
                unit: false
            })
        );
    }

    /// What the LXC retest did: the unit starts a link in a user's folder, and
    /// the user flips it by an atomic rename between a root-owned program and a
    /// script of their own. Whichever way it points, root neither runs it nor
    /// writes there, and the check does not depend on two looks at the link
    /// agreeing: a thread turns it all the while.
    #[cfg(unix)]
    #[test]
    fn a_link_its_user_flips_is_refused_either_way() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let script = t.path().join("evil");
        write_script(&script, "exit 1");
        let prog = t.path().join("prog");
        let flip = |dir: &Path, to: &Path| {
            let tmp = dir.join("prog.new");
            std::os::unix::fs::symlink(to, &tmp).unwrap();
            std::fs::rename(&tmp, dir.join("prog")).unwrap();
        };
        let me = Path::new("/nowhere/pithagoras-sync");
        for to in [Path::new("/bin/sh"), script.as_path()] {
            flip(t.path(), to);
            let e = choose_target(None, Some(&prog), me, &RealFs).unwrap_err();
            assert!(e.contains("root neither runs nor replaces it"), "{e}");
            assert!(root_program(&prog, &RealFs).is_err());
        }
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let turner = {
            let (stop, dir, script) = (stop.clone(), t.path().to_path_buf(), script.clone());
            std::thread::spawn(move || {
                let mut n = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    flip(
                        &dir,
                        if n % 2 == 0 {
                            Path::new("/bin/sh")
                        } else {
                            &script
                        },
                    );
                    n += 1;
                }
            })
        };
        // Every call is refused: none returns the unchecked path for root to run.
        for _ in 0..3000 {
            assert!(choose_target(None, Some(&prog), me, &RealFs).is_err());
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        turner.join().unwrap();
        // The same in the fake layout, where the link's folder belongs to uid 1000.
        for to in ["/usr/local/bin/pithagoras-sync", "/home/svc/bin/evil"] {
            let fs = layout(&[
                ("/home/svc/bin/evil", 1000, 1000, 0o100755, None),
                ("/home/svc/prog", 1000, 1000, 0o120777, Some(to)),
            ]);
            let e = choose_target(None, Some(Path::new("/home/svc/prog")), me, &fs).unwrap_err();
            assert!(e.contains("/home/svc belongs to user svc (1000)"), "{e}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_name_from_the_account_database_is_escaped_in_a_refusal() {
        struct Named(FakeFs);
        impl Fs for Named {
            fn lstat(&self, p: &Path) -> std::io::Result<Option<Node>> {
                self.0.lstat(p)
            }
            fn user_name(&self, _uid: u32) -> Option<String> {
                Some("evil\x1b[2J".into())
            }
            fn group_name(&self, _gid: u32) -> Option<String> {
                Some("grp\x1b[2J".into())
            }
        }
        let bin = Path::new("/usr/local/bin/pithagoras-sync");
        for rows in [
            &[("/usr/local/bin", 1000, 0, 0o40755, None)],
            &[("/usr/local/bin", 0, 50, 0o40775, None)],
        ] {
            let e = root_program(bin, &Named(layout(rows))).unwrap_err();
            assert!(!e.contains('\x1b'), "{e:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_program_written_under_a_strict_umask_is_still_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let old = unsafe { libc::umask(0o077) };
        let r = write_new(&t.path().join("p"), b"x");
        unsafe { libc::umask(old) };
        r.unwrap();
        let mode = std::fs::metadata(t.path().join("p"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn the_program_of_a_unit_is_what_systemd_starts() {
        let show = |out: &str| crate::actions::Fake {
            answers: vec![("systemctl show".into(), Ok(out.into()))],
            ..Default::default()
        };
        // A drop-in that reset ExecStart= and set another: systemd says which.
        let r = show(
            "{ path=/opt/ps/pithagoras-sync ; argv[]=/opt/ps/pithagoras-sync run ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n",
        );
        assert_eq!(
            unit_program(&r),
            Some(PathBuf::from("/opt/ps/pithagoras-sync"))
        );
        assert_eq!(
            r.ran.lock().unwrap()[0],
            crate::actions::argv(&["systemctl", "show", "-p", "ExecStart", "--value", UNIT_NAME])
        );
        // No such unit (empty), or nothing usable.
        assert_eq!(unit_program(&show("\n")), None);
        assert_eq!(unit_program(&show("{ path=pithagoras-sync ; }")), None);
        let r = crate::actions::Fake {
            answers: vec![("systemctl show".into(), Err("no systemd".into()))],
            ..Default::default()
        };
        assert_eq!(unit_program(&r), None);
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
        // Running the replaced file: restarted, whether or not this update
        // replaced it.
        for replaced in [true, false] {
            let r = runner("4242");
            let said = restart_system_unit(&r, exe, replaced, None, |pid| {
                (pid == 4242).then_some(Runs::Replaced)
            })
            .unwrap();
            assert!(
                said.starts_with("Restarted pithagoras-sync.service"),
                "{said}"
            );
            assert_eq!(restarts(&r), 1);
            assert_eq!(
                r.ran.lock().unwrap()[1],
                crate::actions::argv(&["systemctl", "restart", UNIT_NAME])
            );
        }
        // Running the file as it is: left alone.
        let r = runner("4242");
        assert_eq!(
            restart_system_unit(&r, exe, false, None, |_| Some(Runs::Same)),
            None
        );
        assert_eq!(restarts(&r), 0);
        // What it runs cannot be told: restarted only after a replace.
        let r = runner("4242");
        assert_eq!(restart_system_unit(&r, exe, false, None, |_| None), None);
        assert_eq!(restarts(&r), 0);
        let r = runner("4242");
        assert!(restart_system_unit(&r, exe, true, None, |_| None).is_some());
        assert_eq!(restarts(&r), 1);
        // Not running: said after a replace, nothing restarted.
        let r = runner("0");
        let said = restart_system_unit(&r, exe, true, None, |_| Some(Runs::Replaced)).unwrap();
        assert!(said.contains("is not running"), "{said}");
        assert_eq!(restarts(&r), 0);
        assert_eq!(
            restart_system_unit(&runner("0"), exe, false, None, |_| None),
            None
        );
        // The restart fails: the owner is told how to do it.
        let r = crate::actions::Fake {
            answers: vec![
                ("systemctl show".into(), Ok("7\n".into())),
                ("systemctl restart".into(), Err("denied".into())),
            ],
            ..Default::default()
        };
        let said = restart_system_unit(&r, exe, true, None, |_| Some(Runs::Replaced)).unwrap();
        assert!(
            said.contains("sudo systemctl restart pithagoras-sync.service"),
            "{said}"
        );
    }

    #[test]
    fn a_unit_whose_client_restarts_by_itself_is_not_restarted_again() {
        let exe = Path::new("/usr/local/bin/pithagoras-sync");
        let r = crate::actions::Fake {
            answers: vec![("systemctl show".into(), Ok("4242\n".into()))],
            ..Default::default()
        };
        // Root's own client, run by a unit for root, took the request itself.
        assert_eq!(
            restart_system_unit(&r, exe, true, Some(4242), |_| Some(Runs::Replaced)),
            None
        );
        // Another process (the dedicated user's client): restarted as well.
        let said =
            restart_system_unit(&r, exe, true, Some(1111), |_| Some(Runs::Replaced)).unwrap();
        assert!(said.starts_with("Restarted"), "{said}");
    }

    #[test]
    fn a_unit_whose_client_is_restarting_is_not_called_stopped() {
        let exe = Path::new("/usr/local/bin/pithagoras-sync");
        let r = crate::actions::Fake {
            answers: vec![("systemctl show".into(), Ok("0\n".into()))],
            ..Default::default()
        };
        // Root's own client, run by the unit, exited to restart: MainPID is 0
        // until systemd starts it again.
        assert_eq!(
            restart_system_unit(&r, exe, true, Some(4242), |_| None),
            None
        );
    }

    #[test]
    fn the_program_another_process_runs_is_shown_escaped() {
        let exe = Path::new("/usr/local/bin/pithagoras-sync");
        let r = crate::actions::Fake {
            answers: vec![("systemctl show".into(), Ok("4242\n".into()))],
            ..Default::default()
        };
        let said = restart_system_unit(&r, exe, false, None, |_| {
            Some(Runs::Other(PathBuf::from("/tmp/x\x1b[2K\rRestarted")))
        })
        .unwrap();
        assert!(!said.contains('\x1b') && !said.contains('\r'), "{said:?}");
        assert!(said.contains("/tmp/x\\u{1b}[2K\\rRestarted"), "{said:?}");
    }

    #[test]
    fn a_unit_running_another_program_is_not_restarted() {
        let exe = Path::new("/usr/local/bin/pithagoras-sync");
        let r = crate::actions::Fake {
            answers: vec![("systemctl show".into(), Ok("4242\n".into()))],
            ..Default::default()
        };
        // Neither after a replace nor when nothing was replaced: restarting would
        // not make it run `exe`, so every `update` would restart it again.
        for replaced in [true, false] {
            let said = restart_system_unit(&r, exe, replaced, None, |_| {
                Some(Runs::Other(PathBuf::from("/opt/ps/pithagoras-sync")))
            })
            .unwrap();
            assert!(
                said.starts_with(
                    "pithagoras-sync.service runs /opt/ps/pithagoras-sync, not /usr/local/bin/pithagoras-sync, so it was not restarted"
                ),
                "{said}"
            );
        }
        assert!(
            r.ran
                .lock()
                .unwrap()
                .iter()
                .all(|a| a.get(1).map(String::as_str) != Some("restart"))
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
        assert_eq!(what_runs(pid, &exe), Some(Runs::Same));
        let other = t.path().join("other");
        std::fs::copy(&exe, &other).unwrap();
        assert_eq!(
            what_runs(pid, &other),
            Some(Runs::Other(std::fs::canonicalize(&exe).unwrap()))
        );
        let new = t.path().join("prog.new");
        std::fs::copy(&exe, &new).unwrap();
        std::fs::rename(&new, &exe).unwrap();
        assert_eq!(what_runs(pid, &exe), Some(Runs::Replaced));
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
    fn a_client_is_older_only_by_its_version() {
        assert!(is_older("0.1.0", "0.2.0"));
        assert!(is_older("0.9.0", "0.10.0"));
        assert!(!is_older("0.2.0", "0.2.0"));
        // A client newer than the file is not restarted onto the older file.
        assert!(!is_older("0.3.0", "0.2.0"));
        assert!(!is_older("dev", "0.2.0"));
    }

    #[cfg(unix)]
    #[test]
    fn a_release_time_is_recorded_privately() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let new = t.path().join("state/update-released");
        record(&new, 100).unwrap();
        assert_eq!(mode(&new), 0o600);
        // One an older version wrote with the umask's 0664 is tightened.
        let old = t.path().join("state/update-released-1");
        std::fs::write(&old, "50\n").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o664)).unwrap();
        record(&old, 100).unwrap();
        assert_eq!(mode(&old), 0o600);
        assert_eq!(read_seen(&old), 100);
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_not_writable_names_who_updates_it() {
        let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let tmp = Path::new("/home/svc/bin/.pithagoras-sync.update.1");
        let fs = layout(&[("/home/svc/bin", 1000, 1000, 0o40555, None)]);
        // This user's own read-only folder: no word of root or sudo.
        let mine = Path::new("/home/svc/bin/pithagoras-sync");
        let e = write_error(denied(), tmp, mine, &fs, 1000);
        assert!(
            e.ends_with(
                "the folder is this user's own, so make it writable: chmod u+w /home/svc/bin"
            ),
            "{e}"
        );
        assert!(!e.contains("root") && !e.contains("sudo"), "{e}");
        // Another user's folder: that user updates it.
        let e = write_error(denied(), tmp, mine, &fs, 1001);
        assert!(
            e.ends_with("it belongs to user svc (1000), so run `update` as that user"),
            "{e}"
        );
        assert!(!e.contains("sudo"), "{e}");
        // Root's folder, as `setup` makes it: root updates it.
        let bin = Path::new("/usr/local/bin/pithagoras-sync");
        let e = write_error(denied(), tmp, bin, &fs, 1000);
        assert!(
            e.ends_with("so root updates it: sudo pithagoras-sync update"),
            "{e}"
        );
        // Anything other than a refusal is said as it is.
        let e = write_error(std::io::ErrorKind::StorageFull.into(), tmp, bin, &fs, 1000);
        assert!(!e.contains("cannot be replaced"), "{e}");
    }

    #[test]
    fn a_program_not_moved_back_is_not_called_unreplaced() {
        let exe = Path::new("pithagoras-sync.exe");
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let said = not_moved_back(exe, &old_path(exe), &e, &e).text();
        assert!(!said.contains("nothing was replaced"), "{said}");
        assert!(
            said.contains(
                "it is now pithagoras-sync.exe.old: move it back to pithagoras-sync.exe by hand"
            ),
            "{said}"
        );
        let said = Failed::from("the download does not match").text();
        assert!(
            said.ends_with("(nothing was replaced, and no client was restarted)"),
            "{said}"
        );
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
