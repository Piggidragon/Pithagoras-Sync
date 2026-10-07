//! `pithagoras-sync computer-use ...`: the computer-use server on this device.
//! Install, update, roll back and remove it; its setup, test and status; the
//! owner's consent. What a call does is `sync_mcp::service`; this is the
//! owner's side, shared by the command line, the running client (the daily
//! look for new pins) and the windows.

use std::path::{Path, PathBuf};

use sync_mcp::install;
use sync_mcp::pins::{self, Document, PinStore, ServerPin, Taken};
use sync_policy::config::{InstalledServer, InstalledVersion};
use sync_policy::{DeviceConfig, Dirs};

/// The pins this user's client takes: the baseline and the newest signed
/// document, checked with the release key of this build.
pub fn store(dirs: &Dirs) -> PinStore {
    PinStore::new(dirs.mcp_dir(), dirs.mcp_serial_file(), pins_key())
}

/// Set (debug builds only) to a throwaway minisign public key that signs the
/// tests' pins documents. A release build ignores it; a real release key never
/// goes into tests.
pub const TEST_PINS_KEY: &str = "PITHAGORAS_SYNC_TEST_MCP_KEY";

/// The release key of this build, which signs the pins as it signs releases.
fn pins_key() -> Option<String> {
    #[cfg(debug_assertions)]
    if let Ok(k) = std::env::var(TEST_PINS_KEY)
        && !k.is_empty()
    {
        return Some(k);
    }
    crate::update::PUBLIC_KEY.map(str::to_string)
}

/// The server pinned for this platform.
pub fn pinned(doc: &Document) -> Option<&ServerPin> {
    doc.for_platform(sync_mcp::os()).next()
}

fn limits() -> sync_mcp::Limits {
    sync_mcp::Limits::default()
}

fn base_env() -> Vec<(String, String)> {
    std::env::vars().collect()
}

/// What `install --print` lists.
pub fn plan(dirs: &Dirs, doc: &Document) -> Result<Vec<String>, String> {
    let pin = pinned(doc).ok_or("there is no computer-use server for this platform")?;
    let dir = install::version_dir(&dirs.mcp_dir(), &pin.name, &install::folder_name(pin));
    let mut out = vec![format!(
        "computer use: {} {} from the {} pins (serial {})",
        pin.name,
        pin.version,
        if doc.serial == 0 {
            "built-in"
        } else {
            "signed"
        },
        doc.serial
    )];
    if let Some(why) = pin.unpinned(sync_mcp::arch()) {
        out.push(format!("  not installable yet: {why}"));
        return Ok(out);
    }
    for f in pin.files_for(sync_mcp::arch()) {
        out.push(format!(
            "  download {} ({} bytes, sha256 {}) to {}",
            f.url,
            f.size,
            f.sha256,
            install::join(&dir, &f.path).display()
        ));
        if matches!(f.kind, pins::FileKind::Zip | pins::FileKind::Wheel) {
            out.push(format!("  unpack it there ({:?})", f.kind).to_lowercase());
        }
    }
    for w in &pin.write {
        out.push(format!(
            "  write {}",
            install::join(&dir, &w.path).display()
        ));
    }
    if !pin.selftest.imports.is_empty() {
        out.push(format!(
            "  check that its Python imports {}",
            pin.selftest.imports.join(", ")
        ));
    }
    out.push(format!(
        "  run {} once ({} {}) and keep its tool list",
        install::join(&dir, &pin.run.program).display(),
        pin.run.program,
        pin.run.args.join(" ")
    ));
    for (k, v) in &pin.run.env {
        out.push(format!("  its environment: {k}={v}"));
    }
    out.push(format!(
        "  allow only: {} (looking only, without the focus check: {})",
        pin.allowed().join(", "),
        pin.observe.join(", ")
    ));
    out.push(format!(
        "  record {} {} with the hash of its folder in {} ([mcp.{}])",
        pin.name,
        pin.version,
        dirs.config_file().display(),
        pin.name
    ));
    Ok(out)
}

/// Installs (or reinstalls) `pin` and records it; the previous version stays
/// for one rollback, older ones go.
pub async fn install_pin(
    dirs: &Dirs,
    pin: &ServerPin,
    serial: u64,
    say: &mut (dyn FnMut(String) + Send),
) -> Result<(), String> {
    let mcp = dirs.mcp_dir();
    let done = install::install(
        &mcp,
        pin,
        sync_mcp::arch(),
        &base_env(),
        &limits(),
        |url, max| async move { pins::fetch(&url, max, true).await },
        say,
    )
    .await?;
    // Read again right before the save: what the owner changed meanwhile stays.
    let mut cfg = DeviceConfig::load(&dirs.config_file())?;
    let old = cfg.mcp.get(&pin.name).cloned();
    let previous = match &old {
        Some(o) if o.folder != done.folder => Some(InstalledVersion {
            version: o.version.clone(),
            folder: o.folder.clone(),
            sha256: o.sha256.clone(),
        }),
        Some(o) => o.previous.clone(),
        None => None,
    };
    cfg.mcp.insert(
        pin.name.clone(),
        InstalledServer {
            version: pin.version.clone(),
            folder: done.folder.clone(),
            sha256: done.sha256,
            serial,
            previous: previous.clone(),
            held: false,
        },
    );
    cfg.save(&dirs.config_file())?;
    // Older versions go; one that cannot go yet (Windows: still running)
    // stays until the next install, and the install counts as done.
    let mut keep = vec![done.folder.as_str()];
    if let Some(p) = &previous {
        keep.push(p.folder.as_str());
    }
    if let Err(e) = install::prune(&mcp, &pin.name, &keep) {
        say(format!(
            "note: an older version could not be removed yet: {e}"
        ));
    }
    Ok(())
}

/// `computer-use install`: the server pinned now.
pub async fn install_now(
    dirs: &Dirs,
    say: &mut (dyn FnMut(String) + Send),
) -> Result<String, String> {
    let store = store(dirs);
    // A newer signed document first, where there is one; without the network
    // the pins at hand do.
    if store.key.is_some() {
        match pins::check(&store, &pins::pins_url()).await {
            Ok(Taken::New(d)) => say(format!("took the signed pins, serial {}", d.serial)),
            Ok(Taken::Same(_)) => {}
            Err(e) => say(format!("note: no newer pins: {e}")),
        }
    }
    let doc = store.current();
    for n in doc.overruled() {
        say(format!("note: the built-in deny-list keeps {n} off"));
    }
    let pin = pinned(&doc)
        .ok_or("there is no computer-use server for this platform")?
        .clone();
    install_pin(dirs, &pin, doc.serial, say).await?;
    Ok(format!("{} {}", pin.name, pin.version))
}

/// `computer-use uninstall` (and `uninstall`), first step: the record goes,
/// so the running client lets go of the servers once it reloads. Returns
/// the servers to remove (`remove_files`), a folder without a record (an
/// install stopped halfway) among them.
pub fn forget_all(dirs: &Dirs) -> Result<Vec<String>, String> {
    let mut cfg = DeviceConfig::load(&dirs.config_file())?;
    let mut names: Vec<String> = cfg.mcp.keys().cloned().collect();
    if let Ok(rd) = std::fs::read_dir(dirs.mcp_dir()) {
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                let n = e.file_name().to_string_lossy().into_owned();
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
    }
    if !cfg.mcp.is_empty() {
        cfg.mcp.clear();
        cfg.save(&dirs.config_file())?;
    }
    Ok(names)
}

/// The second step: the servers' files. A server the client still runs (a
/// call in flight) holds its files on Windows for a moment: tried for up to
/// ten seconds.
pub async fn remove_files(dirs: &Dirs, names: &[String]) -> Result<(), String> {
    for n in names {
        let mut tries = 0;
        loop {
            match install::uninstall(&dirs.mcp_dir(), n) {
                Ok(()) => break,
                Err(e) if tries >= 20 => {
                    return Err(format!(
                        "{e}; the server is no longer recorded, and `computer-use uninstall` again removes the rest"
                    ));
                }
                Err(_) => {
                    tries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
    }
    Ok(())
}

/// `computer-use rollback`: the version before, if it is still there and
/// unchanged. Updates leave it alone from then on (`held`) until the owner
/// installs again.
pub fn rollback(dirs: &Dirs) -> Result<String, String> {
    let mut cfg = DeviceConfig::load(&dirs.config_file())?;
    let (name, rec) = cfg
        .mcp
        .iter()
        .next()
        .map(|(n, r)| (n.clone(), r.clone()))
        .ok_or("no computer-use server is installed")?;
    let prev = rec.previous.clone().ok_or_else(|| {
        format!(
            "{name} {} has no version before it to go back to",
            rec.version
        )
    })?;
    install::verify(&dirs.mcp_dir(), &name, &prev.folder, &prev.sha256)?;
    cfg.mcp.insert(
        name.clone(),
        InstalledServer {
            version: prev.version.clone(),
            folder: prev.folder,
            sha256: prev.sha256,
            serial: rec.serial,
            previous: Some(InstalledVersion {
                version: rec.version.clone(),
                folder: rec.folder,
                sha256: rec.sha256,
            }),
            held: true,
        },
    );
    cfg.save(&dirs.config_file())?;
    Ok(format!("{name} {} (from {})", prev.version, rec.version))
}

/// What an update found or did.
#[derive(Debug, Default)]
pub struct Updated {
    /// Servers that took (or with `check`, would take) another version.
    pub changed: Vec<String>,
    pub notes: Vec<String>,
}

/// `update` and the daily look: the newest signed pins, and every installed
/// server moved to what they pin, into a new folder; consent, allow-list
/// settings and the rest of the config stay. A failure leaves the old
/// version as it is.
pub async fn update(
    dirs: &Dirs,
    check: bool,
    say: &mut (dyn FnMut(String) + Send),
) -> Result<Updated, String> {
    let mut out = Updated::default();
    let cfg = DeviceConfig::load(&dirs.config_file())?;
    if cfg.mcp.is_empty() {
        return Ok(out);
    }
    let store = store(dirs);
    let mut peeked = None;
    if store.key.is_none() {
        out.notes.push(
            "this build has no release key, so the computer-use server keeps its built-in pins"
                .into(),
        );
    } else {
        // `--check` only looks: nothing is kept, no serial raised.
        let found = if check {
            pins::peek(&store, &pins::pins_url()).await.map(|d| {
                if d.serial > store.seen_serial() {
                    Taken::New(d)
                } else {
                    Taken::Same(d)
                }
            })
        } else {
            pins::check(&store, &pins::pins_url()).await
        };
        match found {
            Ok(Taken::New(d)) => {
                say(format!(
                    "Computer use: new signed pins, serial {}.",
                    d.serial
                ));
                peeked = Some(d);
            }
            Ok(Taken::Same(d)) => say(format!(
                "Computer use: the pins are current (serial {}).",
                d.serial
            )),
            Err(e) => out.notes.push(format!("computer use: no newer pins: {e}")),
        }
    }
    let doc = match peeked {
        Some(d) if check => d,
        _ => store.current(),
    };
    for (name, rec) in &cfg.mcp {
        let Some(pin) = doc.server(name, sync_mcp::os()) else {
            out.notes.push(format!(
                "computer use: {name} is no longer pinned; it stays as installed"
            ));
            continue;
        };
        if rec.held {
            out.notes.push(format!(
                "computer use: {name} stays at {} after the rollback; `pithagoras-sync computer-use install` takes {}",
                rec.version, pin.version
            ));
            continue;
        }
        let same = rec.folder == install::folder_name(pin);
        if same {
            say(format!(
                "Computer use: {name} {} is up to date.",
                rec.version
            ));
            continue;
        }
        if let Some(why) = pin.unpinned(sync_mcp::arch()) {
            out.notes.push(format!(
                "computer use: {name} {} cannot be installed: {why}",
                pin.version
            ));
            continue;
        }
        if check {
            say(format!(
                "Computer use: {name} {} is available (installed: {}).",
                pin.version, rec.version
            ));
            out.changed.push(name.clone());
            continue;
        }
        say(format!(
            "Computer use: updating {name} {} to {}.",
            rec.version, pin.version
        ));
        match install_pin(dirs, pin, doc.serial, say).await {
            Ok(()) => {
                say(format!("Computer use: {name} is now {}.", pin.version));
                out.changed.push(name.clone());
            }
            Err(e) => out.notes.push(format!(
                "computer use: updating {name} to {} failed, {} stays: {e}",
                pin.version, rec.version
            )),
        }
    }
    for n in &out.notes {
        say(format!("note: {n}"));
    }
    Ok(out)
}

/// The installed version's folder, checked; for the setup and the local test.
pub fn installed(dirs: &Dirs, cfg: &DeviceConfig) -> Result<(String, PathBuf, ServerPin), String> {
    let (name, rec) = cfg
        .mcp
        .iter()
        .next()
        .ok_or("no computer-use server is installed: `pithagoras-sync computer-use install`")?;
    let dir = install::verify(&dirs.mcp_dir(), name, &rec.folder, &rec.sha256)?;
    let doc = store(dirs).current();
    let pin = match doc.server(name, sync_mcp::os()) {
        Some(p) if p.version == rec.version => p.clone(),
        _ => install::kept_pin(&dir)?,
    };
    Ok((name.clone(), dir, pin))
}

/// `computer-use test` without a running client: the server started here.
pub async fn test_here(
    dirs: &Dirs,
    verbose: bool,
) -> Result<Vec<sync_mcp::selftest::Step>, String> {
    let cfg = DeviceConfig::load(&dirs.config_file())?;
    let (_, dir, pin) = installed(dirs, &cfg)?;
    let launch = install::launch(&pin, &dir, &dirs.mcp_dir(), &base_env());
    let mut c = sync_mcp::Client::start(&launch, limits())
        .await
        .map_err(|e| format!("{}: {e}", pin.name))?;
    let steps = sync_mcp::selftest::run(&mut c, &pin, verbose).await;
    c.kill().await;
    Ok(steps)
}

/// Set (debug builds only) to how long after a call computer use counts as
/// active, in milliseconds: the tests' way past the minute. A release build
/// ignores it.
pub const TEST_ACTIVE_MS: &str = "PITHAGORAS_SYNC_TEST_MCP_ACTIVE_MS";

/// How long after a call the client takes no change, answer or secret.
pub fn active_ms() -> i64 {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var(TEST_ACTIVE_MS)
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return ms;
    }
    sync_mcp::service::BURST_GAP_MS
}

/// How often the running client looks for new pins.
pub const CHECK_EVERY_MS: i64 = 24 * 3_600_000;

/// Set (debug builds only) to the milliseconds after start of the first daily
/// look: the tests' way to see it run. A release build ignores it.
pub const TEST_CHECK_AFTER_MS: &str = "PITHAGORAS_SYNC_TEST_MCP_CHECK_MS";

/// When the first look for new pins after a start is due: at a random time
/// within the day, so clients do not all ask at once.
pub fn first_check_ms(now_ms: i64) -> i64 {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var(TEST_CHECK_AFTER_MS)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
    {
        return now_ms + ms;
    }
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    let r = ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map(|()| u64::from_le_bytes(b))
        .unwrap_or(0);
    now_ms + (r % CHECK_EVERY_MS as u64) as i64
}

/// How often the running client asks whether the look is due: a minute, or
/// in the tests (debug builds, `TEST_CHECK_AFTER_MS` set) a tenth of a second.
pub fn check_tick() -> std::time::Duration {
    #[cfg(debug_assertions)]
    if std::env::var_os(TEST_CHECK_AFTER_MS).is_some() {
        return std::time::Duration::from_millis(100);
    }
    std::time::Duration::from_secs(60)
}

/// Whether the daily look is due: switched on, a server installed, its time
/// come.
pub fn check_due(cfg: &DeviceConfig, now_ms: i64, next_ms: i64) -> bool {
    cfg.policy.computer_use.auto_update && !cfg.mcp.is_empty() && now_ms >= next_ms
}

/// The setup steps for this desktop and whether each is done.
pub fn setup_state(dir: &Path, pin: &ServerPin) -> Vec<(String, String)> {
    sync_mcp::setup::steps_for(pin, &sync_mcp::setup::desktop())
        .into_iter()
        .map(|s| {
            let state = match sync_mcp::setup::check(s, dir) {
                None => "by hand".to_string(),
                Some(Ok(true)) => "done".to_string(),
                Some(Ok(false)) => "not done".to_string(),
                Some(Err(e)) => format!("unknown ({e})"),
            };
            (s.title.clone(), state)
        })
        .collect()
}

/// The consent in one line, as `status` shows it.
pub fn consent_text(cfg: &DeviceConfig, now_ms: i64) -> String {
    let cu = &cfg.policy.computer_use;
    match (cu.effective(now_ms), cu.expires_ms(now_ms)) {
        (sync_policy::Consent::Allow, Some(until)) => format!(
            "allow until {} UTC",
            crate::update::utc((until / 1000).max(0) as u64)
        ),
        (c, _) => c.as_str().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_daily_look_respects_its_setting() {
        let mut cfg = DeviceConfig::default();
        assert!(!check_due(&cfg, 10, 0), "nothing installed");
        cfg.mcp.insert(
            "s".into(),
            InstalledServer {
                version: "1".into(),
                folder: "1-x".into(),
                sha256: String::new(),
                serial: 0,
                previous: None,
                held: false,
            },
        );
        assert!(check_due(&cfg, 10, 0));
        assert!(!check_due(&cfg, 10, 11), "not yet");
        cfg.policy.computer_use.auto_update = false;
        assert!(!check_due(&cfg, 10, 0), "switched off");
        let first = first_check_ms(1_000);
        assert!((1_000..1_000 + CHECK_EVERY_MS).contains(&first));
    }

    #[test]
    fn the_baseline_plan_says_what_is_not_pinned_yet() {
        let t = tempfile::tempdir().unwrap();
        let dirs = Dirs::under(t.path());
        let lines = plan(&dirs, &pins::baseline()).unwrap();
        assert!(lines[0].contains("built-in"), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("TODO-PIN")), "{lines:?}");
    }
}
