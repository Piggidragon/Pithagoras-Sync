//! Putting a pinned server on the device, and taking it off again.
//!
//! Each version gets its own folder, `<mcp>/<server>/<version>-<pin hash>/`
//! (folders 0700, the user's own, never a link): a pin that changes for the
//! same version (a new Python patch) goes into a fresh folder too. It is built in a staging folder next
//! to it: every file is downloaded from a pinned host, its size and sha256
//! checked against the pin before anything is written, zips and wheels
//! unpacked, the server started once (`initialize`, `tools/list`, and the
//! Python modules it imports), its tool list kept, and only then is the
//! staging folder renamed to its final name. A hash over the whole folder is
//! what the config records; it is checked before every start, so a server
//! changed after install is not run. Nothing is ever taken from `PATH`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{Client, Launch, Limits, Tool};
use crate::fsutil;
use crate::pins::{FileKind, ServerPin};

/// Longest tool description kept (and listed to the portal).
pub const MAX_DESCRIPTION: usize = 4096;
/// Largest input schema kept; a tool with a larger one is left out.
pub const MAX_SCHEMA: usize = 64 * 1024;
/// The tool list kept beside the server, part of its hashed folder.
pub const TOOLS_FILE: &str = "tools.json";
/// The pin the version was installed from, part of its hashed folder: how to
/// run it once a newer document pins another version.
pub const PIN_FILE: &str = "pin.json";

pub fn server_dir(mcp: &Path, server: &str) -> PathBuf {
    mcp.join(server)
}

/// The folder of an installed version (`folder_name`).
pub fn version_dir(mcp: &Path, server: &str, folder: &str) -> PathBuf {
    mcp.join(server).join(folder)
}

/// The folder a pin installs into: its version and the start of the sha256
/// of the pin itself.
pub fn folder_name(pin: &ServerPin) -> String {
    let text = serde_json::to_vec(pin).unwrap_or_default();
    format!("{}-{}", pin.version, &fsutil::sha256_hex(&text)[..12])
}

/// What an install recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub folder: String,
    pub sha256: String,
}

/// The server's stderr, outside its hashed folder.
pub fn log_file(mcp: &Path, server: &str) -> PathBuf {
    mcp.join(format!("{server}.log"))
}

/// A tool as kept in `tools.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeptTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// The program and arguments of a pin, in `dir`.
pub fn launch(pin: &ServerPin, dir: &Path, mcp: &Path, base_env: &[(String, String)]) -> Launch {
    // Python writes no caches into the hashed folder; the rest is the pin's.
    let mut extra = vec![("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string())];
    extra.extend(pin.run.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    #[cfg(unix)]
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    #[cfg(not(unix))]
    let uid = 0;
    Launch {
        program: join(dir, &pin.run.program),
        args: pin
            .run
            .args
            .iter()
            .map(|a| a.replace("{dir}", &dir.to_string_lossy()))
            .collect(),
        env: crate::session::environment(base_env, &extra, uid, &|p| Path::new(p).exists()),
        // Outside the hashed folder: what a server writes to its working
        // folder does not change it (and Windows can still move the folder).
        cwd: dir.parent().unwrap_or(dir).to_path_buf(),
        log: Some(log_file(mcp, &pin.name)),
    }
}

/// A `/`-separated relative path below `dir`.
pub fn join(dir: &Path, rel: &str) -> PathBuf {
    rel.split('/').fold(dir.to_path_buf(), |p, c| p.join(c))
}

/// Where a wheel's entry goes, relative to site-packages: `.data/purelib`
/// and `.data/platlib` are unpacked into it, the other `.data` folders
/// (scripts, headers, data) are left out.
fn wheel_target(name: &str) -> Option<String> {
    // A module at the top of the wheel (`six.py`) goes in as it is.
    let Some((first, rest)) = name.split_once('/') else {
        return Some(name.to_string());
    };
    if !first.ends_with(".data") {
        return Some(name.to_string());
    }
    let (kind, rest) = rest.split_once('/')?;
    matches!(kind, "purelib" | "platlib").then(|| rest.to_string())
}

/// Installs `pin` for `arch` and returns the hash of its folder. `fetch`
/// downloads a URL with at most so many bytes (the real one is
/// `pins::fetch` with the host check); `say` reports each step.
pub async fn install<F, Fut>(
    mcp: &Path,
    pin: &ServerPin,
    arch: &str,
    base_env: &[(String, String)],
    limits: &Limits,
    fetch: F,
    say: &mut (dyn FnMut(String) + Send),
) -> Result<Installed, String>
where
    F: Fn(String, usize) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    if let Some(why) = pin.unpinned(arch) {
        return Err(format!(
            "{} {} cannot be installed: {why}. A signed pins document has to pin it first (docs/mcp-updates.md)",
            pin.name, pin.version
        ));
    }
    let server = server_dir(mcp, &pin.name);
    fsutil::private_dirs(mcp, &server)?;
    fsutil::owned_and_private(mcp, &server)?;
    let folder = folder_name(pin);
    let staging = server.join(format!(".staging-{folder}-{}", std::process::id()));
    fsutil::remove_tree(&staging)?;
    let built = build(&staging, mcp, pin, arch, base_env, limits, fetch, say).await;
    let hash = match built {
        Ok(h) => h,
        Err(e) => {
            let _ = fsutil::remove_tree(&staging);
            return Err(e);
        }
    };
    let dir = version_dir(mcp, &pin.name, &folder);
    // The same pin again (a repair): the old folder steps aside first.
    let aside = server.join(format!(".old-{folder}-{}", std::process::id()));
    if std::fs::symlink_metadata(&dir).is_ok() {
        std::fs::rename(&dir, &aside).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    if let Err(e) = std::fs::rename(&staging, &dir) {
        let _ = std::fs::rename(&aside, &dir);
        let _ = fsutil::remove_tree(&staging);
        return Err(format!("{}: {e}", dir.display()));
    }
    let _ = fsutil::remove_tree(&aside);
    say(format!(
        "installed {} {} in {}",
        pin.name,
        pin.version,
        dir.display()
    ));
    Ok(Installed {
        folder,
        sha256: hash,
    })
}

#[allow(clippy::too_many_arguments)]
async fn build<F, Fut>(
    staging: &Path,
    mcp: &Path,
    pin: &ServerPin,
    arch: &str,
    base_env: &[(String, String)],
    limits: &Limits,
    fetch: F,
    say: &mut (dyn FnMut(String) + Send),
) -> Result<String, String>
where
    F: Fn(String, usize) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    fsutil::private_dirs(mcp, staging)?;
    for f in pin.files_for(arch) {
        say(format!(
            "download {} ({} bytes) from {}",
            f.path, f.size, f.url
        ));
        let data = fetch(f.url.clone(), f.size as usize).await?;
        if data.len() as u64 != f.size {
            return Err(format!(
                "{}: {} bytes came, the pin says {} (cut short or changed): nothing was installed",
                f.path,
                data.len(),
                f.size
            ));
        }
        let got = fsutil::sha256_hex(&data);
        if got != f.sha256 {
            return Err(format!(
                "{}: its sha256 is {got}, the pin says {}: nothing was installed",
                f.path, f.sha256
            ));
        }
        let target = join(staging, &f.path);
        match f.kind {
            FileKind::Executable | FileKind::File => {
                if let Some(parent) = target.parent() {
                    fsutil::private_dirs(mcp, parent)?;
                }
                fsutil::write_new(&target, &data, f.kind == FileKind::Executable)?;
            }
            FileKind::Zip | FileKind::Wheel => {
                say(format!("unpack {}", f.path));
                fsutil::private_dirs(mcp, &target)?;
                let wheel = f.kind == FileKind::Wheel;
                // One file at a time: the archive and one unpacked file in
                // memory, not every file of it.
                crate::unzip::unpack(&data, &target, |name| match wheel {
                    true => wheel_target(name),
                    false => Some(name.to_string()),
                })?;
            }
        }
    }
    for w in &pin.write {
        let target = join(staging, &w.path);
        if let Some(parent) = target.parent() {
            fsutil::private_dirs(mcp, parent)?;
        }
        // Replaces what an unpacked archive put there (Python's own `._pth`).
        match std::fs::symlink_metadata(&target) {
            Ok(m) if m.is_file() => {
                std::fs::remove_file(&target).map_err(|e| format!("{}: {e}", target.display()))?
            }
            Ok(_) => return Err(format!("{} is not a file", w.path)),
            Err(_) => {}
        }
        fsutil::write_new(&target, w.text.as_bytes(), false)?;
    }
    let pin_text = serde_json::to_vec_pretty(pin).map_err(|e| e.to_string())?;
    fsutil::write_new(&staging.join(PIN_FILE), &pin_text, false)?;
    let l = launch(pin, staging, mcp, base_env);
    if !pin.selftest.imports.is_empty() {
        say(format!(
            "check that its Python has {}",
            pin.selftest.imports.join(", ")
        ));
        check_imports(&l, &pin.selftest.imports, limits.startup).await?;
    }
    say(format!("start {} once", pin.name));
    let mut client = Client::start(&l, limits.clone())
        .await
        .map_err(|e| format!("{} {}: {e}", pin.name, pin.version))?;
    let tools = client.list_tools().await;
    // Windows: a first screenshot makes the UI Automation libraries write
    // what they generate once, before the folder is hashed (later runs then
    // find it there and change nothing).
    if pin.platform == "windows" {
        let _ = client
            .call(&pin.selftest.screenshot.tool, &pin.selftest.screenshot.args)
            .await;
    }
    client.kill().await;
    let tools = tools.map_err(|e| format!("{} {}: {e}", pin.name, pin.version))?;
    say(format!(
        "it lists {} tools; {} allowed here",
        tools.len(),
        {
            let allowed = pin.allowed();
            tools.iter().filter(|t| allowed.contains(&t.name)).count()
        }
    ));
    let kept = keep_tools(tools);
    let text = serde_json::to_vec_pretty(&kept).map_err(|e| e.to_string())?;
    fsutil::write_new(&staging.join(TOOLS_FILE), &text, false)?;
    // What the start may have left (Python's caches) is not part of the install.
    remove_caches(staging);
    fsutil::tree_hash(staging)
}

/// The tools as kept: descriptions cut, a tool with an oversized schema left
/// out.
fn keep_tools(tools: Vec<Tool>) -> Vec<KeptTool> {
    tools
        .into_iter()
        .filter(|t| serde_json::to_string(&t.input_schema).is_ok_and(|s| s.len() <= MAX_SCHEMA))
        .map(|t| KeptTool {
            description: cut(&t.description, MAX_DESCRIPTION),
            name: t.name,
            input_schema: t.input_schema,
        })
        .collect()
}

fn cut(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn remove_caches(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let Ok(t) = e.file_type() else { continue };
        if t.is_dir() {
            if e.file_name() == "__pycache__" {
                let _ = std::fs::remove_dir_all(e.path());
            } else {
                remove_caches(&e.path());
            }
        }
    }
}

async fn check_imports(
    l: &Launch,
    modules: &[String],
    timeout: std::time::Duration,
) -> Result<(), String> {
    // One import per line, so a missing one is named by the error itself.
    let script = modules
        .iter()
        .map(|m| format!("import {m}"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut cmd = tokio::process::Command::new(&l.program);
    cmd.args(["-B", "-c", &script])
        .env_clear()
        .envs(l.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&l.cwd)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000);
    let out = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| "its Python did not finish the import check in time".to_string())?
        .map_err(|e| format!("{}: {e}", l.program.display()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let last = err
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        return Err(format!(
            "its Python lacks a module the server needs: {}",
            sync_policy::approve::visible(last.chars().take(300).collect::<String>().as_str())
        ));
    }
    Ok(())
}

/// The kept tool list of an installed version.
pub fn kept_tools(dir: &Path) -> Result<Vec<KeptTool>, String> {
    let data = std::fs::read(dir.join(TOOLS_FILE)).map_err(|e| format!("{TOOLS_FILE}: {e}"))?;
    serde_json::from_slice(&data).map_err(|e| format!("{TOOLS_FILE}: {e}"))
}

/// The pin an installed version was installed from.
pub fn kept_pin(dir: &Path) -> Result<ServerPin, String> {
    let data = std::fs::read(dir.join(PIN_FILE)).map_err(|e| format!("{PIN_FILE}: {e}"))?;
    serde_json::from_slice(&data).map_err(|e| format!("{PIN_FILE}: {e}"))
}

/// Whether the installed version may run: its folders the user's own and
/// private, and its hash the one recorded at install.
pub fn verify(mcp: &Path, server: &str, folder: &str, sha256: &str) -> Result<PathBuf, String> {
    let dir = version_dir(mcp, server, folder);
    let version = folder.rsplit_once('-').map_or(folder, |(v, _)| v);
    if std::fs::symlink_metadata(&dir).is_err() {
        return Err(format!("{server} {version} is not on the device any more"));
    }
    fsutil::owned_and_private(mcp, &dir)?;
    let got = fsutil::tree_hash(&dir)?;
    if got != sha256 {
        return Err(format!(
            "the files of {server} {version} changed since they were installed, so it is not run; `pithagoras-sync computer-use install` puts it back"
        ));
    }
    Ok(dir)
}

/// Removes every version folder of `server` but `keep` (folder names), and
/// what a stopped install left.
pub fn prune(mcp: &Path, server: &str, keep: &[&str]) -> Result<(), String> {
    let dir = server_dir(mcp, server);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Ok(());
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !keep.contains(&name.as_str()) {
            fsutil::remove_tree(&e.path())?;
        }
    }
    Ok(())
}

/// Takes the server off the device: its folder and its log.
pub fn uninstall(mcp: &Path, server: &str) -> Result<(), String> {
    fsutil::remove_tree(&server_dir(mcp, server))?;
    for log in [
        log_file(mcp, server),
        log_file(mcp, server).with_extension("log.1"),
    ] {
        let _ = std::fs::remove_file(log);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wheels_unpack_their_libraries_only() {
        assert_eq!(
            wheel_target("pkg/__init__.py").as_deref(),
            Some("pkg/__init__.py")
        );
        assert_eq!(
            wheel_target("x-1.0.dist-info/RECORD").as_deref(),
            Some("x-1.0.dist-info/RECORD")
        );
        assert_eq!(
            wheel_target("x-1.0.data/platlib/x.pyd").as_deref(),
            Some("x.pyd")
        );
        assert_eq!(
            wheel_target("x-1.0.data/purelib/a/b.py").as_deref(),
            Some("a/b.py")
        );
        assert_eq!(wheel_target("x-1.0.data/scripts/x.exe"), None);
        assert_eq!(wheel_target("six.py").as_deref(), Some("six.py"));
        assert_eq!(wheel_target("x-1.0.data/data/share/x"), None);
    }

    #[test]
    fn descriptions_are_cut_and_big_schemas_dropped() {
        let tools = vec![
            Tool {
                name: "a".into(),
                description: "é".repeat(4000),
                input_schema: serde_json::json!({"type": "object"}),
            },
            Tool {
                name: "b".into(),
                description: String::new(),
                input_schema: serde_json::json!({"type": "object", "description": "x".repeat(MAX_SCHEMA)}),
            },
        ];
        let kept = keep_tools(tools);
        assert_eq!(kept.len(), 1);
        assert!(kept[0].description.len() <= MAX_DESCRIPTION);
    }
}
