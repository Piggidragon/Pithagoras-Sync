//! Facts about the device for `device.info` and `hello`, and the same-machine probe.

use std::io::Read;
use std::path::{Path, PathBuf};

use sync_policy::paths::parse_device_path;
use sync_proto::methods::ProbeResult;
use sync_proto::{RpcError, code};

use crate::fsops::sha256_hex;

pub fn os() -> &'static str {
    std::env::consts::OS
}

pub fn arch() -> &'static str {
    std::env::consts::ARCH
}

/// The OS user name and uid (0 on Windows, which has no uids).
pub fn user() -> (String, u32) {
    #[cfg(unix)]
    {
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let name = std::env::var("USER")
            .ok()
            .filter(|u| !u.is_empty())
            .or_else(|| passwd_name(uid))
            .unwrap_or_else(|| uid.to_string());
        (name, uid)
    }
    #[cfg(windows)]
    {
        (std::env::var("USERNAME").unwrap_or_default(), 0)
    }
}

#[cfg(unix)]
fn passwd_name(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: zeroed passwd struct; getpwuid_r writes into `pw` and `buf`.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    // SAFETY: pw_name points into `buf`, NUL-terminated.
    let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

pub fn hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: gethostname writes at most `len` bytes.
        if unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            return String::from_utf8_lossy(&buf[..end]).into_owned();
        }
        String::new()
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
}

pub fn os_release() -> Option<String> {
    #[cfg(unix)]
    {
        let text = std::fs::read_to_string("/etc/os-release").ok()?;
        text.lines()
            .find_map(|l| l.strip_prefix("PRETTY_NAME="))
            .map(|v| v.trim_matches('"').to_string())
    }
    #[cfg(windows)]
    {
        Some("Windows".into())
    }
}

/// `headless`, `wayland`, `x11`, or `windows`.
pub fn session() -> &'static str {
    if cfg!(windows) {
        return "windows";
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        "wayland"
    } else if std::env::var_os("DISPLAY").is_some() {
        "x11"
    } else {
        "headless"
    }
}

/// The current user's home directory.
pub fn home() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn temp_dirs() -> Vec<PathBuf> {
    let mut v = vec![std::env::temp_dir()];
    #[cfg(unix)]
    v.extend([PathBuf::from("/tmp"), PathBuf::from("/var/tmp")]);
    #[cfg(windows)]
    {
        if let Some(l) = std::env::var_os("LOCALAPPDATA") {
            v.push(PathBuf::from(l).join("Temp"));
        }
        if let Some(w) = std::env::var_os("SystemRoot") {
            v.push(PathBuf::from(w).join("Temp"));
        }
    }
    v.iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect()
}

fn probe_name_ok(name: &str) -> bool {
    name.strip_prefix("pithagoras-probe-")
        .is_some_and(|h| h.len() == 32 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Answers `device.probe`: only for a file named `pithagoras-probe-<32 hex>` directly
/// in a temp directory, opened without following a symlink, so the portal cannot use
/// it to learn about any other path.
pub fn probe(wire_path: &str) -> Result<ProbeResult, RpcError> {
    let (user, uid) = user();
    let bad = |m: &str| RpcError::new(code::BAD_PATH, m);
    let path = parse_device_path(wire_path).map_err(|e| bad(&e.to_string()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !probe_name_ok(&name) {
        return Err(bad("not a probe file name"));
    }
    let parent = path.parent().unwrap_or(Path::new(""));
    let parent = std::fs::canonicalize(parent).ok();
    if !parent.is_some_and(|p| temp_dirs().contains(&p)) {
        return Ok(ProbeResult {
            found: false,
            sha256: None,
            user,
            uid,
        });
    }
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open a link itself, never its target.
        o.custom_flags(0x0020_0000);
    }
    let found = o.open(&path).ok().and_then(|f| {
        let m = f.metadata().ok()?;
        if !m.is_file() || m.len() > 4096 {
            return None;
        }
        let mut data = Vec::new();
        f.take(4096).read_to_end(&mut data).ok()?;
        Some(sha256_hex(&data))
    });
    Ok(ProbeResult {
        found: found.is_some(),
        sha256: found,
        user,
        uid,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn answers_only_for_probe_files_in_temp_dirs() {
        let name = format!("pithagoras-probe-{}", "ab".repeat(16));
        let tmp = std::env::temp_dir().join(&name);
        std::fs::write(&tmp, "token").unwrap();
        let r = probe(&tmp.to_string_lossy()).unwrap();
        std::fs::remove_file(&tmp).unwrap();
        assert!(r.found);
        assert_eq!(r.sha256.unwrap(), sha256_hex(b"token"));
        // Any other name is refused outright.
        assert!(probe("/etc/passwd").is_err());
        assert!(probe(&format!("/tmp/pithagoras-probe-{}", "AB".repeat(16))).is_err());
        // The right name outside a temp directory is not looked at.
        let t = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let elsewhere = t.path().join(&name);
        std::fs::write(&elsewhere, "token").unwrap();
        assert!(!probe(&elsewhere.to_string_lossy()).unwrap().found);
    }

    #[test]
    fn does_not_follow_a_symlink() {
        let name = format!("pithagoras-probe-{}", "cd".repeat(16));
        let link = std::env::temp_dir().join(&name);
        let target = tempfile::NamedTempFile::new_in(std::env::current_dir().unwrap()).unwrap();
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        let r = probe(&link.to_string_lossy());
        std::fs::remove_file(&link).unwrap();
        assert!(!r.unwrap().found);
    }
}
