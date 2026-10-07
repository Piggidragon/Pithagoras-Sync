//! The server's files on disk: written new (never through a link, never over
//! something that is there), folders private to the user, and one hash over
//! the whole installed tree, recorded at install and checked before every
//! start.

use std::io::Write;
use std::path::Path;

/// The sha256 of `data` in lowercase hex (the file tools' own).
pub use sync_ops::fsops::sha256_hex;

/// Whether `s` is a sha256 in lowercase hex.
pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Creates `dir` and the folders between `base` and it, each 0700 (Unix), and
/// refuses one that is a link.
pub fn private_dirs(base: &Path, dir: &Path) -> Result<(), String> {
    let rel = dir
        .strip_prefix(base)
        .map_err(|_| format!("{} is outside {}", dir.display(), base.display()))?;
    // The client's own state folder above it may not be there yet.
    if let Some(parent) = base.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let mut at = base.to_path_buf();
    make_private(&at)?;
    for c in rel.components() {
        at.push(c);
        make_private(&at)?;
    }
    Ok(())
}

fn make_private(dir: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(format!(
                "{} is a link; nothing is written there",
                dir.display()
            ));
        }
        Ok(m) if m.is_dir() => return Ok(()),
        Ok(_) => return Err(format!("{} is not a folder", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    match b.create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => make_private(dir),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

/// Writes a file that must not exist yet: 0755 when `executable`, else 0644.
pub fn write_new(path: &Path, data: &[u8], executable: bool) -> Result<(), String> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(if executable { 0o755 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = executable;
    let mut f = o
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Every regular file below `dir`, relative and `/`-separated, sorted. A link,
/// or anything that is neither a file nor a folder, is an error.
pub fn files(dir: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    walk(dir, String::new(), &mut out)?;
    out.sort();
    Ok(out)
}

fn walk(dir: &Path, prefix: String, out: &mut Vec<String>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for e in rd {
        let e = e.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = e
            .file_name()
            .into_string()
            .map_err(|n| format!("{}: a name that is not UTF-8: {n:?}", dir.display()))?;
        let t = e.file_type().map_err(|e| format!("{name}: {e}"))?;
        let rel = format!("{prefix}{name}");
        if t.is_symlink() {
            return Err(format!("{rel} is a link"));
        } else if t.is_dir() {
            walk(&e.path(), format!("{rel}/"), out)?;
        } else if t.is_file() {
            out.push(rel);
        } else {
            return Err(format!("{rel} is not a regular file"));
        }
    }
    Ok(())
}

/// One hash over a whole tree: each file's name, whether it may run (Unix),
/// and its content's sha256, one line each, in name order.
pub fn tree_hash(dir: &Path) -> Result<String, String> {
    let mut lines = String::new();
    for rel in files(dir)? {
        let path = rel.split('/').fold(dir.to_path_buf(), |p, c| p.join(c));
        let sum = file_sha256(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        #[cfg(unix)]
        let x = {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .permissions()
                .mode();
            if m & 0o111 != 0 { "x" } else { "-" }
        };
        #[cfg(not(unix))]
        let x = "-";
        lines.push_str(&format!("{rel}\t{x}\t{sum}\n"));
    }
    Ok(sha256_hex(lines.as_bytes()))
}

/// The sha256 of a file in lowercase hex, read in pieces: a server's
/// folder may hold files of many megabytes.
fn file_sha256(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(ctx
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// On Unix: `dir` and every folder from `base` down to it belong to this user
/// and nobody else may write them, and none is a link. Another user who could
/// write there could swap the server between the check and the start.
pub fn owned_and_private(base: &Path, dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let rel = dir
            .strip_prefix(base)
            .map_err(|_| format!("{} is outside {}", dir.display(), base.display()))?;
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        let mut at: std::path::PathBuf = base.to_path_buf();
        let check = |p: &Path| -> Result<(), String> {
            let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
            if m.file_type().is_symlink() {
                return Err(format!("{} is a link", p.display()));
            }
            if m.uid() != me {
                return Err(format!("{} belongs to another user", p.display()));
            }
            if m.mode() & 0o022 != 0 {
                return Err(format!("{} can be written by others", p.display()));
            }
            Ok(())
        };
        check(&at)?;
        for c in rel.components() {
            at.push(c);
            check(&at)?;
        }
    }
    #[cfg(not(unix))]
    let _ = (base, dir);
    Ok(())
}

/// Removes a folder and what is in it without following links in it.
pub fn remove_tree(dir: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            std::fs::remove_file(dir).map_err(|e| format!("{}: {e}", dir.display()))
        }
        Ok(_) => std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tree_hash_sees_every_change() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("v");
        private_dirs(t.path(), &d.join("a")).unwrap();
        write_new(&d.join("a/f"), b"1", false).unwrap();
        write_new(&d.join("run"), b"#!", true).unwrap();
        let h = tree_hash(&d).unwrap();
        assert_eq!(tree_hash(&d).unwrap(), h);
        assert!(write_new(&d.join("run"), b"again", true).is_err());
        std::fs::write(d.join("a/f"), b"2").unwrap();
        assert_ne!(tree_hash(&d).unwrap(), h);
        std::fs::write(d.join("a/f"), b"1").unwrap();
        assert_eq!(tree_hash(&d).unwrap(), h);
        std::fs::write(d.join("new"), b"").unwrap();
        assert_ne!(tree_hash(&d).unwrap(), h);
        std::fs::remove_file(d.join("new")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join("a/f"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            assert_ne!(tree_hash(&d).unwrap(), h);
            std::fs::set_permissions(d.join("a/f"), std::fs::Permissions::from_mode(0o644))
                .unwrap();
            std::os::unix::fs::symlink("/etc/passwd", d.join("link")).unwrap();
            assert!(tree_hash(&d).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn folders_are_private_and_links_refused() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let base = t.path().join("mcp");
        let d = base.join("s/1.0");
        private_dirs(&base, &d).unwrap();
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        owned_and_private(&base, &d).unwrap();
        std::fs::set_permissions(base.join("s"), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(owned_and_private(&base, &d).is_err());
        std::fs::set_permissions(base.join("s"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(t.path(), base.join("l")).unwrap();
        assert!(private_dirs(&base, &base.join("l/x")).is_err());
        assert!(owned_and_private(&base, &base.join("l")).is_err());
    }
}
