//! Turning a path from the portal into the real path the policy judges.
//!
//! The portal sends absolute device paths. The device refuses anything else instead
//! of guessing (relative paths, Windows drive letters, NUL bytes), then resolves
//! symlinks and `..` so the policy sees where a call would really land. The open
//! itself later goes through `openat2` with the resolved path, so a symlink that
//! appears between check and use makes the call fail instead of escaping.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub enum PathError {
    Empty,
    Relative,
    /// `C:\...` or `C:/...`: the portal must translate drive letters to `/c/...`.
    DriveLetter,
    Nul,
    /// The path names a symlink whose target does not exist.
    DanglingSymlink(PathBuf),
    /// `..` after the part of the path that exists; it cannot be resolved safely.
    ParentInMissingPart,
    Io(io::Error),
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::Empty => write!(f, "empty path"),
            PathError::Relative => write!(f, "path must be absolute"),
            PathError::DriveLetter => write!(f, "untranslated drive-letter path"),
            PathError::Nul => write!(f, "path contains a NUL byte"),
            PathError::DanglingSymlink(p) => write!(f, "{} is a dangling symlink", p.display()),
            PathError::ParentInMissingPart => {
                write!(f, "'..' after a path component that does not exist")
            }
            PathError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PathError {}

/// Checks the syntax of a path from the portal.
pub fn parse_device_path(s: &str) -> Result<PathBuf, PathError> {
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s.contains('\0') {
        return Err(PathError::Nul);
    }
    let b = s.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return Err(PathError::DriveLetter);
    }
    if s.starts_with("\\\\") {
        return Err(PathError::DriveLetter);
    }
    if !s.starts_with('/') {
        return Err(PathError::Relative);
    }
    Ok(PathBuf::from(s))
}

/// Resolves an absolute path: the part that exists through `realpath`, the rest
/// appended as is. A missing rest may not contain `..`, and a dangling symlink is
/// refused, since either could point anywhere once created.
pub fn resolve(path: &Path) -> Result<PathBuf, PathError> {
    if !path.is_absolute() {
        return Err(PathError::Relative);
    }
    match fs::canonicalize(path) {
        Ok(p) => return Ok(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(PathError::Io(e)),
    }
    let comps: Vec<Component> = path.components().collect();
    // The longest prefix that exists (as anything, symlinks included).
    let mut existing = 1; // the root always exists
    let mut prefix = PathBuf::from("/");
    for (i, c) in comps.iter().enumerate().skip(1) {
        let next = prefix.join(c.as_os_str());
        match fs::symlink_metadata(&next) {
            Ok(_) => {
                prefix = next;
                existing = i + 1;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(PathError::Io(e)),
        }
    }
    let real_prefix = match fs::canonicalize(&prefix) {
        Ok(p) => p,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(PathError::DanglingSymlink(prefix));
        }
        Err(e) => return Err(PathError::Io(e)),
    };
    let mut out = real_prefix;
    for c in &comps[existing..] {
        match c {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            _ => return Err(PathError::ParentInMissingPart),
        }
    }
    Ok(out)
}

/// `path` is `base` or inside it, compared by whole components (`/a/bc` is not inside
/// `/a/b`). Both should be resolved paths.
pub fn within(path: &Path, base: &Path) -> bool {
    path.starts_with(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn refuses_what_it_cannot_interpret() {
        assert!(matches!(parse_device_path(""), Err(PathError::Empty)));
        assert!(matches!(parse_device_path("a/b"), Err(PathError::Relative)));
        assert!(matches!(parse_device_path("~/x"), Err(PathError::Relative)));
        assert!(matches!(
            parse_device_path("C:\\Users"),
            Err(PathError::DriveLetter)
        ));
        assert!(matches!(
            parse_device_path("c:/x"),
            Err(PathError::DriveLetter)
        ));
        assert!(matches!(
            parse_device_path("\\\\srv\\share"),
            Err(PathError::DriveLetter)
        ));
        assert!(matches!(parse_device_path("/a\0b"), Err(PathError::Nul)));
        assert_eq!(
            parse_device_path("/c/Users").unwrap(),
            Path::new("/c/Users")
        );
    }

    #[test]
    fn resolves_symlinks_and_dotdot() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        fs::create_dir(root.join("granted")).unwrap();
        fs::create_dir(root.join("outside")).unwrap();
        symlink(root.join("outside"), root.join("granted/link")).unwrap();
        assert_eq!(
            resolve(&root.join("granted/link/new.txt")).unwrap(),
            root.join("outside/new.txt")
        );
        assert_eq!(
            resolve(&root.join("granted/../outside/x")).unwrap(),
            root.join("outside/x")
        );
        assert_eq!(
            resolve(&root.join("granted/./a/b")).unwrap(),
            root.join("granted/a/b")
        );
        assert!(matches!(
            resolve(&root.join("granted/missing/../../outside")),
            Err(PathError::ParentInMissingPart)
        ));
        symlink(root.join("nowhere/x"), root.join("granted/dangling")).unwrap();
        assert!(matches!(
            resolve(&root.join("granted/dangling")),
            Err(PathError::DanglingSymlink(_))
        ));
        assert!(matches!(
            resolve(&root.join("granted/dangling/y")),
            Err(PathError::DanglingSymlink(_))
        ));
    }

    #[test]
    fn within_compares_components() {
        assert!(within(Path::new("/a/b"), Path::new("/a/b")));
        assert!(within(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(!within(Path::new("/a/bc"), Path::new("/a/b")));
        assert!(!within(Path::new("/a"), Path::new("/a/b")));
    }
}
