//! `uninstall --purge`: the files the client wrote for this user, found and
//! removed. Only names the client itself writes are taken, inside its own
//! folders; anything else there stays, and so does the folder holding it. Links
//! are removed as links, never followed, and a folder of the client's that is
//! itself a link is refused, since what it leads to is not the client's.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use sync_policy::Dirs;

/// What the client left for this user.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// The client's own files and folders inside its folders.
    pub entries: Vec<PathBuf>,
    /// The client's folders, innermost first: removed once nothing else is in them.
    pub folders: Vec<PathBuf>,
}

impl Found {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.folders.is_empty()
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Config,
    State,
    Runtime,
}

/// A file the client writes: `name` itself, or the temporary file that
/// `write_private` (`.<name>.tmp<pid>`) or an older version (`<name>.tmp`) left
/// when it was stopped halfway.
fn written(name: &str, own: impl Fn(&str) -> bool) -> bool {
    if own(name) {
        return true;
    }
    if let Some(rest) = name.strip_prefix('.')
        && let Some((base, pid)) = rest.rsplit_once(".tmp")
        && !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
    {
        return own(base);
    }
    name.strip_suffix(".tmp").is_some_and(own)
}

/// `update-released` (this user's) or `update-released-<16 hex digits>` (one
/// program's): the release times `update` keeps.
fn update_record(name: &str) -> bool {
    match name.strip_prefix("update-released") {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix('-')
            .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit())),
        None => false,
    }
}

fn own(kind: Kind, name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    match kind {
        // The config (policy and folders included), the pairing token and the
        // elevation password.
        Kind::Config => written(name, |n| {
            matches!(n, "config.toml" | "token" | "elevation.secret")
        }),
        Kind::State => {
            // The commands' temporary folders.
            name == "tmp"
            // The logon task's XML, written by `install` with `.tmp<pid>`.
            || name.strip_prefix("logon-task.tmp").is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            || written(name, |n| {
                matches!(
                    n,
                    "audit.jsonl" | "audit.jsonl.1" | "client.log" | "client.log.1" | "paused" | "logon-task.xml"
                ) || update_record(n)
            })
        }
        Kind::Runtime => name == "control.sock",
    }
}

/// What the client left in `dirs`. Refuses, before anything is removed, when one
/// of its folders is a link or not a folder.
pub fn find(dirs: &Dirs) -> Result<Found, String> {
    let mut found = Found::default();
    let folders = [
        (&dirs.runtime, Kind::Runtime),
        (&dirs.state, Kind::State),
        (&dirs.config, Kind::Config),
    ];
    for (folder, kind) in folders {
        let meta = match std::fs::symlink_metadata(folder) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("{}: {e}", folder.display())),
        };
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{} is a link, not a folder of the client's own: nothing was removed. What it leads to is not the client's to delete; remove the link and what it leads to by hand if you no longer need them",
                folder.display()
            ));
        }
        if !meta.is_dir() {
            return Err(format!(
                "{} is not a folder: nothing was removed",
                folder.display()
            ));
        }
        let mut names = Vec::new();
        for e in std::fs::read_dir(folder).map_err(|e| format!("{}: {e}", folder.display()))? {
            names.push(
                e.map_err(|e| format!("{}: {e}", folder.display()))?
                    .file_name(),
            );
        }
        names.sort();
        for name in names {
            let path = folder.join(&name);
            // The runtime folder inside the state folder is taken on its own.
            if own(kind, &name) && !folders.iter().any(|(f, _)| **f == path) {
                found.entries.push(path);
            }
        }
        found.folders.push(folder.clone());
    }
    Ok(found)
}

/// Removes a file, a link (not what it leads to) or a folder of the client's.
fn remove_entry(path: &Path) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let done = if meta.is_dir() {
        // Removes links inside as links, without following them.
        std::fs::remove_dir_all(path)
    } else {
        // On Windows a link to a folder goes with remove_dir.
        std::fs::remove_file(path).or_else(|e| {
            if cfg!(windows) && meta.file_type().is_symlink() {
                std::fs::remove_dir(path)
            } else {
                Err(e)
            }
        })
    };
    match done {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Removes what `find` found. Returns the folders kept because something that
/// is not the client's is still in them.
pub fn remove(found: &Found) -> Result<Vec<PathBuf>, String> {
    for e in &found.entries {
        remove_entry(e).map_err(|err| format!("{}: {err}", e.display()))?;
    }
    let mut kept = Vec::new();
    for f in &found.folders {
        let left = match std::fs::read_dir(f) {
            Ok(mut d) => d.next().is_some(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("{}: {e}", f.display())),
        };
        if left {
            kept.push(f.clone());
            continue;
        }
        match std::fs::remove_dir(f) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("{}: {e}", f.display()));
            }
            _ => {}
        }
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout of a client that ran for a while, plus files that are not its.
    fn client(base: &Path) -> Dirs {
        let dirs = Dirs {
            config: base.join(".config/pithagoras-sync"),
            state: base.join(".local/state/pithagoras-sync"),
            runtime: base.join(".local/state/pithagoras-sync/run"),
        };
        for d in [
            &dirs.config,
            &dirs.runtime,
            &dirs.state.join("tmp/exec-1-0"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        for f in [
            "config.toml",
            "token",
            "elevation.secret",
            ".config.toml.tmp4242",
        ] {
            std::fs::write(dirs.config.join(f), "x").unwrap();
        }
        for f in [
            "audit.jsonl",
            "audit.jsonl.1",
            "client.log",
            "client.log.1",
            "paused",
            "update-released",
            "update-released-0123456789abcdef",
            "update-released-0123456789abcdef.tmp",
            "logon-task.xml",
            "tmp/exec-1-0/scratch",
        ] {
            std::fs::write(dirs.state.join(f), "x").unwrap();
        }
        std::fs::write(dirs.runtime.join("control.sock"), "").unwrap();
        // Next to the client's folders, and not the client's.
        std::fs::write(base.join(".config/other.toml"), "keep").unwrap();
        std::fs::create_dir_all(base.join(".local/state/other")).unwrap();
        dirs
    }

    #[test]
    fn the_clients_files_go_and_nothing_else() {
        let t = tempfile::tempdir().unwrap();
        let dirs = client(t.path());
        let found = find(&dirs).unwrap();
        assert_eq!(
            found.folders,
            vec![
                dirs.runtime.clone(),
                dirs.state.clone(),
                dirs.config.clone()
            ]
        );
        assert!(found.entries.contains(&dirs.state.join("tmp")));
        assert!(!found.entries.contains(&dirs.runtime), "{found:?}");
        assert_eq!(found.entries.len(), 4 + 9 + 1 + 1, "{found:?}");
        assert!(remove(&found).unwrap().is_empty());
        assert!(!dirs.config.exists() && !dirs.state.exists());
        assert_eq!(
            std::fs::read_to_string(t.path().join(".config/other.toml")).unwrap(),
            "keep"
        );
        assert!(t.path().join(".local/state/other").is_dir());
        // Twice: nothing left to find.
        assert!(find(&dirs).unwrap().is_empty());
    }

    #[test]
    fn a_file_the_client_did_not_write_keeps_its_folder() {
        let t = tempfile::tempdir().unwrap();
        let dirs = client(t.path());
        std::fs::write(dirs.config.join("notes.txt"), "mine").unwrap();
        std::fs::write(dirs.state.join("update-released-xyz"), "mine").unwrap();
        let found = find(&dirs).unwrap();
        assert_eq!(
            remove(&found).unwrap(),
            vec![dirs.state.clone(), dirs.config.clone()]
        );
        assert_eq!(
            std::fs::read_dir(&dirs.config).unwrap().count(),
            1,
            "only notes.txt"
        );
        assert!(dirs.state.join("update-released-xyz").exists());
        assert!(!dirs.config.join("config.toml").exists());
        assert!(!dirs.runtime.exists());
    }

    #[cfg(unix)]
    #[test]
    fn links_are_removed_not_followed() {
        let t = tempfile::tempdir().unwrap();
        let dirs = client(t.path());
        let outside = t.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("precious"), "keep").unwrap();
        std::fs::remove_file(dirs.config.join("token")).unwrap();
        std::os::unix::fs::symlink(outside.join("precious"), dirs.config.join("token")).unwrap();
        std::fs::remove_dir_all(dirs.state.join("tmp")).unwrap();
        std::os::unix::fs::symlink(&outside, dirs.state.join("tmp")).unwrap();
        remove(&find(&dirs).unwrap()).unwrap();
        assert_eq!(
            std::fs::read_to_string(outside.join("precious")).unwrap(),
            "keep"
        );
        assert!(std::fs::symlink_metadata(dirs.config.join("token")).is_err());
        assert!(std::fs::symlink_metadata(dirs.state.join("tmp")).is_err());
        // A link inside the commands' temporary folders is not followed either.
        let dirs = client(&t.path().join("again"));
        std::os::unix::fs::symlink(&outside, dirs.state.join("tmp/exec-1-0/out")).unwrap();
        remove(&find(&dirs).unwrap()).unwrap();
        assert!(outside.join("precious").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_that_is_a_link_is_refused_before_anything_goes() {
        let t = tempfile::tempdir().unwrap();
        let dirs = client(t.path());
        let elsewhere = t.path().join("elsewhere");
        std::fs::rename(&dirs.config, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &dirs.config).unwrap();
        let e = find(&dirs).unwrap_err();
        assert!(e.contains("is a link"), "{e}");
        assert!(e.contains("nothing was removed"), "{e}");
        assert!(elsewhere.join("config.toml").exists());
        assert!(dirs.state.join("audit.jsonl").exists());
        // A file where a folder belongs, too.
        std::fs::remove_file(&dirs.config).unwrap();
        std::fs::write(&dirs.config, "x").unwrap();
        assert!(find(&dirs).unwrap_err().contains("is not a folder"));
    }

    #[test]
    fn a_machine_never_set_up_has_nothing() {
        let t = tempfile::tempdir().unwrap();
        let found = find(&Dirs::under(t.path())).unwrap();
        assert!(found.is_empty());
        assert!(remove(&found).unwrap().is_empty());
    }

    #[test]
    fn only_the_names_the_client_writes_are_its() {
        for (kind, name, theirs) in [
            (Kind::Config, "config.toml", true),
            (Kind::Config, ".token.tmp17", true),
            (Kind::Config, ".token.tmp", false),
            (Kind::Config, "config.toml.bak", false),
            (Kind::Config, "audit.jsonl", false),
            (Kind::State, "update-released-0123456789ABCDEF", true),
            (Kind::State, "update-released-0123", false),
            (Kind::State, "update-released.tmp", true),
            (Kind::State, ".update-released.tmp9", true),
            (Kind::State, "logon-task.tmp123", true),
            (Kind::State, "logon-task.tmp", false),
            (Kind::State, "client.log.2", false),
            (Kind::Runtime, "control.sock", true),
            (Kind::Runtime, "other.sock", false),
        ] {
            assert_eq!(own(kind, OsStr::new(name)), theirs, "{name}");
        }
    }
}
