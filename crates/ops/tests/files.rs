#![cfg(target_os = "linux")]
//! File calls, grep and find on real temp directories, including symlinks that
//! appear after the policy resolved a path.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use sync_ops::fsops;
use sync_ops::search::{self, GrepOptions};
use sync_policy::{Confine, Permit};
use sync_proto::code;
use sync_proto::methods::FileKind;

struct Fx {
    _t: tempfile::TempDir,
    root: PathBuf,
}

fn fx() -> Fx {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    for d in ["granted/src", "granted/.git", "outside"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    fs::write(root.join("granted/a.txt"), "alpha\nbeta\ngamma\n").unwrap();
    fs::write(root.join("granted/src/m.rs"), "fn main() {}\n// beta\n").unwrap();
    fs::write(root.join("outside/secret"), "beta secret\n").unwrap();
    Fx { _t: t, root }
}

fn permit(path: PathBuf, root: Option<&Path>) -> Permit {
    Permit {
        path,
        root: root.map(Path::to_path_buf),
        confine: Confine::None,
        elevate: None,
    }
}

#[test]
fn reads_and_writes_with_if_match() {
    let f = fx();
    let g = f.root.join("granted");
    let p = permit(g.join("a.txt"), Some(&g));
    let (data, sha) = fsops::read(&p).unwrap();
    assert_eq!(data, b"alpha\nbeta\ngamma\n");
    assert_eq!(sha, fsops::sha256_hex(&data));
    let w = fsops::write(&p, b"new", Some(&sha), false).unwrap();
    assert_eq!(w.size, 3);
    // The old hash no longer matches: a concurrent change fails the edit.
    let e = fsops::write(&p, b"newer", Some(&sha), false).unwrap_err();
    assert_eq!(e.code, code::CONFLICT);
    assert_eq!(fs::read(g.join("a.txt")).unwrap(), b"new");
    // if_match on a file that does not exist is a conflict too.
    let missing = permit(g.join("missing.txt"), Some(&g));
    assert_eq!(
        fsops::write(&missing, b"x", Some(&sha), false)
            .unwrap_err()
            .code,
        code::CONFLICT
    );
    let deep = permit(g.join("new/dir/f.txt"), Some(&g));
    fsops::write(&deep, b"x", None, true).unwrap();
    assert_eq!(fs::read(g.join("new/dir/f.txt")).unwrap(), b"x");
}

#[test]
fn stat_and_list() {
    let f = fx();
    let g = f.root.join("granted");
    symlink(f.root.join("outside"), g.join("link")).unwrap();
    let s = fsops::stat(&permit(g.join("a.txt"), Some(&g))).unwrap();
    assert_eq!((s.kind, s.size), (FileKind::File, 17));
    let l = fsops::list(&permit(g.clone(), Some(&g))).unwrap();
    let names: Vec<(&str, FileKind)> = l
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.kind))
        .collect();
    assert!(names.contains(&("link", FileKind::Symlink)));
    assert!(names.contains(&("src", FileKind::Dir)));
    assert_eq!(
        fsops::stat(&permit(g.join("nope"), Some(&g)))
            .unwrap_err()
            .code,
        code::NOT_FOUND
    );
}

#[test]
fn a_symlink_that_appears_after_the_check_is_not_followed() {
    let f = fx();
    let g = f.root.join("granted");
    // The policy resolved granted/sub/file while sub was a real directory; then sub
    // is swapped for a symlink to outside.
    let p = permit(g.join("sub/secret"), Some(&g));
    symlink(f.root.join("outside"), g.join("sub")).unwrap();
    let e = fsops::read(&p).unwrap_err();
    assert_eq!(e.code, code::DENIED, "{e:?}");
    let e = fsops::write(&p, b"x", None, false).unwrap_err();
    assert_eq!(e.code, code::DENIED, "{e:?}");
    assert_eq!(
        fs::read(f.root.join("outside/secret")).unwrap(),
        b"beta secret\n"
    );
    // Without a folder root (Full mode) symlinks are refused all the same.
    let e = fsops::read(&permit(g.join("sub/secret"), None)).unwrap_err();
    assert_eq!(e.code, code::DENIED);
    // A path outside the root it claims to be under.
    let e = fsops::read(&permit(f.root.join("outside/secret"), Some(&g))).unwrap_err();
    assert_ne!(e.code, 0);
    assert!(fsops::read(&permit(f.root.join("outside/secret"), Some(&g))).is_err());
}

#[test]
fn writing_through_a_symlinked_file_is_refused() {
    let f = fx();
    let g = f.root.join("granted");
    symlink(f.root.join("outside/secret"), g.join("evil")).unwrap();
    assert!(fsops::write(&permit(g.join("evil"), Some(&g)), b"x", None, false).is_err());
    assert_eq!(
        fs::read(f.root.join("outside/secret")).unwrap(),
        b"beta secret\n"
    );
}

#[test]
fn reading_a_fifo_does_not_block() {
    let f = fx();
    let g = f.root.join("granted");
    let fifo = g.join("pipe");
    let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
    // SAFETY: mkfifo with a valid path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let e = fsops::read(&permit(fifo, Some(&g))).unwrap_err();
    assert!(e.message.contains("regular"), "{e:?}");
}

fn all(_: &Path) -> bool {
    true
}

#[test]
fn grep_finds_lines_with_context_and_skips_what_it_must() {
    let f = fx();
    let g = f.root.join("granted");
    symlink(f.root.join("outside"), g.join("link")).unwrap();
    fs::write(g.join(".git/config"), "beta in git\n").unwrap();
    let opts = GrepOptions {
        pattern: "beta",
        glob: None,
        ignore_case: false,
        literal: false,
        context: 1,
        limit: None,
    };
    let r = search::grep(&permit(g.clone(), Some(&g)), &opts, &all).unwrap();
    let matches: Vec<&str> = r
        .lines
        .iter()
        .filter(|l| !l.context)
        .map(|l| l.path.as_str())
        .collect();
    assert_eq!(matches.len(), 2, "{r:?}");
    assert!(r.lines.iter().any(|l| l.context && l.text == "alpha"));
    // Not through the symlink, not in .git.
    assert!(
        !r.lines
            .iter()
            .any(|l| l.path.contains("outside") || l.path.contains(".git"))
    );
    // The filter (protected paths) leaves files out.
    let no_src = |p: &Path| !p.to_string_lossy().contains("/src/");
    let r = search::grep(&permit(g.clone(), Some(&g)), &opts, &no_src).unwrap();
    assert_eq!(r.lines.iter().filter(|l| !l.context).count(), 1);
    assert_eq!(r.skipped, 1);
    // Glob on the file name, limit.
    let opts = GrepOptions {
        glob: Some("*.rs"),
        limit: Some(1),
        context: 0,
        ..opts
    };
    let r = search::grep(&permit(g.clone(), Some(&g)), &opts, &all).unwrap();
    assert_eq!(r.lines.len(), 1);
    assert!(r.lines[0].path.ends_with("m.rs"));
    assert!(r.truncated);
}

#[test]
fn find_matches_names_and_paths_and_honours_gitignore() {
    let f = fx();
    let g = f.root.join("granted");
    fs::create_dir_all(g.join("target/debug")).unwrap();
    fs::write(g.join("target/debug/x.rs"), "").unwrap();
    fs::write(g.join(".gitignore"), "target/\n").unwrap();
    let r = search::find(&permit(g.clone(), Some(&g)), "*.rs", None, &all).unwrap();
    assert_eq!(
        r.paths,
        vec![g.join("src/m.rs").to_string_lossy().into_owned()]
    );
    let r = search::find(&permit(g.clone(), Some(&g)), "src", None, &all).unwrap();
    assert_eq!(r.paths, vec![format!("{}/", g.join("src").display())]);
    let r = search::find(&permit(g.clone(), Some(&g)), "**/*.txt", None, &all).unwrap();
    assert_eq!(r.paths.len(), 1);
}
