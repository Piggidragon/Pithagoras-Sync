#![cfg(windows)]
//! File calls on real NTFS folders: a junction or symlink that appears after the
//! policy resolved a path fails the call, and a write refused that way leaves the
//! file it would have reached untouched. Runs on the Windows test VM
//! (`scripts/windows-vm-test.sh`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sync_ops::fsops;
use sync_policy::{Confine, Permit};

struct Fx {
    _t: tempfile::TempDir,
    root: PathBuf,
}

fn fx() -> Fx {
    let t = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(t.path()).unwrap();
    let root = PathBuf::from(sync_policy::paths::win::strip_verbatim(
        &root.to_string_lossy(),
    ));
    for d in ["granted", "outside"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    fs::write(root.join("granted/a.txt"), "alpha").unwrap();
    fs::write(root.join("outside/secret.txt"), "keep me").unwrap();
    Fx { _t: t, root }
}

fn permit(path: PathBuf, root: &Path) -> Permit {
    Permit {
        path,
        root: Some(root.to_path_buf()),
        confine: Confine::None,
        elevate: None,
    }
}

/// `mklink /J`: junctions need no privilege, unlike symlinks.
fn junction(link: &Path, target: &Path) {
    let st = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(st.status.success(), "{st:?}");
}

#[test]
fn a_junction_swapped_in_fails_the_call_and_truncates_nothing() {
    let f = fx();
    let g = f.root.join("granted");
    // The policy judged granted\sub\secret.txt, a file inside the folder; then
    // sub became a junction to the outside folder.
    let sub = g.join("sub");
    junction(&sub, &f.root.join("outside"));
    let p = permit(sub.join("secret.txt"), &g);
    assert!(fsops::read(&p).is_err());
    assert!(fsops::stat(&p).is_err());
    assert!(fsops::write(&p, b"x", None, false).is_err());
    assert_eq!(
        fs::read_to_string(f.root.join("outside/secret.txt")).unwrap(),
        "keep me"
    );
    assert!(fsops::list(&permit(sub.clone(), &g)).is_err());
    // An ordinary write in the folder still replaces the whole file.
    let a = permit(g.join("a.txt"), &g);
    fsops::write(&a, b"z", None, false).unwrap();
    assert_eq!(fs::read_to_string(g.join("a.txt")).unwrap(), "z");
}

#[test]
fn short_names_and_case_reach_the_same_file() {
    let f = fx();
    let g = f.root.join("granted");
    let long = g.join("A Long Folder Name");
    fs::create_dir(&long).unwrap();
    fs::write(long.join("f.txt"), "long").unwrap();
    // The policy resolves 8.3 names to the long form; the open accepts either case.
    let resolved = sync_policy::paths::resolve(&g.join("ALONGF~1").join("f.txt"));
    if let Ok(r) = resolved {
        assert!(
            sync_policy::paths::within(&r, &long),
            "{} not in {}",
            r.display(),
            long.display()
        );
    }
    let p = permit(g.join("a long folder name").join("F.TXT"), &g);
    assert_eq!(fsops::read(&p).unwrap().0, b"long");
}
