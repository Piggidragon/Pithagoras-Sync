//! Steps that change the system (`install`, `setup`): planned first, shown to the
//! owner, then applied. Tests apply them under a fake root with a fake command
//! runner, so nothing here needs root or a real systemd to be checked.

use std::path::{Component, Path, PathBuf};

pub trait Runner {
    /// Runs a program; its standard output on success.
    fn run(&self, argv: &[String]) -> Result<String, String>;
}

/// Runs real programs.
pub struct System;

impl Runner for System {
    fn run(&self, argv: &[String]) -> Result<String, String> {
        let (prog, args) = argv.split_first().ok_or("empty command")?;
        let out = std::process::Command::new(prog)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .output()
            .map_err(|e| format!("{prog}: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!("`{}` failed ({})", argv.join(" "), out.status))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Write {
        path: PathBuf,
        content: Vec<u8>,
        mode: u32,
    },
    /// Copies a program into place (skipped when it already runs from there).
    Copy {
        from: PathBuf,
        to: PathBuf,
        mode: u32,
    },
    Remove {
        path: PathBuf,
    },
    Run {
        argv: Vec<String>,
    },
    /// May fail; `hint` tells the owner what to do then.
    Try {
        argv: Vec<String>,
        hint: String,
    },
}

pub fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

impl Action {
    pub fn describe(&self) -> String {
        match self {
            Action::Write { path, .. } => format!("write {}", path.display()),
            Action::Copy { from, to, .. } => {
                format!("copy {} to {}", from.display(), to.display())
            }
            Action::Remove { path } => format!("remove {}", path.display()),
            Action::Run { argv } => format!("run: {}", shell_words(argv)),
            Action::Try { argv, .. } => format!("run (may fail): {}", shell_words(argv)),
        }
    }
}

fn shell_words(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty() || a.contains([' ', '"', '\'', '\\', '$']) {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `path` under `root`; `/` is the real system.
pub fn rooted(root: &Path, path: &Path) -> PathBuf {
    if root == Path::new("/") {
        return path.to_path_buf();
    }
    let mut out = root.to_path_buf();
    for c in path.components() {
        if let Component::Normal(n) = c {
            out.push(n);
        }
    }
    out
}

/// Applies the steps in order and stops at the first failure. Returns the hints
/// of steps that were allowed to fail and did.
pub fn apply(actions: &[Action], root: &Path, runner: &dyn Runner) -> Result<Vec<String>, String> {
    let mut hints = Vec::new();
    for a in actions {
        match a {
            Action::Write {
                path,
                content,
                mode,
            } => {
                let p = rooted(root, path);
                write_file(&p, content, *mode).map_err(|e| format!("{}: {e}", p.display()))?;
            }
            Action::Copy { from, to, mode } => {
                let to = rooted(root, to);
                let same = match (std::fs::canonicalize(from), std::fs::canonicalize(&to)) {
                    (Ok(a), Ok(b)) => a == b,
                    _ => false,
                };
                if !same {
                    let data =
                        std::fs::read(from).map_err(|e| format!("{}: {e}", from.display()))?;
                    write_file(&to, &data, *mode).map_err(|e| format!("{}: {e}", to.display()))?;
                }
            }
            Action::Remove { path } => {
                let p = rooted(root, path);
                match std::fs::remove_file(&p) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        return Err(format!("{}: {e}", p.display()));
                    }
                    _ => {}
                }
            }
            Action::Run { argv } => {
                runner.run(argv)?;
            }
            Action::Try { argv, hint } => {
                if let Err(e) = runner.run(argv) {
                    hints.push(format!("{e}: {hint}"));
                }
            }
        }
    }
    Ok(hints)
}

/// Writes through a temporary file and a rename, so a running program is replaced
/// rather than overwritten in place.
fn write_file(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    std::fs::rename(&tmp, path)
}

/// Records commands instead of running them; answers from a script.
#[derive(Default)]
pub struct Fake {
    pub ran: std::sync::Mutex<Vec<Vec<String>>>,
    /// (program and first argument, answer): the first match answers.
    pub answers: Vec<(String, Result<String, String>)>,
}

impl Runner for Fake {
    fn run(&self, argv: &[String]) -> Result<String, String> {
        self.ran.lock().unwrap().push(argv.to_vec());
        let key = argv.iter().take(2).cloned().collect::<Vec<_>>().join(" ");
        self.answers
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, a)| a.clone())
            .unwrap_or(Ok(String::new()))
    }
}
