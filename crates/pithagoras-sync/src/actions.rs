//! Steps that change the system (`install`, `setup`): planned first, shown to the
//! owner, then applied. Tests apply them under a fake root with a fake command
//! runner, so nothing here needs root or a real systemd to be checked.

use std::path::{Component, Path, PathBuf};

pub trait Runner {
    /// Runs a program; its standard output on success.
    fn run(&self, argv: &[String]) -> Result<String, String>;

    /// Runs a program that may fail (`Action::Try`), whose own error text is
    /// not shown: the hint explains the failure in the client's words, where
    /// the program's would come first and in the system's language.
    fn try_run(&self, argv: &[String]) -> Result<String, String> {
        self.run(argv)
    }

    /// Sets a string value under `HKEY_CURRENT_USER\<key>` (Windows); `name`
    /// empty is the key's default value.
    fn reg_set(&self, key: &str, name: &str, value: &str) -> Result<(), String>;

    /// Removes `HKEY_CURRENT_USER\<key>` and everything under it; a key that is
    /// not there is no error.
    fn reg_delete(&self, key: &str) -> Result<(), String>;
}

/// Runs real programs.
pub struct System;

/// Without a console of its own (`gui` and a detached `run` let go of it), a
/// console program the client starts (`schtasks`, the program's own
/// `--version`) gets none either: Windows would open a window for each one
/// over the dialogs. With a console it shares that one, its errors shown there.
#[cfg(windows)]
pub fn no_console_window(cmd: &mut std::process::Command) -> &mut std::process::Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // SAFETY: GetConsoleWindow has no preconditions.
    if unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() }.is_null() {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[cfg(not(windows))]
pub fn no_console_window(cmd: &mut std::process::Command) -> &mut std::process::Command {
    cmd
}

impl System {
    fn run_with(&self, argv: &[String], stderr: std::process::Stdio) -> Result<String, String> {
        let (prog, args) = argv.split_first().ok_or("empty command")?;
        let out = no_console_window(&mut std::process::Command::new(prog))
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(stderr)
            .output()
            .map_err(|e| format!("{prog}: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!("`{}` failed ({})", argv.join(" "), out.status))
        }
    }
}

impl Runner for System {
    fn run(&self, argv: &[String]) -> Result<String, String> {
        self.run_with(argv, std::process::Stdio::inherit())
    }

    fn try_run(&self, argv: &[String]) -> Result<String, String> {
        self.run_with(argv, std::process::Stdio::null())
    }

    fn reg_set(&self, key: &str, name: &str, value: &str) -> Result<(), String> {
        #[cfg(windows)]
        return crate::registry::set_string(key, name, value);
        #[cfg(not(windows))]
        {
            let _ = (key, name, value);
            Err("the registry is Windows only".into())
        }
    }

    fn reg_delete(&self, key: &str) -> Result<(), String> {
        #[cfg(windows)]
        return crate::registry::delete_tree(key);
        #[cfg(not(windows))]
        {
            let _ = key;
            Err("the registry is Windows only".into())
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
    /// A string value under `HKEY_CURRENT_USER\<key>` (Windows; never another
    /// hive). `name` empty is the key's default value.
    RegSet {
        key: String,
        name: String,
        value: String,
    },
    /// `HKEY_CURRENT_USER\<key>` and everything under it.
    RegDelete {
        key: String,
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
            Action::RegSet { key, name, value } => format!(
                "set HKCU\\{key} {} = {value}",
                if name.is_empty() { "(default)" } else { name }
            ),
            Action::RegDelete { key } => format!("remove HKCU\\{key} and what is in it"),
        }
    }
}

pub fn shell_words(argv: &[String]) -> String {
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
                if let Err(e) = runner.try_run(argv) {
                    hints.push(format!("{e}: {hint}"));
                }
            }
            Action::RegSet { key, name, value } => {
                runner
                    .reg_set(key, name, value)
                    .map_err(|e| format!("HKCU\\{key}: {e}"))?;
            }
            Action::RegDelete { key } => {
                runner
                    .reg_delete(key)
                    .map_err(|e| format!("HKCU\\{key}: {e}"))?;
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
    #[cfg(windows)]
    if let Err(e) = std::fs::rename(&tmp, path) {
        // A running program cannot be replaced on Windows, but it can be renamed:
        // it goes aside to `.old` first, as `update` does it.
        let old = crate::update::old_path(path);
        let _ = std::fs::remove_file(&old);
        if std::fs::rename(path, &old).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::rename(&old, path);
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        return Ok(());
    }
    #[cfg(not(windows))]
    std::fs::rename(&tmp, path)?;
    Ok(())
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

    /// Recorded as `reg set <key> <name> <value>`.
    fn reg_set(&self, key: &str, name: &str, value: &str) -> Result<(), String> {
        self.run(&argv(&["reg", "set", key, name, value]))
            .map(|_| ())
    }

    /// Recorded as `reg delete <key>`.
    fn reg_delete(&self, key: &str) -> Result<(), String> {
        self.run(&argv(&["reg", "delete", key])).map(|_| ())
    }
}
