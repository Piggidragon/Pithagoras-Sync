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

/// Lets go of the console (`gui` started by a double click, a detached `run`).
/// `FreeConsole` leaves the standard handles that pointed into the console set:
/// closed, or by then another object's. A program started with one of them
/// inherited does not start (os error 6 or 50), and a print may land in that
/// other object or fail. So they are cleared: the client's own output then
/// goes nowhere, and the programs it starts get no handle for it.
#[cfg(windows)]
pub fn let_go_of_console() {
    use windows_sys::Win32::System::Console::{
        FreeConsole, GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
        STD_OUTPUT_HANDLE, SetStdHandle,
    };
    let ids = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
    // SAFETY: GetStdHandle, GetConsoleMode, FreeConsole and SetStdHandle have no
    // preconditions; `mode` outlives the call that writes it. Only the handles
    // of the console are cleared: a file or pipe given to the program stays.
    unsafe {
        let console = ids.map(|id| {
            let mut mode = 0;
            GetConsoleMode(GetStdHandle(id), &mut mode) != 0
        });
        FreeConsole();
        for (id, console) in ids.into_iter().zip(console) {
            if console {
                SetStdHandle(id, std::ptr::null_mut());
            }
        }
    }
}

/// How much of a program's error text goes into the error.
const MAX_ERROR_TEXT: usize = 500;

impl System {
    /// Runs a program with none of the client's own handles: a window has no
    /// console to share them with. Its error text goes into the error when
    /// `why` (on one line, cut short), as it would have stood in the terminal.
    fn run_with(&self, argv: &[String], why: bool) -> Result<String, String> {
        let (prog, args) = argv.split_first().ok_or("empty command")?;
        let out = no_console_window(&mut std::process::Command::new(prog))
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map_err(|e| format!("{prog}: {e}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let failed = format!("`{}` failed ({})", argv.join(" "), out.status);
        let text = program_text(&out.stderr);
        let text: String = text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(MAX_ERROR_TEXT)
            .collect();
        if why && !text.is_empty() {
            Err(format!("{failed}: {text}"))
        } else {
            Err(failed)
        }
    }
}

/// A console program's output. Windows' own programs write a pipe in the
/// console's code page (OEM), not in UTF-8.
fn program_text(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Globalization::{CP_OEMCP, MultiByteToWideChar};
        let len = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
        let mut wide = vec![0u16; len as usize];
        // SAFETY: both buffers hold `len` elements and outlive the call; an
        // OEM code page never makes more UTF-16 units than it had bytes.
        let n = unsafe {
            MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), len)
        };
        if n > 0 {
            return String::from_utf16_lossy(&wide[..n as usize]);
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

impl Runner for System {
    fn run(&self, argv: &[String]) -> Result<String, String> {
        self.run_with(argv, true)
    }

    fn try_run(&self, argv: &[String]) -> Result<String, String> {
        self.run_with(argv, false)
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
    /// Removes a folder that is empty. One that is not, or is gone, stays: an
    /// install made it, and something else may have put files in it since.
    RemoveEmptyDir {
        path: PathBuf,
    },
    /// Takes `desktop` out of the handlers `mime` has in the desktop's
    /// `mimeapps.list` (`xdg-mime default` wrote it there), and nothing else:
    /// every other line, section and handler stays. A file that holds
    /// nothing else afterwards goes. Best effort, with a hint when it fails.
    DropMimeHandler {
        path: PathBuf,
        mime: String,
        desktop: String,
    },
    Run {
        argv: Vec<String>,
    },
    /// May fail; `hint` tells the owner what to do then. Empty: a failure is
    /// no news (a task ended that did not run), and adds no note.
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
            Action::RemoveEmptyDir { path } => {
                format!("remove {} if it is empty", path.display())
            }
            Action::DropMimeHandler {
                path,
                mime,
                desktop,
            } => format!(
                "take {desktop} out of the handlers of {mime} in {}",
                path.display()
            ),
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
            Action::RemoveEmptyDir { path } => {
                // Not empty, or gone already: left as it is.
                let _ = std::fs::remove_dir(rooted(root, path));
            }
            Action::DropMimeHandler {
                path,
                mime,
                desktop,
            } => {
                let p = rooted(root, path);
                if let Err(e) = drop_mime_handler(&p, mime, desktop) {
                    hints.push(format!(
                        "{}: {e}: take {desktop} out of the handlers of {mime} there by hand",
                        p.display()
                    ));
                }
            }
            Action::Run { argv } => {
                runner.run(argv)?;
            }
            Action::Try { argv, hint } => {
                if let Err(e) = runner.try_run(argv)
                    && !hint.is_empty()
                {
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

/// `text` of a `mimeapps.list` without `desktop` among the handlers of `mime`
/// in its `[Default Applications]` and `[Added Associations]`; `None` when it
/// had none. A line that lists other handlers as well keeps them, in their
/// order; everything else is copied as it was, line ends included.
pub fn without_mime_handler(text: &str, mime: &str, desktop: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut section = "";
    let mut changed = false;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        let end = &line[body.len()..];
        let head = body.trim();
        if head.starts_with('[') && head.ends_with(']') {
            section = &head[1..head.len() - 1];
        }
        let listed = matches!(section, "Default Applications" | "Added Associations");
        let Some((key, value)) = body
            .split_once('=')
            .filter(|(key, _)| listed && key.trim() == mime)
        else {
            out.push_str(line);
            continue;
        };
        let ids: Vec<&str> = value
            .split(';')
            .map(str::trim)
            .filter(|i| !i.is_empty())
            .collect();
        if !ids.contains(&desktop) {
            out.push_str(line);
            continue;
        }
        changed = true;
        let kept: Vec<&str> = ids.into_iter().filter(|i| *i != desktop).collect();
        if !kept.is_empty() {
            let semicolon = if value.trim_end().ends_with(';') {
                ";"
            } else {
                ""
            };
            out.push_str(&format!("{key}={}{semicolon}{end}", kept.join(";")));
        }
    }
    changed.then_some(out)
}

/// Whether `text` says nothing but section headers and blank lines.
fn only_headers(text: &str) -> bool {
    text.lines().all(|l| {
        let l = l.trim();
        l.is_empty() || (l.starts_with('[') && l.ends_with(']'))
    })
}

/// `Action::DropMimeHandler`: the file that is not there is done.
fn drop_mime_handler(path: &Path, mime: &str, desktop: &str) -> std::io::Result<()> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let text = String::from_utf8(bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not UTF-8 text"))?;
    let Some(new) = without_mime_handler(&text, mime, desktop) else {
        return Ok(());
    };
    if only_headers(&new) {
        return std::fs::remove_file(path);
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)?.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = 0o644;
    write_file(path, new.as_bytes(), mode)
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

#[cfg(test)]
mod tests {
    use super::*;

    const MIME: &str = "x-scheme-handler/pithagoras-sync";
    const DESKTOP: &str = "pithagoras-sync.desktop";

    /// Only the program's own handler goes out of `mimeapps.list`: other
    /// types, other programs' handlers (also for the same type), comments,
    /// the order of the rest and the line ends stay.
    #[test]
    fn only_our_handler_leaves_the_list_of_default_programs() {
        let text = "# mine\n[Default Applications]\nx-scheme-handler/https=firefox.desktop\nx-scheme-handler/pithagoras-sync=pithagoras-sync.desktop\ntext/html=a.desktop;pithagoras-sync.desktop;\n\n[Added Associations]\nx-scheme-handler/pithagoras-sync=other.desktop;pithagoras-sync.desktop;third.desktop\n[Other]\nx-scheme-handler/pithagoras-sync=pithagoras-sync.desktop\n";
        let new = without_mime_handler(text, MIME, DESKTOP).unwrap();
        assert_eq!(
            new,
            "# mine\n[Default Applications]\nx-scheme-handler/https=firefox.desktop\ntext/html=a.desktop;pithagoras-sync.desktop;\n\n[Added Associations]\nx-scheme-handler/pithagoras-sync=other.desktop;third.desktop\n[Other]\nx-scheme-handler/pithagoras-sync=pithagoras-sync.desktop\n"
        );
        // Nothing of ours (another program is the handler): nothing changes.
        let other = "[Default Applications]\nx-scheme-handler/pithagoras-sync=other.desktop\n";
        assert_eq!(without_mime_handler(other, MIME, DESKTOP), None);
        assert_eq!(without_mime_handler("", MIME, DESKTOP), None);
        // Line ends and a last line without one stay as they were.
        let crlf = "[Default Applications]\r\nx-scheme-handler/pithagoras-sync = a.desktop;pithagoras-sync.desktop\r\nb=c";
        assert_eq!(
            without_mime_handler(crlf, MIME, DESKTOP).unwrap(),
            "[Default Applications]\r\nx-scheme-handler/pithagoras-sync =a.desktop\r\nb=c"
        );
    }

    /// `DropMimeHandler` on files: the other entries stay, a file left with
    /// nothing but headers goes, a missing one is done, and a failure is a
    /// hint, not an error.
    #[cfg(unix)]
    #[test]
    fn dropping_the_handler_edits_the_file_in_place() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimeapps.list");
        let drop = || Action::DropMimeHandler {
            path: path.clone(),
            mime: MIME.into(),
            desktop: DESKTOP.into(),
        };
        let run = |a: Action| apply(&[a], Path::new("/"), &Fake::default()).unwrap();
        // No file: nothing to do.
        assert!(run(drop()).is_empty());
        std::fs::write(
            &path,
            "[Default Applications]\nx-scheme-handler/pithagoras-sync=pithagoras-sync.desktop\nx-scheme-handler/mailto=m.desktop\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(run(drop()).is_empty());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[Default Applications]\nx-scheme-handler/mailto=m.desktop\n"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Again: nothing of ours left, the file is not touched.
        run(drop());
        assert!(std::fs::read_to_string(&path).unwrap().contains("mailto"));
        // Only our line in it: nothing is left to keep.
        std::fs::write(
            &path,
            "[Default Applications]\nx-scheme-handler/pithagoras-sync=pithagoras-sync.desktop\n",
        )
        .unwrap();
        run(drop());
        assert!(!path.exists());
        // A comment is something to keep.
        std::fs::write(
            &path,
            "# keep\n[Default Applications]\nx-scheme-handler/pithagoras-sync=pithagoras-sync.desktop\n",
        )
        .unwrap();
        run(drop());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "# keep\n[Default Applications]\n"
        );
        // A file that is no text is left alone, with a hint.
        std::fs::write(&path, [0xff, 0xfe, b'[']).unwrap();
        let hints = run(drop());
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("by hand"), "{hints:?}");
        assert_eq!(std::fs::read(&path).unwrap(), [0xff, 0xfe, b'[']);
    }

    /// `RemoveEmptyDir` removes what is empty and nothing else.
    #[test]
    fn only_an_empty_folder_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (empty, full) = (dir.path().join("empty"), dir.path().join("full"));
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::create_dir_all(&full).unwrap();
        std::fs::write(full.join("x"), "x").unwrap();
        let plan: Vec<Action> = [&empty, &full, &dir.path().join("gone")]
            .iter()
            .map(|p| Action::RemoveEmptyDir { path: (*p).clone() })
            .collect();
        apply(&plan, Path::new("/"), &Fake::default()).unwrap();
        assert!(!empty.exists());
        assert!(full.join("x").exists());
    }

    /// A program that fails says why in the error, which a window shows: it
    /// has no console its text could go to.
    #[test]
    fn a_failing_programs_own_words_are_in_the_error() {
        #[cfg(unix)]
        let fail = argv(&[
            "sh",
            "-c",
            "echo 'no such task' >&2; echo second line >&2; exit 3",
        ]);
        #[cfg(windows)]
        let fail = argv(&[
            "cmd",
            "/c",
            "(echo no such task& echo second line) 1>&2 & exit 3",
        ]);
        let e = System.run(&fail).unwrap_err();
        assert!(e.contains("failed"), "{e}");
        assert!(e.ends_with(": no such task second line"), "{e}");
        // A step that may fail is explained by its hint, not by the program.
        let e = System.try_run(&fail).unwrap_err();
        assert!(!e.ends_with("second line"), "{e}");
    }

    /// The console of a window started by a double click goes away (Windows
    /// Terminal closes its handles): a program started after that with the
    /// standard handles inherited still starts, and printing does not fail.
    /// Run in a child process, which gives up its console.
    #[cfg(windows)]
    #[test]
    fn programs_start_after_the_console_is_let_go() {
        const CHILD: &str = "PITHAGORAS_SYNC_TEST_CONSOLE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            std::process::exit(without_console());
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "actions::tests::programs_start_after_the_console_is_let_go",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{out:?}");
    }

    /// 0 when all went well, else which step failed.
    #[cfg(windows)]
    fn without_console() -> i32 {
        use std::io::Write;
        use windows_sys::Win32::Foundation::{
            CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        use windows_sys::Win32::System::Console::{
            AllocConsole, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
        };
        let open = |name: &str| -> HANDLE {
            let w: Vec<u16> = name.encode_utf16().chain([0]).collect();
            // SAFETY: the name is NUL-terminated and outlives the call.
            unsafe {
                CreateFileW(
                    w.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            }
        };
        // The standard handles point into a console, as for a double click.
        let mut out = open("CONOUT$");
        if out == INVALID_HANDLE_VALUE {
            // SAFETY: AllocConsole has no preconditions.
            unsafe { AllocConsole() };
            out = open("CONOUT$");
        }
        let input = open("CONIN$");
        if out == INVALID_HANDLE_VALUE || input == INVALID_HANDLE_VALUE {
            return 2;
        }
        // SAFETY: the handles are ours; SetStdHandle has no preconditions.
        unsafe {
            SetStdHandle(STD_INPUT_HANDLE, input);
            SetStdHandle(STD_OUTPUT_HANDLE, out);
            SetStdHandle(STD_ERROR_HANDLE, out);
        }
        let_go_of_console();
        // Gone, as Windows Terminal leaves them after FreeConsole.
        // SAFETY: the handles are ours and not used again here.
        unsafe {
            CloseHandle(input);
            CloseHandle(out);
        }
        let inherited = no_console_window(&mut std::process::Command::new("cmd"))
            .args(["/c", "exit 0"])
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status();
        if !inherited.is_ok_and(|s| s.success()) {
            return 3;
        }
        if System.run(&argv(&["cmd", "/c", "exit 0"])).is_err() {
            return 4;
        }
        let mut stdout = std::io::stdout();
        if writeln!(stdout, "nobody reads this")
            .and_then(|_| stdout.flush())
            .is_err()
        {
            return 5;
        }
        0
    }
}
