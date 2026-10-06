//! The windows of the graphical flow (`gui`). No GUI toolkit is linked in (the
//! Linux release is one static binary): on Linux the desktop's own dialog
//! program, `kdialog` on KDE and `zenity` elsewhere, started with an argv and a
//! cleaned environment, never through a shell; on Windows `MessageBoxW`.
//!
//! Text that comes from outside (a portal URL, a status line, an error) goes
//! through `shown` first: control characters become visible escapes and it is
//! cut, so it cannot redraw or bury what the owner reads. The dialog programs
//! may read markup, so text is also escaped for that or marked as plain.

use std::path::{Path, PathBuf};

use sync_policy::approve::visible;

pub const TITLE: &str = "Pithagoras Sync";

/// The longest text a dialog shows.
pub const MAX_TEXT: usize = 4000;

/// The longest answer taken from a dialog (a pasted pairing link).
pub const MAX_ANSWER: usize = 4096;

/// The longest piece of outside text shown in one place.
const MAX_SHOWN: usize = 300;

/// Outside text as a dialog may show it: escaped and cut.
pub fn shown(s: &str) -> String {
    clip(&visible(s), MAX_SHOWN)
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

pub trait Dialogs {
    fn info(&self, text: &str);
    fn error(&self, text: &str);
    /// Yes or No. A closed window, or a dialog that could not be shown, is No.
    fn question(&self, text: &str) -> bool;
    /// One line typed or pasted in; `None` when cancelled.
    fn entry(&self, text: &str) -> Option<String>;
    /// One of `items` (key, label), by its key; `None` when cancelled.
    fn menu(&self, text: &str, items: &[(&'static str, &str)]) -> Option<&'static str>;
}

/// What one dialog asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask<'a> {
    Info(&'a str),
    Error(&'a str),
    Question(&'a str),
    Entry(&'a str),
    Menu(&'a str, &'a [(&'static str, &'a str)]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Helper {
    Zenity(PathBuf),
    Kdialog(PathBuf),
}

/// Pango markup's three special characters (zenity's list and entry texts).
fn pango(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// kdialog shows rich text when the text looks like it: `<qt>` makes it so
/// always, and the escaped text inside can then hold no tag of its own.
fn qt(s: &str) -> String {
    let body = s
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\n', "<br>");
    format!("<qt>{body}</qt>")
}

impl Helper {
    /// The program's arguments for `ask`. Every value is one argument; zenity's
    /// take the `--name=value` form, so none can be read as an option.
    pub fn args(&self, ask: &Ask) -> Vec<String> {
        let clipped = |t: &str| clip(t, MAX_TEXT);
        match self {
            Helper::Zenity(_) => {
                let mut a = vec![format!("--title={TITLE}")];
                match ask {
                    Ask::Info(t) | Ask::Error(t) | Ask::Question(t) => {
                        a.push(
                            match ask {
                                Ask::Info(_) => "--info",
                                Ask::Error(_) => "--error",
                                _ => "--question",
                            }
                            .into(),
                        );
                        a.push("--no-markup".into());
                        a.push("--width=480".into());
                        a.push(format!("--text={}", clipped(t)));
                    }
                    Ask::Entry(t) => {
                        a.push("--entry".into());
                        a.push("--width=560".into());
                        a.push(format!("--text={}", pango(&clipped(t))));
                    }
                    Ask::Menu(t, items) => {
                        a.extend(
                            [
                                "--list",
                                "--hide-header",
                                "--column=key",
                                "--column=choice",
                                "--hide-column=1",
                                "--print-column=1",
                                "--width=480",
                                "--height=340",
                            ]
                            .map(String::from),
                        );
                        a.push(format!("--text={}", pango(&clipped(t))));
                        for (k, l) in *items {
                            a.push(k.to_string());
                            a.push(l.to_string());
                        }
                    }
                }
                a
            }
            Helper::Kdialog(_) => {
                let mut a = vec!["--title".to_string(), TITLE.to_string()];
                let text = |t: &str| qt(&clipped(t));
                match ask {
                    Ask::Info(t) => a.extend(["--msgbox".into(), text(t)]),
                    Ask::Error(t) => a.extend(["--error".into(), text(t)]),
                    Ask::Question(t) => a.extend(["--yesno".into(), text(t)]),
                    Ask::Entry(t) => a.extend(["--inputbox".into(), text(t), String::new()]),
                    Ask::Menu(t, items) => {
                        a.extend(["--menu".into(), text(t)]);
                        for (k, l) in *items {
                            a.push(k.to_string());
                            a.push(l.to_string());
                        }
                    }
                }
                a
            }
        }
    }

    pub fn program(&self) -> &Path {
        match self {
            Helper::Zenity(p) | Helper::Kdialog(p) => p,
        }
    }
}

/// What the dialog programs get of the environment: the display, the session
/// bus, the language and the theme. Nothing else, so no variable of the client's
/// (or a secret someone put in one) reaches them.
const DIALOG_ENV: &[&str] = &[
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "HOME",
    "PATH",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_MESSAGES",
    "LC_CTYPE",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_TYPE",
    "XDG_SESSION_DESKTOP",
    "DESKTOP_SESSION",
    "XDG_DATA_DIRS",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "GDK_BACKEND",
    "GTK_THEME",
    "QT_QPA_PLATFORM",
    "QT_QPA_PLATFORMTHEME",
    "KDE_FULL_SESSION",
    "KDE_SESSION_VERSION",
];

/// Whether a graphical session is there to show a window in.
pub fn has_display() -> bool {
    if cfg!(windows) {
        return true;
    }
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|d| !d.is_empty()))
}

/// The first `name` in an absolute `PATH` folder.
fn on_path(name: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    p.is_file()
}

/// kdialog on KDE (when there), else zenity, else kdialog.
pub fn find_helper(path: &std::ffi::OsStr, desktop: &str) -> Option<Helper> {
    let kde = desktop.split(':').any(|d| d.eq_ignore_ascii_case("kde"));
    let kdialog = || on_path("kdialog", path).map(Helper::Kdialog);
    let zenity = || on_path("zenity", path).map(Helper::Zenity);
    if kde {
        kdialog().or_else(zenity)
    } else {
        zenity().or_else(kdialog)
    }
}

/// The desktop's dialog program.
pub struct Native {
    helper: Helper,
}

impl Native {
    pub fn new(helper: Helper) -> Native {
        Native { helper }
    }

    /// The dialog program of this session, if there is a display and one.
    pub fn find() -> Option<Native> {
        if !has_display() {
            return None;
        }
        let path = std::env::var_os("PATH")?;
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        find_helper(&path, &desktop).map(Native::new)
    }

    /// Runs the program; its exit code and up to `MAX_ANSWER` bytes of its
    /// output (`None` when there was more, or it could not run).
    fn run(&self, ask: &Ask) -> (Option<i32>, Option<String>) {
        use std::io::Read;
        let mut cmd = std::process::Command::new(self.helper.program());
        cmd.args(self.helper.args(ask))
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        for v in DIALOG_ENV {
            if let Some(x) = std::env::var_os(v) {
                cmd.env(v, x);
            }
        }
        let Ok(mut child) = cmd.spawn() else {
            return (None, None);
        };
        let mut out = Vec::new();
        let read = child
            .stdout
            .take()
            .map(|s| s.take(MAX_ANSWER as u64 + 1).read_to_end(&mut out).is_ok());
        let status = child.wait().ok().and_then(|s| s.code());
        let text = (read == Some(true) && out.len() <= MAX_ANSWER)
            .then(|| String::from_utf8(std::mem::take(&mut out)).ok())
            .flatten();
        out.fill(0);
        (status, text)
    }
}

impl Dialogs for Native {
    fn info(&self, text: &str) {
        self.run(&Ask::Info(text));
    }

    fn error(&self, text: &str) {
        self.run(&Ask::Error(text));
    }

    fn question(&self, text: &str) -> bool {
        self.run(&Ask::Question(text)).0 == Some(0)
    }

    fn entry(&self, text: &str) -> Option<String> {
        match self.run(&Ask::Entry(text)) {
            (Some(0), Some(t)) => Some(t.trim_end_matches(['\n', '\r']).to_string()),
            _ => None,
        }
    }

    fn menu(&self, text: &str, items: &[(&'static str, &str)]) -> Option<&'static str> {
        match self.run(&Ask::Menu(text, items)) {
            (Some(0), Some(t)) => {
                // zenity may print the key twice, separated by `|`.
                let key = t.trim().split('|').next().unwrap_or_default().to_string();
                items.iter().map(|(k, _)| *k).find(|k| *k == key)
            }
            _ => None,
        }
    }
}

/// `MessageBoxW`: Yes/No, OK/Cancel and information boxes. There is no input
/// box, so the pairing link is taken from the clipboard after the owner copied
/// it; a menu is a row of Yes/No/Cancel questions. Not run by the tests (see
/// windows.md).
#[cfg(windows)]
pub struct WinDialogs;

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDOK, IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_OKCANCEL,
        MB_SETFOREGROUND, MB_YESNO, MB_YESNOCANCEL, MESSAGEBOX_STYLE, MessageBoxW,
    };

    use super::{Dialogs, MAX_ANSWER, MAX_TEXT, TITLE, WinDialogs, clip};

    /// The clipboard's text format.
    const CF_UNICODETEXT: u32 = 13;
    const IDNO: i32 = 7;

    fn wide(s: &str) -> Vec<u16> {
        // A NUL would end the text early; `shown` already escapes it.
        s.replace('\0', " ")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    fn message(text: &str, style: MESSAGEBOX_STYLE) -> i32 {
        let t = wide(&clip(text, MAX_TEXT));
        let title = wide(TITLE);
        // SAFETY: both strings are NUL-terminated and outlive the call.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                t.as_ptr(),
                title.as_ptr(),
                style | MB_SETFOREGROUND,
            )
        }
    }

    /// The clipboard's text, if it holds some of at most `MAX_ANSWER` units.
    fn clipboard() -> Option<String> {
        // SAFETY: the clipboard is opened and closed here; the data is read
        // under GlobalLock, up to its NUL and never past MAX_ANSWER units.
        unsafe {
            if OpenClipboard(std::ptr::null_mut()) == 0 {
                return None;
            }
            let h = GetClipboardData(CF_UNICODETEXT);
            let mut text = None;
            if !h.is_null() {
                let p = GlobalLock(h) as *const u16;
                if !p.is_null() {
                    let mut units = Vec::new();
                    let mut i = 0;
                    while i <= MAX_ANSWER {
                        let u = *p.add(i);
                        if u == 0 {
                            break;
                        }
                        units.push(u);
                        i += 1;
                    }
                    GlobalUnlock(h);
                    if units.len() <= MAX_ANSWER {
                        text = String::from_utf16(&units).ok();
                    }
                }
            }
            CloseClipboard();
            text
        }
    }

    impl Dialogs for WinDialogs {
        fn info(&self, text: &str) {
            message(text, MB_OK | MB_ICONINFORMATION);
        }

        fn error(&self, text: &str) {
            message(text, MB_OK | MB_ICONERROR);
        }

        fn question(&self, text: &str) -> bool {
            message(text, MB_YESNO | MB_ICONQUESTION) == IDYES
        }

        fn entry(&self, text: &str) -> Option<String> {
            let t = format!("{text}\n\nCopy it, then press OK: it is read from the clipboard.");
            if message(&t, MB_OKCANCEL | MB_ICONQUESTION) != IDOK {
                return None;
            }
            clipboard().map(|s| s.trim().to_string())
        }

        fn menu(&self, text: &str, items: &[(&'static str, &str)]) -> Option<&'static str> {
            for (key, label) in items {
                let t = format!(
                    "{text}\n\n{label}?\n\nYes: {label}. No: the next choice. Cancel: close."
                );
                match message(&t, MB_YESNOCANCEL | MB_ICONQUESTION) {
                    IDYES => return Some(key),
                    IDNO => continue,
                    _ => return None,
                }
            }
            None
        }
    }
}

/// Scripted answers, recording what was shown (tests).
#[derive(Default)]
pub struct Fake {
    pub shown: std::sync::Mutex<Vec<String>>,
    /// Answers in order: `yes`, `no`, `cancel`, `text:<line>`, `pick:<key>`.
    pub answers: std::sync::Mutex<std::collections::VecDeque<String>>,
}

impl Fake {
    pub fn with(answers: &[&str]) -> Fake {
        Fake {
            shown: Default::default(),
            answers: std::sync::Mutex::new(answers.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn next(&self, kind: &str, text: &str) -> String {
        self.shown.lock().unwrap().push(format!("{kind}: {text}"));
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| "cancel".into())
    }

    /// Everything shown so far, one dialog per entry.
    pub fn seen(&self) -> Vec<String> {
        self.shown.lock().unwrap().clone()
    }
}

impl Dialogs for Fake {
    fn info(&self, text: &str) {
        self.shown.lock().unwrap().push(format!("info: {text}"));
    }

    fn error(&self, text: &str) {
        self.shown.lock().unwrap().push(format!("error: {text}"));
    }

    fn question(&self, text: &str) -> bool {
        self.next("question", text) == "yes"
    }

    fn entry(&self, text: &str) -> Option<String> {
        self.next("entry", text)
            .strip_prefix("text:")
            .map(str::to_string)
    }

    fn menu(&self, text: &str, items: &[(&'static str, &str)]) -> Option<&'static str> {
        let a = self.next("menu", text);
        let key = a.strip_prefix("pick:")?;
        items.iter().map(|(k, _)| *k).find(|k| *k == key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outside_text_is_escaped_and_cut() {
        let s = shown("https://evil.example\n\x1b[2KPaired\u{202e}");
        assert!(!s.chars().any(|c| c.is_control()), "{s:?}");
        assert!(s.contains("\\n") && s.contains("\\u{202e}"), "{s}");
        assert_eq!(shown(&"x".repeat(5000)).chars().count(), MAX_SHOWN + 1);
    }

    #[test]
    fn zenity_gets_plain_text_one_argument_each() {
        let z = Helper::Zenity("/usr/bin/zenity".into());
        let a = z.args(&Ask::Question("Pair with <b>x</b> & -y --z?"));
        assert_eq!(
            a,
            [
                "--title=Pithagoras Sync",
                "--question",
                "--no-markup",
                "--width=480",
                "--text=Pair with <b>x</b> & -y --z?"
            ]
        );
        // Texts that zenity reads as markup are escaped.
        let a = z.args(&Ask::Entry("a <i>b</i> & c"));
        assert_eq!(a.last().unwrap(), "--text=a &lt;i&gt;b&lt;/i&gt; &amp; c");
        let a = z.args(&Ask::Menu(
            "Paired with <x>",
            &[("status", "Status"), ("quit", "Quit")],
        ));
        assert!(a.contains(&"--print-column=1".to_string()), "{a:?}");
        assert!(
            a.contains(&"--text=Paired with &lt;x&gt;".to_string()),
            "{a:?}"
        );
        assert_eq!(&a[a.len() - 4..], ["status", "Status", "quit", "Quit"]);
        // Every option is one `--name=value` argument: no text is a separate
        // argument zenity could take for an option.
        let a = z.args(&Ask::Info("--help"));
        assert!(a.iter().all(|x| x.starts_with("--")), "{a:?}");
        assert_eq!(a.last().unwrap(), "--text=--help");
    }

    #[test]
    fn kdialog_text_cannot_carry_markup() {
        let k = Helper::Kdialog("/usr/bin/kdialog".into());
        let a = k.args(&Ask::Info("<img src=x> & \"q\"\nline 2"));
        assert_eq!(
            a,
            [
                "--title",
                "Pithagoras Sync",
                "--msgbox",
                "<qt>&lt;img src=x&gt; &amp; &quot;q&quot;<br>line 2</qt>"
            ]
        );
        let a = k.args(&Ask::Entry("Paste the link"));
        assert_eq!(&a[2..], ["--inputbox", "<qt>Paste the link</qt>", ""]);
        let a = k.args(&Ask::Menu("m", &[("log", "Open log")]));
        assert_eq!(&a[2..], ["--menu", "<qt>m</qt>", "log", "Open log"]);
        // A text that starts with a dash is still inside `<qt>`.
        assert!(k.args(&Ask::Error("-x"))[3].starts_with("<qt>"));
    }

    #[test]
    fn a_long_text_is_cut_before_it_reaches_the_dialog() {
        let z = Helper::Zenity("/usr/bin/zenity".into());
        let a = z.args(&Ask::Info(&"y".repeat(MAX_TEXT * 3)));
        assert!(a.last().unwrap().chars().count() < MAX_TEXT + 10);
    }

    #[cfg(unix)]
    #[test]
    fn kdialog_on_kde_zenity_elsewhere() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        for p in ["zenity", "kdialog"] {
            let f = t.path().join(p);
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = std::ffi::OsString::from(t.path());
        assert_eq!(
            find_helper(&path, "KDE"),
            Some(Helper::Kdialog(t.path().join("kdialog")))
        );
        assert_eq!(
            find_helper(&path, "ubuntu:GNOME"),
            Some(Helper::Zenity(t.path().join("zenity")))
        );
        std::fs::remove_file(t.path().join("zenity")).unwrap();
        assert_eq!(
            find_helper(&path, "GNOME"),
            Some(Helper::Kdialog(t.path().join("kdialog")))
        );
    }

    #[test]
    fn the_fake_answers_in_order_and_cancels_when_out_of_answers() {
        let f = Fake::with(&["yes", "text:abc", "pick:log"]);
        assert!(f.question("q"));
        assert_eq!(f.entry("e").as_deref(), Some("abc"));
        assert_eq!(f.menu("m", &[("log", "Open log")]), Some("log"));
        assert!(!f.question("again"));
        assert_eq!(f.seen().len(), 4);
    }
}
