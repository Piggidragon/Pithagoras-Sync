//! The windows of the graphical flow (`gui`). No GUI toolkit is linked in (the
//! Linux release is one static binary): on Linux the desktop's own dialog
//! program, `kdialog` on KDE and `zenity` elsewhere, started with an argv and a
//! cleaned environment, never through a shell; on Windows `MessageBoxW`.
//!
//! Text that comes from outside (a portal URL, a status line, an error) goes
//! through `shown` first: control characters become visible escapes and it is
//! cut, so it cannot redraw or bury what the owner reads. The dialog programs
//! may read markup, so text is also escaped for that or marked as plain.
//!
//! A password (`password`) comes back through the dialog program's stdout,
//! never its argv or environment, and goes straight into a `Secret`.

use std::path::{Path, PathBuf};

use sync_policy::approve::visible;
use sync_policy::secret::Secret;

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
    /// One line typed in without showing it; `None` when cancelled.
    fn password(&self, text: &str) -> Option<Secret>;
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
    Password(&'a str),
    Menu(&'a str, &'a [(&'static str, &'a str)]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Helper {
    Zenity(PathBuf),
    Kdialog(PathBuf),
}

/// Pango markup's three special characters (zenity's list and entry texts).
fn pango(s: &str) -> String {
    sync_policy::approve::markup_escaped(s)
}

/// kdialog shows rich text when the text looks like it: `<qt>` makes it so
/// always, and the escaped text inside can then hold no tag of its own.
fn qt(s: &str) -> String {
    let body = sync_policy::approve::markup_escaped(s)
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
                    Ask::Entry(t) | Ask::Password(t) => {
                        a.push("--entry".into());
                        if matches!(ask, Ask::Password(_)) {
                            a.push("--hide-text".into());
                        }
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
                                "--height=400",
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
                    Ask::Password(t) => a.extend(["--password".into(), text(t)]),
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

/// The first `name` in an absolute `PATH` folder that `trusted` takes.
fn on_path(name: &str, path: &std::ffi::OsStr, trusted: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|p| is_executable(p) && trusted(p))
}

/// Set (debug builds only) to the one folder whose programs count as the
/// system's: the tests' stand-in dialog programs. A release build ignores it.
pub const TEST_DIALOG_DIR: &str = "PITHAGORAS_SYNC_TEST_DIALOG_DIR";

/// Whether a program found on `PATH` may be shown the owner's passwords: the
/// file and every folder above it (links resolved) belong to root and nobody
/// else can write them. A program the user (or a command of the agent) could
/// change or put earlier on `PATH`, as in `~/bin`, could be a stand-in that
/// draws the same window and keeps what is typed into it.
pub fn system_program(p: &Path) -> bool {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os(TEST_DIALOG_DIR)
        && p.parent() == Some(Path::new(&dir))
    {
        return true;
    }
    root_only(p)
}

#[cfg(unix)]
fn root_only(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(real) = std::fs::canonicalize(p) else {
        return false;
    };
    real.ancestors().all(|a| {
        std::fs::metadata(a).is_ok_and(|m| {
            // A sticky folder (`/tmp`) that others may write in still keeps
            // them from replacing what root owns there.
            let others_write = m.mode() & 0o022 != 0;
            let sticky = m.is_dir() && m.mode() & 0o1000 != 0;
            m.uid() == 0 && (!others_write || sticky)
        })
    })
}

#[cfg(not(unix))]
fn root_only(_p: &Path) -> bool {
    // Windows shows its own message boxes and runs no dialog program.
    false
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

/// kdialog on KDE (when there), else zenity, else kdialog; only one that
/// `trusted` takes (`system_program`).
pub fn find_helper(
    path: &std::ffi::OsStr,
    desktop: &str,
    trusted: &dyn Fn(&Path) -> bool,
) -> Option<Helper> {
    let kde = desktop.split(':').any(|d| d.eq_ignore_ascii_case("kde"));
    let kdialog = || on_path("kdialog", path, trusted).map(Helper::Kdialog);
    let zenity = || on_path("zenity", path, trusted).map(Helper::Zenity);
    if kde {
        kdialog().or_else(zenity)
    } else {
        zenity().or_else(kdialog)
    }
}

/// A locale name as `locale -a` spells it: the codeset in lower case without
/// dashes (`de_DE.UTF-8` is `de_DE.utf8`).
fn normal_locale(name: &str) -> String {
    let (base, modifier) = match name.split_once('@') {
        Some((b, m)) => (b, Some(m)),
        None => (name, None),
    };
    let mut out = match base.split_once('.') {
        Some((l, cs)) => format!(
            "{l}.{}",
            cs.chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
                .to_ascii_lowercase()
        ),
        None => base.to_string(),
    };
    if let Some(m) = modifier {
        out.push('@');
        out.push_str(m);
    }
    out
}

/// What the dialog program's locale needs changed, given the locales
/// installed (`locale -a`). GLib takes the arguments in the locale's
/// charset: with a locale that is not installed (or not UTF-8) it refuses a
/// text with an umlaut or an ellipsis, and the window never shows (a question
/// then reads as No). Such a locale is replaced by an installed UTF-8 one,
/// and the language of the windows goes into `LANGUAGE` for the buttons.
/// Nothing changes when the locale works, or nothing better is installed.
pub fn locale_fix(
    var: impl Fn(&str) -> Option<String>,
    installed: &[String],
    lang: crate::i18n::Lang,
) -> Vec<(&'static str, String)> {
    let set = |v: &str| var(v).filter(|s| !s.is_empty());
    let current = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|v| set(v))
        .unwrap_or_else(|| "C".into());
    let normal = normal_locale(&current);
    let installed: Vec<String> = installed.iter().map(|l| normal_locale(l.trim())).collect();
    let utf8 = |l: &str| l.split(['@']).next().is_some_and(|b| b.ends_with(".utf8"));
    if utf8(&normal) && installed.contains(&normal) {
        return Vec::new();
    }
    let Some(better) = ["C.utf8", "en_US.utf8"]
        .iter()
        .find(|l| installed.iter().any(|i| i == *l))
    else {
        return Vec::new();
    };
    let code = match lang {
        crate::i18n::Lang::De => "de",
        crate::i18n::Lang::En => "en",
    };
    vec![("LC_ALL", better.to_string()), ("LANGUAGE", code.into())]
}

/// The locales installed for the dialog programs: `locale -a`, or none known.
fn installed_locales(path: &std::ffi::OsStr) -> Vec<String> {
    let Some(prog) = on_path("locale", path, &system_program) else {
        return Vec::new();
    };
    std::process::Command::new(prog)
        .arg("-a")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The desktop's dialog program.
pub struct Native {
    helper: Helper,
    /// Locale variables set over the session's (`locale_fix`).
    locale: Vec<(&'static str, String)>,
}

impl Native {
    pub fn new(helper: Helper, locale: Vec<(&'static str, String)>) -> Native {
        Native { helper, locale }
    }

    /// The dialog program of this session, if there is a display and one.
    pub fn find(lang: crate::i18n::Lang) -> Option<Native> {
        if !has_display() {
            return None;
        }
        let path = std::env::var_os("PATH")?;
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        let helper = find_helper(&path, &desktop, &system_program)?;
        let locale = locale_fix(|v| std::env::var(v).ok(), &installed_locales(&path), lang);
        Some(Native::new(helper, locale))
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
        for (k, v) in &self.locale {
            cmd.env(k, v);
        }
        let Ok(mut child) = cmd.spawn() else {
            return (None, None);
        };
        // Room for all of it from the start: a buffer grown on the way would
        // leave copies of a password behind.
        let mut out = Vec::with_capacity(MAX_ANSWER + 1);
        let read = child.stdout.take().map(|mut s| {
            let ok = (&mut s)
                .take(MAX_ANSWER as u64 + 1)
                .read_to_end(&mut out)
                .is_ok();
            // The rest unread, the program would wait on a full pipe forever.
            let _ = std::io::copy(&mut s, &mut std::io::sink());
            ok
        });
        let status = child.wait().ok().and_then(|s| s.code());
        let text = if read == Some(true) && out.len() <= MAX_ANSWER {
            match String::from_utf8(std::mem::take(&mut out)) {
                Ok(t) => Some(t),
                Err(e) => {
                    e.into_bytes().fill(0);
                    None
                }
            }
        } else {
            None
        };
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

    fn password(&self, text: &str) -> Option<Secret> {
        match self.run(&Ask::Password(text)) {
            (Some(0), Some(mut t)) => {
                // Only the line end goes; the rest is never copied.
                while t.ends_with(['\n', '\r']) {
                    t.pop();
                }
                Some(Secret::new(t))
            }
            (_, Some(t)) => {
                drop(Secret::new(t));
                None
            }
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

/// `MessageBoxW`: Yes/No, OK/Cancel and information boxes, with its own texts
/// in `.0`'s language (Windows labels the buttons). There is no input box, so
/// the pairing link is taken from the clipboard after the owner copied it; a
/// menu is a row of Yes/No/Cancel questions. There is no password to ask for:
/// sudo is Linux only. Not run by the tests (see windows.md).
#[cfg(windows)]
pub struct WinDialogs(pub crate::i18n::Lang);

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, OpenClipboard,
    };
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDOK, IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_OKCANCEL,
        MB_SETFOREGROUND, MB_YESNO, MB_YESNOCANCEL, MESSAGEBOX_STYLE, MessageBoxW,
    };

    use sync_policy::win::wide;

    use super::{Dialogs, MAX_ANSWER, MAX_TEXT, Secret, TITLE, WinDialogs, clip};

    /// The clipboard's text format.
    const CF_UNICODETEXT: u32 = 13;
    const IDNO: i32 = 7;

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

    /// The clipboard's text, if it holds some: at most `MAX_ANSWER` units and
    /// one more, so a longer text is still too long for the link's check.
    fn clipboard() -> Option<String> {
        // SAFETY: the clipboard is opened and closed here; the data is read
        // under GlobalLock, up to its NUL, never past the block's size or
        // MAX_ANSWER units.
        unsafe {
            if OpenClipboard(std::ptr::null_mut()) == 0 {
                return None;
            }
            let h = GetClipboardData(CF_UNICODETEXT);
            let mut text = None;
            if !h.is_null() {
                let p = GlobalLock(h) as *const u16;
                if !p.is_null() {
                    let size = GlobalSize(h) / 2;
                    let mut units = Vec::new();
                    let mut i = 0;
                    while i <= MAX_ANSWER && i < size {
                        let u = *p.add(i);
                        if u == 0 {
                            break;
                        }
                        units.push(u);
                        i += 1;
                    }
                    GlobalUnlock(h);
                    text = Some(String::from_utf16_lossy(&units));
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
            let t = format!("{text}\n\n{}", self.0.clipboard_hint());
            if message(&t, MB_OKCANCEL | MB_ICONQUESTION) != IDOK {
                return None;
            }
            // OK with no text in the clipboard (empty, or a picture) is an
            // answer too: the flow says so and asks again.
            Some(clipboard().unwrap_or_default().trim().to_string())
        }

        fn password(&self, _text: &str) -> Option<Secret> {
            None
        }

        fn menu(&self, text: &str, items: &[(&'static str, &str)]) -> Option<&'static str> {
            for (key, label) in items {
                let t = self.0.menu_step(text, label);
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
    /// Answers in order: `yes`, `no`, `cancel`, `text:<line>`, `pw:<password>`,
    /// `pick:<key>`.
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

    fn password(&self, text: &str) -> Option<Secret> {
        self.next("password", text)
            .strip_prefix("pw:")
            .map(|p| Secret::new(p.to_string()))
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
        // A password is not shown as it is typed.
        let a = z.args(&Ask::Password("pw <x>"));
        assert_eq!(&a[1..3], ["--entry", "--hide-text"]);
        assert_eq!(a.last().unwrap(), "--text=pw &lt;x&gt;");
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
        let a = k.args(&Ask::Password("Passwort für <b>"));
        assert_eq!(&a[2..], ["--password", "<qt>Passwort für &lt;b&gt;</qt>"]);
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
        let any = |_: &Path| true;
        assert_eq!(
            find_helper(&path, "KDE", &any),
            Some(Helper::Kdialog(t.path().join("kdialog")))
        );
        assert_eq!(
            find_helper(&path, "ubuntu:GNOME", &any),
            Some(Helper::Zenity(t.path().join("zenity")))
        );
        // One that is not trusted is passed over.
        let no_kdialog = |p: &Path| !p.ends_with("kdialog");
        assert_eq!(
            find_helper(&path, "KDE", &no_kdialog),
            Some(Helper::Zenity(t.path().join("zenity")))
        );
        std::fs::remove_file(t.path().join("zenity")).unwrap();
        assert_eq!(
            find_helper(&path, "GNOME", &any),
            Some(Helper::Kdialog(t.path().join("kdialog")))
        );
    }

    /// A dialog program in a folder the user can write (`~/bin`, or here a
    /// temporary folder) is not shown a password, wherever it is on `PATH`;
    /// one root alone can change is.
    #[cfg(unix)]
    #[test]
    fn a_dialog_program_the_user_could_change_is_not_used() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let fake = t.path().join("zenity");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!root_only(&fake));
        let path =
            std::env::join_paths([t.path(), Path::new("/usr/bin"), Path::new("/bin")]).unwrap();
        assert_ne!(
            find_helper(&path, "GNOME", &root_only),
            Some(Helper::Zenity(fake.clone()))
        );
        // A user-owned folder above a root-owned file counts against it too.
        let inner = t.path().join("sub");
        std::fs::create_dir(&inner).unwrap();
        assert!(!root_only(&inner));
    }

    #[test]
    fn the_dialog_program_gets_a_working_utf8_locale() {
        use crate::i18n::Lang;
        let vars = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        let installed: Vec<String> = ["C", "C.utf8", "POSIX", "de_DE.utf8"]
            .map(String::from)
            .to_vec();
        // Installed and UTF-8: left alone.
        assert!(locale_fix(vars(&[("LANG", "de_DE.UTF-8")]), &installed, Lang::De).is_empty());
        assert!(locale_fix(vars(&[("LC_ALL", "C.UTF-8")]), &installed, Lang::En).is_empty());
        // Not installed, not UTF-8, or none at all: C.UTF-8, the language kept.
        for v in [
            &[("LANG", "fr_FR.UTF-8")][..],
            &[("LANG", "de_DE.ISO-8859-1")][..],
            &[("LANG", "de_DE")][..],
            &[("LANG", "de_DE.UTF-8"), ("LC_ALL", "C")][..],
            &[][..],
        ] {
            let m: std::collections::HashMap<&str, &str> = v.iter().copied().collect();
            let fix = locale_fix(|k| m.get(k).map(|s| s.to_string()), &installed, Lang::De);
            assert_eq!(
                fix,
                [
                    ("LC_ALL", "C.utf8".to_string()),
                    ("LANGUAGE", "de".to_string())
                ],
                "{v:?}"
            );
        }
        // Nothing better installed, or nothing known: left alone.
        assert!(locale_fix(vars(&[("LANG", "C")]), &["C".to_string()], Lang::En).is_empty());
        assert!(locale_fix(vars(&[("LANG", "C")]), &[], Lang::En).is_empty());
        assert_eq!(normal_locale("de_DE.UTF-8@euro"), "de_DE.utf8@euro");
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
