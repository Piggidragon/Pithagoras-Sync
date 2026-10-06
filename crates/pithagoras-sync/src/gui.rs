//! `gui`: install, pair and uninstall without a terminal. One flow, driven by
//! the state it finds (not installed, installed but not paired, paired) and the
//! owner's answers in the OS's own dialogs (`dialogs`). What it does to the
//! system goes through `Host`, the same code the commands run, so the tests
//! drive the flow with fake dialogs and a fake host.
//!
//! A pairing link comes from a web page and is untrusted: it is parsed strictly,
//! shown as what was parsed (never the raw link) and acted on only after the
//! owner said yes. Every step that changes something is refused, as the command
//! line refuses it, when the flow was started by a command the client runs for
//! the portal.

use std::path::PathBuf;
use std::time::Duration;

use sync_connector::url::PairUri;
use sync_policy::Dirs;

use crate::dialogs::{Dialogs, MAX_ANSWER, shown};

/// How long the flow waits for a new pairing to connect.
pub const LINK_WAIT: Duration = Duration::from_secs(10);

/// What the flow says when it asks for the link.
pub const ENTRY_TEXT: &str = "Paste the pairing link from the portal's Devices page (Settings, Devices, Pair a device). It starts with pithagoras-sync://pair?";

/// Whether the link came up after pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    Connected(String),
    /// Not connected (yet), and why.
    Down(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Did what the owner asked.
    Done,
    /// The owner said no or closed a window: nothing changed.
    Cancelled,
    Failed,
}

/// What the flow does to the system. `RealHost` runs the code of the commands.
#[allow(async_fn_in_trait)]
pub trait Host {
    /// Whether `install` set the client up for this user.
    fn installed(&self) -> bool;
    /// The current pairing: the portal's URL.
    fn paired(&self) -> Option<String>;
    /// The name this device pairs as.
    fn device_name(&self) -> String;
    /// Who installs (the user) and where the program goes.
    fn install_target(&self) -> (String, String);
    /// Where the client's log is, as the owner can find it.
    fn log_place(&self) -> String;
    /// Refuses when the flow runs as a command the client runs for the portal.
    async fn owner_check(&self) -> Result<(), String>;
    /// `install`; returns its notes.
    async fn install(&self) -> Result<Vec<String>, String>;
    /// `pair <link>`; returns its notes.
    async fn pair(&self, link: &str) -> Result<Vec<String>, String>;
    /// Waits up to `LINK_WAIT` for the client to connect.
    async fn wait_for_link(&self) -> Link;
    /// What `status` prints.
    async fn status(&self) -> String;
    fn open_log(&self) -> Result<(), String>;
    /// `uninstall`, or `uninstall --purge`; returns what to tell the owner.
    async fn uninstall(&self, purge: bool) -> Result<String, String>;
}

/// The menu of a paired device.
const MENU: &[(&str, &str)] = &[
    ("status", "Status"),
    ("pair", "Pair again"),
    ("log", "Open log"),
    ("uninstall", "Uninstall"),
    ("quit", "Quit"),
];

/// Parses a link as `pair` would; the error as a dialog shows it. A plain-http
/// portal is taken only on this computer (`localhost` or a loopback address):
/// the connection would refuse anything else after the owner said yes, and the
/// question would have asked about a portal that cannot be reached.
fn parse(link: &str) -> Result<PairUri, String> {
    if link.len() > MAX_ANSWER {
        return Err("This is not a pairing link: it is far too long.".into());
    }
    let u = PairUri::parse(link)
        .map_err(|e| format!("This pairing link cannot be used: {}", shown(&e)))?;
    let host = &u.portal.host;
    let local = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback());
    if !u.portal.tls && !local {
        return Err(format!(
            "This pairing link names a portal on another machine over plain http ({}). Plain http is only for a portal on this computer: use the portal's https address.",
            shown(&u.portal.to_string())
        ));
    }
    Ok(u)
}

/// Runs the flow. `link` is the pairing link the OS started the program with.
pub async fn flow(d: &dyn Dialogs, h: &impl Host, link: Option<&str>) -> Outcome {
    // A command of the client's own gets no further than this, so it cannot
    // put questions on the owner's screen either. Each step checks again.
    if let Err(e) = h.owner_check().await {
        d.error(&shown(&e));
        return Outcome::Failed;
    }
    // A link is checked before anything else happens, the install included.
    let link = match link.map(parse) {
        None => None,
        Some(Ok(u)) => Some(u),
        Some(Err(e)) => {
            d.error(&e);
            return Outcome::Failed;
        }
    };
    if !h.installed() {
        let (user, path) = h.install_target();
        let q = format!(
            "Install Pithagoras Sync for {}?\n\nIt copies the program to {}, starts it at login, and opens pithagoras-sync:// links (the pairing link in the portal).",
            shown(&user),
            shown(&path)
        );
        if !d.question(&q) {
            return Outcome::Cancelled;
        }
        if let Err(e) = h.owner_check().await {
            d.error(&shown(&e));
            return Outcome::Failed;
        }
        if let Err(e) = h.install().await {
            d.error(&format!("Installing failed: {}", shown(&e)));
            return Outcome::Failed;
        }
        if link.is_none() && h.paired().is_some() {
            return after(d, h).await;
        }
    }
    if let Some(u) = link {
        return pair(d, h, &u).await;
    }
    if h.paired().is_none() {
        return ask_and_pair(d, h).await;
    }
    menu(d, h).await
}

/// Asks for the link until one parses or the owner cancels, then pairs.
async fn ask_and_pair(d: &dyn Dialogs, h: &impl Host) -> Outcome {
    loop {
        let Some(text) = d.entry(ENTRY_TEXT) else {
            return Outcome::Cancelled;
        };
        match parse(text.trim()) {
            Ok(u) => return pair(d, h, &u).await,
            Err(e) => d.error(&e),
        }
    }
}

/// Confirms with the parsed values, then pairs as `pair` does.
async fn pair(d: &dyn Dialogs, h: &impl Host, uri: &PairUri) -> Outcome {
    let portal = shown(&uri.portal.to_string());
    let name = shown(&h.device_name());
    let pin = if uri.spki.is_some() {
        " Its certificate is pinned by the link."
    } else {
        ""
    };
    let q = match h.paired() {
        Some(old) => format!(
            "This computer is paired with {}.\n\nReplace the pairing with the portal {portal} as \"{name}\"?{pin}",
            shown(&old)
        ),
        None => format!(
            "Pair this computer with the Pithagoras portal {portal} as \"{name}\"?{pin}\n\nIts agent can then ask to use this computer's files and shell. What it may do is decided on this computer: until you change it, every call asks you first."
        ),
    };
    if !d.question(&q) {
        return Outcome::Cancelled;
    }
    if let Err(e) = h.owner_check().await {
        d.error(&shown(&e));
        return Outcome::Failed;
    }
    // Rebuilt from what was parsed and shown, so only that is acted on.
    let link = link_of(uri);
    match h.pair(&link).await {
        Ok(_) => after(d, h).await,
        Err(e) => {
            d.error(&format!("Pairing failed: {}", shown(&e)));
            Outcome::Failed
        }
    }
}

/// The pairing link of a parsed one: the same portal, code and pin.
fn link_of(u: &PairUri) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>()
    };
    let mut l = format!(
        "pithagoras-sync://pair?portal={}&code={}",
        enc(&u.portal.to_string()),
        enc(&u.code)
    );
    if let Some(p) = &u.spki {
        l.push_str(&format!("&spki={}", enc(p)));
    }
    l
}

/// Waits for the link, then says how things stand.
async fn after(d: &dyn Dialogs, h: &impl Host) -> Outcome {
    let log = shown(&h.log_place());
    match h.wait_for_link().await {
        Link::Connected(portal) => d.info(&format!(
            "Pithagoras Sync is running, connected to {}, and starts at login.\n\nLog: {log}",
            shown(&portal)
        )),
        Link::Down(why) => d.info(&format!(
            "Installed, not connected yet: {}\n\nLog: {log}",
            shown(&why)
        )),
    }
    Outcome::Done
}

async fn menu(d: &dyn Dialogs, h: &impl Host) -> Outcome {
    loop {
        let text = format!(
            "Pithagoras Sync is installed and paired with {}.",
            shown(&h.paired().unwrap_or_default())
        );
        match d.menu(&text, MENU) {
            None | Some("quit") => return Outcome::Done,
            Some("status") => {
                // Every portal value in it is escaped already (`status_text`).
                let s = h.status().await;
                d.info(&s);
            }
            Some("pair") => {
                if ask_and_pair(d, h).await == Outcome::Failed {
                    continue;
                }
            }
            Some("log") => {
                if let Err(e) = h.open_log() {
                    d.error(&format!(
                        "Cannot open the log: {}\n\nIt is here: {}",
                        shown(&e),
                        shown(&h.log_place())
                    ));
                }
            }
            Some("uninstall") => return uninstall(d, h).await,
            Some(_) => return Outcome::Done,
        }
    }
}

async fn uninstall(d: &dyn Dialogs, h: &impl Host) -> Outcome {
    if !d.question(
        "Uninstall Pithagoras Sync? The client stops and no longer starts at login, and pairing links no longer open it.",
    ) {
        return Outcome::Cancelled;
    }
    let purge = d.question(
        "Also remove the pairing and all settings?\n\nYes: the pairing, the settings with their folders, the logs and everything else the client keeps go (remove the device in the portal as well). No: they stay for a later install.",
    );
    if let Err(e) = h.owner_check().await {
        d.error(&shown(&e));
        return Outcome::Failed;
    }
    match h.uninstall(purge).await {
        Ok(said) => {
            d.info(&said);
            Outcome::Done
        }
        Err(e) => {
            d.error(&format!("Uninstalling failed: {}", shown(&e)));
            Outcome::Failed
        }
    }
}

/// The system as the commands change it.
pub struct RealHost {
    pub dirs: Dirs,
}

impl RealHost {
    fn config(&self) -> Option<sync_policy::DeviceConfig> {
        crate::cli::load_config(&self.dirs).ok()
    }
}

impl Host for RealHost {
    fn installed(&self) -> bool {
        if cfg!(windows) {
            use crate::actions::Runner;
            return crate::actions::System
                .try_run(&crate::actions::argv(&[
                    "schtasks",
                    "/Query",
                    "/TN",
                    crate::install::TASK_NAME,
                ]))
                .is_ok();
        }
        sync_ops::info::home().is_some_and(|h| {
            h.join(".config/systemd/user")
                .join(crate::install::UNIT_NAME)
                .is_file()
        })
    }

    fn paired(&self) -> Option<String> {
        self.config()?.portal.map(|p| p.url)
    }

    fn device_name(&self) -> String {
        self.config()
            .and_then(|c| c.portal)
            .map(|p| p.name)
            .unwrap_or_else(
                || sync_connector::pair::name_from_hostname(&sync_ops::info::hostname()),
            )
    }

    fn install_target(&self) -> (String, String) {
        let user = sync_ops::info::user().0;
        let path = if cfg!(windows) {
            std::env::var("LOCALAPPDATA")
                .map(|l| {
                    format!(
                        r"{}\Programs\pithagoras-sync\pithagoras-sync.exe",
                        l.trim_end_matches('\\')
                    )
                })
                .unwrap_or_else(|_| "your programs folder".into())
        } else {
            sync_ops::info::home()
                .map(|h| h.join(".local/bin/pithagoras-sync").display().to_string())
                .unwrap_or_else(|| "~/.local/bin/pithagoras-sync".into())
        };
        (user, path)
    }

    fn log_place(&self) -> String {
        let file = crate::cli::log_file(&self.dirs);
        if cfg!(windows) || file.exists() {
            file.display().to_string()
        } else {
            format!(
                "the journal (journalctl --user -u {})",
                crate::install::UNIT_NAME
            )
        }
    }

    async fn owner_check(&self) -> Result<(), String> {
        crate::owner::not_from_own_command(&self.dirs).await
    }

    async fn install(&self) -> Result<Vec<String>, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let plan = crate::cli::install_plan(false, None, true, &exe)?;
        crate::actions::apply(&plan, std::path::Path::new("/"), &crate::actions::System)
    }

    async fn pair(&self, link: &str) -> Result<Vec<String>, String> {
        let cfg = crate::cli::load_config(&self.dirs)?;
        crate::cli::pair_device(&self.dirs, cfg, link, None)
            .await
            .map(|p| p.notes)
    }

    async fn wait_for_link(&self) -> Link {
        use crate::control::{self, Request};
        use sync_connector::LinkState;
        let deadline = tokio::time::Instant::now() + LINK_WAIT;
        let mut last = "the client is not running".to_string();
        loop {
            if let Ok(Some(r)) = control::send(&self.dirs.socket(), Request::Status).await
                && let Some(s) = r.status
            {
                if s.link.state == LinkState::Connected {
                    return Link::Connected(s.portal.unwrap_or_default());
                }
                last = s
                    .link
                    .detail
                    .unwrap_or_else(|| format!("{:?}", s.link.state).to_lowercase());
            }
            if tokio::time::Instant::now() >= deadline {
                return Link::Down(last);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn status(&self) -> String {
        crate::cli::status_report(&self.dirs).await
    }

    fn open_log(&self) -> Result<(), String> {
        let file = self.log_to_open()?;
        let (prog, args): (&str, Vec<std::ffi::OsString>) = if cfg!(windows) {
            ("notepad.exe", vec![file.into_os_string()])
        } else {
            ("xdg-open", vec![file.into_os_string()])
        };
        std::process::Command::new(prog)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("{prog}: {e}"))
    }

    async fn uninstall(&self, purge: bool) -> Result<String, String> {
        let program = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        if purge {
            crate::cli::purge(&self.dirs, false, false, true).await?;
            Ok(format!(
                "Pithagoras Sync is uninstalled, and its pairing and settings are removed. Remove the device in the portal as well (Settings, Devices).\n\nThe program itself stays: {program}. Delete it when you no longer need it."
            ))
        } else {
            let plan = crate::cli::uninstall_plan(false)?;
            crate::actions::apply(&plan, std::path::Path::new("/"), &crate::actions::System)?;
            Ok(format!(
                "Pithagoras Sync is uninstalled. Its pairing and settings stay for a later install.\n\nThe program itself stays: {program}."
            ))
        }
    }
}

impl RealHost {
    /// The log file to open: `client.log` where the client writes one (Windows,
    /// or a client started with `run --detach`), else the unit's journal saved
    /// to `journal.log` beside it, since a text editor cannot open the journal.
    fn log_to_open(&self) -> Result<PathBuf, String> {
        let file = crate::cli::log_file(&self.dirs);
        if cfg!(windows) || file.exists() {
            return Ok(file);
        }
        let out = std::process::Command::new("journalctl")
            .args([
                "--user",
                "-u",
                crate::install::UNIT_NAME,
                "-n",
                "500",
                "--no-pager",
            ])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("journalctl: {e}"))?;
        let saved = self.dirs.state.join("journal.log");
        sync_policy::config::write_private(&saved, &out.stdout)
            .map_err(|e| format!("{}: {e}", saved.display()))?;
        Ok(saved)
    }
}

/// When no dialog can be shown: the message goes to stderr, the client's log
/// file and, where a session bus is, a desktop notification.
pub async fn say_without_dialogs(dirs: &Dirs, text: &str) {
    eprintln!("pithagoras-sync: {text}");
    if let Ok(mut f) =
        crate::logfile::LogFile::open(crate::cli::log_file(dirs), crate::logfile::MAX_BYTES)
    {
        f.write_event(format!("gui: {}\n", sync_policy::approve::visible(text)).as_bytes());
    }
    #[cfg(unix)]
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            sync_policy::notify::show("Pithagoras Sync", text),
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialogs::Fake;
    use std::sync::Mutex;

    const LINK: &str = "pithagoras-sync://pair?portal=https%3A%2F%2Fportal.example&code=AB12CD34";

    #[derive(Default)]
    struct FakeHost {
        installed: Mutex<bool>,
        paired: Mutex<Option<String>>,
        /// Started by one of the client's own commands.
        own_command: bool,
        fail: Option<&'static str>,
        link_down: bool,
        did: Mutex<Vec<String>>,
    }

    impl FakeHost {
        fn did(&self) -> Vec<String> {
            self.did.lock().unwrap().clone()
        }

        fn step(&self, s: &str) -> Result<(), String> {
            self.did.lock().unwrap().push(s.to_string());
            match self.fail {
                Some(f) if s.starts_with(f) => Err(format!("{f} broke\x1b[2K")),
                _ => Ok(()),
            }
        }
    }

    impl Host for FakeHost {
        fn installed(&self) -> bool {
            *self.installed.lock().unwrap()
        }
        fn paired(&self) -> Option<String> {
            self.paired.lock().unwrap().clone()
        }
        fn device_name(&self) -> String {
            "laptop".into()
        }
        fn install_target(&self) -> (String, String) {
            (
                "alice".into(),
                "/home/alice/.local/bin/pithagoras-sync".into(),
            )
        }
        fn log_place(&self) -> String {
            "the journal".into()
        }
        async fn owner_check(&self) -> Result<(), String> {
            if self.own_command {
                return Err(
                    "policy changes cannot come from commands the client runs for the portal"
                        .into(),
                );
            }
            Ok(())
        }
        async fn install(&self) -> Result<Vec<String>, String> {
            self.step("install")?;
            *self.installed.lock().unwrap() = true;
            Ok(Vec::new())
        }
        async fn pair(&self, link: &str) -> Result<Vec<String>, String> {
            self.step(&format!("pair {link}"))?;
            let u = PairUri::parse(link).unwrap();
            *self.paired.lock().unwrap() = Some(u.portal.to_string());
            Ok(Vec::new())
        }
        async fn wait_for_link(&self) -> Link {
            if self.link_down {
                Link::Down("connecting: refused (401)".into())
            } else {
                Link::Connected(self.paired().unwrap_or_default())
            }
        }
        async fn status(&self) -> String {
            "Portal:    https://portal.example as laptop\n".into()
        }
        fn open_log(&self) -> Result<(), String> {
            self.step("log")
        }
        async fn uninstall(&self, purge: bool) -> Result<String, String> {
            self.step(if purge { "purge" } else { "uninstall" })?;
            *self.installed.lock().unwrap() = false;
            if purge {
                *self.paired.lock().unwrap() = None;
            }
            Ok("Uninstalled.".into())
        }
    }

    fn installed() -> FakeHost {
        FakeHost {
            installed: Mutex::new(true),
            ..FakeHost::default()
        }
    }

    fn paired() -> FakeHost {
        FakeHost {
            installed: Mutex::new(true),
            paired: Mutex::new(Some("https://old.example".into())),
            ..FakeHost::default()
        }
    }

    async fn run(h: &FakeHost, answers: &[&str], link: Option<&str>) -> (Outcome, Vec<String>) {
        let d = Fake::with(answers);
        let o = flow(&d, h, link).await;
        (o, d.seen())
    }

    #[tokio::test]
    async fn not_installed_installs_then_asks_for_the_link_and_pairs() {
        let h = FakeHost::default();
        let (o, seen) = run(&h, &["yes", &format!("text:{LINK}"), "yes"], None).await;
        assert_eq!(o, Outcome::Done);
        assert!(
            seen[0].starts_with("question: Install Pithagoras Sync for alice?"),
            "{seen:?}"
        );
        assert!(seen[0].contains("/home/alice/.local/bin/pithagoras-sync"));
        assert!(
            seen[1].starts_with("entry: Paste the pairing link"),
            "{seen:?}"
        );
        // The confirmation shows what was parsed.
        assert!(
            seen[2].contains("Pithagoras portal https://portal.example as \"laptop\"?"),
            "{seen:?}"
        );
        assert!(
            seen[3].starts_with(
                "info: Pithagoras Sync is running, connected to https://portal.example"
            ),
            "{seen:?}"
        );
        assert!(seen[3].contains("Log: the journal"));
        assert_eq!(h.did()[0], "install");
        assert!(h.did()[1].starts_with(
            "pair pithagoras-sync://pair?portal=https%3A%2F%2Fportal.example&code=AB12CD34"
        ));
    }

    #[tokio::test]
    async fn every_no_or_cancel_changes_nothing() {
        // No to the install.
        let h = FakeHost::default();
        assert_eq!(run(&h, &["no"], None).await.0, Outcome::Cancelled);
        assert!(h.did().is_empty());
        // The install, then cancel at the link.
        let h = FakeHost::default();
        assert_eq!(
            run(&h, &["yes", "cancel"], None).await.0,
            Outcome::Cancelled
        );
        assert_eq!(h.did(), ["install"]);
        // No to the pairing.
        let h = installed();
        assert_eq!(
            run(&h, &[&format!("text:{LINK}"), "no"], None).await.0,
            Outcome::Cancelled
        );
        assert!(h.did().is_empty());
        // A link from the OS, refused.
        let h = installed();
        assert_eq!(run(&h, &["no"], Some(LINK)).await.0, Outcome::Cancelled);
        assert!(h.did().is_empty());
        // The menu closed.
        let h = paired();
        assert_eq!(run(&h, &["cancel"], None).await.0, Outcome::Done);
        assert_eq!(run(&h, &["pick:quit"], None).await.0, Outcome::Done);
        assert!(h.did().is_empty());
        // Uninstall, then no; and "pair again" cancelled at the link.
        let h = paired();
        let (o, _) = run(&h, &["pick:uninstall", "no"], None).await;
        assert_eq!(o, Outcome::Cancelled);
        let (_, seen) = run(&h, &["pick:pair", "cancel", "pick:quit"], None).await;
        assert!(seen[1].starts_with("entry:"), "{seen:?}");
        assert!(h.did().is_empty());
    }

    #[tokio::test]
    async fn a_link_that_does_not_parse_is_asked_for_again_and_never_used() {
        let h = installed();
        let (o, seen) = run(
            &h,
            &[
                "text:https://portal.example",
                "text:pithagoras-sync://pair?portal=http://192.168.1.5:3000&code=AB",
                &format!("text:{LINK}&mode=full"),
                "cancel",
            ],
            None,
        )
        .await;
        assert_eq!(o, Outcome::Cancelled);
        assert!(h.did().is_empty());
        let errors: Vec<&String> = seen.iter().filter(|s| s.starts_with("error:")).collect();
        assert_eq!(errors.len(), 3, "{seen:?}");
        assert!(errors[1].contains("over plain http"), "{seen:?}");
        assert!(errors[2].contains("unknown key"), "{seen:?}");
        // A portal on this computer may use plain http.
        let h = installed();
        let local = "pithagoras-sync://pair?portal=http://127.0.0.1:3000&code=AB";
        let (o, _) = run(&h, &["yes"], Some(local)).await;
        assert_eq!(o, Outcome::Done);
    }

    #[tokio::test]
    async fn a_hostile_link_from_the_os_is_refused_before_anything_happens() {
        for bad in [
            "https://portal.example/pair?code=AB".to_string(),
            "pithagoras-sync://pair?portal=https://x.example&code=A%0aB".to_string(),
            format!("{LINK}&code=CD"),
            format!("{LINK}{}", "A".repeat(MAX_ANSWER)),
            "pithagoras-sync://pair?portal=https://x.example%1b[2K&code=AB".to_string(),
        ] {
            // Not installed: no question about installing comes first.
            let h = FakeHost::default();
            let (o, seen) = run(&h, &["yes", "yes"], Some(&bad)).await;
            assert_eq!(o, Outcome::Failed, "{bad}");
            assert_eq!(seen.len(), 1, "{seen:?}");
            assert!(seen[0].starts_with("error: "), "{seen:?}");
            assert!(
                !seen[0].chars().any(|c| c.is_control() && c != '\n'),
                "{seen:?}"
            );
            assert!(h.did().is_empty());
        }
    }

    #[tokio::test]
    async fn the_confirmation_shows_parsed_values_with_control_characters_escaped() {
        let h = installed();
        // A base path with an escape sequence and a line break in it.
        let link = "pithagoras-sync://pair?portal=https%3A%2F%2Fportal.example%2Fa%1b%5B2K%0aPaired&code=AB12";
        let (o, seen) = run(&h, &["no"], Some(link)).await;
        assert_eq!(o, Outcome::Cancelled);
        let q = &seen[0];
        assert!(
            q.contains("https://portal.example/a\\u{1b}[2K\\nPaired"),
            "{q}"
        );
        assert!(
            !q.contains("pithagoras-sync://"),
            "the raw link is not shown: {q}"
        );
    }

    #[tokio::test]
    async fn a_paired_device_asks_before_replacing_the_pairing() {
        let h = paired();
        let (o, seen) = run(&h, &["yes"], Some(LINK)).await;
        assert_eq!(o, Outcome::Done);
        assert!(
            seen[0].starts_with("question: This computer is paired with https://old.example."),
            "{seen:?}"
        );
        assert!(seen[0].contains("Replace the pairing with the portal https://portal.example"));
        assert_eq!(h.paired().as_deref(), Some("https://portal.example"));
    }

    #[tokio::test]
    async fn the_menu_shows_status_opens_the_log_pairs_again_and_uninstalls() {
        let h = paired();
        let (o, seen) = run(
            &h,
            &[
                "pick:status",
                "pick:log",
                "pick:pair",
                &format!("text:{LINK}"),
                "yes",
                "pick:uninstall",
                "yes",
                "no",
            ],
            None,
        )
        .await;
        assert_eq!(o, Outcome::Done);
        assert!(seen[0].starts_with(
            "menu: Pithagoras Sync is installed and paired with https://old.example."
        ));
        assert!(seen[1].starts_with("info: Portal:"), "{seen:?}");
        assert_eq!(h.did()[0], "log");
        assert!(h.did()[1].starts_with("pair "));
        assert_eq!(h.did()[2], "uninstall");
        assert!(
            seen.last().unwrap().starts_with("info: Uninstalled."),
            "{seen:?}"
        );
        // Yes to "also remove the pairing" purges.
        let h = paired();
        run(&h, &["pick:uninstall", "yes", "yes"], None).await;
        assert_eq!(h.did(), ["purge"]);
    }

    #[tokio::test]
    async fn not_connected_after_pairing_says_why() {
        let h = FakeHost {
            link_down: true,
            ..installed()
        };
        let (o, seen) = run(&h, &["yes"], Some(LINK)).await;
        assert_eq!(o, Outcome::Done);
        assert!(
            seen[1].starts_with("info: Installed, not connected yet: connecting: refused (401)"),
            "{seen:?}"
        );
    }

    #[tokio::test]
    async fn a_failing_step_is_shown_escaped() {
        let h = FakeHost {
            fail: Some("pair"),
            ..installed()
        };
        let (o, seen) = run(&h, &["yes"], Some(LINK)).await;
        assert_eq!(o, Outcome::Failed);
        let e = seen.last().unwrap();
        assert!(
            e.starts_with("error: Pairing failed: pair broke\\u{1b}[2K"),
            "{e}"
        );
        let h = FakeHost {
            fail: Some("install"),
            ..FakeHost::default()
        };
        let (o, seen) = run(&h, &["yes"], Some(LINK)).await;
        assert_eq!(o, Outcome::Failed);
        assert!(seen.last().unwrap().starts_with("error: Installing failed"));
        assert!(h.paired().is_none());
    }

    #[tokio::test]
    async fn every_change_is_refused_from_the_clients_own_commands() {
        let own = |h: FakeHost| FakeHost {
            own_command: true,
            ..h
        };
        let h = own(FakeHost::default());
        let (o, seen) = run(&h, &["yes"], None).await;
        assert_eq!(o, Outcome::Failed);
        assert!(
            seen.last()
                .unwrap()
                .contains("cannot come from commands the client runs")
        );
        let h = own(installed());
        assert_eq!(run(&h, &["yes"], Some(LINK)).await.0, Outcome::Failed);
        let h = own(paired());
        assert_eq!(
            run(&h, &["pick:uninstall", "yes", "yes"], None).await.0,
            Outcome::Failed
        );
        let h = own(paired());
        run(
            &h,
            &["pick:pair", &format!("text:{LINK}"), "yes", "pick:quit"],
            None,
        )
        .await;
        assert!(h.did().is_empty(), "{:?}", h.did());
        assert_eq!(h.paired().as_deref(), Some("https://old.example"));
    }

    #[test]
    fn the_link_acted_on_is_rebuilt_from_the_parsed_one() {
        let u = PairUri::parse(&format!("{LINK}&spki={}", "A".repeat(43))).unwrap();
        let again = PairUri::parse(&link_of(&u)).unwrap();
        assert_eq!(again, u);
        let u = PairUri::parse("pithagoras-sync://pair?portal=http://127.0.0.1:3000/a%20b&code=x1")
            .unwrap();
        assert_eq!(PairUri::parse(&link_of(&u)).unwrap(), u);
    }
}
