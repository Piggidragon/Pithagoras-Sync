//! `gui`: install, pair and uninstall without a terminal, and set up sudo
//! access. One flow, driven by the state it finds (not installed, installed but
//! not paired, paired) and the owner's answers in the OS's own dialogs
//! (`dialogs`), in the desktop's language (`i18n`). What it does to the system
//! goes through `Host`, the same code the commands run, so the tests drive the
//! flow with fake dialogs and a fake host.
//!
//! A pairing link comes from a web page and is untrusted: it is parsed strictly,
//! shown as what was parsed (never the raw link) and acted on only after the
//! owner said yes. Every step that changes something is refused, as the command
//! line refuses it, when the flow was started by a command the client runs for
//! the portal.
//!
//! The sudo password is typed into a dialog that does not show it and checked
//! with sudo before anything is stored. That check is also what proves the owner
//! switches sudo access on, as the `su` password check does in a terminal: a
//! command of the agent that clicks through the windows does not know it.

use std::path::PathBuf;
use std::time::Duration;

use sync_connector::LinkState;
use sync_connector::url::PairUri;
use sync_policy::secret::Secret;
use sync_policy::{Dirs, Mode};
use sync_proto::methods::FolderInfo;

use crate::cli::Kept;
use crate::dialogs::{Dialogs, MAX_ANSWER, shown};
use crate::i18n::Lang;
use crate::secrets::SudoCheck;

/// How long the flow waits for a new pairing to connect.
pub const LINK_WAIT: Duration = Duration::from_secs(10);

/// Whether the link came up after pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    Connected(String),
    /// Not connected (yet): the link's state, `None` when the client does not
    /// run, and its detail.
    Down(Option<LinkState>, Option<String>),
}

/// Where the client's log is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogPlace {
    File(String),
    /// The journal of this systemd user unit.
    Journal(&'static str),
}

/// What the menu's Status shows. Text in it is escaped (`shown`).
#[derive(Debug, Clone, PartialEq)]
pub struct StatusView {
    /// The running client's link state and detail; `None` when it does not run.
    pub link: Option<(LinkState, Option<String>)>,
    /// The portal's URL and this device's name there.
    pub portal: Option<(String, String)>,
    pub paused: bool,
    pub mode: Mode,
    /// Full mode: how long until it falls back to ask, `None` for never.
    pub full_left_ms: Option<i64>,
    pub folders: Vec<FolderInfo>,
    pub approvals_waiting: usize,
    /// Whether sudo access is on, where there is sudo access to set up.
    pub sudo: Option<bool>,
    /// The settings could not be read.
    pub problem: Option<String>,
}

/// The mode the portal's agent gets right after pairing: this computer's
/// now, which pairing keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairMode {
    pub mode: Mode,
    /// Full mode: how long until it falls back to ask, `None` for never.
    pub full_left_ms: Option<i64>,
    pub folders: usize,
}

/// Sudo access and its password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SudoState {
    pub active: bool,
    pub password: bool,
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
    /// Who installs (the user) and where the program goes, when known.
    fn install_target(&self) -> (String, Option<String>);
    /// The account whose password `su` and sudo check.
    fn account(&self) -> String;
    /// Where the client's log is.
    fn log_place(&self) -> LogPlace;
    /// The mode pairing would leave the agent in.
    fn pair_mode(&self) -> PairMode;
    /// Refuses when the flow runs as a command the client runs for the portal.
    async fn owner_check(&self) -> Result<(), String>;
    /// Whether pairing asks for the user's password (a Linux desktop), as
    /// `pair` does in a terminal.
    fn owner_password_needed(&self) -> bool;
    /// Checks the user's password with `su`; `Ok(false)` when it refused it.
    async fn owner_password(&self, pw: &Secret) -> Result<bool, String>;
    /// `install`; returns its notes.
    async fn install(&self) -> Result<Vec<String>, String>;
    /// `pair <link>`; returns its notes.
    async fn pair(&self, link: &str) -> Result<Vec<String>, String>;
    /// Waits up to `LINK_WAIT` for the client to connect.
    async fn wait_for_link(&self) -> Link;
    /// What `status` reports.
    async fn status(&self) -> StatusView;
    fn open_log(&self) -> Result<(), String>;
    /// `uninstall`, or `uninstall --purge`; returns the program, which stays,
    /// and the notes of its steps.
    async fn uninstall(&self, purge: bool) -> Result<(String, Vec<String>), String>;
    /// Whether sudo access can be set up here (Linux, not as root).
    fn sudo_available(&self) -> bool;
    /// As `sudo status` finds it.
    async fn sudo_state(&self) -> Result<SudoState, String>;
    /// Checks the password with sudo.
    async fn sudo_check(&self, pw: &Secret) -> Result<SudoCheck, String>;
    /// `sudo set` without the prompt: to the running client or the storage.
    async fn keep_password(&self, pw: Secret) -> Result<Kept, String>;
    /// `sudo activate` or `sudo deactivate`, without their checks.
    async fn switch_sudo(&self, on: bool) -> Result<(), String>;
    /// `sudo clear`, without its questions.
    async fn forget_password(&self) -> Result<(), String>;
}

/// Parses a link as `pair` would; the error as a dialog shows it. A plain-http
/// portal is taken only on this computer (`localhost` or a loopback address):
/// the connection would refuse anything else after the owner said yes, and the
/// question would have asked about a portal that cannot be reached.
fn parse(t: Lang, link: &str) -> Result<PairUri, String> {
    if link.len() > MAX_ANSWER {
        return Err(t.link_too_long().into());
    }
    let u = PairUri::parse(link).map_err(|e| t.link_unusable(&shown(&e)))?;
    let host = &u.portal.host;
    let local = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback());
    if !u.portal.tls && !local {
        return Err(t.link_plain_http(&shown(&u.portal.to_string())));
    }
    Ok(u)
}

/// The owner check, with its refusal shown.
async fn owner_ok(d: &dyn Dialogs, h: &impl Host, t: Lang) -> bool {
    match h.owner_check().await {
        Ok(()) => true,
        Err(_) => {
            d.error(t.own_command());
            false
        }
    }
}

/// Runs the flow. `link` is the pairing link the OS started the program with.
pub async fn flow(d: &dyn Dialogs, h: &impl Host, t: Lang, link: Option<&str>) -> Outcome {
    // A command of the client's own gets no further than this, so it cannot
    // put questions on the owner's screen either. Each step checks again.
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    // A link is checked before anything else happens, the install included.
    let link = match link.map(|l| parse(t, l)) {
        None => None,
        Some(Ok(u)) => Some(u),
        Some(Err(e)) => {
            d.error(&e);
            return Outcome::Failed;
        }
    };
    if !h.installed() {
        let (user, path) = h.install_target();
        let q = t.install_question(&shown(&user), path.map(|p| shown(&p)).as_deref());
        if !d.question(&q) {
            return Outcome::Cancelled;
        }
        if !owner_ok(d, h, t).await {
            return Outcome::Failed;
        }
        match h.install().await {
            Ok(notes) if !notes.is_empty() => {
                let notes: Vec<String> = notes.iter().map(|n| shown(n)).collect();
                d.info(&t.notes(&notes));
            }
            Ok(_) => {}
            Err(e) => {
                d.error(&t.install_failed(&shown(&e)));
                return Outcome::Failed;
            }
        }
        if link.is_none() && h.paired().is_some() {
            return after(d, h, t, &[]).await;
        }
    }
    if let Some(u) = link {
        return pair(d, h, t, &u).await;
    }
    if h.paired().is_none() {
        return ask_and_pair(d, h, t).await;
    }
    menu(d, h, t).await
}

/// Asks for the link until one parses or the owner cancels, then pairs.
async fn ask_and_pair(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Outcome {
    loop {
        let Some(text) = d.entry(t.entry_text()) else {
            return Outcome::Cancelled;
        };
        match parse(t, text.trim()) {
            Ok(u) => return pair(d, h, t, &u).await,
            Err(e) => d.error(&e),
        }
    }
}

/// Confirms with the parsed values and the mode the agent gets, checks the
/// owner's password where `pair` would, then pairs as `pair` does.
async fn pair(d: &dyn Dialogs, h: &impl Host, t: Lang, uri: &PairUri) -> Outcome {
    let portal = shown(&uri.portal.to_string());
    let name = shown(&h.device_name());
    let pinned = uri.spki.is_some();
    let mode = h.pair_mode();
    let q = match h.paired() {
        Some(old) => t.replace_question(&shown(&old), &portal, &name, pinned, mode),
        None => t.pair_question(&portal, &name, pinned, mode),
    };
    if !d.question(&q) {
        return Outcome::Cancelled;
    }
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    if h.owner_password_needed() {
        match owner_password(d, h, t).await {
            Outcome::Done => {}
            other => return other,
        }
    }
    // Rebuilt from what was parsed and shown, so only that is acted on.
    let link = link_of(uri);
    match h.pair(&link).await {
        Ok(notes) => after(d, h, t, &notes).await,
        Err(e) => {
            d.error(&t.pair_failed(&shown(&e)));
            Outcome::Failed
        }
    }
}

/// The user's password, checked with `su`: on a desktop the command line asks
/// for it in a terminal before `pair`, and a command of the agent that clicks
/// through the windows does not know it.
async fn owner_password(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Outcome {
    let Some(pw) = d.password(&t.owner_password_prompt(&shown(&h.account()))) else {
        return Outcome::Cancelled;
    };
    if pw.expose().is_empty() {
        d.error(t.password_empty());
        return Outcome::Failed;
    }
    match h.owner_password(&pw).await {
        Ok(true) => Outcome::Done,
        Ok(false) => {
            d.error(t.owner_password_wrong());
            Outcome::Failed
        }
        Err(e) => {
            d.error(&t.owner_password_failed(&shown(&e)));
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

/// Waits for the link, then says how things stand, with the notes of `pair`
/// (the token in a file where the keyring did not take it).
async fn after(d: &dyn Dialogs, h: &impl Host, t: Lang, notes: &[String]) -> Outcome {
    let log = shown(&t.log_place(&h.log_place()));
    let mut text = match h.wait_for_link().await {
        Link::Connected(portal) => t.connected(&shown(&portal), &log),
        Link::Down(state, detail) => {
            let why = t.link_state(state, detail.map(|d| shown(&d)).as_deref());
            t.not_connected(&why, &log)
        }
    };
    if !notes.is_empty() {
        let notes: Vec<String> = notes.iter().map(|n| shown(n)).collect();
        text = format!("{text}\n\n{}", t.notes(&notes));
    }
    d.info(&text);
    Outcome::Done
}

async fn menu(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Outcome {
    let mut keys = vec!["status", "pair"];
    if h.sudo_available() {
        keys.push("sudo");
    }
    keys.extend(["log", "uninstall", "quit"]);
    let items: Vec<(&'static str, &str)> = keys.iter().map(|k| (*k, t.label(k))).collect();
    loop {
        let text = t.menu_text(&shown(&h.paired().unwrap_or_default()));
        match d.menu(&text, &items) {
            None | Some("quit") => return Outcome::Done,
            Some("status") => {
                // Every value in it is escaped already.
                let s = h.status().await;
                d.info(&t.status(&s));
            }
            Some("pair") => {
                ask_and_pair(d, h, t).await;
            }
            Some("sudo") => {
                sudo_menu(d, h, t).await;
            }
            Some("log") => {
                if let Err(e) = h.open_log() {
                    let place = t.log_place(&h.log_place());
                    d.error(&t.log_open_failed(&shown(&e), &shown(&place)));
                }
            }
            Some("uninstall") => return uninstall(d, h, t).await,
            Some(_) => return Outcome::Done,
        }
    }
}

/// Sudo access: the password (set or forget it) and switching it off. It is
/// switched on only right after the password was checked (`set_password`).
async fn sudo_menu(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Outcome {
    loop {
        let st = match h.sudo_state().await {
            Ok(s) => s,
            Err(e) => {
                d.error(&t.sudo_failed(&shown(&e)));
                return Outcome::Failed;
            }
        };
        let mut keys = vec!["set"];
        if st.active {
            keys.push("off");
        }
        if st.password {
            keys.push("forget");
        }
        keys.push("back");
        let items: Vec<(&'static str, &str)> = keys.iter().map(|k| (*k, t.label(k))).collect();
        match d.menu(&t.sudo_text(st), &items) {
            Some("set") => {
                set_password(d, h, t).await;
            }
            Some("off") => {
                if owner_ok(d, h, t).await {
                    switch_sudo(d, h, t, false).await;
                }
            }
            Some("forget") => {
                forget_password(d, h, t, st).await;
            }
            _ => return Outcome::Done,
        }
    }
}

/// Switches sudo access and says so.
async fn switch_sudo(d: &dyn Dialogs, h: &impl Host, t: Lang, on: bool) -> Outcome {
    match h.switch_sudo(on).await {
        Ok(()) => {
            d.info(t.sudo_now(on));
            Outcome::Done
        }
        Err(e) => {
            d.error(&t.sudo_failed(&shown(&e)));
            Outcome::Failed
        }
    }
}

/// `sudo set`: the password, checked with sudo, then kept; then the offer to
/// switch sudo access on. A password sudo did not take is never stored.
async fn set_password(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Outcome {
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    let Some(pw) = d.password(&t.password_prompt(&shown(&h.account()))) else {
        return Outcome::Cancelled;
    };
    if pw.expose().is_empty() {
        d.error(t.password_empty());
        return Outcome::Failed;
    }
    if crate::secrets::check(pw.expose()).is_err() {
        d.error(&t.password_not_one_line(crate::secrets::MAX_LEN));
        return Outcome::Failed;
    }
    match h.sudo_check(&pw).await {
        Ok(SudoCheck::Accepted) => {}
        Ok(SudoCheck::NoPasswordNeeded) => {
            d.info(t.sudo_needs_no_password());
            return Outcome::Cancelled;
        }
        Ok(SudoCheck::Refused(why)) => {
            d.error(&t.sudo_refused(&shown(&why)));
            return Outcome::Failed;
        }
        Err(e) => {
            d.error(&t.sudo_check_failed(&shown(&e)));
            return Outcome::Failed;
        }
    }
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    let kept = match h.keep_password(pw).await {
        Ok(Kept::Nowhere) => {
            d.error(t.not_kept());
            return Outcome::Failed;
        }
        Ok(k) => k,
        Err(e) => {
            d.error(&t.store_failed(&shown(&e)));
            return Outcome::Failed;
        }
    };
    // Read again: the dialogs may have waited a long time.
    if h.sudo_state().await.is_ok_and(|s| s.active) {
        d.info(&format!("{}\n\n{}", t.kept(kept), t.sudo_now(true)));
        return Outcome::Done;
    }
    if !d.question(&t.activate_question(kept)) {
        return Outcome::Done;
    }
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    switch_sudo(d, h, t, true).await
}

/// `sudo clear`: forgets the password, then offers to switch sudo access off.
async fn forget_password(d: &dyn Dialogs, h: &impl Host, t: Lang, st: SudoState) -> Outcome {
    if !d.question(t.forget_question()) {
        return Outcome::Cancelled;
    }
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    if let Err(e) = h.forget_password().await {
        d.error(&t.sudo_failed(&shown(&e)));
        return Outcome::Failed;
    }
    if !st.active {
        d.info(t.forgotten());
        return Outcome::Done;
    }
    if d.question(&t.also_off_question()) && owner_ok(d, h, t).await {
        return switch_sudo(d, h, t, false).await;
    }
    Outcome::Done
}

async fn uninstall(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Outcome {
    if !d.question(t.uninstall_question()) {
        return Outcome::Cancelled;
    }
    let purge = d.question(t.purge_question());
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    match h.uninstall(purge).await {
        Ok((program, notes)) => {
            let mut text = t.uninstalled(purge, &shown(&program));
            if !notes.is_empty() {
                let notes: Vec<String> = notes.iter().map(|n| shown(n)).collect();
                text = format!("{text}\n\n{}", t.notes(&notes));
            }
            d.info(&text);
            Outcome::Done
        }
        Err(e) => {
            d.error(&t.uninstall_failed(&shown(&e)));
            Outcome::Failed
        }
    }
}

/// How the client is set up for this user on Linux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxInstall {
    /// The user unit `install` writes.
    User,
    /// No user unit, but the system unit (`install --system`, `setup`) runs
    /// the client as this user: installing a user unit next to it would start
    /// a second client for the same config.
    System,
    None,
}

fn linux_install(
    home: Option<&std::path::Path>,
    system_unit: &std::path::Path,
    me: &str,
) -> LinuxInstall {
    if home.is_some_and(|h| crate::install::user_unit_file(h).is_file()) {
        return LinuxInstall::User;
    }
    let runs_as_me = std::fs::read_to_string(system_unit)
        .ok()
        .and_then(|u| crate::install::unit_user(&u))
        .is_some_and(|u| u == me);
    if runs_as_me {
        LinuxInstall::System
    } else {
        LinuxInstall::None
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
            return crate::install::task_installed(&crate::actions::System);
        }
        match linux_install(
            sync_ops::info::home().as_deref(),
            &crate::update::system_unit_file(),
            &sync_ops::info::user().0,
        ) {
            LinuxInstall::User | LinuxInstall::System => true,
            LinuxInstall::None => false,
        }
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

    fn install_target(&self) -> (String, Option<String>) {
        let user = sync_ops::info::user().0;
        let path = if cfg!(windows) {
            std::env::var("LOCALAPPDATA")
                .ok()
                .map(|l| crate::install::windows_program(&l))
        } else {
            Some(
                sync_ops::info::home()
                    .map(|h| crate::install::user_program(&h).display().to_string())
                    .unwrap_or_else(|| format!("~/{}", crate::install::USER_PROGRAM)),
            )
        };
        (user, path)
    }

    fn account(&self) -> String {
        crate::owner::account().unwrap_or_else(|_| sync_ops::info::user().0)
    }

    fn log_place(&self) -> LogPlace {
        let file = crate::cli::log_file(&self.dirs);
        if cfg!(windows) || file.exists() {
            LogPlace::File(file.display().to_string())
        } else {
            LogPlace::Journal(crate::install::UNIT_NAME)
        }
    }

    fn pair_mode(&self) -> PairMode {
        let now = sync_policy::system_clock()();
        match self.config() {
            Some(c) => PairMode {
                mode: c.policy.effective_mode(c.profile, now),
                full_left_ms: c.policy.full.until_ms.map(|t| t - now),
                folders: c.policy.folders.len(),
            },
            // `pair` fails on a config it cannot read as well.
            None => PairMode {
                mode: Mode::Ask,
                full_left_ms: None,
                folders: 0,
            },
        }
    }

    async fn owner_check(&self) -> Result<(), String> {
        crate::owner::not_from_own_command(&self.dirs).await
    }

    fn owner_password_needed(&self) -> bool {
        // A config that cannot be read asks as well, where asking is possible.
        self.config()
            .map_or(cfg!(unix), |c| crate::owner::password_needed(c.profile))
    }

    async fn owner_password(&self, pw: &Secret) -> Result<bool, String> {
        crate::owner::check_password(pw).await
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
        let deadline = tokio::time::Instant::now() + LINK_WAIT;
        let mut last = (None, None);
        loop {
            if let Ok(Some(r)) = control::send(&self.dirs.socket(), Request::Status).await
                && let Some(s) = r.status
            {
                if s.link.state == LinkState::Connected {
                    return Link::Connected(s.portal.unwrap_or_default());
                }
                last = (Some(s.link.state), s.link.detail);
            }
            if tokio::time::Instant::now() >= deadline {
                return Link::Down(last.0, last.1);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn status(&self) -> StatusView {
        use crate::control::{self, Request};
        use sync_policy::config::Elevation;
        let now = sync_policy::system_clock()();
        let cfg = crate::cli::load_config(&self.dirs);
        let sudo = self.sudo_available().then(|| {
            cfg.as_ref()
                .is_ok_and(|c| c.policy.privilege.elevation == Elevation::Sudo)
        });
        let folder = |f: &FolderInfo| FolderInfo {
            path: shown(&f.path),
            ..f.clone()
        };
        if let Ok(Some(r)) = control::send(&self.dirs.socket(), Request::Status).await
            && let Some(s) = r.status
        {
            return StatusView {
                link: Some((s.link.state, s.link.detail.as_deref().map(shown))),
                portal: s.portal.zip(s.name).map(|(p, n)| (shown(&p), shown(&n))),
                paused: s.paused,
                mode: s.mode,
                full_left_ms: s.mode_expires_ms.map(|t| t - now),
                folders: s.folders.iter().map(folder).collect(),
                approvals_waiting: s.approvals_waiting,
                sudo,
                problem: None,
            };
        }
        match cfg {
            Ok(c) => StatusView {
                link: None,
                portal: c.portal.as_ref().map(|p| (shown(&p.url), shown(&p.name))),
                paused: false,
                mode: c.policy.effective_mode(c.profile, now),
                full_left_ms: c.policy.full.until_ms.map(|t| t - now),
                folders: c
                    .policy
                    .folders
                    .iter()
                    .map(|f| FolderInfo {
                        path: shown(&f.path.display().to_string()),
                        access: f.access,
                        execute: f.execute,
                    })
                    .collect(),
                approvals_waiting: 0,
                sudo,
                problem: None,
            },
            Err(e) => StatusView {
                link: None,
                portal: None,
                paused: false,
                mode: Mode::Ask,
                full_left_ms: None,
                folders: Vec::new(),
                approvals_waiting: 0,
                sudo,
                problem: Some(shown(&e)),
            },
        }
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

    async fn uninstall(&self, purge: bool) -> Result<(String, Vec<String>), String> {
        if cfg!(target_os = "linux")
            && linux_install(
                sync_ops::info::home().as_deref(),
                &crate::update::system_unit_file(),
                &sync_ops::info::user().0,
            ) == LinuxInstall::System
        {
            return Err(format!(
                "the client runs from the system unit {} (installed with `install --system` or `setup`), which only root can remove: sudo pithagoras-sync uninstall --system",
                crate::update::system_unit_file().display()
            ));
        }
        let program = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let notes = if purge {
            let mut hints = Vec::new();
            crate::cli::purge(&self.dirs, false, false, true, true, &mut hints).await?;
            hints
        } else {
            let plan = crate::cli::uninstall_plan(false)?;
            crate::actions::apply(&plan, std::path::Path::new("/"), &crate::actions::System)?
        };
        Ok((program, notes))
    }

    fn sudo_available(&self) -> bool {
        cfg!(target_os = "linux") && !crate::cli::is_root()
    }

    async fn sudo_state(&self) -> Result<SudoState, String> {
        use sync_policy::config::Elevation;
        let cfg = crate::cli::load_config(&self.dirs)?;
        let p = &cfg.policy.privilege;
        Ok(SudoState {
            active: p.elevation == Elevation::Sudo,
            password: crate::cli::sudo_password_set(&self.dirs, p.secret_storage).await?,
        })
    }

    async fn sudo_check(&self, pw: &Secret) -> Result<SudoCheck, String> {
        #[cfg(unix)]
        {
            let cfg = crate::cli::load_config(&self.dirs)?;
            crate::secrets::check_with_sudo(&cfg.policy.privilege.sudo_path, pw).await
        }
        #[cfg(not(unix))]
        {
            let _ = pw;
            Err("sudo access is Linux only".into())
        }
    }

    async fn keep_password(&self, pw: Secret) -> Result<Kept, String> {
        crate::cli::keep_password(&self.dirs, pw).await
    }

    async fn switch_sudo(&self, on: bool) -> Result<(), String> {
        use sync_policy::config::Elevation;
        let to = if on { Elevation::Sudo } else { Elevation::Off };
        crate::cli::switch_elevation(&self.dirs, to)
            .await
            .map(|_| ())
    }

    async fn forget_password(&self) -> Result<(), String> {
        crate::cli::forget_password(&self.dirs).await
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

/// When no dialog can be shown: the message goes to stderr, `gui.log` beside
/// the client's log and, where a session bus is, a desktop notification.
pub async fn say_without_dialogs(dirs: &Dirs, text: &str) {
    eprintln!("pithagoras-sync: {text}");
    if let Ok(mut f) =
        crate::logfile::LogFile::open(crate::cli::gui_log_file(dirs), crate::logfile::MAX_BYTES)
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

    struct FakeHost {
        installed: Mutex<bool>,
        paired: Mutex<Option<String>>,
        /// Started by one of the client's own commands.
        own_command: bool,
        /// The owner checks after this many pass fail (a client's command that
        /// took over meanwhile).
        own_from: Option<usize>,
        checks: Mutex<usize>,
        fail: Option<&'static str>,
        link_down: bool,
        sudo: bool,
        sudo_active: Mutex<bool>,
        /// The password the running client holds.
        password: Mutex<Option<String>>,
        /// What sudo says to a password other than "right pw".
        sudo_says: SudoCheck,
        kept: Kept,
        mode: PairMode,
        /// A Linux desktop: pairing asks for the password ("my login").
        desktop: bool,
        install_notes: Vec<String>,
        pair_notes: Vec<String>,
        uninstall_notes: Vec<String>,
        did: Mutex<Vec<String>>,
    }

    impl Default for FakeHost {
        fn default() -> FakeHost {
            FakeHost {
                installed: Mutex::new(false),
                paired: Mutex::new(None),
                own_command: false,
                own_from: None,
                checks: Mutex::new(0),
                fail: None,
                link_down: false,
                sudo: true,
                sudo_active: Mutex::new(false),
                password: Mutex::new(None),
                sudo_says: SudoCheck::Refused("sudo: 1 incorrect password attempt".into()),
                kept: Kept::InClient,
                mode: PairMode {
                    mode: Mode::Ask,
                    full_left_ms: None,
                    folders: 0,
                },
                desktop: false,
                install_notes: Vec::new(),
                pair_notes: Vec::new(),
                uninstall_notes: Vec::new(),
                did: Mutex::new(Vec::new()),
            }
        }
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
        fn install_target(&self) -> (String, Option<String>) {
            (
                "alice".into(),
                Some("/home/alice/.local/bin/pithagoras-sync".into()),
            )
        }
        fn account(&self) -> String {
            "alice".into()
        }
        fn log_place(&self) -> LogPlace {
            LogPlace::Journal("pithagoras-sync.service")
        }
        fn pair_mode(&self) -> PairMode {
            self.mode
        }
        fn owner_password_needed(&self) -> bool {
            self.desktop
        }
        async fn owner_password(&self, pw: &Secret) -> Result<bool, String> {
            self.step("owner password")?;
            Ok(pw.expose() == "my login")
        }
        async fn owner_check(&self) -> Result<(), String> {
            let mut n = self.checks.lock().unwrap();
            *n += 1;
            if self.own_command || self.own_from.is_some_and(|f| *n > f) {
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
            Ok(self.install_notes.clone())
        }
        async fn pair(&self, link: &str) -> Result<Vec<String>, String> {
            self.step(&format!("pair {link}"))?;
            let u = PairUri::parse(link).unwrap();
            *self.paired.lock().unwrap() = Some(u.portal.to_string());
            Ok(self.pair_notes.clone())
        }
        async fn wait_for_link(&self) -> Link {
            if self.link_down {
                Link::Down(Some(LinkState::Connecting), Some("refused (401)".into()))
            } else {
                Link::Connected(self.paired().unwrap_or_default())
            }
        }
        async fn status(&self) -> StatusView {
            StatusView {
                link: Some((LinkState::Connected, None)),
                portal: Some(("https://portal.example".into(), "laptop".into())),
                paused: false,
                mode: Mode::Ask,
                full_left_ms: None,
                folders: Vec::new(),
                approvals_waiting: 0,
                sudo: Some(*self.sudo_active.lock().unwrap()),
                problem: None,
            }
        }
        fn open_log(&self) -> Result<(), String> {
            self.step("log")
        }
        async fn uninstall(&self, purge: bool) -> Result<(String, Vec<String>), String> {
            self.step(if purge { "purge" } else { "uninstall" })?;
            *self.installed.lock().unwrap() = false;
            if purge {
                *self.paired.lock().unwrap() = None;
            }
            Ok((
                "/home/alice/.local/bin/pithagoras-sync".into(),
                self.uninstall_notes.clone(),
            ))
        }
        fn sudo_available(&self) -> bool {
            self.sudo
        }
        async fn sudo_state(&self) -> Result<SudoState, String> {
            Ok(SudoState {
                active: *self.sudo_active.lock().unwrap(),
                password: self.password.lock().unwrap().is_some(),
            })
        }
        async fn sudo_check(&self, pw: &Secret) -> Result<SudoCheck, String> {
            self.step("sudo check")?;
            Ok(if pw.expose() == "right pw" {
                SudoCheck::Accepted
            } else {
                self.sudo_says.clone()
            })
        }
        async fn keep_password(&self, pw: Secret) -> Result<Kept, String> {
            self.step("keep")?;
            if self.kept != Kept::Nowhere {
                *self.password.lock().unwrap() = Some(pw.expose().to_string());
            }
            Ok(self.kept)
        }
        async fn switch_sudo(&self, on: bool) -> Result<(), String> {
            self.step(if on { "sudo on" } else { "sudo off" })?;
            *self.sudo_active.lock().unwrap() = on;
            Ok(())
        }
        async fn forget_password(&self) -> Result<(), String> {
            self.step("forget")?;
            *self.password.lock().unwrap() = None;
            Ok(())
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

    async fn run_in(
        t: Lang,
        h: &FakeHost,
        answers: &[&str],
        link: Option<&str>,
    ) -> (Outcome, Vec<String>) {
        let d = Fake::with(answers);
        let o = flow(&d, h, t, link).await;
        (o, d.seen())
    }

    async fn run(h: &FakeHost, answers: &[&str], link: Option<&str>) -> (Outcome, Vec<String>) {
        run_in(Lang::En, h, answers, link).await
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
        assert!(
            seen[3].contains("Log: the journal (journalctl --user -u pithagoras-sync.service)")
        );
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
        // Sudo access: the password cancelled, forgetting refused, the menu left.
        let h = paired();
        *h.password.lock().unwrap() = Some("right pw".into());
        run(
            &h,
            &[
                "pick:sudo",
                "pick:set",
                "cancel",
                "pick:forget",
                "no",
                "pick:back",
                "pick:quit",
            ],
            None,
        )
        .await;
        assert!(h.did().is_empty(), "{:?}", h.did());
        // No to switching sudo access on: the password is kept, nothing else.
        let h = paired();
        run(&h, &["pick:sudo", "pick:set", "pw:right pw", "no"], None).await;
        assert_eq!(h.did(), ["sudo check", "keep"]);
        assert!(!*h.sudo_active.lock().unwrap());
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
            for t in [Lang::En, Lang::De] {
                let h = FakeHost::default();
                let (o, seen) = run_in(t, &h, &["yes", "yes"], Some(&bad)).await;
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
    }

    #[tokio::test]
    async fn a_portal_path_that_could_read_as_more_of_the_question_is_refused() {
        for link in [
            // An escape sequence and a line break.
            "pithagoras-sync://pair?portal=https%3A%2F%2Fportal.example%2Fa%1b%5B2K%0aPaired&code=AB12",
            // Spaces and a dash that make the URL read as two.
            "pithagoras-sync://pair?portal=https%3A%2F%2Fevil.example%2F%20%E2%80%94%20verified%3A%20https%3A%2F%2Fportal.company.example&code=AB12",
        ] {
            for t in [Lang::En, Lang::De] {
                let h = installed();
                let (o, seen) = run_in(t, &h, &["yes", "yes"], Some(link)).await;
                assert_eq!(o, Outcome::Failed);
                assert_eq!(seen.len(), 1, "{seen:?}");
                assert!(seen[0].starts_with("error: "), "{seen:?}");
                assert!(
                    !seen[0].chars().any(|c| c.is_control() && c != '\n'),
                    "{seen:?}"
                );
                assert!(h.did().is_empty());
            }
        }
        // An escaped path is shown escaped: it cannot pass for words.
        let h = installed();
        let link = "pithagoras-sync://pair?portal=https%3A%2F%2Fportal.example%2Fa%2520b&code=AB12";
        let (_, seen) = run(&h, &["no"], Some(link)).await;
        assert!(
            seen[0].contains("portal https://portal.example/a%20b as"),
            "{seen:?}"
        );
        assert!(
            !seen[0].contains("pithagoras-sync://"),
            "the raw link is not shown"
        );
    }

    #[tokio::test]
    async fn the_pairing_question_says_what_the_agent_may_do_at_once() {
        let ask = |mode, full_left_ms, folders| FakeHost {
            installed: Mutex::new(true),
            mode: PairMode {
                mode,
                full_left_ms,
                folders,
            },
            ..FakeHost::default()
        };
        async fn q(t: Lang, h: &FakeHost) -> String {
            run_in(t, h, &["no"], Some(LINK)).await.1[0].clone()
        }
        let h = ask(Mode::Ask, None, 0);
        assert!(q(Lang::En, &h).await.contains("every call asks you first"));
        let h = ask(Mode::Full, None, 0);
        let en = q(Lang::En, &h).await;
        assert!(en.contains("full mode, with no expiry"), "{en}");
        assert!(!en.contains("asks you first"), "{en}");
        let de = q(Lang::De, &h).await;
        assert!(de.contains("im Modus full, ohne Ablauf"), "{de}");
        assert!(!de.contains("fragt dich jeder Aufruf"), "{de}");
        let h = ask(Mode::Full, Some(90 * 60_000), 0);
        assert!(q(Lang::En, &h).await.contains("full mode for 1h 30m"));
        let h = ask(Mode::Folders, None, 2);
        assert!(
            q(Lang::En, &h)
                .await
                .contains("in the 2 granted folder(s) without asking")
        );
        let h = ask(Mode::Folders, None, 0);
        assert!(q(Lang::En, &h).await.contains("nothing is reachable"));
        // Replacing a pairing says it as well.
        let h = FakeHost {
            paired: Mutex::new(Some("https://old.example".into())),
            ..ask(Mode::Full, None, 0)
        };
        let en = q(Lang::En, &h).await;
        assert!(
            en.contains("Replace the pairing") && en.contains("full mode"),
            "{en}"
        );
    }

    #[tokio::test]
    async fn pairing_on_a_desktop_needs_the_users_password() {
        let desktop = || FakeHost {
            installed: Mutex::new(true),
            desktop: true,
            ..FakeHost::default()
        };
        // A wrong one: nothing is paired.
        let h = desktop();
        let (o, seen) = run(&h, &["yes", "pw:guess"], Some(LINK)).await;
        assert_eq!(o, Outcome::Failed);
        assert!(seen[1].starts_with("password: Pairing decides"), "{seen:?}");
        assert!(seen[1].contains("(alice)"), "{seen:?}");
        assert!(seen[2].starts_with("error: su did not accept"), "{seen:?}");
        assert_eq!(h.did(), ["owner password"]);
        assert_eq!(h.paired(), None);
        // Cancelled, or su could not check it: nothing either.
        let h = desktop();
        assert_eq!(
            run(&h, &["yes", "cancel"], Some(LINK)).await.0,
            Outcome::Cancelled
        );
        assert!(h.did().is_empty());
        let h = FakeHost {
            fail: Some("owner password"),
            ..desktop()
        };
        let (o, seen) = run(&h, &["yes", "pw:my login"], Some(LINK)).await;
        assert_eq!(o, Outcome::Failed);
        assert!(seen[2].contains("could not be checked"), "{seen:?}");
        assert_eq!(h.paired(), None);
        // The right one, asked after the question: paired.
        let h = desktop();
        let (o, seen) = run(&h, &["yes", "pw:my login"], Some(LINK)).await;
        assert_eq!(o, Outcome::Done);
        assert!(
            seen[0].starts_with("question: Pair this computer"),
            "{seen:?}"
        );
        assert_eq!(h.did()[0], "owner password");
        assert!(h.did()[1].starts_with("pair "), "{:?}", h.did());
        // The menu's "Pair again" asks as well.
        let h = FakeHost {
            paired: Mutex::new(Some("https://old.example".into())),
            ..desktop()
        };
        run(
            &h,
            &[
                "pick:pair",
                &format!("text:{LINK}"),
                "yes",
                "pw:guess",
                "pick:quit",
            ],
            None,
        )
        .await;
        assert_eq!(h.paired().as_deref(), Some("https://old.example"));
        // A headless machine asks none, as `pair` asks none there.
        let h = installed();
        let (o, seen) = run(&h, &["yes"], Some(LINK)).await;
        assert_eq!(o, Outcome::Done);
        assert!(!seen.iter().any(|s| s.starts_with("password:")), "{seen:?}");
    }

    #[tokio::test]
    async fn the_notes_of_install_and_pair_are_shown() {
        let h = FakeHost {
            install_notes: vec!["pairing links may not open Pithagoras Sync\x1b[2K".into()],
            pair_notes: vec!["the keyring did not take the token; it is kept in /home/alice/.config/pithagoras-sync/token".into()],
            ..FakeHost::default()
        };
        let (o, seen) = run(&h, &["yes", &format!("text:{LINK}"), "yes"], None).await;
        assert_eq!(o, Outcome::Done);
        assert!(
            seen[1].starts_with("info: Note: pairing links may not open Pithagoras Sync\\u{1b}[2K"),
            "{seen:?}"
        );
        let last = seen.last().unwrap();
        assert!(last.contains("connected to"), "{seen:?}");
        assert!(
            last.contains("Note: the keyring did not take the token; it is kept in"),
            "{seen:?}"
        );
        let h = FakeHost {
            installed: Mutex::new(true),
            pair_notes: vec!["kept in a file".into()],
            ..FakeHost::default()
        };
        let (_, seen) = run_in(Lang::De, &h, &["yes"], Some(LINK)).await;
        assert!(
            seen.last().unwrap().contains("Hinweis: kept in a file"),
            "{seen:?}"
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
        assert!(
            seen[1].starts_with(
                "info: Client: running, connected\nPortal: https://portal.example as \"laptop\""
            ),
            "{seen:?}"
        );
        assert_eq!(h.did()[0], "log");
        assert!(h.did()[1].starts_with("pair "));
        assert_eq!(h.did()[2], "uninstall");
        let last = seen.last().unwrap();
        assert!(
            last.starts_with("info: Pithagoras Sync is uninstalled. Its pairing and settings stay"),
            "{seen:?}"
        );
        assert!(last.contains("The program itself stays: /home/alice/.local/bin/pithagoras-sync"));
        assert!(!last.contains("Note:"), "{seen:?}");
        // Yes to "also remove the pairing" purges; the notes of its steps are
        // shown, as the CLI prints them.
        let h = FakeHost {
            uninstall_notes: vec!["the menu may show Pithagoras Sync until the next login".into()],
            ..paired()
        };
        let (_, seen) = run(&h, &["pick:uninstall", "yes", "yes"], None).await;
        assert_eq!(h.did(), ["purge"]);
        let last = seen.last().unwrap();
        assert!(
            last.contains("\n\nNote: the menu may show Pithagoras Sync until the next login"),
            "{seen:?}"
        );
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

    /// The password, checked with sudo, then kept, then sudo access on: in that
    /// order, and the password in no window's text.
    #[tokio::test]
    async fn sudo_access_is_set_up_with_a_checked_password() {
        let h = paired();
        let (_, seen) = run(
            &h,
            &[
                "pick:sudo",
                "pick:set",
                "pw:right pw",
                "yes",
                "pick:back",
                "pick:quit",
            ],
            None,
        )
        .await;
        assert_eq!(h.did(), ["sudo check", "keep", "sudo on"]);
        assert_eq!(h.password.lock().unwrap().as_deref(), Some("right pw"));
        assert!(seen[1].starts_with("menu: Sudo access lets"), "{seen:?}");
        assert!(seen[1].contains("Sudo access: off. Password: not stored."));
        assert!(
            seen[2].starts_with("password: The password sudo asks alice for."),
            "{seen:?}"
        );
        assert!(seen[3].starts_with(
            "question: The password is stored in the running client.\n\nSwitch sudo access on now?"
        ));
        assert_eq!(seen[4], "info: Sudo access is on.");
        assert!(
            seen[5].contains("Sudo access: on. Password: stored."),
            "{seen:?}"
        );
        assert!(seen.iter().all(|s| !s.contains("right pw")), "{seen:?}");
        // Already on: the password is replaced, no question.
        let (_, seen) = run(&h, &["pick:sudo", "pick:set", "pw:right pw"], None).await;
        assert_eq!(h.did()[3..], ["sudo check", "keep"]);
        assert!(
            seen[3].ends_with("running client.\n\nSudo access is on."),
            "{seen:?}"
        );
        // Off, then the password forgotten.
        run(
            &h,
            &["pick:sudo", "pick:off", "pick:forget", "yes", "pick:back"],
            None,
        )
        .await;
        assert_eq!(h.did()[5..], ["sudo off", "forget"]);
        assert!(h.password.lock().unwrap().is_none());
        // Forgotten while on: the offer to switch it off too.
        *h.sudo_active.lock().unwrap() = true;
        *h.password.lock().unwrap() = Some("right pw".into());
        let (_, seen) = run(&h, &["pick:sudo", "pick:forget", "yes", "yes"], None).await;
        assert_eq!(h.did()[7..], ["forget", "sudo off"]);
        assert!(seen[3].contains("Switch it off too?"), "{seen:?}");
    }

    /// A password sudo refuses, or one sudo does not ask for, is never kept and
    /// switches nothing on.
    #[tokio::test]
    async fn a_password_sudo_does_not_take_is_never_kept() {
        let h = paired();
        let (_, seen) = run(&h, &["pick:sudo", "pick:set", "pw:wrong\x1b[2K"], None).await;
        assert_eq!(h.did(), ["sudo check"]);
        assert!(
            seen[3].starts_with(
                "error: sudo did not accept this password (sudo: 1 incorrect password attempt)"
            ),
            "{seen:?}"
        );
        // sudo asks no password here: any text would pass, so nothing is proven.
        let h = FakeHost {
            sudo_says: SudoCheck::NoPasswordNeeded,
            ..paired()
        };
        let (_, seen) = run(&h, &["pick:sudo", "pick:set", "pw:anything", "yes"], None).await;
        assert_eq!(h.did(), ["sudo check"]);
        assert!(seen[3].contains("--no-password"), "{seen:?}");
        assert!(!*h.sudo_active.lock().unwrap());
        // Empty, or more than one line: sudo is not even asked.
        let h = paired();
        for pw in ["pw:", "pw:a\nb"] {
            let (_, seen) = run(&h, &["pick:sudo", "pick:set", pw], None).await;
            assert!(seen[3].starts_with("error: "), "{seen:?}");
        }
        assert!(h.did().is_empty());
        // Not running and memory only: nothing stored, nothing switched on.
        let h = FakeHost {
            kept: Kept::Nowhere,
            ..paired()
        };
        let (_, seen) = run(&h, &["pick:sudo", "pick:set", "pw:right pw", "yes"], None).await;
        assert_eq!(h.did(), ["sudo check", "keep"]);
        assert!(
            seen[3].starts_with("error: The client is not running"),
            "{seen:?}"
        );
        assert!(!*h.sudo_active.lock().unwrap());
    }

    #[tokio::test]
    async fn sudo_access_is_refused_from_the_clients_own_commands() {
        // Started by one: no window at all.
        let h = FakeHost {
            own_command: true,
            ..paired()
        };
        let (_, seen) = run(&h, &["pick:sudo", "pick:set", "pw:right pw", "yes"], None).await;
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(h.did().is_empty());
    }

    /// Each step checks again: before the password is asked for, before it is
    /// kept, before sudo access is switched on or off, and before forgetting.
    #[tokio::test]
    async fn every_sudo_step_checks_the_owner_again() {
        let set = ["pick:sudo", "pick:set", "pw:right pw", "yes"];
        for (passing, did) in [
            (1, &[][..]),
            (2, &["sudo check"][..]),
            (3, &["sudo check", "keep"][..]),
        ] {
            let h = FakeHost {
                own_from: Some(passing),
                ..paired()
            };
            let (_, seen) = run(&h, &set, None).await;
            assert_eq!(h.did(), did, "{seen:?}");
            assert!(!*h.sudo_active.lock().unwrap());
            if passing == 1 {
                assert!(seen.iter().all(|s| !s.starts_with("password:")), "{seen:?}");
            }
        }
        let h = FakeHost {
            own_from: Some(1),
            ..paired()
        };
        *h.sudo_active.lock().unwrap() = true;
        *h.password.lock().unwrap() = Some("right pw".into());
        run(&h, &["pick:sudo", "pick:off", "pick:forget", "yes"], None).await;
        assert!(h.did().is_empty(), "{:?}", h.did());
        // Forgotten, then the check before switching off fails.
        let h = FakeHost {
            own_from: Some(2),
            ..paired()
        };
        *h.sudo_active.lock().unwrap() = true;
        *h.password.lock().unwrap() = Some("right pw".into());
        run(&h, &["pick:sudo", "pick:forget", "yes", "yes"], None).await;
        assert_eq!(h.did(), ["forget"]);
        assert!(*h.sudo_active.lock().unwrap());
    }

    #[tokio::test]
    async fn no_sudo_menu_where_there_is_no_sudo_access_to_set_up() {
        let h = FakeHost {
            sudo: false,
            ..paired()
        };
        let (o, seen) = run(&h, &["pick:sudo"], None).await;
        assert_eq!(o, Outcome::Done);
        assert_eq!(seen.len(), 1);
    }

    #[tokio::test]
    async fn the_windows_speak_german() {
        let h = FakeHost::default();
        let (_, seen) = run_in(Lang::De, &h, &["yes", &format!("text:{LINK}"), "yes"], None).await;
        assert!(
            seen[0].starts_with("question: Pithagoras Sync für alice installieren?"),
            "{seen:?}"
        );
        assert!(
            seen[1].starts_with("entry: Füge den Kopplungslink"),
            "{seen:?}"
        );
        assert!(
            seen[2].contains("Pithagoras-Portal https://portal.example als „laptop“ koppeln?"),
            "{seen:?}"
        );
        assert!(
            seen[3].starts_with(
                "info: Pithagoras Sync läuft, ist mit https://portal.example verbunden"
            )
        );
        assert!(seen[3].contains("Protokoll: das Journal"));
        // The menu, the status and sudo access.
        let (_, seen) = run_in(
            Lang::De,
            &h,
            &[
                "pick:status",
                "pick:sudo",
                "pick:set",
                "pw:wrong",
                "pick:back",
                "pick:quit",
            ],
            None,
        )
        .await;
        assert!(seen[0].starts_with("menu: Pithagoras Sync ist installiert und mit"));
        assert!(seen[1].contains("Client: läuft, verbunden"), "{seen:?}");
        assert!(
            seen[1].contains("Modus: ask: Jeder Dateizugriff"),
            "{seen:?}"
        );
        assert!(
            seen[3].contains("Sudo-Zugriff: ausgeschaltet. Passwort: nicht gespeichert."),
            "{seen:?}"
        );
        assert!(seen[4].starts_with("password: Das Passwort, nach dem sudo alice fragt"));
        assert!(seen[5].starts_with("error: sudo hat dieses Passwort nicht angenommen"));
        // Refused from the client's own commands, in German too.
        let h = FakeHost {
            own_command: true,
            ..FakeHost::default()
        };
        let (_, seen) = run_in(Lang::De, &h, &[], None).await;
        assert!(
            seen[0].starts_with("error: Änderungen an den Rechten"),
            "{seen:?}"
        );
    }

    #[test]
    fn the_status_names_mode_folders_and_waiting_approvals() {
        use sync_policy::Access;
        let s = StatusView {
            link: Some((LinkState::Waiting, Some("refused (401)".into()))),
            portal: None,
            paused: true,
            mode: Mode::Full,
            full_left_ms: Some(65 * 60_000 + 5),
            folders: vec![FolderInfo {
                path: "/home/alice/work".into(),
                access: Access::Rw,
                execute: true,
            }],
            approvals_waiting: 2,
            sudo: None,
            problem: None,
        };
        let en = Lang::En.status(&s);
        assert!(
            en.contains("Client: running, not connected: waiting to try again: refused (401)"),
            "{en}"
        );
        assert!(en.contains("Portal: not paired"), "{en}");
        assert!(en.contains("PAUSED"), "{en}");
        assert!(en.contains("(falls back to ask in 1h 05m)"), "{en}");
        assert!(
            en.contains("  /home/alice/work (read and write, commands)"),
            "{en}"
        );
        assert!(en.contains("Waiting for you: 2"), "{en}");
        assert!(!en.contains("Sudo"), "{en}");
        let de = Lang::De.status(&s);
        assert!(de.contains("(fällt in 1 h 05 min auf ask zurück)"), "{de}");
        assert!(
            de.contains("  /home/alice/work (lesen und schreiben, Befehle)"),
            "{de}"
        );
        assert!(de.contains("Wartet auf dich: 2"), "{de}");
    }

    #[test]
    fn the_link_acted_on_is_rebuilt_from_the_parsed_one() {
        let u = PairUri::parse(&format!("{LINK}&spki={}", "A".repeat(43))).unwrap();
        let again = PairUri::parse(&link_of(&u)).unwrap();
        assert_eq!(again, u);
        let u =
            PairUri::parse("pithagoras-sync://pair?portal=http://127.0.0.1:3000/a%2520b&code=x1")
                .unwrap();
        assert_eq!(PairUri::parse(&link_of(&u)).unwrap(), u);
    }

    /// A client installed for the whole system (`install --system --user me`,
    /// `setup`) counts as installed for its user: the window does not put a
    /// second, user-unit client next to it. One running as another user does
    /// not count.
    #[test]
    fn a_system_unit_for_this_user_counts_as_installed() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let unit = t.path().join("system.service");
        assert_eq!(linux_install(Some(&home), &unit, "me"), LinuxInstall::None);
        std::fs::write(&unit, crate::install::system_unit(Some("someone"))).unwrap();
        assert_eq!(linux_install(Some(&home), &unit, "me"), LinuxInstall::None);
        std::fs::write(&unit, crate::install::system_unit(Some("me"))).unwrap();
        assert_eq!(
            linux_install(Some(&home), &unit, "me"),
            LinuxInstall::System
        );
        assert_eq!(linux_install(None, &unit, "me"), LinuxInstall::System);
        let user_unit = crate::install::user_unit_file(&home);
        std::fs::create_dir_all(user_unit.parent().unwrap()).unwrap();
        std::fs::write(&user_unit, crate::install::user_unit()).unwrap();
        assert_eq!(linux_install(Some(&home), &unit, "me"), LinuxInstall::User);
    }
}
