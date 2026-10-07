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

use crate::cli::{Asked, Changed, Kept, Update};
use crate::dialogs::{
    Buttons, Dialogs, Filled, Form, MAX_ANSWER, MAX_TEXT, Style, shown, shown_lines,
};
use crate::i18n::{InstallPair, Lang};
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
    /// The system journal of this system unit (`install --system`, `setup`),
    /// run as this user. Its user reads the client's lines there where the
    /// journal is kept on disk (journald splits it by user); systemd's own
    /// lines about the unit need root or the journal's groups.
    SystemJournal(&'static str),
}

/// What opening the log fails with when `journalctl` shows none of the
/// client's lines, which the window explains in its own words.
pub const NO_JOURNAL_LINES: &str = "journalctl shows no lines of the client here";

/// The arguments of `journalctl` for the client's lines in `place`.
fn journal_args(place: &LogPlace) -> Option<Vec<&'static str>> {
    let (user, unit) = match place {
        LogPlace::File(_) => return None,
        LogPlace::Journal(unit) => (true, *unit),
        LogPlace::SystemJournal(unit) => (false, *unit),
    };
    let mut args = vec!["-u", unit, "-n", "500", "--no-pager"];
    if user {
        args.insert(0, "--user");
    }
    Some(args)
}

/// The status the menu shows in its text. Text in it is escaped (`shown`).
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
    /// Why `uninstall` cannot be done from here, known before it asks
    /// anything: the system unit runs the client, which only root removes.
    fn uninstall_refused(&self) -> Option<String>;
    /// `uninstall`, or `uninstall --purge`; returns the program, which stays,
    /// and the notes of its steps.
    async fn uninstall(&self, purge: bool) -> Result<(String, Vec<String>), String>;
    /// Whether this build can update itself (it has the release key).
    fn can_update(&self) -> bool;
    /// `update --check`: what it found.
    async fn update_check(&self) -> Result<Update, String>;
    /// `update`, of only what the owner was asked about: what it did.
    async fn update(&self, asked: Asked<'_>) -> Result<Update, String>;
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

/// `parse` for a text that may be anything the owner copied (Windows'
/// clipboard). One that is no pairing link at all gets no description
/// (`None`), since that would quote it; the one made is zeroed.
fn parse_copied(t: Lang, text: &str) -> Option<Result<PairUri, String>> {
    if text.len() > MAX_ANSWER {
        return None;
    }
    if let Err(e) = PairUri::parse(text) {
        drop(Secret::new(e));
        return None;
    }
    Some(parse(t, text))
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

/// The dialogs as the flow uses them: a message that asks nothing (a result,
/// a note, an error after which the flow goes on) is held back and shown at
/// the top of the next window, instead of a window of its own. A question is
/// never made longer (a confirmation shows all of itself): held messages get
/// their own window before it, as they do when they would not fit, and at the
/// end (`flush`).
struct Later<'a> {
    d: &'a dyn Dialogs,
    /// The messages held back; `true` for an error.
    held: std::cell::RefCell<Vec<(bool, String)>>,
}

impl<'a> Later<'a> {
    fn new(d: &'a dyn Dialogs) -> Later<'a> {
        Later {
            d,
            held: Default::default(),
        }
    }

    /// Shows what is held in a window of its own: an error's if one is.
    fn flush(&self) {
        let held = std::mem::take(&mut *self.held.borrow_mut());
        if held.is_empty() {
            return;
        }
        let error = held.iter().any(|(e, _)| *e);
        let text = held
            .into_iter()
            .map(|(_, t)| t)
            .collect::<Vec<_>>()
            .join("\n\n");
        if error {
            self.d.error(&text);
        } else {
            self.d.info(&text);
        }
    }

    /// `text` with the held messages above it, when all of it fits a window.
    fn with_held(&self, text: &str) -> String {
        let top: Vec<String> = self.held.borrow().iter().map(|(_, t)| t.clone()).collect();
        if top.is_empty() {
            return text.to_string();
        }
        let top = top.join("\n\n");
        if top.chars().count() + 2 + text.chars().count() > MAX_TEXT {
            self.flush();
            return text.to_string();
        }
        self.held.borrow_mut().clear();
        format!("{top}\n\n{text}")
    }
}

impl Dialogs for Later<'_> {
    fn style(&self) -> Style {
        self.d.style()
    }

    fn info(&self, text: &str) {
        self.held.borrow_mut().push((false, text.to_string()));
    }

    fn error(&self, text: &str) {
        self.held.borrow_mut().push((true, text.to_string()));
    }

    fn question(&self, text: &str) -> bool {
        self.flush();
        self.d.question(text)
    }

    fn entry(&self, text: &str, buttons: Buttons) -> Option<Secret> {
        self.d.entry(&self.with_held(text), buttons)
    }

    fn password(&self, text: &str) -> Option<Secret> {
        self.d.password(&self.with_held(text))
    }

    fn menu(
        &self,
        text: &str,
        items: &[(&'static str, &str)],
        buttons: Buttons,
    ) -> Option<&'static str> {
        self.d.menu(&self.with_held(text), items, buttons)
    }

    fn form(&self, text: &str, form: Form, buttons: Buttons) -> Option<Filled> {
        self.d.form(&self.with_held(text), form, buttons)
    }

    fn at_hand(&self) -> Option<Secret> {
        self.d.at_hand()
    }
}

/// Runs the flow. `link` is the pairing link the OS started the program with.
pub async fn flow(d: &dyn Dialogs, h: &impl Host, t: Lang, link: Option<&str>) -> Outcome {
    let later = Later::new(d);
    let o = flow_in(&later, h, t, link).await;
    later.flush();
    o
}

async fn flow_in(d: &dyn Dialogs, h: &impl Host, t: Lang, link: Option<&str>) -> Outcome {
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
        return install(d, h, t, link).await;
    }
    if let Some(u) = link {
        return confirm_and_pair(d, h, t, &u, false, None).await;
    }
    if h.paired().is_none() {
        return ask_link(d, h, t, false).await;
    }
    menu(d, h, t).await
}

/// Installs, and pairs where a link comes. With the link known before the
/// first window (opened from the portal, or on Windows a valid one in the
/// clipboard) one question asks for both; else the first window asks for the
/// link, which may stay empty (zenity's form with the login password beside
/// it, kdialog's entry). Windows, without a link at hand, asks to install and
/// then for the link. Nothing changes before a Yes.
async fn install(d: &dyn Dialogs, h: &impl Host, t: Lang, link: Option<PairUri>) -> Outcome {
    let (user, path) = h.install_target();
    let (user, path) = (shown(&user), path.map(|p| shown(&p)));
    // The clipboard's text is taken only as a link that parses; anything
    // else in it is dropped unseen, and zeroed.
    let link = link.or_else(|| {
        d.at_hand()
            .and_then(|c| parse_copied(t, c.expose().trim()))
            .and_then(Result::ok)
    });
    if let Some(u) = link {
        let portal = shown(&u.portal.to_string());
        let name = shown(&h.device_name());
        let old = h.paired().map(|o| shown(&o));
        let mut q = t.install_pair_question(
            &user,
            path.as_deref(),
            &InstallPair {
                portal: &portal,
                name: &name,
                pinned: u.spki.is_some(),
                mode: h.pair_mode(),
                old: old.as_deref(),
            },
        );
        if !u.portal.tls {
            q = format!("{q}\n\n{}", t.plain_http_note());
        }
        if !d.question(&q) {
            return Outcome::Cancelled;
        }
        return pair_after_yes(d, h, t, &u, true, None).await;
    }
    if d.style() == Style::Boxes {
        if !d.question(&t.install_question(&user, path.as_deref())) {
            return Outcome::Cancelled;
        }
        let notes = match install_now(d, h, t).await {
            Ok(n) => n,
            Err(o) => return o,
        };
        if h.paired().is_some() {
            return after(d, h, t, &notes).await;
        }
        if !notes.is_empty() {
            d.info(&t.notes(&notes));
        }
        // It is installed by now: closing the link window leaves it so,
        // not paired, and says that.
        return match ask_link(d, h, t, false).await {
            Outcome::Cancelled => {
                d.info(t.installed_not_paired());
                Outcome::Done
            }
            o => o,
        };
    }
    ask_link(d, h, t, true).await
}

/// `install`; its notes (escaped), or the outcome after its error was shown.
async fn install_now(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Result<Vec<String>, Outcome> {
    if !owner_ok(d, h, t).await {
        return Err(Outcome::Failed);
    }
    match h.install().await {
        Ok(notes) => Ok(notes.iter().map(|n| shown(n)).collect()),
        Err(e) => {
            d.error(&t.install_failed(&shown(&e)));
            Err(Outcome::Failed)
        }
    }
}

/// The window that asks for the link (`install`: and says what installing
/// does; an empty link then installs only), with the login password beside
/// it where pairing needs it and the dialog program has forms. Asked again,
/// with what was wrong at the top, until a link parses or the owner cancels.
async fn ask_link(d: &dyn Dialogs, h: &impl Host, t: Lang, install: bool) -> Outcome {
    let account =
        (d.style() == Style::Forms && h.owner_password_needed()).then(|| shown(&h.account()));
    let text = if install {
        let (user, path) = h.install_target();
        let old = h.paired().map(|o| shown(&o));
        t.install_form_text(
            &shown(&user),
            path.map(|p| shown(&p)).as_deref(),
            old.as_deref(),
            account.as_deref(),
        )
    } else {
        t.pair_form_text(account.as_deref())
    };
    let form = Form {
        entry: Some(t.link_label()),
        password: account.as_ref().map(|_| t.password_label()),
    };
    let buttons = pair_buttons(t, install);
    loop {
        let Some(filled) = d.form(&text, form, buttons) else {
            return Outcome::Cancelled;
        };
        let link = filled.entry.unwrap_or_else(|| Secret::new(String::new()));
        let link = link.expose().trim();
        if link.is_empty() {
            if install {
                return install_only(d, h, t).await;
            }
            d.error(t.no_link());
            continue;
        }
        // Windows reads the link from the clipboard, which may hold
        // anything: a text that is no link is not shown.
        let parsed = if d.style() == Style::Boxes {
            parse_copied(t, link).unwrap_or_else(|| Err(t.clipboard_no_link().into()))
        } else {
            parse(t, link)
        };
        match parsed {
            Ok(u) => return confirm_and_pair(d, h, t, &u, install, filled.password).await,
            Err(e) => d.error(&e),
        }
    }
}

/// The buttons of the windows that ask for the link or the login password:
/// the same label on the first form and the ones that come back.
fn pair_buttons(t: Lang, install: bool) -> Buttons<'static> {
    Buttons {
        ok: if install {
            t.install_and_pair_button()
        } else {
            t.pair_button()
        },
        cancel: t.cancel_button(),
    }
}

/// The install with the link left empty: then how it stands.
async fn install_only(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Outcome {
    let notes = match install_now(d, h, t).await {
        Ok(n) => n,
        Err(o) => return o,
    };
    if h.paired().is_some() {
        return after(d, h, t, &notes).await;
    }
    let mut text = t.installed_not_paired().to_string();
    if !notes.is_empty() {
        text = format!("{text}\n\n{}", t.notes(&notes));
    }
    d.info(&text);
    Outcome::Done
}

/// Confirms with the parsed values and the mode the agent gets, then pairs
/// (`pair_after_yes`). `password`: the login password typed into the form
/// beside the link, checked only after the Yes.
async fn confirm_and_pair(
    d: &dyn Dialogs,
    h: &impl Host,
    t: Lang,
    uri: &PairUri,
    install: bool,
    password: Option<Secret>,
) -> Outcome {
    let portal = shown(&uri.portal.to_string());
    let name = shown(&h.device_name());
    let pinned = uri.spki.is_some();
    let mode = h.pair_mode();
    let mut q = match h.paired() {
        Some(old) => t.replace_question(&shown(&old), &portal, &name, pinned, mode),
        None => t.pair_question(&portal, &name, pinned, mode),
    };
    // Only a portal on this computer gets this far over plain http (`parse`).
    if !uri.portal.tls {
        q = format!("{q}\n\n{}", t.plain_http_note());
    }
    if !d.question(&q) {
        return Outcome::Cancelled;
    }
    pair_after_yes(d, h, t, uri, install, password).await
}

/// After the owner's Yes: the login password where `pair` would ask for it,
/// then (`install`) the install, then the pairing as `pair` does it, then how
/// it stands, with the notes of both.
async fn pair_after_yes(
    d: &dyn Dialogs,
    h: &impl Host,
    t: Lang,
    uri: &PairUri,
    install: bool,
    password: Option<Secret>,
) -> Outcome {
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    if h.owner_password_needed() {
        match owner_password(d, h, t, uri, install, password).await {
            Outcome::Done => {}
            other => return other,
        }
    }
    let mut notes = Vec::new();
    if install {
        match install_now(d, h, t).await {
            Ok(n) => notes = n,
            Err(o) => return o,
        }
    }
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    // Rebuilt from what was parsed and shown, so only that is acted on.
    let link = link_of(uri);
    match h.pair(&link).await {
        Ok(n) => {
            notes.extend(n.iter().map(|n| shown(n)));
            after(d, h, t, &notes).await
        }
        Err(e) => {
            d.error(&t.pair_failed(&shown(&e)));
            Outcome::Failed
        }
    }
}

/// How many passwords `su` may refuse in one flow, as sudo allows by default.
const OWNER_PASSWORD_TRIES: u32 = 3;

/// The user's password, checked with `su`: on a desktop the command line asks
/// for it in a terminal before `pair`, and a command of the agent that clicks
/// through the windows does not know it. `typed`: the one from the form, if
/// it had a field for it. A password `su` refused is asked for again, with
/// why at the top: zenity's form again, the link kept (shown as parsed), or
/// the password window; after `OWNER_PASSWORD_TRIES` refusals the flow ends,
/// so a program that drives the window cannot guess on in it.
async fn owner_password(
    d: &dyn Dialogs,
    h: &impl Host,
    t: Lang,
    uri: &PairUri,
    install: bool,
    typed: Option<Secret>,
) -> Outcome {
    let account = shown(&h.account());
    let mut typed = typed;
    let mut refused = 0;
    loop {
        let pw = match typed.take() {
            Some(pw) => pw,
            None if d.style() == Style::Forms => {
                let text = t.password_again_text(
                    &shown(&uri.portal.to_string()),
                    &shown(&h.device_name()),
                    &account,
                );
                let form = Form {
                    entry: None,
                    password: Some(t.password_label()),
                };
                let buttons = pair_buttons(t, install);
                match d.form(&text, form, buttons).and_then(|f| f.password) {
                    Some(pw) => pw,
                    None => return Outcome::Cancelled,
                }
            }
            None => match d.password(&t.owner_password_prompt(&account)) {
                Some(pw) => pw,
                None => return Outcome::Cancelled,
            },
        };
        if pw.expose().is_empty() {
            d.error(t.password_empty());
            continue;
        }
        match h.owner_password(&pw).await {
            Ok(true) => return Outcome::Done,
            Ok(false) => {
                refused += 1;
                if refused >= OWNER_PASSWORD_TRIES {
                    d.error(&t.owner_password_tries(OWNER_PASSWORD_TRIES));
                    return Outcome::Failed;
                }
                d.error(t.owner_password_wrong());
            }
            Err(e) => {
                d.error(&t.owner_password_failed(&shown(&e)));
                return Outcome::Failed;
            }
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

/// Waits for the link, then says how things stand, with the notes (escaped)
/// of `install` and `pair` (the token in a file where the keyring did not
/// take it).
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
        text = format!("{text}\n\n{}", t.notes(notes));
    }
    d.info(&text);
    Outcome::Done
}

/// The menu of a paired device: the status in its text, read anew each time
/// it shows, one item per action and no item to quit (Close, or closing the
/// window, ends it; the client keeps running).
async fn menu(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Outcome {
    let mut keys = vec!["pair"];
    if h.sudo_available() {
        keys.push("sudo");
    }
    if h.can_update() {
        keys.push("update");
    }
    keys.extend(["log", "uninstall"]);
    let items: Vec<(&'static str, &str)> = keys.iter().map(|k| (*k, t.label(k))).collect();
    let buttons = Buttons {
        ok: t.open_button(),
        cancel: t.close_button(),
    };
    loop {
        // Every value in the status is escaped already.
        let status = t.status(&h.status().await);
        let text = t.menu_text(&shown(&h.paired().unwrap_or_default()), &status);
        match d.menu(&text, &items, buttons) {
            None => return Outcome::Done,
            Some("pair") => {
                ask_link(d, h, t, false).await;
            }
            Some("sudo") => {
                sudo_menu(d, h, t).await;
            }
            Some("update") => {
                update(d, h, t).await;
            }
            Some("log") => {
                if let Err(e) = h.open_log() {
                    let place = t.log_place(&h.log_place());
                    let e = if e == NO_JOURNAL_LINES {
                        t.no_journal_lines().to_string()
                    } else {
                        shown(&e)
                    };
                    d.error(&t.log_open_failed(&e, &shown(&place)));
                }
            }
            Some("uninstall") => return uninstall(d, h, t).await,
            Some(_) => return Outcome::Done,
        }
    }
}

/// `update`: what `update --check` finds, and on a Yes the update to that
/// version. The release is checked as the command checks it (signed by the
/// key built in, no older release served again).
async fn update(d: &dyn Dialogs, h: &impl Host, t: Lang) -> Outcome {
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    let found = match h.update_check().await {
        Ok(u) => u,
        Err(e) => {
            d.error(&t.update_failed(&shown(&e)));
            return Outcome::Failed;
        }
    };
    let current = shown(&found.current);
    let released = shown(&found.released);
    let version = found.available.as_deref().map(shown);
    let asked = match (&version, &found.stale_client) {
        (Some(v), _) => {
            if !d.question(&t.update_question(v, &released, &current)) {
                return Outcome::Cancelled;
            }
            Asked::Release(found.available.as_deref().unwrap_or_default())
        }
        // The file is current, but the client still runs the one it
        // replaced: a restart is what is left to do.
        (None, Some(old)) => {
            if !d.question(&t.restart_question(&current, &released, &shown(old))) {
                return Outcome::Cancelled;
            }
            Asked::Restart
        }
        (None, None) => {
            d.info(&t.up_to_date(&current, &released));
            return Outcome::Done;
        }
    };
    if !owner_ok(d, h, t).await {
        return Outcome::Failed;
    }
    let done = match h.update(asked).await {
        Ok(u) => u,
        Err(e) => {
            d.error(&t.update_failed(&shown(&e)));
            return Outcome::Failed;
        }
    };
    if let Some(c) = &done.changed {
        d.error(&match c {
            Changed::Other { asked, offered } => t.release_changed(&shown(asked), &shown(offered)),
            Changed::Gone(v) => t.release_gone(&shown(v)),
            Changed::Offered(v) => t.release_offered(&shown(v)),
        });
        return Outcome::Failed;
    }
    let (error, text) = match (&done.installed, &done.stale_client) {
        (Some(v), _) => (false, t.updated(&shown(v), done.restarted)),
        (None, _) if done.restarted => (false, t.client_restarted(&current).to_string()),
        // The client restarted meanwhile: nothing is left to do.
        (None, None) => (false, t.up_to_date(&current, &released)),
        (None, Some(_)) => (true, t.client_not_restarted().to_string()),
    };
    let mut text = text;
    if !done.notes.is_empty() {
        let notes: Vec<String> = done.notes.iter().map(|n| shown(n)).collect();
        text = format!("{text}\n\n{}", t.notes(&notes));
    }
    if error {
        d.error(&text);
        Outcome::Failed
    } else {
        d.info(&text);
        Outcome::Done
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
        let items: Vec<(&'static str, &str)> = keys.iter().map(|k| (*k, t.label(k))).collect();
        // Back is the window's own button, no item of the list.
        let buttons = Buttons {
            ok: t.choose_button(),
            cancel: t.back_button(),
        };
        match d.menu(&t.sudo_text(st), &items, buttons) {
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
    // Said before the two questions, whose answers would not count.
    if let Some(e) = h.uninstall_refused() {
        d.error(&t.uninstall_failed(&shown(&e)));
        return Outcome::Failed;
    }
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
            d.error(&t.uninstall_failed(&shown_lines(&e)));
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

    fn linux_install(&self) -> LinuxInstall {
        linux_install(
            sync_ops::info::home().as_deref(),
            &crate::update::system_unit_file(),
            &sync_ops::info::user().0,
        )
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
        } else if self.linux_install() == LinuxInstall::System {
            LogPlace::SystemJournal(crate::install::UNIT_NAME)
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
        let exe = crate::cli::this_program()?;
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

    fn uninstall_refused(&self) -> Option<String> {
        (cfg!(target_os = "linux") && self.linux_install() == LinuxInstall::System).then(|| {
            format!(
                "the client runs from the system unit {} (installed with `install --system` or `setup`), which only root can remove: sudo pithagoras-sync uninstall --system",
                crate::update::system_unit_file().display()
            )
        })
    }

    async fn uninstall(&self, purge: bool) -> Result<(String, Vec<String>), String> {
        if let Some(e) = self.uninstall_refused() {
            return Err(e);
        }
        let program = crate::cli::this_program()
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

    fn can_update(&self) -> bool {
        crate::update::PUBLIC_KEY.is_some()
    }

    async fn update_check(&self) -> Result<Update, String> {
        crate::cli::update(&self.dirs, true, None, Asked::Anything, &mut |_| {}).await
    }

    async fn update(&self, asked: Asked<'_>) -> Result<Update, String> {
        crate::cli::update(&self.dirs, false, None, asked, &mut |_| {}).await
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
        let place = self.log_place();
        let Some(args) = journal_args(&place) else {
            return Ok(crate::cli::log_file(&self.dirs));
        };
        let out = std::process::Command::new("journalctl")
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("journalctl: {e}"))?;
        // Nothing of the client in the system journal: it has not logged
        // yet, or the journal is not split by user (kept only in memory, or
        // set up so), and then only root and the journal's groups read it.
        // journalctl says the latter only on stderr.
        if matches!(place, LogPlace::SystemJournal(_)) && out.stdout.trim_ascii().is_empty() {
            return Err(NO_JOURNAL_LINES.into());
        }
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
        /// The system unit runs the client: uninstall is root's.
        system_unit: bool,
        /// Where the log is.
        log: LogPlace,
        /// What opening the log fails with.
        log_fails: Option<&'static str>,
        /// This build has the release key.
        updates: bool,
        /// The release `update --check` offers; `None`: up to date.
        release: Option<&'static str>,
        /// The running client's version, older than the program's file.
        stale_client: Option<&'static str>,
        /// The client does not take the request to restart.
        no_restart: bool,
        /// What changed on offer between the question and the Yes.
        changed: Option<Changed>,
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
                system_unit: false,
                log: LogPlace::Journal("pithagoras-sync.service"),
                log_fails: None,
                updates: true,
                release: None,
                stale_client: None,
                no_restart: false,
                changed: None,
                did: Mutex::new(Vec::new()),
            }
        }
    }

    impl FakeHost {
        /// What `update --check` finds.
        fn found(&self) -> Update {
            Update {
                available: self.release.map(String::from),
                current: "0.0.2".into(),
                released: "2026-10-08 10:00 UTC".into(),
                stale_client: self.stale_client.map(String::from),
                installed: None,
                restarted: false,
                changed: None,
                notes: Vec::new(),
            }
        }

        fn did(&self) -> Vec<String> {
            self.did.lock().unwrap().clone()
        }

        fn step(&self, s: &str) -> Result<(), String> {
            self.did.lock().unwrap().push(s.to_string());
            match self.fail {
                Some(f) if s.starts_with(f) => Err(format!("{f} broke\x1b[2K\nRun this again.")),
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
            self.log.clone()
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
            if let Some(e) = self.log_fails {
                return Err(e.into());
            }
            self.step("log")
        }
        fn uninstall_refused(&self) -> Option<String> {
            self.system_unit
                .then(|| "only root can remove the system unit".into())
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
        fn can_update(&self) -> bool {
            self.updates
        }
        async fn update_check(&self) -> Result<Update, String> {
            self.step("update check")?;
            Ok(self.found())
        }
        async fn update(&self, asked: Asked<'_>) -> Result<Update, String> {
            let found = self.found();
            if let Some(c) = &self.changed {
                return Ok(Update {
                    changed: Some(c.clone()),
                    ..found
                });
            }
            match asked {
                Asked::Release(v) => {
                    self.step(&format!("update {v}"))?;
                    Ok(Update {
                        installed: Some(v.into()),
                        restarted: !self.no_restart,
                        notes: vec!["The one you ran, /tmp/x\x1b[2K, is unchanged.".into()],
                        ..found
                    })
                }
                Asked::Restart => {
                    self.step("restart")?;
                    Ok(Update {
                        restarted: !self.no_restart,
                        ..found
                    })
                }
                Asked::Anything => panic!("the window asks about one release"),
            }
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

    /// A Linux desktop: pairing asks for the login password ("my login").
    fn desktop(h: FakeHost) -> FakeHost {
        FakeHost { desktop: true, ..h }
    }

    /// The flow with dialogs of `style` (`Entries` is kdialog's) and what the
    /// clipboard holds (Windows); the windows shown.
    async fn run_as(
        style: Style,
        t: Lang,
        h: &FakeHost,
        answers: &[&str],
        link: Option<&str>,
        at_hand: Option<&str>,
    ) -> (Outcome, Vec<String>) {
        let d = Fake {
            at_hand: at_hand.map(String::from),
            ..Fake::styled(style, answers)
        };
        let o = flow(&d, h, t, link).await;
        (o, d.seen())
    }

    async fn run_in(
        t: Lang,
        h: &FakeHost,
        answers: &[&str],
        link: Option<&str>,
    ) -> (Outcome, Vec<String>) {
        run_as(Style::Entries, t, h, answers, link, None).await
    }

    async fn run(h: &FakeHost, answers: &[&str], link: Option<&str>) -> (Outcome, Vec<String>) {
        run_in(Lang::En, h, answers, link).await
    }

    async fn zenity(h: &FakeHost, answers: &[&str], link: Option<&str>) -> (Outcome, Vec<String>) {
        run_as(Style::Forms, Lang::En, h, answers, link, None).await
    }

    fn pair_did() -> String {
        format!("pair {LINK}")
    }

    /// GNOME: one form for the link and the login password, the
    /// confirmation, the result. Nothing is checked, installed or paired
    /// before the confirmation's Yes.
    #[tokio::test]
    async fn zenity_installs_and_pairs_with_a_form_a_confirmation_and_a_result() {
        let h = desktop(FakeHost::default());
        let form = format!("form:{LINK}|my login");
        let (o, seen) = zenity(&h, &[&form, "yes"], None).await;
        assert_eq!(o, Outcome::Done);
        assert_eq!(seen.len(), 3, "{seen:#?}");
        assert!(
            seen[0].starts_with(
                "form [Pairing link, Login password] [Install and pair]: Install Pithagoras Sync for alice?"
            ),
            "{seen:#?}"
        );
        assert!(seen[0].contains("/home/alice/.local/bin/pithagoras-sync"));
        assert!(seen[0].contains("Left empty, it installs without pairing."));
        assert!(seen[0].contains("your login password (alice)"), "{seen:#?}");
        // The confirmation shows what was parsed, never the raw link.
        assert!(
            seen[1].starts_with(
                "question: Pair this computer with the Pithagoras portal https://portal.example as \"laptop\"?"
            ),
            "{seen:#?}"
        );
        assert!(!seen[1].contains("AB12CD34"), "{seen:#?}");
        assert!(
            seen[2].starts_with(
                "info: Pithagoras Sync is running, connected to https://portal.example"
            ),
            "{seen:#?}"
        );
        assert!(
            seen[2].contains("Log: the journal (journalctl --user -u pithagoras-sync.service)")
        );
        assert_eq!(h.did(), ["owner password", "install", &pair_did()]);
        assert!(seen.iter().all(|s| !s.contains("my login")), "{seen:#?}");
        // No at the confirmation: the password was never checked, nothing
        // installed or paired.
        let h = desktop(FakeHost::default());
        let (o, seen) = zenity(&h, &[&form, "no"], None).await;
        assert_eq!(o, Outcome::Cancelled);
        assert_eq!(seen.len(), 2, "{seen:#?}");
        assert!(h.did().is_empty(), "{:?}", h.did());
        // Cancel at the form.
        let h = desktop(FakeHost::default());
        assert_eq!(zenity(&h, &["cancel"], None).await.0, Outcome::Cancelled);
        assert!(h.did().is_empty());
        // No login password asked for where pairing asks none: the form has
        // the link alone.
        let h = FakeHost::default();
        let (o, seen) = zenity(&h, &[&format!("form:{LINK}"), "yes"], None).await;
        assert_eq!(o, Outcome::Done);
        assert!(seen[0].starts_with("form [Pairing link] "), "{seen:#?}");
        assert!(!seen[0].contains("password"), "{seen:#?}");
        assert_eq!(h.did(), ["install", &pair_did()]);
    }

    /// The link left empty installs only: the form, then the result. A
    /// password typed beside it is not checked.
    #[tokio::test]
    async fn an_empty_link_installs_without_pairing() {
        let h = desktop(FakeHost {
            install_notes: vec!["pairing links may not open Pithagoras Sync".into()],
            ..FakeHost::default()
        });
        let (o, seen) = zenity(&h, &["form:  |typed anyway"], None).await;
        assert_eq!(o, Outcome::Done);
        assert_eq!(seen.len(), 2, "{seen:#?}");
        assert!(
            seen[1].starts_with(
                "info: Pithagoras Sync is installed and starts at login. It is not paired yet"
            ),
            "{seen:#?}"
        );
        assert!(
            seen[1].ends_with("\n\nNote: pairing links may not open Pithagoras Sync"),
            "{seen:#?}"
        );
        assert_eq!(h.did(), ["install"]);
        // A pairing kept from an earlier install stays, and says how it stands.
        let h = FakeHost {
            paired: Mutex::new(Some("https://old.example".into())),
            ..FakeHost::default()
        };
        let (_, seen) = zenity(&h, &["form:"], None).await;
        assert!(
            seen[0].contains(
                "Left empty, it installs and keeps the pairing with https://old.example."
            ),
            "{seen:#?}"
        );
        assert!(
            seen[1].starts_with("info: Pithagoras Sync is running"),
            "{seen:#?}"
        );
        assert_eq!(h.did(), ["install"]);
    }

    /// A login password su refuses: the form again, with why at its top and
    /// the link kept (shown as parsed), asking for the password alone; no
    /// second confirmation. Nothing is installed until su took one.
    #[tokio::test]
    async fn a_wrong_login_password_shows_the_form_again_with_the_link_kept() {
        let h = desktop(FakeHost::default());
        let first = format!("form:{LINK}|guess");
        let (o, seen) = zenity(&h, &[&first, "yes", "form:my login"], None).await;
        assert_eq!(o, Outcome::Done);
        assert_eq!(seen.len(), 4, "{seen:#?}");
        assert!(
            seen[2].starts_with(
                "form [Login password] [Install and pair]: su did not accept this password. Nothing changed.\n\nPairing with the Pithagoras portal https://portal.example as \"laptop\" needs your login password (alice)."
            ),
            "{seen:#?}"
        );
        assert!(
            seen[3].starts_with("info: Pithagoras Sync is running"),
            "{seen:#?}"
        );
        assert_eq!(
            h.did(),
            ["owner password", "owner password", "install", &pair_did()]
        );
        // Cancelled the second time: nothing installed or paired.
        let h = desktop(FakeHost::default());
        let (o, _) = zenity(&h, &[&first, "yes", "cancel"], None).await;
        assert_eq!(o, Outcome::Cancelled);
        assert_eq!(h.did(), ["owner password"]);
        assert!(!h.installed() && h.paired().is_none());
        // An empty one is not even tried.
        let h = desktop(FakeHost::default());
        let (_, seen) = zenity(&h, &[&format!("form:{LINK}|"), "yes", "cancel"], None).await;
        assert!(seen[2].contains("The password is empty."), "{seen:#?}");
        assert!(h.did().is_empty());
        // su that cannot check it (a login that wants a fingerprint) ends it.
        let h = desktop(FakeHost {
            fail: Some("owner password"),
            ..FakeHost::default()
        });
        let (o, seen) = zenity(&h, &[&first, "yes"], None).await;
        assert_eq!(o, Outcome::Failed);
        assert!(
            seen.last()
                .unwrap()
                .starts_with("error: Your password could not be checked"),
            "{seen:#?}"
        );
        assert!(!h.installed());
    }

    /// A link that does not parse: the form again with why at its top.
    #[tokio::test]
    async fn a_bad_link_in_the_form_is_asked_for_again() {
        let h = desktop(FakeHost::default());
        let (o, seen) = zenity(
            &h,
            &["form:https://portal.example|my login", "cancel"],
            None,
        )
        .await;
        assert_eq!(o, Outcome::Cancelled);
        assert_eq!(seen.len(), 2, "{seen:#?}");
        assert!(
            seen[1].starts_with(
                "form [Pairing link, Login password] [Install and pair]: This pairing link cannot be used:"
            ),
            "{seen:#?}"
        );
        assert!(h.did().is_empty());
    }

    /// KDE: the install question and the link are one entry; then the
    /// confirmation, the password window, the result.
    #[tokio::test]
    async fn kdialog_asks_install_and_link_in_one_entry() {
        let h = desktop(FakeHost::default());
        let (o, seen) = run(&h, &[&format!("text:{LINK}"), "yes", "pw:my login"], None).await;
        assert_eq!(o, Outcome::Done);
        assert_eq!(seen.len(), 4, "{seen:#?}");
        assert!(
            seen[0].starts_with("entry [Install and pair]: Install Pithagoras Sync for alice?"),
            "{seen:#?}"
        );
        assert!(seen[0].contains("Left empty, it installs without pairing."));
        // No password in the entry's text: kdialog asks it in a window of
        // its own, after the confirmation.
        assert!(!seen[0].contains("login password"), "{seen:#?}");
        assert!(
            seen[1].starts_with("question: Pair this computer"),
            "{seen:#?}"
        );
        assert!(
            seen[2].starts_with("password: Pairing decides"),
            "{seen:#?}"
        );
        assert!(
            seen[3].starts_with("info: Pithagoras Sync is running"),
            "{seen:#?}"
        );
        assert_eq!(h.did(), ["owner password", "install", &pair_did()]);
        // A wrong password: the password window again, with why at its top.
        let h = desktop(FakeHost::default());
        let (o, seen) = run(
            &h,
            &[&format!("text:{LINK}"), "yes", "pw:guess", "cancel"],
            None,
        )
        .await;
        assert_eq!(o, Outcome::Cancelled);
        assert!(
            seen[3].starts_with(
                "password: su did not accept this password. Nothing changed.\n\nPairing decides"
            ),
            "{seen:#?}"
        );
        assert_eq!(h.did(), ["owner password"]);
        // Empty: installs only.
        let h = FakeHost::default();
        let (_, seen) = run(&h, &["text:"], None).await;
        assert_eq!(seen.len(), 2, "{seen:#?}");
        assert_eq!(h.did(), ["install"]);
    }

    /// Windows with a valid pairing link in the clipboard: one box asks to
    /// install and pair, with the facts of both questions.
    #[tokio::test]
    async fn windows_with_a_link_in_the_clipboard_asks_once() {
        for t in [Lang::En, Lang::De] {
            let h = FakeHost::default();
            let (o, seen) = run_as(Style::Boxes, t, &h, &["yes"], None, Some(LINK)).await;
            assert_eq!(o, Outcome::Done);
            assert_eq!(seen.len(), 2, "{seen:#?}");
            let q = &seen[0];
            let expect = match t {
                Lang::En => {
                    "question: Install Pithagoras Sync for alice and pair it with the Pithagoras portal https://portal.example as \"laptop\"?"
                }
                Lang::De => {
                    "question: Pithagoras Sync für alice installieren und mit dem Pithagoras-Portal https://portal.example als „laptop“ koppeln?"
                }
            };
            assert!(q.starts_with(expect), "{q}");
            assert!(q.contains("/home/alice/.local/bin/pithagoras-sync"), "{q}");
            // What the agent may do, as the pairing question says it.
            assert!(
                q.contains(match t {
                    Lang::En => "every call asks you first",
                    Lang::De => "fragt dich jeder Aufruf",
                }),
                "{q}"
            );
            assert!(!q.contains("AB12CD34"), "{q}");
            assert_eq!(h.did(), ["install", &pair_did()]);
            // No: nothing at all.
            let h = FakeHost::default();
            let (o, _) = run_as(Style::Boxes, t, &h, &["no"], None, Some(LINK)).await;
            assert_eq!(o, Outcome::Cancelled);
            assert!(h.did().is_empty());
        }
        // Anything else in the clipboard (a password, a link that is refused)
        // is dropped unseen: the two steps as before.
        for other in [
            "hunter2 secret",
            "pithagoras-sync://pair?portal=http://192.168.1.5:3000&code=AB",
        ] {
            let h = FakeHost::default();
            let (o, seen) = run_as(Style::Boxes, Lang::En, &h, &["no"], None, Some(other)).await;
            assert_eq!(o, Outcome::Cancelled);
            assert_eq!(seen.len(), 1, "{seen:#?}");
            assert!(
                seen[0].starts_with("question: Install Pithagoras Sync for alice?"),
                "{seen:#?}"
            );
            assert!(seen.iter().all(|s| !s.contains("hunter2")), "{seen:#?}");
            assert!(seen.iter().all(|s| !s.contains("192.168")), "{seen:#?}");
        }
    }

    /// Windows, at the box that reads the link: a clipboard text that is no
    /// pairing link (a password, say) is refused without being shown; a
    /// link that is refused for its portal still says why.
    #[tokio::test]
    async fn windows_never_shows_a_copied_text_that_is_no_link() {
        let h = FakeHost::default();
        let (_, seen) = run_as(
            Style::Boxes,
            Lang::En,
            &h,
            &[
                "yes",
                "text:hunter2 secret",
                "text:pithagoras-sync://pair?portal=http://192.168.1.5:3000&code=AB",
                "cancel",
            ],
            None,
            None,
        )
        .await;
        assert!(seen.iter().all(|s| !s.contains("hunter2")), "{seen:#?}");
        assert!(
            seen[2].starts_with("entry [Pair]: The clipboard holds no pairing link"),
            "{seen:#?}"
        );
        assert!(seen[3].contains("http://192.168.1.5:3000"), "{seen:#?}");
        assert_eq!(h.did(), ["install"]);
    }

    /// Windows without a link at hand: install, then the box that reads the
    /// link from the clipboard; the install's notes in that box's text.
    #[tokio::test]
    async fn windows_without_a_link_keeps_the_two_steps() {
        let h = FakeHost {
            install_notes: vec!["the logon task did not start".into()],
            ..FakeHost::default()
        };
        let (o, seen) = run_as(
            Style::Boxes,
            Lang::En,
            &h,
            &["yes", &format!("text:{LINK}"), "yes"],
            None,
            None,
        )
        .await;
        assert_eq!(o, Outcome::Done);
        assert_eq!(seen.len(), 4, "{seen:#?}");
        assert!(seen[0].starts_with("question: Install Pithagoras Sync for alice?"));
        assert!(
            seen[1].starts_with(
                "entry [Pair]: Note: the logon task did not start\n\nPaste the pairing link"
            ),
            "{seen:#?}"
        );
        assert!(
            seen[2].starts_with("question: Pair this computer"),
            "{seen:#?}"
        );
        assert!(
            seen[3].starts_with("info: Pithagoras Sync is running"),
            "{seen:#?}"
        );
        assert_eq!(h.did(), ["install", &pair_did()]);
        // Cancelled at the link: installed, not paired, and said so; not
        // "nothing changed".
        let h = FakeHost::default();
        let (o, seen) = run_as(Style::Boxes, Lang::En, &h, &["yes", "cancel"], None, None).await;
        assert_eq!(o, Outcome::Done);
        assert_eq!(h.did(), ["install"]);
        assert!(
            seen.last().unwrap().starts_with(
                "info: Pithagoras Sync is installed and starts at login. It is not paired yet"
            ),
            "{seen:#?}"
        );
    }

    /// Opened from the portal's link before installing: one question for both
    /// on every desktop; then the password where pairing needs it.
    #[tokio::test]
    async fn a_link_from_the_os_installs_and_pairs_after_one_question() {
        for style in [Style::Forms, Style::Entries] {
            let h = FakeHost::default();
            let (o, seen) = run_as(style, Lang::En, &h, &["yes"], Some(LINK), None).await;
            assert_eq!(o, Outcome::Done);
            assert_eq!(seen.len(), 2, "{seen:#?}");
            assert!(
                seen[0].starts_with("question: Install Pithagoras Sync for alice and pair it"),
                "{seen:#?}"
            );
            assert_eq!(h.did(), ["install", &pair_did()]);
            let h = desktop(FakeHost::default());
            let pw = if style == Style::Forms {
                "form:my login"
            } else {
                "pw:my login"
            };
            let (o, seen) = run_as(style, Lang::En, &h, &["yes", pw], Some(LINK), None).await;
            assert_eq!(o, Outcome::Done, "{seen:#?}");
            assert_eq!(seen.len(), 3, "{seen:#?}");
            assert_eq!(h.did(), ["owner password", "install", &pair_did()]);
        }
        // Paired from an earlier install: the question says it replaces that.
        let h = FakeHost {
            paired: Mutex::new(Some("https://old.example".into())),
            ..FakeHost::default()
        };
        let (_, seen) = run(&h, &["no"], Some(LINK)).await;
        assert!(seen[0].starts_with("question: Install Pithagoras Sync for alice?"));
        assert!(
            seen[0].contains("This computer is paired with https://old.example."),
            "{seen:#?}"
        );
        assert!(h.did().is_empty());
    }

    #[tokio::test]
    async fn every_no_or_cancel_changes_nothing() {
        // Cancel at the first window, in each style.
        for style in [Style::Forms, Style::Entries, Style::Boxes] {
            let h = FakeHost::default();
            let a = if style == Style::Boxes {
                "no"
            } else {
                "cancel"
            };
            let (o, _) = run_as(style, Lang::En, &h, &[a], None, None).await;
            assert_eq!(o, Outcome::Cancelled);
            assert!(h.did().is_empty());
        }
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
        assert!(h.did().is_empty());
        // Uninstall, then no; and "pair again" cancelled at the link.
        let h = paired();
        let (o, _) = run(&h, &["pick:uninstall", "no"], None).await;
        assert_eq!(o, Outcome::Cancelled);
        let (_, seen) = run(&h, &["pick:pair", "cancel", "cancel"], None).await;
        assert!(seen[1].starts_with("entry [Pair]:"), "{seen:?}");
        assert!(h.did().is_empty());
        // Update, then no: checked, nothing installed.
        let h = FakeHost {
            release: Some("0.0.3"),
            ..paired()
        };
        run(&h, &["pick:update", "no"], None).await;
        assert_eq!(h.did(), ["update check"]);
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
                "cancel",
                "cancel",
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

    /// OK with nothing in it (on Windows: no text in the clipboard) says so
    /// at the top of the next one; it is not a cancel.
    #[tokio::test]
    async fn no_link_at_all_is_asked_for_again() {
        for t in [Lang::En, Lang::De] {
            let h = installed();
            let (o, seen) = run_in(t, &h, &["text:", "text:  \r\n", "cancel"], None).await;
            assert_eq!(o, Outcome::Cancelled);
            assert_eq!(seen.len(), 3, "{seen:?}");
            for s in &seen[1..] {
                assert!(s.contains(&format!(": {}\n\n", t.no_link())), "{seen:?}");
            }
            assert!(h.did().is_empty());
        }
    }

    /// The link as Windows hands it to the handler, `pair/?`: the question,
    /// then the pairing with the link rebuilt from what was shown.
    #[tokio::test]
    async fn a_link_from_the_windows_shell_pairs() {
        let h = installed();
        let link = LINK.replace("://pair?", "://pair/?");
        let (o, seen) = run(&h, &["yes"], Some(&link)).await;
        assert_eq!(o, Outcome::Done);
        assert!(
            seen[0].starts_with("question: Pair this computer"),
            "{seen:?}"
        );
        assert_eq!(h.did(), [pair_did()]);
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
        // Each reason at the top of the next entry.
        assert_eq!(seen.len(), 4, "{seen:?}");
        assert!(seen[1].contains("cannot be used"), "{seen:?}");
        assert!(seen[2].contains("over plain http"), "{seen:?}");
        assert!(seen[3].contains("unknown key"), "{seen:?}");
        // A portal on this computer may use plain http; the question says
        // who else could answer there, as `pair` does.
        for t in [Lang::En, Lang::De] {
            let h = installed();
            let local = "pithagoras-sync://pair?portal=http://127.0.0.1:3000&code=AB";
            let (o, seen) = run_in(t, &h, &["yes"], Some(local)).await;
            assert_eq!(o, Outcome::Done);
            assert!(
                seen[0].ends_with(&format!("\n\n{}", t.plain_http_note())),
                "{seen:?}"
            );
            let h = paired();
            let (_, seen) = run_in(t, &h, &["no"], Some(local)).await;
            assert!(seen[0].ends_with(t.plain_http_note()), "{seen:?}");
            let (_, seen) = run_in(t, &h, &["no"], Some(LINK)).await;
            assert!(!seen[0].contains(t.plain_http_note()), "{seen:?}");
            // And so does the question that installs too.
            let h = FakeHost::default();
            let (_, seen) = run_in(t, &h, &["no"], Some(local)).await;
            assert!(seen[0].ends_with(t.plain_http_note()), "{seen:?}");
        }
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
                for style in [Style::Forms, Style::Entries, Style::Boxes] {
                    let h = FakeHost::default();
                    let (o, seen) = run_as(style, t, &h, &["yes", "yes"], Some(&bad), None).await;
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
        // So does the question that installs and pairs at once.
        let h = FakeHost {
            installed: Mutex::new(false),
            ..ask(Mode::Full, None, 0)
        };
        let en = q(Lang::En, &h).await;
        assert!(en.contains("and pair it with"), "{en}");
        assert!(en.contains("full mode, with no expiry"), "{en}");
    }

    /// su refusing `OWNER_PASSWORD_TRIES` passwords ends the flow: a program
    /// that drives the window cannot go on guessing in it.
    #[tokio::test]
    async fn the_login_password_is_asked_for_three_times_at_most() {
        // zenity's form, and the password window.
        let h = desktop(FakeHost::default());
        let first = format!("form:{LINK}|guess 1");
        let (o, seen) = zenity(
            &h,
            &[
                &first,
                "yes",
                "form:guess 2",
                "form:guess 3",
                "form:my login",
            ],
            None,
        )
        .await;
        assert_eq!(o, Outcome::Failed);
        assert_eq!(h.did(), ["owner password"; 3]);
        assert_eq!(
            seen.last().unwrap(),
            "error: su did not accept the password 3 times. Nothing changed; open Pithagoras Sync again to try again."
        );
        assert_eq!(seen.len(), 5, "{seen:#?}");
        assert_eq!(h.paired(), None);
        let h = desktop(installed());
        let (o, seen) = run(
            &h,
            &[
                "yes",
                "pw:guess 1",
                "pw:guess 2",
                "pw:guess 3",
                "pw:my login",
            ],
            Some(LINK),
        )
        .await;
        assert_eq!(o, Outcome::Failed);
        assert_eq!(h.did(), ["owner password"; 3]);
        assert!(
            seen.last()
                .unwrap()
                .starts_with("error: su did not accept the password 3 times")
        );
        assert_eq!(h.paired(), None);
        // An empty password is no try: su never saw it.
        let h = desktop(installed());
        let (o, _) = run(
            &h,
            &["yes", "pw:", "pw:guess 1", "pw:guess 2", "pw:my login"],
            Some(LINK),
        )
        .await;
        assert_eq!(o, Outcome::Done);
    }

    #[tokio::test]
    async fn pairing_on_a_desktop_needs_the_users_password() {
        let desktop = || desktop(installed());
        // A wrong one: nothing is paired; asked again until cancelled.
        let h = desktop();
        let (o, seen) = run(&h, &["yes", "pw:guess"], Some(LINK)).await;
        assert_eq!(o, Outcome::Cancelled);
        assert!(seen[1].starts_with("password: Pairing decides"), "{seen:?}");
        assert!(seen[1].contains("(alice)"), "{seen:?}");
        assert!(
            seen[2].starts_with("password: su did not accept"),
            "{seen:?}"
        );
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
        // The menu's "Pair again" asks as well; on zenity in the form.
        let h = FakeHost {
            paired: Mutex::new(Some("https://old.example".into())),
            ..desktop()
        };
        run(
            &h,
            &["pick:pair", &format!("text:{LINK}"), "yes", "pw:guess"],
            None,
        )
        .await;
        assert_eq!(h.paired().as_deref(), Some("https://old.example"));
        let (_, seen) = zenity(
            &h,
            &["pick:pair", &format!("form:{LINK}|guess"), "yes"],
            None,
        )
        .await;
        assert!(
            seen[1]
                .starts_with("form [Pairing link, Login password] [Pair]: Paste the pairing link"),
            "{seen:?}"
        );
        assert_eq!(h.paired().as_deref(), Some("https://old.example"));
        // A headless machine asks none, as `pair` asks none there.
        let h = installed();
        let (o, seen) = run(&h, &["yes"], Some(LINK)).await;
        assert_eq!(o, Outcome::Done);
        assert!(!seen.iter().any(|s| s.starts_with("password:")), "{seen:?}");
    }

    #[tokio::test]
    async fn the_notes_of_install_and_pair_are_shown_with_the_result() {
        let h = FakeHost {
            install_notes: vec!["pairing links may not open Pithagoras Sync\x1b[2K".into()],
            pair_notes: vec!["the keyring did not take the token; it is kept in /home/alice/.config/pithagoras-sync/token".into()],
            ..FakeHost::default()
        };
        let (o, seen) = run(&h, &[&format!("text:{LINK}"), "yes"], None).await;
        assert_eq!(o, Outcome::Done);
        assert_eq!(seen.len(), 3, "{seen:?}");
        let last = seen.last().unwrap();
        assert!(last.contains("connected to"), "{seen:?}");
        assert!(
            last.contains("\n\nNote: pairing links may not open Pithagoras Sync\\u{1b}[2K\nNote: the keyring did not take the token; it is kept in"),
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

    /// A client the system unit runs (`install --system`, `setup`): its log
    /// is the system journal, read without `--user`, and uninstalling it is
    /// root's, which the window says before it asks anything.
    #[tokio::test]
    async fn a_system_unit_has_the_system_journal_and_is_roots_to_uninstall() {
        assert_eq!(
            journal_args(&LogPlace::Journal("u.service")).unwrap(),
            ["--user", "-u", "u.service", "-n", "500", "--no-pager"]
        );
        assert_eq!(
            journal_args(&LogPlace::SystemJournal("u.service")).unwrap(),
            ["-u", "u.service", "-n", "500", "--no-pager"]
        );
        assert_eq!(journal_args(&LogPlace::File("client.log".into())), None);
        for t in [Lang::En, Lang::De] {
            let h = FakeHost {
                system_unit: true,
                log: LogPlace::SystemJournal("pithagoras-sync.service"),
                ..installed()
            };
            let (_, seen) = run_in(t, &h, &["yes"], Some(LINK)).await;
            let info = seen.last().unwrap();
            assert!(
                info.contains("journalctl -u pithagoras-sync.service;"),
                "{info}"
            );
            assert!(!info.contains("--user"), "{info}");
            // The client's own lines are this user's to read; only systemd's
            // need the journal's groups.
            assert!(
                info.contains(match t {
                    Lang::En => "you can read the client's own lines there",
                    Lang::De => "die Zeilen des Clients kannst du dort selbst lesen",
                }),
                "{info}"
            );
            // No lines: why that may be, not a claim it is the groups; at the
            // top of the menu shown next.
            let h = FakeHost {
                log_fails: Some(NO_JOURNAL_LINES),
                ..h
            };
            let (_, seen) = run_in(t, &h, &["pick:log", "cancel"], None).await;
            assert_eq!(seen.len(), 2, "{seen:?}");
            let e = &seen[1];
            assert!(e.starts_with("menu "), "{seen:?}");
            assert!(e.contains(t.no_journal_lines()), "{e}");
            assert!(
                e.contains(match t {
                    Lang::En => "has not written any yet",
                    Lang::De => "noch keine geschrieben",
                }),
                "{e}"
            );
            let (o, seen) = run_in(t, &h, &["pick:uninstall", "yes", "yes"], None).await;
            assert_eq!(o, Outcome::Failed);
            assert_eq!(seen.len(), 2, "{seen:?}");
            assert!(seen[1].starts_with("error: "), "{seen:?}");
            assert!(
                seen[1].contains("only root can remove the system unit"),
                "{seen:?}"
            );
            assert_eq!(h.did(), [pair_did()]);
        }
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
        // Whose request "what it may do" is about.
        assert!(
            seen[0].contains(
                "Its agent can then ask to use this computer's files and shell. What it may do"
            ),
            "{seen:?}"
        );
        assert_eq!(h.paired().as_deref(), Some("https://portal.example"));
        let h = paired();
        let (_, seen) = run_in(Lang::De, &h, &["no"], Some(LINK)).await;
        assert!(
            seen[0].contains("Sein Agent kann dann darum bitten"),
            "{seen:?}"
        );
    }

    /// The menu holds the status in its own text, has no item to quit (its
    /// Cancel button is Close) and an OK button that says Open. What an
    /// action reports, it reports at the top of the menu shown next.
    #[tokio::test]
    async fn the_menu_shows_the_status_and_has_no_quit_item() {
        for t in [Lang::En, Lang::De] {
            let h = paired();
            let (o, seen) = run_in(t, &h, &["cancel"], None).await;
            assert_eq!(o, Outcome::Done);
            assert_eq!(seen.len(), 1, "{seen:?}");
            let expect = match t {
                Lang::En => {
                    "menu [Pair again, Sudo access, Update, Open log, Uninstall] [Close / Open]: Pithagoras Sync is installed and paired with https://old.example.\n\nClient: running, connected\nPortal: https://portal.example as \"laptop\"\nMode: ask"
                }
                Lang::De => {
                    "menu [Neu koppeln, Sudo-Zugriff, Aktualisieren, Protokoll öffnen, Deinstallieren] [Schließen / Öffnen]: Pithagoras Sync ist installiert und mit https://old.example gekoppelt.\n\nClient: läuft, verbunden\nPortal: https://portal.example als „laptop“\nModus: ask"
                }
            };
            assert!(seen[0].starts_with(expect), "{seen:?}");
            assert!(
                !seen[0].contains("Quit") && !seen[0].contains("Status,"),
                "{seen:?}"
            );
        }
        // Without sudo access to set up, or a release key, no such items.
        let h = FakeHost {
            sudo: false,
            updates: false,
            ..paired()
        };
        let (_, seen) = run(&h, &["pick:sudo", "pick:update"], None).await;
        assert!(
            seen[0].starts_with("menu [Pair again, Open log, Uninstall] [Close / Open]"),
            "{seen:?}"
        );
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(h.did().is_empty());
    }

    #[tokio::test]
    async fn the_menu_opens_the_log_pairs_again_and_uninstalls() {
        let h = paired();
        let (o, seen) = run(
            &h,
            &[
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
        // Menu, menu (the log opened, nothing to say), entry, question, menu
        // (the pairing's result at its top), the two questions, the result.
        assert_eq!(seen.len(), 8, "{seen:#?}");
        assert!(seen[1].starts_with("menu "), "{seen:#?}");
        assert!(
            seen[1].contains(": Pithagoras Sync is installed and paired"),
            "{seen:#?}"
        );
        assert!(
            seen[4].contains("]: Pithagoras Sync is running, connected to https://portal.example"),
            "{seen:#?}"
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

    /// Update: what the check found, the version asked about, and only that
    /// version installed after a Yes; the outcome at the top of the menu.
    #[tokio::test]
    async fn the_menu_updates_after_a_yes() {
        let h = FakeHost {
            release: Some("0.0.3"),
            ..paired()
        };
        let (o, seen) = run(&h, &["pick:update", "yes", "cancel"], None).await;
        assert_eq!(o, Outcome::Done);
        assert_eq!(seen.len(), 3, "{seen:#?}");
        assert!(
            seen[1].starts_with(
                "question: Version 0.0.3 of Pithagoras Sync is available, released 2026-10-08 10:00 UTC; this computer has 0.0.2.\n\nUpdate Pithagoras Sync to 0.0.3 now?"
            ),
            "{seen:#?}"
        );
        // The notes as the command line says them, escaped.
        assert!(
            seen[2].contains("]: Pithagoras Sync is updated to 0.0.3. The client restarts with it.\n\nNote: The one you ran, /tmp/x\\u{1b}[2K, is unchanged."),
            "{seen:#?}"
        );
        assert_eq!(h.did(), ["update check", "update 0.0.3"]);
        // In German, all of it but the notes.
        let h = FakeHost {
            release: Some("0.0.3"),
            ..paired()
        };
        let (_, seen) = run_in(Lang::De, &h, &["pick:update", "yes", "cancel"], None).await;
        assert!(
            seen[1].starts_with("question: Version 0.0.3 von Pithagoras Sync ist verfügbar, veröffentlicht am 2026-10-08 10:00 UTC; dieser Computer hat 0.0.2."),
            "{seen:#?}"
        );
        assert!(
            seen[2].contains("]: Pithagoras Sync ist auf 0.0.3 aktualisiert. Der Client startet mit dieser Version neu.\n\nHinweis: The one you ran"),
            "{seen:#?}"
        );
        // Up to date: said at the top of the menu, no question.
        let h = paired();
        let (_, seen) = run_in(Lang::De, &h, &["pick:update", "cancel"], None).await;
        assert_eq!(seen.len(), 2, "{seen:#?}");
        assert!(
            seen[1].contains("]: Pithagoras Sync ist aktuell (0.0.2; die neueste Version wurde am 2026-10-08 10:00 UTC veröffentlicht).\n\n"),
            "{seen:#?}"
        );
        assert_eq!(h.did(), ["update check"]);
        // A failed check: why, and nothing else.
        let h = FakeHost {
            fail: Some("update check"),
            ..paired()
        };
        let (_, seen) = run(&h, &["pick:update", "cancel"], None).await;
        assert!(
            seen[1].contains("]: Updating failed: update check broke"),
            "{seen:#?}"
        );
        // Refused from the client's own commands, the check included.
        let h = FakeHost {
            release: Some("0.0.3"),
            own_from: Some(1),
            ..paired()
        };
        run(&h, &["pick:update", "yes"], None).await;
        assert!(h.did().is_empty(), "{:?}", h.did());
        let h = FakeHost {
            release: Some("0.0.3"),
            own_from: Some(2),
            ..paired()
        };
        run(&h, &["pick:update", "yes"], None).await;
        assert_eq!(h.did(), ["update check"]);
    }

    /// The program is current but the client still runs the one it replaced:
    /// the window offers the restart `update` would do, and does only that.
    #[tokio::test]
    async fn the_menu_restarts_a_client_that_runs_the_replaced_program() {
        let h = FakeHost {
            stale_client: Some("0.0.1"),
            ..paired()
        };
        let (o, seen) = run(&h, &["pick:update", "yes", "cancel"], None).await;
        assert_eq!(o, Outcome::Done);
        assert!(
            seen[1].starts_with(
                "question: Pithagoras Sync is up to date (0.0.2; the newest release was made 2026-10-08 10:00 UTC), but the running client is still 0.0.1.\n\nRestart the client with 0.0.2 now?"
            ),
            "{seen:#?}"
        );
        assert!(
            seen[2].contains("]: The client restarts with 0.0.2.\n\n"),
            "{seen:#?}"
        );
        assert_eq!(h.did(), ["update check", "restart"]);
        // No: nothing.
        let h = FakeHost {
            stale_client: Some("0.0.1"),
            ..paired()
        };
        run(&h, &["pick:update", "no", "cancel"], None).await;
        assert_eq!(h.did(), ["update check"]);
        // Refused: said as an error.
        let h = FakeHost {
            stale_client: Some("0.0.1"),
            no_restart: true,
            ..paired()
        };
        let (_, seen) = run(&h, &["pick:update", "yes", "cancel"], None).await;
        assert!(
            seen[2].contains("The client did not take the request to restart"),
            "{seen:#?}"
        );
    }

    /// A release that changed between the question and the Yes is said, in
    /// the window's language, as nothing done.
    #[tokio::test]
    async fn the_menu_says_what_changed_on_offer_in_its_language() {
        let changes = [
            (
                Changed::Other {
                    asked: "0.0.3".into(),
                    offered: "0.0.4".into(),
                },
                "Jetzt wird Version 0.0.4 statt 0.0.3 angeboten: Es wurde nichts installiert.",
            ),
            (
                Changed::Gone("0.0.3".into()),
                "Version 0.0.3 wird nicht mehr angeboten: Es wurde nichts installiert.",
            ),
            (
                Changed::Offered("0.0.4".into()),
                "Jetzt wird Version 0.0.4 angeboten: Es wurde nichts installiert oder neu gestartet.",
            ),
        ];
        for (c, de) in changes {
            let h = FakeHost {
                release: Some("0.0.3"),
                changed: Some(c),
                ..paired()
            };
            let (o, seen) = run_in(Lang::De, &h, &["pick:update", "yes", "cancel"], None).await;
            assert_eq!(o, Outcome::Done);
            assert!(seen[2].contains(de), "{seen:#?}");
            assert!(!seen[2].contains("nothing was"), "{seen:#?}");
            assert_eq!(h.did(), ["update check"]);
        }
    }

    /// A held message that would make the next window's text too long gets
    /// a window of its own; a question is never made longer.
    #[tokio::test]
    async fn held_messages_never_lengthen_a_question_or_overflow_a_window() {
        let d = Fake::with(&["yes", "text:x", "text:y"]);
        let l = Later::new(&d);
        l.info("note one");
        assert!(l.question("Pair?"));
        l.error(&"e".repeat(MAX_TEXT));
        l.entry(
            "Paste it",
            Buttons {
                ok: "OK",
                cancel: "Cancel",
            },
        );
        l.info("short");
        l.entry(
            "Again",
            Buttons {
                ok: "OK",
                cancel: "Cancel",
            },
        );
        l.flush();
        let seen = d.seen();
        assert_eq!(
            seen[..2],
            ["info: note one".to_string(), "question: Pair?".to_string()]
        );
        assert!(seen[2].starts_with("error: eee"), "{seen:?}");
        assert_eq!(seen[3], "entry [OK]: Paste it");
        assert_eq!(seen[4], "entry [OK]: short\n\nAgain");
        assert_eq!(seen.len(), 5, "{seen:?}");
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
        assert_eq!(
            e,
            "error: Pairing failed: pair broke\\u{1b}[2K\\nRun this again."
        );
        let h = FakeHost {
            fail: Some("install"),
            ..FakeHost::default()
        };
        let (o, seen) = run(&h, &["yes"], Some(LINK)).await;
        assert_eq!(o, Outcome::Failed);
        assert!(seen.last().unwrap().starts_with("error: Installing failed"));
        assert!(h.paired().is_none());
        // The lines of an uninstall's error are its own (what the stop left,
        // and that running it again goes on): they stay lines.
        for purge in ["yes", "no"] {
            let h = FakeHost {
                fail: Some(if purge == "yes" { "purge" } else { "uninstall" }),
                ..paired()
            };
            let (o, seen) = run(&h, &["pick:uninstall", "yes", purge], None).await;
            assert_eq!(o, Outcome::Failed);
            let e = seen.last().unwrap();
            assert!(e.starts_with("error: Uninstalling failed: "), "{e}");
            assert!(e.ends_with(" broke\\u{1b}[2K\nRun this again."), "{e}");
        }
    }

    #[tokio::test]
    async fn every_change_is_refused_from_the_clients_own_commands() {
        let own = |h: FakeHost| FakeHost {
            own_command: true,
            ..h
        };
        for style in [Style::Forms, Style::Entries, Style::Boxes] {
            let h = own(FakeHost::default());
            let (o, seen) = run_as(style, Lang::En, &h, &["yes"], None, Some(LINK)).await;
            assert_eq!(o, Outcome::Failed);
            assert_eq!(seen.len(), 1, "{seen:?}");
            assert!(
                seen[0].contains("cannot come from commands the client runs"),
                "{seen:?}"
            );
            assert!(h.did().is_empty());
        }
        let h = own(installed());
        assert_eq!(run(&h, &["yes"], Some(LINK)).await.0, Outcome::Failed);
        let h = own(paired());
        assert_eq!(
            run(&h, &["pick:uninstall", "yes", "yes"], None).await.0,
            Outcome::Failed
        );
        let h = own(paired());
        run(&h, &["pick:pair", &format!("text:{LINK}"), "yes"], None).await;
        assert!(h.did().is_empty(), "{:?}", h.did());
        assert_eq!(h.paired().as_deref(), Some("https://old.example"));
        // A command that took over after an earlier check: after the Yes,
        // before installing and before pairing it checks again.
        for passing in [1, 2, 3] {
            let h = FakeHost {
                own_from: Some(passing),
                ..FakeHost::default()
            };
            let (o, _) = zenity(&h, &[&format!("form:{LINK}"), "yes"], None).await;
            assert_eq!(o, Outcome::Failed);
            assert!(h.paired().is_none());
            assert_eq!(h.installed(), passing == 3, "{:?}", h.did());
        }
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
                "cancel",
                "cancel",
            ],
            None,
        )
        .await;
        assert_eq!(h.did(), ["sudo check", "keep", "sudo on"]);
        assert_eq!(h.password.lock().unwrap().as_deref(), Some("right pw"));
        // Back is the window's button, no item.
        assert!(
            seen[1].starts_with("menu [Enter the password] [Back / Choose]: Sudo access lets"),
            "{seen:?}"
        );
        assert!(seen[1].contains("Sudo access: off. Password: not stored."));
        assert!(
            seen[2].starts_with("password: The password sudo asks alice for."),
            "{seen:?}"
        );
        assert!(seen[3].starts_with(
            "question: The password is stored in the running client.\n\nSwitch sudo access on now?"
        ));
        // What happened, at the top of the sudo menu shown next.
        assert!(
            seen[4].contains("]: Sudo access is on.\n\nSudo access lets"),
            "{seen:?}"
        );
        assert!(
            seen[4].contains("Sudo access: on. Password: stored."),
            "{seen:?}"
        );
        assert!(
            seen[4].starts_with(
                "menu [Enter the password, Switch sudo access off, Forget the password]"
            )
        );
        assert!(seen.iter().all(|s| !s.contains("right pw")), "{seen:?}");
        // Already on: the password is replaced, no question.
        let (_, seen) = run(&h, &["pick:sudo", "pick:set", "pw:right pw"], None).await;
        assert_eq!(h.did()[3..], ["sudo check", "keep"]);
        assert!(
            seen[3].contains("]: The password is stored in the running client.\n\nSudo access is on.\n\nSudo access lets"),
            "{seen:?}"
        );
        // Off, then the password forgotten.
        run(
            &h,
            &["pick:sudo", "pick:off", "pick:forget", "yes", "cancel"],
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
            seen[3].contains(
                "]: sudo did not accept this password (sudo: 1 incorrect password attempt)"
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
            assert!(seen[3].contains("Nothing changed."), "{seen:?}");
        }
        assert!(h.did().is_empty());
        // Not running and memory only: nothing stored, nothing switched on.
        let h = FakeHost {
            kept: Kept::Nowhere,
            ..paired()
        };
        let (_, seen) = run(&h, &["pick:sudo", "pick:set", "pw:right pw", "yes"], None).await;
        assert_eq!(h.did(), ["sudo check", "keep"]);
        assert!(seen[3].contains("]: The client is not running"), "{seen:?}");
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
        assert!(seen[0].starts_with("error: "), "{seen:?}");
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
    async fn the_windows_speak_german() {
        let h = desktop(FakeHost::default());
        let (_, seen) = run_as(
            Style::Forms,
            Lang::De,
            &h,
            &[&format!("form:{LINK}|my login"), "yes"],
            None,
            None,
        )
        .await;
        assert!(
            seen[0].starts_with(
                "form [Kopplungslink, Anmeldepasswort] [Installieren und koppeln]: Pithagoras Sync für alice installieren?"
            ),
            "{seen:?}"
        );
        assert!(seen[0].contains("Bleibt es leer, wird ohne Kopplung installiert."));
        assert!(seen[0].contains("dein Anmeldepasswort (alice)"), "{seen:?}");
        assert!(
            seen[1].contains("Pithagoras-Portal https://portal.example als „laptop“ koppeln?"),
            "{seen:?}"
        );
        assert!(
            seen[2].starts_with(
                "info: Pithagoras Sync läuft, ist mit https://portal.example verbunden"
            )
        );
        assert!(seen[2].contains("Protokoll: das Journal"));
        // The menu with the status, and sudo access.
        let (_, seen) = run_in(
            Lang::De,
            &h,
            &["pick:sudo", "pick:set", "pw:wrong", "cancel", "cancel"],
            None,
        )
        .await;
        assert!(seen[0].contains("]: Pithagoras Sync ist installiert und mit"));
        assert!(seen[0].contains("Client: läuft, verbunden"), "{seen:?}");
        assert!(
            seen[0].contains("Modus: ask: Jeder Dateizugriff"),
            "{seen:?}"
        );
        assert!(
            seen[1].starts_with("menu [Passwort eingeben] [Zurück / Auswählen]"),
            "{seen:?}"
        );
        assert!(
            seen[1].contains("Sudo-Zugriff: ausgeschaltet. Passwort: nicht gespeichert."),
            "{seen:?}"
        );
        assert!(seen[2].starts_with("password: Das Passwort, nach dem sudo alice fragt"));
        assert!(seen[3].contains("]: sudo hat dieses Passwort nicht angenommen"));
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
