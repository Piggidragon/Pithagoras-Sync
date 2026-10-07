//! The languages of the windows (`gui`, `dialogs`): English and German, chosen
//! from the desktop's language. Every text the windows show is a method here
//! with one arm per language, so a text cannot exist in one language only. The
//! command line stays English.
//!
//! Values in the texts (a portal URL, a path, an error) come escaped by the
//! caller (`dialogs::shown`); errors from below the windows (the connector, the
//! keyring, the system) stay in English inside the translated sentence.

use sync_connector::LinkState;
use sync_policy::{Access, Mode};

use crate::cli::Kept;
use crate::gui::{LogPlace, PairMode, StatusView, SudoState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    De,
}

impl Lang {
    /// The language of a locale or language name: `de`, `de_AT.UTF-8`,
    /// `de-CH`, `en_GB`; `None` for one the windows do not speak.
    pub fn from_code(code: &str) -> Option<Lang> {
        let primary = code
            .split(['_', '.', '@', '-'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        match primary.as_str() {
            "de" => Some(Lang::De),
            "en" => Some(Lang::En),
            _ => None,
        }
    }

    /// The language from locale variables as gettext reads them: the first set
    /// of `LC_ALL`, `LC_MESSAGES` and `LANG` is the locale; unless it is `C`,
    /// `LANGUAGE` is a list of preferred languages before it. English when
    /// nothing names a language spoken here.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Lang {
        let set = |v: &str| var(v).filter(|s| !s.is_empty());
        let Some(locale) = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|v| set(v))
        else {
            return Lang::En;
        };
        if locale == "C" || locale == "POSIX" || locale.starts_with("C.") {
            return Lang::En;
        }
        set("LANGUAGE")
            .and_then(|list| list.split(':').find_map(Lang::from_code))
            .or_else(|| Lang::from_code(&locale))
            .unwrap_or(Lang::En)
    }

    /// The language of this session: the locale on Linux, the user's display
    /// language on Windows.
    pub fn detect() -> Lang {
        #[cfg(windows)]
        {
            // SAFETY: no arguments, no preconditions.
            let id = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
            // The primary language is the low 10 bits; LANG_GERMAN is 0x07.
            if id & 0x3ff == 0x07 {
                Lang::De
            } else {
                Lang::En
            }
        }
        #[cfg(not(windows))]
        Lang::from_vars(|v| std::env::var(v).ok())
    }

    fn pick(self, en: &'static str, de: &'static str) -> &'static str {
        match self {
            Lang::En => en,
            Lang::De => de,
        }
    }

    // Pairing links.

    pub fn entry_text(self) -> &'static str {
        self.pick(
            "Paste the pairing link from the portal's Devices page (Settings, Devices, Pair a device). It starts with pithagoras-sync://pair?",
            "Füge den Kopplungslink von der Geräteseite des Portals ein (Einstellungen, Geräte, Gerät koppeln). Er beginnt mit pithagoras-sync://pair?",
        )
    }

    /// OK with nothing typed or pasted in (on Windows: nothing in the clipboard).
    pub fn no_link(self) -> &'static str {
        self.pick(
            "No pairing link came in. Copy the link from the portal's Devices page, then try again.",
            "Es kam kein Kopplungslink an. Kopiere den Link von der Geräteseite des Portals und versuche es noch einmal.",
        )
    }

    pub fn link_too_long(self) -> &'static str {
        self.pick(
            "This is not a pairing link: it is far too long.",
            "Das ist kein Kopplungslink: Er ist viel zu lang.",
        )
    }

    pub fn link_unusable(self, e: &str) -> String {
        match self {
            Lang::En => format!("This pairing link cannot be used: {e}"),
            Lang::De => format!("Dieser Kopplungslink ist nicht verwendbar: {e}"),
        }
    }

    pub fn link_plain_http(self, portal: &str) -> String {
        match self {
            Lang::En => format!(
                "This pairing link names a portal on another machine over plain http ({portal}). Plain http is only for a portal on this computer: use the portal's https address."
            ),
            Lang::De => format!(
                "Dieser Kopplungslink nennt ein Portal auf einem anderen Rechner über unverschlüsseltes http ({portal}). Unverschlüsseltes http ist nur für ein Portal auf diesem Computer gedacht: Verwende die https-Adresse des Portals."
            ),
        }
    }

    // Install and pair.

    pub fn install_question(self, user: &str, path: Option<&str>) -> String {
        match self {
            Lang::En => format!(
                "Install Pithagoras Sync for {user}?\n\nIt copies the program to {}, starts it at login, and opens pithagoras-sync:// links (the pairing link in the portal).",
                path.unwrap_or("your programs folder")
            ),
            Lang::De => format!(
                "Pithagoras Sync für {user} installieren?\n\nDas Programm wird nach {} kopiert, beim Anmelden gestartet und öffnet pithagoras-sync://-Links (den Kopplungslink im Portal).",
                path.unwrap_or("deinen Programme-Ordner")
            ),
        }
    }

    pub fn install_failed(self, e: &str) -> String {
        match self {
            Lang::En => format!("Installing failed: {e}"),
            Lang::De => format!("Die Installation ist fehlgeschlagen: {e}"),
        }
    }

    /// The flow was started by a command the client runs for the portal.
    pub fn own_command(self) -> &'static str {
        self.pick(
            "Policy changes cannot come from commands the client runs for the portal.",
            "Änderungen an den Rechten können nicht von Befehlen kommen, die der Client für das Portal ausführt.",
        )
    }

    /// Below the pairing question for a portal on this computer over plain
    /// http, as `pair` says it: who else could answer there.
    pub fn plain_http_note(self) -> &'static str {
        if cfg!(target_os = "linux") {
            self.pick(
                "The portal is reached over plain http on this computer: the client talks there only to a program of your user or root. A portal that runs as another user needs https.",
                "Das Portal wird auf diesem Computer über unverschlüsseltes http erreicht: Der Client spricht dort nur mit einem Programm deines Benutzers oder von root. Ein Portal, das als anderer Benutzer läuft, braucht https.",
            )
        } else {
            self.pick(
                "The portal is reached over plain http on this computer: any account here that listens on its port while the portal is down gets the token. On a computer shared with other accounts, use https.",
                "Das Portal wird auf diesem Computer über unverschlüsseltes http erreicht: Jedes Konto hier, das auf seinem Port lauscht, während das Portal nicht läuft, bekommt den Token. Auf einem Computer, den du mit anderen Konten teilst, verwende https.",
            )
        }
    }

    fn pin_note(self, pinned: bool) -> &'static str {
        if !pinned {
            return "";
        }
        self.pick(
            " Its certificate is pinned by the link.",
            " Sein Zertifikat ist durch den Link festgelegt.",
        )
    }

    /// What the portal's agent may do right after pairing: the mode this
    /// computer is in now, which pairing keeps.
    fn pair_mode(self, p: PairMode) -> String {
        match (p.mode, self) {
            (Mode::Ask, Lang::En) => "What it may do is decided on this computer: until you change it, every call asks you first.".into(),
            (Mode::Ask, Lang::De) => "Was er darf, wird auf diesem Computer entschieden: Bis du es änderst, fragt dich jeder Aufruf zuerst.".into(),
            (Mode::Folders, _) if p.folders == 0 => self.pick(
                "What it may do is decided on this computer. This computer is in folders mode with no folder granted yet, so nothing is reachable until you add one.",
                "Was er darf, wird auf diesem Computer entschieden. Dieser Computer ist im Modus folders, aber noch ohne freigegebenen Ordner, also ist nichts erreichbar, bis du einen hinzufügst.",
            ).into(),
            (Mode::Folders, Lang::En) => format!(
                "What it may do is decided on this computer. This computer is in folders mode: the agent may use files and run commands in the {} granted folder(s) without asking you first.",
                p.folders
            ),
            (Mode::Folders, Lang::De) => format!(
                "Was er darf, wird auf diesem Computer entschieden. Dieser Computer ist im Modus folders: Der Agent darf in den {} freigegebenen Ordnern Dateien nutzen und Befehle ausführen, ohne dich zuerst zu fragen.",
                p.folders
            ),
            (Mode::Full, _) => {
                let until = match (p.full_left_ms, self) {
                    (Some(left), Lang::En) => {
                        let mins = left.max(0) / 60_000;
                        format!(" for {}h {:02}m", mins / 60, mins % 60)
                    }
                    (Some(left), Lang::De) => {
                        let mins = left.max(0) / 60_000;
                        format!(" für {} h {:02} min", mins / 60, mins % 60)
                    }
                    (None, _) => self.pick(", with no expiry", ", ohne Ablauf").into(),
                };
                match self {
                    Lang::En => format!(
                        "This computer is in full mode{until}: the agent acts with your rights right away and is mostly not asked. If that is not what you want, say No and switch to ask first (pithagoras-sync mode ask)."
                    ),
                    Lang::De => format!(
                        "Dieser Computer ist im Modus full{until}: Der Agent handelt sofort mit deinen Rechten und wird meist nicht gefragt. Wenn du das nicht willst, wähle Nein und stelle zuerst auf ask um (pithagoras-sync mode ask)."
                    ),
                }
            }
        }
    }

    pub fn pair_question(self, portal: &str, name: &str, pinned: bool, mode: PairMode) -> String {
        let pin = self.pin_note(pinned);
        let mode = self.pair_mode(mode);
        match self {
            Lang::En => format!(
                "Pair this computer with the Pithagoras portal {portal} as \"{name}\"?{pin}\n\nIts agent can then ask to use this computer's files and shell. {mode}"
            ),
            Lang::De => format!(
                "Diesen Computer mit dem Pithagoras-Portal {portal} als „{name}“ koppeln?{pin}\n\nSein Agent kann dann darum bitten, die Dateien und die Shell dieses Computers zu nutzen. {mode}"
            ),
        }
    }

    pub fn replace_question(
        self,
        old: &str,
        portal: &str,
        name: &str,
        pinned: bool,
        mode: PairMode,
    ) -> String {
        let pin = self.pin_note(pinned);
        let mode = self.pair_mode(mode);
        match self {
            Lang::En => format!(
                "This computer is paired with {old}.\n\nReplace the pairing with the portal {portal} as \"{name}\"?{pin}\n\nIts agent can then ask to use this computer's files and shell. {mode}"
            ),
            Lang::De => format!(
                "Dieser Computer ist mit {old} gekoppelt.\n\nDie Kopplung durch das Portal {portal} als „{name}“ ersetzen?{pin}\n\nSein Agent kann dann darum bitten, die Dateien und die Shell dieses Computers zu nutzen. {mode}"
            ),
        }
    }

    /// On a desktop, pairing asks for the user's password, as `pair` does in
    /// a terminal.
    pub fn owner_password_prompt(self, user: &str) -> String {
        match self {
            Lang::En => format!(
                "Pairing decides which portal's agent may use this computer, so it needs your password ({user}), as `pithagoras-sync pair` does in a terminal.\n\nIt is checked with su and not kept."
            ),
            Lang::De => format!(
                "Die Kopplung legt fest, welcher Agent eines Portals diesen Computer nutzen darf, daher braucht sie dein Passwort ({user}), wie `pithagoras-sync pair` im Terminal.\n\nEs wird mit su geprüft und nicht aufbewahrt."
            ),
        }
    }

    pub fn owner_password_wrong(self) -> &'static str {
        self.pick(
            "su did not accept this password. Nothing changed.",
            "su hat dieses Passwort nicht angenommen. Es wurde nichts geändert.",
        )
    }

    pub fn owner_password_failed(self, e: &str) -> String {
        match self {
            Lang::En => format!(
                "Your password could not be checked: {e}. Nothing changed. If your login asks for more than a password (a fingerprint, a security key), pair in a terminal: `pithagoras-sync pair` with the link, where su asks you itself."
            ),
            Lang::De => format!(
                "Dein Passwort konnte nicht geprüft werden: {e}. Es wurde nichts geändert. Wenn deine Anmeldung mehr als ein Passwort verlangt (einen Fingerabdruck, einen Sicherheitsschlüssel), kopple im Terminal: `pithagoras-sync pair` mit dem Link, dort fragt su dich selbst."
            ),
        }
    }

    /// The notes of `install`, `pair` or `uninstall` (escaped), one per line.
    pub fn notes(self, notes: &[String]) -> String {
        let word = self.pick("Note", "Hinweis");
        notes
            .iter()
            .map(|n| format!("{word}: {n}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn pair_failed(self, e: &str) -> String {
        match self {
            Lang::En => format!("Pairing failed: {e}"),
            Lang::De => format!("Die Kopplung ist fehlgeschlagen: {e}"),
        }
    }

    pub fn log_place(self, p: &LogPlace) -> String {
        match (p, self) {
            (LogPlace::File(f), _) => f.clone(),
            (LogPlace::Journal(unit), Lang::En) => {
                format!("the journal (journalctl --user -u {unit})")
            }
            (LogPlace::Journal(unit), Lang::De) => {
                format!("das Journal (journalctl --user -u {unit})")
            }
            (LogPlace::SystemJournal(unit), Lang::En) => format!(
                "the system journal (journalctl -u {unit}; you can read the client's own lines there, systemd's lines about the unit need root or the groups systemd-journal and adm)"
            ),
            (LogPlace::SystemJournal(unit), Lang::De) => format!(
                "das Systemjournal (journalctl -u {unit}; die Zeilen des Clients kannst du dort selbst lesen, die von systemd über die Unit nur root und die Gruppen systemd-journal und adm)"
            ),
        }
    }

    pub fn connected(self, portal: &str, log: &str) -> String {
        match self {
            Lang::En => format!(
                "Pithagoras Sync is running, connected to {portal}, and starts at login.\n\nLog: {log}"
            ),
            Lang::De => format!(
                "Pithagoras Sync läuft, ist mit {portal} verbunden und startet beim Anmelden.\n\nProtokoll: {log}"
            ),
        }
    }

    pub fn not_connected(self, why: &str, log: &str) -> String {
        match self {
            Lang::En => format!("Installed, not connected yet: {why}\n\nLog: {log}"),
            Lang::De => {
                format!("Installiert, aber noch nicht verbunden: {why}\n\nProtokoll: {log}")
            }
        }
    }

    /// The link's state; `None` when the client does not run. `detail` is
    /// escaped.
    pub fn link_state(self, state: Option<LinkState>, detail: Option<&str>) -> String {
        let word = match state {
            None => self.pick("the client is not running", "der Client läuft nicht"),
            Some(LinkState::Connecting) => self.pick("connecting", "verbindet"),
            Some(LinkState::Connected) => self.pick("connected", "verbunden"),
            Some(LinkState::Waiting) => {
                self.pick("waiting to try again", "wartet auf den nächsten Versuch")
            }
            Some(LinkState::Rejected) => self.pick(
                "the portal refused this device",
                "das Portal hat dieses Gerät abgelehnt",
            ),
            Some(LinkState::Paused) => self.pick("paused", "pausiert"),
            Some(LinkState::Stopped) => self.pick("stopped", "angehalten"),
        };
        match detail {
            Some(d) => format!("{word}: {d}"),
            None => word.to_string(),
        }
    }

    // The menu of a paired device.

    pub fn menu_text(self, portal: &str) -> String {
        match self {
            Lang::En => format!("Pithagoras Sync is installed and paired with {portal}."),
            Lang::De => format!("Pithagoras Sync ist installiert und mit {portal} gekoppelt."),
        }
    }

    /// The label of a menu item, by its key.
    pub fn label(self, key: &str) -> &'static str {
        match key {
            "status" => "Status",
            "pair" => self.pick("Pair again", "Neu koppeln"),
            "sudo" => self.pick("Sudo access", "Sudo-Zugriff"),
            "log" => self.pick("Open log", "Protokoll öffnen"),
            "uninstall" => self.pick("Uninstall", "Deinstallieren"),
            "set" => self.pick("Enter the password", "Passwort eingeben"),
            "off" => self.pick("Switch sudo access off", "Sudo-Zugriff ausschalten"),
            "forget" => self.pick("Forget the password", "Passwort vergessen"),
            "back" => self.pick("Back", "Zurück"),
            _ => self.pick("Close", "Schließen"),
        }
    }

    /// `journalctl` showed none of the client's lines in the system journal.
    pub fn no_journal_lines(self) -> &'static str {
        match self {
            Lang::En => {
                "journalctl shows no lines of the client here. Either it has not written any yet, or this system lets only root and the groups systemd-journal and adm read them: it does where the journal is kept only in memory (no /var/log/journal) or is not split by user."
            }
            Lang::De => {
                "journalctl zeigt hier keine Zeilen des Clients. Entweder hat er noch keine geschrieben, oder dieses System lässt sie nur root und die Gruppen systemd-journal und adm lesen: So ist es, wo das Journal nur im Speicher liegt (kein /var/log/journal) oder nicht nach Benutzern getrennt wird."
            }
        }
    }

    pub fn log_open_failed(self, e: &str, place: &str) -> String {
        match self {
            Lang::En => format!("Cannot open the log: {e}\n\nIt is here: {place}"),
            Lang::De => {
                format!("Das Protokoll lässt sich nicht öffnen: {e}\n\nEs liegt hier: {place}")
            }
        }
    }

    // Status.

    fn mode_text(self, mode: Mode, left_ms: Option<i64>) -> String {
        let what = match mode {
            Mode::Ask => self.pick(
                "ask: every file access and every command asks you first",
                "ask: Jeder Dateizugriff und jeder Befehl fragt dich zuerst",
            ),
            Mode::Folders => self.pick(
                "folders: files and commands only in the folders below",
                "folders: Dateien und Befehle nur in den Ordnern unten",
            ),
            Mode::Full => self.pick(
                "full: the agent acts with your rights and is mostly not asked",
                "full: Der Agent handelt mit deinen Rechten und wird meist nicht gefragt",
            ),
        };
        if mode != Mode::Full {
            return what.to_string();
        }
        match left_ms {
            Some(left) => {
                let mins = left.max(0) / 60_000;
                let (h, m) = (mins / 60, mins % 60);
                match self {
                    Lang::En => format!("{what} (falls back to ask in {h}h {m:02}m)"),
                    Lang::De => format!("{what} (fällt in {h} h {m:02} min auf ask zurück)"),
                }
            }
            None => format!("{what} ({})", self.pick("no expiry", "ohne Ablauf")),
        }
    }

    /// What the menu's Status shows. Values in `s` are escaped.
    pub fn status(self, s: &StatusView) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let client = match &s.link {
            None => self.pick("not running", "läuft nicht").to_string(),
            Some((LinkState::Connected, _)) => self
                .pick("running, connected", "läuft, verbunden")
                .to_string(),
            Some((state, detail)) => format!(
                "{}: {}",
                self.pick("running, not connected", "läuft, nicht verbunden"),
                self.link_state(Some(*state), detail.as_deref())
            ),
        };
        let _ = writeln!(out, "Client: {client}");
        let portal = match &s.portal {
            Some((url, name)) => match self {
                Lang::En => format!("{url} as \"{name}\""),
                Lang::De => format!("{url} als „{name}“"),
            },
            None => self.pick("not paired", "nicht gekoppelt").to_string(),
        };
        let _ = writeln!(out, "Portal: {portal}");
        if s.paused {
            let _ = writeln!(
                out,
                "{}",
                self.pick(
                    "PAUSED: every call is refused until `pithagoras-sync unlock`.",
                    "PAUSIERT: Jeder Aufruf wird abgelehnt bis `pithagoras-sync unlock`.",
                )
            );
        }
        let _ = writeln!(
            out,
            "{}: {}",
            self.pick("Mode", "Modus"),
            self.mode_text(s.mode, s.full_left_ms)
        );
        let folders = self.pick("Folders", "Ordner");
        if s.folders.is_empty() {
            let _ = writeln!(out, "{folders}: {}", self.pick("none", "keine"));
        } else {
            let _ = writeln!(out, "{folders}:");
        }
        for f in &s.folders {
            let access = match f.access {
                Access::Ro => self.pick("read only", "nur lesen"),
                Access::Rw => self.pick("read and write", "lesen und schreiben"),
            };
            let exec = if f.execute {
                self.pick(", commands", ", Befehle")
            } else {
                ""
            };
            let _ = writeln!(out, "  {} ({access}{exec})", f.path);
        }
        if s.approvals_waiting > 0 {
            let _ = writeln!(
                out,
                "{}: {} ({})",
                self.pick("Waiting for you", "Wartet auf dich"),
                s.approvals_waiting,
                self.pick(
                    "answer in the portal's Devices tab",
                    "beantworte sie im Geräte-Tab des Portals"
                )
            );
        }
        if let Some(on) = s.sudo {
            let _ = writeln!(out, "{}: {}", self.label("sudo"), self.on_off(on));
        }
        if let Some(p) = &s.problem {
            let _ = writeln!(out, "{}: {p}", self.pick("Problem", "Problem"));
        }
        out
    }

    fn on_off(self, on: bool) -> &'static str {
        if on {
            self.pick("on", "eingeschaltet")
        } else {
            self.pick("off", "ausgeschaltet")
        }
    }

    // Uninstall.

    pub fn uninstall_question(self) -> &'static str {
        self.pick(
            "Uninstall Pithagoras Sync? The client stops and no longer starts at login, and pairing links no longer open it.",
            "Pithagoras Sync deinstallieren? Der Client wird beendet und startet nicht mehr beim Anmelden, und Kopplungslinks öffnen ihn nicht mehr.",
        )
    }

    pub fn purge_question(self) -> &'static str {
        self.pick(
            "Also remove the pairing and all settings?\n\nYes: the pairing, the settings with their folders, the logs and everything else the client keeps go (remove the device in the portal as well). No: they stay for a later install.",
            "Auch die Kopplung und alle Einstellungen entfernen?\n\nJa: Die Kopplung, die Einstellungen mit ihren Ordnern, die Protokolle und alles andere, was der Client aufbewahrt, werden entfernt (entferne das Gerät auch im Portal). Nein: Sie bleiben für eine spätere Installation erhalten.",
        )
    }

    pub fn uninstall_failed(self, e: &str) -> String {
        match self {
            Lang::En => format!("Uninstalling failed: {e}"),
            Lang::De => format!("Die Deinstallation ist fehlgeschlagen: {e}"),
        }
    }

    pub fn uninstalled(self, purged: bool, program: &str) -> String {
        match (self, purged) {
            (Lang::En, true) => format!(
                "Pithagoras Sync is uninstalled, and its pairing and settings are removed. Remove the device in the portal as well (Settings, Devices).\n\nThe program itself stays: {program}. Delete it when you no longer need it."
            ),
            (Lang::En, false) => format!(
                "Pithagoras Sync is uninstalled. Its pairing and settings stay for a later install.\n\nThe program itself stays: {program}."
            ),
            (Lang::De, true) => format!(
                "Pithagoras Sync ist deinstalliert, seine Kopplung und Einstellungen sind entfernt. Entferne das Gerät auch im Portal (Einstellungen, Geräte).\n\nDas Programm selbst bleibt: {program}. Lösche es, wenn du es nicht mehr brauchst."
            ),
            (Lang::De, false) => format!(
                "Pithagoras Sync ist deinstalliert. Kopplung und Einstellungen bleiben für eine spätere Installation erhalten.\n\nDas Programm selbst bleibt: {program}."
            ),
        }
    }

    // Sudo access.

    pub fn sudo_text(self, s: SudoState) -> String {
        let pw = if s.password {
            self.pick("stored", "gespeichert")
        } else {
            self.pick("not stored", "nicht gespeichert")
        };
        match self {
            Lang::En => format!(
                "Sudo access lets the portal's agent run `sudo <command>` on this computer; each such command asks you first, unless you exempted it in the settings.\n\nSudo access: {}. Password: {pw}.",
                self.on_off(s.active)
            ),
            Lang::De => format!(
                "Mit Sudo-Zugriff kann der Agent des Portals auf diesem Computer `sudo <Befehl>` ausführen; jeder solche Befehl fragt dich zuerst, außer du hast ihn in den Einstellungen ausgenommen.\n\nSudo-Zugriff: {}. Passwort: {pw}.",
                self.on_off(s.active)
            ),
        }
    }

    pub fn password_prompt(self, user: &str) -> String {
        match self {
            Lang::En => format!(
                "The password sudo asks {user} for.\n\nIt is checked with sudo, then kept on this computer only; it is never sent to the portal."
            ),
            Lang::De => format!(
                "Das Passwort, nach dem sudo {user} fragt.\n\nEs wird mit sudo geprüft und dann nur auf diesem Computer aufbewahrt; es wird nie an das Portal gesendet."
            ),
        }
    }

    pub fn password_empty(self) -> &'static str {
        self.pick(
            "The password is empty. Nothing changed.",
            "Das Passwort ist leer. Es wurde nichts geändert.",
        )
    }

    pub fn password_not_one_line(self, max: usize) -> String {
        match self {
            Lang::En => {
                format!("The password must be one line of at most {max} bytes. Nothing changed.")
            }
            Lang::De => format!(
                "Das Passwort muss eine Zeile mit höchstens {max} Bytes sein. Es wurde nichts geändert."
            ),
        }
    }

    /// `detail` is empty when sudo said nothing, or said the password.
    pub fn sudo_refused(self, detail: &str) -> String {
        let detail = if detail.is_empty() {
            String::new()
        } else {
            format!(" ({detail})")
        };
        match self {
            Lang::En => format!("sudo did not accept this password{detail}. Nothing changed."),
            Lang::De => format!(
                "sudo hat dieses Passwort nicht angenommen{detail}. Es wurde nichts geändert."
            ),
        }
    }

    pub fn sudo_needs_no_password(self) -> &'static str {
        self.pick(
            "sudo asks you no password on this computer, so there is nothing to store. To let the agent use sudo all the same, run in a terminal: pithagoras-sync sudo activate --no-password",
            "sudo fragt dich auf diesem Computer nach keinem Passwort, also gibt es nichts zu speichern. Damit der Agent sudo trotzdem nutzen kann, führe in einem Terminal aus: pithagoras-sync sudo activate --no-password",
        )
    }

    pub fn sudo_check_failed(self, e: &str) -> String {
        match self {
            Lang::En => format!("The password could not be checked: {e}. Nothing changed."),
            Lang::De => {
                format!("Das Passwort konnte nicht geprüft werden: {e}. Es wurde nichts geändert.")
            }
        }
    }

    /// Where the password went; `Kept::Nowhere` is `not_kept`.
    pub fn kept(self, k: Kept) -> &'static str {
        match k {
            Kept::InClient => self.pick(
                "The password is stored in the running client.",
                "Das Passwort ist im laufenden Client gespeichert.",
            ),
            Kept::ForNextStart => self.pick(
                "The password is stored for the client's next start.",
                "Das Passwort ist für den nächsten Start des Clients gespeichert.",
            ),
            Kept::Nowhere => self.not_kept(),
        }
    }

    pub fn not_kept(self) -> &'static str {
        self.pick(
            "The client is not running, and it keeps the password in memory only, so it cannot be stored now. Start the client first, then try again.",
            "Der Client läuft nicht und bewahrt das Passwort nur im Arbeitsspeicher auf, daher kann es jetzt nicht gespeichert werden. Starte zuerst den Client und versuche es dann erneut.",
        )
    }

    pub fn store_failed(self, e: &str) -> String {
        match self {
            Lang::En => format!("Storing the password failed: {e}"),
            Lang::De => format!("Das Passwort konnte nicht gespeichert werden: {e}"),
        }
    }

    pub fn activate_question(self, kept: Kept) -> String {
        let kept = self.kept(kept);
        match self {
            Lang::En => format!(
                "{kept}\n\nSwitch sudo access on now? The agent may then run `sudo <command>`; each such command asks you first."
            ),
            Lang::De => format!(
                "{kept}\n\nSudo-Zugriff jetzt einschalten? Der Agent darf dann `sudo <Befehl>` ausführen; jeder solche Befehl fragt dich zuerst."
            ),
        }
    }

    pub fn sudo_now(self, on: bool) -> &'static str {
        if on {
            self.pick("Sudo access is on.", "Sudo-Zugriff ist eingeschaltet.")
        } else {
            self.pick("Sudo access is off.", "Sudo-Zugriff ist ausgeschaltet.")
        }
    }

    pub fn sudo_stays_off(self) -> &'static str {
        self.pick(
            "Sudo access stays off.",
            "Sudo-Zugriff bleibt ausgeschaltet.",
        )
    }

    pub fn forget_question(self) -> &'static str {
        self.pick(
            "Forget the stored sudo password?",
            "Das gespeicherte sudo-Passwort vergessen?",
        )
    }

    pub fn forgotten(self) -> &'static str {
        self.pick("The password is forgotten.", "Das Passwort ist gelöscht.")
    }

    pub fn also_off_question(self) -> String {
        format!(
            "{}\n\n{}",
            self.forgotten(),
            self.pick(
                "Sudo access is still on, but works only for what sudoers allows without a password. Switch it off too?",
                "Sudo-Zugriff ist noch eingeschaltet, funktioniert aber nur für das, was sudoers ohne Passwort erlaubt. Auch ausschalten?",
            )
        )
    }

    pub fn sudo_failed(self, e: &str) -> String {
        match self {
            Lang::En => format!("Changing sudo access failed: {e}"),
            Lang::De => format!("Sudo-Zugriff konnte nicht geändert werden: {e}"),
        }
    }

    // Outside the windows.

    pub fn no_dialogs(self) -> &'static str {
        self.pick(
            "Pithagoras Sync cannot show its windows here: there is no display, or neither zenity nor kdialog is installed. Install one of them, or use the command line (pithagoras-sync --help).",
            "Pithagoras Sync kann hier keine Fenster anzeigen: Es gibt keine Anzeige, oder weder zenity noch kdialog ist installiert. Installiere eines davon oder nutze die Kommandozeile (pithagoras-sync --help).",
        )
    }

    /// Linux: something traces the window, which could read what is typed in.
    #[cfg(target_os = "linux")]
    pub fn traced(self) -> &'static str {
        self.pick(
            "Pithagoras Sync is being traced (a debugger or another program watches it), so it asks for no password now. Close what traces it and open Pithagoras Sync again.",
            "Pithagoras Sync wird gerade verfolgt (ein Debugger oder ein anderes Programm beobachtet es), deshalb fragt es jetzt nach keinem Passwort. Beende, was es verfolgt, und öffne Pithagoras Sync erneut.",
        )
    }

    /// Windows: the entry is a message box, the link is read from the
    /// clipboard.
    pub fn clipboard_hint(self) -> &'static str {
        self.pick(
            "Copy it, then press OK: it is read from the clipboard.",
            "Kopiere ihn und drücke dann OK: Er wird aus der Zwischenablage gelesen.",
        )
    }

    /// Windows: one item of a menu, as a Yes/No/Cancel question. After the
    /// `last` one there is no next choice: No closes as well.
    pub fn menu_step(self, text: &str, label: &str, last: bool) -> String {
        match (self, last) {
            (Lang::En, false) => {
                format!("{text}\n\n{label}?\n\nYes: {label}. No: the next choice. Cancel: close.")
            }
            (Lang::En, true) => format!("{text}\n\n{label}?\n\nYes: {label}. No or Cancel: close."),
            (Lang::De, false) => format!(
                "{text}\n\n{label}?\n\nJa: {label}. Nein: die nächste Auswahl. Abbrechen: schließen."
            ),
            (Lang::De, true) => {
                format!("{text}\n\n{label}?\n\nJa: {label}. Nein oder Abbrechen: schließen.")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    /// A password that could not be checked: the terminal is offered for a
    /// login that asks for more than a password, never as a check of its own
    /// (with a PAM stack that trusts the account it checks nothing either).
    #[test]
    fn an_unchecked_password_promises_no_check_in_the_terminal() {
        for t in [Lang::En, Lang::De] {
            let s = t.owner_password_failed("su let this account through");
            assert!(
                s.contains(t.pick("a fingerprint", "einen Fingerabdruck")),
                "{s}"
            );
            assert!(!s.contains(t.pick("checks it as well", "ebenfalls")), "{s}");
        }
    }

    /// The last box of the Windows menu offers no next choice.
    #[test]
    fn the_last_menu_step_offers_no_next_choice() {
        for t in [Lang::En, Lang::De] {
            let next = t.menu_step("Menu", "Status", false);
            let last = t.menu_step("Menu", "Close", true);
            assert!(
                next.contains(t.pick("the next choice", "die nächste Auswahl")),
                "{next}"
            );
            assert!(
                !last.contains(t.pick("the next choice", "die nächste Auswahl")),
                "{last}"
            );
            assert!(
                last.ends_with(t.pick("No or Cancel: close.", "Nein oder Abbrechen: schließen.")),
                "{last}"
            );
        }
    }

    #[test]
    fn the_language_follows_the_locale_as_gettext_reads_it() {
        let l = |p: &[(&str, &str)]| Lang::from_vars(vars(p));
        assert_eq!(l(&[]), Lang::En);
        assert_eq!(l(&[("LANG", "de_DE.UTF-8")]), Lang::De);
        assert_eq!(l(&[("LANG", "de_AT.UTF-8")]), Lang::De);
        assert_eq!(l(&[("LANG", "en_US.UTF-8")]), Lang::En);
        // An unknown language is English.
        assert_eq!(l(&[("LANG", "fr_FR.UTF-8")]), Lang::En);
        // LC_ALL before LC_MESSAGES before LANG; an empty one is unset.
        assert_eq!(l(&[("LANG", "en_US"), ("LC_MESSAGES", "de_DE")]), Lang::De);
        assert_eq!(
            l(&[
                ("LANG", "de_DE"),
                ("LC_MESSAGES", "de_DE"),
                ("LC_ALL", "en_GB")
            ]),
            Lang::En
        );
        assert_eq!(l(&[("LANG", "de_DE"), ("LC_ALL", "")]), Lang::De);
        // LANGUAGE lists preferences; its first language spoken here wins,
        // unless the locale is C.
        assert_eq!(
            l(&[("LANG", "en_US.UTF-8"), ("LANGUAGE", "fr:de:en")]),
            Lang::De
        );
        assert_eq!(l(&[("LANG", "de_DE.UTF-8"), ("LANGUAGE", "en")]), Lang::En);
        assert_eq!(l(&[("LANG", "C.UTF-8"), ("LANGUAGE", "de")]), Lang::En);
        assert_eq!(l(&[("LC_ALL", "C"), ("LANG", "de_DE")]), Lang::En);
    }

    #[test]
    fn every_menu_label_has_both_languages() {
        for key in [
            "status",
            "pair",
            "sudo",
            "log",
            "uninstall",
            "set",
            "off",
            "forget",
            "back",
            "quit",
        ] {
            assert!(!Lang::En.label(key).is_empty());
            assert!(!Lang::De.label(key).is_empty());
        }
        assert_eq!(Lang::De.label("uninstall"), "Deinstallieren");
    }
}
