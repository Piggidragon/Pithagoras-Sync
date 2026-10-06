//! The device's configuration file (`config.toml`): pairing data and policy.
//!
//! The owner edits it by hand or with `pithagoras-sync mode` / `folder`; the portal
//! never writes it. The connector token lives in a separate 0600 file (`token`).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
pub use sync_proto::methods::{Access, Mode};

pub use crate::rules::{
    CommandRule, Commands, Compiled, DenyRule, GlobGrant, Hours, Rights, Tools,
};

/// Desktop: a person uses the machine (owner confirmations go through `su` on the
/// terminal). Headless: a server. Both answer approvals through the portal or the
/// local `approve` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Desktop,
    #[default]
    Headless,
}

/// How the shell runs in Folders mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FoldersShell {
    /// Under Landlock, writable only inside rw folders. Falls back to `prompt`
    /// where the kernel has no Landlock.
    #[default]
    Landlock,
    /// Every command asks (denied headless).
    Prompt,
    /// Runs like any other program of the user; the owner's explicit choice.
    Unconfined,
}

impl FoldersShell {
    pub fn as_str(self) -> &'static str {
        match self {
            FoldersShell::Landlock => "landlock",
            FoldersShell::Prompt => "prompt",
            FoldersShell::Unconfined => "unconfined",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderGrant {
    pub path: PathBuf,
    pub access: Access,
    /// Commands may run here (as their working folder) and run programs from here.
    #[serde(default)]
    pub execute: bool,
}

/// What stays on in Full mode. Every switch defaults to the restricted side; turning
/// them all off and the expiry to never makes Full unrestricted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FullOptions {
    /// Hours until Full falls back to the profile's default mode; 0 means never.
    pub expiry_hours: u32,
    /// When the current Full mode ends (Unix ms), set when Full is switched on.
    pub until_ms: Option<i64>,
    pub pattern_prompts: bool,
    pub protected_paths: bool,
    pub taint_prompts: bool,
}

impl Default for FullOptions {
    fn default() -> Self {
        FullOptions {
            expiry_hours: 8,
            until_ms: None,
            pattern_prompts: true,
            protected_paths: true,
            taint_prompts: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProtectedOptions {
    /// More protected paths (absolute, or `~/...`).
    pub extra: Vec<String>,
    /// Built-in protected paths the owner releases by name (absolute, or `~/...`).
    pub allow: Vec<String>,
    /// Names that, anywhere in a path, make writes ask (`.git`, `.envrc`, ...).
    pub tool_config: Vec<String>,
}

impl Default for ProtectedOptions {
    fn default() -> Self {
        ProtectedOptions {
            extra: Vec::new(),
            allow: Vec::new(),
            tool_config: crate::protected::TOOL_CONFIG
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// What an approval nobody answers in time turns into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TimeoutAnswer {
    #[default]
    Deny,
    /// Allow this call once (the owner's explicit choice).
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApprovalOptions {
    /// How long a call waits for an answer.
    pub timeout_secs: u64,
    pub on_timeout: TimeoutAnswer,
    /// How long an "allow for this chat" answer lasts; 0 means until the chat's
    /// grant ends.
    pub remember_minutes: u32,
    /// The longest "allow for a time" answer the device accepts.
    pub max_minutes: u32,
    /// Also show approvals as desktop notifications (Allow once / Deny). Off: they
    /// come back as the device's own dialog in phase 2.
    pub desktop_notifications: bool,
}

impl Default for ApprovalOptions {
    fn default() -> Self {
        ApprovalOptions {
            timeout_secs: 120,
            on_timeout: TimeoutAnswer::Deny,
            remember_minutes: 60,
            max_minutes: 480,
            desktop_notifications: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Elevation {
    #[default]
    Off,
    /// `sudo ...` commands run through sudo with the password the owner stored on
    /// the device (`secret set elevation`), or a sudoers rule of the owner's.
    Sudo,
}

/// Where the elevation password is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SecretStorage {
    /// Only in the running client's memory: set again after each start.
    #[default]
    Memory,
    /// A 0600 file in the client's config folder, which survives restarts. Any
    /// unconfined command of the same user could read it.
    File,
}

impl SecretStorage {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretStorage::Memory => "memory",
            SecretStorage::File => "file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PrivilegeOptions {
    /// The client may run as root (Linux) or an elevated administrator (Windows).
    pub allow_root: bool,
    pub elevation: Elevation,
    /// The sudo the client runs (device only).
    pub sudo_path: PathBuf,
    /// Device only.
    pub secret_storage: SecretStorage,
}

impl Default for PrivilegeOptions {
    fn default() -> Self {
        PrivilegeOptions {
            allow_root: false,
            elevation: Elevation::Off,
            sudo_path: PathBuf::from("/usr/bin/sudo"),
            secret_storage: SecretStorage::Memory,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    pub mode: Mode,
    pub folders: Vec<FolderGrant>,
    pub folders_shell: FoldersShell,
    pub full: FullOptions,
    pub protected: ProtectedOptions,
    pub tools: Tools,
    /// Paths and globs refused in every mode.
    pub deny: Vec<DenyRule>,
    /// Globs the file tools may reach in Folders mode, besides the folders.
    pub allow_globs: Vec<GlobGrant>,
    pub commands: Commands,
    /// Absent: every hour of every day.
    pub hours: Option<Hours>,
    pub approvals: ApprovalOptions,
    pub privilege: PrivilegeOptions,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::Ask,
            folders: Vec::new(),
            folders_shell: FoldersShell::default(),
            full: FullOptions::default(),
            protected: ProtectedOptions::default(),
            tools: Tools::default(),
            deny: Vec::new(),
            allow_globs: Vec::new(),
            commands: Commands::default(),
            hours: None,
            approvals: ApprovalOptions::default(),
            privilege: PrivilegeOptions::default(),
        }
    }
}

impl Policy {
    /// The restricted default, the mode Full falls back to: Ask, on every device
    /// (approvals come through the portal or the local `approve` command).
    pub fn default_mode(_profile: Profile) -> Mode {
        Mode::Ask
    }

    /// The mode in force at `now_ms`: Full falls back once its time is up.
    pub fn effective_mode(&self, profile: Profile, now_ms: i64) -> Mode {
        match self.mode {
            Mode::Full => match self.full.until_ms {
                Some(until) if now_ms >= until => Policy::default_mode(profile),
                _ if self.full.expiry_hours != 0 && self.full.until_ms.is_none() => {
                    // Full with an expiry but no end time was not set through the
                    // CLI; without a start time it cannot be dated, so it counts as
                    // expired rather than as Full forever.
                    Policy::default_mode(profile)
                }
                _ => Mode::Full,
            },
            m => m,
        }
    }

    /// Switches the mode, dating Full's expiry from `now_ms`.
    pub fn set_mode(&mut self, mode: Mode, now_ms: i64) {
        self.mode = mode;
        self.full.until_ms = match (mode, self.full.expiry_hours) {
            (Mode::Full, 0) => None,
            (Mode::Full, h) => Some(now_ms + i64::from(h) * 3_600_000),
            _ => None,
        };
    }

    /// Full set by hand in the file has no end time yet; the client dates it from
    /// when it loads the file. Returns whether anything changed (to save it back).
    pub fn date_full(&mut self, now_ms: i64) -> bool {
        if self.mode == Mode::Full && self.full.expiry_hours != 0 && self.full.until_ms.is_none() {
            self.set_mode(Mode::Full, now_ms);
            return true;
        }
        false
    }

    pub fn validate(&self, _profile: Profile) -> Result<(), String> {
        for f in &self.folders {
            if !f.path.is_absolute() {
                return Err(format!("folder {} is not absolute", f.path.display()));
            }
        }
        let a = &self.approvals;
        if a.timeout_secs == 0 || a.timeout_secs > 3600 {
            return Err("approvals.timeout_secs must be between 1 and 3600".into());
        }
        if a.max_minutes > 7 * 24 * 60 || a.remember_minutes > 7 * 24 * 60 {
            return Err("approvals: minutes must be at most a week (10080)".into());
        }
        // sudo is Linux only, so its path is a Unix one on every platform; Windows
        // would not call `/usr/bin/sudo` absolute and refuse the default config.
        if !self
            .privilege
            .sudo_path
            .to_str()
            .is_some_and(|s| s.starts_with('/'))
        {
            return Err("privilege.sudo_path must be absolute".into());
        }
        for t in &self.protected.tool_config {
            if t.is_empty() || t.contains(['/', '\\']) {
                return Err(format!(
                    "protected.tool_config {t:?}: a single file or folder name"
                ));
            }
        }
        // Compiling checks every rule; any home will do for that.
        self.compile(Path::new("/")).map(|_| ())
    }

    /// The deny rules, glob grants, command lists and hours, compiled.
    pub fn compile(&self, home: &Path) -> Result<Compiled, String> {
        Compiled::new(
            home,
            &self.deny,
            &self.allow_globs,
            &self.commands,
            self.hours.as_ref(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalConfig {
    /// Base URL, `https://portal.example` (`http` only for a loopback portal).
    pub url: String,
    /// Pinned certificate key: base64url sha256 of the SubjectPublicKeyInfo. Absent:
    /// the certificate is checked against the system's roots.
    #[serde(default)]
    pub spki_sha256: Option<String>,
    pub device_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExecOptions {
    /// Variables of the client's own environment that commands also get, beyond the
    /// built-in list (`PATH`, `HOME`, `LANG`, ...). `PORTAL_*` is never passed.
    pub env_passthrough: Vec<String>,
    /// The longest a command may run, whatever the portal asks for.
    pub max_timeout_secs: u64,
    /// Output beyond this many bytes per command is dropped.
    pub output_cap_bytes: u64,
    /// Most commands running at once.
    pub max_running: u32,
    /// The shell the `bash` tool runs. Absent: bash (else sh) on Linux, pwsh (else
    /// Windows PowerShell) on Windows.
    pub shell: Option<PathBuf>,
}

impl ExecOptions {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_timeout_secs == 0 || self.max_running == 0 || self.output_cap_bytes == 0 {
            return Err(
                "exec: max_timeout_secs, max_running and output_cap_bytes must be above 0".into(),
            );
        }
        if let Some(s) = &self.shell
            && !s.is_absolute()
        {
            return Err("exec.shell must be absolute".into());
        }
        Ok(())
    }
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            env_passthrough: Vec::new(),
            max_timeout_secs: 4 * 3600,
            output_cap_bytes: 16 * 1024 * 1024,
            max_running: 16,
            shell: None,
        }
    }
}

/// What the portal's Devices tab may do with this device's settings. Only the CLI
/// changes it, never the portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PortalPolicy {
    /// The portal neither sees nor changes them.
    Off,
    /// The portal shows them.
    #[default]
    Read,
    /// The owner's portal session may change them, widening included; each change is
    /// audited with its old and new value.
    Write,
}

impl PortalPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            PortalPolicy::Off => "off",
            PortalPolicy::Read => "read",
            PortalPolicy::Write => "write",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct DeviceConfig {
    pub profile: Profile,
    pub portal_policy: PortalPolicy,
    pub portal: Option<PortalConfig>,
    pub policy: Policy,
    pub exec: ExecOptions,
}

impl DeviceConfig {
    pub fn load(path: &Path) -> Result<DeviceConfig, String> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DeviceConfig::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let cfg: DeviceConfig =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        cfg.policy.validate(cfg.profile)?;
        cfg.exec.validate()?;
        Ok(cfg)
    }

    /// Writes the file atomically with mode 0600.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        self.policy.validate(self.profile)?;
        self.exec.validate()?;
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        write_private(path, text.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Writes a file only its owner can read (0600, directory 0700), atomically through a
/// temporary file in the same directory.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("no parent directory"))?;
    crate::private::private_dir(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);
    let mut f = crate::private::private_options()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

/// Where the client keeps its files. Tests build one from a temp dir.
#[derive(Debug, Clone)]
pub struct Dirs {
    pub config: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
}

impl Dirs {
    /// `$PITHAGORAS_SYNC_CONFIG_DIR`, or the XDG directories of the current user
    /// (on Windows `%APPDATA%` and `%LOCALAPPDATA%`).
    pub fn from_env() -> Result<Dirs, String> {
        if let Some(base) = std::env::var_os("PITHAGORAS_SYNC_CONFIG_DIR") {
            return Ok(Dirs::under(Path::new(&base)));
        }
        Dirs::platform()
    }

    #[cfg(not(windows))]
    fn platform() -> Result<Dirs, String> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")?;
        let xdg = |var: &str, fallback: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(fallback))
        };
        let state = xdg("XDG_STATE_HOME", ".local/state").join("pithagoras-sync");
        // Not under XDG_RUNTIME_DIR: a system unit has none, while the same user's
        // login shell does, and both must find the same control socket.
        Ok(Dirs {
            config: xdg("XDG_CONFIG_HOME", ".config").join("pithagoras-sync"),
            runtime: state.join("run"),
            state,
        })
    }

    #[cfg(windows)]
    fn platform() -> Result<Dirs, String> {
        let var = |v: &str| {
            std::env::var_os(v)
                .map(PathBuf::from)
                .ok_or(format!("{v} is not set"))
        };
        let state = var("LOCALAPPDATA")?.join("pithagoras-sync");
        Ok(Dirs {
            config: var("APPDATA")?.join("pithagoras-sync"),
            runtime: state.join("run"),
            state,
        })
    }

    /// All three under one base directory (tests, or an explicit override).
    pub fn under(base: &Path) -> Dirs {
        Dirs {
            config: base.join("config"),
            state: base.join("state"),
            runtime: base.join("run"),
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    pub fn token_file(&self) -> PathBuf {
        self.config.join("token")
    }

    pub fn audit_file(&self) -> PathBuf {
        self.state.join("audit.jsonl")
    }

    /// The release time of the newest update manifest seen for `program`. One
    /// record per program file: a manifest only looked at for one copy (root's own
    /// client, say) must not refuse an older-dated one for another (the dedicated
    /// user's in /usr/local/bin).
    pub fn update_seen_file(&self, program: &Path) -> PathBuf {
        let program = std::fs::canonicalize(program).unwrap_or_else(|_| program.to_path_buf());
        self.state
            .join(format!("update-released-{:016x}", path_hash(&program)))
    }

    /// The release time of the newest release this user installed, for any
    /// program: no program is taken below it, so one updated for the first time
    /// still refuses an older manifest served again.
    pub fn update_user_seen_file(&self) -> PathBuf {
        self.state.join("update-released")
    }

    /// Present while the client is paused by `panic`, until `unlock`.
    pub fn paused_file(&self) -> PathBuf {
        self.state.join("paused")
    }

    /// The control channel to the running client: a Unix socket, or on Windows a
    /// named pipe whose name is derived from the config directory.
    pub fn socket(&self) -> PathBuf {
        #[cfg(windows)]
        {
            // Stable across runs, and distinct per config directory.
            let h = path_hash(&self.config);
            PathBuf::from(format!(r"\\.\pipe\pithagoras-sync-{h:016x}"))
        }
        #[cfg(not(windows))]
        {
            self.runtime.join("control.sock")
        }
    }
}

/// FNV-1a of a path, case-blind on Windows, whose paths are.
fn path_hash(path: &Path) -> u64 {
    let s = path.to_string_lossy();
    #[cfg(windows)]
    let s = s.to_lowercase();
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_program_has_its_own_update_record() {
        let t = tempfile::tempdir().unwrap();
        let dirs = Dirs::under(t.path());
        let a = t.path().join("a");
        let b = t.path().join("b");
        std::fs::write(&a, "x").unwrap();
        std::fs::write(&b, "x").unwrap();
        assert_ne!(dirs.update_seen_file(&a), dirs.update_seen_file(&b));
        assert_eq!(dirs.update_seen_file(&a), dirs.update_seen_file(&a));
        assert!(dirs.update_seen_file(&a).starts_with(&dirs.state));
        // The same file by another name.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&a, t.path().join("link")).unwrap();
            assert_eq!(
                dirs.update_seen_file(&t.path().join("link")),
                dirs.update_seen_file(&a)
            );
        }
    }

    #[test]
    fn full_expires_after_eight_hours_by_default() {
        let mut p = Policy::default();
        p.set_mode(Mode::Full, 1_000);
        assert_eq!(p.effective_mode(Profile::Desktop, 1_000), Mode::Full);
        let eight_h = 8 * 3_600_000;
        assert_eq!(
            p.effective_mode(Profile::Desktop, 1_000 + eight_h - 1),
            Mode::Full
        );
        assert_eq!(
            p.effective_mode(Profile::Desktop, 1_000 + eight_h),
            Mode::Ask
        );
        assert_eq!(
            p.effective_mode(Profile::Headless, 1_000 + eight_h),
            Mode::Ask
        );
    }

    #[test]
    fn full_without_expiry_stays() {
        let mut p = Policy::default();
        p.full.expiry_hours = 0;
        p.set_mode(Mode::Full, 0);
        assert_eq!(p.effective_mode(Profile::Headless, i64::MAX), Mode::Full);
    }

    #[test]
    fn full_written_by_hand_without_a_start_counts_as_expired() {
        let mut p: Policy = toml::from_str("mode = \"full\"").unwrap();
        assert_eq!(p.effective_mode(Profile::Headless, 0), Mode::Ask);
        assert!(p.date_full(5));
        assert_eq!(p.effective_mode(Profile::Headless, 5), Mode::Full);
        assert!(!p.date_full(6));
    }

    #[test]
    fn ask_is_the_default_everywhere() {
        let p = Policy::default();
        assert_eq!(p.mode, Mode::Ask);
        assert!(p.validate(Profile::Headless).is_ok());
        assert!(p.validate(Profile::Desktop).is_ok());
        let cfg: DeviceConfig = toml::from_str("profile = \"headless\"").unwrap();
        assert_eq!(cfg.policy.effective_mode(cfg.profile, 0), Mode::Ask);
    }

    #[test]
    fn every_setting_defaults_to_the_safe_side() {
        let p = Policy::default();
        assert!(!p.privilege.allow_root);
        assert_eq!(p.privilege.elevation, Elevation::Off);
        assert_eq!(p.privilege.secret_storage, SecretStorage::Memory);
        assert_eq!(p.approvals.on_timeout, TimeoutAnswer::Deny);
        assert!(!p.approvals.desktop_notifications);
        assert!(p.folders.is_empty() && p.allow_globs.is_empty());
        assert_eq!(p.folders_shell, FoldersShell::Landlock);
        assert!(p.full.pattern_prompts && p.full.protected_paths && p.full.taint_prompts);
        assert_eq!(p.full.expiry_hours, 8);
        assert!(p.commands.never_ask.is_empty());
        assert!(p.hours.is_none());
        assert_eq!(
            p.protected.tool_config,
            [".git", ".envrc", ".vscode", ".idea"]
        );
        let g: FolderGrant = toml::from_str("path = \"/a\"\naccess = \"rw\"").unwrap();
        assert!(!g.execute);
    }

    #[test]
    fn broken_rules_do_not_load() {
        for text in [
            "[[policy.commands.deny]]\nregex = \"(\"\n",
            "[[policy.commands.allow]]\nexact = \"a\"\nprefix = \"b\"\n",
            "[[policy.deny]]\npath = \"relative\"\n",
            "[[policy.deny]]\npath = \"/a\"\nrights = \"q\"\n",
            "[policy.hours]\nfrom = \"25:00\"\nto = \"01:00\"\n",
            "[policy.approvals]\ntimeout_secs = 0\n",
            "[policy.protected]\ntool_config = [\"a/b\"]\n",
            "[policy.privilege]\nsudo_path = \"sudo\"\n",
        ] {
            let cfg: Result<DeviceConfig, _> = toml::from_str(text);
            let ok = cfg.is_ok_and(|c| c.policy.validate(c.profile).is_ok());
            assert!(!ok, "{text}");
        }
    }

    #[test]
    fn config_round_trips_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c/config.toml");
        let mut cfg = DeviceConfig::default();
        cfg.policy.folders.push(FolderGrant {
            path: if cfg!(windows) {
                "C:\\srv\\a"
            } else {
                "/srv/a"
            }
            .into(),
            access: Access::Ro,
            execute: true,
        });
        cfg.policy.deny.push(DenyRule {
            path: "~/x/**".into(),
            rights: "wx".parse().unwrap(),
        });
        cfg.policy.commands.deny.push(CommandRule {
            prefix: Some("rm ".into()),
            ..Default::default()
        });
        cfg.save(&path).unwrap();
        assert_eq!(DeviceConfig::load(&path).unwrap(), cfg);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(DeviceConfig::load(&dir.path().join("missing.toml")).is_ok());
        fs::write(&path, "[policy]\nmood = \"full\"\n").unwrap();
        assert!(DeviceConfig::load(&path).is_err());
    }
}
