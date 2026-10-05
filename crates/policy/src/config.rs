//! The device's configuration file (`config.toml`): pairing data and policy.
//!
//! The owner edits it by hand or with `pithagoras-sync mode` / `folder`; the portal
//! never writes it. The connector token lives in a separate 0600 file (`token`).

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
pub use sync_proto::methods::{Access, Mode};

/// Desktop: someone can answer approval notifications. Headless: nobody can, so
/// Ask mode does not exist and whatever would prompt is denied.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ProtectedOptions {
    /// More protected paths (absolute, or `~/...`).
    pub extra: Vec<String>,
    /// Built-in protected paths the owner releases by name (absolute, or `~/...`).
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    pub mode: Mode,
    pub folders: Vec<FolderGrant>,
    pub folders_shell: FoldersShell,
    pub full: FullOptions,
    pub protected: ProtectedOptions,
    /// An unanswered approval is denied after this long.
    pub approval_timeout_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::Folders,
            folders: Vec::new(),
            folders_shell: FoldersShell::default(),
            full: FullOptions::default(),
            protected: ProtectedOptions::default(),
            approval_timeout_secs: 120,
        }
    }
}

impl Policy {
    /// The restricted default for a profile: Ask where someone can answer, Folders
    /// (with nothing granted) where nobody can.
    pub fn default_mode(profile: Profile) -> Mode {
        match profile {
            Profile::Desktop => Mode::Ask,
            Profile::Headless => Mode::Folders,
        }
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

    pub fn validate(&self, profile: Profile) -> Result<(), String> {
        if profile == Profile::Headless && self.mode == Mode::Ask {
            return Err("Ask mode needs a desktop to answer prompts; use folders or full".into());
        }
        for f in &self.folders {
            if !f.path.is_absolute() {
                return Err(format!("folder {} is not absolute", f.path.display()));
            }
        }
        if self.approval_timeout_secs == 0 || self.approval_timeout_secs > 3600 {
            return Err("approval_timeout_secs must be between 1 and 3600".into());
        }
        Ok(())
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
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            env_passthrough: Vec::new(),
            max_timeout_secs: 4 * 3600,
            output_cap_bytes: 16 * 1024 * 1024,
            max_running: 16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct DeviceConfig {
    pub profile: Profile,
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
        Ok(cfg)
    }

    /// Writes the file atomically with mode 0600.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        self.policy.validate(self.profile)?;
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
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
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
    /// `$PITHAGORAS_SYNC_CONFIG_DIR` or the XDG directories of the current user.
    pub fn from_env() -> Result<Dirs, String> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")?;
        let xdg = |var: &str, fallback: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(fallback))
        };
        if let Some(base) = std::env::var_os("PITHAGORAS_SYNC_CONFIG_DIR") {
            return Ok(Dirs::under(Path::new(&base)));
        }
        let state = xdg("XDG_STATE_HOME", ".local/state").join("pithagoras-sync");
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .map(|p| p.join("pithagoras-sync"))
            .unwrap_or_else(|| state.join("run"));
        Ok(Dirs {
            config: xdg("XDG_CONFIG_HOME", ".config").join("pithagoras-sync"),
            state,
            runtime,
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

    /// Present while the client is paused by `panic`, until `unlock`.
    pub fn paused_file(&self) -> PathBuf {
        self.state.join("paused")
    }

    pub fn socket(&self) -> PathBuf {
        self.runtime.join("control.sock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            Mode::Folders
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
        assert_eq!(p.effective_mode(Profile::Headless, 0), Mode::Folders);
        assert!(p.date_full(5));
        assert_eq!(p.effective_mode(Profile::Headless, 5), Mode::Full);
        assert!(!p.date_full(6));
    }

    #[test]
    fn ask_does_not_exist_headless() {
        let p = Policy {
            mode: Mode::Ask,
            ..Policy::default()
        };
        assert!(p.validate(Profile::Headless).is_err());
        assert!(p.validate(Profile::Desktop).is_ok());
    }

    #[test]
    fn config_round_trips_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c/config.toml");
        let mut cfg = DeviceConfig::default();
        cfg.policy.folders.push(FolderGrant {
            path: "/srv/a".into(),
            access: Access::Ro,
        });
        cfg.save(&path).unwrap();
        assert_eq!(DeviceConfig::load(&path).unwrap(), cfg);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(DeviceConfig::load(&dir.path().join("missing.toml")).is_ok());
        fs::write(&path, "[policy]\nmood = \"full\"\n").unwrap();
        assert!(DeviceConfig::load(&path).is_err());
    }
}
