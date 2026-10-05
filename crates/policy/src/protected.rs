//! Protected paths: places whose content gives away secrets or runs code later.
//!
//! They prompt in every mode (in Full only while its protection is on) unless the
//! owner grants them by name: a folder grant at or inside the protected path, or an
//! entry in `protected.allow`. A grant of a whole home does not release `~/.ssh`.
//! Matching ignores case, so a case-insensitive filesystem cannot slip `~/.SSH` past.

use std::path::{Component, Path, PathBuf};

use crate::config::{FolderGrant, ProtectedOptions};
use crate::paths::{resolve, within};

/// Relative to the home directory.
#[cfg(not(windows))]
const HOME: &[&str] = &[
    // keys and credentials
    ".ssh",
    ".gnupg",
    ".local/share/keyrings",
    ".local/share/kwalletd",
    ".kde/share/apps/kwallet",
    ".kde4/share/apps/kwallet",
    ".password-store",
    ".config/keepassxc",
    ".config/Bitwarden",
    ".config/1Password",
    ".git-credentials",
    ".netrc",
    ".aws",
    ".kube",
    ".docker",
    ".config/gh",
    // browser and mail profiles
    ".mozilla",
    ".librewolf",
    ".thunderbird",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".config/vivaldi",
    ".config/microsoft-edge",
    ".config/opera",
    ".var/app",
    ".local/share/flatpak/app",
    // shell start-up and session environment
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".config/fish",
    ".config/nushell",
    ".xprofile",
    ".xinitrc",
    ".xsession",
    ".xsessionrc",
    ".pam_environment",
    ".config/environment.d",
    // autostart, systemd user units, cron
    ".config/autostart",
    ".config/autostart-scripts",
    ".config/plasma-workspace",
    ".kde/Autostart",
    ".config/systemd",
    ".local/share/systemd",
];

/// Relative to the home directory: config that makes tools run commands. Reading
/// it is harmless and tools need it (git's identity), so only writes prompt.
const HOME_WRITE_ONLY: &[&str] = &[".gitconfig", ".config/git"];

/// Relative to the user profile on Windows.
#[cfg(windows)]
const HOME: &[&str] = &[
    // keys and credentials
    ".ssh",
    ".gnupg",
    "AppData/Roaming/gnupg",
    "AppData/Roaming/Microsoft/Credentials",
    "AppData/Local/Microsoft/Credentials",
    "AppData/Roaming/Microsoft/Protect",
    "AppData/Roaming/Microsoft/Vault",
    "AppData/Local/Microsoft/Vault",
    "AppData/Roaming/Microsoft/Crypto",
    "AppData/Roaming/Microsoft/SystemCertificates",
    "AppData/Roaming/Bitwarden",
    "AppData/Roaming/KeePass",
    "AppData/Roaming/KeePassXC",
    "AppData/Local/1Password",
    "AppData/Roaming/GitHub CLI",
    ".git-credentials",
    "_netrc",
    ".aws",
    ".kube",
    ".docker",
    // browser and mail profiles
    "AppData/Local/Google/Chrome/User Data",
    "AppData/Local/Microsoft/Edge/User Data",
    "AppData/Local/BraveSoftware",
    "AppData/Local/Vivaldi",
    "AppData/Roaming/Mozilla",
    "AppData/Roaming/Opera Software",
    "AppData/Roaming/Thunderbird",
    // start-up, shell profiles and history
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
    "AppData/Roaming/Microsoft/Windows/PowerShell",
    "Documents/WindowsPowerShell",
    "Documents/PowerShell",
];

/// System paths, for a client that runs as root (or reads what others may write).
#[cfg(not(windows))]
const SYSTEM: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/etc/pam.d",
    "/etc/security",
    "/etc/polkit-1",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/etc/systemd",
    "/etc/profile",
    "/etc/profile.d",
    "/etc/environment",
    "/etc/bash.bashrc",
    "/etc/zsh",
    "/etc/xdg/autostart",
];

/// System paths on Windows: machine-wide start-up and scheduled tasks.
#[cfg(windows)]
const SYSTEM: &[&str] = &[
    "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp",
    "C:/Windows/System32/Tasks",
    "C:/Windows/System32/config",
];

/// Inside any folder: whose content the user's tools run. Writes there prompt.
const TOOL_CONFIG: &[&str] = &[".git", ".envrc", ".vscode", ".idea"];

#[derive(Debug, Clone)]
pub struct Protected {
    entries: Vec<PathBuf>,
    write_only: Vec<PathBuf>,
}

fn fold(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().to_lowercase())
}

fn expand(home: &Path, s: &str) -> Option<PathBuf> {
    if let Some(rest) = s.strip_prefix("~/") {
        Some(home.join(rest))
    } else if s == "~" {
        Some(home.to_path_buf())
    } else if Path::new(s).is_absolute() {
        Some(PathBuf::from(s))
    } else {
        None
    }
}

/// Folds a list, adds each entry's resolved form (resolved paths are what gets
/// checked, also when the home is a symlink and the entry does not exist yet) and
/// drops what the owner released.
fn finish(list: impl Iterator<Item = PathBuf>, allow: &[PathBuf]) -> Vec<PathBuf> {
    let mut all: Vec<PathBuf> = list.collect();
    let real: Vec<PathBuf> = all.iter().filter_map(|e| resolve(e).ok()).collect();
    all.extend(real);
    let mut all: Vec<PathBuf> = all.iter().map(|e| fold(e)).collect();
    all.retain(|e| !allow.contains(e));
    all.sort();
    all.dedup();
    all
}

impl Protected {
    /// `own` are the client's own config and state directories.
    pub fn new(home: &Path, own: &[PathBuf], opts: &ProtectedOptions) -> Protected {
        let allow: Vec<PathBuf> = opts
            .allow
            .iter()
            .filter_map(|s| expand(home, s))
            .map(|p| fold(&p))
            .collect();
        let entries = HOME
            .iter()
            .map(|r| home.join(r))
            .chain(SYSTEM.iter().map(PathBuf::from))
            .chain(own.iter().cloned())
            .chain(opts.extra.iter().filter_map(|s| expand(home, s)));
        let write_only = HOME_WRITE_ONLY.iter().map(|r| home.join(r));
        Protected {
            entries: finish(entries, &allow),
            write_only: finish(write_only, &allow),
        }
    }

    /// The protected entry `path` falls in, unless a folder grant names it.
    pub fn check(&self, path: &Path, write: bool, grants: &[FolderGrant]) -> Option<&Path> {
        let folded = fold(path);
        let mut candidates = self.entries.iter();
        let mut write_only = self.write_only.iter().filter(|_| write);
        let entry = candidates
            .find(|e| within(&folded, e))
            .or_else(|| write_only.find(|e| within(&folded, e)))?;
        // Granted by name: a grant at or inside the protected entry that holds `path`.
        let named = grants.iter().any(|g| {
            let gf = fold(&g.path);
            within(&gf, entry) && within(&folded, &gf)
        });
        if named { None } else { Some(entry) }
    }

    /// Protected entries strictly inside `dir`, writes included when `write` (to carve
    /// out of a Landlock rule).
    pub fn inside(&self, dir: &Path, write: bool) -> Vec<&Path> {
        let folded = fold(dir);
        let write_only = self.write_only.iter().filter(|_| write);
        self.entries
            .iter()
            .chain(write_only)
            .filter(|e| e.as_path() != folded && within(e, &folded))
            .map(|e| e.as_path())
            .collect()
    }

    /// Write-only protected entries (readable by the confined shell).
    pub fn write_only(&self) -> &[PathBuf] {
        &self.write_only
    }

    /// All entries, folded to lowercase.
    pub fn entries(&self) -> impl Iterator<Item = &PathBuf> {
        self.entries.iter().chain(&self.write_only)
    }
}

/// The tool-config component (`.git`, `.envrc`, ...) a write to `path` touches.
pub fn tool_config(path: &Path) -> Option<&'static str> {
    path.components().find_map(|c| match c {
        Component::Normal(n) => {
            let n = n.to_string_lossy().to_lowercase();
            TOOL_CONFIG.iter().copied().find(|t| *t == n)
        }
        _ => None,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sync_proto::methods::Access;

    fn prot() -> Protected {
        Protected::new(
            Path::new("/home/u"),
            &[PathBuf::from("/home/u/.config/pithagoras-sync")],
            &ProtectedOptions::default(),
        )
    }

    fn grant(p: &str) -> FolderGrant {
        FolderGrant {
            path: p.into(),
            access: Access::Rw,
        }
    }

    #[test]
    fn protects_keys_shell_startup_and_own_config() {
        let p = prot();
        for path in [
            "/home/u/.ssh",
            "/home/u/.ssh/id_ed25519",
            "/home/u/.bashrc",
            "/home/u/.config/systemd/user/x.service",
            "/home/u/.config/autostart/a.desktop",
            "/home/u/.config/pithagoras-sync/config.toml",
            "/etc/sudoers.d/x",
        ] {
            assert!(p.check(Path::new(path), false, &[]).is_some(), "{path}");
        }
        for path in ["/home/u/proj/a.rs", "/home/u/.sshx", "/home/u/.config"] {
            assert!(p.check(Path::new(path), false, &[]).is_none(), "{path}");
        }
    }

    #[test]
    fn git_config_is_protected_for_writes_only() {
        let p = prot();
        assert!(
            p.check(Path::new("/home/u/.gitconfig"), false, &[])
                .is_none()
        );
        assert!(
            p.check(Path::new("/home/u/.gitconfig"), true, &[])
                .is_some()
        );
        assert!(
            p.check(Path::new("/home/u/.config/git/config"), true, &[])
                .is_some()
        );
    }

    #[test]
    fn ignores_case() {
        let p = prot();
        assert!(
            p.check(Path::new("/home/u/.SSH/id_rsa"), false, &[])
                .is_some()
        );
        assert!(p.check(Path::new("/HOME/U/.GnuPG"), false, &[]).is_some());
    }

    #[test]
    fn released_only_by_name() {
        let p = prot();
        // A grant of the whole home does not release ~/.ssh ...
        assert!(
            p.check(Path::new("/home/u/.ssh/config"), false, &[grant("/home/u")])
                .is_some()
        );
        // ... a grant of ~/.ssh itself does.
        assert!(
            p.check(
                Path::new("/home/u/.ssh/config"),
                false,
                &[grant("/home/u/.ssh")]
            )
            .is_none()
        );
        let opts = ProtectedOptions {
            allow: vec!["~/.docker".into()],
            ..Default::default()
        };
        let p = Protected::new(Path::new("/home/u"), &[], &opts);
        assert!(
            p.check(Path::new("/home/u/.docker/x"), false, &[])
                .is_none()
        );
        assert!(p.check(Path::new("/home/u/.ssh/x"), false, &[]).is_some());
    }

    #[test]
    fn finds_tool_config_inside_folders() {
        assert_eq!(
            tool_config(Path::new("/w/p/.git/hooks/pre-commit")),
            Some(".git")
        );
        assert_eq!(tool_config(Path::new("/w/p/.envrc")), Some(".envrc"));
        assert_eq!(
            tool_config(Path::new("/w/p/.VSCode/tasks.json")),
            Some(".vscode")
        );
        assert_eq!(tool_config(Path::new("/w/p/src/git.rs")), None);
        assert_eq!(tool_config(Path::new("/w/p/.github/x.yml")), None);
    }

    #[test]
    fn a_missing_entry_under_a_symlinked_home_is_protected() {
        let t = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(t.path()).unwrap();
        std::fs::create_dir(real.join("realhome")).unwrap();
        std::os::unix::fs::symlink(real.join("realhome"), real.join("home")).unwrap();
        let p = Protected::new(&real.join("home"), &[], &ProtectedOptions::default());
        // ~/.ssh does not exist yet; the path a write resolves to is the real one.
        assert!(
            p.check(&real.join("realhome/.ssh/authorized_keys"), true, &[])
                .is_some()
        );
    }

    #[test]
    fn lists_entries_inside_a_folder() {
        let p = prot();
        let inside = p.inside(Path::new("/home/u"), false);
        assert!(inside.contains(&Path::new("/home/u/.ssh")));
        assert!(p.inside(Path::new("/home/u/proj"), true).is_empty());
        assert!(!inside.contains(&Path::new("/home/u/.gitconfig")));
        assert!(
            p.inside(Path::new("/home/u"), true)
                .contains(&Path::new("/home/u/.gitconfig"))
        );
    }
}
