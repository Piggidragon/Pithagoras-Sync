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
    ".config/hub",
    ".config/gcloud",
    ".azure",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".vault-token",
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
    ".bashrc.d",
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

/// Relative to the home directory: config that makes tools run commands, and
/// programs that run later in place of others (`~/.local/bin` comes early in
/// `PATH` on many systems, a fake `sudo` there would catch the password; a
/// `.desktop` file runs its `Exec=` line when its app is opened). Reading them is
/// harmless and tools need it (git's identity), so only writes prompt.
const HOME_WRITE_ONLY: &[&str] = &[
    ".gitconfig",
    ".config/git",
    ".local/bin",
    ".local/share/applications",
];

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
    "AppData/Roaming/gcloud",
    ".git-credentials",
    "_netrc",
    ".aws",
    ".kube",
    ".docker",
    ".azure",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".vault-token",
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

/// System paths on Windows come from the known folders (`KnownFolders`), since
/// Windows need not live in `C:\Windows`.
#[cfg(windows)]
const SYSTEM: &[&str] = &[];

/// Windows folders that need not be where the profile's defaults put them: a
/// Documents folder moved to OneDrive or redirected by policy (the PowerShell
/// profiles live in it), a redirected Startup folder, Windows on another drive.
/// Windows says where they are; `Protected` protects what is in them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownFolders {
    pub documents: Option<PathBuf>,
    pub startup: Option<PathBuf>,
    pub common_startup: Option<PathBuf>,
    /// `System32`.
    pub system: Option<PathBuf>,
}

impl KnownFolders {
    /// The protected entries in these folders: the PowerShell profiles in
    /// Documents, both Startup folders, and the scheduled tasks and registry hives
    /// in System32.
    pub fn entries(&self) -> Vec<PathBuf> {
        let mut v = Vec::new();
        if let Some(d) = &self.documents {
            v.push(d.join("WindowsPowerShell"));
            v.push(d.join("PowerShell"));
        }
        v.extend(self.startup.iter().cloned());
        v.extend(self.common_startup.iter().cloned());
        if let Some(s) = &self.system {
            v.push(s.join("Tasks"));
            v.push(s.join("config"));
        }
        v
    }

    /// Where Windows says they are (`SHGetKnownFolderPath`). Without an answer,
    /// the machine-wide ones fall back to `%SystemRoot%` and `%ProgramData%`, and
    /// only without those to `C:\Windows` and `C:\ProgramData`: a missing entry
    /// would leave a path unprotected.
    #[cfg(windows)]
    pub fn current() -> KnownFolders {
        use windows_sys::Win32::UI::Shell::{
            FOLDERID_CommonStartup, FOLDERID_Documents, FOLDERID_Startup, FOLDERID_System,
        };
        let env = |var: &str, fallback: &str, rest: &str| {
            let base = std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| PathBuf::from(fallback));
            Some(base.join(rest))
        };
        KnownFolders {
            documents: known_folder(&FOLDERID_Documents),
            startup: known_folder(&FOLDERID_Startup),
            common_startup: known_folder(&FOLDERID_CommonStartup).or_else(|| {
                env(
                    "ProgramData",
                    "C:\\ProgramData",
                    "Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
                )
            }),
            system: known_folder(&FOLDERID_System)
                .or_else(|| env("SystemRoot", "C:\\Windows", "System32")),
        }
    }
}

/// One known folder's path, `None` when Windows has none for this user.
#[cfg(windows)]
fn known_folder(id: &windows_sys::core::GUID) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    let mut out: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: a GUID in, a string out that the shell allocated and we free below,
    // also when the call failed (it then sets it to null or a valid allocation).
    let hr =
        unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as u32, std::ptr::null_mut(), &mut out) };
    let path = if hr >= 0 && !out.is_null() {
        // SAFETY: a NUL-terminated wide string from the shell.
        let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
        // SAFETY: `len` units before the NUL are readable.
        let wide = unsafe { std::slice::from_raw_parts(out, len) };
        Some(PathBuf::from(std::ffi::OsString::from_wide(wide)))
    } else {
        None
    };
    // SAFETY: allocated by SHGetKnownFolderPath (null is allowed).
    unsafe { CoTaskMemFree(out as *const _) };
    path.filter(|p| p.is_absolute())
}

/// Inside any folder: whose content the user's tools run. Writes there prompt.
pub(crate) const TOOL_CONFIG: &[&str] = &[".git", ".envrc", ".vscode", ".idea"];

#[derive(Debug, Clone)]
pub struct Protected {
    entries: Vec<PathBuf>,
    write_only: Vec<PathBuf>,
    /// Tool-config names, folded.
    tool_config: Vec<String>,
}

pub(crate) fn fold(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().to_lowercase())
}

pub(crate) fn expand(home: &Path, s: &str) -> Option<PathBuf> {
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
    /// `own` are the client's own config and state directories. On Windows the
    /// known folders are asked where they are.
    pub fn new(home: &Path, own: &[PathBuf], opts: &ProtectedOptions) -> Protected {
        #[cfg(windows)]
        let known = KnownFolders::current();
        #[cfg(not(windows))]
        let known = KnownFolders::default();
        Protected::with_known(home, own, opts, &known)
    }

    /// `new`, with the known folders given (tests).
    pub fn with_known(
        home: &Path,
        own: &[PathBuf],
        opts: &ProtectedOptions,
        known: &KnownFolders,
    ) -> Protected {
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
            .chain(known.entries())
            .chain(own.iter().cloned())
            .chain(opts.extra.iter().filter_map(|s| expand(home, s)));
        let write_only = HOME_WRITE_ONLY.iter().map(|r| home.join(r));
        Protected {
            entries: finish(entries, &allow),
            write_only: finish(write_only, &allow),
            tool_config: opts.tool_config.iter().map(|t| t.to_lowercase()).collect(),
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

    /// The tool-config component (`.git`, `.envrc`, ...) a write to `path` touches.
    pub fn tool_config(&self, path: &Path) -> Option<&str> {
        path.components().find_map(|c| match c {
            Component::Normal(n) => {
                let n = n.to_string_lossy().to_lowercase();
                self.tool_config
                    .iter()
                    .find(|t| **t == n)
                    .map(String::as_str)
            }
            _ => None,
        })
    }
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
            execute: false,
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
            "/home/u/.config/gcloud/application_default_credentials.json",
            "/home/u/.azure/msal_token_cache.json",
            "/home/u/.npmrc",
            "/home/u/.pypirc",
            "/home/u/.cargo/credentials.toml",
            "/home/u/.config/hub",
            "/home/u/.vault-token",
            "/home/u/.bashrc.d/x.sh",
        ] {
            assert!(p.check(Path::new(path), false, &[]).is_some(), "{path}");
        }
        // Programs that run in place of others or when an app opens: their writes.
        for path in [
            "/home/u/.local/bin/sudo",
            "/home/u/.local/share/applications/x.desktop",
        ] {
            assert!(p.check(Path::new(path), false, &[]).is_none(), "{path}");
            assert!(p.check(Path::new(path), true, &[]).is_some(), "{path}");
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
        let p = prot();
        let tool_config = |s: &str| p.tool_config(Path::new(s)).map(str::to_string);
        assert_eq!(
            tool_config("/w/p/.git/hooks/pre-commit").as_deref(),
            Some(".git")
        );
        assert_eq!(tool_config("/w/p/.envrc").as_deref(), Some(".envrc"));
        assert_eq!(
            tool_config("/w/p/.VSCode/tasks.json").as_deref(),
            Some(".vscode")
        );
        assert_eq!(tool_config("/w/p/src/git.rs"), None);
        assert_eq!(tool_config("/w/p/.github/x.yml"), None);
        // The list is the owner's: names can go and come.
        let opts = ProtectedOptions {
            tool_config: vec![".github".into()],
            ..Default::default()
        };
        let p = Protected::new(Path::new("/home/u"), &[], &opts);
        assert!(p.tool_config(Path::new("/w/p/.git/config")).is_none());
        assert!(p.tool_config(Path::new("/w/p/.github/x.yml")).is_some());
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

    /// Windows says where Documents and System32 are; a profile in a Documents
    /// folder moved elsewhere (OneDrive) and Windows on another drive are protected
    /// there. Unix paths stand in for Windows ones: the rule is the same.
    #[test]
    fn protects_profiles_and_system_paths_where_windows_has_them() {
        let known = KnownFolders {
            documents: Some("/d/OneDrive/Documents".into()),
            startup: Some("/d/Redirected/Startup".into()),
            common_startup: None,
            system: Some("/e/Win/System32".into()),
        };
        let p = Protected::with_known(
            Path::new("/home/u"),
            &[],
            &ProtectedOptions::default(),
            &known,
        );
        for path in [
            "/d/OneDrive/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
            "/d/OneDrive/Documents/PowerShell/profile.ps1",
            "/d/Redirected/Startup/run.lnk",
            "/e/Win/System32/Tasks/x",
            "/e/Win/System32/config/SAM",
        ] {
            assert!(p.check(Path::new(path), true, &[]).is_some(), "{path}");
        }
        for path in [
            "/d/OneDrive/Documents/notes.txt",
            "/e/Win/System32/drivers/etc/hosts",
        ] {
            assert!(p.check(Path::new(path), true, &[]).is_none(), "{path}");
        }
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// The real known folders: Windows answers for each, and what is in them is
    /// protected wherever they are.
    #[test]
    fn asks_windows_where_its_folders_are() {
        let k = KnownFolders::current();
        let docs = k.documents.clone().expect("a Documents folder");
        let system = k.system.clone().expect("System32");
        assert!(docs.is_absolute() && system.is_absolute(), "{k:?}");
        let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap();
        assert!(crate::paths::within(&system, &root), "{k:?}");
        let p = Protected::new(Path::new(r"C:\nobody"), &[], &ProtectedOptions::default());
        for e in [
            docs.join(r"WindowsPowerShell\profile.ps1"),
            system.join(r"Tasks\x"),
        ] {
            assert!(p.check(&e, true, &[]).is_some(), "{}", e.display());
        }
    }
}
