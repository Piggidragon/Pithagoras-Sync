//! The command line. Everything but `run` is a short-lived command that edits the
//! config as the owner, or talks to the running client over the control channel.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use sync_connector::pair;
use sync_ops::info;
use sync_policy::{Access, DeviceConfig, Dirs, FolderGrant, Mode, Policy, Profile};

use crate::actions::{self, Action};
use crate::control::{self, Request, Status};
use crate::{install, owner, setup};

#[derive(Parser)]
#[command(
    name = "pithagoras-sync",
    version,
    about = "Lets a Pithagoras portal's agent reach this computer's files and shell, within the limits you set here."
)]
pub struct Cli {
    /// More log output.
    #[arg(short, long, global = true)]
    pub verbose: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run the client (what the systemd unit or the logon task starts).
    Run {
        /// Windows: let go of the console window.
        #[arg(long, hide = true)]
        detach: bool,
    },
    /// Pair with a portal, using the URI it shows under Settings, Devices.
    Pair {
        uri: String,
        /// Device name shown in the portal (a-z, 0-9 and -, up to 24); default from
        /// the host name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Forget the pairing. Remove the device in the portal as well.
    Unpair,
    /// Show what the client is doing.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Stop everything at once: close the link, kill every command, deny every call
    /// until `unlock`.
    Panic,
    /// End a pause.
    Unlock,
    /// Show or hide the quick-ask overlay (comes with the desktop app, phase 2).
    Toggle,
    /// Show the mode, or set it: ask, folders or full.
    Mode {
        mode: Option<ModeArg>,
        /// Hours until Full falls back (0: never). Default 8.
        #[arg(long)]
        expiry_hours: Option<u32>,
    },
    /// The folders the portal may use in Folders mode.
    Folder {
        #[command(subcommand)]
        cmd: FolderCmd,
    },
    /// Start the client with the machine (systemd unit, or a logon task on Windows).
    Install {
        /// A system unit instead of a user unit (run as root).
        #[arg(long)]
        system: bool,
        /// With --system: the user the client runs as (default: root).
        #[arg(long, requires = "system")]
        user: Option<String>,
        /// Do not enable lingering for a user unit on a machine without a desktop.
        #[arg(long)]
        no_linger: bool,
        /// Only show what would be done.
        #[arg(long)]
        print: bool,
    },
    /// Undo `install` (config, pairing and the program stay).
    Uninstall {
        #[arg(long)]
        system: bool,
        #[arg(long)]
        print: bool,
    },
    /// On a server, as root: create (or remove) a dedicated user running the client.
    Setup {
        #[arg(long, conflicts_with = "remove", required_unless_present = "remove")]
        create_user: bool,
        #[arg(long)]
        remove: bool,
        #[arg(long, default_value = setup::DEFAULT_USER)]
        name: String,
        /// Do not ask before making the changes.
        #[arg(short, long)]
        yes: bool,
        /// Only show what would be done.
        #[arg(long)]
        print: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ModeArg {
    Ask,
    Folders,
    Full,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Mode {
        match m {
            ModeArg::Ask => Mode::Ask,
            ModeArg::Folders => Mode::Folders,
            ModeArg::Full => Mode::Full,
        }
    }
}

#[derive(Subcommand)]
pub enum FolderCmd {
    /// Grant a folder, read-only unless --rw.
    Add {
        path: PathBuf,
        #[arg(long)]
        rw: bool,
    },
    Remove {
        path: PathBuf,
    },
    List,
}

fn now_ms() -> i64 {
    sync_policy::system_clock()()
}

pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        false
    }
}

/// The profile of a fresh config: desktop where someone can answer notifications.
/// Windows has no approvals in phase 1, so it counts as headless there.
fn detect_profile() -> Profile {
    if cfg!(windows) || is_root() || info::session() == "headless" {
        Profile::Headless
    } else {
        Profile::Desktop
    }
}

async fn reload_running(dirs: &Dirs) {
    match control::send(&dirs.socket(), Request::Reload).await {
        Ok(Some(r)) if !r.ok => eprintln!(
            "the running client kept its old config: {}",
            r.error.unwrap_or_default()
        ),
        Ok(Some(_)) => println!("The running client took the change."),
        _ => {}
    }
}

/// The config file, or a new config for this machine when there is none yet. The
/// profile is detected once, by whichever command writes the file first, so a
/// `folder add` before `pair` on a desktop does not make it headless.
fn load_config(dirs: &Dirs) -> Result<DeviceConfig, String> {
    if dirs.config_file().exists() {
        return DeviceConfig::load(&dirs.config_file());
    }
    let mut cfg = DeviceConfig {
        profile: detect_profile(),
        ..DeviceConfig::default()
    };
    cfg.policy.mode = Policy::default_mode(cfg.profile);
    Ok(cfg)
}

/// Checks that the owner makes a policy change, from outside the client's own
/// commands; returns the config to edit.
async fn owner_edit(dirs: &Dirs) -> Result<DeviceConfig, String> {
    owner::not_from_own_command(dirs).await?;
    let cfg = load_config(dirs)?;
    owner::confirm(cfg.profile)?;
    Ok(cfg)
}

fn canonical_folder(p: &Path) -> Result<PathBuf, String> {
    let c = std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if !c.is_dir() {
        return Err(format!("{} is not a folder", p.display()));
    }
    #[cfg(windows)]
    let c = PathBuf::from(sync_policy::paths::win::strip_verbatim(
        &c.to_string_lossy(),
    ));
    Ok(c)
}

fn mode_text(mode: Mode, expires: Option<i64>) -> String {
    let m = format!("{mode:?}").to_lowercase();
    match (mode, expires) {
        (Mode::Full, Some(t)) => {
            let mins = (t - now_ms()).max(0) / 60_000;
            format!("{m} (falls back in {}h {:02}m)", mins / 60, mins % 60)
        }
        (Mode::Full, None) => format!("{m} (no expiry)"),
        _ => m,
    }
}

fn print_status(s: &Status) {
    let state = format!("{:?}", s.link.state).to_lowercase();
    println!(
        "pithagoras-sync {}, running as pid {} ({:?})",
        s.version, s.pid, s.profile
    );
    match (&s.portal, &s.name) {
        (Some(p), Some(n)) => println!(
            "Portal:    {p} as {n} (device {})",
            s.device_id.as_deref().unwrap_or("?")
        ),
        _ => println!("Portal:    not paired"),
    }
    println!(
        "Link:      {state}{}",
        s.link
            .detail
            .as_ref()
            .map(|d| format!(": {d}"))
            .unwrap_or_default()
    );
    if s.paused {
        println!("PAUSED:    every call is denied until `pithagoras-sync unlock`");
    }
    println!("Mode:      {}", mode_text(s.mode, s.mode_expires_ms));
    if s.folders.is_empty() {
        println!("Folders:   none");
    }
    for f in &s.folders {
        println!("Folder:    {} ({:?})", f.path, f.access);
    }
    println!(
        "Shell:     {} ({} in Folders mode)",
        s.shell, s.folders_shell
    );
    println!("Approvals: {}", s.approvals);
    println!(
        "Commands:  {} running; own cgroup per command: {}; Landlock: {}",
        s.running_commands,
        if s.cgroups { "yes" } else { "no" },
        if s.landlock { "yes" } else { "no" }
    );
    println!("Config:    {}", s.config_file);
    println!("Audit log: {}", s.audit_file);
}

fn show_plan(plan: &[Action]) {
    for a in plan {
        println!("  - {}", a.describe());
    }
}

fn ask(question: &str) -> bool {
    use std::io::Write;
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok()
        && matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn apply_plan(plan: &[Action]) -> Result<(), String> {
    let hints = actions::apply(plan, Path::new("/"), &actions::System)?;
    for h in hints {
        eprintln!("note: {h}");
    }
    Ok(())
}

pub async fn run(cli: Cli) -> Result<ExitCode, String> {
    let dirs = Dirs::from_env()?;
    match cli.cmd {
        Cmd::Run { detach } => {
            #[cfg(windows)]
            if detach {
                // SAFETY: FreeConsole has no preconditions.
                unsafe { windows_sys::Win32::System::Console::FreeConsole() };
            }
            #[cfg(not(windows))]
            let _ = detach;
            crate::daemon::run(dirs).await?;
        }
        Cmd::Pair { uri, name } => {
            let mut cfg = owner_edit(&dirs).await?;
            let name = name
                .or_else(|| cfg.portal.as_ref().map(|p| p.name.clone()))
                .unwrap_or_else(|| pair::name_from_hostname(&info::hostname()));
            if let Some(old) = &cfg.portal {
                println!("Replacing the pairing with {}.", old.url);
            }
            if is_root() {
                eprintln!(
                    "warning: pairing as root. The portal's agent will act with root's rights wherever the policy allows; a dedicated user is safer (see `pithagoras-sync setup --create-user`)."
                );
            }
            let paired = pair::pair(&uri, &name).await?;
            pair::save_token(&dirs.token_file(), &paired.token)?;
            cfg.portal = Some(paired.portal.clone());
            cfg.save(&dirs.config_file())?;
            println!(
                "Paired with {} as {} (device {}).",
                paired.portal.url, paired.portal.name, paired.portal.device_id
            );
            println!("Mode: {:?}.", cfg.policy.mode);
            if cfg.policy.mode == Mode::Folders && cfg.policy.folders.is_empty() {
                println!(
                    "Grant a folder next: pithagoras-sync folder add <path> --rw (nothing is reachable until then)."
                );
            }
            match control::send(&dirs.socket(), Request::Reload).await {
                Ok(Some(_)) => println!("The running client connects now."),
                _ => println!("Start it with the machine: pithagoras-sync install"),
            }
        }
        Cmd::Unpair => {
            owner::not_from_own_command(&dirs).await?;
            let mut cfg = DeviceConfig::load(&dirs.config_file())?;
            cfg.portal = None;
            cfg.save(&dirs.config_file())?;
            match std::fs::remove_file(dirs.token_file()) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("{}: {e}", dirs.token_file().display()));
                }
                _ => {}
            }
            reload_running(&dirs).await;
            println!("Unpaired. Remove the device in the portal as well.");
        }
        Cmd::Status { json } => match control::send(&dirs.socket(), Request::Status).await? {
            Some(r) => match r.status {
                Some(s) if json => {
                    println!("{}", serde_json::to_string_pretty(&s).unwrap_or_default())
                }
                Some(s) => print_status(&s),
                None => return Err(r.error.unwrap_or_default()),
            },
            None => {
                let cfg = DeviceConfig::load(&dirs.config_file())?;
                if json {
                    println!("{}", serde_json::json!({"running": false}));
                } else {
                    println!("pithagoras-sync is not running.");
                    match &cfg.portal {
                        Some(p) => println!("Paired with {} as {}.", p.url, p.name),
                        None => println!("Not paired."),
                    }
                    println!(
                        "Mode: {}",
                        mode_text(
                            cfg.policy.effective_mode(cfg.profile, now_ms()),
                            cfg.policy.full.until_ms
                        )
                    );
                    if dirs.paused_file().exists() {
                        println!("Paused: it will start paused.");
                    }
                }
                return Ok(ExitCode::from(3));
            }
        },
        Cmd::Panic => match control::send(&dirs.socket(), Request::Panic).await? {
            Some(r) if r.ok => {
                println!("Paused: link closed, commands killed. `pithagoras-sync unlock` ends it.")
            }
            Some(r) => return Err(r.error.unwrap_or_default()),
            None => {
                sync_policy::config::write_private(&dirs.paused_file(), b"")
                    .map_err(|e| e.to_string())?;
                println!("The client is not running; it will start paused.");
            }
        },
        Cmd::Unlock => {
            owner_edit(&dirs).await?;
            match control::send(&dirs.socket(), Request::Unlock).await? {
                Some(r) if r.ok => println!("Unlocked."),
                Some(r) => return Err(r.error.unwrap_or_default()),
                None => {
                    match std::fs::remove_file(dirs.paused_file()) {
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                            return Err(e.to_string());
                        }
                        _ => {}
                    }
                    println!("Unlocked.");
                }
            }
        }
        Cmd::Toggle => {
            eprintln!(
                "toggle shows the quick-ask overlay, which comes with the desktop app (phase 2); this build has none."
            );
            return Ok(ExitCode::from(2));
        }
        Cmd::Mode { mode, expiry_hours } => {
            let Some(mode) = mode else {
                let cfg = load_config(&dirs)?;
                println!(
                    "{}",
                    mode_text(
                        cfg.policy.effective_mode(cfg.profile, now_ms()),
                        cfg.policy.full.until_ms
                    )
                );
                return Ok(ExitCode::SUCCESS);
            };
            let mut cfg = owner_edit(&dirs).await?;
            if let Some(h) = expiry_hours {
                cfg.policy.full.expiry_hours = h;
            }
            cfg.policy.set_mode(mode.into(), now_ms());
            cfg.save(&dirs.config_file())?;
            if cfg.policy.mode == Mode::Full {
                println!(
                    "Full mode: the portal's agent can do whatever {} can do here{}.",
                    info::user().0,
                    if cfg.policy.full.expiry_hours == 0 {
                        ", with no expiry".to_string()
                    } else {
                        format!(", for {} hours", cfg.policy.full.expiry_hours)
                    }
                );
            }
            println!(
                "Mode: {}",
                mode_text(cfg.policy.mode, cfg.policy.full.until_ms)
            );
            reload_running(&dirs).await;
        }
        Cmd::Folder { cmd } => match cmd {
            FolderCmd::List => {
                let cfg = DeviceConfig::load(&dirs.config_file())?;
                for f in &cfg.policy.folders {
                    println!("{} ({:?})", f.path.display(), f.access);
                }
            }
            FolderCmd::Add { path, rw } => {
                let mut cfg = owner_edit(&dirs).await?;
                let path = canonical_folder(&path)?;
                let access = if rw { Access::Rw } else { Access::Ro };
                cfg.policy.folders.retain(|f| f.path != path);
                cfg.policy.folders.push(FolderGrant {
                    path: path.clone(),
                    access,
                });
                cfg.save(&dirs.config_file())?;
                println!("Granted {} ({access:?}).", path.display());
                reload_running(&dirs).await;
            }
            FolderCmd::Remove { path } => {
                let mut cfg = owner_edit(&dirs).await?;
                let canonical = canonical_folder(&path).ok();
                let before = cfg.policy.folders.len();
                cfg.policy
                    .folders
                    .retain(|f| f.path != path && Some(&f.path) != canonical.as_ref());
                if cfg.policy.folders.len() == before {
                    return Err(format!("{} is not granted", path.display()));
                }
                cfg.save(&dirs.config_file())?;
                println!("Removed {}.", path.display());
                reload_running(&dirs).await;
            }
        },
        Cmd::Install {
            system,
            user,
            no_linger,
            print,
        } => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let plan = install_plan(system, user.as_deref(), !no_linger, &exe)?;
            println!("Install:");
            show_plan(&plan);
            if !print {
                apply_plan(&plan)?;
                println!("Installed. `pithagoras-sync status` shows the running client.");
            }
        }
        Cmd::Uninstall { system, print } => {
            let plan = uninstall_plan(system)?;
            println!("Uninstall:");
            show_plan(&plan);
            if !print {
                apply_plan(&plan)?;
                println!("Uninstalled.");
            }
        }
        Cmd::Setup {
            create_user,
            remove,
            name,
            yes,
            print,
        } => {
            if !cfg!(target_os = "linux") {
                return Err("setup is for Linux servers".into());
            }
            if !is_root() && !print {
                return Err("setup needs root: sudo pithagoras-sync setup ...".into());
            }
            let runner = actions::System;
            let plan = if create_user {
                let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                setup::create_plan(&runner, Path::new("/"), &name, &exe)?
            } else {
                debug_assert!(remove);
                setup::remove_plan(&runner, &name)?
            };
            println!("This will:");
            show_plan(&plan);
            if remove {
                println!("  (the home folder of {name} and everything in it is deleted)");
            }
            if print {
                return Ok(ExitCode::SUCCESS);
            }
            if !yes && !ask("Go ahead?") {
                println!("Nothing changed.");
                return Ok(ExitCode::from(1));
            }
            apply_plan(&plan)?;
            if create_user {
                print!("{}", setup::next_steps(&name));
            } else {
                println!("Removed.");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn install_plan(
    system: bool,
    user: Option<&str>,
    linger: bool,
    exe: &Path,
) -> Result<Vec<Action>, String> {
    if cfg!(windows) {
        if system {
            return Err("on Windows the client runs as a logon task of the current user; there is no --system".into());
        }
        let local = std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA is not set")?;
        let user_id = format!(
            "{}\\{}",
            std::env::var("USERDOMAIN").unwrap_or_default(),
            std::env::var("USERNAME").unwrap_or_default()
        );
        return Ok(install::windows_plan(&local, exe, &user_id));
    }
    if system {
        if !is_root() {
            return Err("--system needs root: sudo pithagoras-sync install --system".into());
        }
        if let Some(u) = user {
            actions::System
                .run(&actions::argv(&["getent", "passwd", u]))
                .map_err(|_| format!("there is no user {u}"))?;
        }
        return Ok(install::system_plan(exe, user));
    }
    if is_root() {
        return Err(
            "as root, install a system unit: sudo pithagoras-sync install --system [--user <name>]"
                .into(),
        );
    }
    let home = info::home().ok_or("cannot find the home directory")?;
    let linger = linger && info::session() == "headless";
    Ok(install::user_plan(&home, exe, &info::user().0, linger))
}

fn uninstall_plan(system: bool) -> Result<Vec<Action>, String> {
    if cfg!(windows) {
        let local = std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA is not set")?;
        return Ok(install::windows_uninstall_plan(&local));
    }
    if system {
        if !is_root() {
            return Err("--system needs root".into());
        }
        return Ok(install::system_uninstall_plan());
    }
    let home = info::home().ok_or("cannot find the home directory")?;
    Ok(install::user_uninstall_plan(&home))
}

use crate::actions::Runner as _;
