//! `install` and `uninstall`: start the client with the machine.
//!
//! Linux: a systemd user unit (desktop, or a server user with lingering), or with
//! `--system` a system unit (`User=` a dedicated user, or root). Windows: a
//! per-user logon task in Task Scheduler, not a service (session 0 has no desktop).
//!
//! On a desktop, `install` also registers the program for `pithagoras-sync://`
//! links, so the pairing link in the portal opens it: a `.desktop` file and an
//! icon on Linux, a key under `HKEY_CURRENT_USER\Software\Classes` on Windows.

use std::path::{Path, PathBuf};

use crate::actions::{Action, argv};

pub const UNIT_NAME: &str = "pithagoras-sync.service";
pub const TASK_NAME: &str = "Pithagoras Sync";

/// Whether the logon task `install` makes is there (Windows): for the window's
/// menu and `uninstall --purge` alike.
pub fn task_installed(runner: &dyn crate::actions::Runner) -> bool {
    runner
        .try_run(&crate::actions::argv(&[
            "schtasks", "/Query", "/TN", TASK_NAME,
        ]))
        .is_ok()
}
pub const SYSTEM_BIN: &str = "/usr/local/bin/pithagoras-sync";
/// Where `install` puts the program for one user on Linux, below the home
/// directory: the user unit, the desktop entry and the windows all name it.
pub const USER_PROGRAM: &str = ".local/bin/pithagoras-sync";
/// The URI scheme of the pairing link.
pub const SCHEME: &str = "pithagoras-sync";
/// The desktop entry, in `<data home>/applications`.
pub const DESKTOP_FILE: &str = "pithagoras-sync.desktop";
/// The icon, built into the program (the release is one file).
pub const ICON: &[u8] = include_bytes!("../../../assets/pithagoras-sync.svg");
/// The icon's name in the icon theme: the desktop entry and the windows name it.
pub const ICON_NAME: &str = "pithagoras-sync";
/// The icon in the raster sizes desktops look for first, made from the SVG
/// (`assets/`): a lone scalable SVG in a user's `hicolor` folder is not always
/// picked up.
pub const ICON_PNGS: [(u32, &[u8]); 4] = [
    (48, include_bytes!("../../../assets/pithagoras-sync-48.png")),
    (64, include_bytes!("../../../assets/pithagoras-sync-64.png")),
    (
        128,
        include_bytes!("../../../assets/pithagoras-sync-128.png"),
    ),
    (
        256,
        include_bytes!("../../../assets/pithagoras-sync-256.png"),
    ),
];
/// The link handler's key under `HKEY_CURRENT_USER`.
pub const WINDOWS_CLASS_KEY: &str = r"Software\Classes\pithagoras-sync";
const DESCRIPTION: &str = "Pithagoras Sync: lets a Pithagoras portal's agent reach this computer";
const DOCS: &str = "https://github.com/Piggidragon/Pithagoras-Sync";

const SERVICE_BODY: &str = "Type=simple
Restart=on-failure
RestartSec=5
# Each command the portal runs gets its own cgroup below this unit's, so a
# timeout, panic or disconnect can kill all of it.
Delegate=yes
KillMode=control-group
UMask=0077
";

/// Where `install` puts the program on Windows, below `%LOCALAPPDATA%`.
pub const WINDOWS_PROGRAM: &str = r"Programs\pithagoras-sync\pithagoras-sync.exe";
/// Where `install` puts the user unit on Linux, below the home directory.
const USER_UNIT_FOLDER: &str = ".config/systemd/user";

/// The program `install` puts in `home` (`USER_PROGRAM`).
pub fn user_program(home: &Path) -> PathBuf {
    home.join(USER_PROGRAM)
}

/// The folder of the user unit in `home`.
pub fn user_unit_folder(home: &Path) -> PathBuf {
    home.join(USER_UNIT_FOLDER)
}

/// The user unit `install` writes in `home`.
pub fn user_unit_file(home: &Path) -> PathBuf {
    user_unit_folder(home).join(UNIT_NAME)
}

/// The program `install` puts in `local_app_data` (`%LOCALAPPDATA%`), built with
/// `\` whichever platform computes it (tests run on Linux).
pub fn windows_program(local_app_data: &str) -> String {
    format!(
        r"{}\{WINDOWS_PROGRAM}",
        local_app_data.trim_end_matches('\\')
    )
}

/// The user unit. The program lives in `~/.local/bin` (`USER_PROGRAM`).
pub fn user_unit() -> String {
    format!(
        "[Unit]
Description={DESCRIPTION}
Documentation={DOCS}

[Service]
ExecStart=%h/{USER_PROGRAM} run
{SERVICE_BODY}
[Install]
WantedBy=default.target
"
    )
}

/// The system unit, running as `user`, or as root when `user` is `None`.
pub fn system_unit(user: Option<&str>) -> String {
    let user_line = match user {
        Some(u) => format!("User={u}\n"),
        // Named all the same: only with a User= line does systemd set HOME, which
        // the client needs to find its config.
        None => "User=root\n".to_string(),
    };
    format!(
        "[Unit]
Description={DESCRIPTION}
Documentation={DOCS}
After=network-online.target
Wants=network-online.target

[Service]
{user_line}ExecStart={SYSTEM_BIN} run
{SERVICE_BODY}
[Install]
WantedBy=multi-user.target
"
    )
}

/// What `pair` says when no client runs yet: start the unit that exists for
/// `user` (`setup` enables its system unit but leaves it stopped), or install one.
pub fn start_hint(system_unit: Option<&str>, user: &str, user_unit: bool) -> String {
    if system_unit.and_then(unit_user).as_deref() == Some(user) {
        format!("Start it: sudo systemctl start {UNIT_NAME}")
    } else if user_unit {
        format!("Start it: systemctl --user start {UNIT_NAME}")
    } else {
        "Start it with the machine: pithagoras-sync install".into()
    }
}

/// The user a system unit runs the client as: its `User=` line.
pub fn unit_user(unit: &str) -> Option<String> {
    unit.lines()
        .find_map(|l| l.trim().strip_prefix("User="))
        .map(|u| u.trim().to_string())
}

pub fn user_plan(home: &Path, exe: &Path, user: &str, linger: bool) -> Vec<Action> {
    let mut v = vec![
        Action::Copy {
            from: exe.to_path_buf(),
            to: user_program(home),
            mode: 0o755,
        },
        Action::Write {
            path: user_unit_file(home),
            content: user_unit().into_bytes(),
            mode: 0o644,
        },
        Action::Run {
            argv: argv(&["systemctl", "--user", "daemon-reload"]),
        },
        Action::Run {
            argv: argv(&["systemctl", "--user", "enable", "--now", UNIT_NAME]),
        },
    ];
    if linger {
        v.push(Action::Try {
            argv: argv(&["loginctl", "enable-linger", user]),
            hint: format!(
                "run `sudo loginctl enable-linger {user}` so the client also runs while {user} is not logged in"
            ),
        });
    }
    v
}

/// The desktop entry's `Exec=` program, quoted as the Desktop Entry
/// Specification asks: inside double quotes `"`, `` ` ``, `$` and `\` take a
/// backslash, then every backslash is doubled for the file's string escapes, and
/// `%` is doubled since it starts a field code.
fn desktop_exec_arg(program: &str) -> String {
    let mut q = String::from("\"");
    for c in program.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            q.push('\\');
        }
        q.push(c);
    }
    q.push('"');
    q.replace('\\', "\\\\").replace('%', "%%")
}

/// The `.desktop` file: in the menu as "Pithagoras Sync", the handler of
/// `pithagoras-sync://` links. Both start `gui`, which takes the link when
/// there is one (`%u`).
pub fn desktop_entry(program: &Path) -> Result<String, String> {
    let p = program
        .to_str()
        .filter(|p| !p.chars().any(char::is_control))
        .ok_or_else(|| format!("{}: not a path a desktop entry can name", program.display()))?;
    Ok(format!(
        "[Desktop Entry]
Type=Application
Name=Pithagoras Sync
Comment=Lets your Pithagoras portal's agent reach this computer
Comment[de]=Lässt den Agenten deines Pithagoras-Portals diesen Computer erreichen
Exec={} gui %u
Icon=pithagoras-sync
Terminal=false
Categories=Network;
MimeType=x-scheme-handler/{SCHEME};
",
        desktop_exec_arg(p)
    ))
}

/// The user's `hicolor` icon folder below the data home.
fn hicolor(data_home: &Path) -> PathBuf {
    data_home.join("icons/hicolor")
}

/// The icon's path below the data home.
pub fn icon_path(data_home: &Path) -> PathBuf {
    hicolor(data_home).join("scalable/apps/pithagoras-sync.svg")
}

/// The raster icon of `size` pixels below the data home.
pub fn png_icon_path(data_home: &Path, size: u32) -> PathBuf {
    hicolor(data_home).join(format!("{size}x{size}/apps/pithagoras-sync.png"))
}

/// Every icon file `install` writes below the data home.
pub fn icon_paths(data_home: &Path) -> Vec<PathBuf> {
    let mut v = vec![icon_path(data_home)];
    v.extend(ICON_PNGS.iter().map(|(s, _)| png_icon_path(data_home, *s)));
    v
}

/// The icon cache of the user's `hicolor` folder. Most have none: GTK then
/// reads the folders themselves. One that is there is trusted while the
/// folder is not newer than it, which a file added to a subfolder does not
/// change, so it must be rebuilt after one.
pub fn icon_cache(data_home: &Path) -> PathBuf {
    hicolor(data_home).join("icon-theme.cache")
}

/// Rebuilds the icon cache of the user's `hicolor` folder (`-t`: the folder
/// has no `index.theme` of its own), so the menu and the windows find the
/// icon without a new login. Only where there is one (`icon_cache`): a cache
/// made here would hide the icons other programs add later without
/// rebuilding it.
fn icon_cache_update(data_home: &Path, hint: &str) -> Action {
    Action::Try {
        argv: argv(&[
            "gtk-update-icon-cache",
            "-f",
            "-t",
            &hicolor(data_home).to_string_lossy(),
        ]),
        hint: hint.into(),
    }
}

/// The desktop entry, the icon and the link handler for the program `install`
/// put in place. The tools are best effort: one that is missing is a note.
/// `cache`: the user's `hicolor` folder has an icon cache (`icon_cache`).
pub fn desktop_plan(data_home: &Path, program: &Path, cache: bool) -> Result<Vec<Action>, String> {
    let apps = data_home.join("applications");
    let mut plan = vec![Action::Write {
        path: icon_path(data_home),
        content: ICON.to_vec(),
        mode: 0o644,
    }];
    plan.extend(ICON_PNGS.iter().map(|(size, png)| Action::Write {
        path: png_icon_path(data_home, *size),
        content: png.to_vec(),
        mode: 0o644,
    }));
    if cache {
        plan.push(icon_cache_update(
            data_home,
            "the menu may show Pithagoras Sync with a generic icon until the next login",
        ));
    }
    plan.extend([
        Action::Write {
            path: apps.join(DESKTOP_FILE),
            content: desktop_entry(program)?.into_bytes(),
            mode: 0o644,
        },
        Action::Try {
            argv: argv(&["update-desktop-database", &apps.to_string_lossy()]),
            hint: "the menu may show Pithagoras Sync only after the next login".into(),
        },
        Action::Try {
            argv: argv(&[
                "xdg-mime",
                "default",
                DESKTOP_FILE,
                &format!("x-scheme-handler/{SCHEME}"),
            ]),
            hint: "pairing links may not open Pithagoras Sync; paste the link into it instead (Pithagoras Sync in the menu)".into(),
        },
    ]);
    Ok(plan)
}

/// The desktop's list of default programs, in its config home: where
/// `xdg-mime default` wrote the link handler.
pub fn mimeapps_file(config_home: &Path) -> PathBuf {
    config_home.join("mimeapps.list")
}

/// The type `xdg-mime default` set the handler for.
fn scheme_mime() -> String {
    format!("x-scheme-handler/{SCHEME}")
}

/// Whether the desktop's list of default programs still names the program as
/// the handler of its links.
pub fn mime_handler_left(config_home: &Path) -> bool {
    std::fs::read_to_string(mimeapps_file(config_home)).is_ok_and(|t| {
        crate::actions::without_mime_handler(&t, &scheme_mime(), DESKTOP_FILE).is_some()
    })
}

/// Undoes `desktop_plan`: the entry, the icons and the folders that held
/// them, and the program as the handler of its links in the desktop's list
/// of default programs (`config_home/mimeapps.list`): that line only, and no
/// other program's. `cache`: as for `desktop_plan`; the cache is rebuilt
/// without the icon, and stays.
pub fn desktop_uninstall_plan(data_home: &Path, config_home: &Path, cache: bool) -> Vec<Action> {
    let apps = data_home.join("applications");
    let mut plan = vec![Action::Remove {
        path: apps.join(DESKTOP_FILE),
    }];
    let icons = icon_paths(data_home);
    plan.extend(
        icons
            .iter()
            .map(|path| Action::Remove { path: path.clone() }),
    );
    // `<size>x<size>/apps` and then `<size>x<size>`: made by the install, and
    // left empty by it. The folders of the icon theme above them are the
    // desktop's, and a folder with anything else in it stays.
    for icon in &icons {
        for dir in icon.ancestors().skip(1).take(2) {
            plan.push(Action::RemoveEmptyDir {
                path: dir.to_path_buf(),
            });
        }
    }
    plan.push(Action::DropMimeHandler {
        path: mimeapps_file(config_home),
        mime: scheme_mime(),
        desktop: DESKTOP_FILE.into(),
    });
    if cache {
        plan.push(icon_cache_update(
            data_home,
            "the icon cache may list Pithagoras Sync's icon until it is rebuilt",
        ));
    }
    plan.push(Action::Try {
        argv: argv(&["update-desktop-database", &apps.to_string_lossy()]),
        hint: "the menu may show Pithagoras Sync until the next login".into(),
    });
    plan
}

/// The `pithagoras-sync://` handler on Windows, for the program at `exe`:
/// `HKCU\Software\Classes\pithagoras-sync` with `URL Protocol` and the command
/// `"<exe>" "%1"`.
pub fn windows_link_plan(exe: &str) -> Vec<Action> {
    let set = |key: &str, name: &str, value: &str| Action::RegSet {
        key: key.to_string(),
        name: name.to_string(),
        value: value.to_string(),
    };
    let command = format!(r"{WINDOWS_CLASS_KEY}\shell\open\command");
    vec![
        set(WINDOWS_CLASS_KEY, "", "URL:Pithagoras Sync pairing link"),
        set(WINDOWS_CLASS_KEY, "URL Protocol", ""),
        set(&command, "", &format!("\"{exe}\" \"%1\"")),
    ]
}

pub fn windows_link_uninstall_plan() -> Vec<Action> {
    vec![Action::RegDelete {
        key: WINDOWS_CLASS_KEY.into(),
    }]
}

pub fn user_uninstall_plan(home: &Path) -> Vec<Action> {
    vec![
        Action::Try {
            argv: argv(&["systemctl", "--user", "disable", "--now", UNIT_NAME]),
            hint: "the unit was not enabled".into(),
        },
        Action::Remove {
            path: user_unit_file(home),
        },
        Action::Run {
            argv: argv(&["systemctl", "--user", "daemon-reload"]),
        },
    ]
}

pub fn system_plan(exe: &Path, user: Option<&str>) -> Vec<Action> {
    vec![
        Action::Copy {
            from: exe.to_path_buf(),
            to: PathBuf::from(SYSTEM_BIN),
            mode: 0o755,
        },
        Action::Write {
            path: Path::new("/etc/systemd/system").join(UNIT_NAME),
            content: system_unit(user).into_bytes(),
            mode: 0o644,
        },
        Action::Run {
            argv: argv(&["systemctl", "daemon-reload"]),
        },
        Action::Run {
            argv: argv(&["systemctl", "enable", "--now", UNIT_NAME]),
        },
    ]
}

pub fn system_uninstall_plan() -> Vec<Action> {
    vec![
        Action::Try {
            argv: argv(&["systemctl", "disable", "--now", UNIT_NAME]),
            hint: "the unit was not enabled".into(),
        },
        Action::Remove {
            path: Path::new("/etc/systemd/system").join(UNIT_NAME),
        },
        Action::Run {
            argv: argv(&["systemctl", "daemon-reload"]),
        },
    ]
}

/// For `uninstall --purge`: stops the client the user unit starts, so it does
/// not write its files again while they are removed. Nothing is removed here.
pub fn user_stop_plan() -> Vec<Action> {
    vec![Action::Try {
        argv: argv(&["systemctl", "--user", "stop", UNIT_NAME]),
        hint: "it was not running".into(),
    }]
}

/// `user_stop_plan` for the system unit.
pub fn system_stop_plan() -> Vec<Action> {
    vec![Action::Try {
        argv: argv(&["systemctl", "stop", UNIT_NAME]),
        hint: "it was not running".into(),
    }]
}

/// What the unit or task was before `uninstall --purge` stopped it, so a purge
/// that fails puts back that and no more: a unit the owner had switched off
/// stays off, and a client that was not running is not started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Before {
    /// Switched on: starts with the login or the machine.
    pub enabled: bool,
    /// A client was running: the unit was up, or one answered on the control
    /// channel (Windows has no state of the task to ask that is not in the
    /// system's language).
    pub running: bool,
}

/// Asks the service manager what the unit or task is now, before the purge
/// stops it. `client_running`: a client answered on the control channel.
/// What it cannot find out counts as off, so a failed purge never switches on
/// what it does not know was on.
pub fn state_before(
    windows: bool,
    system: bool,
    runner: &dyn crate::actions::Runner,
    client_running: bool,
) -> Before {
    if windows {
        let enabled = runner
            .try_run(&argv(&["schtasks", "/Query", "/TN", TASK_NAME, "/XML"]))
            .is_ok_and(|xml| task_enabled(&xml));
        return Before {
            enabled,
            running: client_running,
        };
    }
    let systemctl = |args: &[&str]| {
        let mut a = vec!["systemctl"];
        if !system {
            a.push("--user");
        }
        a.extend(args);
        a.push(UNIT_NAME);
        runner.try_run(&argv(&a))
    };
    // `is-enabled` exits non-zero for anything that is not switched on.
    let enabled = systemctl(&["is-enabled"]).is_ok_and(|s| s.trim() == "enabled");
    // A unit between two starts (`activating`) is up as well.
    let active = systemctl(&["show", "-p", "ActiveState", "--value"])
        .is_ok_and(|s| !matches!(s.trim(), "" | "inactive" | "failed"));
    Before {
        enabled,
        running: client_running || active,
    }
}

/// Whether the logon task's definition (`schtasks /Query /XML`) has it
/// switched on: `<Enabled>false</Enabled>` in its settings is off, the same in
/// every language. A definition without its settings counts as off.
pub fn task_enabled(xml: &str) -> bool {
    let Some(settings) = xml
        .find("<Settings>")
        .and_then(|i| xml[i..].find("</Settings>").map(|j| &xml[i..i + j]))
    else {
        return false;
    };
    // Task Scheduler leaves the element out where it is on (the default).
    match settings.find("<Enabled>") {
        None => true,
        Some(i) => {
            let rest = &settings[i + "<Enabled>".len()..];
            rest.split('<').next().is_some_and(|v| v.trim() == "true")
        }
    }
}

/// Puts back what the stop of `uninstall --purge` (and the `disable` of the
/// uninstall after it) changed, as `before` says it was, when the purge fails
/// while the unit or task is still there. Empty where nothing was on.
pub fn restart_plan(windows: bool, system: bool, before: Before) -> Vec<Action> {
    if windows {
        // A switched-off task cannot be run, so a client started by hand
        // beside it is not started again.
        if !before.enabled {
            return Vec::new();
        }
        let mut plan = vec![Action::Run {
            argv: argv(&["schtasks", "/Change", "/TN", TASK_NAME, "/ENABLE"]),
        }];
        if before.running {
            plan.push(Action::Try {
                argv: argv(&["schtasks", "/Run", "/TN", TASK_NAME]),
                hint: "the task starts it within a minute".into(),
            });
        }
        return plan;
    }
    let systemctl = |what: &str| {
        let mut a = vec!["systemctl"];
        if !system {
            a.push("--user");
        }
        a.extend([what, UNIT_NAME]);
        Action::Run { argv: argv(&a) }
    };
    let mut plan = Vec::new();
    if before.enabled {
        plan.push(systemctl("enable"));
    }
    if before.running {
        plan.push(systemctl("start"));
    }
    plan
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The logon task for `user_id` (a SID): starts `exe run --detach` at logon with the
/// user's normal rights and never stops it. Task Scheduler's restart on failure only
/// covers a start that failed, not a program that exited with an error (a crash, or
/// the restart after `update`). So a second trigger fires every minute (from a start
/// in the past, so from the moment the task exists, not only after the next logon);
/// a client still running makes it a no-op (`IgnoreNew`), and `InteractiveToken`
/// keeps it from running while the user is logged off.
pub fn task_xml(user_id: &str, exe: &str) -> String {
    let user = xml_escape(user_id);
    let exe = xml_escape(exe);
    let desc = xml_escape(DESCRIPTION);
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{desc}</Description>
    <URI>\{TASK_NAME}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
    <TimeTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>2020-01-01T00:00:00</StartBoundary>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>run --detach</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// schtasks reads task XML reliably as UTF-16 with a byte order mark.
pub fn utf16_with_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xff, 0xfe];
    for u in s.replace('\n', "\r\n").encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// A SID in its string form, `S-1-5-21-...`, from its parts.
pub fn sid_string(authority: [u8; 6], sub_authorities: &[u32]) -> String {
    // The authority is a 48-bit big-endian number; in practice it fits in a byte.
    let auth = authority
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let mut s = format!("S-1-{auth}");
    for sub in sub_authorities {
        s.push_str(&format!("-{sub}"));
    }
    s
}

/// The SID of the user this process runs as: the logon task names its user by SID.
/// `USERDOMAIN\USERNAME` from the environment is wrong in an ssh session, where
/// `USERDOMAIN` is `WORKGROUP`, and Task Scheduler then refuses the task.
#[cfg(windows)]
pub fn current_user_sid() -> Result<String, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount,
        GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle needs no closing; the token handle is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(format!(
            "no process token: {}",
            std::io::Error::last_os_error()
        ));
    }
    // u64s keep the buffer aligned for TOKEN_USER.
    let mut buf = vec![0u64; 64];
    let mut len = 0u32;
    // SAFETY: the buffer holds `buf.len() * 8` bytes and outlives the call.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut len,
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: the token handle is ours.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(format!("cannot read the token's user: {err}"));
    }
    // SAFETY: GetTokenInformation filled the buffer with a TOKEN_USER whose SID
    // points into the same buffer; the SID functions only read it.
    unsafe {
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = user.User.Sid;
        let auth = (*GetSidIdentifierAuthority(sid)).Value;
        let count = *GetSidSubAuthorityCount(sid);
        let subs: Vec<u32> = (0..u32::from(count))
            .map(|i| *GetSidSubAuthority(sid, i))
            .collect();
        Ok(sid_string(auth, &subs))
    }
}

/// `local_app_data` is `%LOCALAPPDATA%`; paths are built with `\` so the plan is the
/// same whichever platform computes it (tests run it on Linux).
pub fn windows_plan(local_app_data: &str, exe: &Path, user_id: &str) -> Vec<Action> {
    let base = local_app_data.trim_end_matches('\\');
    let target = windows_program(base);
    let xml_path = format!(r"{base}\pithagoras-sync\logon-task.xml");
    let mut plan = vec![
        // A running client holds its program open, and the copy over it would fail:
        // `install` again (to repair or update by hand) ends the task first.
        Action::Try {
            argv: argv(&["schtasks", "/End", "/TN", TASK_NAME]),
            // Not running (every first install): no news, no note.
            hint: String::new(),
        },
        Action::Copy {
            from: exe.to_path_buf(),
            to: PathBuf::from(&target),
            mode: 0o755,
        },
        Action::Write {
            path: PathBuf::from(&xml_path),
            content: utf16_with_bom(&task_xml(user_id, &target)),
            mode: 0o600,
        },
        Action::Run {
            argv: argv(&[
                "schtasks", "/Create", "/TN", TASK_NAME, "/XML", &xml_path, "/F",
            ]),
        },
        Action::Try {
            argv: argv(&["schtasks", "/Run", "/TN", TASK_NAME]),
            hint: "it starts at the next logon".into(),
        },
    ];
    plan.extend(windows_link_plan(&target));
    plan
}

/// `user_stop_plan` for the logon task: switched off first, or its minute
/// trigger starts the client again before the task is deleted.
pub fn windows_stop_plan() -> Vec<Action> {
    vec![
        Action::Try {
            argv: argv(&["schtasks", "/Change", "/TN", TASK_NAME, "/DISABLE"]),
            hint: "the task may start the client again within a minute".into(),
        },
        Action::Try {
            argv: argv(&["schtasks", "/End", "/TN", TASK_NAME]),
            // Not running (every first install): no news, no note.
            hint: String::new(),
        },
    ]
}

/// `task`: whether the logon task is there (`task_installed`). Without it
/// there is nothing to end or delete, and `uninstall` again succeeds.
pub fn windows_uninstall_plan(local_app_data: &str, task: bool) -> Vec<Action> {
    let base = local_app_data.trim_end_matches('\\');
    let mut plan = Vec::new();
    if task {
        plan.extend([
            Action::Try {
                argv: argv(&["schtasks", "/End", "/TN", TASK_NAME]),
                // Not running (every first install): no news, no note.
                hint: String::new(),
            },
            Action::Run {
                argv: argv(&["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]),
            },
        ]);
    }
    plan.push(Action::Remove {
        path: PathBuf::from(format!(r"{base}\pithagoras-sync\logon-task.xml")),
    });
    plan.extend(windows_link_uninstall_plan());
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{Fake, apply};

    /// Only the task's own setting counts, not its triggers'; a definition
    /// that cannot be read counts as off.
    #[test]
    fn a_switched_off_task_is_read_from_its_settings() {
        let on = task_xml("S-1-5-21-1", r"C:\p.exe");
        assert!(task_enabled(&on));
        let settings_off = on.replace(
            "<Enabled>true</Enabled>\n  </Settings>",
            "<Enabled>false</Enabled>\n  </Settings>",
        );
        assert_ne!(settings_off, on);
        assert!(!task_enabled(&settings_off));
        let triggers_off = on.replacen("<Enabled>true</Enabled>", "<Enabled>false</Enabled>", 2);
        assert!(task_enabled(&triggers_off));
        assert!(task_enabled(&on.replace(
            "    <Enabled>true</Enabled>\n  </Settings>",
            "  </Settings>"
        )));
        assert!(!task_enabled(""));
        assert!(!task_enabled("ERROR: access denied"));
    }

    /// What the unit was before the purge, asked of systemd, with what it
    /// cannot tell taken as off.
    #[test]
    fn the_state_before_the_purge_is_asked_of_the_service_manager() {
        let fake = |enabled: Result<&str, &str>, active: &str| Fake {
            answers: vec![
                (
                    "systemctl is-enabled".into(),
                    enabled.map(String::from).map_err(String::from),
                ),
                ("systemctl show".into(), Ok(active.into())),
            ],
            ..Fake::default()
        };
        let b = |enabled, running| Before { enabled, running };
        for (enabled, active, client, want) in [
            (Ok("enabled\n"), "active\n", false, b(true, true)),
            (Ok("enabled\n"), "activating\n", false, b(true, true)),
            (Err("disabled"), "inactive\n", false, b(false, false)),
            (Err("disabled"), "failed\n", true, b(false, true)),
            (Ok("static\n"), "inactive\n", false, b(false, false)),
            (Err("no bus"), "", false, b(false, false)),
        ] {
            let f = fake(enabled, active);
            assert_eq!(
                state_before(false, true, &f, client),
                want,
                "{enabled:?} {active}"
            );
        }
        // The user unit is asked with --user.
        let f = Fake::default();
        state_before(false, false, &f, false);
        let ran = f.ran.lock().unwrap();
        assert_eq!(ran.len(), 2);
        assert!(ran.iter().all(|a| a[1] == "--user"), "{ran:?}");
        // Windows: the task's definition, and the control channel for the client.
        let f = Fake {
            answers: vec![(
                "schtasks /Query".into(),
                Ok(task_xml("S-1-5-21-1", r"C:\p.exe")),
            )],
            ..Fake::default()
        };
        assert_eq!(state_before(true, false, &f, true), b(true, true));
        let f = Fake {
            answers: vec![("schtasks /Query".into(), Err("no such task".into()))],
            ..Fake::default()
        };
        assert_eq!(state_before(true, false, &f, false), b(false, false));
    }

    #[test]
    fn the_logon_task_is_switched_off_before_it_is_ended() {
        let plan = windows_stop_plan();
        let argv = |a: &Action| match a {
            Action::Try { argv, .. } | Action::Run { argv } => argv.join(" "),
            _ => String::new(),
        };
        // The minute trigger would start the client again between the two.
        assert!(argv(&plan[0]).contains("/Change") && argv(&plan[0]).ends_with("/DISABLE"));
        assert!(argv(&plan[1]).contains("/End"));
        assert_eq!(plan.len(), 2);
        assert!(argv(&user_stop_plan()[0]).ends_with(&format!("stop {UNIT_NAME}")));
    }

    #[test]
    fn pair_names_the_unit_that_exists_for_this_user() {
        let unit = system_unit(Some("pithagoras-sync"));
        assert_eq!(
            start_hint(Some(&unit), "pithagoras-sync", false),
            "Start it: sudo systemctl start pithagoras-sync.service"
        );
        // The system unit is another user's: this one has none yet.
        assert_eq!(
            start_hint(Some(&unit), "alice", false),
            "Start it with the machine: pithagoras-sync install"
        );
        assert_eq!(
            start_hint(Some(&system_unit(None)), "root", false),
            "Start it: sudo systemctl start pithagoras-sync.service"
        );
        assert_eq!(
            start_hint(None, "alice", true),
            "Start it: systemctl --user start pithagoras-sync.service"
        );
        assert_eq!(
            start_hint(None, "alice", false),
            "Start it with the machine: pithagoras-sync install"
        );
    }

    #[test]
    fn units_run_the_client_with_delegation() {
        let u = user_unit();
        assert!(u.contains("ExecStart=%h/.local/bin/pithagoras-sync run"));
        assert!(u.contains("Delegate=yes"));
        assert!(u.contains("WantedBy=default.target"));
        assert!(!u.contains("User="));
        let s = system_unit(Some("pithagoras-sync"));
        assert!(s.contains("User=pithagoras-sync\nExecStart=/usr/local/bin/pithagoras-sync run"));
        assert!(s.contains("WantedBy=multi-user.target"));
        // The root variant names root, so systemd sets HOME.
        assert!(system_unit(None).contains("User=root\nExecStart="));
    }

    /// `install` again while the client runs (to repair or update by hand): Windows
    /// refuses to replace a running program, so it goes aside to `.old`.
    #[cfg(windows)]
    #[test]
    fn a_running_program_is_replaced() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let running = bin.join("p.exe");
        std::fs::copy(
            std::path::Path::new(&std::env::var_os("SystemRoot").unwrap())
                .join(r"System32\PING.EXE"),
            &running,
        )
        .unwrap();
        let mut child = std::process::Command::new(&running)
            .args(["-n", "60", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let new = root.path().join("new.exe");
        std::fs::write(&new, b"new binary").unwrap();
        let plan = [Action::Copy {
            from: new,
            to: PathBuf::from("bin/p.exe"),
            mode: 0o755,
        }];
        let result = apply(&plan, root.path(), &Fake::default());
        let _ = child.kill();
        let _ = child.wait();
        result.unwrap();
        assert_eq!(std::fs::read(&running).unwrap(), b"new binary");
        assert!(crate::update::old_path(&running).exists());
    }

    #[test]
    fn user_install_under_a_fake_root() {
        let root = tempfile::tempdir().unwrap();
        let exe = root.path().join("download/pithagoras-sync");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"binary").unwrap();
        let home = Path::new("/home/someone");
        let fake = Fake::default();
        let plan = user_plan(home, &exe, "someone", true);
        let hints = apply(&plan, root.path(), &fake).unwrap();
        assert!(hints.is_empty());
        let r = root.path();
        assert_eq!(
            std::fs::read(r.join("home/someone/.local/bin/pithagoras-sync")).unwrap(),
            b"binary"
        );
        let unit = std::fs::read_to_string(
            r.join("home/someone/.config/systemd/user/pithagoras-sync.service"),
        )
        .unwrap();
        assert_eq!(unit, user_unit());
        let ran = fake.ran.lock().unwrap().clone();
        assert_eq!(ran[0], argv(&["systemctl", "--user", "daemon-reload"]));
        assert_eq!(
            ran[1],
            argv(&["systemctl", "--user", "enable", "--now", UNIT_NAME])
        );
        assert_eq!(ran[2], argv(&["loginctl", "enable-linger", "someone"]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(r.join("home/someone/.local/bin/pithagoras-sync"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o755);
        }
    }

    #[test]
    fn a_failing_linger_only_gives_a_hint() {
        let root = tempfile::tempdir().unwrap();
        let exe = root.path().join("exe");
        std::fs::write(&exe, b"x").unwrap();
        let fake = Fake {
            answers: vec![("loginctl enable-linger".into(), Err("denied".into()))],
            ..Fake::default()
        };
        let hints = apply(
            &user_plan(Path::new("/home/u"), &exe, "u", true),
            root.path(),
            &fake,
        )
        .unwrap();
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("sudo loginctl enable-linger u"));
        // A failing systemctl stops the install.
        let fake = Fake {
            answers: vec![("systemctl --user".into(), Err("no user manager".into()))],
            ..Fake::default()
        };
        assert!(
            apply(
                &user_plan(Path::new("/home/u"), &exe, "u", false),
                root.path(),
                &fake
            )
            .is_err()
        );
    }

    #[test]
    fn system_install_and_uninstall_under_a_fake_root() {
        let root = tempfile::tempdir().unwrap();
        let exe = root.path().join("exe");
        std::fs::write(&exe, b"x").unwrap();
        let fake = Fake::default();
        apply(&system_plan(&exe, Some("svc")), root.path(), &fake).unwrap();
        let unit = root
            .path()
            .join("etc/systemd/system/pithagoras-sync.service");
        assert!(std::fs::read_to_string(&unit).unwrap().contains("User=svc"));
        assert!(root.path().join("usr/local/bin/pithagoras-sync").exists());
        apply(&system_uninstall_plan(), root.path(), &fake).unwrap();
        assert!(!unit.exists());
        let ran = fake.ran.lock().unwrap().clone();
        assert!(ran.contains(&argv(&["systemctl", "enable", "--now", UNIT_NAME])));
        assert!(ran.contains(&argv(&["systemctl", "disable", "--now", UNIT_NAME])));
    }

    #[test]
    fn the_desktop_entry_opens_pairing_links_and_the_menu_with_gui() {
        let e = desktop_entry(Path::new("/home/someone/.local/bin/pithagoras-sync")).unwrap();
        assert!(e.contains("\nExec=\"/home/someone/.local/bin/pithagoras-sync\" gui %u\n"));
        assert!(e.contains("\nMimeType=x-scheme-handler/pithagoras-sync;\n"));
        assert!(e.contains("\nTerminal=false\n"));
        assert!(e.contains("\nIcon=pithagoras-sync\n"));
        assert!(e.contains("\nCategories=Network;\n"));
        assert!(e.contains("\nName=Pithagoras Sync\n"));
        // Quoted as the spec says: no space, quote, `$` or `%` in the path can
        // add an argument, expand a variable or become a field code.
        let e = desktop_entry(Path::new("/home/a b/$x \"q\" 100%/p\\s")).unwrap();
        assert!(
            e.contains(r#"Exec="/home/a b/\\$x \\"q\\" 100%%/p\\\\s" gui %u"#),
            "{e}"
        );
        // A path with a line break could add lines to the file.
        assert!(desktop_entry(Path::new("/home/a\nExec=evil/p")).is_err());
        assert!(desktop_plan(Path::new("/d"), Path::new("/x\ry"), false).is_err());
    }

    /// The desktop entry is Linux's: its folders are Unix paths, which a
    /// `join` on Windows would write with `\`.
    #[cfg(unix)]
    #[test]
    fn install_and_uninstall_register_and_remove_the_link_handler() {
        let root = tempfile::tempdir().unwrap();
        let data = Path::new("/home/someone/.local/share");
        let program = Path::new("/home/someone/.local/bin/pithagoras-sync");
        let fake = Fake::default();
        apply(
            &desktop_plan(data, program, true).unwrap(),
            root.path(),
            &fake,
        )
        .unwrap();
        let r = root.path();
        let entry = r.join("home/someone/.local/share/applications/pithagoras-sync.desktop");
        let icon =
            r.join("home/someone/.local/share/icons/hicolor/scalable/apps/pithagoras-sync.svg");
        assert_eq!(
            std::fs::read_to_string(&entry).unwrap(),
            desktop_entry(program).unwrap()
        );
        assert_eq!(std::fs::read(&icon).unwrap(), ICON);
        // The raster sizes next to the SVG, where GTK and KDE look first.
        for (size, png) in ICON_PNGS {
            let p = r.join(format!(
                "home/someone/.local/share/icons/hicolor/{size}x{size}/apps/pithagoras-sync.png"
            ));
            assert_eq!(std::fs::read(&p).unwrap(), png);
            assert!(png.starts_with(b"\x89PNG"));
            // The width in the PNG header is the folder's size.
            assert_eq!(u32::from_be_bytes(png[16..20].try_into().unwrap()), size);
        }
        let ran = fake.ran.lock().unwrap().clone();
        let cache = argv(&[
            "gtk-update-icon-cache",
            "-f",
            "-t",
            "/home/someone/.local/share/icons/hicolor",
        ]);
        assert_eq!(
            ran,
            [
                cache.clone(),
                argv(&[
                    "update-desktop-database",
                    "/home/someone/.local/share/applications"
                ]),
                argv(&[
                    "xdg-mime",
                    "default",
                    "pithagoras-sync.desktop",
                    "x-scheme-handler/pithagoras-sync"
                ]),
            ]
        );
        // A missing tool is a note, not a failed install.
        let missing = Fake {
            answers: vec![("xdg-mime default".into(), Err("xdg-mime: not found".into()))],
            ..Fake::default()
        };
        let hints = apply(&desktop_plan(data, program, true).unwrap(), r, &missing).unwrap();
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("paste the link"), "{hints:?}");
        // Without gtk-update-icon-cache the icon is still written.
        let no_cache = Fake {
            answers: vec![(
                "gtk-update-icon-cache -f".into(),
                Err("gtk-update-icon-cache: not found".into()),
            )],
            ..Fake::default()
        };
        let hints = apply(&desktop_plan(data, program, true).unwrap(), r, &no_cache).unwrap();
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("generic icon"), "{hints:?}");
        let uninstall = Fake::default();
        apply(
            &desktop_uninstall_plan(data, Path::new("/home/someone/.config"), true),
            r,
            &uninstall,
        )
        .unwrap();
        assert!(!entry.exists() && !icon.exists());
        for p in icon_paths(data) {
            assert!(!crate::actions::rooted(r, &p).exists(), "{}", p.display());
        }
        assert!(uninstall.ran.lock().unwrap().contains(&cache));
        // Without an icon cache none is made, on install or uninstall: one
        // made here would hide icons other programs add later.
        let fake = Fake::default();
        apply(&desktop_plan(data, program, false).unwrap(), r, &fake).unwrap();
        apply(
            &desktop_uninstall_plan(data, Path::new("/home/someone/.config"), false),
            r,
            &fake,
        )
        .unwrap();
        let ran = fake.ran.lock().unwrap().clone();
        assert!(
            ran.iter().all(|a| a[0] != "gtk-update-icon-cache"),
            "{ran:?}"
        );
        assert_eq!(
            icon_cache(data),
            Path::new("/home/someone/.local/share/icons/hicolor/icon-theme.cache")
        );
        // The plans as `--print` lists them.
        let listed: Vec<String> = desktop_plan(data, program, true)
            .unwrap()
            .iter()
            .map(Action::describe)
            .collect();
        assert!(
            listed
                .iter()
                .any(|l| l.ends_with("applications/pithagoras-sync.desktop"))
        );
        assert!(listed.iter().any(|l| l.contains("xdg-mime default")));
        assert!(
            listed
                .iter()
                .any(|l| l.ends_with("hicolor/256x256/apps/pithagoras-sync.png")),
            "{listed:?}"
        );
        assert!(
            listed
                .iter()
                .any(|l| l.contains("gtk-update-icon-cache -f -t")),
            "{listed:?}"
        );
    }

    /// Uninstalling takes back what installing made: the icon folders it left
    /// empty (never one with something else in it, and never the icon theme's
    /// own `hicolor`), and the program as the handler of its links in the
    /// desktop's list of default programs (never another entry).
    #[cfg(unix)]
    #[test]
    fn uninstall_leaves_no_empty_icon_folders_and_no_handler_line() {
        let root = tempfile::tempdir().unwrap();
        let (data, config) = (root.path().join("share"), root.path().join("config"));
        let program = root.path().join("bin/pithagoras-sync");
        let hicolor = data.join("icons/hicolor");
        let list = config.join("mimeapps.list");
        // Another program's icon in one of the sizes.
        let other = hicolor.join("48x48/apps/other.png");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::write(&other, "png").unwrap();
        let fake = Fake::default();
        apply(
            &desktop_plan(&data, &program, false).unwrap(),
            Path::new("/"),
            &fake,
        )
        .unwrap();
        // What `xdg-mime default` wrote, among the owner's own entries.
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            &list,
            "[Default Applications]\nx-scheme-handler/pithagoras-sync=pithagoras-sync.desktop\nx-scheme-handler/https=browser.desktop\n",
        )
        .unwrap();
        assert!(mime_handler_left(&config));
        for dir in [
            "64x64/apps",
            "128x128/apps",
            "256x256/apps",
            "scalable/apps",
        ] {
            assert!(hicolor.join(dir).is_dir(), "{dir}");
        }
        let plan = desktop_uninstall_plan(&data, &config, false);
        // `--print` lists what it would do.
        assert!(plan.iter().any(|a| a.describe().contains(&format!(
            "remove {} if it is empty",
            hicolor.join("64x64/apps").display()
        ))));
        assert!(plan.iter().any(|a| a.describe().contains(&format!(
            "take pithagoras-sync.desktop out of the handlers of x-scheme-handler/pithagoras-sync in {}",
            list.display()
        ))));
        apply(&plan, Path::new("/"), &fake).unwrap();
        for dir in ["64x64", "128x128", "256x256", "scalable"] {
            assert!(!hicolor.join(dir).exists(), "{dir}");
        }
        // The other program's icon keeps its folders, and the theme stays.
        assert!(other.is_file());
        assert!(hicolor.is_dir());
        assert_eq!(
            std::fs::read_to_string(&list).unwrap(),
            "[Default Applications]\nx-scheme-handler/https=browser.desktop\n"
        );
        assert!(!mime_handler_left(&config));
        // Again, with nothing left: no error.
        apply(&plan, Path::new("/"), &fake).unwrap();
    }

    /// Ending a logon task that does not run (on every first install) is no
    /// news: it adds no note. A start that failed does.
    #[test]
    fn a_task_that_was_not_running_adds_no_note() {
        let tries = |plan: Vec<Action>| -> Vec<Action> {
            plan.into_iter()
                .filter(|a| matches!(a, Action::Try { .. }))
                .collect()
        };
        let fake = Fake {
            answers: vec![
                ("schtasks /End".into(), Err("`schtasks /End` failed".into())),
                ("schtasks /Run".into(), Err("`schtasks /Run` failed".into())),
            ],
            ..Fake::default()
        };
        let root = tempfile::tempdir().unwrap();
        let install = tries(windows_plan(r"C:\x", Path::new("p.exe"), "S-1"));
        assert_eq!(
            apply(&install, root.path(), &fake).unwrap(),
            ["`schtasks /Run` failed: it starts at the next logon"]
        );
        for plan in [windows_stop_plan(), windows_uninstall_plan(r"C:\x", true)] {
            assert_eq!(
                apply(&tries(plan), root.path(), &fake).unwrap(),
                Vec::<String>::new()
            );
        }
    }

    #[test]
    fn the_windows_link_handler_is_the_current_users_alone() {
        let plan = windows_plan(
            r"C:\Users\ann\AppData\Local",
            Path::new("pithagoras-sync.exe"),
            "S-1-5-21-1",
        );
        let fake = Fake::default();
        let root = tempfile::tempdir().unwrap();
        let regs: Vec<Action> = plan
            .into_iter()
            .filter(|a| matches!(a, Action::RegSet { .. }))
            .collect();
        apply(&regs, root.path(), &fake).unwrap();
        let ran = fake.ran.lock().unwrap().clone();
        let exe = r"C:\Users\ann\AppData\Local\Programs\pithagoras-sync\pithagoras-sync.exe";
        assert_eq!(
            ran,
            [
                argv(&[
                    "reg",
                    "set",
                    r"Software\Classes\pithagoras-sync",
                    "",
                    "URL:Pithagoras Sync pairing link"
                ]),
                argv(&[
                    "reg",
                    "set",
                    r"Software\Classes\pithagoras-sync",
                    "URL Protocol",
                    ""
                ]),
                argv(&[
                    "reg",
                    "set",
                    r"Software\Classes\pithagoras-sync\shell\open\command",
                    "",
                    &format!("\"{exe}\" \"%1\"")
                ]),
            ]
        );
        assert!(
            regs[0]
                .describe()
                .starts_with(r"set HKCU\Software\Classes\pithagoras-sync")
        );
        let un = windows_uninstall_plan(r"C:\Users\ann\AppData\Local", true);
        assert_eq!(
            un.last(),
            Some(&Action::RegDelete {
                key: r"Software\Classes\pithagoras-sync".into()
            })
        );
        let schtasks = |plan: &[Action]| -> Vec<String> {
            plan.iter()
                .filter_map(|a| match a {
                    Action::Try { argv, .. } | Action::Run { argv } => Some(argv[1].clone()),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(schtasks(&un), ["/End", "/Delete"]);
        // Uninstalled already: nothing for schtasks to fail on, the rest again.
        let again = windows_uninstall_plan(r"C:\Users\ann\AppData\Local", false);
        assert!(schtasks(&again).is_empty(), "{again:?}");
        assert_eq!(again[..], un[2..]);
        // The real runner refuses the registry off Windows rather than doing
        // something else.
        #[cfg(not(windows))]
        assert!(
            crate::actions::Runner::reg_set(&crate::actions::System, "Software\\x", "", "")
                .is_err()
        );
    }

    #[test]
    fn sids_in_string_form() {
        assert_eq!(
            sid_string(
                [0, 0, 0, 0, 0, 5],
                &[21, 1111111111, 2222222222, 3333333333, 1001]
            ),
            "S-1-5-21-1111111111-2222222222-3333333333-1001"
        );
        assert_eq!(sid_string([0, 0, 0, 0, 0, 16], &[12288]), "S-1-16-12288");
    }

    #[test]
    fn windows_logon_task() {
        let x = task_xml(
            r"PC\Ann & Bob",
            r"C:\Users\ann\AppData\Local\Programs\pithagoras-sync\pithagoras-sync.exe",
        );
        assert!(x.contains(r"<UserId>PC\Ann &amp; Bob</UserId>"));
        assert!(x.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(x.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(x.contains("<Arguments>run --detach</Arguments>"));
        assert!(x.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        // Started again within a minute after it exits, whatever its exit code.
        assert!(x.contains("<TimeTrigger>"));
        assert!(x.contains("<Repetition>\n        <Interval>PT1M</Interval>"));
        assert!(x.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
        let bytes = utf16_with_bom("a\nb");
        assert_eq!(
            bytes,
            vec![0xff, 0xfe, b'a', 0, b'\r', 0, b'\n', 0, b'b', 0]
        );
        let plan = windows_plan(
            r"C:\Users\ann\AppData\Local\",
            Path::new("pithagoras-sync.exe"),
            r"PC\ann",
        );
        let Action::Try { argv: end, .. } = &plan[0] else {
            panic!("{plan:?}")
        };
        assert_eq!(end, &argv(&["schtasks", "/End", "/TN", TASK_NAME]));
        let Action::Run { argv: create } = &plan[3] else {
            panic!("{plan:?}")
        };
        assert_eq!(
            create,
            &argv(&[
                "schtasks",
                "/Create",
                "/TN",
                TASK_NAME,
                "/XML",
                r"C:\Users\ann\AppData\Local\pithagoras-sync\logon-task.xml",
                "/F"
            ])
        );
        let Action::Copy { to, .. } = &plan[1] else {
            panic!()
        };
        assert_eq!(
            to,
            Path::new(r"C:\Users\ann\AppData\Local\Programs\pithagoras-sync\pithagoras-sync.exe")
        );
    }
}
