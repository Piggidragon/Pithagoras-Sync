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

/// The icon's path below the data home.
pub fn icon_path(data_home: &Path) -> PathBuf {
    data_home.join("icons/hicolor/scalable/apps/pithagoras-sync.svg")
}

/// The desktop entry, the icon and the link handler for the program `install`
/// put in place. The two tools are best effort: one that is missing is a note.
pub fn desktop_plan(data_home: &Path, program: &Path) -> Result<Vec<Action>, String> {
    let apps = data_home.join("applications");
    Ok(vec![
        Action::Write {
            path: icon_path(data_home),
            content: ICON.to_vec(),
            mode: 0o644,
        },
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
    ])
}

/// Undoes `desktop_plan`. The `x-scheme-handler` line `xdg-mime` wrote to
/// `mimeapps.list` stays: the file is the desktop's, and the line leads nowhere
/// once the entry is gone.
pub fn desktop_uninstall_plan(data_home: &Path) -> Vec<Action> {
    let apps = data_home.join("applications");
    vec![
        Action::Remove {
            path: apps.join(DESKTOP_FILE),
        },
        Action::Remove {
            path: icon_path(data_home),
        },
        Action::Try {
            argv: argv(&["update-desktop-database", &apps.to_string_lossy()]),
            hint: "the menu may show Pithagoras Sync until the next login".into(),
        },
    ]
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

/// Puts back what the stop of `uninstall --purge` (and the `disable` of the
/// uninstall after it) did, when the purge fails while the unit or task is
/// still there: switched on, and the client started.
pub fn restart_plan(windows: bool, system: bool) -> Vec<Action> {
    if windows {
        return vec![
            Action::Run {
                argv: argv(&["schtasks", "/Change", "/TN", TASK_NAME, "/ENABLE"]),
            },
            Action::Try {
                argv: argv(&["schtasks", "/Run", "/TN", TASK_NAME]),
                hint: "the task starts it within a minute".into(),
            },
        ];
    }
    let mut systemctl = vec!["systemctl"];
    if !system {
        systemctl.push("--user");
    }
    systemctl.extend(["enable", "--now", UNIT_NAME]);
    vec![Action::Run {
        argv: argv(&systemctl),
    }]
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
            hint: "it was not running".into(),
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
            hint: "it was not running".into(),
        },
    ]
}

pub fn windows_uninstall_plan(local_app_data: &str) -> Vec<Action> {
    let base = local_app_data.trim_end_matches('\\');
    let mut plan = vec![
        Action::Try {
            argv: argv(&["schtasks", "/End", "/TN", TASK_NAME]),
            hint: "it was not running".into(),
        },
        Action::Run {
            argv: argv(&["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]),
        },
        Action::Remove {
            path: PathBuf::from(format!(r"{base}\pithagoras-sync\logon-task.xml")),
        },
    ];
    plan.extend(windows_link_uninstall_plan());
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{Fake, apply};

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
        assert!(desktop_plan(Path::new("/d"), Path::new("/x\ry")).is_err());
    }

    #[test]
    fn install_and_uninstall_register_and_remove_the_link_handler() {
        let root = tempfile::tempdir().unwrap();
        let data = Path::new("/home/someone/.local/share");
        let program = Path::new("/home/someone/.local/bin/pithagoras-sync");
        let fake = Fake::default();
        apply(&desktop_plan(data, program).unwrap(), root.path(), &fake).unwrap();
        let r = root.path();
        let entry = r.join("home/someone/.local/share/applications/pithagoras-sync.desktop");
        let icon =
            r.join("home/someone/.local/share/icons/hicolor/scalable/apps/pithagoras-sync.svg");
        assert_eq!(
            std::fs::read_to_string(&entry).unwrap(),
            desktop_entry(program).unwrap()
        );
        assert_eq!(std::fs::read(&icon).unwrap(), ICON);
        let ran = fake.ran.lock().unwrap().clone();
        assert_eq!(
            ran,
            [
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
        let hints = apply(&desktop_plan(data, program).unwrap(), r, &missing).unwrap();
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("paste the link"), "{hints:?}");
        apply(&desktop_uninstall_plan(data), r, &Fake::default()).unwrap();
        assert!(!entry.exists() && !icon.exists());
        // The plans as `--print` lists them.
        let listed: Vec<String> = desktop_plan(data, program)
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
        let un = windows_uninstall_plan(r"C:\Users\ann\AppData\Local");
        assert_eq!(
            un.last(),
            Some(&Action::RegDelete {
                key: r"Software\Classes\pithagoras-sync".into()
            })
        );
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
