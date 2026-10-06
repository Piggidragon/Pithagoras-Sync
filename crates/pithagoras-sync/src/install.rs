//! `install` and `uninstall`: start the client with the machine.
//!
//! Linux: a systemd user unit (desktop, or a server user with lingering), or with
//! `--system` a system unit (`User=` a dedicated user, or root). Windows: a
//! per-user logon task in Task Scheduler, not a service (session 0 has no desktop).

use std::path::{Path, PathBuf};

use crate::actions::{Action, argv};

pub const UNIT_NAME: &str = "pithagoras-sync.service";
pub const TASK_NAME: &str = "Pithagoras Sync";
pub const SYSTEM_BIN: &str = "/usr/local/bin/pithagoras-sync";
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

/// The user unit. The program lives in `~/.local/bin`.
pub fn user_unit() -> String {
    format!(
        "[Unit]
Description={DESCRIPTION}
Documentation={DOCS}

[Service]
ExecStart=%h/.local/bin/pithagoras-sync run
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
    let runs_as = |unit: &str| {
        unit.lines()
            .find_map(|l| l.trim().strip_prefix("User="))
            .map(|u| u.trim().to_string())
    };
    if system_unit.and_then(runs_as).as_deref() == Some(user) {
        format!("Start it: sudo systemctl start {UNIT_NAME}")
    } else if user_unit {
        format!("Start it: systemctl --user start {UNIT_NAME}")
    } else {
        "Start it with the machine: pithagoras-sync install".into()
    }
}

pub fn user_plan(home: &Path, exe: &Path, user: &str, linger: bool) -> Vec<Action> {
    let mut v = vec![
        Action::Copy {
            from: exe.to_path_buf(),
            to: home.join(".local/bin/pithagoras-sync"),
            mode: 0o755,
        },
        Action::Write {
            path: home.join(".config/systemd/user").join(UNIT_NAME),
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

pub fn user_uninstall_plan(home: &Path) -> Vec<Action> {
    vec![
        Action::Try {
            argv: argv(&["systemctl", "--user", "disable", "--now", UNIT_NAME]),
            hint: "the unit was not enabled".into(),
        },
        Action::Remove {
            path: home.join(".config/systemd/user").join(UNIT_NAME),
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
    let target = format!(r"{base}\Programs\pithagoras-sync\pithagoras-sync.exe");
    let xml_path = format!(r"{base}\pithagoras-sync\logon-task.xml");
    vec![
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
    ]
}

pub fn windows_uninstall_plan(local_app_data: &str) -> Vec<Action> {
    let base = local_app_data.trim_end_matches('\\');
    vec![
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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{Fake, apply};

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
