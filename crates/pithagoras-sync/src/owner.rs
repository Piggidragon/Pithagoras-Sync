//! Who may change the policy: the device owner, never the portal or the agent.
//!
//! On a headless machine the shell login is the authentication (spec 10.1). On a
//! Linux desktop, a change also asks for the user's password in a terminal (through
//! `su`, so PAM checks it), which a command the agent runs cannot type. In both
//! cases a change from a command the client itself runs is refused. The windows
//! (`gui`) ask for the same password in a dialog and give it to `su` on a
//! terminal of its own (`check_password`).

use sync_policy::secret::Secret;
use sync_policy::{Dirs, Profile};

use crate::control::{self, Request};

/// Refuses when this process descends from the running client, i.e. the portal's
/// agent runs it.
pub async fn not_from_own_command(dirs: &Dirs) -> Result<(), String> {
    if let Ok(Some(r)) = control::send(&dirs.socket(), Request::Status).await
        && let Some(s) = r.status
        && control::descends_from(std::process::id(), s.pid)
    {
        return Err(
            "policy changes cannot come from commands the client runs for the portal".into(),
        );
    }
    Ok(())
}

/// Confirms that the owner makes this change.
pub fn confirm(profile: Profile) -> Result<(), String> {
    if !password_needed(profile) {
        return Ok(());
    }
    confirm_desktop()
}

/// Whether a change in this profile asks for the user's password: on a Linux
/// desktop. Windows has no way to check it (`confirm_desktop`).
pub fn password_needed(profile: Profile) -> bool {
    profile != Profile::Headless && cfg!(unix)
}

/// How long `su` may take to check the password, its delay after a wrong one
/// included.
#[cfg(target_os = "linux")]
const PASSWORD_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Checks the user's password with `su` as `confirm` does, for the windows:
/// `su` runs on a pseudo-terminal of its own, and the password typed into the
/// dialog is written to it once `su` switched echo off for its prompt. It is
/// never in an argument or the environment. `Ok(false)`: `su` refused it.
#[cfg(target_os = "linux")]
pub async fn check_password(pw: &Secret) -> Result<bool, String> {
    let user = account()?;
    let cmd = su_check(&user)?;
    let pw = pw.clone();
    tokio::task::spawn_blocking(move || pty::answer(cmd, &pw, PASSWORD_WAIT))
        .await
        .map_err(|e| e.to_string())?
}

#[cfg(not(target_os = "linux"))]
pub async fn check_password(_pw: &Secret) -> Result<bool, String> {
    Err("the password can be checked in a window only on Linux".into())
}

/// A program on a pseudo-terminal, answered with a password.
#[cfg(target_os = "linux")]
mod pty {
    use std::ffi::CStr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use sync_policy::secret::Secret;

    fn os_err(what: &str) -> String {
        format!("{what}: {}", std::io::Error::last_os_error())
    }

    /// A new pseudo-terminal: its master and the path of its other end.
    fn open() -> Result<(OwnedFd, std::ffi::CString), String> {
        // SAFETY: plain libc calls; the descriptor is owned right after.
        let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(os_err("no pseudo-terminal"));
        }
        // SAFETY: fd is a new descriptor of ours.
        let master = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: on the master just opened.
        if unsafe { libc::grantpt(fd) } != 0 || unsafe { libc::unlockpt(fd) } != 0 {
            return Err(os_err("no pseudo-terminal"));
        }
        let mut name = [0 as libc::c_char; 128];
        // SAFETY: the buffer is of the length given.
        if unsafe { libc::ptsname_r(fd, name.as_mut_ptr(), name.len()) } != 0 {
            return Err(os_err("no pseudo-terminal"));
        }
        // SAFETY: ptsname_r wrote a NUL-terminated name into the buffer.
        let path = unsafe { CStr::from_ptr(name.as_ptr()) }.to_owned();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        // SAFETY: on our descriptor.
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(os_err("no pseudo-terminal"));
        }
        Ok((master, path))
    }

    /// Whether the terminal's echo is off: the program waits for a password.
    fn echo_off(master: &OwnedFd) -> bool {
        // SAFETY: termios is plain data; tcgetattr on the master reads the
        // terminal's settings.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { libc::tcgetattr(master.as_raw_fd(), &mut t) == 0 && t.c_lflag & libc::ECHO == 0 }
    }

    fn write_all(master: &OwnedFd, mut b: &[u8]) -> Result<(), String> {
        while !b.is_empty() {
            // SAFETY: the buffer is valid for its length.
            let n = unsafe { libc::write(master.as_raw_fd(), b.as_ptr().cast(), b.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted
                {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                return Err(format!("cannot type the password: {e}"));
            }
            b = &b[n as usize..];
        }
        Ok(())
    }

    /// Runs `cmd` with the terminal as its controlling one, types `pw` and a
    /// newline once it switched echo off, and returns whether it exited 0.
    /// Killed after `wait`.
    pub fn answer(mut cmd: Command, pw: &Secret, wait: Duration) -> Result<bool, String> {
        // The line discipline would act on these (erase, kill, end of file)
        // instead of passing them on.
        if pw.expose().chars().any(char::is_control) {
            return Err(
                "this password holds control characters; use the command line in a terminal".into(),
            );
        }
        let (master, path) = open()?;
        // SAFETY: opens the other end of our pseudo-terminal.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(os_err("no pseudo-terminal"));
        }
        // SAFETY: fd is a new descriptor of ours.
        let other = unsafe { OwnedFd::from_raw_fd(fd) };
        let io = |f: &OwnedFd| f.try_clone().map(Stdio::from).map_err(|e| e.to_string());
        cmd.stdin(io(&other)?)
            .stdout(io(&other)?)
            .stderr(Stdio::from(other));
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("TERM", "dumb");
        // SAFETY: setsid and ioctl are async-signal-safe; the child gets a
        // session of its own with the terminal (its stdin) as the controlling one.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let program = cmd.get_program().to_string_lossy().into_owned();
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("cannot run {program} to check the password: {e}"))?;
        // Our copies of the terminal's other end go.
        drop(cmd);
        let deadline = Instant::now() + wait;
        let mut typed = false;
        let mut buf = [0u8; 256];
        let result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status.success()),
                Ok(None) => {}
                Err(e) => break Err(e.to_string()),
            }
            // What it says (its prompt) is read and dropped, so it never blocks
            // on a full terminal.
            // SAFETY: the buffer is valid for its length; the master does not block.
            while unsafe { libc::read(master.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0
            {
            }
            if !typed && echo_off(&master) {
                if let Err(e) = write_all(&master, pw.expose().as_bytes())
                    .and_then(|()| write_all(&master, b"\n"))
                {
                    break Err(e);
                }
                typed = true;
            }
            if Instant::now() >= deadline {
                break Err(format!(
                    "{program} did not {} in time",
                    if typed {
                        "finish"
                    } else {
                        "ask for the password"
                    }
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        buf.fill(0);
        if result.is_err() {
            let _ = child.kill();
        }
        let _ = child.wait();
        result
    }
}

#[cfg(unix)]
fn confirm_desktop() -> Result<(), String> {
    // SAFETY: isatty on fd 0.
    if unsafe { libc::isatty(0) } != 1 {
        return Err(
            "on a desktop, policy changes ask for your password; run this in a terminal".into(),
        );
    }
    let user = account()?;
    eprintln!("Changing what the portal may do on this device needs your password ({user}).");
    let status = su_check(&user)?
        .status()
        .map_err(|e| format!("cannot run su to check the password: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("password check failed; nothing changed".into())
    }
}

/// The account whose password is checked: the one this process runs as, from
/// the user database. Not `$USER`: whoever started the process sets that, and
/// could name an account whose password they know.
#[cfg(unix)]
pub fn account() -> Result<String, String> {
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    match sync_ops::info::passwd_name(uid) {
        Some(u) if !u.is_empty() && !u.starts_with('-') => Ok(u),
        _ => Err(format!("cannot tell which user this is (uid {uid})")),
    }
}

/// `su -c true <user>`, from a system folder: a `su` looked up through `PATH`
/// could be any program the user (or a command of the agent) put there, and
/// would answer "the password was right".
#[cfg(unix)]
fn su_check(user: &str) -> Result<std::process::Command, String> {
    let su = ["/usr/bin/su", "/bin/su"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .ok_or("no su in /usr/bin or /bin to check the password with")?;
    let mut cmd = std::process::Command::new(su);
    cmd.args(["-c", "true", user]);
    Ok(cmd)
}

#[cfg(windows)]
pub fn account() -> Result<String, String> {
    Ok(sync_ops::info::user().0)
}

#[cfg(windows)]
fn confirm_desktop() -> Result<(), String> {
    // Phase 1 on Windows has no way to ask for the password without a GUI; the
    // account login is the authentication there, as on a headless Linux machine.
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_desktop_change_without_a_terminal_is_refused() {
        // Test runs have no terminal on stdin when run by cargo in CI or by the agent;
        // when a terminal is attached this test has nothing to show.
        // SAFETY: isatty on fd 0.
        if unsafe { libc::isatty(0) } == 1 {
            return;
        }
        assert!(confirm(Profile::Desktop).unwrap_err().contains("terminal"));
        assert!(confirm(Profile::Headless).is_ok());
    }

    /// A stand-in `su` takes the password from its terminal only after it
    /// switched echo off (a real one flushes what came before), never from its
    /// arguments or environment.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_password_is_typed_into_a_terminal_of_its_own() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        use std::time::{Duration, Instant};
        if !std::path::Path::new("/bin/bash").exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let seen = dir.path().join("seen");
        let su = dir.path().join("su");
        std::fs::write(
            &su,
            format!(
                "#!/bin/bash\n{{ echo \"$*\"; env; tty; }} > '{seen}'\nprintf 'Password: '\nsleep 0.3\nread -t 0 && echo early >> '{seen}'\nstty -echo\nIFS= read -r p\nstty echo\necho\n[ \"$p\" = 'right one' ]\n",
                seen = seen.display()
            ),
        )
        .unwrap();
        let quiet = dir.path().join("quiet");
        std::fs::write(&quiet, "#!/bin/sh\nsleep 30\n").unwrap();
        for p in [&su, &quiet] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let wait = Duration::from_secs(10);
        let run = |pw: &str| pty::answer(Command::new(&su), &Secret::new(pw.into()), wait);
        assert_eq!(run("right one"), Ok(true));
        let s = std::fs::read_to_string(&seen).unwrap();
        assert!(!s.contains("right one"), "{s}");
        assert!(!s.contains("early"), "typed before echo was off: {s}");
        assert!(s.contains("/dev/pts/"), "on a terminal of its own: {s}");
        assert_eq!(run("wrong one"), Ok(false));
        // The line discipline would act on these.
        assert!(run("right\u{15}one").unwrap_err().contains("control"));
        // A program that never asks: an error after the wait, and it is ended.
        let start = Instant::now();
        let e = pty::answer(
            Command::new(&quiet),
            &Secret::new("x".into()),
            Duration::from_millis(500),
        )
        .unwrap_err();
        assert!(e.contains("did not ask for the password"), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    /// Run by the test below in a process of its own, with `USER` set.
    #[test]
    fn print_account() {
        if std::env::var_os("PRINT_ACCOUNT").is_some() {
            println!("account={:?}", account());
        }
    }

    #[test]
    fn the_account_checked_is_not_taken_from_the_environment() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "owner::tests::print_account", "--nocapture"])
            .env("USER", "someone-else")
            .env("PRINT_ACCOUNT", "1")
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&out.stdout);
        assert!(out.contains("account="), "{out}");
        assert!(!out.contains("someone-else"), "{out}");
    }

    #[test]
    fn the_password_check_runs_su_from_a_system_folder() {
        // Whatever PATH holds, the check never runs a `su` found there.
        let Ok(cmd) = su_check("someone") else {
            return;
        };
        let program = std::path::Path::new(cmd.get_program());
        assert!(
            program.starts_with("/usr/bin") || program.starts_with("/bin"),
            "{program:?}"
        );
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, ["-c", "true", "someone"]);
    }
}
