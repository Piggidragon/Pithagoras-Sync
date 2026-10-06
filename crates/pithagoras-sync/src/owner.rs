//! Who may change the policy: the device owner, never the portal or the agent.
//!
//! On a headless machine the shell login is the authentication (spec 10.1). On a
//! Linux desktop, a change also asks for the user's password in a terminal (through
//! `su`, so PAM checks it), which a command the agent runs cannot type. In both
//! cases a change from a command the client itself runs is refused.

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
    if profile == Profile::Headless {
        return Ok(());
    }
    confirm_desktop()
}

#[cfg(unix)]
fn confirm_desktop() -> Result<(), String> {
    // SAFETY: isatty on fd 0.
    if unsafe { libc::isatty(0) } != 1 {
        return Err(
            "on a desktop, policy changes ask for your password; run this in a terminal".into(),
        );
    }
    let (user, _) = sync_ops::info::user();
    if user.is_empty() || user.starts_with('-') {
        return Err("cannot tell which user this is".into());
    }
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
