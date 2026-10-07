//! `computer-use setup`: the steps a server needs on this desktop, from its
//! pin. A step can be checked (a command and the output it must give) and
//! carried out (a command run only after the owner's yes); the client never
//! changes the desktop on its own.

use std::path::Path;
use std::time::Duration;

use crate::pins::{ServerPin, SetupStep};

/// The desktop as the steps name it: `gnome`, `kde`, or what
/// `XDG_CURRENT_DESKTOP` says, lowercase.
pub fn desktop() -> String {
    let d = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_lowercase();
    if d.contains("gnome") || d.contains("zorin") || d.contains("ubuntu") {
        "gnome".into()
    } else if d.contains("kde") {
        "kde".into()
    } else {
        d
    }
}

/// The steps for `desktop` (and those for every desktop).
pub fn steps_for<'a>(pin: &'a ServerPin, desktop: &str) -> Vec<&'a SetupStep> {
    pin.setup
        .iter()
        .filter(|s| s.desktop.as_deref().is_none_or(|d| d == desktop))
        .collect()
}

/// `argv` with `{dir}` naming the server's folder.
pub fn argv(argv: &[String], dir: &Path) -> Vec<String> {
    argv.iter()
        .map(|a| a.replace("{dir}", &dir.to_string_lossy()))
        .collect()
}

/// Most bytes of a setup command's output kept; the rest is read and dropped.
const MAX_OUTPUT: u64 = 1 << 20;

/// Reads a pipe to its end on a thread of its own, so a command that writes
/// much never blocks on a full pipe; sends the first `MAX_OUTPUT` bytes.
fn drain<R: std::io::Read + Send + 'static>(r: Option<R>) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut kept = Vec::new();
        if let Some(mut r) = r {
            let _ = (&mut r).take(MAX_OUTPUT).read_to_end(&mut kept);
            let _ = std::io::copy(&mut r, &mut std::io::sink());
        }
        let _ = tx.send(kept);
    });
    rx
}

fn run_argv(argv: &[String]) -> Result<String, String> {
    let (program, args) = argv.split_first().ok_or("an empty command")?;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).stdin(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{program} did not finish within 60s"));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Something the command left running may hold the pipes open: then its
    // output does not end, and is taken as empty (the reader drops the rest).
    let wait = Duration::from_secs(5);
    let out = stdout.recv_timeout(wait).unwrap_or_default();
    let err = stderr.recv_timeout(wait).unwrap_or_default();
    if !status.success() {
        let err = String::from_utf8_lossy(&err);
        return Err(format!(
            "{program} failed ({status}): {}",
            sync_policy::approve::visible(err.trim())
        ));
    }
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// Whether the step is done; `None` when it has no check.
pub fn check(step: &SetupStep, dir: &Path) -> Option<Result<bool, String>> {
    let c = step.check.as_ref()?;
    Some(run_argv(&argv(&c.argv, dir)).map(|out| out == c.expect))
}

/// Carries the step out (after the owner's yes).
pub fn apply(step: &SetupStep, dir: &Path) -> Result<(), String> {
    let a = step.run.as_ref().ok_or("this step is done by hand")?;
    run_argv(&argv(a, dir)).map(|_| ())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::pins::Check;

    #[test]
    fn a_step_is_checked_and_run_with_its_argv() {
        let t = tempfile::tempdir().unwrap();
        let step = SetupStep {
            id: "a".into(),
            title: "t".into(),
            text: "t".into(),
            desktop: Some("gnome".into()),
            check: Some(Check {
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "cat {dir}/flag 2>/dev/null || echo no".into(),
                ],
                expect: "yes".into(),
            }),
            run: Some(vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo yes > {dir}/flag".into(),
            ]),
        };
        assert_eq!(check(&step, t.path()), Some(Ok(false)));
        apply(&step, t.path()).unwrap();
        assert_eq!(check(&step, t.path()), Some(Ok(true)));
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_writes_much_still_finishes() {
        // More than a pipe holds, on both outputs.
        let argv: Vec<String> = [
            "/bin/sh",
            "-c",
            "head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2; echo done",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let started = std::time::Instant::now();
        let out = run_argv(&argv).unwrap();
        assert!(out.ends_with("done"));
        assert!(started.elapsed() < Duration::from_secs(20));
    }
}
