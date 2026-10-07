//! Starting a server and stopping it with everything it started. On Linux the
//! server leads a process group of its own and dies with the client
//! (`PR_SET_PDEATHSIG`); stopping it kills the group. On Windows it runs
//! without a console window (`CREATE_NO_WINDOW`) in a Job Object with
//! kill-on-close, so the whole tree goes on stop, timeout, `panic` and when the
//! client exits.

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::io::AsyncReadExt;
use tokio::process::Child;

use crate::client::Launch;

/// Most bytes of a server's stderr log; past it the log starts again, the old
/// one kept as `.1`.
pub const MAX_LOG: u64 = 1 << 20;

pub struct Spawned {
    pub child: Child,
    #[cfg(windows)]
    pub job: sync_ops::Job,
}

/// Starts the server. A program written a moment ago can be "busy" while
/// another thread of the client forks (the fork holds the write handle until
/// its exec): that is tried again for up to a second.
pub async fn spawn(launch: &Launch) -> Result<Spawned, String> {
    for _ in 0..20 {
        match spawn_once(launch) {
            Err(e) if busy(&e) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            r => return r.map_err(|e| format!("{}: {e}", launch.program.display())),
        }
    }
    spawn_once(launch).map_err(|e| format!("{}: {e}", launch.program.display()))
}

fn busy(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    return e.raw_os_error() == Some(libc::ETXTBSY);
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

fn spawn_once(launch: &Launch) -> std::io::Result<Spawned> {
    let mut cmd = tokio::process::Command::new(&launch.program);
    cmd.args(&launch.args)
        .env_clear()
        .envs(launch.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&launch.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        cmd.process_group(0);
        #[cfg(target_os = "linux")]
        // SAFETY: prctl is async-signal-safe; nothing else runs in the hook.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(windows)]
    let job = sync_ops::Job::new()?;
    let child = cmd.spawn()?;
    #[cfg(windows)]
    let child = {
        let mut child = child;
        let Some(h) = child.raw_handle() else {
            let _ = child.start_kill();
            return Err(std::io::Error::other("no process handle"));
        };
        if let Err(e) = job.assign(h) {
            let _ = child.start_kill();
            return Err(e);
        }
        child
    };
    Ok(Spawned {
        child,
        #[cfg(windows)]
        job,
    })
}

/// Kills the server and its process group (Unix), and reaps it.
pub async fn kill_tree(child: &mut Child) {
    kill_now(child);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
}

/// The same without waiting (for `Drop`).
pub fn kill_now(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: the group is the server's own (`process_group(0)`).
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    }
    let _ = child.start_kill();
}

/// Copies the server's stderr into `log`, bounded: at `MAX_LOG` the file
/// becomes `<log>.1` and a new one starts.
pub async fn log_stderr(mut stderr: tokio::process::ChildStderr, log: Option<PathBuf>) {
    let mut buf = vec![0u8; 8192];
    let mut file: Option<std::fs::File> = None;
    let mut written = 0u64;
    loop {
        let n = match stderr.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let Some(path) = &log else { continue };
        if file.is_none() || written >= MAX_LOG {
            if written >= MAX_LOG {
                let _ = std::fs::rename(path, path.with_extension("log.1"));
            }
            written = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            file = open_log(path);
        }
        if let Some(f) = &mut file
            && f.write_all(&buf[..n]).is_ok()
        {
            written += n as u64;
        }
    }
}

fn open_log(path: &std::path::Path) -> Option<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    o.open(path).ok()
}
