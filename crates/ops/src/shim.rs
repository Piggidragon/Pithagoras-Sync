//! The exec shim: a small process between the client and each command's shell.
//!
//! The client runs `pithagoras-sync __exec-shim <spec>` per command. On Linux the shim
//! makes itself a child subreaper, so whatever the command starts stays its
//! descendant even after `setsid`, `nohup` or a double fork; it moves itself into the
//! command's cgroup when there is one; it applies Landlock to the shell in Folders
//! mode; and on SIGTERM it kills its whole tree (SIGTERM, SIGKILL after 3 s). When
//! the client dies, the kernel sends the shim SIGTERM (`PR_SET_PDEATHSIG`).
//!
//! On Windows the client puts the shim into a Job Object before it starts anything
//! (the shim waits for one byte on stdin), so the job holds every descendant and
//! terminating it kills them all.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Argument that selects the shim in the client binary.
pub const SHIM_ARG: &str = "__exec-shim";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LandlockSpec {
    pub read: Vec<PathBuf>,
    /// Writable, and readable.
    pub write: Vec<PathBuf>,
    /// Programs here may run.
    pub exec: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    /// The client's pid: a shim whose parent already changed exits at once.
    pub parent: u32,
    pub cgroup: Option<PathBuf>,
    pub landlock: Option<LandlockSpec>,
    /// The client passes the elevation secret on fd 4 for sudo's stdin.
    #[serde(default)]
    pub secret_fd: bool,
}

/// Runs the shim and returns its exit code. Must be called before any thread or
/// async runtime starts in the process.
pub fn shim_main(spec_json: &str) -> i32 {
    let spec: ShimSpec = match serde_json::from_str(spec_json) {
        Ok(s) => s,
        Err(_) => return 125,
    };
    imp::run(spec)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::ShimSpec;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// fd 3: the client reads the main shell's exit status from it.
    const STATUS_FD: i32 = 3;
    /// fd 4: a socket the client sends the elevation secret over.
    const SECRET_FD: i32 = 4;
    /// Longest secret taken.
    const MAX_SECRET: usize = 1024;

    /// Takes the secret from the client and returns a pipe holding it, for sudo's
    /// stdin. The shim first makes itself undumpable and checks nobody traces it,
    /// so no other process of the user can read the secret out of its memory, then
    /// tells the client it is ready; the client sends the secret only then.
    fn take_secret() -> Result<std::os::fd::OwnedFd, String> {
        use std::io::{Read, Write as _};
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::os::unix::net::UnixStream;
        // SAFETY: fd 4 is the client's socket, passed to us alone.
        if unsafe { libc::fcntl(SECRET_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err("no secret channel".into());
        }
        // SAFETY: as above; nothing else owns fd 4.
        let mut sock = unsafe { UnixStream::from_raw_fd(SECRET_FD) };
        sync_policy::secret::undumpable();
        if sync_policy::secret::traced() {
            return Err("the shim is being traced; the secret stays with the client".into());
        }
        sock.write_all(b"R").map_err(|e| e.to_string())?;
        let mut secret = Vec::with_capacity(MAX_SECRET);
        let r = (&mut sock)
            .take(MAX_SECRET as u64 + 1)
            .read_to_end(&mut secret);
        drop(sock);
        let result = (|| {
            r.map_err(|e| e.to_string())?;
            if secret.is_empty() || secret.len() > MAX_SECRET || secret.contains(&b'\n') {
                return Err("no usable secret".to_string());
            }
            let (rd, wr) = std::io::pipe().map_err(|e| e.to_string())?;
            let mut wr = File::from(OwnedFd::from(wr));
            // Far below a pipe's buffer, so this never blocks.
            wr.write_all(&secret).map_err(|e| e.to_string())?;
            wr.write_all(b"\n").map_err(|e| e.to_string())?;
            Ok(OwnedFd::from(rd))
        })();
        secret.fill(0);
        result
    }

    fn status_file() -> Option<File> {
        // SAFETY: fcntl on a possibly unused fd only reports EBADF.
        if unsafe { libc::fcntl(STATUS_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return None;
        }
        // SAFETY: fd 3 is ours (the client put it there) and nothing else owns it.
        Some(unsafe { File::from_raw_fd(STATUS_FD) })
    }

    fn report(status: &mut Option<File>, line: &str) {
        if let Some(mut f) = status.take() {
            let _ = writeln!(f, "{line}");
        }
    }

    fn wait_status_line(st: i32) -> String {
        if libc::WIFEXITED(st) {
            format!("exit {}", libc::WEXITSTATUS(st))
        } else if libc::WIFSIGNALED(st) {
            format!("signal {}", libc::WTERMSIG(st))
        } else {
            "exit 255".into()
        }
    }

    /// All descendants of `me`, from /proc (orphans were reparented to us, the
    /// subreaper, so they are still found).
    fn descendants(me: i32) -> Vec<i32> {
        let mut parent: HashMap<i32, i32> = HashMap::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
                    continue;
                };
                let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                    continue;
                };
                // "pid (comm) state ppid ...": comm may hold spaces and parens.
                let Some(after) = stat.rfind(')').map(|i| &stat[i + 1..]) else {
                    continue;
                };
                if let Some(ppid) = after.split_whitespace().nth(1).and_then(|p| p.parse().ok()) {
                    parent.insert(pid, ppid);
                }
            }
        }
        let mut out = Vec::new();
        let mut frontier = vec![me];
        while let Some(p) = frontier.pop() {
            for (&c, &pp) in &parent {
                if pp == p && !out.contains(&c) {
                    out.push(c);
                    frontier.push(c);
                }
            }
        }
        out
    }

    fn signal_tree(me: i32, sig: i32) -> usize {
        let pids = descendants(me);
        for &p in &pids {
            // SAFETY: plain kill(2).
            unsafe { libc::kill(p, sig) };
        }
        pids.len()
    }

    struct Reaper {
        main: i32,
        main_done: bool,
    }

    impl Reaper {
        /// Reaps what has exited; returns false once no child is left.
        fn reap(&mut self, status: &mut Option<File>) -> bool {
            loop {
                let mut st = 0;
                // SAFETY: waitpid on any child, non-blocking.
                let pid = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
                if pid > 0 {
                    if pid == self.main {
                        self.main_done = true;
                        report(status, &wait_status_line(st));
                    }
                    continue;
                }
                return pid == 0;
            }
        }
    }

    fn wait_signal(sfd: i32, timeout_ms: i32) -> Option<u32> {
        let mut pfd = libc::pollfd {
            fd: sfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if n <= 0 {
            return None;
        }
        // SAFETY: zeroed POD struct, read from a signalfd.
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::signalfd_siginfo>();
        // SAFETY: reading one siginfo into `info`.
        let r = unsafe { libc::read(sfd, &mut info as *mut _ as *mut libc::c_void, size) };
        (r == size as isize).then_some(info.ssi_signo)
    }

    /// Kills the whole tree: SIGTERM, then SIGKILL after 3 s, until nothing is left.
    fn kill_all(me: i32, sfd: i32, reaper: &mut Reaper, status: &mut Option<File>, hard: bool) {
        if !hard {
            signal_tree(me, libc::SIGTERM);
            let end = Instant::now() + Duration::from_secs(3);
            while Instant::now() < end {
                if !reaper.reap(status) {
                    return;
                }
                let left = end.saturating_duration_since(Instant::now());
                wait_signal(sfd, left.as_millis().clamp(1, 100) as i32);
            }
        }
        for _ in 0..200 {
            if signal_tree(me, libc::SIGKILL) == 0 && !reaper.reap(status) {
                return;
            }
            reaper.reap(status);
            wait_signal(sfd, 10);
        }
    }

    pub fn run(spec: ShimSpec) -> i32 {
        let mut status = status_file();
        // SAFETY: prctl and getppid with plain integer arguments.
        unsafe {
            libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
            if libc::getppid() as u32 != spec.parent {
                return 125;
            }
        }
        let me = std::process::id() as i32;
        if let Some(cg) = &spec.cgroup {
            // Best effort: without it the subreaper tree still holds everything.
            let _ = std::fs::write(cg.join("cgroup.procs"), me.to_string());
        }
        // Signals arrive through a signalfd, so the loop below is plain code.
        // SAFETY: building and installing a signal mask.
        let sfd = unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for s in [
                libc::SIGTERM,
                libc::SIGINT,
                libc::SIGHUP,
                libc::SIGUSR1,
                libc::SIGCHLD,
            ] {
                libc::sigaddset(&mut set, s);
            }
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            libc::signalfd(-1, &set, libc::SFD_CLOEXEC)
        };
        if sfd < 0 {
            report(&mut status, "error signalfd");
            return 125;
        }
        let mut ruleset = match &spec.landlock {
            Some(l) => match super::landlock::prepare(l) {
                Ok(r) => Some(r),
                Err(e) => {
                    report(&mut status, &format!("error landlock: {e}"));
                    return 126;
                }
            },
            None => None,
        };
        let stdin = if spec.secret_fd {
            match take_secret() {
                Ok(fd) => Stdio::from(fd),
                Err(e) => {
                    report(&mut status, &format!("error elevation: {e}"));
                    return 126;
                }
            }
        } else {
            Stdio::null()
        };
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args)
            .current_dir(&spec.cwd)
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .stdin(stdin);
        // SAFETY: the shim is single-threaded, so the child may allocate after fork;
        // everything here is setsid, the signal mask and Landlock.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let mut empty: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut empty);
                libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
                if let Some(r) = ruleset.take() {
                    super::landlock::enforce(r)?;
                }
                Ok(())
            });
        }
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                report(&mut status, &format!("error spawn: {e}"));
                return 127;
            }
        };
        let mut reaper = Reaper {
            main: child.id() as i32,
            main_done: false,
        };
        drop(child);
        loop {
            if !reaper.reap(&mut status) {
                return 0;
            }
            match wait_signal(sfd, 1000) {
                Some(s) if s == libc::SIGTERM as u32 || s == libc::SIGHUP as u32 => {
                    kill_all(me, sfd, &mut reaper, &mut status, false);
                    return 0;
                }
                Some(s) if s == libc::SIGUSR1 as u32 => {
                    kill_all(me, sfd, &mut reaper, &mut status, true);
                    return 0;
                }
                Some(s) if s == libc::SIGINT as u32 && !reaper.main_done => {
                    // The shell leads its own session and process group.
                    // SAFETY: plain kill(2) on the group.
                    unsafe { libc::kill(-reaper.main, libc::SIGINT) };
                }
                _ => {}
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub mod landlock {
    //! Landlock for the Folders shell. Everything filesystem-related is handled (so
    //! denied unless a rule allows it); granted folders are readable or writable,
    //! system directories readable. On Linux 6.12+ the shell also cannot signal
    //! processes outside its sandbox or reach abstract sockets, and on 7.1+ it
    //! cannot connect to path sockets outside its folders (the session bus, the
    //! user's systemd), which would otherwise let a command run unconfined.

    use super::LandlockSpec;
    use landlock::{
        ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr,
        RulesetStatus, Scope, path_beneath_rules,
    };

    const ABI_WANTED: ABI = ABI::V9;

    pub fn prepare(spec: &LandlockSpec) -> Result<RulesetCreated, String> {
        let e = |e: landlock::RulesetError| e.to_string();
        // Running a program is its own right, granted only where `exec` says.
        let mut read = AccessFs::from_read(ABI_WANTED);
        read.remove(AccessFs::Execute);
        let mut write = AccessFs::from_all(ABI_WANTED);
        write.remove(AccessFs::Execute);
        let mut rs = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI_WANTED))
            .map_err(e)?;
        if !Scope::from_all(ABI_WANTED).is_empty() {
            rs = rs.scope(Scope::from_all(ABI_WANTED)).map_err(e)?;
        }
        rs.create()
            .map_err(e)?
            .add_rules(path_beneath_rules(&spec.read, read))
            .map_err(e)?
            .add_rules(path_beneath_rules(&spec.write, write))
            .map_err(e)?
            .add_rules(path_beneath_rules(&spec.exec, AccessFs::Execute))
            .map_err(e)
    }

    /// Restricts the calling process. Fails (and so the command does not run) when
    /// the kernel enforces nothing.
    pub fn enforce(rs: RulesetCreated) -> std::io::Result<()> {
        let st = rs.restrict_self().map_err(std::io::Error::other)?;
        if st.ruleset == RulesetStatus::NotEnforced {
            return Err(std::io::Error::other("Landlock is not enforced"));
        }
        Ok(())
    }

    /// The kernel's Landlock ABI version, `None` when Landlock is off or missing.
    pub fn abi_version() -> Option<i32> {
        const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
        // SAFETY: the version query takes no ruleset and returns an integer.
        let v = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        (v > 0).then_some(v as i32)
    }
}

#[cfg(windows)]
mod imp {
    use super::ShimSpec;
    use std::io::Read;
    use std::process::{Command, Stdio};

    pub fn run(spec: ShimSpec) -> i32 {
        // Wait until the client has put this process into the command's job.
        let mut go = [0u8; 1];
        if std::io::stdin().read_exact(&mut go).is_err() {
            return 125;
        }
        let child = Command::new(&spec.program)
            .args(&spec.args)
            .current_dir(&spec.cwd)
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .spawn();
        match child.and_then(|mut c| c.wait()) {
            Ok(st) => st.code().unwrap_or(255),
            Err(e) => {
                eprintln!(
                    "pithagoras-sync: cannot start {}: {e}",
                    spec.program.display()
                );
                127
            }
        }
    }
}
