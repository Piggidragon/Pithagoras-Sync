//! Running commands for `exec.start`: spawn the shim, stream the merged output with
//! backpressure and a cap, enforce the timeout, and kill whole trees on request,
//! panic or disconnect.
//!
//! A command whose shell exited may leave background processes; they keep running
//! (as on the server) until a panic or disconnect, which kills them too.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sync_policy::{Confine, Permit};
use sync_proto::binary::MAX_CHUNK;
use sync_proto::methods::Signal;
use sync_proto::{RpcError, code};
use tokio::sync::{mpsc, watch};

use crate::shim::{LandlockSpec, SHIM_ARG, ShimSpec};
use sync_policy::secret::{Scrubber, Secret, SecretSlot};

#[derive(Debug, Clone)]
pub struct ExecConfig {
    /// The program that runs the shim (the client binary itself).
    pub shim_program: PathBuf,
    /// Arguments before `__exec-shim` (tests use none).
    pub shim_args: Vec<String>,
    /// The shell; `None` picks bash (else sh) on Linux, pwsh (else Windows
    /// PowerShell) on Windows.
    pub shell: Option<PathBuf>,
    /// The client's own environment, scrubbed per command.
    pub base_env: Vec<(String, String)>,
    pub env_passthrough: Vec<String>,
    pub output_cap: u64,
    pub max_timeout: Duration,
    pub max_running: usize,
    /// Private temporary directories of confined commands go here.
    pub tmp_base: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecOutcome {
    pub code: Option<i32>,
    pub signal: Option<String>,
    pub timed_out: bool,
    pub truncated: bool,
    /// Why the command never ran (Landlock could not be applied, the shell is
    /// missing); reported in the output as well.
    pub error: Option<String>,
}

/// A started command: its output arrives on the channel given to `start`, and the
/// outcome when the shell is done.
pub struct Started {
    pub outcome: tokio::task::JoinHandle<ExecOutcome>,
}

/// One shim and what belongs to it.
struct Scope {
    #[cfg(unix)]
    pidfd: std::os::fd::OwnedFd,
    #[cfg(windows)]
    job: win::Job,
    #[cfg(target_os = "linux")]
    cgroup: Option<PathBuf>,
    /// Becomes true when the shim has exited.
    exited: watch::Receiver<bool>,
}

impl Scope {
    fn done(&self) -> bool {
        *self.exited.borrow()
    }

    /// Kills everything in the scope: SIGTERM (the shim passes it on, SIGKILL after
    /// 3 s), or at once with `hard`. Returns when it is all gone.
    async fn kill(&self, hard: bool) {
        #[cfg(unix)]
        {
            if !self.done() {
                let sig = if hard { libc::SIGUSR1 } else { libc::SIGTERM };
                send_pidfd(&self.pidfd, sig);
            }
            let mut rx = self.exited.clone();
            let grace = Duration::from_secs(if hard { 2 } else { 5 });
            if tokio::time::timeout(grace, rx.wait_for(|d| *d))
                .await
                .is_err()
            {
                send_pidfd(&self.pidfd, libc::SIGKILL);
            }
            #[cfg(target_os = "linux")]
            if let Some(cg) = &self.cgroup {
                // Catches anything that left the shim's tree in some other way.
                crate::cgroup::kill(cg);
            }
        }
        #[cfg(windows)]
        {
            let _ = hard;
            self.job.terminate();
            let mut rx = self.exited.clone();
            let _ = tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|d| *d)).await;
        }
    }
}

#[cfg(unix)]
fn send_pidfd(fd: &std::os::fd::OwnedFd, sig: i32) {
    use std::os::fd::AsRawFd;
    // SAFETY: pidfd_send_signal on a pidfd we own; no siginfo.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::c_void>(),
            0,
        );
    }
}

#[derive(Default)]
struct Table {
    running: HashMap<u32, Arc<Scope>>,
    /// Streams whose command is being started: taken under the same lock as the
    /// checks, so two starts cannot both pass them, and counted as running.
    starting: HashSet<u32>,
    /// Shells that exited while their background processes live on.
    lingering: Vec<Arc<Scope>>,
    /// Counts `kill_all`: a command whose start began before one is killed when
    /// it would enter the table, since that `kill_all` could not see it.
    epoch: u64,
    /// Panic: no command starts until `unlock`.
    paused: bool,
}

pub struct Execs {
    /// Read once per command; the owner's limits change at runtime.
    cfg: std::sync::RwLock<ExecConfig>,
    table: Arc<Mutex<Table>>,
    #[cfg(target_os = "linux")]
    cgroups: Option<crate::cgroup::CgroupBase>,
    /// The elevation secret: injected for `sudo` commands, scrubbed from output.
    secrets: std::sync::OnceLock<Arc<SecretSlot>>,
    /// Numbers the private temporary directories, so no two commands share one.
    next_tmp: std::sync::atomic::AtomicU64,
}

impl Execs {
    pub fn new(cfg: ExecConfig) -> Execs {
        Execs {
            cfg: std::sync::RwLock::new(cfg),
            table: Arc::new(Mutex::new(Table::default())),
            #[cfg(target_os = "linux")]
            cgroups: crate::cgroup::CgroupBase::detect(),
            secrets: std::sync::OnceLock::new(),
            next_tmp: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn use_secrets(&self, slot: Arc<SecretSlot>) {
        let _ = self.secrets.set(slot);
    }

    fn secret(&self) -> Option<Secret> {
        self.secrets.get().and_then(|s| s.get())
    }

    /// Whether commands get a cgroup of their own here.
    pub fn uses_cgroups(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.cgroups.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// The shell commands run in, for `device.info` and `hello`.
    pub fn shell(&self) -> PathBuf {
        if let Some(s) = &self.cfg.read().unwrap().shell {
            return s.clone();
        }
        default_shell()
    }

    /// The shell's name as the portal sees it: `bash`, `sh`, `pwsh`, `powershell`.
    pub fn shell_name(&self) -> String {
        self.shell()
            .file_stem()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default()
    }

    /// The owner changed the limits: later commands get the new ones.
    pub fn set_limits(
        &self,
        env_passthrough: Vec<String>,
        output_cap: u64,
        max_timeout: Duration,
        max_running: usize,
    ) {
        let mut cfg = self.cfg.write().unwrap();
        cfg.env_passthrough = env_passthrough;
        cfg.output_cap = output_cap;
        cfg.max_timeout = max_timeout;
        cfg.max_running = max_running;
    }

    pub fn running(&self) -> usize {
        self.table.lock().unwrap().running.len()
    }

    /// Panic: kill everything, and start nothing until `unlock`. A start that
    /// was already under way is killed when it would enter the table.
    pub async fn pause(&self) {
        self.set_paused(true);
        self.kill_all().await;
    }

    /// Whether commands may start (false after `unlock`).
    pub fn set_paused(&self, paused: bool) {
        self.table.lock().unwrap().paused = paused;
    }

    /// Starts a command the policy allowed (`permit.path` is the working folder).
    /// Output chunks go to `out`; a slow receiver slows the command down.
    pub fn start(
        &self,
        stream: u32,
        command: &str,
        permit: &Permit,
        timeout: Option<Duration>,
        out: mpsc::Sender<Vec<u8>>,
    ) -> Result<Started, RpcError> {
        let cfg = self.cfg.read().unwrap().clone();
        let epoch = {
            let mut t = self.table.lock().unwrap();
            t.lingering.retain(|s| !s.done());
            if t.paused {
                return Err(RpcError::denied("the device is paused"));
            }
            if t.running.contains_key(&stream) || t.starting.contains(&stream) {
                return Err(RpcError::new(code::INVALID_PARAMS, "stream already in use"));
            }
            if t.running.len() + t.starting.len() >= cfg.max_running {
                return Err(RpcError::new(code::BUSY, "too many commands running"));
            }
            t.starting.insert(stream);
            t.epoch
        };
        let spawned = self.spawn_command(&cfg, command, permit);
        let mut t = self.table.lock().unwrap();
        t.starting.remove(&stream);
        let spawned = spawned?;
        if t.epoch != epoch || t.paused {
            // A panic or disconnect came while this command was being started.
            let scope = spawned.scope.clone();
            t.lingering.push(scope.clone());
            drop(t);
            tokio::spawn(async move { scope.kill(true).await });
            return Err(RpcError::denied(
                "the device was paused or the connection ended while the command started",
            ));
        }
        t.running.insert(stream, spawned.scope.clone());
        drop(t);
        Ok(self.watch(&cfg, stream, spawned, timeout, out))
    }

    /// Everything of `start` from the checks to the running shim.
    fn spawn_command(
        &self,
        cfg: &ExecConfig,
        command: &str,
        permit: &Permit,
    ) -> Result<Spawned, RpcError> {
        let mut env = crate::env::scrubbed(&cfg.base_env, &cfg.env_passthrough);
        let mut tmp = None;
        let landlock = match &permit.confine {
            Confine::None => None,
            Confine::Landlock(rules) => {
                // A private temporary directory: the confined shell cannot write /tmp.
                // One per command, never reused (stream numbers start again on every
                // connection), and removed when the command is gone.
                let n = self
                    .next_tmp
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let dir = cfg
                    .tmp_base
                    .join(format!("exec-{}-{n}", std::process::id()));
                fresh_dir(&dir).map_err(|e| RpcError::new(code::IO, format!("temp dir: {e}")))?;
                env.retain(|(k, _)| k != "TMPDIR");
                env.push(("TMPDIR".into(), dir.to_string_lossy().into_owned()));
                let mut write = rules.write.clone();
                write.push(dir.clone());
                tmp = Some(dir);
                Some(LandlockSpec {
                    read: rules.read.clone(),
                    write,
                    exec: rules.exec.clone(),
                })
            }
        };
        let spawned = self.spawn_shim(cfg, command, permit, env, landlock, tmp.clone());
        if spawned.is_err()
            && let Some(t) = tmp
        {
            let _ = std::fs::remove_dir_all(t);
        }
        spawned
    }

    fn spawn_shim(
        &self,
        cfg: &ExecConfig,
        command: &str,
        permit: &Permit,
        env: Vec<(String, String)>,
        landlock: Option<LandlockSpec>,
        tmp: Option<PathBuf>,
    ) -> Result<Spawned, RpcError> {
        let shell = self.shell();
        let (program, args, secret) = match &permit.elevate {
            None => (shell.clone(), shell_args(&shell, command), None),
            Some(sudo) => self.elevated(sudo, &shell, command)?,
        };
        let elevated = permit.elevate.is_some();
        #[cfg(target_os = "linux")]
        let cgroup = match self.cgroups.as_ref().map(|c| c.create()) {
            None => None,
            Some(Ok(cg)) => Some(cg),
            // Without one, panic could not stop a root command: refuse it.
            Some(Err(e)) if elevated => {
                return Err(RpcError::denied(format!(
                    "an elevated command needs a cgroup of its own, and none could be made: {e}"
                )));
            }
            Some(Err(_)) => None,
        };
        #[cfg(not(target_os = "linux"))]
        let cgroup = None;
        let spec = ShimSpec {
            args,
            program,
            cwd: permit.path.clone(),
            env,
            parent: std::process::id(),
            cgroup,
            require_cgroup: elevated,
            landlock,
            secret_fd: secret.is_some(),
        };
        let spec_json = serde_json::to_string(&spec)
            .map_err(|e| RpcError::new(code::INTERNAL, e.to_string()))?;
        let spawned = spawn(cfg, spec_json, &spec, secret, tmp);
        #[cfg(target_os = "linux")]
        if spawned.is_err()
            && let Some(cg) = &spec.cgroup
        {
            let _ = std::fs::remove_dir(cg);
        }
        spawned
    }

    /// Streams the output of a command in the table and takes it out at its end.
    fn watch(
        &self,
        cfg: &ExecConfig,
        stream: u32,
        spawned: Spawned,
        timeout: Option<Duration>,
        out: mpsc::Sender<Vec<u8>>,
    ) -> Started {
        let timeout = timeout.unwrap_or(cfg.max_timeout).min(cfg.max_timeout);
        let scope = spawned.scope;
        let table = self.table.clone();
        let cap = cfg.output_cap;
        let scrub = self.secret().map(|s| Scrubber::new(&s));
        let outcome = tokio::spawn(async move {
            let reader = tokio::spawn(forward_output(spawned.output, out, cap, scrub));
            let mut timed_out = false;
            let status = tokio::select! {
                s = spawned.status => s.ok().flatten(),
                _ = tokio::time::sleep(timeout) => {
                    timed_out = true;
                    scope.kill(false).await;
                    None
                }
            };
            // Background processes may hold the output open; take what comes soon.
            let truncated = match tokio::time::timeout(Duration::from_millis(300), reader).await {
                Ok(Ok(t)) => t,
                _ => false,
            };
            {
                let mut t = table.lock().unwrap();
                if t.running
                    .get(&stream)
                    .is_some_and(|s| Arc::ptr_eq(s, &scope))
                {
                    t.running.remove(&stream);
                }
                if !scope.done() {
                    t.lingering.push(scope.clone());
                }
            }
            let mut o = parse_status(status.as_deref());
            o.timed_out = timed_out;
            o.truncated = truncated;
            o
        });
        Started { outcome }
    }

    /// sudo running the shell as root: `sudo -k -S` with the secret on stdin (the
    /// shell's first line closes stdin, so with a sudoers rule that asks no
    /// password the secret is not left for the command to read), or `sudo -n`
    /// without one. Only with a cgroup of its own: `panic` cannot signal root's
    /// processes, but it can kill their cgroup.
    #[allow(unused_variables)]
    fn elevated(
        &self,
        sudo: &Path,
        shell: &Path,
        command: &str,
    ) -> Result<(PathBuf, Vec<String>, Option<Secret>), RpcError> {
        #[cfg(not(target_os = "linux"))]
        return Err(RpcError::denied(
            "elevated commands are Linux only (sudo); Windows has none",
        ));
        #[cfg(target_os = "linux")]
        {
            let rest = sync_policy::engine::elevated_command(command)
                .ok_or_else(|| RpcError::denied("not a sudo command"))?;
            if self.cgroups.is_none() {
                return Err(RpcError::denied(
                    "elevated commands need a cgroup of their own (the systemd unit's Delegate=yes), or panic could not stop them",
                ));
            }
            let secret = self.secret();
            let sh = shell.to_string_lossy().into_owned();
            let args: Vec<String> = match &secret {
                Some(_) => vec![
                    "-k".into(),
                    "-S".into(),
                    "-p".into(),
                    String::new(),
                    "--".into(),
                    sh,
                    "-c".into(),
                    format!("exec </dev/null\n{rest}"),
                ],
                None => vec!["-n".into(), "--".into(), sh, "-c".into(), rest.to_string()],
            };
            Ok((sudo.to_path_buf(), args, secret))
        }
    }

    /// A signal from the portal: SIGINT goes to the shell's process group,
    /// SIGTERM and SIGKILL end the whole command.
    pub async fn signal(&self, stream: u32, sig: Signal) -> Result<(), RpcError> {
        let scope = self
            .table
            .lock()
            .unwrap()
            .running
            .get(&stream)
            .cloned()
            .ok_or_else(|| RpcError::new(code::NOT_FOUND, "no such command"))?;
        match sig {
            #[cfg(unix)]
            Signal::Int => send_pidfd(&scope.pidfd, libc::SIGINT),
            #[cfg(windows)]
            Signal::Int => scope.kill(false).await,
            Signal::Term => scope.kill(false).await,
            Signal::Kill => scope.kill(true).await,
        }
        Ok(())
    }

    /// Panic or disconnect: kill every command and everything it left behind.
    pub async fn kill_all(&self) {
        let scopes: Vec<Arc<Scope>> = {
            let mut t = self.table.lock().unwrap();
            t.epoch += 1;
            let mut v: Vec<Arc<Scope>> = t.running.values().cloned().collect();
            v.append(&mut t.lingering);
            v
        };
        // All at once: each shim gets its SIGTERM now and its grace runs in parallel.
        let tasks: Vec<_> = scopes
            .into_iter()
            .map(|s| tokio::spawn(async move { s.kill(false).await }))
            .collect();
        for t in tasks {
            let _ = t.await;
        }
    }
}

fn parse_status(s: Option<&str>) -> ExecOutcome {
    let mut o = ExecOutcome::default();
    let Some(s) = s.map(str::trim) else {
        o.signal = Some("SIGKILL".into());
        return o;
    };
    if let Some(c) = s.strip_prefix("exit ") {
        o.code = c.parse().ok();
    } else if let Some(n) = s.strip_prefix("signal ") {
        o.signal = Some(signal_name(n.parse().unwrap_or(0)));
    } else if let Some(e) = s.strip_prefix("error ") {
        o.error = Some(e.to_string());
        o.code = Some(126);
    } else {
        o.signal = Some("SIGKILL".into());
    }
    o
}

fn signal_name(n: i32) -> String {
    match n {
        1 => "SIGHUP",
        2 => "SIGINT",
        9 => "SIGKILL",
        13 => "SIGPIPE",
        15 => "SIGTERM",
        _ => return format!("SIG{n}"),
    }
    .to_string()
}

/// Copies output to the channel in frames' worth, dropping what exceeds the cap
/// and taking the elevation secret out.
async fn forward_output(
    mut output: OutputReader,
    out: mpsc::Sender<Vec<u8>>,
    cap: u64,
    mut scrub: Option<Scrubber>,
) -> bool {
    let mut sent = 0u64;
    let mut truncated = false;
    let mut ended = false;
    loop {
        let chunk = match output.next().await {
            Some(c) => match &mut scrub {
                Some(s) => s.push(&c),
                None => c,
            },
            None if !ended => {
                ended = true;
                match scrub.as_mut().map(Scrubber::finish) {
                    Some(rest) if !rest.is_empty() => rest,
                    _ => break,
                }
            }
            None => break,
        };
        if chunk.is_empty() {
            continue;
        }
        let room = cap.saturating_sub(sent) as usize;
        if room == 0 {
            truncated = true;
            continue;
        }
        let chunk = if chunk.len() > room {
            truncated = true;
            chunk[..room].to_vec()
        } else {
            chunk
        };
        sent += chunk.len() as u64;
        // Scrubbing can make a chunk longer than it was read (the held-back tail
        // goes in front, and `[redacted]` is longer than a short secret), and a
        // frame over `MAX_CHUNK` is dropped by the portal: one frame per piece.
        let frames = if chunk.len() > MAX_CHUNK {
            chunk.chunks(MAX_CHUNK).map(<[u8]>::to_vec).collect()
        } else {
            vec![chunk]
        };
        for f in frames {
            if out.send(f).await.is_err() {
                return truncated;
            }
        }
    }
    truncated
}

/// An empty directory at `dir`; whatever an earlier client process with the same
/// pid left there goes first.
fn fresh_dir(dir: &Path) -> std::io::Result<()> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_dir_all(dir) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    std::fs::create_dir(dir)
}

/// Removes a command's private temporary directory once its shim is gone.
async fn remove_tmp(tmp: Option<PathBuf>) {
    if let Some(t) = tmp {
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(t)).await;
    }
}

#[cfg(not(windows))]
fn default_shell() -> PathBuf {
    for p in ["/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"] {
        if Path::new(p).exists() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("/bin/sh")
}

#[cfg(windows)]
fn default_shell() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        let p = dir.join("pwsh.exe");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("powershell.exe")
}

/// The arguments that make `shell` run `command`. PowerShell takes it as one
/// argument after `-Command` (Rust quotes it for the Windows command line, and the
/// .NET runtime parses it back the same way). Not `-EncodedCommand`: with it,
/// Windows PowerShell writes errors and progress to a redirected stderr as CLIXML,
/// which the model cannot read.
pub fn shell_args(shell: &Path, command: &str) -> Vec<String> {
    let name = shell
        .file_stem()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name == "pwsh" || name == "powershell" {
        vec![
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-ExecutionPolicy".into(),
            "Bypass".into(),
            "-Command".into(),
            command.into(),
        ]
    } else {
        vec!["-c".into(), command.into()]
    }
}

/// Output of a command, in chunks of at most one binary frame.
pub struct OutputReader {
    #[cfg(unix)]
    rx: tokio::net::unix::pipe::Receiver,
    #[cfg(windows)]
    rx: mpsc::Receiver<Vec<u8>>,
}

impl OutputReader {
    async fn next(&mut self) -> Option<Vec<u8>> {
        #[cfg(unix)]
        {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; MAX_CHUNK];
            match self.rx.read(&mut buf).await {
                Ok(0) | Err(_) => None,
                Ok(n) => {
                    buf.truncate(n);
                    Some(buf)
                }
            }
        }
        #[cfg(windows)]
        {
            self.rx.recv().await
        }
    }
}

struct Spawned {
    scope: Arc<Scope>,
    output: OutputReader,
    /// The shell's exit line from the shim; `None` when the shim died first.
    status: tokio::task::JoinHandle<Option<String>>,
}

#[cfg(unix)]
fn spawn(
    cfg: &ExecConfig,
    spec_json: String,
    spec: &ShimSpec,
    secret: Option<Secret>,
    tmp: Option<PathBuf>,
) -> Result<Spawned, RpcError> {
    use std::os::fd::{AsRawFd, OwnedFd};
    let io = |e: std::io::Error| RpcError::new(code::IO, format!("cannot start the command: {e}"));
    let (out_r, out_w) = std::io::pipe().map_err(io)?;
    let out_w2 = out_w.try_clone().map_err(io)?;
    let (st_r, st_w) = std::io::pipe().map_err(io)?;
    let st_raw = st_w.as_raw_fd();
    // A socket, not a pipe: a pipe could be reopened through /proc by any process
    // of the user, a socket cannot.
    let secret_pair = match &secret {
        Some(_) => Some(std::os::unix::net::UnixStream::pair().map_err(io)?),
        None => None,
    };
    let sk_raw = secret_pair.as_ref().map_or(-1, |(_, c)| c.as_raw_fd());
    let mut cmd = tokio::process::Command::new(&cfg.shim_program);
    // The spec goes on stdin, not in argv: every user can read a process's
    // command line, and the spec holds the command's environment.
    cmd.args(&cfg.shim_args)
        .arg(SHIM_ARG)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::from(OwnedFd::from(out_w)))
        .stderr(std::process::Stdio::from(OwnedFd::from(out_w2)))
        .kill_on_drop(false);
    // SAFETY: dup2 and fcntl only, both async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            // Out of the way first, so placing one cannot overwrite the other.
            let high = |fd: i32| libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10);
            let st = high(st_raw);
            let sk = if sk_raw >= 0 { high(sk_raw) } else { -1 };
            if st < 0 || (sk_raw >= 0 && sk < 0) || libc::dup2(st, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if sk >= 0 && libc::dup2(sk, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(io)?;
    drop(cmd);
    drop(st_w);
    let stdin = child.stdin.take();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        // Closing stdin ends the spec; a shim that died first just misses it.
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(spec_json.as_bytes()).await;
        }
    });
    if let (Some((mine, theirs)), Some(secret)) = (secret_pair, secret) {
        drop(theirs);
        send_secret(mine, secret);
    }
    let pid = child
        .id()
        .ok_or_else(|| io(std::io::Error::other("no pid")))? as i32;
    // SAFETY: pidfd_open on our own unreaped child.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pidfd < 0 {
        let _ = child.start_kill();
        return Err(io(std::io::Error::last_os_error()));
    }
    // SAFETY: the syscall returned a new descriptor we own.
    let pidfd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(pidfd as i32) };
    let (tx, exited) = watch::channel(false);
    #[cfg(target_os = "linux")]
    let cgroup = spec.cgroup.clone();
    #[cfg(not(target_os = "linux"))]
    let _ = spec;
    let scope = Arc::new(Scope {
        pidfd,
        #[cfg(target_os = "linux")]
        cgroup: cgroup.clone(),
        exited,
    });
    tokio::spawn(async move {
        let _ = child.wait().await;
        #[cfg(target_os = "linux")]
        if let Some(cg) = cgroup {
            // The shim is gone; whatever is left in its cgroup goes too.
            if crate::cgroup::populated(&cg) {
                crate::cgroup::kill(&cg);
            }
            crate::cgroup::remove(cg).await;
        }
        remove_tmp(tmp).await;
        let _ = tx.send(true);
    });
    let rx = tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(out_r)).map_err(io)?;
    let st_rx = tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(st_r)).map_err(io)?;
    let status = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut st_rx = st_rx;
        let mut s = String::new();
        st_rx.read_to_string(&mut s).await.ok()?;
        (!s.trim().is_empty()).then_some(s)
    });
    Ok(Spawned {
        scope,
        output: OutputReader { rx },
        status,
    })
}

/// Hands the secret to the shim once it says it is ready (undumpable, untraced).
/// Any failure leaves the shim without it, and it does not run the command.
#[cfg(unix)]
fn send_secret(sock: std::os::unix::net::UnixStream, secret: Secret) {
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Ok(()) = sock.set_nonblocking(true) else {
            return;
        };
        let Ok(mut s) = tokio::net::UnixStream::from_std(sock) else {
            return;
        };
        let mut ready = [0u8; 1];
        let got = tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut ready)).await;
        if matches!(got, Ok(Ok(_))) && ready == *b"R" {
            let _ = s.write_all(secret.expose().as_bytes()).await;
            let _ = s.shutdown().await;
        }
    });
}

#[cfg(windows)]
fn spawn(
    cfg: &ExecConfig,
    spec_json: String,
    _spec: &ShimSpec,
    _secret: Option<Secret>,
    tmp: Option<PathBuf>,
) -> Result<Spawned, RpcError> {
    use std::io::Read;
    use tokio::io::AsyncWriteExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let io = |e: std::io::Error| RpcError::new(code::IO, format!("cannot start the command: {e}"));
    let job = win::Job::new().map_err(io)?;
    let (mut out_r, out_w) = std::io::pipe().map_err(io)?;
    let out_w2 = out_w.try_clone().map_err(io)?;
    let mut cmd = tokio::process::Command::new(&cfg.shim_program);
    cmd.args(&cfg.shim_args)
        .arg(SHIM_ARG)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::from(
            std::os::windows::io::OwnedHandle::from(out_w),
        ))
        .stderr(std::process::Stdio::from(
            std::os::windows::io::OwnedHandle::from(out_w2),
        ))
        // A console of its own without a window: the logon task's client has no
        // console, and each command would otherwise open a window on the desktop.
        // The shim sets this console to UTF-8 for the shell.
        .creation_flags(CREATE_NO_WINDOW)
        .kill_on_drop(false);
    let mut child = cmd.spawn().map_err(io)?;
    drop(cmd);
    let handle = child
        .raw_handle()
        .ok_or_else(|| io(std::io::Error::other("no process handle")))?;
    if let Err(e) = job.assign(handle) {
        let _ = child.start_kill();
        return Err(io(e));
    }
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io(std::io::Error::other("no stdin")))?;
    let (tx, exited) = watch::channel(false);
    let (status_tx, status_rx) = tokio::sync::oneshot::channel::<Option<String>>();
    tokio::spawn(async move {
        // The shim waits for its spec, which comes only now that it is in the
        // job, so nothing runs outside the job. Not in argv, as on Linux.
        let _ = stdin.write_all(spec_json.as_bytes()).await;
        drop(stdin);
        let st = child.wait().await.ok().and_then(|s| s.code());
        let _ = status_tx.send(st.map(|c| format!("exit {c}")));
        remove_tmp(tmp).await;
        let _ = tx.send(true);
    });
    let status = tokio::spawn(async move { status_rx.await.ok().flatten() });
    let (otx, orx) = mpsc::channel(8);
    std::thread::spawn(move || {
        let mut buf = vec![0u8; MAX_CHUNK];
        loop {
            match out_r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if otx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    Ok(Spawned {
        scope: Arc::new(Scope { job, exited }),
        output: OutputReader { rx: orx },
        status,
    })
}

#[cfg(windows)]
mod win {
    //! Job Objects: every process in a job dies with `TerminateJobObject`, and with
    //! kill-on-close when the client itself goes away.

    use std::io;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };

    pub struct Job(HANDLE);

    // SAFETY: a job handle may be used from any thread.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        pub fn new() -> io::Result<Job> {
            // SAFETY: an anonymous job with default security.
            let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Job(h);
            // SAFETY: zeroed POD limit structure, then one flag set.
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `info` matches the information class and outlives the call.
            let ok = unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        pub fn assign(&self, process: std::os::windows::io::RawHandle) -> io::Result<()> {
            // SAFETY: both handles are open.
            if unsafe { AssignProcessToJobObject(self.0, process as HANDLE) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn terminate(&self) {
            // SAFETY: the job handle is open.
            unsafe { TerminateJobObject(self.0, 1) };
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: closing our own handle; kill-on-close ends what is left.
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_takes_the_command_as_one_plain_argument() {
        let cmd = "Write-Output 'a\"b' \"c\\\"; exit 3";
        for shell in ["powershell.exe", "/usr/bin/pwsh"] {
            let args = shell_args(Path::new(shell), cmd);
            assert_eq!(args[args.len() - 2..], ["-Command", cmd], "{shell}");
            assert!(!args.iter().any(|a| a == "-EncodedCommand"));
        }
        assert_eq!(shell_args(Path::new("/bin/bash"), cmd), ["-c", cmd]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_elevated_command_without_its_cgroup_is_refused() {
        // Cgroups are on, but this command's cgroup cannot be made: a command of
        // the user runs without it, a root one must not.
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path().to_path_buf();
        let mut e = Execs::new(ExecConfig {
            shim_program: PathBuf::from("/bin/true"),
            shim_args: vec![],
            shell: Some(PathBuf::from("/bin/sh")),
            base_env: vec![],
            env_passthrough: vec![],
            output_cap: 1024,
            max_timeout: Duration::from_secs(5),
            max_running: 4,
            tmp_base: t.clone(),
        });
        e.cgroups = Some(crate::cgroup::CgroupBase::at(t.join("missing/base")));
        let permit = Permit {
            path: PathBuf::from("/"),
            root: None,
            confine: Confine::None,
            elevate: Some(PathBuf::from("/nonexistent/sudo")),
        };
        let (tx, _rx) = mpsc::channel(1);
        let err = e
            .start(1, "sudo true", &permit, None, tx)
            .err()
            .expect("an elevated command without its cgroup started");
        assert_eq!(err.code, code::DENIED, "{err:?}");
        let user = Permit {
            elevate: None,
            ..permit
        };
        let (tx, _rx) = mpsc::channel(1);
        assert!(e.start(2, "true", &user, None, tx).is_ok());
    }
}
