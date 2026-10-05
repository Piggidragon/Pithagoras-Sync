//! Running commands for `exec.start`: spawn the shim, stream the merged output with
//! backpressure and a cap, enforce the timeout, and kill whole trees on request,
//! panic or disconnect.
//!
//! A command whose shell exited may leave background processes; they keep running
//! (as on the server) until a panic or disconnect, which kills them too.

use std::collections::HashMap;
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
    /// Shells that exited while their background processes live on.
    lingering: Vec<Arc<Scope>>,
}

pub struct Execs {
    /// Read once per command; the owner's limits change at runtime.
    cfg: std::sync::RwLock<ExecConfig>,
    table: Arc<Mutex<Table>>,
    #[cfg(target_os = "linux")]
    cgroups: Option<crate::cgroup::CgroupBase>,
    /// The elevation secret: injected for `sudo` commands, scrubbed from output.
    secrets: std::sync::OnceLock<Arc<SecretSlot>>,
}

impl Execs {
    pub fn new(cfg: ExecConfig) -> Execs {
        Execs {
            cfg: std::sync::RwLock::new(cfg),
            table: Arc::new(Mutex::new(Table::default())),
            #[cfg(target_os = "linux")]
            cgroups: crate::cgroup::CgroupBase::detect(),
            secrets: std::sync::OnceLock::new(),
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
        {
            let mut t = self.table.lock().unwrap();
            t.lingering.retain(|s| !s.done());
            if t.running.contains_key(&stream) {
                return Err(RpcError::new(code::INVALID_PARAMS, "stream already in use"));
            }
            if t.running.len() >= cfg.max_running {
                return Err(RpcError::new(code::BUSY, "too many commands running"));
            }
        }
        let timeout = timeout.unwrap_or(cfg.max_timeout).min(cfg.max_timeout);
        let mut env = crate::env::scrubbed(&cfg.base_env, &cfg.env_passthrough);
        let landlock = match &permit.confine {
            Confine::None => None,
            Confine::Landlock(rules) => {
                // A private temporary directory: the confined shell cannot write /tmp.
                let tmp = cfg
                    .tmp_base
                    .join(format!("exec-{}-{stream}", std::process::id()));
                std::fs::create_dir_all(&tmp)
                    .map_err(|e| RpcError::new(code::IO, format!("temp dir: {e}")))?;
                env.retain(|(k, _)| k != "TMPDIR");
                env.push(("TMPDIR".into(), tmp.to_string_lossy().into_owned()));
                let mut write = rules.write.clone();
                write.push(tmp);
                Some(LandlockSpec {
                    read: rules.read.clone(),
                    write,
                    exec: rules.exec.clone(),
                })
            }
        };
        let shell = self.shell();
        let (program, args, secret) = match &permit.elevate {
            None => (shell.clone(), shell_args(&shell, command), None),
            Some(sudo) => self.elevated(sudo, &shell, command)?,
        };
        let spec = ShimSpec {
            args,
            program,
            cwd: permit.path.clone(),
            env,
            parent: std::process::id(),
            #[cfg(target_os = "linux")]
            cgroup: self.cgroups.as_ref().and_then(|c| c.create().ok()),
            #[cfg(not(target_os = "linux"))]
            cgroup: None,
            landlock,
            secret_fd: secret.is_some(),
        };
        let spec_json = serde_json::to_string(&spec)
            .map_err(|e| RpcError::new(code::INTERNAL, e.to_string()))?;
        let spawned = spawn(&cfg, &spec_json, &spec, secret)?;
        let scope = spawned.scope;
        self.table
            .lock()
            .unwrap()
            .running
            .insert(stream, scope.clone());
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
                t.running.remove(&stream);
                if !scope.done() {
                    t.lingering.push(scope.clone());
                }
            }
            let mut o = parse_status(status.as_deref());
            o.timed_out = timed_out;
            o.truncated = truncated;
            o
        });
        Ok(Started { outcome })
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
            "elevated commands are only built for Linux in this version",
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
        if out.send(chunk).await.is_err() {
            break;
        }
    }
    truncated
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

/// The arguments that make `shell` run `command`. PowerShell gets it base64-encoded
/// (`-EncodedCommand`), which avoids every quoting problem.
pub fn shell_args(shell: &Path, command: &str) -> Vec<String> {
    let name = shell
        .file_stem()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name == "pwsh" || name == "powershell" {
        use base64::Engine;
        let utf16: Vec<u8> = command.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        vec![
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-ExecutionPolicy".into(),
            "Bypass".into(),
            "-EncodedCommand".into(),
            encoded,
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
    spec_json: &str,
    spec: &ShimSpec,
    secret: Option<Secret>,
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
    cmd.args(&cfg.shim_args)
        .arg(SHIM_ARG)
        .arg(spec_json)
        .env_clear()
        .stdin(std::process::Stdio::null())
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
    spec_json: &str,
    _spec: &ShimSpec,
    _secret: Option<Secret>,
) -> Result<Spawned, RpcError> {
    use std::io::Read;
    use tokio::io::AsyncWriteExt;
    let io = |e: std::io::Error| RpcError::new(code::IO, format!("cannot start the command: {e}"));
    let job = win::Job::new().map_err(io)?;
    let (mut out_r, out_w) = std::io::pipe().map_err(io)?;
    let out_w2 = out_w.try_clone().map_err(io)?;
    let mut cmd = tokio::process::Command::new(&cfg.shim_program);
    cmd.args(&cfg.shim_args)
        .arg(SHIM_ARG)
        .arg(spec_json)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::from(
            std::os::windows::io::OwnedHandle::from(out_w),
        ))
        .stderr(std::process::Stdio::from(
            std::os::windows::io::OwnedHandle::from(out_w2),
        ))
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
        // The shim waits for this byte, so nothing runs outside the job.
        let _ = stdin.write_all(b"g").await;
        drop(stdin);
        let st = child.wait().await.ok().and_then(|s| s.code());
        let _ = status_tx.send(st.map(|c| format!("exit {c}")));
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
