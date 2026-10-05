//! `pithagoras-sync run`: the background client. Loads the config, builds the policy
//! engine and the command runner, keeps the link to the portal, and answers the
//! control channel.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sync_connector::link::{self, LinkConfig, LinkState, LinkStatus};
use sync_connector::{Device, pair};
use sync_ops::{ExecConfig, Execs, info};
use sync_policy::*;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::control::{self, Reply, Request, Status};

pub struct Daemon {
    dirs: Dirs,
    device: Arc<Device>,
    cfg: Mutex<DeviceConfig>,
    link_status: watch::Receiver<LinkStatus>,
    relink: mpsc::Sender<()>,
    approvals: String,
}

/// Who answers approvals, and how `status` describes it.
async fn approver(profile: Profile) -> (Arc<dyn Approver>, String) {
    if profile == Profile::Desktop {
        #[cfg(unix)]
        if let Some(a) = sync_policy::notify::NotifyApprover::connect().await {
            return (Arc::new(a), "notifications".into());
        }
        return (
            Arc::new(NoApprover {
                why: "no notification service",
            }),
            "nobody: no notification service with Allow/Deny actions, so what would ask is denied"
                .into(),
        );
    }
    (
        Arc::new(NoApprover { why: "headless" }),
        "nobody (headless): what would ask is denied".into(),
    )
}

fn now_ms() -> i64 {
    system_clock()()
}

pub async fn run(dirs: Dirs) -> Result<(), String> {
    let socket = dirs.socket();
    if let Ok(Some(_)) = control::send(&socket, Request::Status).await {
        return Err("pithagoras-sync is already running for this user".into());
    }
    let mut cfg = DeviceConfig::load(&dirs.config_file())?;
    if cfg.policy.date_full(now_ms()) {
        cfg.save(&dirs.config_file())?;
    }
    let home = info::home().ok_or("cannot find the home directory")?;
    let audit = Arc::new(
        AuditLog::open(&dirs.audit_file())
            .map_err(|e| format!("{}: {e}", dirs.audit_file().display()))?,
    );
    let (approver, approvals) = approver(cfg.profile).await;
    let landlock = sync_ops::landlock_available();
    let engine = Arc::new(Engine::new(
        cfg.policy.clone(),
        cfg.profile,
        EngineOptions {
            home: home.clone(),
            own_dirs: vec![
                dirs.config.clone(),
                dirs.state.clone(),
                dirs.runtime.clone(),
            ],
            approver,
            audit,
            clock: system_clock(),
            landlock,
        },
    ));
    if dirs.paused_file().exists() {
        engine.pause();
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this program: {e}"))?;
    let execs = Arc::new(Execs::new(ExecConfig {
        shim_program: exe,
        shim_args: Vec::new(),
        shell: cfg.exec.shell.clone(),
        base_env: std::env::vars().collect(),
        env_passthrough: cfg.exec.env_passthrough.clone(),
        output_cap: cfg.exec.output_cap_bytes,
        max_timeout: Duration::from_secs(cfg.exec.max_timeout_secs),
        max_running: cfg.exec.max_running as usize,
        tmp_base: dirs.state.join("tmp"),
    }));
    let name = cfg
        .portal
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_else(|| pair::name_from_hostname(&info::hostname()));
    let device = Device::new(engine, execs, name, home);
    info!(
        "started: profile {:?}, mode {:?}, landlock {landlock}, cgroups {}, approvals: {approvals}",
        cfg.profile,
        device.engine.effective_mode(),
        device.execs.uses_cgroups()
    );
    if is_root() {
        warn!(
            "running as root: the portal's agent acts with root's rights where the policy allows"
        );
    }

    let (status_tx, link_status) =
        watch::channel(LinkStatus::new(LinkState::Stopped, Some("starting".into())));
    let (relink, relink_rx) = mpsc::channel(4);
    let daemon = Arc::new(Daemon {
        dirs: dirs.clone(),
        device: device.clone(),
        cfg: Mutex::new(cfg),
        link_status,
        relink,
        approvals,
    });
    let (shutdown_tx, shutdown) = watch::channel(false);
    let control = tokio::spawn(serve_control(daemon.clone(), socket, shutdown.clone()));
    let supervisor = tokio::spawn(supervise(
        daemon.clone(),
        relink_rx,
        status_tx,
        shutdown.clone(),
    ));
    wait_for_signals(&daemon).await;
    info!("shutting down");
    shutdown_tx.send_replace(true);
    let _ = tokio::time::timeout(Duration::from_secs(15), supervisor).await;
    device.execs.kill_all().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), control).await;
    Ok(())
}

#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn is_root() -> bool {
    false
}

/// Returns on SIGTERM or SIGINT (Ctrl+C on Windows); SIGHUP reloads the config.
async fn wait_for_signals(daemon: &Arc<Daemon>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
            signal(SignalKind::hangup()),
        ) else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        loop {
            tokio::select! {
                _ = term.recv() => return,
                _ = int.recv() => return,
                _ = hup.recv() => {
                    if let Err(e) = daemon.reload() {
                        warn!("reload failed, keeping the old config: {e}");
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        let _ = daemon;
        let _ = tokio::signal::ctrl_c().await;
    }
}

impl Daemon {
    fn link_config(&self) -> Result<Option<LinkConfig>, String> {
        let Some(portal) = self.cfg.lock().unwrap().portal.clone() else {
            return Ok(None);
        };
        let token = pair::load_token(&self.dirs.token_file())?;
        Ok(Some(LinkConfig { portal, token }))
    }

    /// Takes the config file as it is now. A bad file leaves the running policy as it
    /// was.
    pub fn reload(&self) -> Result<(), String> {
        let mut cfg = DeviceConfig::load(&self.dirs.config_file())?;
        if cfg.policy.date_full(now_ms()) {
            cfg.save(&self.dirs.config_file())?;
        }
        let old_profile = self.cfg.lock().unwrap().profile;
        if cfg.profile != old_profile {
            warn!("the profile changed; restart the client for it to take effect");
            cfg.profile = old_profile;
        }
        self.device.engine.reload(cfg.policy.clone(), cfg.profile);
        if let Some(p) = &cfg.portal {
            self.device.set_name(p.name.clone());
        }
        *self.cfg.lock().unwrap() = cfg;
        let _ = self.relink.try_send(());
        info!("config reloaded");
        Ok(())
    }

    pub fn status(&self) -> Status {
        let cfg = self.cfg.lock().unwrap().clone();
        let info = self.device.info();
        Status {
            pid: std::process::id(),
            version: sync_connector::device::CLIENT_VERSION.into(),
            profile: cfg.profile,
            portal: cfg.portal.as_ref().map(|p| p.url.clone()),
            device_id: cfg.portal.as_ref().map(|p| p.device_id.clone()),
            name: cfg.portal.as_ref().map(|p| p.name.clone()),
            link: self.link_status.borrow().clone(),
            paused: self.device.is_paused(),
            mode: info.mode,
            mode_expires_ms: info.mode_expires_ms,
            folders: info.folders,
            folders_shell: info.folders_shell,
            shell: info.shell,
            approvals: self.approvals.clone(),
            running_commands: self.device.execs.running(),
            cgroups: self.device.execs.uses_cgroups(),
            landlock: self.device.engine.landlock_available(),
            config_file: self.dirs.config_file().to_string_lossy().into_owned(),
            audit_file: self.dirs.audit_file().to_string_lossy().into_owned(),
        }
    }

    async fn handle(&self, req: Request) -> Reply {
        match req {
            Request::Status => Reply {
                status: Some(self.status()),
                ..Reply::ok()
            },
            Request::Panic => {
                // The marker first: a crash right after still comes back paused.
                if let Err(e) = sync_policy::config::write_private(&self.dirs.paused_file(), b"") {
                    warn!("cannot write the pause marker: {e}");
                }
                self.device.pause().await;
                Reply::ok()
            }
            Request::Unlock => {
                if let Err(e) = std::fs::remove_file(self.dirs.paused_file())
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    return Reply::err(format!("cannot remove the pause marker: {e}"));
                }
                self.device.unlock();
                Reply::ok()
            }
            Request::Reload => match self.reload() {
                Ok(()) => Reply::ok(),
                Err(e) => Reply::err(e),
            },
        }
    }
}

/// Keeps one link running for the current pairing; restarts it when a reload
/// changed the pairing, and waits for one after the portal refused the device.
async fn supervise(
    d: Arc<Daemon>,
    mut relink: mpsc::Receiver<()>,
    status: watch::Sender<LinkStatus>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let cfg = match d.link_config() {
            Ok(Some(c)) => c,
            other => {
                let why = match other {
                    Err(e) => e,
                    _ => "not paired: run `pithagoras-sync pair <uri>`".into(),
                };
                status.send_replace(LinkStatus::new(LinkState::Stopped, Some(why)));
                tokio::select! {
                    _ = relink.recv() => continue,
                    _ = until(&mut shutdown) => return,
                }
            }
        };
        let current = (cfg.portal.clone(), cfg.token.clone());
        let (stop, stop_rx) = watch::channel(false);
        let mut task = tokio::spawn(link::run(d.device.clone(), cfg, status.clone(), stop_rx));
        loop {
            tokio::select! {
                end = &mut task => {
                    if let Ok(link::LinkEnd::Rejected(why)) = end {
                        warn!("{why}");
                    }
                    // Down until the owner pairs again (or the client stops).
                    tokio::select! {
                        _ = relink.recv() => break,
                        _ = until(&mut shutdown) => return,
                    }
                }
                _ = relink.recv() => {
                    let same = matches!(d.link_config(), Ok(Some(c)) if (c.portal.clone(), c.token.clone()) == current);
                    if !same {
                        stop.send_replace(true);
                        let _ = (&mut task).await;
                        break;
                    }
                }
                _ = until(&mut shutdown) => {
                    stop.send_replace(true);
                    let _ = (&mut task).await;
                    return;
                }
            }
        }
    }
}

async fn until(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|v| *v).await;
}

async fn handle_conn<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    d: &Daemon,
    s: S,
    from_own_command: bool,
) {
    let (r, w) = tokio::io::split(s);
    let reply = match control::read_request(r).await {
        Ok(req) if from_own_command && !req.allowed_from_own_commands() => {
            Reply::err("commands the client runs for the portal cannot unlock or reload it")
        }
        Ok(req) => d.handle(req).await,
        Err(e) => Reply::err(e),
    };
    control::write_reply(w, &reply).await;
}

#[cfg(unix)]
async fn serve_control(d: Arc<Daemon>, socket: PathBuf, mut shutdown: watch::Receiver<bool>) {
    use tokio::net::UnixListener;
    if let Some(dir) = socket.parent()
        && let Err(e) = sync_policy::private::private_dir(dir)
    {
        return warn!("no control socket: {}: {e}", dir.display());
    }
    // No client answered on it (checked at start), so a socket file there is stale.
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => return warn!("no control socket at {}: {e}", socket.display()),
    };
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    }
    // SAFETY: geteuid cannot fail.
    let me = unsafe { libc::geteuid() };
    loop {
        tokio::select! {
            r = listener.accept() => {
                let Ok((s, _)) = r else { continue };
                let cred = s.peer_cred().ok();
                if cred.is_none_or(|c| c.uid() != me) {
                    continue;
                }
                let own = cred
                    .and_then(|c| c.pid())
                    .is_some_and(|pid| control::descends_from(pid as u32, std::process::id()));
                let d = d.clone();
                tokio::spawn(async move { handle_conn(&d, s, own).await });
            }
            _ = until(&mut shutdown) => break,
        }
    }
    let _ = std::fs::remove_file(&socket);
}

#[cfg(windows)]
async fn serve_control(d: Arc<Daemon>, socket: PathBuf, mut shutdown: watch::Receiver<bool>) {
    use tokio::net::windows::named_pipe::ServerOptions;
    let mut server = match ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&socket)
    {
        Ok(s) => s,
        Err(e) => return warn!("no control pipe at {}: {e}", socket.display()),
    };
    loop {
        tokio::select! {
            r = server.connect() => {
                if r.is_err() {
                    continue;
                }
                let next = match ServerOptions::new().reject_remote_clients(true).create(&socket) {
                    Ok(n) => n,
                    Err(e) => return warn!("control pipe: {e}"),
                };
                let conn = std::mem::replace(&mut server, next);
                let d = d.clone();
                // Windows has no cheap ancestry check here; see docs/windows.md.
                tokio::spawn(async move { handle_conn(&d, conn, false).await });
            }
            _ = until(&mut shutdown) => break,
        }
    }
}
