//! `pithagoras-sync run`: the background client. Loads the config, builds the policy
//! engine and the command runner, keeps the link to the portal, and answers the
//! control channel.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sync_connector::link::{self, LinkConfig, LinkState, LinkStatus};
use sync_connector::settings::ConfigStore;
use sync_connector::{Device, pair};
use sync_ops::{ExecConfig, Execs, info};
use sync_policy::*;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::control::{self, Reply, Request, Status};
use sync_policy::config::{Elevation, SecretStorage};
use sync_policy::secret::Secret;

pub struct Daemon {
    dirs: Dirs,
    device: Arc<Device>,
    store: Arc<ConfigStore>,
    queue: Arc<ApprovalQueue>,
    link_status: watch::Receiver<LinkStatus>,
    relink: mpsc::Sender<()>,
    approvals: String,
}

/// With `approvals.desktop_notifications` on a Linux desktop: each approval is also
/// shown as a notification (Allow once / Deny) answering the same queue. Off by
/// default; the device's own dialog replaces it in phase 2.
#[cfg(unix)]
async fn mirror_to_notifications(queue: Arc<ApprovalQueue>) -> bool {
    use std::collections::HashMap;
    use sync_policy::notify::NotifyApprover;
    let Some(n) = NotifyApprover::connect().await else {
        warn!("approvals.desktop_notifications is on, but there is no notification service");
        return false;
    };
    let n = Arc::new(n);
    let mut events = queue.subscribe();
    tokio::spawn(async move {
        let mut shown: HashMap<u64, tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            match events.recv().await {
                Ok(ApprovalEvent::Requested(info)) => {
                    let (n, q) = (n.clone(), queue.clone());
                    let id = info.id;
                    shown.insert(
                        id,
                        tokio::spawn(async move {
                            let req = ApprovalRequest {
                                call: None,
                                chat: info.chat,
                                tool: info.tool,
                                target: info.target,
                                reasons: info.reasons,
                                preview: info.preview,
                                offer_chat: false,
                                max_minutes: info.max_minutes,
                                expires_ms: info.expires_ms,
                                on_timeout_allow: false,
                            };
                            let choice = match n.ask(&req).await {
                                Answer::Deny => sync_proto::methods::Choice::Deny,
                                _ => sync_proto::methods::Choice::Once,
                            };
                            let _ = q.answer(id, choice, None, "notification");
                        }),
                    );
                }
                // Answered elsewhere: dropping the task withdraws the notification.
                Ok(ApprovalEvent::Resolved(r)) => {
                    if let Some(t) = shown.remove(&r.id) {
                        t.abort();
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(_) => break,
            }
        }
    });
    true
}

fn now_ms() -> i64 {
    system_clock()()
}

pub async fn run(dirs: Dirs) -> Result<(), String> {
    // Other processes of this user (the commands it runs among them) cannot read
    // the client's memory, where the elevation secret lives.
    #[cfg(target_os = "linux")]
    sync_policy::secret::undumpable();
    let socket = dirs.socket();
    if let Ok(Some(_)) = control::send(&socket, Request::Status).await {
        return Err("pithagoras-sync is already running for this user".into());
    }
    let mut cfg = DeviceConfig::load(&dirs.config_file())?;
    if cfg.policy.date_full(now_ms()) {
        cfg.save(&dirs.config_file())?;
    }
    // Without its control channel `panic` could not reach the client, so it does not
    // start at all.
    let listener = open_control(&socket)?;
    let home = info::home().ok_or("cannot find the home directory")?;
    let audit = Arc::new(
        AuditLog::open(&dirs.audit_file())
            .map_err(|e| format!("{}: {e}", dirs.audit_file().display()))?,
    );
    if is_root() && !cfg.policy.privilege.allow_root {
        return Err(format!(
            "refusing to run as {}: the portal's agent would act with its rights. A dedicated user is safer (`pithagoras-sync setup --create-user`); to allow it, run `pithagoras-sync config set policy.privilege.allow_root true` as this user.",
            if cfg!(windows) {
                "an elevated administrator"
            } else {
                "root"
            }
        ));
    }
    let queue = ApprovalQueue::new(system_clock());
    #[allow(unused_mut)]
    let mut approvals =
        "through the portal's Devices tab and `pithagoras-sync approve`".to_string();
    #[cfg(unix)]
    if cfg.policy.approvals.desktop_notifications
        && cfg.profile == Profile::Desktop
        && mirror_to_notifications(queue.clone()).await
    {
        approvals.push_str(", and as desktop notifications");
    }
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
            approver: queue.clone(),
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
    let store = ConfigStore::new(
        dirs.config_file(),
        cfg.clone(),
        engine.clone(),
        execs.clone(),
    );
    let device = Device::with_parts(
        engine,
        execs,
        name,
        home,
        Some(queue.clone()),
        Some(store.clone()),
    );
    crate::secrets::scrub_log_with(device.secrets.clone());
    device.engine.seal(vec![crate::secrets::file(&dirs)]);
    if cfg.policy.privilege.secret_storage == SecretStorage::File {
        match crate::secrets::load(&crate::secrets::file(&dirs)) {
            Ok(Some(s)) => device.secrets.set(s),
            Ok(None) => {}
            Err(e) => warn!("elevation password not loaded: {e}"),
        }
    }
    info!(
        "started: profile {:?}, mode {:?}, landlock {landlock}, cgroups {}, approvals: {approvals}",
        cfg.profile,
        device.engine.effective_mode(),
        device.execs.uses_cgroups()
    );
    if is_root() {
        warn!(
            "running as root (privilege.allow_root): the portal's agent acts with its rights where the policy allows"
        );
    }

    let (status_tx, link_status) =
        watch::channel(LinkStatus::new(LinkState::Stopped, Some("starting".into())));
    let (relink, relink_rx) = mpsc::channel(4);
    drop(cfg);
    let daemon = Arc::new(Daemon {
        dirs: dirs.clone(),
        device: device.clone(),
        store,
        queue,
        link_status,
        relink,
        approvals,
    });
    let (shutdown_tx, shutdown) = watch::channel(false);
    let control = tokio::spawn(serve_control(
        daemon.clone(),
        listener,
        socket,
        shutdown.clone(),
    ));
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

/// Whether this process runs with an elevated administrator token.
#[cfg(windows)]
fn is_root() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle needs no closing; the token handle is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION of the size given.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    // SAFETY: the token handle is ours.
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.TokenIsElevated != 0
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
        let Some(portal) = self.store.config().portal else {
            return Ok(None);
        };
        let token = pair::load_token(&self.dirs.token_file())?;
        Ok(Some(LinkConfig { portal, token }))
    }

    /// Takes the config file as it is now. A bad file leaves the running policy as it
    /// was.
    pub fn reload(&self) -> Result<(), String> {
        let cfg = self.store.reload()?;
        if let Some(p) = &cfg.portal {
            self.device.set_name(p.name.clone());
        }
        let _ = self.relink.try_send(());
        info!("config reloaded");
        Ok(())
    }

    pub fn status(&self) -> Status {
        let cfg = self.store.config();
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
            approvals_waiting: self.queue.list().len(),
            portal_policy: cfg.portal_policy.as_str().into(),
            elevation: self.elevation_status(&cfg),
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
                // Kept in memory only, the secret is gone until the owner types it
                // again; a stored one comes back with unlock.
                self.device.secrets.clear();
                Reply::ok()
            }
            Request::Unlock => {
                if let Err(e) = std::fs::remove_file(self.dirs.paused_file())
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    return Reply::err(format!("cannot remove the pause marker: {e}"));
                }
                self.device.unlock();
                self.load_stored_secret();
                Reply::ok()
            }
            Request::Reload => match self.reload() {
                Ok(()) => Reply::ok(),
                Err(e) => Reply::err(e),
            },
            Request::Approvals => Reply {
                approvals: Some(self.queue.list()),
                ..Reply::ok()
            },
            Request::Answer {
                id,
                answer,
                minutes,
            } => match self.queue.answer(id, answer, minutes, "device") {
                Ok(()) => Reply::ok(),
                Err(e) => Reply::err(e.to_string()),
            },
            Request::SecretSet { name, value } => match self.set_secret(&name, value) {
                Ok(()) => Reply::ok(),
                Err(e) => Reply::err(e),
            },
            Request::SecretClear { name } => {
                if name != crate::secrets::ELEVATION {
                    return Reply::err(format!("there is no secret {name}"));
                }
                self.device.secrets.clear();
                if let Err(e) = crate::secrets::remove(&crate::secrets::file(&self.dirs)) {
                    return Reply::err(e);
                }
                info!("elevation password cleared");
                Reply::ok()
            }
        }
    }

    fn set_secret(&self, name: &str, value: Secret) -> Result<(), String> {
        if name != crate::secrets::ELEVATION {
            return Err(format!("there is no secret {name}"));
        }
        if !cfg!(target_os = "linux") {
            return Err("elevation is built for Linux (sudo) only in this version".into());
        }
        #[cfg(target_os = "linux")]
        if sync_policy::secret::traced() {
            return Err("the client is being traced; it does not take the password now".into());
        }
        crate::secrets::check(value.expose())?;
        let storage = self.store.config().policy.privilege.secret_storage;
        if storage == SecretStorage::File {
            crate::secrets::save(&crate::secrets::file(&self.dirs), &value)?;
        }
        self.device.secrets.set(value);
        info!("elevation password set (kept in {})", storage.as_str());
        Ok(())
    }

    fn load_stored_secret(&self) {
        if self.store.config().policy.privilege.secret_storage != SecretStorage::File {
            return;
        }
        match crate::secrets::load(&crate::secrets::file(&self.dirs)) {
            Ok(Some(s)) => self.device.secrets.set(s),
            Ok(None) => {}
            Err(e) => warn!("elevation password not loaded: {e}"),
        }
    }

    fn elevation_status(&self, cfg: &DeviceConfig) -> String {
        let p = &cfg.policy.privilege;
        match p.elevation {
            Elevation::Off => "off".into(),
            Elevation::Sudo if self.device.secrets.is_set() => {
                format!("sudo, password set (kept in {})", p.secret_storage.as_str())
            }
            Elevation::Sudo => {
                "sudo, no password set (sudo -n: only what sudoers allows without one)".into()
            }
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
        Ok(req) if from_own_command && !req.allowed_from_own_commands() => Reply::err(
            "commands the client runs for the portal cannot change, unlock or reload it, answer its approvals or set its secrets",
        ),
        Ok(req) => d.handle(req).await,
        Err(e) => Reply::err(e),
    };
    control::write_reply(w, &reply).await;
}

#[cfg(unix)]
type ControlListener = tokio::net::UnixListener;

#[cfg(unix)]
fn open_control(socket: &Path) -> Result<ControlListener, String> {
    let fail =
        |e: &dyn std::fmt::Display| format!("no control socket at {}: {e}", socket.display());
    if let Some(dir) = socket.parent() {
        sync_policy::private::private_dir(dir).map_err(|e| fail(&e))?;
    }
    // No client answered on it (checked at start), so a socket file there is stale.
    let _ = std::fs::remove_file(socket);
    let listener = tokio::net::UnixListener::bind(socket).map_err(|e| fail(&e))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| fail(&e))?;
    Ok(listener)
}

#[cfg(unix)]
async fn serve_control(
    d: Arc<Daemon>,
    listener: ControlListener,
    socket: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) {
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
type ControlListener = tokio::net::windows::named_pipe::NamedPipeServer;

/// The first instance of the pipe. Failing when the name exists means a program
/// that took the name first can stop the client from starting, but never receive
/// what the owner's CLI sends to it.
#[cfg(windows)]
fn open_control(socket: &Path) -> Result<ControlListener, String> {
    tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(socket)
        .map_err(|e| format!("no control pipe at {}: {e}", socket.display()))
}

#[cfg(windows)]
async fn serve_control(
    d: Arc<Daemon>,
    listener: ControlListener,
    socket: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) {
    use tokio::net::windows::named_pipe::ServerOptions;
    let mut server = listener;
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
