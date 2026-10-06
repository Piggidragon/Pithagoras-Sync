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
use sync_connector::token::TokenStore;
use sync_policy::config::{Elevation, SecretStorage};
use sync_policy::keyring::SecretStore;
use sync_policy::secret::Secret;

pub struct Daemon {
    dirs: Dirs,
    /// The program this client was started from.
    exe: std::path::PathBuf,
    device: Arc<Device>,
    store: Arc<ConfigStore>,
    queue: Arc<ApprovalQueue>,
    link_status: watch::Receiver<LinkStatus>,
    relink: mpsc::Sender<()>,
    approvals: String,
    /// `restart` asked the client to exit for its unit to start it again (after
    /// an update).
    restart: tokio::sync::Notify,
    restarting: std::sync::atomic::AtomicBool,
    /// The OS keyring, for a token or password kept there.
    keyring: Arc<dyn SecretStore>,
    /// Why the stored password could not be loaded from the keyring, for
    /// `status`; cleared once it is set or loaded.
    secret_error: std::sync::Mutex<Option<String>>,
    /// Counts what set or dropped the password (`panic`, `sudo set`, `sudo
    /// clear`). A load from the keyring may wait minutes on its unlock prompt;
    /// it keeps what it read only when nothing of these came in meanwhile.
    secret_gen: std::sync::Mutex<u64>,
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
                                cwd: info.cwd,
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

/// Runs until SIGTERM (`Ok(false)`) or a `restart` request (`Ok(true)`: the caller
/// exits with a failure code so the unit or logon task starts it again).
pub async fn run(dirs: Dirs) -> Result<bool, String> {
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
        return Err(root_refusal(cfg!(windows)));
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
            // Windows has no sudo of its own to skip; an elevated token still asks.
            as_root: cfg!(unix) && is_root(),
        },
    ));
    if dirs.paused_file().exists() {
        engine.pause();
    }
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this program: {e}"))?;
    let execs = Arc::new(Execs::new(ExecConfig {
        shim_program: exe.clone(),
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
    let keyring = sync_policy::keyring::system();
    info!(
        "started: profile {:?}, mode {:?}, landlock {landlock}, cgroups {}, approvals: {approvals}",
        cfg.profile,
        device.engine.effective_mode(),
        device.execs.uses_cgroups()
    );
    if is_root() {
        warn!(
            "running as {} (privilege.allow_root): the portal's agent acts with its rights where the policy allows",
            if cfg!(windows) {
                "an elevated administrator"
            } else {
                "root"
            }
        );
    }

    let (status_tx, link_status) =
        watch::channel(LinkStatus::new(LinkState::Stopped, Some("starting".into())));
    let (relink, relink_rx) = mpsc::channel(4);
    drop(cfg);
    let daemon = Arc::new(Daemon {
        dirs: dirs.clone(),
        exe,
        device: device.clone(),
        store,
        queue,
        link_status,
        relink,
        approvals,
        restart: tokio::sync::Notify::new(),
        restarting: std::sync::atomic::AtomicBool::new(false),
        keyring,
        secret_error: std::sync::Mutex::new(None),
        secret_gen: std::sync::Mutex::new(0),
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
    // After the control channel is up: a keyring may ask the owner to unlock it,
    // and `panic` must reach the client meanwhile.
    let loader = daemon.clone();
    tokio::spawn(async move {
        if let Err(e) = loader.load_stored_secret().await {
            warn!(
                "elevation password {e}; sudo commands run without it until `pithagoras-sync unlock` or `sudo set`"
            );
        }
    });
    wait_for_signals(&daemon).await;
    info!("shutting down");
    shutdown_tx.send_replace(true);
    let _ = tokio::time::timeout(Duration::from_secs(15), supervisor).await;
    device.execs.kill_all().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), control).await;
    Ok(daemon.restarting.load(std::sync::atomic::Ordering::SeqCst))
}

/// Why the client does not start as root (or elevated, on Windows) while
/// `allow_root` is off, and what to do instead on that platform.
pub fn root_refusal(windows: bool) -> String {
    let (who, instead) = if windows {
        (
            "an elevated administrator",
            "Run it without elevation: the logon task from `pithagoras-sync install` does",
        )
    } else {
        (
            "root",
            "A dedicated user is safer (`pithagoras-sync setup --create-user`)",
        )
    };
    format!(
        "refusing to run as {who}: the portal's agent would act with its rights. {instead}; to allow it, run `pithagoras-sync config set policy.privilege.allow_root true` as this user."
    )
}

/// Whether this process runs as root.
#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Whether this process runs with an elevated administrator token.
#[cfg(windows)]
pub fn is_root() -> bool {
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
                _ = daemon.restart.notified() => return,
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
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = daemon.restart.notified() => {}
        }
    }
}

impl Daemon {
    fn tokens(&self, cfg: &DeviceConfig) -> TokenStore {
        TokenStore::new(
            self.dirs.token_file(),
            cfg.token_storage,
            self.keyring.clone(),
        )
    }

    async fn link_config(&self) -> Result<Option<LinkConfig>, String> {
        let cfg = self.store.config();
        let Some(portal) = cfg.portal.clone() else {
            return Ok(None);
        };
        let token = self.tokens(&cfg).load().await?;
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
            elevation_password: self.device.secrets.is_set(),
            token_storage: self.tokens(&cfg).describe().into(),
            running_commands: self.device.execs.running(),
            cgroups: self.device.execs.uses_cgroups(),
            landlock: self.device.engine.landlock_available(),
            config_file: self.dirs.config_file().to_string_lossy().into_owned(),
            audit_file: self.dirs.audit_file().to_string_lossy().into_owned(),
            exe: self.exe.to_string_lossy().into_owned(),
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
                self.drop_secret();
                Reply::ok()
            }
            Request::Unlock => {
                if let Err(e) = std::fs::remove_file(self.dirs.paused_file())
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    return Reply::err(format!("cannot remove the pause marker: {e}"));
                }
                self.device.unlock();
                match self.load_stored_secret().await {
                    Ok(()) => Reply::ok(),
                    Err(e) => Reply::err(format!("unlocked, but the elevation password was {e}")),
                }
            }
            Request::Reload => match self.reload() {
                Ok(()) => Reply::ok(),
                Err(e) => Reply::err(e),
            },
            Request::Approvals => {
                let (list, left_out) = self.queue.list_within();
                Reply {
                    approvals: Some(list),
                    left_out: (left_out > 0).then_some(left_out),
                    ..Reply::ok()
                }
            }
            Request::Answer {
                id,
                answer,
                minutes,
            } => match self.queue.answer(id, answer, minutes, "device") {
                Ok(()) => Reply::ok(),
                Err(e) => Reply::err(e.to_string()),
            },
            Request::Restart => {
                info!("restarting on the owner's request");
                self.restarting
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                self.restart.notify_one();
                Reply::ok()
            }
            Request::SecretSet { name, value } => match self.set_secret(&name, value).await {
                Ok(()) => Reply::ok(),
                Err(e) => Reply::err(e),
            },
            Request::SecretClear { name } => {
                if name != crate::secrets::ELEVATION {
                    return Reply::err(format!("there is no secret {name}"));
                }
                self.drop_secret();
                let storage = self.store.config().policy.privilege.secret_storage;
                let forgot =
                    crate::secrets::forget(&self.dirs, storage, self.keyring.as_ref()).await;
                // Again: an `unlock` may have read the stored one before it was gone.
                self.drop_secret();
                if let Err(e) = forgot {
                    return Reply::err(e);
                }
                *self.secret_error.lock().unwrap() = None;
                info!("elevation password cleared");
                Reply::ok()
            }
        }
    }

    async fn set_secret(&self, name: &str, value: Secret) -> Result<(), String> {
        if name != crate::secrets::ELEVATION {
            return Err(format!("there is no secret {name}"));
        }
        if !cfg!(target_os = "linux") {
            return Err("elevation is Linux only (sudo); Windows has none".into());
        }
        #[cfg(target_os = "linux")]
        if sync_policy::secret::traced() {
            return Err("the client is being traced; it does not take the password now".into());
        }
        crate::secrets::check(value.expose())?;
        let storage = self.store.config().policy.privilege.secret_storage;
        crate::secrets::store(&self.dirs, storage, self.keyring.as_ref(), &value).await?;
        let mut generation = self.secret_gen.lock().unwrap();
        *generation += 1;
        self.device.secrets.set(value);
        *self.secret_error.lock().unwrap() = None;
        drop(generation);
        info!("elevation password set (kept in {})", storage.as_str());
        Ok(())
    }

    /// Loads the password from the file or the keyring, where the owner keeps it
    /// there. A keyring that fails is an error the owner hears of (`status`,
    /// `unlock`), never a reason to look elsewhere.
    async fn load_stored_secret(&self) -> Result<(), String> {
        let storage = self.store.config().policy.privilege.secret_storage;
        // Paused (`panic`), it stays forgotten until `unlock` loads it.
        if (storage == SecretStorage::Keyring && !cfg!(target_os = "linux"))
            || self.device.is_paused()
        {
            return Ok(());
        }
        let started = *self.secret_gen.lock().unwrap();
        let loaded = crate::secrets::load_stored(&self.dirs, storage, self.keyring.as_ref()).await;
        // Held to the end, so a `panic` cannot come in between the check and the set.
        let generation = self.secret_gen.lock().unwrap();
        if *generation != started || self.device.is_paused() {
            info!(
                "elevation password not loaded: panic, sudo set or sudo clear came in while it was read from {}",
                storage.as_str()
            );
            return Ok(());
        }
        let result = match loaded {
            Ok(Some(s)) => {
                self.device.secrets.set(s);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) if storage == SecretStorage::Keyring => Err(e),
            Err(e) => {
                warn!("elevation password not loaded: {e}");
                Ok(())
            }
        };
        *self.secret_error.lock().unwrap() = result.as_ref().err().cloned();
        drop(generation);
        result
    }

    /// Forgets the password in memory; a load still reading it does not put it
    /// back.
    fn drop_secret(&self) {
        let mut generation = self.secret_gen.lock().unwrap();
        *generation += 1;
        self.device.secrets.clear();
    }

    fn elevation_status(&self, cfg: &DeviceConfig) -> String {
        let p = &cfg.policy.privilege;
        match p.elevation {
            Elevation::Off => "off".into(),
            Elevation::Sudo if self.device.secrets.is_set() => {
                format!("sudo, password set (kept in {})", p.secret_storage.as_str())
            }
            Elevation::Sudo => match &*self.secret_error.lock().unwrap() {
                Some(e) => format!("sudo, no password: it was {e}"),
                None => {
                    "sudo, no password set (sudo -n: only what sudoers allows without one)".into()
                }
            },
        }
    }
}

/// The first wait before reading the token again from a keyring that was not
/// there; it doubles up to `KEYRING_RETRY_MAX`.
const KEYRING_RETRY: Duration = Duration::from_secs(3);
const KEYRING_RETRY_MAX: Duration = Duration::from_secs(300);

/// Keeps one link running for the current pairing; restarts it when a reload
/// changed the pairing, and waits for one after the portal refused the device.
/// A keyring service that is not there yet (the client started at login before
/// it) is tried again; a keyring that said no waits for the owner.
async fn supervise(
    d: Arc<Daemon>,
    mut relink: mpsc::Receiver<()>,
    status: watch::Sender<LinkStatus>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut retry = KEYRING_RETRY;
    loop {
        let loaded = tokio::select! {
            c = d.link_config() => c,
            _ = until(&mut shutdown) => return,
        };
        let cfg = match loaded {
            Ok(Some(c)) => c,
            other => {
                let again = match &other {
                    Err(e) if sync_policy::keyring::may_come_later(e) => Some(retry),
                    _ => None,
                };
                let why = match other {
                    Err(e) if again.is_some() => {
                        format!("{e}; trying again in {}s", retry.as_secs())
                    }
                    Err(e) => e,
                    _ => "not paired: run `pithagoras-sync pair <uri>`".into(),
                };
                status.send_replace(LinkStatus::new(LinkState::Stopped, Some(why)));
                let wait = async {
                    match again {
                        Some(t) => tokio::time::sleep(t).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    _ = relink.recv() => retry = KEYRING_RETRY,
                    _ = wait => retry = (retry * 2).min(KEYRING_RETRY_MAX),
                    _ = until(&mut shutdown) => return,
                }
                continue;
            }
        };
        retry = KEYRING_RETRY;
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
                    let now = tokio::select! {
                        c = d.link_config() => c,
                        _ = until(&mut shutdown) => {
                            stop.send_replace(true);
                            let _ = (&mut task).await;
                            return;
                        }
                    };
                    let same = match now {
                        Ok(Some(c)) => (c.portal.clone(), c.token.clone()) == current,
                        Ok(None) => false,
                        // A keyring that cannot be read now (locked, its prompt
                        // cancelled, gone for a moment) says nothing about the
                        // pairing: a new pairing changes the config as well.
                        Err(e) if current_portal_kept(&d, &current.0) => {
                            warn!("the token could not be read again ({e}); the link stays as it is");
                            true
                        }
                        Err(_) => false,
                    };
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

/// Whether the config still names the portal the link runs for.
fn current_portal_kept(d: &Daemon, portal: &sync_policy::config::PortalConfig) -> bool {
    d.store.config().portal.as_ref() == Some(portal)
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
    let security = pipe_security::PipeSecurity::for_this_user()?;
    let mut opts = tokio::net::windows::named_pipe::ServerOptions::new();
    opts.first_pipe_instance(true).reject_remote_clients(true);
    security
        .create(&opts, socket)
        .map_err(|e| format!("no control pipe at {}: {e}", socket.display()))
}

#[cfg(windows)]
mod pipe_security {
    //! Who may open the control pipe. The default security of a named pipe lets
    //! every user, anonymous logons included, open it for reading, and a reader
    //! holding every free instance kept the owner's `panic` from getting through
    //! ("all pipe instances are busy"). The pipe is the user's and SYSTEM's only,
    //! and its Medium label keeps the user's own low-integrity processes (sandboxes)
    //! from reading or writing it.

    use std::ffi::c_void;
    use std::path::Path;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    pub struct PipeSecurity(*mut c_void);

    // SAFETY: the descriptor is only read after it was built.
    unsafe impl Send for PipeSecurity {}
    unsafe impl Sync for PipeSecurity {}

    impl PipeSecurity {
        pub fn for_this_user() -> Result<PipeSecurity, String> {
            let sid = crate::install::current_user_sid()?;
            let sddl = super::control_pipe_sddl(&sid);
            let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut sd: *mut c_void = std::ptr::null_mut();
            // SAFETY: a NUL-terminated string in, a descriptor out that we free in Drop.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(format!(
                    "control pipe security: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(PipeSecurity(sd))
        }

        pub fn create(
            &self,
            opts: &ServerOptions,
            name: &Path,
        ) -> std::io::Result<NamedPipeServer> {
            let mut sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            };
            // SAFETY: `sa` and the descriptor it points to outlive the call.
            unsafe {
                opts.create_with_security_attributes_raw(
                    name,
                    (&mut sa as *mut SECURITY_ATTRIBUTES).cast(),
                )
            }
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// The control pipe's security: full access for SYSTEM and the user only (no
/// inherited entries), and a Medium label that refuses lower integrity levels
/// reading and writing.
pub fn control_pipe_sddl(user_sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;{user_sid})S:(ML;;NRNW;;;ME)")
}

#[cfg(windows)]
async fn serve_control(
    d: Arc<Daemon>,
    listener: ControlListener,
    socket: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) {
    use tokio::net::windows::named_pipe::ServerOptions;
    let security = match pipe_security::PipeSecurity::for_this_user() {
        Ok(s) => s,
        Err(e) => return warn!("control pipe: {e}"),
    };
    let mut opts = ServerOptions::new();
    opts.reject_remote_clients(true);
    let mut server = listener;
    loop {
        tokio::select! {
            r = server.connect() => {
                if r.is_err() {
                    continue;
                }
                let next = match security.create(&opts, &socket) {
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

#[cfg(test)]
mod tests {
    #[test]
    fn the_root_refusal_names_what_works_on_each_platform() {
        let linux = super::root_refusal(false);
        assert!(linux.contains("as root") && linux.contains("setup --create-user"));
        let windows = super::root_refusal(true);
        assert!(windows.contains("elevated administrator"), "{windows}");
        assert!(!windows.contains("setup --create-user"), "{windows}");
        assert!(windows.contains("pithagoras-sync install"), "{windows}");
        for t in [linux, windows] {
            assert!(t.contains("policy.privilege.allow_root true"), "{t}");
        }
    }

    #[test]
    fn the_control_pipe_is_the_users_alone() {
        let sddl = super::control_pipe_sddl("S-1-5-21-1-2-3-1001");
        // Protected (nothing inherited), no Everyone (WD) or anonymous (AN) entry.
        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert!(!sddl.contains(";WD)") && !sddl.contains(";AN)"), "{sddl}");
        assert!(sddl.contains("(A;;GA;;;S-1-5-21-1-2-3-1001)"), "{sddl}");
        assert!(sddl.ends_with("S:(ML;;NRNW;;;ME)"), "{sddl}");
    }
}
