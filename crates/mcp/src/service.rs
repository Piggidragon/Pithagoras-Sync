//! Computer use as the device serves it: the installed servers and their
//! allowed tools (`mcp.list`), and one call through every check (`mcp.call`):
//! the allow-list, the arguments against the schema, the owner's consent, the
//! focus check before input, then the server, which is started on the first
//! call, stopped on `panic`, and started again with backoff after a crash.
//!
//! Nothing here knows the portal: the connector calls it through
//! `sync_connector::device::ComputerUse`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use sync_policy::config::InstalledServer;
use sync_policy::{BoxFuture, Call, Engine, ScreenRequest};
use sync_proto::methods::{
    MAX_MCP_ARGS, MAX_MCP_NAME, McpCallParams, McpCallResult, McpChanged, McpListResult,
    McpServerInfo, McpToolInfo,
};
use sync_proto::{Id, RpcError, code, mcp_reason as why};
use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

use crate::client::{Client, ClientError, Limits};
use crate::install::{self, KeptTool};
use crate::pins::{Document, ServerPin};

/// Most calls waiting for one server (its consent question included).
pub const MAX_WAITING: usize = 8;
/// The title prefix of every window of Pithagoras Sync: input is refused while
/// one is open or focused.
pub const OWN_WINDOW: &str = "Pithagoras Sync";
/// A burst of calls ends after this long without one; the next call shows the
/// indicator again.
pub const BURST_GAP_MS: i64 = 60_000;
/// Longest text of the arguments shown in the question and the audit log.
pub const MAX_SHOWN: usize = 1000;

/// How the owner learns that the screen is in use.
pub trait Indicator: Send + Sync {
    /// A chat starts a burst of computer-use calls.
    fn burst(&self, server: &str, chat: &str);
}

/// Shows nothing (no desktop, tests).
pub struct NoIndicator;

impl Indicator for NoIndicator {
    fn burst(&self, _server: &str, _chat: &str) {}
}

/// A desktop notification at the start of each burst (Linux, where a
/// notification service runs).
#[cfg(unix)]
pub struct Notification;

#[cfg(unix)]
impl Indicator for Notification {
    fn burst(&self, server: &str, chat: &str) {
        let body = format!(
            "Chat {} uses the screen, pointer and keyboard ({server}). `pithagoras-sync panic` stops it.",
            chat.chars().take(64).collect::<String>()
        );
        tokio::spawn(async move {
            if let Err(e) = sync_policy::notify::show("Pithagoras Sync: computer use", &body).await
            {
                info!("no computer-use notification: {e}");
            }
        });
    }
}

pub struct Options {
    /// `<state>/mcp`.
    pub dir: PathBuf,
    pub os: String,
    pub arch: String,
    /// The client's environment, which the server's is cut from.
    pub base_env: Vec<(String, String)>,
    pub limits: Limits,
    pub indicator: Arc<dyn Indicator>,
    /// How long after a call computer use counts as active (`active`).
    pub active_ms: i64,
}

/// The process of one server and how its last starts went.
#[derive(Default)]
struct Slot {
    client: Option<Client>,
    failures: u32,
    retry_at: Option<Instant>,
    last_error: Option<String>,
}

struct Server {
    name: String,
    version: String,
    folder: String,
    sha256: String,
    pin: ServerPin,
    dir: PathBuf,
    /// The allowed tools the server listed at install.
    tools: Vec<KeptTool>,
    /// Why it cannot run (its files changed or are gone, it is no longer
    /// pinned); found at load or before a start.
    error: Mutex<Option<String>>,
    slot: tokio::sync::Mutex<Slot>,
    waiting: AtomicUsize,
}

impl Server {
    fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    fn info(&self) -> McpServerInfo {
        let error = self.error();
        McpServerInfo {
            name: self.name.clone(),
            version: self.version.clone(),
            state: if error.is_some() {
                "unavailable"
            } else {
                "ready"
            }
            .into(),
            tools: if error.is_some() {
                Vec::new()
            } else {
                self.tools
                    .iter()
                    .map(|t| McpToolInfo {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        input_schema: t.input_schema.clone(),
                        input: self.pin.is_input(&t.name),
                    })
                    .collect()
            },
            error,
        }
    }
}

/// What `status` shows of one server.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServerStatus {
    pub name: String,
    pub version: String,
    pub running: bool,
    pub tools: Vec<String>,
    pub error: Option<String>,
    /// How the last start or call failed, and when it is tried again.
    pub last_error: Option<String>,
    pub retry_in_secs: Option<u64>,
}

/// Who uses the screen now.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InUse {
    pub chat: String,
    pub server: String,
    pub last_ms: i64,
}

pub struct Service {
    /// Itself, for the reload the last call out starts.
    me: Weak<Service>,
    engine: Arc<Engine>,
    opts: Options,
    servers: Mutex<BTreeMap<String, Arc<Server>>>,
    changes: broadcast::Sender<McpChanged>,
    last: Mutex<Option<McpChanged>>,
    /// Calls in flight, their questions included: an update waits for none.
    /// Taken before a call looks up its server, and checked under the same
    /// lock as the swap, so no call holds a server the swap replaced.
    busy: AtomicUsize,
    /// The installed servers and pins to switch to once nothing is in flight.
    pending: Mutex<Option<(BTreeMap<String, InstalledServer>, Document)>>,
    /// One reload at a time.
    applying: tokio::sync::Mutex<()>,
    in_use: Mutex<Option<InUse>>,
    last_call_ms: AtomicI64,
    /// Calls past their consent (`active`), and when the last one ended.
    acting: AtomicUsize,
    last_acted_ms: AtomicI64,
    /// Bumped by `stop_all` (`panic`): every request in flight ends at once.
    stop: watch::Sender<u64>,
}

/// The list's version, made as the settings' version is.
fn list_version(servers: &[McpServerInfo]) -> String {
    sync_policy::settings::version(&serde_json::to_value(servers).unwrap_or_default())
}

fn server_err(reason: &str, message: impl Into<String>) -> RpcError {
    RpcError::new(code::SERVER, message).with_reason(reason)
}

/// The arguments as the owner reads them: control characters escaped, cut.
pub fn shown(args: &Map<String, Value>) -> String {
    shown_cut(args).0
}

/// `shown`, and whether it had to be cut (then a question cannot be
/// answered with yes: nobody could read what they allowed).
pub fn shown_cut(args: &Map<String, Value>) -> (String, bool) {
    let text = sync_policy::approve::visible(&Value::Object(args.clone()).to_string());
    if text.chars().count() <= MAX_SHOWN {
        return (text, false);
    }
    let cut: String = text.chars().take(MAX_SHOWN).collect();
    (
        format!("{cut}… ({} characters in all)", text.chars().count()),
        true,
    )
}

fn paused() -> RpcError {
    RpcError::denied("the device is paused").with_reason(why::PAUSED)
}

impl Service {
    pub fn new(engine: Arc<Engine>, opts: Options) -> Arc<Service> {
        let (changes, _) = broadcast::channel(16);
        let (stop, _) = watch::channel(0);
        Arc::new_cyclic(|me| Service {
            me: me.clone(),
            engine,
            opts,
            servers: Mutex::new(BTreeMap::new()),
            changes,
            last: Mutex::new(None),
            busy: AtomicUsize::new(0),
            pending: Mutex::new(None),
            applying: tokio::sync::Mutex::new(()),
            in_use: Mutex::new(None),
            last_call_ms: AtomicI64::new(i64::MIN / 2),
            acting: AtomicUsize::new(0),
            last_acted_ms: AtomicI64::new(i64::MIN / 2),
            stop,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.opts.dir
    }

    /// Takes the installed servers and the pins in force. While a call is in
    /// flight it waits and is applied when the last one ends, so no server is
    /// swapped under a running call or an open question.
    pub async fn reload(&self, installed: BTreeMap<String, InstalledServer>, doc: Document) {
        *self.pending.lock().unwrap() = Some((installed, doc));
        self.apply_pending().await;
    }

    /// Applies a waiting reload unless a call is in flight (the last one out
    /// starts it again). The changed servers' files are hashed off the
    /// runtime; a call that comes meanwhile keeps the servers it found, and
    /// the swap waits for it.
    async fn apply_pending(&self) {
        let _one = self.applying.lock().await;
        if self.busy.load(Ordering::SeqCst) > 0 {
            if self.pending.lock().unwrap().is_some() {
                info!("computer use: the new servers wait for the calls in flight");
            }
            return;
        }
        let Some((installed, doc)) = self.pending.lock().unwrap().take() else {
            return;
        };
        let mut next = BTreeMap::new();
        let old = self.servers.lock().unwrap().clone();
        for (name, rec) in &installed {
            let dir = install::version_dir(&self.opts.dir, name, &rec.folder);
            let pin = effective_pin(name, &self.opts.os, &rec.folder, &doc, &dir);
            // The same files run by the same pin: the running process stays.
            if let Some(s) = old.get(name)
                && s.folder == rec.folder
                && s.sha256 == rec.sha256
                && s.error().is_none()
                && pin.as_ref().is_ok_and(|p| *p == s.pin)
            {
                next.insert(name.clone(), s.clone());
                continue;
            }
            let (mcp, n, folder, sha) = (
                self.opts.dir.clone(),
                name.clone(),
                rec.folder.clone(),
                rec.sha256.clone(),
            );
            let checked =
                tokio::task::spawn_blocking(move || install::verify(&mcp, &n, &folder, &sha))
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()));
            next.insert(
                name.clone(),
                Arc::new(self.load(name, rec, pin, dir, checked)),
            );
        }
        let stale: Vec<Arc<Server>> = {
            let mut servers = self.servers.lock().unwrap();
            if self.busy.load(Ordering::SeqCst) > 0 {
                // A call came while the files were hashed: the last one out
                // applies this (unless a newer reload came too).
                let mut pending = self.pending.lock().unwrap();
                if pending.is_none() {
                    *pending = Some((installed, doc));
                }
                info!("computer use: the new servers wait for the calls in flight");
                return;
            }
            let stale = old
                .iter()
                .filter(|(n, s)| next.get(*n).is_none_or(|x| !Arc::ptr_eq(x, s)))
                .map(|(_, s)| s.clone())
                .collect();
            *servers = next;
            stale
        };
        // The old processes end; nothing is in flight on them.
        for s in stale {
            tokio::spawn(async move {
                if let Some(mut c) = s.slot.lock().await.client.take() {
                    c.kill().await;
                }
            });
        }
        self.announce();
    }

    /// Holds `busy` (a call, the owner's test or a probe) until dropped.
    fn hold(&self) -> Busy<'_> {
        self.busy.fetch_add(1, Ordering::SeqCst);
        Busy(self)
    }

    fn load(
        &self,
        name: &str,
        rec: &InstalledServer,
        pin: Result<ServerPin, String>,
        dir: PathBuf,
        checked: Result<PathBuf, String>,
    ) -> Server {
        let (pin, error) = match (pin, checked) {
            (Ok(p), Ok(_)) => (Some(p), None),
            (Ok(p), Err(e)) => (Some(p), Some(e)),
            (Err(e), _) => (None, Some(e)),
        };
        let pin = pin.unwrap_or_else(|| empty_pin(name, &rec.version, &self.opts.os));
        let allowed = pin.allowed();
        let tools = if error.is_none() {
            install::kept_tools(&dir)
                .unwrap_or_default()
                .into_iter()
                .filter(|t| allowed.contains(&t.name))
                .collect()
        } else {
            Vec::new()
        };
        if let Some(e) = &error {
            warn!("computer use: {name} {}: {e}", rec.version);
        }
        Server {
            name: name.to_string(),
            version: rec.version.clone(),
            folder: rec.folder.clone(),
            sha256: rec.sha256.clone(),
            pin,
            dir,
            tools,
            error: Mutex::new(error),
            slot: tokio::sync::Mutex::new(Slot::default()),
            waiting: AtomicUsize::new(0),
        }
    }

    /// Sends `mcp.changed` when the list or the consent changed.
    pub fn announce(&self) {
        let l = self.list();
        let now = McpChanged {
            version: l.version,
            consent: l.consent,
            consent_expires_ms: l.consent_expires_ms,
        };
        let mut last = self.last.lock().unwrap();
        if last.as_ref() != Some(&now) {
            *last = Some(now.clone());
            let _ = self.changes.send(now);
        }
    }

    pub fn list(&self) -> McpListResult {
        let servers: Vec<McpServerInfo> = self
            .servers
            .lock()
            .unwrap()
            .values()
            .map(|s| s.info())
            .collect();
        let (policy, _) = self.engine.policy();
        let now = self.engine.now();
        McpListResult {
            version: list_version(&servers),
            consent: policy.computer_use.effective(now),
            consent_expires_ms: policy.computer_use.expires_ms(now),
            servers,
        }
    }

    pub fn in_use(&self) -> Option<InUse> {
        self.in_use.lock().unwrap().clone()
    }

    /// Stops every server and ends every call in flight (`panic`).
    pub async fn stop_all(&self) {
        self.stop.send_modify(|g| *g += 1);
        let servers: Vec<Arc<Server>> = self.servers.lock().unwrap().values().cloned().collect();
        for s in servers {
            let mut slot = s.slot.lock().await;
            if let Some(mut c) = slot.client.take() {
                c.kill().await;
            }
        }
        *self.in_use.lock().unwrap() = None;
    }

    pub async fn status(&self, probe: bool) -> Vec<ServerStatus> {
        // A probe may start a server: none the swap replaces.
        let _busy = probe.then(|| self.hold());
        let servers: Vec<Arc<Server>> = self.servers.lock().unwrap().values().cloned().collect();
        let mut out = Vec::new();
        for s in servers {
            let mut slot = s.slot.lock().await;
            if probe && s.error().is_none() {
                match self
                    .ensure_started(&s, &mut slot, self.stop.subscribe())
                    .await
                {
                    Ok(()) => {
                        if let Some(c) = slot.client.as_mut()
                            && let Err(e) = c
                                .request(
                                    "ping",
                                    Value::Object(Map::new()),
                                    self.opts.limits.startup,
                                )
                                .await
                        {
                            slot.last_error = Some(format!("ping: {e}"));
                            slot.client = None;
                        }
                    }
                    Err(e) => slot.last_error = Some(e.message),
                }
            }
            let running = slot.client.as_mut().is_some_and(|c| !c.is_dead());
            out.push(ServerStatus {
                name: s.name.clone(),
                version: s.version.clone(),
                running,
                tools: s.tools.iter().map(|t| t.name.clone()).collect(),
                error: s.error(),
                last_error: slot.last_error.clone(),
                retry_in_secs: slot
                    .retry_at
                    .and_then(|t| t.checked_duration_since(Instant::now()))
                    .map(|d| d.as_secs() + 1),
            });
        }
        out
    }

    /// Starts the server unless it runs, within its backoff, after checking
    /// its files. `stop` was taken before the call checked the pause, so a
    /// `panic` while the files are hashed still ends what comes next.
    async fn ensure_started(
        &self,
        s: &Server,
        slot: &mut Slot,
        stop: watch::Receiver<u64>,
    ) -> Result<(), RpcError> {
        if let Some(c) = slot.client.as_mut()
            && !c.is_dead()
        {
            return Ok(());
        }
        slot.client = None;
        if let Some(at) = slot.retry_at
            && let Some(wait) = at.checked_duration_since(Instant::now())
        {
            return Err(server_err(
                why::NOT_RUNNING,
                format!(
                    "{} failed and starts again in {}s{}",
                    s.name,
                    wait.as_secs() + 1,
                    slot.last_error
                        .as_ref()
                        .map(|e| format!(" ({e})"))
                        .unwrap_or_default()
                ),
            ));
        }
        let dir = s.dir.clone();
        let (mcp, name, folder, sha) = (
            self.opts.dir.clone(),
            s.name.clone(),
            s.folder.clone(),
            s.sha256.clone(),
        );
        // The hash at every start: a server changed after install is not run.
        let checked =
            tokio::task::spawn_blocking(move || install::verify(&mcp, &name, &folder, &sha))
                .await
                .map_err(|e| RpcError::new(code::INTERNAL, e.to_string()))?;
        if let Err(e) = checked {
            warn!("computer use: {e}");
            // Unavailable from now on, and the portal hears of it.
            *s.error.lock().unwrap() = Some(e.clone());
            self.announce();
            return Err(server_err(why::CHANGED, e));
        }
        let launch = install::launch(&s.pin, &dir, &self.opts.dir, &self.opts.base_env);
        match Client::start_with(&launch, self.opts.limits.clone(), stop).await {
            Ok(c) => {
                info!("computer use: {} {} started", s.name, s.version);
                slot.client = Some(c);
                slot.retry_at = None;
                Ok(())
            }
            Err(ClientError::Stopped) => Err(paused()),
            Err(e) => {
                let msg = e.to_string();
                failed(slot, &msg);
                Err(server_err(why::NOT_RUNNING, format!("{}: {msg}", s.name)))
            }
        }
    }

    /// The focus check before input: the server's window list (and focused
    /// window) must name no window of Pithagoras Sync, and must be readable.
    async fn focus_check(&self, s: &Server, slot: &mut Slot) -> Result<(), String> {
        let mut calls = vec![s.pin.focus.windows.clone()];
        calls.extend(s.pin.focus.focused.clone());
        for fc in calls {
            let c = slot.client.as_mut().ok_or("the server is not running")?;
            let raw = c.call(&fc.tool, &fc.args).await.map_err(|e| {
                format!(
                    "the device could not tell which windows are open ({e}), so input is refused"
                )
            })?;
            let r = crate::content::convert(&raw).map_err(|e| {
                format!("the device could not read the window list ({e}), so input is refused")
            })?;
            let text = crate::content::text_of(&r);
            if r.is_error || text.trim().is_empty() {
                return Err(
                    "the device could not tell which windows are open, so input is refused".into(),
                );
            }
            if names_own_window(&text) {
                return Err(format!(
                    "a window of {OWN_WINDOW} is open or focused; input waits until it is closed"
                ));
            }
        }
        Ok(())
    }

    /// A refusal before the consent, in the audit log as every decision is.
    fn refuse(&self, chat: &str, target: &str, e: RpcError) -> RpcError {
        self.engine.record(
            Some(chat),
            "computer_use",
            target,
            "denied",
            Some(e.message.clone()),
        );
        e
    }

    async fn call_inner(&self, id: &Id, p: McpCallParams) -> Result<McpCallResult, RpcError> {
        // Taken first: a `panic` from here on ends this call wherever it is.
        let stop = self.stop.subscribe();
        let name = |s: &str| {
            sync_policy::approve::visible(&s.chars().take(MAX_MCP_NAME).collect::<String>())
        };
        let early = format!("{}.{}", name(&p.server), name(&p.tool));
        let chat = p.ctx.chat.clone();
        if self.engine.is_paused() {
            return Err(self.refuse(&chat, &early, paused()));
        }
        if p.server.len() > MAX_MCP_NAME || p.tool.len() > MAX_MCP_NAME {
            return Err(self.refuse(
                &chat,
                &early,
                RpcError::new(
                    code::INVALID_PARAMS,
                    "server and tool names have at most 64 bytes",
                ),
            ));
        }
        if p.ctx.tool.is_some() {
            return Err(self.refuse(
                &chat,
                &early,
                RpcError::denied("mcp.call takes no pi tool label in ctx"),
            ));
        }
        let server = self.servers.lock().unwrap().get(&p.server).cloned();
        let Some(s) = server else {
            return Err(self.refuse(
                &chat,
                &early,
                server_err(
                    why::NOT_INSTALLED,
                    format!(
                        "no MCP server {} is installed on this device",
                        name(&p.server)
                    ),
                ),
            ));
        };
        if let Some(e) = s.error() {
            return Err(self.refuse(&chat, &early, server_err(why::CHANGED, e)));
        }
        let Some(tool) = s.tools.iter().find(|t| t.name == p.tool) else {
            return Err(self.refuse(
                &chat,
                &early,
                RpcError::denied(format!(
                    "{} is not a tool this device allows for {} {}",
                    name(&p.tool),
                    s.name,
                    s.version
                ))
                .with_reason(why::TOOL_NOT_ALLOWED),
            ));
        };
        let size = serde_json::to_string(&p.args)
            .map(|t| t.len())
            .unwrap_or(usize::MAX);
        if size > MAX_MCP_ARGS {
            return Err(self.refuse(
                &chat,
                &early,
                RpcError::new(
                    code::TOO_LARGE,
                    format!("args are limited to {MAX_MCP_ARGS} bytes"),
                ),
            ));
        }
        let (shown, cut) = shown_cut(&p.args);
        let target = format!("{}.{} {shown}", s.name, p.tool);
        if let Err(e) = crate::schema::check(&tool.input_schema, &p.args) {
            return Err(self.refuse(&chat, &target, RpcError::new(code::INVALID_PARAMS, e)));
        }
        if s.waiting.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING {
            s.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(self.refuse(
                &chat,
                &target,
                RpcError::new(
                    code::BUSY,
                    "too many computer-use calls wait for this server",
                ),
            ));
        }
        let _waiting = Counter(&s.waiting);
        let call = Call {
            id: Some(id),
            chat: &p.ctx.chat,
            portal_tainted: p.ctx.tainted,
            tool: "computer_use",
            pi_tool: None,
        };
        let grant = self
            .engine
            .authorize_screen(
                &call,
                ScreenRequest {
                    server: &s.name,
                    tool: &p.tool,
                    shown: &shown,
                    cut,
                },
            )
            .await?;
        let mut slot = s.slot.lock().await;
        // Waiting in the queue does not outlast the consent: switched off,
        // run out, paused or outside the hours meanwhile, the call is refused.
        self.engine.screen_still_allowed(&call, &target, grant)?;
        // From here the call may act on the screen.
        let _acting = Acting::new(self);
        // From here on every way out is in the audit log too, after the
        // consent's own record.
        let audited = |decision: &str, e: RpcError| {
            self.engine.record(
                Some(&p.ctx.chat),
                "computer_use",
                &target,
                decision,
                Some(e.message.clone()),
            );
            e
        };
        self.ensure_started(&s, &mut slot, stop)
            .await
            .map_err(|e| audited("failed", e))?;
        if s.pin.is_input(&p.tool)
            && let Err(e) = self.focus_check(&s, &mut slot).await
        {
            if slot.client.as_mut().is_none_or(|c| c.is_dead()) {
                slot.client = None;
            }
            self.engine.record(
                Some(&p.ctx.chat),
                "computer_use",
                &target,
                "denied",
                Some(e.clone()),
            );
            return Err(RpcError::denied(e).with_reason(why::FOCUS));
        }
        // The last moment before the input: a `panic` meanwhile wins.
        if self.engine.is_paused() {
            return Err(audited("denied", paused()));
        }
        self.indicate(&s.name, &p.ctx.chat);
        // From here the chat sees what is on the screen: untrusted content.
        self.engine.mark_tainted(&p.ctx.chat);
        let c = slot.client.as_mut().ok_or_else(|| {
            audited(
                "failed",
                server_err(why::NOT_RUNNING, "the server is not running"),
            )
        })?;
        let raw = match c.call(&p.tool, &p.args).await {
            Ok(r) => r,
            Err(e) => {
                let err = match &e {
                    ClientError::Timeout => RpcError::new(
                        code::TIMEOUT,
                        format!(
                            "{} did not answer within {}s and was stopped",
                            s.name,
                            self.opts.limits.call.as_secs()
                        ),
                    )
                    .with_reason(why::TIMED_OUT),
                    ClientError::Stopped => paused(),
                    ClientError::Crashed(m) => server_err(why::CRASHED, format!("{}: {m}", s.name)),
                    other => server_err(why::BAD_ANSWER, format!("{}: {other}", s.name)),
                };
                if !matches!(e, ClientError::Rpc(_)) {
                    slot.client = None;
                    if matches!(e, ClientError::Crashed(_) | ClientError::BadAnswer(_)) {
                        failed(&mut slot, &e.to_string());
                    }
                }
                self.engine.record(
                    Some(&p.ctx.chat),
                    "computer_use",
                    &target,
                    "failed",
                    Some(err.message.clone()),
                );
                return Err(err);
            }
        };
        slot.failures = 0;
        crate::content::convert(&raw).map_err(|e| {
            self.engine.record(
                Some(&p.ctx.chat),
                "computer_use",
                &target,
                "failed",
                Some(e.clone()),
            );
            server_err(why::BAD_ANSWER, format!("{}: {e}", s.name))
        })
    }

    fn indicate(&self, server: &str, chat: &str) {
        let now = self.engine.now();
        let last = self.last_call_ms.swap(now, Ordering::SeqCst);
        if now - last >= BURST_GAP_MS {
            self.opts.indicator.burst(server, chat);
        }
        *self.in_use.lock().unwrap() = Some(InUse {
            chat: chat.to_string(),
            server: server.to_string(),
            last_ms: now,
        });
    }

    /// Runs `f` on a server's client, started if need be, with the call slot
    /// held: the owner's self-test.
    pub async fn with_client<T>(
        &self,
        server: &str,
        f: impl for<'c> FnOnce(&'c mut Client, &'c ServerPin) -> BoxFuture<'c, T>,
    ) -> Result<T, String> {
        let _busy = self.hold();
        let s = self
            .servers
            .lock()
            .unwrap()
            .get(server)
            .cloned()
            .ok_or_else(|| format!("{server} is not installed"))?;
        if let Some(e) = s.error() {
            return Err(e);
        }
        let mut slot = s.slot.lock().await;
        self.ensure_started(&s, &mut slot, self.stop.subscribe())
            .await
            .map_err(|e| e.message)?;
        let c = slot.client.as_mut().ok_or("the server is not running")?;
        Ok(f(c, &s.pin).await)
    }

    /// Whether a call is in flight (its question included).
    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst) > 0
    }

    /// Whether computer use is active: a call past its consent in flight, or
    /// one that ended within `active_ms`. Meanwhile the agent may be typing
    /// into a terminal or clicking in a browser of the owner's, so the client
    /// takes no answer, setting or secret from the owner's side (only
    /// `status`, `panic` and a denial): it could be the agent answering
    /// itself. A call that waits for its consent question does not count, so
    /// the owner can answer a chat's first question on the device.
    pub fn active(&self) -> bool {
        self.acting.load(Ordering::SeqCst) > 0
            || self.engine.now() - self.last_acted_ms.load(Ordering::SeqCst) < self.opts.active_ms
    }
}

/// The pin an installed server runs by: the document's when it is the very
/// pin the server's folder was installed from (the folder's name holds its
/// hash); else the one it was installed from, narrowed to what the document
/// allows (a tool it dropped stays off, and the focus check runs wherever
/// either asks for it). So the files of one pin never run by another's
/// program, arguments or environment. A server the signed document no longer
/// names is not run.
pub fn effective_pin(
    name: &str,
    os: &str,
    folder: &str,
    doc: &Document,
    dir: &Path,
) -> Result<ServerPin, String> {
    match doc.server(name, os) {
        Some(p) if install::folder_name(p) == folder => Ok(p.clone()),
        Some(p) => {
            let mut kept = install::kept_pin(dir)?;
            let allowed = p.allowed();
            kept.allow.retain(|t| allowed.contains(t));
            kept.observe.retain(|t| p.observe.contains(t));
            Ok(kept)
        }
        None if doc.serial == 0 => install::kept_pin(dir),
        None => Err(format!(
            "the signed pins in force do not name {name} (or the kept pins are lost or no longer verify), so it is not run; `pithagoras-sync computer-use update` fetches the pins again, `computer-use uninstall` removes it"
        )),
    }
}

/// The start failed or the server crashed: the next start waits 1 s, doubling
/// to 60 s.
fn failed(slot: &mut Slot, why: &str) {
    slot.failures += 1;
    let wait = Duration::from_secs(1u64 << slot.failures.saturating_sub(1).min(6))
        .min(Duration::from_secs(60));
    slot.retry_at = Some(Instant::now() + wait);
    slot.last_error = Some(why.to_string());
}

/// Whether a window list names a window of Pithagoras Sync.
pub fn names_own_window(text: &str) -> bool {
    text.to_lowercase().contains(&OWN_WINDOW.to_lowercase())
}

fn empty_pin(name: &str, version: &str, os: &str) -> ServerPin {
    use crate::pins::{Focus, Run, SelfTest, ToolCall};
    let none = ToolCall {
        tool: String::new(),
        args: Map::new(),
    };
    ServerPin {
        name: name.into(),
        platform: os.into(),
        version: version.into(),
        files: Vec::new(),
        write: Vec::new(),
        run: Run {
            program: String::new(),
            args: Vec::new(),
            env: BTreeMap::new(),
        },
        allow: Vec::new(),
        observe: Vec::new(),
        focus: Focus {
            windows: none.clone(),
            focused: None,
        },
        selftest: SelfTest {
            screenshot: none,
            pointer: None,
            imports: Vec::new(),
        },
        setup: Vec::new(),
    }
}

struct Counter<'a>(&'a AtomicUsize);

impl Drop for Counter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Holds `busy` for a call; the last one out applies a waiting reload (or
/// one that is being prepared and may still have to wait), off the call.
struct Busy<'a>(&'a Service);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        let s = self.0;
        if s.busy.fetch_sub(1, Ordering::SeqCst) == 1
            && (s.pending.lock().unwrap().is_some() || s.applying.try_lock().is_err())
            && let Some(me) = s.me.upgrade()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            rt.spawn(async move { me.apply_pending().await });
        }
    }
}

/// Counts a call past its consent; when it ends, computer use stays active for
/// `active_ms`.
struct Acting<'a>(&'a Service);

impl<'a> Acting<'a> {
    fn new(s: &'a Service) -> Acting<'a> {
        s.acting.fetch_add(1, Ordering::SeqCst);
        Acting(s)
    }
}

impl Drop for Acting<'_> {
    fn drop(&mut self) {
        let s = self.0;
        s.last_acted_ms.store(s.engine.now(), Ordering::SeqCst);
        s.acting.fetch_sub(1, Ordering::SeqCst);
    }
}

impl sync_connector::device::ComputerUse for Service {
    fn list(&self) -> McpListResult {
        Service::list(self)
    }

    fn call<'a>(
        &'a self,
        id: &'a Id,
        params: McpCallParams,
    ) -> BoxFuture<'a, Result<McpCallResult, RpcError>> {
        Box::pin(async move {
            let _busy = self.hold();
            self.call_inner(id, params).await
        })
    }

    fn subscribe(&self) -> broadcast::Receiver<McpChanged> {
        self.changes.subscribe()
    }
}

/// The servers by name, for the tests.
pub fn names(s: &Service) -> Vec<String> {
    s.servers.lock().unwrap().keys().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_own_window_is_found_in_any_case() {
        assert!(names_own_window("1234 zenity \"Pithagoras Sync: pair\""));
        assert!(names_own_window("PITHAGORAS SYNC"));
        assert!(!names_own_window("Firefox — Pithagoras portal"));
    }

    #[test]
    fn arguments_are_shown_escaped_and_cut() {
        let mut a = Map::new();
        a.insert("text".into(), Value::String("hi\u{1b}[2K".into()));
        assert!(!shown(&a).contains('\u{1b}'));
        a.insert("text".into(), Value::String("x".repeat(5000)));
        let s = shown(&a);
        assert!(s.chars().count() < MAX_SHOWN + 40, "{}", s.len());
        assert!(s.contains("characters in all"));
    }
}
