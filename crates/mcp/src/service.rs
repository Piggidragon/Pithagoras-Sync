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
use std::sync::{Arc, Mutex};
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
    sha256: String,
    pin: ServerPin,
    dir: PathBuf,
    /// The allowed tools the server listed at install.
    tools: Vec<KeptTool>,
    /// Why it cannot run (its files changed or are gone).
    error: Option<String>,
    slot: tokio::sync::Mutex<Slot>,
    waiting: AtomicUsize,
}

impl Server {
    fn info(&self) -> McpServerInfo {
        McpServerInfo {
            name: self.name.clone(),
            version: self.version.clone(),
            state: if self.error.is_some() {
                "unavailable"
            } else {
                "ready"
            }
            .into(),
            error: self.error.clone(),
            tools: self
                .tools
                .iter()
                .map(|t| McpToolInfo {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema: t.input_schema.clone(),
                    input: self.pin.is_input(&t.name),
                })
                .collect(),
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
    engine: Arc<Engine>,
    opts: Options,
    servers: Mutex<BTreeMap<String, Arc<Server>>>,
    changes: broadcast::Sender<McpChanged>,
    last: Mutex<Option<McpChanged>>,
    /// Calls in flight, their questions included: an update waits for none.
    busy: AtomicUsize,
    /// The installed servers and pins to switch to once nothing is in flight.
    pending: Mutex<Option<(BTreeMap<String, InstalledServer>, Document)>>,
    in_use: Mutex<Option<InUse>>,
    last_call_ms: AtomicI64,
    /// Bumped by `stop_all` (`panic`): every request in flight ends at once.
    stop: watch::Sender<u64>,
}

/// An FNV-1a hash of the list, as the settings' version is made.
fn list_version(servers: &[McpServerInfo]) -> String {
    let text = serde_json::to_string(servers).unwrap_or_default();
    let mut h: u64 = 0xcbf29ce484222325;
    for b in text.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn server_err(reason: &str, message: impl Into<String>) -> RpcError {
    RpcError::new(code::SERVER, message).with_reason(reason)
}

/// The arguments as the owner reads them: control characters escaped, cut.
pub fn shown(args: &Map<String, Value>) -> String {
    let text = sync_policy::approve::visible(&Value::Object(args.clone()).to_string());
    if text.chars().count() <= MAX_SHOWN {
        return text;
    }
    let cut: String = text.chars().take(MAX_SHOWN).collect();
    format!("{cut}… ({} characters in all)", text.chars().count())
}

impl Service {
    pub fn new(engine: Arc<Engine>, opts: Options) -> Arc<Service> {
        let (changes, _) = broadcast::channel(16);
        let (stop, _) = watch::channel(0);
        Arc::new(Service {
            engine,
            opts,
            servers: Mutex::new(BTreeMap::new()),
            changes,
            last: Mutex::new(None),
            busy: AtomicUsize::new(0),
            pending: Mutex::new(None),
            in_use: Mutex::new(None),
            last_call_ms: AtomicI64::new(i64::MIN / 2),
            stop,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.opts.dir
    }

    /// Takes the installed servers and the pins in force. While a call is in
    /// flight it waits and is applied when the last one ends, so no server is
    /// swapped under a running call or an open question.
    pub fn reload(&self, installed: BTreeMap<String, InstalledServer>, doc: Document) {
        *self.pending.lock().unwrap() = Some((installed, doc));
        if self.busy.load(Ordering::SeqCst) == 0 {
            self.apply_pending();
        } else {
            info!("computer use: the new servers wait for the calls in flight");
        }
    }

    fn apply_pending(&self) {
        let Some((installed, doc)) = self.pending.lock().unwrap().take() else {
            return;
        };
        let mut next = BTreeMap::new();
        let old = self.servers.lock().unwrap().clone();
        for (name, rec) in installed {
            if let Some(s) = old.get(&name)
                && s.version == rec.version
                && s.sha256 == rec.sha256
                && doc
                    .server(&name, &self.opts.os)
                    .is_none_or(|p| p.version != rec.version || p.allowed() == s.pin.allowed())
            {
                next.insert(name, s.clone());
                continue;
            }
            next.insert(name.clone(), Arc::new(self.load(&name, &rec, &doc)));
        }
        let stale: Vec<Arc<Server>> = old
            .iter()
            .filter(|(n, s)| next.get(*n).is_none_or(|x| !Arc::ptr_eq(x, s)))
            .map(|(_, s)| s.clone())
            .collect();
        *self.servers.lock().unwrap() = next;
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

    fn load(&self, name: &str, rec: &InstalledServer, doc: &Document) -> Server {
        let dir = install::version_dir(&self.opts.dir, name, &rec.version);
        let checked = install::verify(&self.opts.dir, name, &rec.version, &rec.sha256);
        // The document's pin when it is for this version (its allow-list may
        // have narrowed), else the one it was installed from.
        let pin = match doc.server(name, &self.opts.os) {
            Some(p) if p.version == rec.version => Ok(p.clone()),
            _ => install::kept_pin(&dir),
        };
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
            sha256: rec.sha256.clone(),
            pin,
            dir,
            tools,
            error,
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
        let servers: Vec<Arc<Server>> = self.servers.lock().unwrap().values().cloned().collect();
        let mut out = Vec::new();
        for s in servers {
            let mut slot = s.slot.lock().await;
            if probe && s.error.is_none() {
                match self.ensure_started(&s, &mut slot).await {
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
                error: s.error.clone(),
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
    /// its files.
    async fn ensure_started(&self, s: &Server, slot: &mut Slot) -> Result<(), RpcError> {
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
        let (mcp, name, version, sha) = (
            self.opts.dir.clone(),
            s.name.clone(),
            s.version.clone(),
            s.sha256.clone(),
        );
        // The hash at every start: a server changed after install is not run.
        let checked =
            tokio::task::spawn_blocking(move || install::verify(&mcp, &name, &version, &sha))
                .await
                .map_err(|e| RpcError::new(code::INTERNAL, e.to_string()))?;
        if let Err(e) = checked {
            warn!("computer use: {e}");
            return Err(server_err(why::CHANGED, e));
        }
        let launch = install::launch(&s.pin, &dir, &self.opts.dir, &self.opts.base_env);
        match Client::start_with(&launch, self.opts.limits.clone(), self.stop.subscribe()).await {
            Ok(c) => {
                info!("computer use: {} {} started", s.name, s.version);
                slot.client = Some(c);
                slot.retry_at = None;
                Ok(())
            }
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

    async fn call_inner(&self, id: &Id, p: McpCallParams) -> Result<McpCallResult, RpcError> {
        if p.server.len() > MAX_MCP_NAME || p.tool.len() > MAX_MCP_NAME {
            return Err(RpcError::new(
                code::INVALID_PARAMS,
                "server and tool names have at most 64 bytes",
            ));
        }
        if p.ctx.tool.is_some() {
            return Err(RpcError::denied("mcp.call takes no pi tool label in ctx"));
        }
        let server = self.servers.lock().unwrap().get(&p.server).cloned();
        let Some(s) = server else {
            return Err(server_err(
                why::NOT_INSTALLED,
                format!(
                    "no MCP server {} is installed on this device",
                    sync_policy::approve::visible(&p.server)
                ),
            ));
        };
        if let Some(e) = &s.error {
            return Err(server_err(why::CHANGED, e.clone()));
        }
        let Some(tool) = s.tools.iter().find(|t| t.name == p.tool) else {
            return Err(RpcError::denied(format!(
                "{} is not a tool this device allows for {} {}",
                sync_policy::approve::visible(&p.tool),
                s.name,
                s.version
            ))
            .with_reason(why::TOOL_NOT_ALLOWED));
        };
        let size = serde_json::to_string(&p.args)
            .map(|t| t.len())
            .unwrap_or(usize::MAX);
        if size > MAX_MCP_ARGS {
            return Err(RpcError::new(
                code::TOO_LARGE,
                format!("args are limited to {MAX_MCP_ARGS} bytes"),
            ));
        }
        crate::schema::check(&tool.input_schema, &p.args)
            .map_err(|e| RpcError::new(code::INVALID_PARAMS, e))?;
        if s.waiting.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING {
            s.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(RpcError::new(
                code::BUSY,
                "too many computer-use calls wait for this server",
            ));
        }
        let _waiting = Counter(&s.waiting);
        let shown = shown(&p.args);
        let call = Call {
            id: Some(id),
            chat: &p.ctx.chat,
            portal_tainted: p.ctx.tainted,
            tool: "computer_use",
            pi_tool: None,
        };
        self.engine
            .authorize_screen(
                &call,
                ScreenRequest {
                    server: &s.name,
                    tool: &p.tool,
                    shown: &shown,
                },
            )
            .await?;
        let mut slot = s.slot.lock().await;
        if self.engine.is_paused() {
            return Err(RpcError::denied("the device is paused").with_reason(why::PAUSED));
        }
        self.ensure_started(&s, &mut slot).await?;
        let target = format!("{}.{} {shown}", s.name, p.tool);
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
        self.indicate(&s.name, &p.ctx.chat);
        // From here the chat sees what is on the screen: untrusted content.
        self.engine.mark_tainted(&p.ctx.chat);
        let c = slot
            .client
            .as_mut()
            .ok_or_else(|| server_err(why::NOT_RUNNING, "the server is not running"))?;
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
                    ClientError::Stopped => {
                        RpcError::denied("the device is paused").with_reason(why::PAUSED)
                    }
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
        let s = self
            .servers
            .lock()
            .unwrap()
            .get(server)
            .cloned()
            .ok_or_else(|| format!("{server} is not installed"))?;
        if let Some(e) = &s.error {
            return Err(e.clone());
        }
        let mut slot = s.slot.lock().await;
        self.ensure_started(&s, &mut slot)
            .await
            .map_err(|e| e.message)?;
        let c = slot.client.as_mut().ok_or("the server is not running")?;
        Ok(f(c, &s.pin).await)
    }

    /// Whether a call is in flight (its question included).
    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst) > 0
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
        input: Vec::new(),
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

/// Holds `busy` for a call; the last one out applies a waiting reload.
struct Busy<'a>(&'a Service);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        if self.0.busy.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.apply_pending();
        }
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
            self.busy.fetch_add(1, Ordering::SeqCst);
            let _busy = Busy(self);
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
