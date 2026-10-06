//! The engine every portal call goes through: resolve the path, decide by tools,
//! hours, deny rules, mode, folders, protected paths, command rules, patterns and
//! taint, ask the owner where needed, audit.
//!
//! Only the device owner changes the policy (config file or CLI, or the portal's
//! `policy.set` where the owner switched that on, then `reload`). A call's own
//! inputs are the call itself, its tool label and its taint flag, which can only
//! narrow what it may do.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use sync_proto::{Id, RpcError, code};
use tokio::sync::broadcast;

use crate::approve::{Answer, ApprovalRequest, Approver};
use crate::audit::{AuditLog, AuditRecord};
use crate::config::{Elevation, FolderGrant, FoldersShell, Mode, Policy, Profile, TimeoutAnswer};
use crate::paths::{PathError, parse_device_path, resolve, within};
use crate::patterns::{command_prompts, names_protected};
use crate::protected::{Protected, fold};
use crate::rules::{Compiled, Rights};
use crate::secret::SecretSlot;
use sync_proto::methods::{Access, PiTool};

/// System directories the Landlock-confined shell may read and execute from.
const SYSTEM_READ: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/etc",
    "/opt",
    "/nix/store",
    "/run/current-system",
    "/proc",
    "/sys",
    "/dev",
];

/// Device files the confined shell may write (`> /dev/null`).
const DEVICE_WRITE: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/tty",
    "/dev/pts",
];

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Audit(AuditRecord),
}

/// Where a call comes from.
#[derive(Debug, Clone)]
pub struct Call<'a> {
    pub id: Option<&'a Id>,
    pub chat: &'a str,
    /// The portal guard's taint flag. Adds to the device's own taint, never clears it.
    pub portal_tainted: bool,
    /// The method's tool name for prompts and the audit log (`read`, `write`,
    /// `exec`, ...).
    pub tool: &'a str,
    /// The pi tool the portal says the call is for; checked against the method and
    /// the tools switched on.
    pub pi_tool: Option<PiTool>,
}

#[derive(Debug, Clone)]
pub enum Request<'a> {
    Read(&'a str),
    Write {
        path: &'a str,
        preview: Option<String>,
    },
    Exec {
        command: &'a str,
        cwd: &'a str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockRules {
    /// Readable hierarchies or files.
    pub read: Vec<PathBuf>,
    /// Writable (and readable) hierarchies or files.
    pub write: Vec<PathBuf>,
    /// Hierarchies or files whose programs may run.
    pub exec: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confine {
    None,
    Landlock(LandlockRules),
}

/// What an allowed call may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permit {
    /// The resolved path (file calls) or working folder (exec).
    pub path: PathBuf,
    /// Open beneath this folder (`openat2(RESOLVE_BENEATH)`) in Folders mode.
    pub root: Option<PathBuf>,
    pub confine: Confine,
    /// A `sudo ...` command the device runs elevated, through this sudo.
    pub elevate: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    BadPath(String),
    Denied(String),
}

impl From<Refusal> for RpcError {
    fn from(r: Refusal) -> RpcError {
        match r {
            Refusal::BadPath(m) => RpcError::new(code::BAD_PATH, m),
            Refusal::Denied(m) => RpcError::denied(m),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Scope {
    Read,
    Write,
}

#[derive(Debug, Default)]
struct ChatState {
    tainted: bool,
    /// Standing approvals and when they end (Unix ms; `None` with the grant).
    approved: HashMap<Scope, Option<i64>>,
    /// The last call of this chat (Unix ms).
    used_ms: i64,
}

/// Most chats the device keeps taint and approvals for. Chat ids come from the
/// portal; past this the chat unused longest is forgotten, so the portal cannot
/// make the device hold memory without bound.
pub const MAX_CHATS: usize = 4096;

/// The state of `chat`, made when missing; drops the chat unused longest when
/// that would hold more than `MAX_CHATS`.
fn chat_state<'a>(
    chats: &'a mut HashMap<String, ChatState>,
    chat: &str,
    now: i64,
) -> &'a mut ChatState {
    if !chats.contains_key(chat)
        && chats.len() >= MAX_CHATS
        && let Some(oldest) = chats
            .iter()
            .min_by_key(|(_, c)| c.used_ms)
            .map(|(k, _)| k.clone())
    {
        chats.remove(&oldest);
    }
    let c = chats.entry(chat.to_string()).or_default();
    c.used_ms = now;
    c
}

struct Snapshot {
    policy: Policy,
    profile: Profile,
    protected: Protected,
    /// The policy's rules, or why they do not compile (then everything is denied).
    rules: Result<Compiled, String>,
}

impl Snapshot {
    fn new(policy: Policy, profile: Profile, home: &Path, own_dirs: &[PathBuf]) -> Snapshot {
        let protected = Protected::new(home, own_dirs, &policy.protected);
        let rules = policy.compile(home);
        Snapshot {
            policy,
            profile,
            protected,
            rules,
        }
    }
}

enum Verdict {
    Allow(Permit),
    Prompt {
        permit: Permit,
        reasons: Vec<String>,
        offer: Option<Scope>,
    },
    Deny(String),
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    })
}

pub struct EngineOptions {
    pub home: PathBuf,
    /// The client's own config and state directories (always protected).
    pub own_dirs: Vec<PathBuf>,
    pub approver: Arc<dyn Approver>,
    pub audit: Arc<AuditLog>,
    pub clock: Clock,
    /// Whether the kernel enforces Landlock; without it the Folders shell prompts.
    pub landlock: bool,
    /// Whether the client runs as root (Unix, `geteuid() == 0`): then `sudo` and
    /// the like change nothing, so they neither ask nor elevate.
    pub as_root: bool,
}

pub struct Engine {
    snap: RwLock<Arc<Snapshot>>,
    home: PathBuf,
    own_dirs: Vec<PathBuf>,
    chats: Mutex<HashMap<String, ChatState>>,
    approver: Arc<dyn Approver>,
    audit: Arc<AuditLog>,
    events: broadcast::Sender<Event>,
    paused: AtomicBool,
    clock: Clock,
    landlock: bool,
    as_root: bool,
    secrets: std::sync::OnceLock<Arc<SecretSlot>>,
    /// Files no tool reaches in any mode (the stored elevation secret).
    sealed: std::sync::OnceLock<Vec<PathBuf>>,
}

impl Engine {
    pub fn new(policy: Policy, profile: Profile, opts: EngineOptions) -> Engine {
        let snap = Snapshot::new(policy, profile, &opts.home, &opts.own_dirs);
        let (events, _) = broadcast::channel(256);
        Engine {
            snap: RwLock::new(Arc::new(snap)),
            home: opts.home,
            own_dirs: opts.own_dirs,
            chats: Mutex::new(HashMap::new()),
            approver: opts.approver,
            audit: opts.audit,
            events,
            paused: AtomicBool::new(false),
            clock: opts.clock,
            landlock: opts.landlock,
            as_root: opts.as_root,
            secrets: std::sync::OnceLock::new(),
            sealed: std::sync::OnceLock::new(),
        }
    }

    /// Files the file tools never reach and Landlock carves out, whatever the
    /// policy says: the secret the device keeps for itself.
    pub fn seal(&self, paths: Vec<PathBuf>) {
        // As named and as resolved, so a symlinked config folder is sealed too.
        let resolved: Vec<PathBuf> = paths.iter().filter_map(|p| resolve(p).ok()).collect();
        let _ = self.sealed.set(paths.into_iter().chain(resolved).collect());
    }

    fn sealed(&self, path: &Path) -> bool {
        let folded = fold(path);
        self.sealed
            .get()
            .is_some_and(|s| s.iter().any(|e| within(&folded, &fold(e))))
    }

    /// The elevation secret to keep out of the audit log.
    pub fn scrub_with(&self, slot: Arc<SecretSlot>) {
        let _ = self.secrets.set(slot);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Takes a new policy from the owner (config file, CLI or the portal where the
    /// owner allows it). Audited when it differs.
    pub fn reload(&self, policy: Policy, profile: Profile) {
        self.reload_by(policy, profile, "the device owner");
    }

    /// `reload`, saying who changed it in the audit log.
    pub fn reload_by(&self, policy: Policy, profile: Profile, by: &str) {
        let snap = Snapshot::new(policy, profile, &self.home, &self.own_dirs);
        let old = std::mem::replace(&mut *self.snap.write().unwrap(), Arc::new(snap));
        let new = self.snapshot();
        if old.policy != new.policy {
            let now = self.now();
            self.record(
                None,
                "policy",
                &format!("{:?}", new.policy.effective_mode(new.profile, now)).to_lowercase(),
                "changed",
                Some(format!("changed by {by}")),
            );
        }
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        self.snap.read().unwrap().clone()
    }

    pub fn policy(&self) -> (Policy, Profile) {
        let s = self.snapshot();
        (s.policy.clone(), s.profile)
    }

    pub fn effective_mode(&self) -> Mode {
        let s = self.snapshot();
        s.policy.effective_mode(s.profile, self.now())
    }

    pub fn landlock_available(&self) -> bool {
        self.landlock
    }

    /// Panic: deny everything, answer open approvals with deny and forget per-chat
    /// approvals until `unlock`.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        for c in self.chats.lock().unwrap().values_mut() {
            c.approved.clear();
        }
        self.approver.cancel_all();
        self.record(None, "pause", "", "paused", None);
    }

    pub fn unlock(&self) {
        self.paused.store(false, Ordering::SeqCst);
        self.record(None, "pause", "", "unlocked", None);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// The device served untrusted content (screen, MCP) to this chat: from now on
    /// its mutating calls prompt.
    pub fn mark_tainted(&self, chat: &str) {
        let now = self.now();
        chat_state(&mut self.chats.lock().unwrap(), chat, now).tainted = true;
    }

    /// How many chats the device keeps taint or approvals for.
    pub fn chats(&self) -> usize {
        self.chats.lock().unwrap().len()
    }

    pub fn is_tainted(&self, chat: &str) -> bool {
        self.chats
            .lock()
            .unwrap()
            .get(chat)
            .is_some_and(|c| c.tainted)
    }

    /// The chat's grant of this device ended: its taint and approvals go.
    pub fn grant_end(&self, chat: &str) {
        self.chats.lock().unwrap().remove(chat);
    }

    /// Writes an audit record and passes it to subscribers (the connector mirrors
    /// decisions to the portal).
    pub fn record(
        &self,
        chat: Option<&str>,
        tool: &str,
        target: &str,
        decision: &str,
        reason: Option<String>,
    ) {
        self.record_exit(chat, tool, target, decision, reason, None);
    }

    pub fn record_exit(
        &self,
        chat: Option<&str>,
        tool: &str,
        target: &str,
        decision: &str,
        reason: Option<String>,
        exit_code: Option<i32>,
    ) {
        self.record_in(chat, tool, target, None, decision, reason, exit_code);
    }

    /// `record` with the folder a command runs in.
    #[allow(clippy::too_many_arguments)]
    fn record_in(
        &self,
        chat: Option<&str>,
        tool: &str,
        target: &str,
        cwd: Option<&str>,
        decision: &str,
        reason: Option<String>,
        exit_code: Option<i32>,
    ) {
        // Whatever a command or the owner wrote, the elevation secret stays out.
        let scrub = |t: &str| match self.secrets.get() {
            Some(s) => s.scrub(t),
            None => t.to_string(),
        };
        // Cut after scrubbing, so a cut cannot leave half the secret behind.
        let rec = AuditRecord {
            time_ms: self.now(),
            chat: chat.map(|c| crate::audit::cut(&scrub(c), sync_proto::methods::MAX_CHAT_ID)),
            tool: tool.to_string(),
            target: crate::audit::cut(&scrub(target), crate::audit::MAX_FIELD),
            cwd: cwd.map(|c| crate::audit::cut(&scrub(c), crate::audit::MAX_FIELD)),
            decision: decision.to_string(),
            reason: reason
                .as_deref()
                .map(|r| crate::audit::cut(&scrub(r), crate::audit::MAX_FIELD)),
            exit_code,
        };
        self.audit.append(&rec);
        let _ = self.events.send(Event::Audit(rec));
    }

    /// Decides one call, asking the owner where the policy says so.
    pub async fn authorize(&self, call: &Call<'_>, req: Request<'_>) -> Result<Permit, Refusal> {
        let target = match &req {
            Request::Read(p) => p.to_string(),
            Request::Write { path, .. } => path.to_string(),
            Request::Exec { command, .. } => command.to_string(),
        };
        // Where a command runs: as the portal named it until the policy resolved
        // it, then the resolved folder, which is where it would run.
        let mut cwd = match &req {
            Request::Exec { cwd, .. } => Some(cwd.to_string()),
            _ => None,
        };
        let record = |cwd: &Option<String>, decision: &str, reason: Option<String>| {
            self.record_in(
                Some(call.chat),
                call.tool,
                &target,
                cwd.as_deref(),
                decision,
                reason,
                None,
            );
        };
        let deny = |cwd: &Option<String>, reason: String| {
            record(cwd, "denied", Some(reason.clone()));
            reason
        };
        if self.is_paused() {
            return Err(Refusal::Denied(deny(&cwd, "the device is paused".into())));
        }
        if call.portal_tainted {
            self.mark_tainted(call.chat);
        }
        let verdict = match self.decide(call, &req) {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string();
                deny(&cwd, format!("bad path: {msg}"));
                return Err(Refusal::BadPath(msg));
            }
        };
        if let (
            Some(c),
            Verdict::Allow(Permit { path, .. })
            | Verdict::Prompt {
                permit: Permit { path, .. },
                ..
            },
        ) = (&mut cwd, &verdict)
        {
            *c = crate::paths::to_wire(path);
        }
        let (permit, reasons, offer) = match verdict {
            Verdict::Allow(permit) => {
                record(&cwd, "allowed", None);
                return Ok(permit);
            }
            Verdict::Deny(reason) => return Err(Refusal::Denied(deny(&cwd, reason))),
            Verdict::Prompt {
                permit,
                reasons,
                offer,
            } => (permit, reasons, offer),
        };
        let reason_text = reasons.join("; ");
        if !self.approver.can_prompt() {
            return Err(Refusal::Denied(deny(
                &cwd,
                format!(
                    "needs the owner's approval ({reason_text}), and nobody can answer prompts on this device"
                ),
            )));
        }
        let preview = match &req {
            Request::Write { preview, .. } => preview.clone(),
            _ => None,
        };
        let opts = self.snapshot().policy.approvals.clone();
        let timeout = Duration::from_secs(opts.timeout_secs);
        let request = ApprovalRequest {
            call: call.id.cloned(),
            chat: call.chat.to_string(),
            tool: call.tool.to_string(),
            target: target.clone(),
            cwd: cwd.clone(),
            reasons,
            preview,
            offer_chat: offer.is_some(),
            max_minutes: opts.max_minutes,
            expires_ms: self.now() + timeout.as_millis() as i64,
            on_timeout_allow: opts.on_timeout == TimeoutAnswer::Allow,
        };
        let answer = match tokio::time::timeout(timeout, self.approver.ask(&request)).await {
            Ok(a) => a,
            Err(_) if opts.on_timeout == TimeoutAnswer::Allow && !self.is_paused() => {
                record(
                    &cwd,
                    "approved",
                    Some(format!(
                        "no answer within {}s, and this device allows on timeout ({reason_text})",
                        timeout.as_secs()
                    )),
                );
                return Ok(permit);
            }
            Err(_) => {
                return Err(Refusal::Denied(deny(
                    &cwd,
                    format!("no answer to the approval within {}s", timeout.as_secs()),
                )));
            }
        };
        // The owner may have paused while the prompt was open.
        if self.is_paused() {
            return Err(Refusal::Denied(deny(&cwd, "the device is paused".into())));
        }
        match answer {
            Answer::Deny => Err(Refusal::Denied(deny(
                &cwd,
                format!("the owner denied it ({reason_text})"),
            ))),
            Answer::Once | Answer::ForChat | Answer::ForTime(_) => {
                let until = match answer {
                    Answer::ForChat if opts.remember_minutes == 0 => Some(None),
                    Answer::ForChat => {
                        Some(Some(self.now() + i64::from(opts.remember_minutes) * 60_000))
                    }
                    Answer::ForTime(m) => Some(Some(
                        self.now() + i64::from(m.min(opts.max_minutes)) * 60_000,
                    )),
                    _ => None,
                };
                if let (Some(until), Some(scope)) = (until, offer) {
                    let now = self.now();
                    chat_state(&mut self.chats.lock().unwrap(), call.chat, now)
                        .approved
                        .insert(scope, until);
                }
                record(&cwd, "approved", Some(reason_text));
                Ok(permit)
            }
        }
    }

    /// For grep and find, after the search root passed `authorize`: whether a path
    /// met during the walk may be read. Protected paths are skipped rather than
    /// prompted for one by one, and in Folders mode the walk stays in granted
    /// folders (it never follows symlinks, so this only matters for nested grants).
    pub fn walk_filter(&self) -> Box<dyn Fn(&Path) -> bool + Send + Sync> {
        let snap = self.snapshot();
        let mode = snap.policy.effective_mode(snap.profile, self.now());
        let protections = mode != Mode::Full || snap.policy.full.protected_paths;
        let folders = mode == Mode::Folders;
        let grants = resolved_grants(&snap.policy.folders);
        let sealed = self.sealed.get().cloned().unwrap_or_default();
        Box::new(move |p: &Path| {
            let Ok(rules) = &snap.rules else {
                return false;
            };
            let folded = fold(p);
            if sealed.iter().any(|e| within(&folded, &fold(e))) {
                return false;
            }
            if rules.denied(p, Rights::READ).is_some() {
                return false;
            }
            if folders && grant_for(p, &grants).is_none() && rules.glob_grant(p).is_none() {
                return false;
            }
            !(protections && snap.protected.check(p, false, &grants).is_some())
        })
    }

    fn decide(&self, call: &Call<'_>, req: &Request<'_>) -> Result<Verdict, PathError> {
        let snap = self.snapshot();
        let policy = &snap.policy;
        let rules = match &snap.rules {
            Ok(r) => r,
            Err(e) => {
                return Ok(Verdict::Deny(format!(
                    "the device's policy has a broken rule ({e}), so it refuses everything"
                )));
            }
        };
        if let Some(why) = policy.tools.refusal(call.tool, call.pi_tool) {
            return Ok(Verdict::Deny(why));
        }
        let now = self.now();
        if !rules.within_hours(now) {
            return Ok(Verdict::Deny(
                "outside the hours this device works for the portal".into(),
            ));
        }
        let mode = policy.effective_mode(snap.profile, now);
        let grants = resolved_grants(&policy.folders);
        let (tainted, approved) = {
            let mut chats = self.chats.lock().unwrap();
            if let Some(c) = chats.get_mut(call.chat) {
                c.used_ms = now;
            }
            let c = chats.get(call.chat);
            let approved: HashSet<Scope> = c
                .map(|c| {
                    c.approved
                        .iter()
                        .filter(|(_, until)| until.is_none_or(|u| now < u))
                        .map(|(s, _)| *s)
                        .collect()
                })
                .unwrap_or_default();
            (c.is_some_and(|c| c.tainted), approved)
        };
        let full = mode == Mode::Full;
        let protections = !full || policy.full.protected_paths;
        let taint_prompts = tainted && (!full || policy.full.taint_prompts);
        let mut reasons = Vec::new();
        let mut offer = None;

        let permit = match req {
            Request::Read(p) | Request::Write { path: p, .. } => {
                let write = matches!(req, Request::Write { .. });
                let path = resolve(&parse_device_path(p)?)?;
                let right = if write { Rights::WRITE } else { Rights::READ };
                if self.sealed(&path) {
                    return Ok(Verdict::Deny(format!(
                        "{} holds the device's own secret and stays on the device",
                        path.display()
                    )));
                }
                if let Some(r) = rules.denied(&path, right) {
                    return Ok(Verdict::Deny(format!(
                        "{} is denied on this device (rule {} {})",
                        path.display(),
                        r.path,
                        r.rights
                    )));
                }
                let mut root = None;
                match mode {
                    Mode::Ask => {
                        let scope = if write { Scope::Write } else { Scope::Read };
                        if !approved.contains(&scope) {
                            reasons.push("Ask mode: every call asks".to_string());
                            offer = Some(scope);
                        }
                    }
                    Mode::Folders => {
                        let access = if let Some(g) = grant_for(&path, &grants) {
                            root = Some(g.path.clone());
                            (g.access, g.path.display().to_string())
                        } else if let Some(g) = rules.glob_grant(&path) {
                            // A glob names files, not a folder to open beneath; the
                            // resolved path's own folder is the root.
                            root = path.parent().map(Path::to_path_buf);
                            (g.access, g.glob.clone())
                        } else {
                            return Ok(Verdict::Deny(format!(
                                "{} is outside the folders granted on this device",
                                path.display()
                            )));
                        };
                        if write && access.0 == Access::Ro {
                            return Ok(Verdict::Deny(format!(
                                "{} is read-only on this device",
                                access.1
                            )));
                        }
                    }
                    Mode::Full => {}
                }
                if protections {
                    if let Some(e) = snap.protected.check(&path, write, &grants) {
                        reasons.push(format!("{} is a protected path", e.display()));
                    }
                    if write && let Some(t) = snap.protected.tool_config(&path) {
                        reasons.push(format!("writes to {t} ask first"));
                    }
                }
                if write && taint_prompts {
                    reasons.push("this chat has seen untrusted content".to_string());
                }
                Permit {
                    path,
                    root,
                    confine: Confine::None,
                    elevate: None,
                }
            }
            Request::Exec { command, cwd } => {
                let cwd = resolve(&parse_device_path(cwd)?)?;
                if let Some(r) = rules.denied(&cwd, Rights::EXECUTE) {
                    return Ok(Verdict::Deny(format!(
                        "commands are denied in {} (rule {} {})",
                        cwd.display(),
                        r.path,
                        r.rights
                    )));
                }
                if let Some(why) = rules.command_refusal(command) {
                    return Ok(Verdict::Deny(why));
                }
                let never_ask = rules.never_ask(command);
                // A client that runs as root has nothing to elevate to: its `sudo`
                // is an ordinary command.
                let elevated = elevated_command(command).filter(|_| !self.as_root);
                let elevate = match (policy.privilege.elevation, elevated) {
                    (Elevation::Sudo, Some(rest)) if rest.starts_with('-') || rest.is_empty() => {
                        return Ok(Verdict::Deny(
                            "elevated commands are `sudo <command>`, run as root; sudo's own options are not taken".into(),
                        ));
                    }
                    (Elevation::Sudo, Some(_)) => Some(policy.privilege.sudo_path.clone()),
                    _ => None,
                };
                let mut asks = Vec::new();
                let mut confine = Confine::None;
                match mode {
                    Mode::Ask => asks.push("Ask mode: every command asks".to_string()),
                    Mode::Folders => {
                        let Some(g) = grant_for(&cwd, &grants) else {
                            return Ok(Verdict::Deny(format!(
                                "working folder {} is outside the folders granted on this device",
                                cwd.display()
                            )));
                        };
                        if !g.execute {
                            return Ok(Verdict::Deny(format!(
                                "{} does not allow commands on this device (no execute right)",
                                g.path.display()
                            )));
                        }
                        match policy.folders_shell {
                            FoldersShell::Landlock if self.landlock => {
                                let mut denied = rules.denied_paths();
                                denied.extend(
                                    self.sealed
                                        .get()
                                        .into_iter()
                                        .flatten()
                                        .map(|p| (p.clone(), Rights::ALL)),
                                );
                                confine = Confine::Landlock(landlock_rules(
                                    &grants,
                                    &snap.protected,
                                    &denied,
                                ));
                            }
                            FoldersShell::Landlock => asks.push(NO_LANDLOCK.to_string()),
                            FoldersShell::Prompt => {
                                asks.push("Folders mode: every command asks".to_string())
                            }
                            FoldersShell::Unconfined => {
                                asks.extend(command_prompts(
                                    command,
                                    &cwd,
                                    &self.home,
                                    self.as_root,
                                ));
                                asks.extend(names_protected(command, &snap.protected, &self.home));
                            }
                        }
                    }
                    Mode::Full => {
                        if policy.full.pattern_prompts {
                            asks.extend(command_prompts(command, &cwd, &self.home, self.as_root));
                        }
                        if policy.full.protected_paths {
                            asks.extend(names_protected(command, &snap.protected, &self.home));
                        }
                    }
                }
                // Root's commands ask in every mode; only the owner's never-ask list
                // lifts that, command by command.
                if elevate.is_some() {
                    asks.push("the command runs as root through sudo".to_string());
                }
                // The owner's never-ask list skips the mode's and the patterns'
                // questions; the confinement above and the taint question stay.
                if !never_ask {
                    reasons.extend(asks);
                }
                if let Some(why) = rules.always_ask(command) {
                    reasons.push(why);
                }
                if taint_prompts {
                    reasons.push("this chat has seen untrusted content".to_string());
                }
                if elevate.is_some() && confine != Confine::None {
                    return Ok(Verdict::Deny(
                        "sudo cannot run under Landlock (no_new_privs); elevated commands need folders_shell = unconfined or Full mode".into(),
                    ));
                }
                Permit {
                    path: cwd,
                    root: None,
                    confine,
                    elevate,
                }
            }
        };
        Ok(if reasons.is_empty() {
            Verdict::Allow(permit)
        } else {
            Verdict::Prompt {
                permit,
                reasons,
                offer,
            }
        })
    }
}

/// Why every command asks in Folders mode when commands cannot be confined: on
/// Linux the kernel lacks Landlock; other systems have none at all.
const NO_LANDLOCK: &str = if cfg!(windows) {
    "Windows has no Landlock to confine commands, so every command in Folders mode asks"
} else if cfg!(target_os = "linux") {
    "the kernel has no Landlock, so every command asks"
} else {
    "this system has no Landlock to confine commands, so every command in Folders mode asks"
};

/// The command after a leading `sudo `, which the device runs elevated.
pub fn elevated_command(command: &str) -> Option<&str> {
    let c = command.trim_start();
    c.strip_prefix("sudo")
        .filter(|r| r.starts_with([' ', '\t']))
        .map(str::trim_start)
}

/// Grants with their paths resolved; a folder that does not exist grants nothing.
fn resolved_grants(folders: &[FolderGrant]) -> Vec<FolderGrant> {
    folders
        .iter()
        .filter_map(|g| {
            std::fs::canonicalize(&g.path).ok().map(|path| FolderGrant {
                path,
                access: g.access,
                execute: g.execute,
            })
        })
        .collect()
}

/// The grant holding `path`, the innermost one when grants nest (so a read-only
/// folder inside a read-write one stays read-only).
fn grant_for<'a>(path: &Path, grants: &'a [FolderGrant]) -> Option<&'a FolderGrant> {
    grants
        .iter()
        .filter(|g| within(path, &g.path))
        .max_by_key(|g| g.path.components().count())
}

/// The Landlock rules for the Folders shell: system directories readable and
/// executable, granted folders readable or writable (and executable where the
/// grant says so), minus the protected paths and the denied paths inside them.
pub fn landlock_rules(
    grants: &[FolderGrant],
    protected: &Protected,
    denied: &[(PathBuf, Rights)],
) -> LandlockRules {
    let existing = |list: &[&str]| -> Vec<PathBuf> {
        list.iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    };
    // Folded, as the protected entries are, to compare against.
    let denied_for = |right: Rights| -> Vec<PathBuf> {
        denied
            .iter()
            .filter(|(_, r)| r.overlaps(right))
            .map(|(p, _)| fold(p))
            .collect()
    };
    let (no_read, no_write, no_exec) = (
        denied_for(Rights::READ),
        denied_for(Rights::WRITE),
        denied_for(Rights::EXECUTE),
    );
    let mut read = existing(SYSTEM_READ);
    read.retain(|p| !no_read.iter().any(|d| within(&fold(p), d)));
    read.extend(
        protected
            .write_only()
            .iter()
            .filter(|p| p.exists() && !no_read.iter().any(|d| within(p, d)))
            .cloned(),
    );
    let mut exec = existing(SYSTEM_READ);
    exec.retain(|p| !no_exec.iter().any(|d| within(&fold(p), d)));
    let mut write = existing(DEVICE_WRITE);
    for g in grants {
        match g.access {
            Access::Ro => add(
                &g.path,
                protected.inside(&g.path, false),
                &no_read,
                &mut read,
            ),
            Access::Rw => {
                // A write rule grants reading too, so paths denied either way stay out.
                let mut no_rw = no_read.clone();
                no_rw.extend(no_write.iter().cloned());
                add(&g.path, protected.inside(&g.path, true), &no_rw, &mut write);
                // What is only write-denied inside stays readable.
                for (d, _) in denied.iter().filter(|(_, r)| r.write && !r.read) {
                    let df = fold(d);
                    if within(&df, &fold(&g.path))
                        && !no_read.iter().any(|r| within(&df, r))
                        && protected
                            .inside(&g.path, false)
                            .iter()
                            .all(|p| !within(&df, p))
                        && d.exists()
                    {
                        read.push(d.clone());
                    }
                }
            }
        }
        if g.execute {
            add(
                &g.path,
                protected.inside(&g.path, false),
                &no_exec,
                &mut exec,
            );
        }
    }
    LandlockRules { read, write, exec }
}

/// Adds the rule for `dir` minus the paths carved out of it: none when `dir` itself
/// lies in a denied path.
fn add(dir: &Path, protected_inside: Vec<&Path>, denied: &[PathBuf], out: &mut Vec<PathBuf>) {
    let folded = fold(dir);
    if denied.iter().any(|d| within(&folded, d)) {
        return;
    }
    let mut inside = protected_inside;
    inside.extend(
        denied
            .iter()
            .filter(|d| d.as_path() != folded && within(d, &folded))
            .map(PathBuf::as_path),
    );
    carve(dir, &inside, out);
}

/// Adds `dir` as one rule, or, when protected paths lie inside it, each of its
/// entries except those (recursing towards nested ones). Symlinks get no rule of
/// their own: a rule follows them, which could name anything.
fn carve(dir: &Path, protected_inside: &[&Path], out: &mut Vec<PathBuf>) {
    if protected_inside.is_empty() {
        out.push(dir.to_path_buf());
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let folded = PathBuf::from(child.to_string_lossy().to_lowercase());
        if protected_inside.iter().any(|p| *p == folded) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&child) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let nested: Vec<&Path> = protected_inside
            .iter()
            .copied()
            .filter(|p| within(p, &folded))
            .collect();
        if nested.is_empty() {
            out.push(child);
        } else if meta.is_dir() {
            carve(&child, &nested, out);
        }
    }
}
