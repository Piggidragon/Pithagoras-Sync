//! The engine every portal call goes through: resolve the path, decide by mode,
//! folders, protected paths, patterns and taint, ask the owner where needed, audit.
//!
//! Only the device owner changes the policy (config file or CLI, then `reload`).
//! Nothing the portal sends reaches `reload`; the portal's only inputs here are the
//! call itself and its taint flag, which can only add prompts.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use sync_proto::{Id, RpcError, code};
use tokio::sync::broadcast;

use crate::approve::{Answer, ApprovalRequest, Approver};
use crate::audit::{AuditLog, AuditRecord};
use crate::config::{FolderGrant, FoldersShell, Mode, Policy, Profile};
use crate::paths::{PathError, parse_device_path, resolve, within};
use crate::patterns::{command_prompts, names_protected};
use crate::protected::{Protected, tool_config};
use sync_proto::methods::Access;

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
    /// A call waits for the owner's approval; the portal shows it in the chat.
    Waiting {
        id: Id,
        chat: String,
    },
}

/// Where a call comes from.
#[derive(Debug, Clone)]
pub struct Call<'a> {
    pub id: Option<&'a Id>,
    pub chat: &'a str,
    /// The portal guard's taint flag. Adds to the device's own taint, never clears it.
    pub portal_tainted: bool,
    /// Tool name for prompts and the audit log (`read`, `write`, `exec`, ...).
    pub tool: &'a str,
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
    /// Readable (and executable) hierarchies or files.
    pub read: Vec<PathBuf>,
    /// Writable hierarchies or files.
    pub write: Vec<PathBuf>,
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
    approved: HashSet<Scope>,
}

struct Snapshot {
    policy: Policy,
    profile: Profile,
    protected: Protected,
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
}

impl Engine {
    pub fn new(policy: Policy, profile: Profile, opts: EngineOptions) -> Engine {
        let protected = Protected::new(&opts.home, &opts.own_dirs, &policy.protected);
        let (events, _) = broadcast::channel(256);
        Engine {
            snap: RwLock::new(Arc::new(Snapshot {
                policy,
                profile,
                protected,
            })),
            home: opts.home,
            own_dirs: opts.own_dirs,
            chats: Mutex::new(HashMap::new()),
            approver: opts.approver,
            audit: opts.audit,
            events,
            paused: AtomicBool::new(false),
            clock: opts.clock,
            landlock: opts.landlock,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Takes a new policy from the owner (config file or CLI). Audited as a mode
    /// change when the mode differs.
    pub fn reload(&self, policy: Policy, profile: Profile) {
        let protected = Protected::new(&self.home, &self.own_dirs, &policy.protected);
        let old = std::mem::replace(
            &mut *self.snap.write().unwrap(),
            Arc::new(Snapshot {
                policy,
                profile,
                protected,
            }),
        );
        let new = self.snapshot();
        if old.policy != new.policy {
            let now = self.now();
            self.record(
                None,
                "policy",
                &format!("{:?}", new.policy.effective_mode(new.profile, now)).to_lowercase(),
                "changed",
                Some("changed by the device owner".into()),
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

    /// Panic: deny everything and forget per-chat approvals until `unlock`.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        for c in self.chats.lock().unwrap().values_mut() {
            c.approved.clear();
        }
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
        self.chats
            .lock()
            .unwrap()
            .entry(chat.to_string())
            .or_default()
            .tainted = true;
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
        let rec = AuditRecord {
            time_ms: self.now(),
            chat: chat.map(str::to_string),
            tool: tool.to_string(),
            target: target.to_string(),
            decision: decision.to_string(),
            reason,
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
        let deny = |reason: String| {
            self.record(
                Some(call.chat),
                call.tool,
                &target,
                "denied",
                Some(reason.clone()),
            );
            reason
        };
        if self.is_paused() {
            return Err(Refusal::Denied(deny("the device is paused".into())));
        }
        if call.portal_tainted {
            self.mark_tainted(call.chat);
        }
        let verdict = match self.decide(call.chat, &req) {
            Ok(v) => v,
            Err(e) => {
                let msg = e.to_string();
                deny(format!("bad path: {msg}"));
                return Err(Refusal::BadPath(msg));
            }
        };
        let (permit, reasons, offer) = match verdict {
            Verdict::Allow(permit) => {
                self.record(Some(call.chat), call.tool, &target, "allowed", None);
                return Ok(permit);
            }
            Verdict::Deny(reason) => return Err(Refusal::Denied(deny(reason))),
            Verdict::Prompt {
                permit,
                reasons,
                offer,
            } => (permit, reasons, offer),
        };
        let reason_text = reasons.join("; ");
        if !self.approver.can_prompt() {
            return Err(Refusal::Denied(deny(format!(
                "needs the owner's approval ({reason_text}), and nobody can answer prompts on this device"
            ))));
        }
        let preview = match &req {
            Request::Write { preview, .. } => preview.clone(),
            _ => None,
        };
        let request = ApprovalRequest {
            chat: call.chat.to_string(),
            tool: call.tool.to_string(),
            target: target.clone(),
            reasons,
            preview,
            offer_chat: offer.is_some(),
        };
        if let Some(id) = call.id {
            let _ = self.events.send(Event::Waiting {
                id: id.clone(),
                chat: call.chat.to_string(),
            });
        }
        let timeout = Duration::from_secs(self.snapshot().policy.approval_timeout_secs);
        let answer = match tokio::time::timeout(timeout, self.approver.ask(&request)).await {
            Ok(a) => a,
            Err(_) => {
                return Err(Refusal::Denied(deny(format!(
                    "no answer to the approval within {}s",
                    timeout.as_secs()
                ))));
            }
        };
        // The owner may have paused while the prompt was open.
        if self.is_paused() {
            return Err(Refusal::Denied(deny("the device is paused".into())));
        }
        match answer {
            Answer::Deny => Err(Refusal::Denied(deny(format!(
                "the owner denied it ({reason_text})"
            )))),
            Answer::Once | Answer::ForChat => {
                if let (Answer::ForChat, Some(scope)) = (answer, offer) {
                    self.chats
                        .lock()
                        .unwrap()
                        .entry(call.chat.to_string())
                        .or_default()
                        .approved
                        .insert(scope);
                }
                self.record(
                    Some(call.chat),
                    call.tool,
                    &target,
                    "approved",
                    Some(reason_text),
                );
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
        Box::new(move |p: &Path| {
            if folders && grant_for(p, &grants).is_none() {
                return false;
            }
            !(protections && snap.protected.check(p, false, &grants).is_some())
        })
    }

    fn decide(&self, chat: &str, req: &Request<'_>) -> Result<Verdict, PathError> {
        let snap = self.snapshot();
        let policy = &snap.policy;
        let mode = policy.effective_mode(snap.profile, self.now());
        let grants = resolved_grants(&policy.folders);
        let (tainted, approved) = {
            let chats = self.chats.lock().unwrap();
            let c = chats.get(chat);
            (
                c.is_some_and(|c| c.tainted),
                c.map(|c| c.approved.clone()).unwrap_or_default(),
            )
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
                        let Some(g) = grant_for(&path, &grants) else {
                            return Ok(Verdict::Deny(format!(
                                "{} is outside the folders granted on this device",
                                path.display()
                            )));
                        };
                        if write && g.access == Access::Ro {
                            return Ok(Verdict::Deny(format!(
                                "{} is read-only on this device",
                                g.path.display()
                            )));
                        }
                        root = Some(g.path.clone());
                    }
                    Mode::Full => {}
                }
                if protections {
                    if let Some(e) = snap.protected.check(&path, write, &grants) {
                        reasons.push(format!("{} is a protected path", e.display()));
                    }
                    if write && let Some(t) = tool_config(&path) {
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
                }
            }
            Request::Exec { command, cwd } => {
                let cwd = resolve(&parse_device_path(cwd)?)?;
                let mut confine = Confine::None;
                match mode {
                    Mode::Ask => reasons.push("Ask mode: every command asks".to_string()),
                    Mode::Folders => {
                        if grant_for(&cwd, &grants).is_none() {
                            return Ok(Verdict::Deny(format!(
                                "working folder {} is outside the folders granted on this device",
                                cwd.display()
                            )));
                        }
                        match policy.folders_shell {
                            FoldersShell::Landlock if self.landlock => {
                                confine =
                                    Confine::Landlock(landlock_rules(&grants, &snap.protected));
                            }
                            FoldersShell::Landlock => reasons.push(
                                "the kernel has no Landlock, so every command asks".to_string(),
                            ),
                            FoldersShell::Prompt => {
                                reasons.push("Folders mode: every command asks".to_string())
                            }
                            FoldersShell::Unconfined => {
                                reasons.extend(command_prompts(command, &cwd, &self.home));
                                reasons.extend(names_protected(
                                    command,
                                    &snap.protected,
                                    &self.home,
                                ));
                            }
                        }
                    }
                    Mode::Full => {
                        if policy.full.pattern_prompts {
                            reasons.extend(command_prompts(command, &cwd, &self.home));
                        }
                        if policy.full.protected_paths {
                            reasons.extend(names_protected(command, &snap.protected, &self.home));
                        }
                    }
                }
                if taint_prompts {
                    reasons.push("this chat has seen untrusted content".to_string());
                }
                Permit {
                    path: cwd,
                    root: None,
                    confine,
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

/// Grants with their paths resolved; a folder that does not exist grants nothing.
fn resolved_grants(folders: &[FolderGrant]) -> Vec<FolderGrant> {
    folders
        .iter()
        .filter_map(|g| {
            std::fs::canonicalize(&g.path).ok().map(|path| FolderGrant {
                path,
                access: g.access,
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

/// The Landlock rules for the Folders shell: system directories readable, granted
/// folders readable or writable, minus the protected paths inside them.
pub fn landlock_rules(grants: &[FolderGrant], protected: &Protected) -> LandlockRules {
    let mut read: Vec<PathBuf> = SYSTEM_READ
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    read.extend(
        protected
            .write_only()
            .iter()
            .filter(|p| p.exists())
            .cloned(),
    );
    let mut write: Vec<PathBuf> = DEVICE_WRITE
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    for g in grants {
        match g.access {
            Access::Ro => carve(&g.path, &protected.inside(&g.path, false), &mut read),
            Access::Rw => carve(&g.path, &protected.inside(&g.path, true), &mut write),
        }
    }
    LandlockRules { read, write }
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
