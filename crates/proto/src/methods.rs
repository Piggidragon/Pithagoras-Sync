//! Method names, their params (portal to device) and results (device to portal).
//!
//! Params are `deny_unknown_fields`: the device refuses what it does not understand.
//! Results and notifications are what the device writes.

use serde::{Deserialize, Serialize};

pub const DEVICE_INFO: &str = "device.info";
pub const DEVICE_PROBE: &str = "device.probe";
pub const FS_STAT: &str = "fs.stat";
pub const FS_LIST: &str = "fs.list";
pub const FS_READ: &str = "fs.read";
pub const FS_WRITE: &str = "fs.write";
pub const FS_GREP: &str = "fs.grep";
pub const FS_FIND: &str = "fs.find";
pub const EXEC_START: &str = "exec.start";
pub const EXEC_SIGNAL: &str = "exec.signal";

/// The owner's answer to an approval request, from the portal's Devices tab.
pub const APPROVAL_ANSWER: &str = "approval.answer";
/// The approvals waiting now (after a reconnect, say).
pub const APPROVAL_LIST: &str = "approval.list";
/// The device's settings, for the portal's Devices tab (`portal_policy` read or write).
pub const POLICY_GET: &str = "policy.get";
/// Replaces the device's settings (`portal_policy = write` only).
pub const POLICY_SET: &str = "policy.set";

/// Portal to device notification: a chat's grant of this device ended.
pub const GRANT_END: &str = "grant.end";

/// Device to portal notifications.
pub const HELLO: &str = "hello";
pub const EXEC_EXIT: &str = "exec.exit";
pub const AUDIT: &str = "audit";
pub const APPROVAL_REQUESTED: &str = "approval.requested";
pub const APPROVAL_RESOLVED: &str = "approval.resolved";
pub const POLICY_CHANGED: &str = "policy.changed";

/// Capabilities phase 1 announces in `hello`.
pub const CAPABILITIES: &[&str] = &["fs", "grep", "find", "exec", "probe"];
/// Added to `hello`'s capabilities when the device asks the portal for approvals.
pub const CAP_APPROVALS: &str = "approvals";
/// Added when the device shares its settings (`portal_policy` read or write).
pub const CAP_POLICY: &str = "policy";

/// Which chat a call comes from, and the portal guard's taint flag for it. The
/// device keeps its own taint and only ever adds the portal's flag to it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ctx {
    pub chat: String,
    #[serde(default)]
    pub tainted: bool,
    /// The pi tool the call is for. The device checks that this tool is switched on;
    /// a label can only narrow what a call may do, since every label still has to
    /// fit the method (an `fs.write` is `write` or `edit`).
    #[serde(default)]
    pub tool: Option<PiTool>,
}

/// pi's built-in tools, the ones a device can serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PiTool {
    Read,
    Write,
    Edit,
    Bash,
    Grep,
    Find,
    Ls,
}

impl PiTool {
    pub const ALL: [PiTool; 7] = [
        PiTool::Read,
        PiTool::Write,
        PiTool::Edit,
        PiTool::Bash,
        PiTool::Grep,
        PiTool::Find,
        PiTool::Ls,
    ];

    pub fn name(self) -> &'static str {
        match self {
            PiTool::Read => "read",
            PiTool::Write => "write",
            PiTool::Edit => "edit",
            PiTool::Bash => "bash",
            PiTool::Grep => "grep",
            PiTool::Find => "find",
            PiTool::Ls => "ls",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeParams {
    pub path: String,
}

/// `fs.stat` and `fs.list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathParams {
    pub path: String,
    pub ctx: Ctx,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadParams {
    pub path: String,
    /// Stream id the content's `FileData` frames carry; chosen by the portal.
    pub stream: u32,
    pub ctx: Ctx,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteParams {
    pub path: String,
    /// Stream id of the `FileUpload` frames that follow this request.
    pub stream: u32,
    /// Total bytes the frames carry; 0 means no frames follow.
    pub size: u64,
    /// sha256 (lowercase hex) of the content the portal read; the write fails with
    /// `CONFLICT` when the file changed since. Absent: write unconditionally.
    #[serde(default)]
    pub if_match: Option<String>,
    /// Create missing parent directories (pi's `WriteOperations.mkdir`).
    #[serde(default)]
    pub create_dirs: bool,
    pub ctx: Ctx,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrepParams {
    /// File or directory to search.
    pub path: String,
    pub pattern: String,
    /// Glob on the path relative to `path`, like pi's grep `glob`.
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub ignore_case: bool,
    /// Treat `pattern` as a literal string instead of a regex.
    #[serde(default)]
    pub literal: bool,
    /// Lines of context before and after each match.
    #[serde(default)]
    pub context: u32,
    /// Most match lines to return; the device caps it too.
    #[serde(default)]
    pub limit: Option<u32>,
    pub ctx: Ctx,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindParams {
    /// Directory to search.
    pub path: String,
    /// Glob matched against paths relative to `path` (`**/*.rs`).
    pub pattern: String,
    #[serde(default)]
    pub limit: Option<u32>,
    pub ctx: Ctx,
}

/// `exec.start`. There is deliberately no `env`: the device runs commands in its own
/// scrubbed environment, and an `env` field is refused as unknown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecStartParams {
    /// Stream id for the `ExecOutput` frames and the `exec.exit` notification.
    pub stream: u32,
    pub command: String,
    /// Absolute working directory on the device.
    pub cwd: String,
    /// Kill the command after this long. The device applies its own cap as well.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    pub ctx: Ctx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    #[serde(rename = "SIGINT")]
    Int,
    #[serde(rename = "SIGTERM")]
    Term,
    #[serde(rename = "SIGKILL")]
    Kill,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecSignalParams {
    pub stream: u32,
    pub signal: Signal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantEndParams {
    pub chat: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatResult {
    pub kind: FileKind,
    pub size: u64,
    pub mtime_ms: i64,
    /// Permission bits (`0o644`).
    pub mode: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListEntry {
    pub name: String,
    pub kind: FileKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListResult {
    pub entries: Vec<ListEntry>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadResult {
    pub size: u64,
    /// sha256 (lowercase hex) of the whole content, for a later `if_match`.
    pub sha256: String,
    /// How many `FileData` frames were sent before this result.
    pub chunks: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WriteResult {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrepLine {
    /// Absolute path of the file.
    pub path: String,
    /// 1-based line number.
    pub line: u64,
    pub text: String,
    /// A context line around a match rather than a match.
    pub context: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrepResult {
    pub lines: Vec<GrepLine>,
    pub truncated: bool,
    /// Files left out because they are protected or unreadable.
    pub skipped: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindResult {
    /// Absolute paths.
    pub paths: Vec<String>,
    pub truncated: bool,
    pub skipped: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecStartResult {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecExit {
    pub stream: u32,
    /// Exit code, when the shell exited normally.
    pub code: Option<i32>,
    /// Signal name, when the shell was killed by one.
    pub signal: Option<String>,
    pub timed_out: bool,
    /// Output bytes beyond the device's cap were dropped.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub found: bool,
    /// sha256 (lowercase hex) of the probe file's content, when found.
    pub sha256: Option<String>,
    pub user: String,
    pub uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Ask,
    Folders,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Ro,
    Rw,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FolderInfo {
    pub path: String,
    pub access: Access,
    /// Commands may run in it.
    #[serde(default)]
    pub execute: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub os: String,
    pub arch: String,
    pub os_release: Option<String>,
    pub hostname: String,
    pub user: String,
    pub uid: u32,
    pub home: String,
    /// What the `bash` tool runs: `bash` or `sh` on Linux, `pwsh` or `powershell` on
    /// Windows. The tool keeps its name; the model has to write for this shell.
    pub shell: String,
    /// `headless`, `wayland`, `x11` or `windows`.
    pub session: String,
    /// The mode in force now (after Full's expiry).
    pub mode: Mode,
    /// When Full mode ends, Unix milliseconds; absent when not Full or set to never.
    pub mode_expires_ms: Option<i64>,
    pub folders: Vec<FolderInfo>,
    /// How the shell runs in Folders mode: `landlock`, `prompt` or `unconfined`.
    pub folders_shell: String,
    /// The pi tools switched on; the portal offers the device to these only.
    #[serde(default)]
    pub tools: Vec<PiTool>,
    /// Computer-use tools; always empty in phase 1.
    pub mcp_tools: Vec<serde_json::Value>,
    pub client_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub proto: u32,
    pub device_id: String,
    pub client_version: String,
    pub os: String,
    pub user: String,
    /// As in `DeviceInfo::shell`.
    pub shell: String,
    pub capabilities: Vec<String>,
}

/// Device to portal: one decision for the portal's Audit page. Only decisions are
/// mirrored (denials, approvals, mode changes, pauses), never every call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub time_ms: i64,
    pub chat: Option<String>,
    pub tool: String,
    pub target: String,
    pub decision: String,
    pub reason: Option<String>,
}

/// How the owner answers an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Choice {
    /// This call only.
    Once,
    /// Calls of this kind from this chat, until the grant ends or the device's
    /// `remember_minutes` run out.
    Chat,
    /// Calls of this kind from this chat for `minutes`.
    Time,
    Deny,
}

/// Device to portal (`approval.requested`), and what `approval.list` and the local
/// `approvals` command show: a call waits for the owner's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalInfo {
    /// The device's number for this approval; answers name it.
    pub id: u64,
    /// The JSON-RPC id of the waiting call, when it came from the portal.
    pub call: Option<crate::Id>,
    pub chat: String,
    /// The method's tool (`read`, `write`, `exec`, ...).
    pub tool: String,
    /// The path or command.
    pub target: String,
    /// Why it asks (mode, protected path, pattern, taint, a rule).
    pub reasons: Vec<String>,
    /// The start of what a write puts there.
    pub preview: Option<String>,
    /// The answers the device accepts for this call.
    pub choices: Vec<Choice>,
    /// The longest `time` answer the device accepts, in minutes.
    pub max_minutes: u32,
    pub created_ms: i64,
    /// When the device stops waiting and applies its timeout answer.
    pub expires_ms: i64,
}

/// Device to portal (`approval.resolved`): an approval was answered, timed out or
/// withdrawn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalResolved {
    pub id: u64,
    pub chat: String,
    pub answer: Choice,
    pub minutes: Option<u32>,
    /// `portal`, `device` (the local CLI), `notification`, `timeout`, `pause` or
    /// `withdrawn` (the call ended first).
    pub by: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAnswerParams {
    pub id: u64,
    pub answer: Choice,
    /// For `time`: how long, at most the request's `max_minutes`.
    #[serde(default)]
    pub minutes: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalListResult {
    pub approvals: Vec<ApprovalInfo>,
}

/// `policy.set`: the whole settings document as `policy.get` returned it, changed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySetParams {
    pub settings: serde_json::Value,
    /// The `version` the change is based on; a newer one on the device is
    /// `CONFLICT`. Absent: replace whatever is there.
    #[serde(default)]
    pub if_version: Option<String>,
}

/// `policy.get` result and `policy.changed` notification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDocument {
    /// `read` or `write`: whether the portal may change it.
    pub portal_policy: String,
    /// A hash of the settings (hex); changes with every change.
    pub version: String,
    pub settings: serde_json::Value,
    /// Settings only the device can change; `policy.set` must leave them as they are.
    pub device_only: Vec<String>,
}

/// `POST /sync/v1/pair` body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairRequest {
    pub code: String,
    pub name: String,
    pub os: String,
    pub arch: String,
}

/// `POST /sync/v1/pair` answer. Unknown fields are ignored here: nothing in it can
/// widen the device's policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairResponse {
    pub device_id: String,
    pub connector_token: String,
    /// For the phase 2 overlay; phase 1 does not store it.
    #[serde(default)]
    pub overlay_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exec_start_refuses_an_environment() {
        let ok = json!({"stream": 1, "command": "ls", "cwd": "/w", "ctx": {"chat": "c"}});
        assert!(serde_json::from_value::<ExecStartParams>(ok.clone()).is_ok());
        let mut with_env = ok;
        with_env["env"] = json!({"PORTAL_SECRET": "x"});
        assert!(serde_json::from_value::<ExecStartParams>(with_env).is_err());
    }

    #[test]
    fn ctx_refuses_extra_fields() {
        let bad = json!({"path": "/a", "ctx": {"chat": "c", "approved": true}});
        assert!(serde_json::from_value::<PathParams>(bad).is_err());
        let bad = json!({"path": "/a", "ctx": {"chat": "c"}, "mode": "full"});
        assert!(serde_json::from_value::<PathParams>(bad).is_err());
    }

    #[test]
    fn signals_have_their_unix_names() {
        let p: ExecSignalParams =
            serde_json::from_value(json!({"stream": 2, "signal": "SIGTERM"})).unwrap();
        assert_eq!(p.signal, Signal::Term);
        assert!(
            serde_json::from_value::<ExecSignalParams>(json!({"stream": 2, "signal": "SIGSTOP"}))
                .is_err()
        );
    }
}
