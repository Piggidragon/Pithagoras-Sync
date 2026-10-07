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
/// Computer use: the MCP servers installed on the device and their allowed tools.
pub const MCP_LIST: &str = "mcp.list";
/// Computer use: one call of an allowed tool of an MCP server on the device.
pub const MCP_CALL: &str = "mcp.call";

/// Portal to device notification: a chat's grant of this device ended.
pub const GRANT_END: &str = "grant.end";

/// Device to portal notifications.
pub const HELLO: &str = "hello";
pub const EXEC_EXIT: &str = "exec.exit";
pub const AUDIT: &str = "audit";
pub const APPROVAL_REQUESTED: &str = "approval.requested";
pub const APPROVAL_RESOLVED: &str = "approval.resolved";
pub const POLICY_CHANGED: &str = "policy.changed";
/// The list `mcp.list` returns, or the consent, changed.
pub const MCP_CHANGED: &str = "mcp.changed";

/// Capabilities phase 1 announces in `hello`.
pub const CAPABILITIES: &[&str] = &["fs", "grep", "find", "exec", "probe"];
/// Added to `hello`'s capabilities when the device asks the portal for approvals.
pub const CAP_APPROVALS: &str = "approvals";
/// Added when the device shares its settings (`portal_policy` read or write).
pub const CAP_POLICY: &str = "policy";
/// Added when the device serves computer use (`mcp.list`, `mcp.call`,
/// `mcp.changed`), whether or not a server is installed yet.
pub const CAP_MCP: &str = "mcp";

/// Which chat a call comes from, and the portal guard's taint flag for it. The
/// device keeps its own taint and only ever adds the portal's flag to it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ctx {
    #[serde(deserialize_with = "chat_id")]
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

/// Longest command `exec.start` takes, in bytes: about the most Linux passes to
/// the shell as one argument (`MAX_ARG_STRLEN`), and a bound on what the device's
/// command rules have to scan.
pub const MAX_COMMAND: usize = 128 * 1024;

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
    #[serde(deserialize_with = "chat_id")]
    pub chat: String,
}

/// Longest chat id, in bytes.
pub const MAX_CHAT_ID: usize = 256;

/// A chat id: at most `MAX_CHAT_ID` bytes and no control characters. The device
/// keeps state per chat and shows the id to the owner, so the portal cannot make it
/// hold or print anything larger.
fn chat_id<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if s.len() > MAX_CHAT_ID {
        return Err(serde::de::Error::custom(format!(
            "a chat id has at most {MAX_CHAT_ID} bytes"
        )));
    }
    if s.chars().any(char::is_control) {
        return Err(serde::de::Error::custom(
            "a chat id has no control characters",
        ));
    }
    Ok(s)
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
    /// Computer use: the allowed tools of the installed MCP servers, as
    /// `mcp.list` lists them (empty when none is installed).
    #[serde(default)]
    pub mcp_tools: Vec<McpToolRef>,
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
    /// With `mcp` in `capabilities`: the `version` of what `mcp.list` returns
    /// now, so a portal can tell whether the tools it registered are current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_version: Option<String>,
}

/// Device to portal: one decision for the portal's Audit page. Only decisions are
/// mirrored (denials, approvals, mode changes, pauses), never every call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub time_ms: i64,
    pub chat: Option<String>,
    pub tool: String,
    pub target: String,
    /// The folder a command runs in (commands only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
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

/// Longest command or path (and folder) an approval shows. A longer one is shown
/// cut, says `cut`, and takes only `deny`: nobody could read what they allow.
pub const MAX_APPROVAL_TEXT: usize = 64 * 1024;
/// Longest reason an approval shows.
pub const MAX_APPROVAL_REASON: usize = 4096;
/// Most bytes of JSON one `approval.list` answer (or the local `approvals`) holds,
/// well below the 4 MiB message limit; approvals past it are left out and counted.
pub const MAX_APPROVAL_LIST: usize = 3 << 20;

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
    /// The folder a command runs in (commands only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
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
    /// The target or folder is longer than `MAX_APPROVAL_TEXT` and shown cut; such
    /// an approval takes only `deny`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cut: bool,
}

impl ApprovalInfo {
    /// This approval as it is shown and sent: target and folder cut at
    /// `MAX_APPROVAL_TEXT`, each reason at `MAX_APPROVAL_REASON` bytes.
    pub fn shown(&self) -> ApprovalInfo {
        let mut a = self.clone();
        a.target = cut_text(&a.target, MAX_APPROVAL_TEXT);
        a.cwd = a.cwd.map(|c| cut_text(&c, MAX_APPROVAL_TEXT));
        for r in &mut a.reasons {
            *r = cut_text(r, MAX_APPROVAL_REASON);
        }
        a
    }
}

/// `s` cut at a char boundary to at most `max` bytes, with `…` when cut.
fn cut_text(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
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
    /// Approvals left out because the answer would pass `MAX_APPROVAL_LIST`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub left_out: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
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

/// Whether the agent may use the screen, pointer and keyboard
/// (`policy.computer_use.consent`). Set on the device only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Consent {
    /// Every computer-use call is refused.
    #[default]
    Off,
    /// Each chat asks the owner, through the approval path.
    Ask,
    /// Allowed without asking until `until_ms`, then back to `off`.
    Allow,
}

impl Consent {
    pub fn as_str(self) -> &'static str {
        match self {
            Consent::Off => "off",
            Consent::Ask => "ask",
            Consent::Allow => "allow",
        }
    }
}

/// Longest server or tool name `mcp.call` takes, in bytes.
pub const MAX_MCP_NAME: usize = 64;
/// Most bytes of `mcp.call`'s `args`, as JSON.
pub const MAX_MCP_ARGS: usize = 64 * 1024;
/// Most content items of one `mcp.call` result.
pub const MAX_MCP_ITEMS: usize = 16;
/// Most text of one `mcp.call` result, all text items together, in bytes.
pub const MAX_MCP_TEXT: usize = 1024 * 1024;
/// Most base64 characters of one image item.
pub const MAX_MCP_IMAGE: usize = 3 * 1024 * 1024;
/// Most bytes of one `mcp.call` result as JSON: well below the 4 MiB message.
pub const MAX_MCP_RESULT: usize = 3 * 1024 * 1024 + 512 * 1024;
/// The image types `mcp.call` passes on.
pub const MCP_IMAGE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/webp"];

/// `mcp.call`. `ctx` is the context of every other call; its `tool` label must
/// be absent, since no pi tool fits computer use.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCallParams {
    pub server: String,
    pub tool: String,
    /// The tool's arguments; an object, checked against the input schema the
    /// server listed before the server sees it.
    #[serde(default)]
    pub args: serde_json::Map<String, serde_json::Value>,
    pub ctx: Ctx,
}

/// One item of an `mcp.call` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum McpContent {
    Text {
        text: String,
    },
    Image {
        /// One of `MCP_IMAGE_TYPES`.
        mime: String,
        /// Base64 (standard alphabet, padded).
        data: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpCallResult {
    pub content: Vec<McpContent>,
    /// The tool itself reported a failure (MCP's `isError`); `content` says what.
    pub is_error: bool,
}

/// One allowed tool of a server, as `mcp.list` lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolInfo {
    pub name: String,
    pub description: String,
    /// The JSON Schema of `args`, as the server listed it when it was installed.
    pub input_schema: serde_json::Value,
    /// Pointer or keyboard input: the device checks before each call that no
    /// window of Pithagoras Sync is open or focused.
    pub input: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServerInfo {
    pub name: String,
    /// The pinned version installed.
    pub version: String,
    /// `ready`, or `unavailable` (then `error` says why and `tools` is empty).
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub tools: Vec<McpToolInfo>,
}

/// `mcp.list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpListResult {
    /// A hash of `servers`; changes whenever they do.
    pub version: String,
    pub consent: Consent,
    /// When an `allow` consent ends (Unix ms); absent otherwise.
    pub consent_expires_ms: Option<i64>,
    pub servers: Vec<McpServerInfo>,
}

/// `device.info`'s short form of an allowed tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolRef {
    pub server: String,
    pub tool: String,
}

/// Device to portal (`mcp.changed`): what `mcp.list` returns, or the consent,
/// changed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpChanged {
    pub version: String,
    pub consent: Consent,
    pub consent_expires_ms: Option<i64>,
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
    fn chat_ids_are_short_and_printable() {
        let with = |chat: String| json!({"path": "/a", "ctx": {"chat": chat}});
        let ok = "c".repeat(MAX_CHAT_ID);
        assert!(serde_json::from_value::<PathParams>(with(ok.clone())).is_ok());
        assert!(serde_json::from_value::<PathParams>(with(ok + "c")).is_err());
        assert!(serde_json::from_value::<PathParams>(with("c\x1b[2K".into())).is_err());
        assert!(
            serde_json::from_value::<GrantEndParams>(json!({"chat": "c".repeat(300)})).is_err()
        );
    }

    #[test]
    fn mcp_calls_take_an_object_and_nothing_else() {
        let ok = json!({"server": "s", "tool": "t", "args": {"x": 1}, "ctx": {"chat": "c"}});
        let p: McpCallParams = serde_json::from_value(ok.clone()).unwrap();
        assert_eq!(p.args["x"], 1);
        let mut no_args = ok.clone();
        no_args.as_object_mut().unwrap().remove("args");
        assert!(
            serde_json::from_value::<McpCallParams>(no_args)
                .unwrap()
                .args
                .is_empty()
        );
        for bad in [
            json!({"server": "s", "tool": "t", "args": [1], "ctx": {"chat": "c"}}),
            json!({"server": "s", "tool": "t", "args": "x", "ctx": {"chat": "c"}}),
            json!({"server": "s", "tool": "t", "ctx": {"chat": "c", "consent": true}}),
            json!({"server": "s", "tool": "t", "ctx": {"chat": "c"}, "approved": true}),
            json!({"server": "s", "tool": "t"}),
        ] {
            assert!(
                serde_json::from_value::<McpCallParams>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn mcp_content_is_text_or_an_image() {
        let r = McpCallResult {
            content: vec![
                McpContent::Text { text: "hi".into() },
                McpContent::Image {
                    mime: "image/png".into(),
                    data: "AA==".into(),
                },
            ],
            is_error: false,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v,
            json!({"content": [{"type": "text", "text": "hi"}, {"type": "image", "mime": "image/png", "data": "AA=="}], "is_error": false})
        );
        assert_eq!(Consent::default(), Consent::Off);
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
