//! The control channel between the CLI and the running client: one JSON line in,
//! one JSON line out. A Unix socket in the private runtime directory on Linux, a
//! named pipe on Windows.
//!
//! The channel carries no policy: `mode`, `folder` and `config` edit the config file
//! as the owner and then ask for a `reload`. It also carries the owner's answers to
//! approvals and the elevation password (`sudo set`). Commands the client runs for the portal may
//! still ask for `status` or `panic`, nothing else.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sync_connector::LinkStatus;
use sync_policy::secret::Secret;
use sync_policy::{Mode, Profile};
use sync_proto::methods::{ApprovalInfo, Choice, FolderInfo};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// `Debug` shows no secret: `Secret` prints as `<secret>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    Panic,
    Unlock,
    Reload,
    /// The approvals waiting now.
    Approvals,
    /// The owner's answer to approval `id`.
    Answer {
        id: u64,
        answer: Choice,
        #[serde(default)]
        minutes: Option<u32>,
    },
    /// Sets the elevation password (only `elevation` exists).
    SecretSet {
        name: String,
        value: Secret,
    },
    SecretClear {
        name: String,
    },
    /// Exit for the unit (or logon task) to start the client again: after an
    /// update.
    Restart,
    /// Computer use: the servers as the client runs them; with `probe`, each
    /// is started if need be and asked whether it answers.
    McpStatus {
        #[serde(default)]
        probe: bool,
    },
    /// Computer use: `computer-use test` on the running client's server.
    McpTest {
        #[serde(default)]
        verbose: bool,
    },
}

/// Computer use as the running client sees it (`computer-use status`, `test`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct McpReport {
    pub servers: Vec<sync_mcp::service::ServerStatus>,
    #[serde(default)]
    pub in_use: Option<sync_mcp::service::InUse>,
    /// The steps of `computer-use test`.
    #[serde(default)]
    pub test: Vec<sync_mcp::selftest::Step>,
    /// How the last look for new pins went (the daily check or `update`).
    #[serde(default)]
    pub last_update: Option<String>,
}

/// How long the CLI waits for the client's answer.
pub const REPLY_WAIT: Duration = Duration::from_secs(30);
/// How long the client works on one request that reads or writes the keyring,
/// waiting for a `sudo set` before it included: two prompts (an unlock and a
/// confirmation, up to two minutes each for the owner) and the calls around
/// them. Then it gives up, dismisses a prompt still open and answers with an
/// error; prompts left open longer, or one request waiting on another, end
/// that way.
pub const KEYRING_WORK: Duration = Duration::from_secs(300);
/// How long the CLI waits on such a request: longer than the client works on
/// it, so the CLI never reports a failure while the client goes on to store or
/// clear the password.
pub const KEYRING_REPLY_WAIT: Duration = Duration::from_secs(300 + 30);

/// Set (debug builds only) to a shorter time in milliseconds for
/// `KEYRING_WORK`: the tests' wait for it to run out. A release build ignores
/// it, and it never makes the time longer.
pub const TEST_KEYRING_WORK_MS: &str = "PITHAGORAS_SYNC_TEST_KEYRING_WORK_MS";

/// `KEYRING_WORK`, or the tests' shorter time.
pub fn keyring_work() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var(TEST_KEYRING_WORK_MS)
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return Duration::from_millis(ms).min(KEYRING_WORK);
    }
    KEYRING_WORK
}

impl Request {
    /// Whether a command the client itself runs (a descendant) may send this.
    pub fn allowed_from_own_commands(&self) -> bool {
        matches!(self, Request::Status | Request::Panic)
    }

    /// How long the answer may take.
    pub fn reply_wait(&self) -> Duration {
        match self {
            Request::SecretSet { .. } | Request::SecretClear { .. } | Request::Unlock => {
                KEYRING_REPLY_WAIT
            }
            // A server's start, the screenshot and the pointer steps.
            Request::McpTest { .. } | Request::McpStatus { probe: true } => {
                Duration::from_secs(240)
            }
            _ => REPLY_WAIT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub pid: u32,
    pub version: String,
    pub profile: Profile,
    pub portal: Option<String>,
    pub device_id: Option<String>,
    pub name: Option<String>,
    pub link: LinkStatus,
    pub paused: bool,
    pub mode: Mode,
    pub mode_expires_ms: Option<i64>,
    pub folders: Vec<FolderInfo>,
    pub folders_shell: String,
    pub shell: String,
    /// Who answers approvals.
    pub approvals: String,
    /// Approvals waiting now.
    #[serde(default)]
    pub approvals_waiting: usize,
    /// `off`, `read` or `write`.
    #[serde(default)]
    pub portal_policy: String,
    /// `off`, or `sudo` with whether the password is set.
    #[serde(default)]
    pub elevation: String,
    /// Whether the client holds the elevation password now (for `sudo status`).
    #[serde(default)]
    pub elevation_password: bool,
    /// Where the connector token is kept: `file`, `keyring`, or the keyring as
    /// this platform's default.
    #[serde(default)]
    pub token_storage: String,
    pub running_commands: usize,
    pub cgroups: bool,
    pub landlock: bool,
    pub config_file: String,
    pub audit_file: String,
    /// The program the running client was started from: what its unit or logon
    /// task starts again, and so what `update` replaces.
    #[serde(default)]
    pub exe: String,
    /// Computer use in one line: the consent, the servers, who uses the screen.
    #[serde(default)]
    pub computer_use: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvals: Option<Vec<ApprovalInfo>>,
    /// Approvals left out of `approvals` to keep the answer small.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_out: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpReport>,
}

impl Reply {
    pub fn ok() -> Reply {
        Reply {
            ok: true,
            error: None,
            status: None,
            approvals: None,
            left_out: None,
            mcp: None,
        }
    }

    pub fn err(e: impl Into<String>) -> Reply {
        Reply {
            ok: false,
            error: Some(e.into()),
            status: None,
            approvals: None,
            left_out: None,
            mcp: None,
        }
    }
}

const MAX_LINE: usize = 4096;

/// Reads one request line from a connection.
pub async fn read_request<S: AsyncRead + Unpin>(s: S) -> Result<Request, String> {
    let mut line = String::new();
    let mut r = BufReader::new(s).take(MAX_LINE as u64);
    tokio::time::timeout(Duration::from_secs(5), r.read_line(&mut line))
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let req = serde_json::from_str(line.trim()).map_err(|e| format!("bad request: {e}"));
    // The line may have carried the elevation secret.
    wipe(line);
    req
}

fn wipe(s: String) {
    let mut b = s.into_bytes();
    b.fill(0);
}

pub async fn write_reply<S: AsyncWrite + Unpin>(mut s: S, reply: &Reply) {
    let mut text = serde_json::to_string(reply).unwrap_or_default();
    text.push('\n');
    let _ = s.write_all(text.as_bytes()).await;
    let _ = s.flush().await;
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(s: S, req: Request) -> Result<Reply, String> {
    let wait = req.reply_wait();
    let (r, mut w) = tokio::io::split(s);
    let mut text = serde_json::to_string(&req).unwrap_or_default();
    text.push('\n');
    w.write_all(text.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    wipe(text);
    w.flush().await.map_err(|e| e.to_string())?;
    let mut line = String::new();
    // Room for the approvals list (`MAX_APPROVAL_LIST`) and its escapes.
    let mut r = BufReader::new(r).take(4 << 20);
    tokio::time::timeout(wait, r.read_line(&mut line))
        .await
        .map_err(|_| "the client did not answer".to_string())?
        .map_err(|e| e.to_string())?;
    serde_json::from_str(line.trim()).map_err(|e| format!("bad reply: {e}"))
}

/// Sends a request to the running client. `Ok(None)` when no client is running.
pub async fn send(socket: &Path, req: Request) -> Result<Option<Reply>, String> {
    #[cfg(unix)]
    {
        let s = match tokio::net::UnixStream::connect(socket).await {
            Ok(s) => s,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(format!("{}: {e}", socket.display())),
        };
        exchange(s, req).await.map(Some)
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        /// Every instance is taken: the client is busy with other connections.
        const ERROR_PIPE_BUSY: i32 = 231;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let s = loop {
            match ClientOptions::new().open(socket) {
                Ok(s) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => return Err(format!("{}: {e}", socket.display())),
            }
        };
        exchange(s, req).await.map(Some)
    }
}

/// Whether process `pid` is `ancestor` or one of its descendants. Commands the
/// client runs stay its descendants even after `setsid` or double forks, because
/// the exec shim is a child subreaper.
#[cfg(target_os = "linux")]
pub fn descends_from(mut pid: u32, ancestor: u32) -> bool {
    for _ in 0..4096 {
        if pid == ancestor {
            return true;
        }
        if pid <= 1 {
            return false;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        // The command name may hold spaces and parentheses; fields follow the last ')'.
        let Some(after) = stat.rfind(')').map(|i| &stat[i + 1..]) else {
            return false;
        };
        let Some(ppid) = after.split_whitespace().nth(1).and_then(|p| p.parse().ok()) else {
            return false;
        };
        pid = ppid;
    }
    false
}

#[cfg(not(target_os = "linux"))]
pub fn descends_from(_pid: u32, _ancestor: u32) -> bool {
    false
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn finds_ancestors() {
        let me = std::process::id();
        let parent = std::os::unix::process::parent_id();
        assert!(descends_from(me, me));
        assert!(descends_from(me, parent));
        assert!(descends_from(me, 1) || parent == 0);
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        assert!(descends_from(child.id(), me));
        assert!(!descends_from(me, child.id()));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn requests_that_may_wait_on_a_keyring_prompt_get_the_time_for_it() {
        use sync_policy::keyring::secret_service::{CALL, PROMPT};
        let secret = Request::SecretSet {
            name: "elevation".into(),
            value: Secret::new("x".into()),
        };
        let clear = Request::SecretClear {
            name: "elevation".into(),
        };
        // Two prompts (an unlock, then a confirmation), plus the calls around
        // them; and the CLI waits longer than the client works.
        assert!(KEYRING_WORK >= PROMPT * 2 + CALL * 6);
        for r in [secret, clear, Request::Unlock] {
            assert!(r.reply_wait() >= KEYRING_WORK + REPLY_WAIT, "{r:?}");
        }
        assert_eq!(Request::Status.reply_wait(), REPLY_WAIT);
    }

    #[test]
    fn only_status_and_panic_from_own_commands() {
        assert!(Request::Panic.allowed_from_own_commands());
        assert!(!Request::Unlock.allowed_from_own_commands());
        assert!(!Request::Reload.allowed_from_own_commands());
        assert!(!Request::Approvals.allowed_from_own_commands());
        let answer = Request::Answer {
            id: 1,
            answer: Choice::Once,
            minutes: None,
        };
        assert!(!answer.allowed_from_own_commands());
        let secret = Request::SecretSet {
            name: "elevation".into(),
            value: Secret::new("hunter2".into()),
        };
        assert!(!secret.allowed_from_own_commands());
        assert!(!format!("{secret:?}").contains("hunter2"));
        assert!(!Request::Restart.allowed_from_own_commands());
        let r: Request = serde_json::from_str(r#"{"cmd":"panic"}"#).unwrap();
        assert_eq!(r, Request::Panic);
    }
}
