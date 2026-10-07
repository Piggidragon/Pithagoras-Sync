//! The MCP client: JSON-RPC 2.0, one message per line, over the server's stdin
//! and stdout. By hand rather than a library, because the device needs only a
//! handful of messages and wants every one of them bounded: `initialize`, the
//! `notifications/initialized` notification, `tools/list` (with its pages)
//! and `tools/call`.
//!
//! One request is outstanding at a time (the caller holds the client behind a
//! lock, so calls queue). The parser is strict in what it acts on: only the
//! answer to the request in flight counts; answers to ids never sent are
//! dropped, notifications are logged and dropped, and a request from the
//! server (`sampling/createMessage`, `roots/list`, `elicitation/create`, ...)
//! is answered with an error and never served. A line over the limit, too
//! much output for one call, too many lines that are not JSON, a hang past the
//! timeout or the server's end all stop the server; the caller starts it again
//! with backoff.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// The MCP versions this client speaks; it asks for the first.
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

#[derive(Debug, Clone)]
pub struct Limits {
    /// Longest line the server may write.
    pub max_line: usize,
    /// Most bytes the server may write while one request is in flight.
    pub max_output: usize,
    /// Most lines that are not JSON-RPC while one request is in flight.
    pub max_garbage: usize,
    /// How long the server has to start and answer `initialize`.
    pub startup: Duration,
    /// How long one call may take.
    pub call: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_line: 8 << 20,
            max_output: 16 << 20,
            max_garbage: 32,
            startup: Duration::from_secs(30),
            call: Duration::from_secs(60),
        }
    }
}

/// How to start a server.
#[derive(Debug, Clone)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The whole environment: nothing else of the client's passes.
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    /// Where the server's stderr goes (bounded); none: dropped.
    pub log: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The server did not start or did not finish the handshake.
    Start(String),
    /// The server ended.
    Crashed(String),
    /// No answer in time; the server was stopped.
    Timeout,
    /// The server broke the protocol or a limit; it was stopped.
    BadAnswer(String),
    /// A JSON-RPC error answer to the request.
    Rpc(String),
    /// The device stopped it (`panic`, the client's end).
    Stopped,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Start(m) => write!(f, "the server did not start: {m}"),
            ClientError::Crashed(m) => write!(f, "the server ended: {m}"),
            ClientError::Timeout => write!(f, "the server did not answer in time"),
            ClientError::BadAnswer(m) => write!(f, "the server's answer was refused: {m}"),
            ClientError::Rpc(m) => write!(f, "the server answered with an error: {m}"),
            ClientError::Stopped => write!(f, "the device stopped the server"),
        }
    }
}

/// What the reader hands over, line by line.
enum Line {
    Message(Map<String, Value>, usize),
    Garbage(usize),
    TooLong,
    Closed,
}

/// One tool as the server lists it.
#[derive(Debug, Clone, PartialEq)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

pub struct Client {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<Line>,
    next_id: i64,
    limits: Limits,
    dead: Option<String>,
    /// Changes when the device stops every server (`panic`): a request in
    /// flight ends at once.
    stop: tokio::sync::watch::Receiver<u64>,
    #[cfg(windows)]
    _job: sync_ops::Job,
}

impl Client {
    /// Starts the server and does the handshake within `limits.startup`.
    pub async fn start(launch: &Launch, limits: Limits) -> Result<Client, ClientError> {
        let (_keep, stop) = tokio::sync::watch::channel(0);
        Client::start_with(launch, limits, stop).await
    }

    /// `start`, ending every request when `stop` changes.
    pub async fn start_with(
        launch: &Launch,
        limits: Limits,
        mut stop: tokio::sync::watch::Receiver<u64>,
    ) -> Result<Client, ClientError> {
        stop.mark_unchanged();
        let mut c = crate::proc::spawn(launch)
            .await
            .map_err(ClientError::Start)?;
        let stdout = c
            .child
            .stdout
            .take()
            .ok_or(ClientError::Start("no stdout".into()))?;
        let stdin = c
            .child
            .stdin
            .take()
            .ok_or(ClientError::Start("no stdin".into()))?;
        if let Some(stderr) = c.child.stderr.take() {
            tokio::spawn(crate::proc::log_stderr(stderr, launch.log.clone()));
        }
        let (tx, lines) = mpsc::channel(64);
        tokio::spawn(read_lines(stdout, tx, limits.max_line));
        let mut client = Client {
            child: c.child,
            stdin,
            lines,
            next_id: 0,
            limits: limits.clone(),
            dead: None,
            stop,
            #[cfg(windows)]
            _job: c.job,
        };
        let params = json!({
            "protocolVersion": PROTOCOL_VERSIONS[0],
            "capabilities": {},
            "clientInfo": {"name": "pithagoras-sync", "version": env!("CARGO_PKG_VERSION")},
        });
        let result = match client.request("initialize", params, limits.startup).await {
            Ok(r) => r,
            Err(ClientError::Timeout) => {
                return Err(ClientError::Start(format!(
                    "no answer to initialize within {}s",
                    limits.startup.as_secs()
                )));
            }
            Err(e) => {
                client.kill().await;
                return Err(ClientError::Start(e.to_string()));
            }
        };
        let version = result.get("protocolVersion").and_then(Value::as_str);
        if !version.is_some_and(|v| PROTOCOL_VERSIONS.contains(&v)) {
            client.kill().await;
            return Err(ClientError::Start(format!(
                "it speaks MCP version {}, not one of {}",
                version.unwrap_or("(none)"),
                PROTOCOL_VERSIONS.join(", ")
            )));
        }
        client
            .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await?;
        Ok(client)
    }

    /// Whether the server ended or was stopped.
    pub fn is_dead(&mut self) -> bool {
        if self.dead.is_none()
            && let Ok(Some(st)) = self.child.try_wait()
        {
            self.dead = Some(format!("exited ({st})"));
        }
        self.dead.is_some()
    }

    /// Stops the server and everything it started.
    pub async fn kill(&mut self) {
        if self.dead.is_none() {
            self.dead = Some("stopped".into());
        }
        crate::proc::kill_tree(&mut self.child).await;
        #[cfg(windows)]
        self._job.terminate();
    }

    async fn send(&mut self, msg: &Value) -> Result<(), ClientError> {
        let mut line = msg.to_string();
        line.push('\n');
        if let Err(e) = self.stdin.write_all(line.as_bytes()).await {
            self.kill().await;
            return Err(ClientError::Crashed(format!("cannot write to it: {e}")));
        }
        let _ = self.stdin.flush().await;
        Ok(())
    }

    /// What came in between requests: requests are refused, the rest dropped.
    async fn drain(&mut self) -> Result<(), ClientError> {
        while let Ok(line) = self.lines.try_recv() {
            match line {
                Line::Message(m, _) => self.unsolicited(m).await?,
                Line::Garbage(_) => debug!("the MCP server wrote a line that is not JSON-RPC"),
                Line::TooLong => return self.broken("a line over the limit").await,
                Line::Closed => {
                    self.dead = Some("closed its output".into());
                    return Err(ClientError::Crashed("closed its output".into()));
                }
            }
        }
        Ok(())
    }

    async fn broken<T>(&mut self, why: &str) -> Result<T, ClientError> {
        self.kill().await;
        Err(ClientError::BadAnswer(why.into()))
    }

    /// A message that is not the answer awaited.
    async fn unsolicited(&mut self, m: Map<String, Value>) -> Result<(), ClientError> {
        let method = m.get("method").and_then(Value::as_str).map(clip);
        match (method, m.get("id")) {
            (Some(method), Some(id)) => {
                // The device serves nothing to the server: no sampling, no
                // roots, no elicitation.
                warn!("the MCP server asked for {method}; refused");
                let answer = json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": -32601, "message": "pithagoras-sync serves no requests to MCP servers"}
                });
                self.send(&answer).await
            }
            (Some(method), None) => {
                debug!("MCP notification {method} dropped");
                Ok(())
            }
            (None, _) => {
                debug!("an MCP answer to no request in flight dropped");
                Ok(())
            }
        }
    }

    /// One request and its answer's `result`.
    pub async fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, ClientError> {
        if self.is_dead() {
            return Err(ClientError::Crashed(self.dead.clone().unwrap_or_default()));
        }
        self.drain().await?;
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await?;
        let deadline = tokio::time::Instant::now() + timeout;
        let (mut bytes, mut garbage) = (0usize, 0usize);
        loop {
            let next = tokio::select! {
                l = tokio::time::timeout_at(deadline, self.lines.recv()) => l,
                // A dropped sender (a client started without one) never stops it.
                Ok(()) = self.stop.changed() => {
                    self.kill().await;
                    return Err(ClientError::Stopped);
                }
            };
            let line = match next {
                Err(_) => {
                    self.kill().await;
                    return Err(ClientError::Timeout);
                }
                Ok(None) | Ok(Some(Line::Closed)) => {
                    let st = tokio::time::timeout(Duration::from_secs(2), self.child.wait())
                        .await
                        .ok()
                        .and_then(Result::ok);
                    let why = match st {
                        Some(st) => format!("exited ({st}) during {method}"),
                        None => format!("closed its output during {method}"),
                    };
                    self.kill().await;
                    self.dead = Some(why.clone());
                    return Err(ClientError::Crashed(why));
                }
                Ok(Some(l)) => l,
            };
            let n = match &line {
                Line::Message(_, n) | Line::Garbage(n) => *n,
                _ => 0,
            };
            bytes += n;
            if bytes > self.limits.max_output {
                return self.broken("more output than one call may give").await;
            }
            match line {
                Line::TooLong => return self.broken("a line over the limit").await,
                Line::Garbage(_) => {
                    garbage += 1;
                    if garbage > self.limits.max_garbage {
                        return self.broken("too many lines that are not JSON-RPC").await;
                    }
                }
                Line::Closed => unreachable!(),
                Line::Message(m, _) => {
                    let ours = !m.contains_key("method") && m.get("id") == Some(&json!(id));
                    if !ours {
                        self.unsolicited(m).await?;
                        continue;
                    }
                    if m.get("jsonrpc") != Some(&json!("2.0")) {
                        return self.broken("an answer without jsonrpc 2.0").await;
                    }
                    if let Some(e) = m.get("error") {
                        let msg = e
                            .get("message")
                            .and_then(Value::as_str)
                            .map(clip)
                            .unwrap_or_else(|| "(no message)".into());
                        return Err(ClientError::Rpc(msg));
                    }
                    return match m.get("result") {
                        Some(r @ Value::Object(_)) => Ok(r.clone()),
                        _ => self.broken("an answer without a result object").await,
                    };
                }
            }
        }
    }

    /// Every tool the server lists, page by page (at most 100 pages, 1000
    /// tools).
    pub async fn list_tools(&mut self) -> Result<Vec<Tool>, ClientError> {
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..100 {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let r = self.request("tools/list", params, self.limits.call).await?;
            let Some(list) = r.get("tools").and_then(Value::as_array) else {
                return self.broken("tools/list without tools").await;
            };
            for t in list {
                let Some(name) = t.get("name").and_then(Value::as_str) else {
                    return self.broken("a tool without a name").await;
                };
                let schema = t
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or(json!({"type": "object"}));
                tools.push(Tool {
                    name: name.to_string(),
                    description: t
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    input_schema: schema,
                });
            }
            if tools.len() > 1000 {
                return self.broken("more than 1000 tools").await;
            }
            match r.get("nextCursor") {
                Some(Value::String(c)) if !c.is_empty() => cursor = Some(c.clone()),
                _ => return Ok(tools),
            }
        }
        self.broken("more than 100 pages of tools").await
    }

    /// `tools/call`; the raw result, checked later against the protocol's
    /// limits.
    pub async fn call(
        &mut self,
        name: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, ClientError> {
        self.request(
            "tools/call",
            json!({"name": name, "arguments": args}),
            self.limits.call,
        )
        .await
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        crate::proc::kill_now(&mut self.child);
    }
}

/// A server's text, as far as a log line should hold it.
fn clip(s: &str) -> String {
    let s: String = s.chars().take(200).collect();
    sync_policy::approve::visible(&s)
}

async fn read_lines(stdout: tokio::process::ChildStdout, tx: mpsc::Sender<Line>, max_line: usize) {
    let mut r = BufReader::new(stdout);
    loop {
        let mut buf = Vec::new();
        // One byte over the limit tells a long line from one at the limit.
        // A read error ends the server's output as its end does.
        let n = (&mut r)
            .take(max_line as u64 + 1)
            .read_until(b'\n', &mut buf)
            .await
            .unwrap_or_default();
        if n == 0 {
            let _ = tx.send(Line::Closed).await;
            return;
        }
        if !buf.ends_with(b"\n") && buf.len() > max_line {
            let _ = tx.send(Line::TooLong).await;
            return;
        }
        let text = buf.trim_ascii();
        if text.is_empty() {
            continue;
        }
        let line = match serde_json::from_slice::<Value>(text) {
            Ok(Value::Object(m)) => Line::Message(m, n),
            _ => Line::Garbage(n),
        };
        if tx.send(line).await.is_err() {
            return;
        }
    }
}
