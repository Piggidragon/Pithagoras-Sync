//! One live connection: send `hello`, answer the portal's calls through the policy
//! engine, stream file content and command output, mirror decisions.
//!
//! When the connection ends for any reason, every running command is killed and
//! nothing is resumed: the portal's pending calls fail on its side.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::Value;
use sync_ops::fsops::{self, MAX_WRITE};
use sync_ops::search::{self, GrepOptions};
use sync_ops::{ExecOutcome, info};
use sync_policy::{AnswerError, ApprovalEvent, Call, Event, Permit, Request};
use sync_proto::binary::MAX_CHUNK;
use sync_proto::methods::*;
use sync_proto::{
    BinaryFrame, FrameError, FrameKind, Id, Incoming, RpcError, code, error_without_id,
    notification, parse_incoming, response,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tracing::{debug, warn};

use crate::device::Device;
use crate::net::BoxIo;

/// The client pings this often; the portal answers with a pong.
pub const PING_EVERY: Duration = Duration::from_secs(20);
/// A connection with no frame at all for this long is dead.
pub const DEAD_AFTER: Duration = Duration::from_secs(45);
/// Frames waiting to be written. Full means the portal reads too slowly, and file
/// reads and command output wait (backpressure) instead of piling up in memory.
const OUT_QUEUE: usize = 64;
/// Calls handled at once; more are answered with `BUSY`.
const MAX_CALLS: usize = 64;
/// `fs.write` calls holding their content at once (each up to 64 MiB), from the
/// first frame until the write is done, its approval included.
const MAX_UPLOADS: usize = 4;
/// `fs.read` calls holding a file in memory at once (each up to 64 MiB); more wait.
const MAX_READS: usize = 4;
/// An upload with no frame for this long fails.
const UPLOAD_STALL: Duration = Duration::from_secs(60);
/// Longest preview of new content in an approval prompt.
const PREVIEW: usize = 2000;

#[derive(Debug)]
pub enum End {
    /// The portal closed the connection (close code and reason), or it just ended.
    Closed(Option<u16>, String),
    Paused,
    Shutdown,
    /// No frame for `DEAD_AFTER`.
    Dead,
    Error(String),
}

struct Upload {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    remaining: u64,
}

struct Shared {
    device: Arc<Device>,
    out: mpsc::Sender<Message>,
    uploads: Mutex<HashMap<u32, Upload>>,
    upload_slots: Arc<Semaphore>,
    reads: Arc<Semaphore>,
}

/// A write's content on its way in, and its slot among `MAX_UPLOADS`.
type UploadIn = (
    WriteParams,
    mpsc::UnboundedReceiver<Vec<u8>>,
    Option<OwnedSemaphorePermit>,
);

impl Shared {
    async fn send_text(&self, text: String) {
        let _ = self.out.send(Message::text(text)).await;
    }
}

pub async fn run(
    device: Arc<Device>,
    ws: WebSocketStream<BoxIo>,
    device_id: &str,
    shutdown: &mut watch::Receiver<bool>,
) -> End {
    let (mut sink, mut stream) = ws.split();
    let (out, mut out_rx) = mpsc::channel::<Message>(OUT_QUEUE);
    let secrets = device.secrets.clone();
    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(PING_EVERY);
        ping.tick().await;
        loop {
            tokio::select! {
                m = out_rx.recv() => {
                    let Some(m) = m else { break };
                    // The last stop before the wire: no text the device sends (an
                    // error, a notification, a path) carries the elevation secret.
                    // Command output was scrubbed as it streamed.
                    let m = match m {
                        Message::Text(t) if secrets.is_set() => Message::text(secrets.scrub(t.as_str())),
                        m => m,
                    };
                    let close = matches!(m, Message::Close(_));
                    if sink.send(m).await.is_err() || close {
                        break;
                    }
                }
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Default::default())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = sink.close().await;
    });

    let shared = Arc::new(Shared {
        device: device.clone(),
        out: out.clone(),
        uploads: Mutex::new(HashMap::new()),
        upload_slots: Arc::new(Semaphore::new(MAX_UPLOADS)),
        reads: Arc::new(Semaphore::new(MAX_READS)),
    });
    shared
        .send_text(notification(HELLO, device.hello(device_id)))
        .await;

    let mut tasks = JoinSet::new();
    let mut events = device.engine.subscribe();
    let ev = shared.clone();
    tasks.spawn(async move {
        loop {
            let text = match events.recv().await {
                Ok(Event::Audit(r)) if r.mirrored() => notification(
                    AUDIT,
                    AuditEvent {
                        time_ms: r.time_ms,
                        chat: r.chat,
                        tool: r.tool,
                        target: r.target,
                        cwd: r.cwd,
                        decision: r.decision,
                        reason: r.reason,
                    },
                ),
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            };
            ev.send_text(text).await;
        }
    });

    if let Some(queue) = &device.approvals {
        let mut events = queue.subscribe();
        let ev = shared.clone();
        tasks.spawn(async move {
            loop {
                let text = match events.recv().await {
                    Ok(ApprovalEvent::Requested(info)) => notification(APPROVAL_REQUESTED, info),
                    Ok(ApprovalEvent::Resolved(r)) => notification(APPROVAL_RESOLVED, r),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                };
                ev.send_text(text).await;
            }
        });
    }
    if let Some(cu) = device.computer_use() {
        let mut changed = cu.subscribe();
        let ev = shared.clone();
        tasks.spawn(async move {
            loop {
                let text = match changed.recv().await {
                    Ok(c) => notification(MCP_CHANGED, c),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                };
                ev.send_text(text).await;
            }
        });
    }
    if let Some(store) = &device.store {
        let mut changed = store.subscribe();
        let ev = shared.clone();
        let store = store.clone();
        tasks.spawn(async move {
            loop {
                match changed.recv().await {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => break,
                }
                // Off: the portal hears nothing of the settings.
                if let Ok(doc) = store.document_for_portal() {
                    ev.send_text(notification(POLICY_CHANGED, doc)).await;
                }
            }
        });
    }

    let calls = Arc::new(Semaphore::new(MAX_CALLS));
    let mut paused = device.paused();
    let close = |code: u16, reason: &str| {
        Message::Close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: reason.to_string().into(),
        }))
    };
    let end = loop {
        tokio::select! {
            r = tokio::time::timeout(DEAD_AFTER, stream.next()) => match r {
                Err(_) => break End::Dead,
                Ok(None) => break End::Closed(None, "connection closed".into()),
                Ok(Some(Err(e))) => break End::Error(e.to_string()),
                Ok(Some(Ok(msg))) => match msg {
                    Message::Text(t) => on_text(&shared, &mut tasks, &calls, t.as_str()).await,
                    Message::Binary(b) => on_binary(&shared, &b),
                    Message::Close(f) => {
                        break End::Closed(
                            f.as_ref().map(|f| u16::from(f.code)),
                            f.map(|f| f.reason.to_string()).unwrap_or_default(),
                        )
                    }
                    _ => {}
                },
            },
            _ = crate::until(&mut paused, true) => {
                let _ = out.send(close(1000, "paused on the device")).await;
                break End::Paused;
            }
            _ = crate::until(shutdown, true) => {
                let _ = out.send(close(1001, "the device is shutting down")).await;
                break End::Shutdown;
            }
        }
        while tasks.try_join_next().is_some() {}
    };
    // Waits for the calls to stop, not only asks them to: one inside the
    // synchronous part of `exec.start` finishes that first, and the `kill_all`
    // below then sees its command.
    tasks.shutdown().await;
    shared.uploads.lock().unwrap().clear();
    drop(shared);
    drop(out);
    // No resume: whatever runs now belongs to a connection that is gone.
    device.execs.kill_all().await;
    let mut writer = writer;
    if tokio::time::timeout(Duration::from_secs(2), &mut writer)
        .await
        .is_err()
    {
        writer.abort();
    }
    end
}

async fn on_text(
    shared: &Arc<Shared>,
    tasks: &mut JoinSet<()>,
    calls: &Arc<Semaphore>,
    text: &str,
) {
    let (id, method, params) = match parse_incoming(text) {
        Err(FrameError {
            id: Some(id),
            error,
        }) => {
            return shared.send_text(response(&id, Err(error))).await;
        }
        Err(FrameError { id: None, error }) => {
            return shared.send_text(error_without_id(&error)).await;
        }
        Ok(Incoming::Notification { method, params }) => {
            if method == GRANT_END {
                match serde_json::from_value::<GrantEndParams>(params) {
                    Ok(p) => shared.device.engine.grant_end(&p.chat),
                    Err(e) => warn!("bad grant.end: {e}"),
                }
            } else {
                debug!("ignoring notification {method}");
            }
            return;
        }
        Ok(Incoming::Request { id, method, params }) => (id, method, params),
    };
    let Ok(permit) = calls.clone().try_acquire_owned() else {
        let busy = RpcError::new(code::BUSY, "too many calls at once");
        return shared.send_text(response(&id, Err(busy))).await;
    };
    // The upload frames of `fs.write` follow its request at once, so its stream is
    // registered here, before the next frame is read.
    let upload = if method == FS_WRITE {
        match register_upload(shared, params.clone()) {
            Ok(u) => Some(u),
            Err(e) => return shared.send_text(response(&id, Err(e))).await,
        }
    } else {
        None
    };
    let shared = shared.clone();
    tasks.spawn(async move {
        if method == EXEC_START {
            // Answered inside: the result goes out before the first output frame.
            return exec_start(&shared, &id, params, permit).await;
        }
        let result = dispatch(&shared, &id, &method, params, upload).await;
        drop(permit);
        shared.send_text(response(&id, result)).await;
    });
}

fn parse<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, RpcError> {
    serde_json::from_value(params).map_err(|e| RpcError::new(code::INVALID_PARAMS, e.to_string()))
}

fn to_value(v: impl Serialize) -> Result<Value, RpcError> {
    serde_json::to_value(v).map_err(|e| RpcError::new(code::INTERNAL, e.to_string()))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, RpcError> + Send + 'static,
) -> Result<T, RpcError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| RpcError::new(code::INTERNAL, e.to_string()))?
}

async fn authorize(
    shared: &Shared,
    id: &Id,
    ctx: &Ctx,
    tool: &str,
    req: Request<'_>,
) -> Result<Permit, RpcError> {
    let call = Call {
        id: Some(id),
        chat: &ctx.chat,
        portal_tainted: ctx.tainted,
        tool,
        pi_tool: ctx.tool,
    };
    shared
        .device
        .engine
        .authorize(&call, req)
        .await
        .map_err(RpcError::from)
}

fn register_upload(shared: &Shared, params: Value) -> Result<UploadIn, RpcError> {
    let p: WriteParams = parse(params)?;
    if p.size > MAX_WRITE {
        return Err(RpcError::new(
            code::TOO_LARGE,
            format!("writes are limited to {MAX_WRITE} bytes"),
        ));
    }
    let (tx, rx) = mpsc::unbounded_channel();
    let mut slot = None;
    if p.size > 0 {
        let mut ups = shared.uploads.lock().unwrap();
        if ups.contains_key(&p.stream) {
            return Err(RpcError::new(code::INVALID_PARAMS, "stream already in use"));
        }
        // Held until the write is done: content waiting for an approval counts.
        slot = Some(
            shared
                .upload_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| RpcError::new(code::BUSY, "too many uploads at once"))?,
        );
        ups.insert(
            p.stream,
            Upload {
                tx,
                remaining: p.size,
            },
        );
    }
    Ok((p, rx, slot))
}

fn on_binary(shared: &Shared, data: &[u8]) {
    let f = match BinaryFrame::decode(data) {
        Ok(f) => f,
        Err(e) => return warn!("bad binary frame: {e}"),
    };
    if f.kind != FrameKind::FileUpload {
        return warn!("unexpected binary frame kind {:?}", f.kind);
    }
    let mut ups = shared.uploads.lock().unwrap();
    let Some(u) = ups.get_mut(&f.stream) else {
        return debug!("upload frame for unknown stream {}", f.stream);
    };
    let len = f.payload.len() as u64;
    let over = len > u.remaining;
    u.remaining = u.remaining.saturating_sub(len);
    // The handler counts what it got and fails a write that brought too much.
    let _ = u.tx.send(f.payload);
    if over || u.remaining == 0 {
        ups.remove(&f.stream);
    }
}

async fn dispatch(
    shared: &Arc<Shared>,
    id: &Id,
    method: &str,
    params: Value,
    upload: Option<UploadIn>,
) -> Result<Value, RpcError> {
    match method {
        DEVICE_INFO => {
            parse::<EmptyParams>(params)?;
            to_value(shared.device.info())
        }
        DEVICE_PROBE => {
            let p: ProbeParams = parse(params)?;
            to_value(blocking(move || info::probe(&p.path)).await?)
        }
        FS_STAT => {
            let p: PathParams = parse(params)?;
            let permit = authorize(shared, id, &p.ctx, "stat", Request::Read(&p.path)).await?;
            to_value(blocking(move || fsops::stat(&permit)).await?)
        }
        FS_LIST => {
            let p: PathParams = parse(params)?;
            let permit = authorize(shared, id, &p.ctx, "ls", Request::Read(&p.path)).await?;
            to_value(blocking(move || fsops::list(&permit)).await?)
        }
        FS_READ => {
            let p: ReadParams = parse(params)?;
            let permit = authorize(shared, id, &p.ctx, "read", Request::Read(&p.path)).await?;
            // Until its frames are queued: bounds what reads hold in memory.
            let _slot = shared
                .reads
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| RpcError::new(code::INTERNAL, "closed"))?;
            let (data, sha256) = blocking(move || fsops::read(&permit)).await?;
            let mut chunks = 0u32;
            for c in data.chunks(MAX_CHUNK) {
                let frame = BinaryFrame {
                    kind: FrameKind::FileData,
                    stream: p.stream,
                    seq: chunks,
                    payload: c.to_vec(),
                };
                if shared
                    .out
                    .send(Message::binary(frame.encode()))
                    .await
                    .is_err()
                {
                    return Err(RpcError::new(code::IO, "connection closed"));
                }
                chunks += 1;
            }
            to_value(ReadResult {
                size: data.len() as u64,
                sha256,
                chunks,
            })
        }
        FS_WRITE => {
            let (p, rx, _slot) =
                upload.ok_or_else(|| RpcError::new(code::INTERNAL, "no upload"))?;
            write(shared, id, p, rx).await
        }
        FS_GREP => {
            let p: GrepParams = parse(params)?;
            let permit = authorize(shared, id, &p.ctx, "grep", Request::Read(&p.path)).await?;
            let allowed = shared.device.engine.walk_filter();
            to_value(
                blocking(move || {
                    let opts = GrepOptions {
                        pattern: &p.pattern,
                        glob: p.glob.as_deref(),
                        ignore_case: p.ignore_case,
                        literal: p.literal,
                        context: p.context,
                        limit: p.limit,
                    };
                    search::grep(&permit, &opts, &*allowed)
                })
                .await?,
            )
        }
        FS_FIND => {
            let p: FindParams = parse(params)?;
            let permit = authorize(shared, id, &p.ctx, "find", Request::Read(&p.path)).await?;
            let allowed = shared.device.engine.walk_filter();
            to_value(blocking(move || search::find(&permit, &p.pattern, p.limit, &*allowed)).await?)
        }
        APPROVAL_ANSWER => {
            let queue = shared
                .device
                .approvals
                .as_ref()
                .ok_or_else(|| unknown(method))?;
            let p: ApprovalAnswerParams = parse(params)?;
            queue
                .answer(p.id, p.answer, p.minutes, "portal")
                .map_err(|e| match e {
                    AnswerError::NotFound(_) => RpcError::new(code::NOT_FOUND, e.to_string()),
                    AnswerError::Invalid(_) => RpcError::new(code::INVALID_PARAMS, e.to_string()),
                })?;
            Ok(serde_json::json!({}))
        }
        APPROVAL_LIST => {
            let queue = shared
                .device
                .approvals
                .as_ref()
                .ok_or_else(|| unknown(method))?;
            parse::<EmptyParams>(params)?;
            let (approvals, left_out) = queue.list_within();
            to_value(ApprovalListResult {
                approvals,
                left_out,
            })
        }
        POLICY_GET => {
            let store = shared
                .device
                .store
                .as_ref()
                .ok_or_else(|| unknown(method))?;
            parse::<EmptyParams>(params)?;
            to_value(store.document_for_portal()?)
        }
        POLICY_SET => {
            let store = shared.device.store.clone().ok_or_else(|| unknown(method))?;
            let p: PolicySetParams = parse(params)?;
            to_value(blocking(move || store.set_from_portal(p)).await?)
        }
        MCP_LIST => {
            let cu = shared
                .device
                .computer_use()
                .ok_or_else(|| unknown(method))?;
            parse::<EmptyParams>(params)?;
            to_value(cu.list())
        }
        MCP_CALL => {
            let cu = shared
                .device
                .computer_use()
                .ok_or_else(|| unknown(method))?
                .clone();
            let p: McpCallParams = parse(params)?;
            to_value(cu.call(id, p).await?)
        }
        EXEC_SIGNAL => {
            let p: ExecSignalParams = parse(params)?;
            shared.device.execs.signal(p.stream, p.signal).await?;
            Ok(serde_json::json!({}))
        }
        _ => Err(unknown(method)),
    }
}

fn unknown(method: &str) -> RpcError {
    RpcError::new(code::METHOD_NOT_FOUND, format!("unknown method {method}"))
}

async fn write(
    shared: &Arc<Shared>,
    id: &Id,
    p: WriteParams,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<Value, RpcError> {
    let mut data = Vec::with_capacity(p.size.min(1 << 20) as usize);
    while (data.len() as u64) < p.size {
        match tokio::time::timeout(UPLOAD_STALL, rx.recv()).await {
            Ok(Some(c)) => data.extend_from_slice(&c),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    shared.uploads.lock().unwrap().remove(&p.stream);
    while let Ok(c) = rx.try_recv() {
        data.extend_from_slice(&c);
    }
    if data.len() as u64 > p.size {
        return Err(RpcError::new(
            code::TOO_LARGE,
            "more data than the write announced",
        ));
    }
    if (data.len() as u64) < p.size {
        return Err(RpcError::new(code::IO, "the upload stopped before its end"));
    }
    // Content is collected before asking, so a long approval never holds up the
    // connection's reading.
    let permit = authorize(
        shared,
        id,
        &p.ctx,
        "write",
        Request::Write {
            path: &p.path,
            preview: Some(preview(&data)),
        },
    )
    .await?;
    to_value(
        blocking(move || fsops::write(&permit, &data, p.if_match.as_deref(), p.create_dirs))
            .await?,
    )
}

/// The start of new content for an approval prompt.
fn preview(data: &[u8]) -> String {
    match std::str::from_utf8(data) {
        Ok(s) if s.len() <= PREVIEW => s.to_string(),
        Ok(s) => {
            let mut end = PREVIEW;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}\n… ({} bytes in all)", &s[..end], data.len())
        }
        Err(_) => format!("(binary content, {} bytes)", data.len()),
    }
}

async fn exec_start(
    shared: &Arc<Shared>,
    id: &Id,
    params: Value,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let started = async {
        let p: ExecStartParams = parse(params)?;
        if p.command.len() > MAX_COMMAND {
            return Err(RpcError::new(
                code::TOO_LARGE,
                format!(
                    "commands are limited to {MAX_COMMAND} bytes; run a longer script from a file"
                ),
            ));
        }
        let allowed = authorize(
            shared,
            id,
            &p.ctx,
            "exec",
            Request::Exec {
                command: &p.command,
                cwd: &p.cwd,
            },
        )
        .await?;
        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let started = shared.device.execs.start(
            p.stream,
            &p.command,
            &allowed,
            p.timeout_ms.map(Duration::from_millis),
            tx,
        )?;
        Ok::<_, RpcError>((p, started, rx))
    }
    .await;
    drop(permit);
    let (p, started, mut rx) = match started {
        Ok(s) => s,
        Err(e) => return shared.send_text(response(id, Err(e))).await,
    };
    shared
        .send_text(response(id, Ok(serde_json::json!({}))))
        .await;
    // Detached on purpose: the command's end is audited even when the connection
    // dropped meanwhile (the session kills it then).
    let out = shared.out.clone();
    let engine = shared.device.engine.clone();
    tokio::spawn(async move {
        let mut seq = 0u32;
        let mut outcome = started.outcome;
        let send = |seq: u32, payload: Vec<u8>| {
            Message::binary(
                BinaryFrame {
                    kind: FrameKind::ExecOutput,
                    stream: p.stream,
                    seq,
                    payload,
                }
                .encode(),
            )
        };
        let result = loop {
            tokio::select! {
                biased;
                c = rx.recv() => match c {
                    Some(c) => {
                        let _ = out.send(send(seq, c)).await;
                        seq += 1;
                    }
                    None => break (&mut outcome).await,
                },
                o = &mut outcome => {
                    while let Ok(c) = rx.try_recv() {
                        let _ = out.send(send(seq, c)).await;
                        seq += 1;
                    }
                    break o;
                }
            }
        };
        // Output of background processes after the shell's exit is not forwarded;
        // closing the channel lets them see a broken pipe.
        drop(rx);
        let o = result.unwrap_or_else(|_| ExecOutcome {
            signal: Some("SIGKILL".into()),
            ..ExecOutcome::default()
        });
        let exit = ExecExit {
            stream: p.stream,
            code: o.code,
            signal: o.signal.clone(),
            timed_out: o.timed_out,
            truncated: o.truncated,
        };
        let _ = out.send(Message::text(notification(EXEC_EXIT, exit))).await;
        let detail = o
            .error
            .clone()
            .or_else(|| o.signal.clone().map(|s| format!("killed by {s}")))
            .or_else(|| o.timed_out.then(|| "timed out".to_string()));
        engine.record_exit(
            Some(&p.ctx.chat),
            "exit",
            &p.command,
            "exited",
            detail,
            o.code,
        );
    });
}
