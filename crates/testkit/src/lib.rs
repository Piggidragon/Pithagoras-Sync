//! A mock portal for tests: the pairing endpoint and the WebSocket endpoint of
//! `docs/protocol.md`, over plain HTTP on loopback or TLS with a self-signed
//! certificate. Tests drive the device through `DeviceLink` as the portal would.
//!
//! It implements only what the protocol document says; it is not a model of the
//! real portal's behaviour beyond that.

#[cfg(unix)]
pub mod keyring;

/// The release signer, under the name the tests know it by: tests sign their
/// releases with throwaway keys the same way a real release is signed.
pub mod minisign {
    pub use sync_release::minisign::SigningKey as TestKey;
}

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use rcgen::PublicKeyData;
use serde_json::{Value, json};
use sync_proto::methods::PairRequest;
use sync_proto::{BinaryFrame, FrameKind, RpcError, binary::MAX_CHUNK, code};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role};

#[derive(Default)]
pub struct MockOptions {
    pub tls: bool,
    /// One-time pairing codes the portal accepts.
    pub codes: Vec<String>,
}

pub struct MockPortal {
    pub url: String,
    /// The pin of the TLS certificate (base64url sha256 of its SPKI).
    pub spki: Option<String>,
    /// The TLS certificate in DER.
    pub cert_der: Option<Vec<u8>>,
    state: Arc<State>,
    devices: tokio::sync::Mutex<mpsc::UnboundedReceiver<DeviceLink>>,
    task: tokio::task::JoinHandle<()>,
}

struct State {
    codes: Mutex<Vec<String>>,
    /// token -> device id
    tokens: Mutex<HashMap<String, String>>,
    /// device id -> its connection's outgoing queue
    live: Mutex<HashMap<String, mpsc::Sender<Message>>>,
    refused: AtomicUsize,
    pairs: Mutex<Vec<PairRequest>>,
    devices: mpsc::UnboundedSender<DeviceLink>,
    next: AtomicUsize,
    /// Set: the next pairing keeps this device id (`pair_next_as`).
    same_device: Mutex<Option<String>>,
    /// Every byte devices sent: request heads and bodies, and each message.
    transcript: Mutex<Vec<u8>>,
}

impl State {
    fn record(&self, data: &[u8]) {
        let mut t = self.transcript.lock().unwrap();
        t.extend_from_slice(data);
        t.push(b'\n');
    }
}

fn random_token() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut b).unwrap();
    URL_SAFE_NO_PAD.encode(b)
}

impl Drop for MockPortal {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockPortal {
    pub async fn start(opts: MockOptions) -> MockPortal {
        MockPortal::start_on(opts, 0).await
    }

    /// On a fixed loopback port (0: any free one).
    pub async fn start_on(opts: MockOptions, port: u16) -> MockPortal {
        MockPortal::start_with(opts, port, false).await
    }

    /// With TLS (`opts.tls`) whose self-signed certificate says it is a CA, as
    /// `openssl req -x509` makes it by default.
    pub async fn start_with_ca_certificate(opts: MockOptions) -> MockPortal {
        MockPortal::start_with(opts, 0, true).await
    }

    async fn start_with(opts: MockOptions, port: u16, ca: bool) -> MockPortal {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let state = Arc::new(State {
            codes: Mutex::new(opts.codes),
            tokens: Mutex::new(HashMap::new()),
            live: Mutex::new(HashMap::new()),
            refused: AtomicUsize::new(0),
            pairs: Mutex::new(Vec::new()),
            devices: tx,
            next: AtomicUsize::new(1),
            same_device: Mutex::new(None),
            transcript: Mutex::new(Vec::new()),
        });
        let (acceptor, spki, cert_der) = if opts.tls {
            let names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
            let ck = if ca {
                let mut params = rcgen::CertificateParams::new(names).unwrap();
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                let signing_key = rcgen::KeyPair::generate().unwrap();
                let cert = params.self_signed(&signing_key).unwrap();
                rcgen::CertifiedKey { cert, signing_key }
            } else {
                rcgen::generate_simple_self_signed(names).unwrap()
            };
            let spki = URL_SAFE_NO_PAD.encode(ring::digest::digest(
                &ring::digest::SHA256,
                &ck.signing_key.subject_public_key_info(),
            ));
            let cert_der = ck.cert.der().to_vec();
            let key =
                rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![ck.cert.der().clone()], key)
            .unwrap();
            (
                Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))),
                Some(spki),
                Some(cert_der),
            )
        } else {
            (None, None, None)
        };
        let st = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let st = st.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(a) => {
                            if let Ok(tls) = a.accept(tcp).await {
                                serve(st, tls).await;
                            }
                        }
                        None => serve(st, tcp).await,
                    }
                });
            }
        });
        let scheme = if opts.tls { "https" } else { "http" };
        MockPortal {
            url: format!("{scheme}://127.0.0.1:{}", addr.port()),
            spki,
            cert_der,
            state,
            devices: tokio::sync::Mutex::new(rx),
            task,
        }
    }

    /// The pairing URI the portal would show for `code`.
    pub fn pair_uri(&self, code: &str) -> String {
        let portal: String = self
            .url
            .bytes()
            .map(|b| match b {
                b':' => "%3A".to_string(),
                b'/' => "%2F".to_string(),
                b => (b as char).to_string(),
            })
            .collect();
        let mut s = format!("pithagoras-sync://pair?portal={portal}&code={code}");
        if let Some(p) = &self.spki {
            s.push_str(&format!("&spki={p}"));
        }
        s
    }

    pub fn add_code(&self, code: &str) {
        self.state.codes.lock().unwrap().push(code.into());
    }

    /// The next pairing gives the device `device_id` again, with a new token,
    /// as a portal that pairs a device it knows may. Its old token keeps
    /// working.
    pub fn pair_next_as(&self, device_id: &str) {
        *self.state.same_device.lock().unwrap() = Some(device_id.into());
    }

    /// Lets `token` connect as `device_id` without pairing.
    pub fn add_token(&self, token: &str, device_id: &str) {
        self.state
            .tokens
            .lock()
            .unwrap()
            .insert(token.into(), device_id.into());
    }

    /// "Remove device": its tokens stop working and a live connection is closed
    /// with 4001.
    pub async fn revoke(&self, device_id: &str) {
        self.state
            .tokens
            .lock()
            .unwrap()
            .retain(|_, d| d != device_id);
        let live = self.state.live.lock().unwrap().remove(device_id);
        if let Some(out) = live {
            let _ = out.send(close(4001, "device removed")).await;
        }
    }

    /// The next device that connected and sent `hello`.
    pub async fn next_device(&self, timeout: Duration) -> Option<DeviceLink> {
        let mut rx = self.devices.lock().await;
        tokio::time::timeout(timeout, rx.recv())
            .await
            .ok()
            .flatten()
    }

    /// Upgrades refused with 401.
    pub fn refused(&self) -> usize {
        self.state.refused.load(Ordering::SeqCst)
    }

    pub fn pairs(&self) -> Vec<PairRequest> {
        self.state.pairs.lock().unwrap().clone()
    }

    /// Everything any device sent to this portal so far, as received.
    pub fn transcript(&self) -> Vec<u8> {
        self.state.transcript.lock().unwrap().clone()
    }
}

fn close(code: u16, reason: &str) -> Message {
    Message::Close(Some(CloseFrame {
        code: CloseCode::from(code),
        reason: reason.to_string().into(),
    }))
}

struct Head {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    rest: Vec<u8>,
}

async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> Option<Head> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = io.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(len) = req.parse(&buf).ok()? {
            return Some(Head {
                method: req.method?.to_string(),
                path: req.path?.to_string(),
                headers: req
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_ascii_lowercase(),
                            String::from_utf8_lossy(h.value).into_owned(),
                        )
                    })
                    .collect(),
                rest: buf[len..].to_vec(),
            });
        }
        if buf.len() > 65536 {
            return None;
        }
    }
}

async fn respond<S: AsyncWrite + Unpin>(io: &mut S, status: &str, body: &Value) {
    let body = body.to_string();
    let text = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = io.write_all(text.as_bytes()).await;
    let _ = io.flush().await;
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(st: Arc<State>, mut io: S) {
    let Some(head) = read_head(&mut io).await else {
        return;
    };
    st.record(format!("{} {} {:?}", head.method, head.path, head.headers).as_bytes());
    match (head.method.as_str(), head.path.as_str()) {
        ("POST", sync_proto::PAIR_PATH) => pair(st, io, head).await,
        ("GET", sync_proto::CONNECT_PATH) => upgrade(st, io, head).await,
        _ => respond(&mut io, "404 Not Found", &json!({"error": "not found"})).await,
    }
}

async fn pair<S: AsyncRead + AsyncWrite + Unpin>(st: Arc<State>, mut io: S, head: Head) {
    let len: usize = head
        .headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = head.rest;
    let mut chunk = [0u8; 4096];
    while body.len() < len {
        match io.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    st.record(&body);
    let Ok(req) = serde_json::from_slice::<PairRequest>(&body) else {
        return respond(&mut io, "400 Bad Request", &json!({"error": "bad body"})).await;
    };
    let ok = {
        let mut codes = st.codes.lock().unwrap();
        match codes.iter().position(|c| *c == req.code) {
            Some(i) => {
                codes.remove(i);
                true
            }
            None => false,
        }
    };
    st.pairs.lock().unwrap().push(req);
    if !ok {
        return respond(
            &mut io,
            "403 Forbidden",
            &json!({"error": "unknown or expired code"}),
        )
        .await;
    }
    let same = st.same_device.lock().unwrap().take();
    let device_id =
        same.unwrap_or_else(|| format!("dev-{}", st.next.fetch_add(1, Ordering::SeqCst)));
    let token = random_token();
    st.tokens
        .lock()
        .unwrap()
        .insert(token.clone(), device_id.clone());
    respond(
        &mut io,
        "200 OK",
        &json!({"device_id": device_id, "connector_token": token, "overlay_token": random_token()}),
    )
    .await;
}

async fn upgrade<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    st: Arc<State>,
    mut io: S,
    head: Head,
) {
    let token = head
        .headers
        .get("authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let device_id = st.tokens.lock().unwrap().get(token).cloned();
    let Some(device_id) = device_id else {
        st.refused.fetch_add(1, Ordering::SeqCst);
        return respond(&mut io, "401 Unauthorized", &json!({"error": "bad token"})).await;
    };
    if st.live.lock().unwrap().contains_key(&device_id) {
        return respond(
            &mut io,
            "409 Conflict",
            &json!({"error": "already connected"}),
        )
        .await;
    }
    let Some(key) = head.headers.get("sec-websocket-key") else {
        return respond(&mut io, "400 Bad Request", &json!({"error": "no key"})).await;
    };
    let accept = derive_accept_key(key.as_bytes());
    let text = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    if io.write_all(text.as_bytes()).await.is_err() {
        return;
    }
    let ws = WebSocketStream::from_raw_socket(io, Role::Server, None).await;
    link(st, ws, device_id).await;
}

type Pending = Arc<Mutex<HashMap<i64, oneshot::Sender<Result<Value, RpcError>>>>>;
type Notes = Arc<(Mutex<Vec<(String, Value)>>, Notify)>;

/// The portal's side of one device connection.
pub struct DeviceLink {
    pub device_id: String,
    /// The device's `hello` params.
    pub hello: Value,
    out: mpsc::Sender<Message>,
    pending: Pending,
    frames: Arc<Mutex<HashMap<u32, Vec<BinaryFrame>>>>,
    notes: Notes,
    closed: watch::Receiver<Option<(u16, String)>>,
    next_id: AtomicI64,
}

async fn link<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    st: Arc<State>,
    ws: WebSocketStream<S>,
    device_id: String,
) {
    let (mut sink, mut stream) = ws.split();
    let (out, mut out_rx) = mpsc::channel::<Message>(64);
    tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            let close = matches!(m, Message::Close(_));
            if sink.send(m).await.is_err() || close {
                break;
            }
        }
        let _ = sink.close().await;
    });
    // The first frame must be `hello`.
    let hello = match tokio::time::timeout(Duration::from_secs(10), stream.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => {
            st.record(t.as_bytes());
            let v: Value = serde_json::from_str(t.as_str()).unwrap_or(Value::Null);
            if v["method"] != "hello" {
                let _ = out.send(close(1008, "hello expected")).await;
                return;
            }
            v["params"].clone()
        }
        _ => return,
    };
    st.live
        .lock()
        .unwrap()
        .insert(device_id.clone(), out.clone());
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let frames = Arc::new(Mutex::new(HashMap::new()));
    let notes: Notes = Arc::new((Mutex::new(Vec::new()), Notify::new()));
    let (closed_tx, closed) = watch::channel(None);
    let dl = DeviceLink {
        device_id: device_id.clone(),
        hello,
        out: out.clone(),
        pending: pending.clone(),
        frames: frames.clone(),
        notes: notes.clone(),
        closed,
        next_id: AtomicI64::new(1),
    };
    let _ = st.devices.send(dl);
    tokio::spawn(async move {
        let mut why = (1006u16, String::from("connection lost"));
        while let Some(Ok(m)) = stream.next().await {
            match &m {
                Message::Text(t) => st.record(t.as_bytes()),
                Message::Binary(b) => st.record(b),
                Message::Close(Some(f)) => st.record(f.reason.as_bytes()),
                _ => {}
            }
            match m {
                Message::Text(t) => {
                    let v: Value = serde_json::from_str(t.as_str()).unwrap_or(Value::Null);
                    if let Some(method) = v.get("method").and_then(|m| m.as_str()) {
                        notes
                            .0
                            .lock()
                            .unwrap()
                            .push((method.to_string(), v["params"].clone()));
                        notes.1.notify_waiters();
                        continue;
                    }
                    let waiter = v["id"]
                        .as_i64()
                        .and_then(|id| pending.lock().unwrap().remove(&id));
                    match waiter {
                        Some(w) => {
                            let r = match v.get("error") {
                                Some(e) => {
                                    Err(serde_json::from_value(e.clone()).unwrap_or_else(|_| {
                                        RpcError::new(code::INTERNAL, "unreadable error")
                                    }))
                                }
                                None => Ok(v["result"].clone()),
                            };
                            let _ = w.send(r);
                        }
                        None => {
                            notes.0.lock().unwrap().push(("<response>".into(), v));
                            notes.1.notify_waiters();
                        }
                    }
                }
                Message::Binary(b) => {
                    if let Ok(f) = BinaryFrame::decode(&b) {
                        frames.lock().unwrap().entry(f.stream).or_default().push(f);
                    }
                }
                Message::Close(f) => {
                    if let Some(f) = f {
                        why = (u16::from(f.code), f.reason.to_string());
                    }
                    break;
                }
                _ => {}
            }
        }
        st.live.lock().unwrap().remove(&device_id);
        pending.lock().unwrap().clear();
        let _ = closed_tx.send(Some(why));
        notes.1.notify_waiters();
    });
}

impl DeviceLink {
    /// Calls a method on the device and waits for its answer (30 s at most).
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let rx = self.start_call(method, params).await;
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(RpcError::new(code::INTERNAL, "connection closed")),
            Err(_) => Err(RpcError::new(code::INTERNAL, "no answer within 30 s")),
        }
    }

    /// Starts a call without waiting; the answer goes to the returned receiver.
    pub async fn start_call(
        &self,
        method: &str,
        params: Value,
    ) -> oneshot::Receiver<Result<Value, RpcError>> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let text = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.send_text(text.to_string()).await;
        rx
    }

    pub async fn notify(&self, method: &str, params: Value) {
        let text = json!({"jsonrpc": "2.0", "method": method, "params": params});
        self.send_text(text.to_string()).await;
    }

    pub async fn send_text(&self, text: String) {
        let _ = self.out.send(Message::text(text)).await;
    }

    pub async fn send_binary(&self, data: Vec<u8>) {
        let _ = self.out.send(Message::binary(data)).await;
    }

    /// Sends `data` as the `FileUpload` frames of `stream`.
    pub async fn upload(&self, stream: u32, data: &[u8]) {
        for (seq, c) in data.chunks(MAX_CHUNK).enumerate() {
            let f = BinaryFrame {
                kind: FrameKind::FileUpload,
                stream,
                seq: seq as u32,
                payload: c.to_vec(),
            };
            self.send_binary(f.encode()).await;
        }
    }

    /// `fs.write` as the portal does it: the request, then the upload frames.
    pub async fn write(
        &self,
        stream: u32,
        mut params: Value,
        data: &[u8],
    ) -> Result<Value, RpcError> {
        params["stream"] = json!(stream);
        params["size"] = json!(data.len());
        let rx = self.start_call("fs.write", params).await;
        self.upload(stream, data).await;
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(r)) => r,
            _ => Err(RpcError::new(code::INTERNAL, "no answer")),
        }
    }

    /// The payloads received on `stream` so far, in order.
    pub fn stream_data(&self, stream: u32) -> Vec<u8> {
        let frames = self.frames.lock().unwrap();
        let mut v: Vec<&BinaryFrame> = frames
            .get(&stream)
            .map(|f| f.iter().collect())
            .unwrap_or_default();
        v.sort_by_key(|f| f.seq);
        v.iter().flat_map(|f| f.payload.iter().copied()).collect()
    }

    /// Waits for a notification (or `<response>` for an answer to no pending call)
    /// and takes it.
    pub async fn notification(&self, method: &str, timeout: Duration) -> Option<Value> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let wait = self.notes.1.notified();
            tokio::pin!(wait);
            wait.as_mut().enable();
            {
                let mut notes = self.notes.0.lock().unwrap();
                if let Some(i) = notes.iter().position(|(m, _)| m == method) {
                    return Some(notes.remove(i).1);
                }
            }
            if tokio::time::timeout_at(deadline, wait).await.is_err() {
                return None;
            }
        }
    }

    /// All notifications of `method` received so far, without taking them.
    pub fn notifications(&self, method: &str) -> Vec<Value> {
        self.notes
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == method)
            .map(|(_, v)| v.clone())
            .collect()
    }

    pub async fn close(&self, code: u16, reason: &str) {
        let _ = self.out.send(close(code, reason)).await;
    }

    /// Waits until the device's connection ended; returns the close code and reason.
    pub async fn closed(&self, timeout: Duration) -> Option<(u16, String)> {
        let mut rx = self.closed.clone();
        tokio::time::timeout(timeout, rx.wait_for(|c| c.is_some()))
            .await
            .ok()
            .and_then(|r| r.ok().map(|c| c.clone().unwrap()))
    }
}
