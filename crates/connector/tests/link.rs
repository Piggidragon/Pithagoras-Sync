//! The connector against the mock portal: pairing, TLS pinning, revocation, the
//! file calls through the policy, and everything the portal must not be able to do.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use sync_connector::link::{self, LinkConfig, LinkEnd, LinkState, LinkStatus};
use sync_connector::settings::ConfigStore;
use sync_connector::{Device, pair, tls};
use sync_ops::{ExecConfig, Execs};
use sync_policy::config::PortalPolicy;
use sync_policy::*;
use sync_proto::code;
use sync_proto::methods::Choice;
use sync_testkit::{DeviceLink, MockOptions, MockPortal};
use tokio::sync::watch;

const TOKEN: &str = "test-token-0123456789abcdef";
const WAIT: Duration = Duration::from_secs(10);

struct Fx {
    _t: tempfile::TempDir,
    root: PathBuf,
}

impl Fx {
    fn new() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        // Windows canonical paths start with `\\?\`, which grants and the wire
        // form do not use.
        #[cfg(windows)]
        let root = PathBuf::from(sync_policy::paths::win::strip_verbatim(
            &root.to_string_lossy(),
        ));
        for d in ["home/.ssh", "home/proj/src", "outside", "state", "tmp"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("home/.ssh/id_ed25519"), "secret key").unwrap();
        std::fs::write(root.join("home/proj/a.txt"), "alpha\nbeta\n").unwrap();
        std::fs::write(root.join("home/proj/src/m.rs"), "fn beta() {}\n").unwrap();
        std::fs::write(root.join("outside/b.txt"), "beta outside\n").unwrap();
        Fx { _t: t, root }
    }

    /// A path as the portal sends it (`/c/...` on Windows).
    fn p(&self, rel: &str) -> String {
        sync_policy::paths::to_wire(&self.root.join(rel))
    }

    fn folders(&self, grants: &[(&str, Access)]) -> Policy {
        Policy {
            mode: Mode::Folders,
            folders: grants
                .iter()
                .map(|(p, a)| FolderGrant {
                    path: self.root.join(p),
                    access: *a,
                    execute: true,
                })
                .collect(),
            ..Policy::default()
        }
    }

    fn device(&self, policy: Policy, profile: Profile, approver: Arc<dyn Approver>) -> Arc<Device> {
        let (engine, execs) = self.parts(policy, profile, approver);
        Device::new(engine, execs, "laptop".into(), self.root.join("home"))
    }

    /// A device as the daemon builds it: approvals through the portal, the config
    /// in a file the portal may see or change as `portal_policy` says.
    fn full_device(
        &self,
        policy: Policy,
        portal_policy: PortalPolicy,
    ) -> (Arc<Device>, Arc<ApprovalQueue>, Arc<ConfigStore>) {
        let queue = ApprovalQueue::new(system_clock());
        let (engine, execs) = self.parts(policy.clone(), Profile::Headless, queue.clone());
        let cfg = DeviceConfig {
            portal_policy,
            policy,
            ..Default::default()
        };
        cfg.save(&self.config_file()).unwrap();
        let store = ConfigStore::new(self.config_file(), cfg, engine.clone(), execs.clone());
        let dev = Device::with_parts(
            engine,
            execs,
            "laptop".into(),
            self.root.join("home"),
            Some(queue.clone()),
            Some(store.clone()),
        );
        (dev, queue, store)
    }

    fn config_file(&self) -> PathBuf {
        self.root.join("config/config.toml")
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(self.root.join("state/audit.jsonl")).unwrap_or_default()
    }

    fn parts(
        &self,
        policy: Policy,
        profile: Profile,
        approver: Arc<dyn Approver>,
    ) -> (Arc<Engine>, Arc<Execs>) {
        let home = self.root.join("home");
        let engine = Engine::new(
            policy,
            profile,
            EngineOptions {
                home: home.clone(),
                own_dirs: vec![self.root.join("state")],
                approver,
                audit: Arc::new(AuditLog::open(&self.root.join("state/audit.jsonl")).unwrap()),
                clock: system_clock(),
                landlock: false,
                as_root: false,
            },
        );
        let execs = Execs::new(ExecConfig {
            shim_program: PathBuf::from("/nonexistent/shim"),
            shim_args: Vec::new(),
            shell: None,
            base_env: Vec::new(),
            env_passthrough: Vec::new(),
            output_cap: 1 << 20,
            max_timeout: Duration::from_secs(60),
            max_running: 4,
            tmp_base: self.root.join("tmp"),
        });
        (Arc::new(engine), Arc::new(execs))
    }
}

fn headless() -> Arc<dyn Approver> {
    Arc::new(NoApprover { why: "headless" })
}

struct Running {
    stop: watch::Sender<bool>,
    status: watch::Receiver<LinkStatus>,
    task: tokio::task::JoinHandle<LinkEnd>,
}

impl Running {
    async fn stop(self) -> LinkEnd {
        self.stop.send_replace(true);
        tokio::time::timeout(WAIT, self.task)
            .await
            .unwrap()
            .unwrap()
    }
}

fn run(mock: &MockPortal, dev: Arc<Device>, token: &str) -> Running {
    let cfg = LinkConfig {
        portal: PortalConfig {
            url: mock.url.clone(),
            spki_sha256: mock.spki.clone(),
            device_id: "dev-x".into(),
            name: "laptop".into(),
        },
        token: token.into(),
    };
    let (status_tx, status) = watch::channel(LinkStatus::new(LinkState::Stopped, None));
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(link::run(dev, cfg, status_tx, stop_rx));
    Running { stop, status, task }
}

async fn connected(
    fx: &Fx,
    policy: Policy,
    profile: Profile,
    approver: Arc<dyn Approver>,
) -> (MockPortal, Arc<Device>, Running, DeviceLink) {
    connect(fx.device(policy, profile, approver)).await
}

async fn connect(dev: Arc<Device>) -> (MockPortal, Arc<Device>, Running, DeviceLink) {
    let mock = MockPortal::start(MockOptions::default()).await;
    mock.add_token(TOKEN, "dev-x");
    let r = run(&mock, dev.clone(), TOKEN);
    let dl = mock.next_device(WAIT).await.expect("the device connects");
    (mock, dev, r, dl)
}

fn ctx() -> Value {
    json!({"chat": "chat-1"})
}

fn err_code(r: Result<Value, sync_proto::RpcError>) -> i64 {
    match r {
        Err(e) => e.code,
        Ok(v) => panic!("expected an error, got {v}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pairs_over_tls_with_the_pin_and_says_hello() {
    let fx = Fx::new();
    let mock = MockPortal::start(MockOptions {
        tls: true,
        codes: vec!["AB12CD34".into()],
    })
    .await;
    // The DER walker finds the same key rcgen put in the certificate.
    assert_eq!(
        tls::pin_of_cert(mock.cert_der.as_ref().unwrap()),
        mock.spki.clone()
    );
    let paired = pair::pair(&mock.pair_uri("AB12CD34"), "laptop")
        .await
        .unwrap();
    assert_eq!(paired.portal.spki_sha256, mock.spki);
    assert_eq!(mock.pairs()[0].name, "laptop");
    // The code is single-use.
    assert!(
        pair::pair(&mock.pair_uri("AB12CD34"), "laptop")
            .await
            .is_err()
    );

    let dev = fx.device(fx.folders(&[]), Profile::Headless, headless());
    let cfg = LinkConfig {
        portal: paired.portal.clone(),
        token: paired.token.clone(),
    };
    let (status_tx, mut status) = watch::channel(LinkStatus::new(LinkState::Stopped, None));
    let (stop, stop_rx) = watch::channel(false);
    let task = tokio::spawn(link::run(dev, cfg, status_tx, stop_rx));
    let dl = mock.next_device(WAIT).await.unwrap();
    assert_eq!(dl.hello["device_id"], paired.portal.device_id.as_str());
    assert_eq!(dl.hello["proto"], 1);
    assert!(dl.hello["shell"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(
        dl.hello["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("exec"))
    );
    let info = dl.call("device.info", json!({})).await.unwrap();
    assert_eq!(info["name"], "laptop");
    assert_eq!(info["mode"], "folders");
    status
        .wait_for(|s| s.state == LinkState::Connected)
        .await
        .unwrap();
    stop.send_replace(true);
    assert_eq!(task.await.unwrap(), LinkEnd::Shutdown);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_that_does_not_match_the_pin_is_refused() {
    let mock = MockPortal::start(MockOptions {
        tls: true,
        codes: vec!["AB12CD34".into()],
    })
    .await;
    // A well-formed pin (32 zero bytes) of some other key.
    let wrong = "A".repeat(43);
    let uri = mock
        .pair_uri("AB12CD34")
        .replace(mock.spki.as_deref().unwrap(), &wrong);
    let e = pair::pair(&uri, "laptop").await.err().unwrap();
    assert!(
        e.contains("does not carry the key pinned at pairing"),
        "{e}"
    );
    assert!(e.contains("pair again"), "{e}");
    assert!(!e.contains("ApplicationVerificationFailure"), "{e}");
    // Without a pin, a self-signed certificate fails against the system's roots.
    let no_pin = mock.pair_uri("AB12CD34");
    let no_pin = &no_pin[..no_pin.find("&spki=").unwrap()];
    let e = pair::pair(no_pin, "laptop").await.err().unwrap();
    assert!(
        e.contains("open the portal over https once") || e.contains("root certificates"),
        "{e}"
    );
    assert!(!e.contains("invalid peer certificate"), "{e}");
    // Neither attempt reached the pairing endpoint.
    assert!(mock.pairs().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_token_cannot_connect() {
    let fx = Fx::new();
    let (mock, dev, r, dl) = connected(&fx, fx.folders(&[]), Profile::Headless, headless()).await;
    mock.revoke("dev-x").await;
    assert_eq!(dl.closed(WAIT).await.unwrap().0, 4001);
    let end = tokio::time::timeout(WAIT, r.task).await.unwrap().unwrap();
    assert!(matches!(end, LinkEnd::Rejected(_)), "{end:?}");
    // Connecting again with the same token is refused at the upgrade.
    let r = run(&mock, dev, TOKEN);
    let end = tokio::time::timeout(WAIT, r.task).await.unwrap().unwrap();
    assert!(matches!(end, LinkEnd::Rejected(_)), "{end:?}");
    assert_eq!(mock.refused(), 1);
    assert!(mock.next_device(Duration::from_millis(200)).await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn file_calls_go_through_the_policy() {
    let fx = Fx::new();
    let (_mock, _dev, r, dl) = connected(
        &fx,
        fx.folders(&[("home/proj", Access::Rw), ("home", Access::Ro)]),
        Profile::Headless,
        headless(),
    )
    .await;
    // Read inside: content in FileData frames, then the result with its hash.
    let res = dl
        .call(
            "fs.read",
            json!({"path": fx.p("home/proj/a.txt"), "stream": 5, "ctx": ctx()}),
        )
        .await
        .unwrap();
    assert_eq!(dl.stream_data(5), b"alpha\nbeta\n");
    let sha = res["sha256"].as_str().unwrap().to_string();
    assert_eq!(res["chunks"], 1);
    // Outside the folders: denied.
    let e = dl
        .call(
            "fs.read",
            json!({"path": fx.p("outside/b.txt"), "stream": 6, "ctx": ctx()}),
        )
        .await;
    assert_eq!(err_code(e), code::DENIED);
    assert!(dl.stream_data(6).is_empty());
    // A protected path inside a granted folder prompts, and headless that is a denial.
    let e = dl
        .call(
            "fs.read",
            json!({"path": fx.p("home/.ssh/id_ed25519"), "stream": 7, "ctx": ctx()}),
        )
        .await;
    assert_eq!(err_code(e), code::DENIED);
    // A relative path is refused, not resolved against anything.
    let e = dl
        .call("fs.stat", json!({"path": "proj/a.txt", "ctx": ctx()}))
        .await;
    assert_eq!(err_code(e), code::BAD_PATH);
    // Write with if_match: the right hash wins, a stale one conflicts.
    let w = dl
        .write(
            8,
            json!({"path": fx.p("home/proj/a.txt"), "if_match": sha, "ctx": ctx()}),
            b"new",
        )
        .await
        .unwrap();
    assert_eq!(w["size"], 3);
    let e = dl
        .write(
            9,
            json!({"path": fx.p("home/proj/a.txt"), "if_match": sha, "ctx": ctx()}),
            b"newer",
        )
        .await;
    assert_eq!(err_code(e), code::CONFLICT);
    // The read-only folder takes no writes.
    let e = dl
        .write(
            10,
            json!({"path": fx.p("home/new.txt"), "ctx": ctx()}),
            b"x",
        )
        .await;
    assert_eq!(err_code(e), code::DENIED);
    assert!(!fx.root.join("home/new.txt").exists());
    // A large write arrives in several frames.
    let big = vec![b'z'; 200_000];
    dl.write(
        11,
        json!({"path": fx.p("home/proj/big.bin"), "ctx": ctx()}),
        &big,
    )
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(fx.root.join("home/proj/big.bin")).unwrap(),
        big
    );
    // grep over home skips the protected key file instead of failing.
    let g = dl
        .call(
            "fs.grep",
            json!({"path": fx.p("home"), "pattern": "secret|beta", "ctx": ctx()}),
        )
        .await
        .unwrap();
    let paths: Vec<&str> = g["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["path"].as_str().unwrap())
        .collect();
    assert!(paths.iter().any(|p| p.ends_with("m.rs")), "{g}");
    assert!(!paths.iter().any(|p| p.contains(".ssh")), "{g}");
    assert!(g["skipped"].as_u64().unwrap() >= 1);
    let f = dl
        .call(
            "fs.find",
            json!({"path": fx.p("home"), "pattern": "*", "ctx": ctx()}),
        )
        .await
        .unwrap();
    assert!(!f["paths"].to_string().contains("id_ed25519"), "{f}");
    let l = dl
        .call("fs.list", json!({"path": fx.p("home/proj"), "ctx": ctx()}))
        .await
        .unwrap();
    assert!(l["entries"].to_string().contains("a.txt"));
    // Every denial reached the portal's audit as well.
    assert!(!dl.notifications("audit").is_empty());
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_portal_cannot_widen_mode_folders_or_protections() {
    let fx = Fx::new();
    let policy = fx.folders(&[("home/proj", Access::Ro)]);
    let (_mock, dev, r, dl) = connected(&fx, policy.clone(), Profile::Headless, headless()).await;
    // Methods that would change the policy do not exist (and `policy.set` only
    // where the owner set `portal_policy = write`, tested below).
    for m in [
        "policy.set",
        "approval.answer",
        "device.mode",
        "folder.add",
        "approve",
        "protected.allow",
        "device.unlock",
    ] {
        let e = dl.call(m, json!({"mode": "full"})).await;
        assert_eq!(err_code(e), code::METHOD_NOT_FOUND, "{m}");
    }
    // Extra fields that would widen a call are refused, not ignored.
    let attempts = [
        (
            "fs.read",
            json!({"path": fx.p("outside/b.txt"), "stream": 1, "ctx": ctx(), "mode": "full"}),
        ),
        (
            "fs.read",
            json!({"path": fx.p("outside/b.txt"), "stream": 1, "ctx": {"chat": "c", "approved": true}}),
        ),
        (
            "fs.stat",
            json!({"path": fx.p("outside/b.txt"), "ctx": ctx(), "root": "/"}),
        ),
        (
            "exec.start",
            json!({"stream": 2, "command": "id", "cwd": fx.p("home/proj"), "ctx": ctx(), "env": {"PORTAL_SECRET": "x"}}),
        ),
        ("device.info", json!({"folders": ["/"]})),
    ];
    for (m, params) in attempts {
        let e = dl.call(m, params.clone()).await;
        assert_eq!(err_code(e), code::INVALID_PARAMS, "{m} {params}");
    }
    // Writes into the read-only folder stay refused; the policy is what it was.
    let e = dl
        .write(
            3,
            json!({"path": fx.p("home/proj/a.txt"), "ctx": ctx()}),
            b"x",
        )
        .await;
    assert_eq!(err_code(e), code::DENIED);
    assert_eq!(dev.engine.policy().0, policy);
    let info = dl.call("device.info", json!({})).await.unwrap();
    assert_eq!(info["mode"], "folders");
    assert_eq!(info["folders"][0]["access"], "ro");
    r.stop().await;
}

/// A command longer than the shell could take is refused before the policy sees
/// it, so its rules never scan it.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_over_the_limit_is_too_large() {
    let fx = Fx::new();
    let policy = fx.folders(&[("home/proj", Access::Rw)]);
    let (_mock, _dev, r, dl) = connected(&fx, policy, Profile::Headless, headless()).await;
    let start = |stream: u32, command: String| json!({"stream": stream, "command": command, "cwd": fx.p("home/proj"), "ctx": ctx()});
    let long = format!("echo {}", "a".repeat(sync_proto::methods::MAX_COMMAND - 4));
    let e = dl.call("exec.start", start(1, long.clone())).await;
    assert_eq!(err_code(e), code::TOO_LARGE);
    assert!(!fx.audit().contains("echo aaaa"), "{}", fx.audit());
    // At the limit it goes on to the policy (which asks here, and nobody answers).
    let e = dl
        .call("exec.start", start(2, long[..long.len() - 1].to_string()))
        .await;
    assert_eq!(err_code(e), code::DENIED);
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_frames_get_errors_and_change_nothing() {
    let fx = Fx::new();
    let (_mock, _dev, r, dl) = connected(&fx, fx.folders(&[]), Profile::Headless, headless()).await;
    dl.send_text("not json".into()).await;
    let resp = dl.notification("<response>", WAIT).await.unwrap();
    assert_eq!(resp["error"]["code"], code::PARSE_ERROR);
    assert_eq!(resp["id"], Value::Null);
    dl.send_text(r#"{"jsonrpc":"2.0","id":77,"result":{}}"#.into())
        .await;
    let resp = dl.notification("<response>", WAIT).await.unwrap();
    assert_eq!(resp["error"]["code"], code::PARSE_ERROR);
    // Garbage binary frames are dropped; the connection stays usable.
    dl.send_binary(vec![9, 9]).await;
    dl.call("device.info", json!({})).await.unwrap();
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn uploads_must_match_their_announced_size() {
    let fx = Fx::new();
    let (_mock, _dev, r, dl) = connected(
        &fx,
        fx.folders(&[("home/proj", Access::Rw)]),
        Profile::Headless,
        headless(),
    )
    .await;
    // More data than announced.
    let rx = dl
        .start_call(
            "fs.write",
            json!({"path": fx.p("home/proj/x.txt"), "stream": 1, "size": 3, "ctx": ctx()}),
        )
        .await;
    dl.upload(1, b"too much").await;
    let e = tokio::time::timeout(WAIT, rx).await.unwrap().unwrap();
    assert_eq!(err_code(e), code::TOO_LARGE);
    assert!(!fx.root.join("home/proj/x.txt").exists());
    // Over the device's limit: refused before any data.
    let e = dl
        .call(
            "fs.write",
            json!({"path": fx.p("home/proj/y.txt"), "stream": 2, "size": 1u64 << 40, "ctx": ctx()}),
        )
        .await;
    assert_eq!(err_code(e), code::TOO_LARGE);
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_waiting_for_approval_keep_their_upload_slot() {
    // Each write holds its content until it is done, approval included, so at most
    // four writes' content is held at once; a fifth is BUSY.
    let fx = Fx::new();
    let (dev, queue, _) = fx.full_device(Policy::default(), PortalPolicy::Read);
    let (_mock, _dev, r, dl) = connect(dev).await;
    let mut pending = Vec::new();
    for stream in 1..=4u32 {
        let rx = dl
            .start_call(
                "fs.write",
                json!({"path": fx.p(&format!("home/proj/w{stream}.txt")), "stream": stream, "size": 3, "ctx": ctx()}),
            )
            .await;
        dl.upload(stream, b"abc").await;
        pending.push(rx);
    }
    for _ in 0..100 {
        if queue.list().len() == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(queue.list().len(), 4, "all four wait for their approval");
    let e = dl
        .call(
            "fs.write",
            json!({"path": fx.p("home/proj/w5.txt"), "stream": 5, "size": 3, "ctx": ctx()}),
        )
        .await;
    assert_eq!(err_code(e), code::BUSY);
    // Answered, the slots come free again.
    for a in queue.list() {
        queue.answer(a.id, Choice::Deny, None, "device").unwrap();
    }
    for rx in pending {
        let e = tokio::time::timeout(WAIT, rx).await.unwrap().unwrap();
        assert_eq!(err_code(e), code::DENIED);
    }
    let rx = dl
        .start_call(
            "fs.write",
            json!({"path": fx.p("home/proj/w6.txt"), "stream": 6, "size": 3, "ctx": ctx()}),
        )
        .await;
    dl.upload(6, b"abc").await;
    for _ in 0..100 {
        if !queue.list().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    queue
        .answer(queue.list()[0].id, Choice::Once, None, "device")
        .unwrap();
    tokio::time::timeout(WAIT, rx)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::read(fx.root.join("home/proj/w6.txt")).unwrap(),
        b"abc"
    );
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_approval_is_denied_and_the_portal_sees_it_wait() {
    let fx = Fx::new();
    let mut policy = Policy::default();
    policy.approvals.timeout_secs = 1;
    let (dev, queue, _) = fx.full_device(policy, PortalPolicy::Read);
    let (_mock, _dev, r, dl) = connect(dev).await;
    let e = dl
        .call(
            "fs.read",
            json!({"path": fx.p("outside/b.txt"), "stream": 1, "ctx": ctx()}),
        )
        .await;
    match e {
        Err(e) => {
            assert_eq!(e.code, code::DENIED);
            assert!(e.message.contains("no answer"), "{}", e.message);
        }
        Ok(v) => panic!("read went through without approval: {v}"),
    }
    let asked = dl.notification("approval.requested", WAIT).await.unwrap();
    assert_eq!(asked["chat"], "chat-1");
    assert_eq!(asked["tool"], "read");
    assert_eq!(asked["choices"], json!(["once", "chat", "time", "deny"]));
    let done = dl.notification("approval.resolved", WAIT).await.unwrap();
    assert_eq!(
        (&done["answer"], &done["by"]),
        (&json!("deny"), &json!("timeout"))
    );
    assert!(dl.stream_data(1).is_empty());
    assert!(queue.list().is_empty());
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_portal_and_the_device_answer_approvals() {
    let fx = Fx::new();
    let (dev, queue, _) = fx.full_device(Policy::default(), PortalPolicy::Read);
    let (_mock, _dev, r, dl) = connect(dev).await;
    // The portal allows a read for this chat.
    let read = |stream: u32| {
        dl.start_call(
            "fs.read",
            json!({"path": fx.p("outside/b.txt"), "stream": stream, "ctx": ctx()}),
        )
    };
    let pending = read(1).await;
    let asked = dl.notification("approval.requested", WAIT).await.unwrap();
    let id = asked["id"].as_u64().unwrap();
    let listed = dl.call("approval.list", json!({})).await.unwrap();
    assert_eq!(listed["approvals"][0]["id"], id);
    // Answers it does not take are refused; the approval keeps waiting.
    let e = dl
        .call(
            "approval.answer",
            json!({"id": id, "answer": "time", "minutes": 100000}),
        )
        .await;
    assert_eq!(err_code(e), code::INVALID_PARAMS);
    let e = dl
        .call("approval.answer", json!({"id": id + 100, "answer": "once"}))
        .await;
    assert_eq!(err_code(e), code::NOT_FOUND);
    dl.call("approval.answer", json!({"id": id, "answer": "chat"}))
        .await
        .unwrap();
    tokio::time::timeout(WAIT, pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(dl.stream_data(1), b"beta outside\n");
    let done = dl.notification("approval.resolved", WAIT).await.unwrap();
    assert_eq!(
        (&done["answer"], &done["by"]),
        (&json!("chat"), &json!("portal"))
    );
    // Remembered for the chat: the next read asks nobody.
    read(2).await.await.unwrap().unwrap();
    assert!(queue.list().is_empty());
    // A command asks every time and takes once or deny; the device denies this one.
    let cmd = dl
        .start_call(
            "exec.start",
            json!({"stream": 3, "command": "id", "cwd": fx.p("outside"), "ctx": ctx()}),
        )
        .await;
    let mut waiting = queue.list();
    for _ in 0..100 {
        if !waiting.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        waiting = queue.list();
    }
    assert_eq!(waiting[0].choices, [Choice::Once, Choice::Deny]);
    queue
        .answer(waiting[0].id, Choice::Deny, None, "device")
        .unwrap();
    let e = tokio::time::timeout(WAIT, cmd).await.unwrap().unwrap();
    assert_eq!(err_code(e), code::DENIED);
    assert!(fx.audit().contains("the owner denied it"));
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_portal_reads_the_policy_only_where_the_owner_allows_it() {
    let fx = Fx::new();
    let policy = fx.folders(&[("home/proj", Access::Ro)]);
    // Off: the portal sees nothing and changes nothing.
    let (dev, _, _) = fx.full_device(policy.clone(), PortalPolicy::Off);
    let (_mock, dev, r, dl) = connect(dev).await;
    assert_eq!(
        err_code(dl.call("policy.get", json!({})).await),
        code::DENIED
    );
    assert!(!dl.hello["capabilities"].to_string().contains("policy"));
    assert!(dl.hello["capabilities"].to_string().contains("approvals"));
    let mut wide = serde_json::to_value(sync_policy::settings::Settings {
        policy: policy.clone(),
        exec: Default::default(),
    })
    .unwrap();
    wide["policy"]["mode"] = "full".into();
    wide["policy"]["full"]["protected_paths"] = false.into();
    wide["policy"]["folders"] =
        json!([{"path": fx.root.to_string_lossy(), "access": "rw", "execute": true}]);
    let e = dl
        .call("policy.set", json!({"settings": wide.clone()}))
        .await;
    assert_eq!(err_code(e), code::DENIED);
    assert_eq!(dev.engine.policy().0, policy);
    r.stop().await;

    // Read: it sees the settings and still cannot change them.
    let (dev, _, _) = fx.full_device(policy.clone(), PortalPolicy::Read);
    let (_mock, dev, r, dl) = connect(dev).await;
    let doc = dl.call("policy.get", json!({})).await.unwrap();
    assert_eq!(doc["portal_policy"], "read");
    assert_eq!(doc["settings"]["policy"]["mode"], "folders");
    assert!(doc["device_only"].to_string().contains("exec.shell"));
    let e = dl.call("policy.set", json!({"settings": wide})).await;
    assert_eq!(err_code(e), code::DENIED);
    assert_eq!(dev.engine.policy().0, policy);
    let e = dl
        .write(
            1,
            json!({"path": fx.p("home/proj/a.txt"), "ctx": ctx()}),
            b"x",
        )
        .await;
    assert_eq!(err_code(e), code::DENIED);
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn with_write_the_portal_changes_the_policy_and_each_change_is_audited() {
    let fx = Fx::new();
    let policy = fx.folders(&[("home/proj", Access::Ro)]);
    let (dev, _, store) = fx.full_device(policy.clone(), PortalPolicy::Write);
    let (_mock, dev, r, dl) = connect(dev).await;
    let doc = dl.call("policy.get", json!({})).await.unwrap();
    let mut settings = doc["settings"].clone();
    settings["policy"]["folders"][0]["access"] = "rw".into();
    settings["policy"]["tools"]["bash"] = false.into();
    // A stale version conflicts.
    let e = dl
        .call(
            "policy.set",
            json!({"settings": settings.clone(), "if_version": "stale"}),
        )
        .await;
    assert_eq!(err_code(e), code::CONFLICT);
    // Device-only settings and the switch itself stay out of reach.
    let mut shell = settings.clone();
    shell["exec"]["shell"] = "/bin/evil".into();
    let e = dl.call("policy.set", json!({"settings": shell})).await;
    assert_eq!(err_code(e), code::DENIED);
    let mut switch = settings.clone();
    switch["portal_policy"] = "write".into();
    let e = dl.call("policy.set", json!({"settings": switch})).await;
    assert_eq!(err_code(e), code::INVALID_PARAMS);
    let e = dl
        .call(
            "policy.set",
            json!({"settings": settings.clone(), "secret": "x"}),
        )
        .await;
    assert_eq!(err_code(e), code::INVALID_PARAMS);

    let new = dl
        .call(
            "policy.set",
            json!({"settings": settings, "if_version": doc["version"]}),
        )
        .await
        .unwrap();
    assert_ne!(new["version"], doc["version"]);
    // In force at once, saved in the file, audited with old and new values.
    dl.write(
        1,
        json!({"path": fx.p("home/proj/a.txt"), "ctx": ctx()}),
        b"x",
    )
    .await
    .unwrap();
    assert!(!dev.engine.policy().0.tools.bash);
    let saved = DeviceConfig::load(&fx.config_file()).unwrap();
    assert_eq!(saved.policy.folders[0].access, Access::Rw);
    assert_eq!(saved.portal_policy, PortalPolicy::Write);
    let audit = fx.audit();
    assert!(
        audit.contains(r#""target":"policy.folders""#) && audit.contains(r#"\"ro\""#),
        "{audit}"
    );
    assert!(audit.contains(r#""target":"policy.tools.bash""#), "{audit}");
    let changed = dl.notification("policy.changed", WAIT).await.unwrap();
    assert_eq!(changed["version"], new["version"]);

    // A change the owner makes on the device reaches the portal too.
    let mut cfg = DeviceConfig::load(&fx.config_file()).unwrap();
    cfg.policy.tools.bash = true;
    cfg.save(&fx.config_file()).unwrap();
    store.reload().unwrap();
    for _ in 0..100 {
        if dl.notifications("policy.changed").len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let all = dl.notifications("policy.changed");
    assert_eq!(
        all.last().unwrap()["settings"]["policy"]["tools"]["bash"],
        true
    );
    // Audited with old and new value as well, and the switch itself too.
    let audit = fx.audit();
    assert!(
        audit.contains(r#""target":"policy.tools.bash","decision":"changed","reason":"by the device owner: false -> true""#),
        "{audit}"
    );
    let mut cfg = DeviceConfig::load(&fx.config_file()).unwrap();
    cfg.portal_policy = PortalPolicy::Read;
    cfg.save(&fx.config_file()).unwrap();
    store.reload().unwrap();
    let audit = fx.audit();
    assert!(
        audit.contains(r#"by the device owner: \"write\" -> \"read\""#),
        "{audit}"
    );
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tool_labels_only_narrow() {
    let fx = Fx::new();
    let mut policy = fx.folders(&[("home/proj", Access::Rw)]);
    policy.tools.write = false;
    let (_mock, _dev, r, dl) = connected(&fx, policy, Profile::Headless, headless()).await;
    let with = |tool: &str| json!({"chat": "chat-1", "tool": tool});
    let e = dl
        .write(
            1,
            json!({"path": fx.p("home/proj/n.txt"), "ctx": with("write")}),
            b"x",
        )
        .await;
    assert_eq!(err_code(e), code::DENIED);
    dl.write(
        2,
        json!({"path": fx.p("home/proj/n.txt"), "ctx": with("edit")}),
        b"x",
    )
    .await
    .unwrap();
    let e = dl
        .write(
            3,
            json!({"path": fx.p("home/proj/n.txt"), "ctx": with("ls")}),
            b"x",
        )
        .await;
    assert_eq!(err_code(e), code::DENIED);
    let e = dl
        .write(
            4,
            json!({"path": fx.p("home/proj/n.txt"), "ctx": with("sudo")}),
            b"x",
        )
        .await;
    assert_eq!(err_code(e), code::INVALID_PARAMS);
    let info = dl.call("device.info", json!({})).await.unwrap();
    assert!(!info["tools"].to_string().contains("\"write\""), "{info}");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tainted_write_prompts_in_default_full_until_the_grant_ends() {
    let fx = Fx::new();
    let mut policy = Policy::default();
    policy.set_mode(Mode::Full, system_clock()());
    let (_mock, _dev, r, dl) = connected(&fx, policy, Profile::Headless, headless()).await;
    let tainted = json!({"chat": "chat-1", "tainted": true});
    let e = dl
        .write(
            1,
            json!({"path": fx.p("outside/new.txt"), "ctx": tainted}),
            b"x",
        )
        .await;
    assert_eq!(err_code(e), code::DENIED);
    // The device keeps the taint even when the portal stops sending its flag.
    let e = dl
        .write(
            2,
            json!({"path": fx.p("outside/new.txt"), "ctx": ctx()}),
            b"x",
        )
        .await;
    assert_eq!(err_code(e), code::DENIED);
    dl.notify("grant.end", json!({"chat": "chat-1"})).await;
    dl.call("device.info", json!({})).await.unwrap();
    dl.write(
        3,
        json!({"path": fx.p("outside/new.txt"), "ctx": ctx()}),
        b"x",
    )
    .await
    .unwrap();
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pause_closes_the_link_until_unlock() {
    let fx = Fx::new();
    let (mock, dev, mut r, dl) = connected(
        &fx,
        fx.folders(&[("home/proj", Access::Rw)]),
        Profile::Headless,
        headless(),
    )
    .await;
    dev.pause().await;
    assert_eq!(dl.closed(WAIT).await.unwrap().0, 1000);
    r.status
        .wait_for(|s| s.state == LinkState::Paused)
        .await
        .unwrap();
    // No reconnect while paused.
    assert!(
        mock.next_device(Duration::from_millis(1500))
            .await
            .is_none()
    );
    assert!(dev.engine.is_paused());
    dev.unlock();
    let dl = mock
        .next_device(WAIT)
        .await
        .expect("reconnects after unlock");
    dl.call(
        "fs.read",
        json!({"path": fx.p("home/proj/a.txt"), "stream": 1, "ctx": ctx()}),
    )
    .await
    .unwrap();
    r.stop().await;
}
