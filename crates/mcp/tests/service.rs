#![cfg(unix)]
//! `mcp.list` and `mcp.call` through the service with the fake server: the
//! allow-list, the schema, the consent, the focus check, the taint, crashes and
//! backoff, timeouts, `panic`, and an update that waits for the calls in
//! flight.

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use sync_connector::device::ComputerUse;
use sync_mcp::pins::{Document, ServerPin};
use sync_mcp::service::{Indicator, Options, Service};
use sync_policy::config::InstalledServer;
use sync_policy::*;
use sync_proto::methods::{Consent, McpCallParams, McpContent};
use sync_proto::{Id, RpcError, code, mcp_reason as why};
use sync_testkit::files::FileServer;

struct Scripted(Answer, AtomicUsize);

impl Approver for Scripted {
    fn can_prompt(&self) -> bool {
        true
    }
    fn ask<'a>(&'a self, _req: &'a ApprovalRequest) -> BoxFuture<'a, Answer> {
        self.1.fetch_add(1, Ordering::SeqCst);
        let a = self.0;
        Box::pin(async move { a })
    }
}

#[derive(Default)]
struct Counting(Mutex<Vec<String>>);

impl Indicator for Counting {
    fn burst(&self, _server: &str, chat: &str) {
        self.0.lock().unwrap().push(chat.to_string());
    }
}

struct Fx {
    _t: tempfile::TempDir,
    root: PathBuf,
    files: FileServer,
    engine: Arc<Engine>,
    approver: Arc<Scripted>,
    indicator: Arc<Counting>,
    svc: Arc<Service>,
}

impl Fx {
    fn mcp(&self) -> PathBuf {
        self.root.join("mcp")
    }

    fn record(&self) -> String {
        std::fs::read_to_string(self.root.join("record")).unwrap_or_default()
    }

    /// Installs `fake` with `modes` (and `allow`, when given) and loads it.
    async fn install(&self, version: &str, modes: &[&str], allow: Option<&[&str]>) -> ServerPin {
        let mut pin = common::pin(&self.files, version, modes, &self.root.join("record"));
        if let Some(a) = allow {
            pin.allow = a.iter().map(|s| s.to_string()).collect();
            pin.observe.retain(|i| pin.allow.contains(i));
        }
        let done = common::install(&self.mcp(), &pin).await.unwrap();
        let mut installed = BTreeMap::new();
        installed.insert(
            "fake".to_string(),
            InstalledServer {
                version: version.into(),
                folder: done.folder,
                sha256: done.sha256,
                serial: 1,
                previous: None,
                held: false,
            },
        );
        self.svc.reload(installed, doc(&pin));
        // The install's own run is not what the tests look at.
        let _ = std::fs::remove_file(self.root.join("record"));
        pin
    }

    async fn call(&self, chat: &str, tool: &str, args: Value) -> Result<Vec<McpContent>, RpcError> {
        let p = McpCallParams {
            server: "fake".into(),
            tool: tool.into(),
            args: args.as_object().unwrap().clone(),
            ctx: serde_json::from_value(json!({"chat": chat})).unwrap(),
        };
        ComputerUse::call(&*self.svc, &Id::Num(1), p)
            .await
            .map(|r| r.content)
    }
}

fn doc(pin: &ServerPin) -> Document {
    Document {
        serial: 1,
        issued_ms: 1,
        servers: vec![pin.clone()],
    }
}

async fn fx(consent: Consent, answer: Answer, limits: sync_mcp::Limits) -> Fx {
    let t = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(t.path()).unwrap();
    let mut policy = Policy::default();
    let minutes = (consent == Consent::Allow).then_some(60);
    policy
        .computer_use
        .set(consent, minutes, sync_policy::system_clock()())
        .unwrap();
    let approver = Arc::new(Scripted(answer, AtomicUsize::new(0)));
    let engine = Arc::new(Engine::new(
        policy,
        Profile::Desktop,
        EngineOptions {
            home: root.join("home"),
            own_dirs: vec![root.join("state")],
            approver: approver.clone(),
            audit: Arc::new(AuditLog::open(&root.join("audit.jsonl")).unwrap()),
            clock: sync_policy::system_clock(),
            landlock: false,
            as_root: false,
        },
    ));
    let indicator = Arc::new(Counting::default());
    let svc = Service::new(
        engine.clone(),
        Options {
            dir: root.join("mcp"),
            os: sync_mcp::os().into(),
            arch: sync_mcp::arch().into(),
            base_env: common::env(),
            limits,
            indicator: indicator.clone(),
            active_ms: sync_mcp::service::BURST_GAP_MS,
        },
    );
    let files = FileServer::start().await;
    Fx {
        _t: t,
        root,
        files,
        engine,
        approver,
        indicator,
        svc,
    }
}

fn reason(e: &RpcError) -> Option<&str> {
    e.reason()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_list_holds_the_allowed_tools_only() {
    let f = fx(Consent::Off, Answer::Once, common::limits()).await;
    let pin = f
        .install(
            "1.0.0",
            &["new-tool"],
            Some(&[
                "screenshot",
                "list_windows",
                "type_text",
                "set_value",
                "PowerShell",
            ]),
        )
        .await;
    let l = f.svc.list();
    assert_eq!(l.consent, Consent::Off);
    let names: Vec<&str> = l.servers[0].tools.iter().map(|t| t.name.as_str()).collect();
    // set_value and PowerShell are hard-denied; new_tool is not on the table.
    assert_eq!(names, ["screenshot", "list_windows", "type_text"]);
    assert!(
        l.servers[0]
            .tools
            .iter()
            .find(|t| t.name == "type_text")
            .unwrap()
            .input
    );
    assert_eq!(l.servers[0].version, pin.version);
    // Listing started nothing.
    assert!(f.record().is_empty());
    assert_eq!(f.svc.list().version, l.version, "stable");
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_runs_without_consent_and_a_disallowed_tool_never_runs() {
    let f = fx(Consent::Off, Answer::Once, common::limits()).await;
    f.install("1.0.0", &["new-tool"], None).await;
    let e = f.call("c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!((e.code, reason(&e)), (code::DENIED, Some(why::CONSENT_OFF)));
    assert!(f.record().is_empty(), "the server was not even started");
    assert!(!f.engine.is_tainted("c1"));

    let f = fx(Consent::Allow, Answer::Once, common::limits()).await;
    let mut pin = f.install("1.0.0", &["new-tool"], None).await;
    let folder = sync_mcp::install::folder_name(&pin);
    for tool in ["set_value", "PowerShell", "perform_action", "nope"] {
        let e = f.call("c1", tool, json!({})).await.unwrap_err();
        assert_eq!(reason(&e), Some(why::TOOL_NOT_ALLOWED), "{tool}");
    }
    // new_tool is on this pin's table but was not listed at install... it was:
    // the fake lists it in new-tool mode. A pin without it denies it.
    pin.allow.retain(|t| t != "new_tool");
    f.svc.reload(
        BTreeMap::from([(
            "fake".to_string(),
            InstalledServer {
                version: "1.0.0".into(),
                sha256: sync_mcp::fsutil::tree_hash(&f.mcp().join("fake").join(&folder)).unwrap(),
                folder,
                serial: 2,
                previous: None,
                held: false,
            },
        )]),
        doc(&pin),
    );
    let e = f.call("c1", "new_tool", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), Some(why::TOOL_NOT_ALLOWED));
    let rec = f.record();
    for t in ["set_value", "PowerShell", "new_tool"] {
        assert!(!rec.contains(t), "{t} reached the server: {rec}");
    }
    let e = f
        .call("c1", "type_text", json!({"text": "x", "then": "rm -rf"}))
        .await
        .unwrap_err();
    assert_eq!(e.code, code::INVALID_PARAMS);
    let e = f.call("c1", "type_text", json!({})).await.unwrap_err();
    assert_eq!(e.code, code::INVALID_PARAMS);
    let e = f
        .call("c1", "type_text", json!({"text": "x".repeat(70 * 1024)}))
        .await
        .unwrap_err();
    assert_eq!(e.code, code::TOO_LARGE);
    assert!(!f.record().contains("type_text"));
    let e = ComputerUse::call(
        &*f.svc,
        &Id::Num(1),
        McpCallParams {
            server: "other".into(),
            tool: "screenshot".into(),
            args: Default::default(),
            ctx: serde_json::from_value(json!({"chat": "c1"})).unwrap(),
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        (e.code, reason(&e)),
        (code::SERVER, Some(why::NOT_INSTALLED))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_call_runs_taints_and_shows_the_indicator_once_per_burst() {
    let f = fx(Consent::Allow, Answer::Once, common::limits()).await;
    f.install("1.0.0", &[], None).await;
    let c = f.call("c1", "screenshot", json!({})).await.unwrap();
    assert!(matches!(c[0], McpContent::Image { .. }));
    assert!(f.engine.is_tainted("c1"), "computer use taints the chat");
    f.call("c1", "type_text", json!({"text": "hello"}))
        .await
        .unwrap();
    assert_eq!(f.indicator.0.lock().unwrap().as_slice(), ["c1"]);
    assert_eq!(f.svc.in_use().unwrap().chat, "c1");
    // Within a minute of a call it counts as active.
    assert!(f.svc.active());
    let rec = f.record();
    assert!(
        rec.contains("tools/call list_windows"),
        "the focus check ran: {rec}"
    );
    assert!(
        rec.contains("tools/call type_text {\"text\":\"hello\"}"),
        "{rec}"
    );
    // The decision is in the audit log.
    let audit = std::fs::read_to_string(f.root.join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"tool\":\"computer_use\""), "{audit}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ask_asks_through_the_approval_path() {
    let f = fx(Consent::Ask, Answer::ForChat, common::limits()).await;
    f.install("1.0.0", &[], None).await;
    f.call("c1", "screenshot", json!({})).await.unwrap();
    f.call("c1", "screenshot", json!({})).await.unwrap();
    assert_eq!(f.approver.1.load(Ordering::SeqCst), 1);
    let f = fx(Consent::Ask, Answer::Deny, common::limits()).await;
    f.install("1.0.0", &[], None).await;
    let e = f.call("c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), Some(why::CONSENT_DENIED));
    assert!(f.record().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn input_is_refused_while_a_sync_window_is_open_or_the_check_fails() {
    for mode in ["sync-window", "windows-error"] {
        let f = fx(Consent::Allow, Answer::Once, common::limits()).await;
        f.install("1.0.0", &[mode], None).await;
        for (tool, args) in [
            ("mouse_click", json!({"x": 1, "y": 2})),
            ("type_text", json!({"text": "x"})),
            ("press_key", json!({"key": "Return"})),
        ] {
            let e = f.call("c1", tool, args).await.unwrap_err();
            assert_eq!(reason(&e), Some(why::FOCUS), "{mode} {tool}: {e:?}");
        }
        assert!(!f.record().contains("tools/call type_text"), "{mode}");
        // Looking is not input.
        f.call("c1", "screenshot", json!({})).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_crash_backs_off_and_a_hang_times_out() {
    let f = fx(Consent::Allow, Answer::Once, common::limits()).await;
    f.install("1.0.0", &["crash"], None).await;
    let e = f.call("c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!((e.code, reason(&e)), (code::SERVER, Some(why::CRASHED)));
    let e = f.call("c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), Some(why::NOT_RUNNING), "backoff: {e:?}");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    // Started again after the backoff (and crashing again).
    let e = f.call("c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), Some(why::CRASHED));
    assert_eq!(f.record().lines().filter(|l| *l == "initialize").count(), 2);

    let mut l = common::limits();
    l.call = Duration::from_millis(500);
    let f = fx(Consent::Allow, Answer::Once, l).await;
    f.install("1.0.0", &["hang"], None).await;
    let e = f.call("c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!((e.code, reason(&e)), (code::TIMEOUT, Some(why::TIMED_OUT)));
}

#[tokio::test(flavor = "multi_thread")]
async fn panic_ends_the_call_in_flight_and_stops_the_server() {
    let f = fx(Consent::Allow, Answer::Once, common::limits()).await;
    f.install("1.0.0", &["hang", "child"], None).await;
    let call = f.call("c1", "screenshot", json!({}));
    let panic = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        f.engine.pause();
        f.svc.stop_all().await;
    };
    let (r, ()) = tokio::join!(call, panic);
    assert_eq!(reason(&r.unwrap_err()), Some(why::PAUSED));
    let st = f.svc.status(false).await;
    assert!(!st[0].running);
    let e = f.call("c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), Some(why::PAUSED));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_server_is_not_started() {
    let f = fx(Consent::Allow, Answer::Once, common::limits()).await;
    let pin = f.install("1.0.0", &[], None).await;
    let program = f
        .mcp()
        .join("fake")
        .join(sync_mcp::install::folder_name(&pin))
        .join("fake-mcp");
    let mut data = std::fs::read(&program).unwrap();
    data.push(0);
    std::fs::write(&program, data).unwrap();
    let e = f.call("c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!((e.code, reason(&e)), (code::SERVER, Some(why::CHANGED)));
    assert!(f.record().is_empty());
    // From then on it is listed as unavailable, without tools.
    let l = f.svc.list();
    assert_eq!(l.servers[0].state, "unavailable");
    assert!(l.servers[0].tools.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_update_waits_for_the_calls_in_flight_and_is_announced() {
    let mut l = common::limits();
    l.call = Duration::from_secs(2);
    let f = fx(Consent::Allow, Answer::Once, l).await;
    f.install("1.0.0", &["hang"], None).await;
    let mut changes = ComputerUse::subscribe(&*f.svc);
    let before = f.svc.list().version;
    let next = common::pin(&f.files, "2.0.0", &[], &f.root.join("record"));
    let done = common::install(&f.mcp(), &next).await.unwrap();
    let call = f.call("c1", "screenshot", json!({}));
    let update = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        f.svc.reload(
            BTreeMap::from([(
                "fake".to_string(),
                InstalledServer {
                    version: "2.0.0".into(),
                    folder: done.folder.clone(),
                    sha256: done.sha256.clone(),
                    serial: 2,
                    previous: None,
                    held: false,
                },
            )]),
            doc(&next),
        );
        // Still the old one while the call runs.
        assert_eq!(f.svc.list().servers[0].version, "1.0.0");
    };
    let (r, ()) = tokio::join!(call, update);
    assert_eq!(r.unwrap_err().code, code::TIMEOUT);
    assert_eq!(f.svc.list().servers[0].version, "2.0.0");
    assert_ne!(f.svc.list().version, before);
    let c = changes.recv().await.unwrap();
    assert_eq!(c.version, f.svc.list().version);
    f.call("c1", "screenshot", json!({})).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_newer_document_narrows_or_stops_an_installed_version() {
    let f = fx(Consent::Allow, Answer::Once, common::limits()).await;
    let pin = f.install("1.0.0", &[], None).await;
    let folder = sync_mcp::install::folder_name(&pin);
    let installed = || {
        BTreeMap::from([(
            "fake".to_string(),
            InstalledServer {
                version: "1.0.0".into(),
                sha256: sync_mcp::fsutil::tree_hash(&f.mcp().join("fake").join(&folder)).unwrap(),
                folder: folder.clone(),
                serial: 1,
                previous: None,
                held: false,
            },
        )])
    };
    // Pins for 2.0.0 that drop type_text and call screenshot input: the
    // installed 1.0.0 follows them.
    let mut newer = pin.clone();
    newer.version = "2.0.0".into();
    newer.allow.retain(|t| t != "type_text");
    newer.observe.retain(|t| t != "screenshot");
    f.svc.reload(
        installed(),
        Document {
            serial: 3,
            issued_ms: 1,
            servers: vec![newer],
        },
    );
    let e = f
        .call("c1", "type_text", json!({"text": "x"}))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), Some(why::TOOL_NOT_ALLOWED));
    let l = f.svc.list();
    let shot = l.servers[0]
        .tools
        .iter()
        .find(|t| t.name == "screenshot")
        .unwrap();
    assert!(shot.input, "the focus check runs where either asks");
    // Pins that no longer name the server stop it.
    f.svc.reload(
        installed(),
        Document {
            serial: 4,
            issued_ms: 1,
            servers: vec![],
        },
    );
    assert_eq!(f.svc.list().servers[0].state, "unavailable");
    let e = f.call("c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!(e.code, code::SERVER);
}
