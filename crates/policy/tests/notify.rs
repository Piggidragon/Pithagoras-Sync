#![cfg(unix)]
//! The notification approver against a private D-Bus daemon and a fake notification
//! server, so no real notification ever shows on the machine running the tests.

use std::collections::HashMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sync_policy::notify::NotifyApprover;
use sync_policy::*;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedValue;

#[derive(Default)]
struct Seen {
    actions: Vec<String>,
    body: String,
    closed: Vec<u32>,
}

struct FakeServer {
    /// The action the "user" clicks; `None` never answers, `Some("")` dismisses.
    click: Option<&'static str>,
    caps: Vec<String>,
    seen: Arc<Mutex<Seen>>,
}

#[zbus::interface(name = "org.freedesktop.Notifications")]
impl FakeServer {
    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        _app_name: String,
        _replaces_id: u32,
        _app_icon: String,
        _summary: String,
        body: String,
        actions: Vec<String>,
        _hints: HashMap<String, OwnedValue>,
        _expire_timeout: i32,
    ) -> u32 {
        self.seen.lock().unwrap().actions = actions;
        self.seen.lock().unwrap().body = body;
        let id = 42;
        if let Some(click) = self.click {
            let emitter = emitter.to_owned();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                if click.is_empty() {
                    let _ = FakeServer::notification_closed(&emitter, id, 2).await;
                } else {
                    // Another notification's click first: it must be ignored.
                    let _ = FakeServer::action_invoked(&emitter, 7, "allow").await;
                    let _ = FakeServer::action_invoked(&emitter, id, click).await;
                }
            });
        }
        id
    }

    async fn close_notification(&self, id: u32) {
        self.seen.lock().unwrap().closed.push(id);
    }

    async fn get_capabilities(&self) -> Vec<String> {
        self.caps.clone()
    }

    #[zbus(signal)]
    async fn action_invoked(emitter: &SignalEmitter<'_>, id: u32, key: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn notification_closed(
        emitter: &SignalEmitter<'_>,
        id: u32,
        reason: u32,
    ) -> zbus::Result<()>;
}

struct Bus {
    child: Child,
    address: String,
    _dir: tempfile::TempDir,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A private bus with no service directories, so nothing real can be activated.
fn private_bus() -> Option<Bus> {
    if !Path::new("/usr/bin/dbus-daemon").exists() {
        eprintln!("dbus-daemon not installed; skipping");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus");
    let config = dir.path().join("bus.conf");
    std::fs::write(
        &config,
        format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>"#,
            sock.display()
        ),
    )
    .unwrap();
    let child = Command::new("/usr/bin/dbus-daemon")
        .arg(format!("--config-file={}", config.display()))
        .arg("--nofork")
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(Bus {
        child,
        address: format!("unix:path={}", sock.display()),
        _dir: dir,
    })
}

async fn serve(
    bus: &Bus,
    click: Option<&'static str>,
    caps: &[&str],
) -> (zbus::Connection, Arc<Mutex<Seen>>) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let server = FakeServer {
        click,
        caps: caps.iter().map(|s| s.to_string()).collect(),
        seen: seen.clone(),
    };
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.Notifications")
        .unwrap()
        .serve_at("/org/freedesktop/Notifications", server)
        .unwrap()
        .build()
        .await
        .unwrap();
    (conn, seen)
}

async fn client(bus: &Bus) -> zbus::Connection {
    zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap()
}

fn request(offer_chat: bool) -> ApprovalRequest {
    ApprovalRequest {
        call: None,
        chat: "chat-1".into(),
        tool: "write".into(),
        target: "/w/<a>".into(),
        cwd: None,
        reasons: vec!["protected".into()],
        preview: None,
        offer_chat,
        max_minutes: 60,
        expires_ms: i64::MAX,
        on_timeout_allow: false,
    }
}

#[tokio::test]
async fn clicks_become_answers() {
    let Some(bus) = private_bus() else { return };
    for (click, offer, want) in [
        ("allow", false, Answer::Once),
        ("deny", false, Answer::Deny),
        ("allow-chat", true, Answer::ForChat),
        // Not offered, so not honoured.
        ("allow-chat", false, Answer::Deny),
        // Dismissed without a choice.
        ("", false, Answer::Deny),
    ] {
        let (_server, seen) = serve(&bus, Some(click), &["actions", "body"]).await;
        let conn = client(&bus).await;
        let approver = NotifyApprover::with_connection(&conn).await.unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(5), approver.ask(&request(offer)))
            .await
            .unwrap();
        assert_eq!(answer, want, "click {click:?} offer {offer}");
        let actions = seen.lock().unwrap().actions.clone();
        assert_eq!(actions.contains(&"allow-chat".to_string()), offer);
        assert!(actions.contains(&"deny".to_string()));
        drop(_server);
    }
}

#[tokio::test]
async fn portal_text_cannot_redraw_the_notification() {
    // Control characters arrive as visible escapes, and a target too long to show
    // whole offers no Allow: the owner cannot allow what they cannot read.
    let Some(bus) = private_bus() else { return };
    for (target, allow) in [
        ("cat x\x1b[1A\x1b[2K\u{202e}harmless".to_string(), true),
        (format!("echo {}; rm -rf ~", "a".repeat(500)), false),
        // Line and paragraph separators break a notification's lines: escaped,
        // and counted as what is shown, so 60 of them make it too long.
        (format!("ls{}; rm -rf ~", "\u{2028}".repeat(20)), true),
        (format!("ls{}; rm -rf ~", "\u{2029}".repeat(60)), false),
    ] {
        let (_server, seen) = serve(&bus, Some("allow"), &["actions", "body"]).await;
        let conn = client(&bus).await;
        let approver = NotifyApprover::with_connection(&conn).await.unwrap();
        let mut req = request(false);
        req.chat = format!("chat\x1b]0;x\x07{}", "c".repeat(200));
        req.target = target;
        req.cwd = Some("/w/proj\x1b[1A".into());
        req.preview = Some("line 1\r\x1b[2Aline 2\nline 3".into());
        let answer = tokio::time::timeout(Duration::from_secs(5), approver.ask(&req))
            .await
            .unwrap();
        let seen = seen.lock().unwrap();
        assert!(
            !seen.body.chars().any(|c| c.is_control() && c != '\n'
                || matches!(c, '\u{202e}' | '\u{2028}' | '\u{2029}')),
            "{:?}",
            seen.body
        );
        assert!(seen.body.contains("line 2\nline 3"), "{:?}", seen.body);
        assert!(
            seen.body.contains("\nin /w/proj\\u{1b}[1A\n"),
            "{:?}",
            seen.body
        );
        assert!(
            !seen.body.contains(&"c".repeat(100)),
            "the chat id is not cut"
        );
        assert_eq!(seen.actions.contains(&"allow".to_string()), allow);
        // Clicking an Allow that was not offered denies.
        let want = if allow { Answer::Once } else { Answer::Deny };
        assert_eq!(answer, want);
    }
}

#[tokio::test]
async fn a_server_without_actions_cannot_prompt() {
    let Some(bus) = private_bus() else { return };
    let (_server, _) = serve(&bus, None, &["body"]).await;
    let conn = client(&bus).await;
    assert!(NotifyApprover::with_connection(&conn).await.is_none());
}

#[tokio::test]
async fn no_notification_service_cannot_prompt() {
    let Some(bus) = private_bus() else { return };
    let conn = client(&bus).await;
    assert!(NotifyApprover::with_connection(&conn).await.is_none());
}

#[tokio::test]
async fn an_unanswered_notification_is_withdrawn_and_denied() {
    let Some(bus) = private_bus() else { return };
    let (_server, seen) = serve(&bus, None, &["actions"]).await;
    let conn = client(&bus).await;
    let approver = Arc::new(NotifyApprover::with_connection(&conn).await.unwrap());
    let t = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(t.path()).unwrap();
    std::fs::create_dir_all(root.join("home/.ssh")).unwrap();
    let engine = Engine::new(
        Policy {
            mode: Mode::Full,
            approvals: config::ApprovalOptions {
                timeout_secs: 1,
                ..Default::default()
            },
            full: config::FullOptions {
                expiry_hours: 0,
                ..Default::default()
            },
            ..Policy::default()
        },
        Profile::Desktop,
        EngineOptions {
            home: root.join("home"),
            own_dirs: vec![],
            approver,
            audit: Arc::new(AuditLog::open(&root.join("audit.jsonl")).unwrap()),
            clock: system_clock(),
            landlock: false,
            as_root: false,
        },
    );
    let path = root.join("home/.ssh/key").to_string_lossy().into_owned();
    let call = Call {
        id: None,
        chat: "c",
        portal_tainted: false,
        tool: "read",
        pi_tool: None,
    };
    let r = engine.authorize(&call, Request::Read(&path)).await;
    assert!(matches!(r, Err(Refusal::Denied(_))), "{r:?}");
    for _ in 0..50 {
        if !seen.lock().unwrap().closed.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(seen.lock().unwrap().closed, vec![42]);
}
