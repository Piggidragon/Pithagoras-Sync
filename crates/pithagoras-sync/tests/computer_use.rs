#![cfg(target_os = "linux")]
//! Computer use end to end: the real program installs the fake MCP server from
//! a signed pins document and a loopback file server, and the mock portal
//! lists and calls it. The consent in every state, the taint, `panic`, the
//! audit log, an update to newer pins and the uninstall. HOME and the XDG
//! folders point into a temporary folder; the pins are signed with a
//! throwaway key.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use sync_testkit::files::{FileServer, Reply};
use sync_testkit::minisign::TestKey;
use sync_testkit::{DeviceLink, MockOptions, MockPortal, fake_mcp};
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_pithagoras-sync");
const WAIT: Duration = Duration::from_secs(20);

struct Env {
    _t: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    key: TestKey,
    files: FileServer,
}

impl Env {
    async fn new() -> Env {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let home = root.join("home");
        for d in ["home/proj", "tmp", "pins"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        Env {
            _t: t,
            root,
            home,
            key: TestKey::generate(),
            files: FileServer::start().await,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_STATE_HOME", self.home.join(".local/state"))
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("TMPDIR", self.root.join("tmp"))
            .env("LANG", "C.UTF-8")
            .env("USER", "tester")
            .env("PITHAGORAS_SYNC_NO_KEYRING", "1")
            .env(
                "PITHAGORAS_SYNC_TEST_MCP_PINS",
                self.root.join("pins/mcp.json"),
            )
            .env("PITHAGORAS_SYNC_TEST_MCP_KEY", self.key.public_base64())
            .stdin(Stdio::null())
            .kill_on_drop(true);
        c
    }

    async fn run(&self, args: &[&str]) -> (bool, String) {
        let out = self.cmd(args).output().await.unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    async fn ok(&self, args: &[&str]) -> String {
        let (ok, text) = self.run(args).await;
        assert!(ok, "{args:?}: {text}");
        text
    }

    fn start(&self) -> Child {
        let log = std::fs::File::create(self.root.join("daemon.log")).unwrap();
        self.cmd(&["run"]).stderr(log).spawn().unwrap()
    }

    fn state(&self) -> PathBuf {
        self.home.join(".local/state/pithagoras-sync")
    }

    fn record(&self) -> String {
        std::fs::read_to_string(self.root.join("record")).unwrap_or_default()
    }

    /// Publishes signed pins of `fake` `version` (serial `serial`).
    fn publish(&self, serial: u64, version: &str) {
        let data = std::fs::read(fake_mcp::binary()).unwrap();
        let url = self
            .files
            .put(&format!("/{version}/fake-mcp"), Reply::Body(data.clone()));
        let doc = json!({
            "serial": serial, "issued_ms": 1_760_000_000_000i64,
            "servers": [{
                "name": "fake", "platform": "linux", "version": version,
                "files": [{"kind": "executable", "path": "fake-mcp", "url": url,
                           "sha256": sync_mcp::fsutil::sha256_hex(&data), "size": data.len()}],
                "run": {"program": "fake-mcp", "args": ["--record", self.root.join("record").to_string_lossy()], "env": {"FAKE_TELEMETRY": "off"}},
                "allow": ["screenshot", "list_windows", "get_cursor_position", "mouse_move", "type_text", "PowerShell"],
                "input": ["mouse_move", "type_text"],
                "focus": {"windows": {"tool": "list_windows"}},
                "selftest": {"screenshot": {"tool": "screenshot"},
                             "pointer": {"position": {"tool": "get_cursor_position"}, "move_to": {"tool": "mouse_move", "args": {"x": "$x", "y": "$y"}}}},
                "setup": [{"id": "flag", "title": "A flag file", "text": "The server needs a flag.",
                           "check": {"argv": ["/bin/sh", "-c", "test -e {dir}/../flag && echo yes || echo no"], "expect": "yes"}}]
            }]
        })
        .to_string();
        std::fs::write(self.root.join("pins/mcp.json"), &doc).unwrap();
        std::fs::write(
            self.root.join("pins/mcp.json.minisig"),
            self.key.sign(doc.as_bytes(), "file:mcp.json"),
        )
        .unwrap();
    }
}

async fn stop(mut child: Child) {
    if let Some(pid) = child.id() {
        // SAFETY: plain kill(2) on our own child.
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    }
    let _ = tokio::time::timeout(WAIT, child.wait()).await;
}

async fn call(
    dl: &DeviceLink,
    chat: &str,
    tool: &str,
    args: Value,
) -> Result<Value, sync_proto::RpcError> {
    dl.call(
        "mcp.call",
        json!({"server": "fake", "tool": tool, "args": args, "ctx": {"chat": chat}}),
    )
    .await
}

fn reason(e: &sync_proto::RpcError) -> String {
    e.reason().unwrap_or("").to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn computer_use_from_install_to_uninstall() {
    let env = Env::new().await;
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE7777".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE7777"), "--name", "cubox"])
        .await;
    env.publish(1, "1.0.0");

    let plan = env.ok(&["computer-use", "install", "--print"]).await;
    assert!(
        plan.contains("fake-mcp") && plan.contains("allow only"),
        "{plan}"
    );
    let out = env.ok(&["computer-use", "install"]).await;
    assert!(out.contains("fake 1.0.0 is installed"), "{out}");
    assert!(out.contains("stays off"), "{out}");
    let cfg =
        std::fs::read_to_string(env.home.join(".config/pithagoras-sync/config.toml")).unwrap();
    assert!(
        cfg.contains("[mcp.fake]") && cfg.contains("version = \"1.0.0\""),
        "{cfg}"
    );

    let daemon = env.start();
    let dl = mock.next_device(WAIT).await.expect("the client connects");
    let caps = dl.hello["capabilities"].as_array().unwrap().clone();
    assert!(caps.contains(&json!("mcp")), "{caps:?}");
    let list = dl.call("mcp.list", json!({})).await.unwrap();
    assert_eq!(dl.hello["mcp_version"], list["version"]);
    assert_eq!(list["consent"], "off");
    let tools: Vec<&str> = list["servers"][0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        tools.contains(&"screenshot") && !tools.contains(&"PowerShell"),
        "{tools:?}"
    );
    let info = dl.call("device.info", json!({})).await.unwrap();
    assert!(
        info["mcp_tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["tool"] == "type_text")
    );

    // Off: refused, and the server never started.
    let e = call(&dl, "c1", "screenshot", json!({})).await.unwrap_err();
    assert_eq!(reason(&e), "consent_off");
    let e = call(&dl, "c1", "PowerShell", json!({"command": "id"}))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "tool_not_allowed");
    assert!(!env.record().contains("tools/call"), "{}", env.record());

    // Ask: the question goes to the portal with its own choices.
    env.ok(&["computer-use", "ask"]).await;
    let changed = dl
        .notification("mcp.changed", WAIT)
        .await
        .expect("mcp.changed");
    assert_eq!(changed["consent"], "ask");
    let pending = dl
        .start_call(
            "mcp.call",
            json!({"server": "fake", "tool": "screenshot", "args": {}, "ctx": {"chat": "c1"}}),
        )
        .await;
    tokio::pin!(pending);
    let a = tokio::select! {
        a = dl.notification("approval.requested", WAIT) => a.expect("a question"),
        r = &mut pending => panic!("answered without asking: {r:?}"),
    };
    assert_eq!(a["tool"], "computer_use");
    assert_eq!(a["choices"], json!(["once", "chat", "deny"]));
    assert!(
        a["reasons"][0].as_str().unwrap().contains("Full mode"),
        "{a}"
    );
    dl.call("approval.answer", json!({"id": a["id"], "answer": "chat"}))
        .await
        .unwrap();
    let shot = pending.await.unwrap().unwrap();
    assert_eq!(shot["content"][0]["type"], "image");
    // For this chat: no second question.
    call(&dl, "c1", "screenshot", json!({})).await.unwrap();

    // Allow: typed text goes through the focus check; the audit log keeps
    // the arguments only as far as the question shows them.
    env.ok(&["computer-use", "allow", "--minutes", "5"]).await;
    let long = format!("{}AFTERTHECUT", "a".repeat(2000));
    call(&dl, "c2", "type_text", json!({"text": long}))
        .await
        .unwrap();
    let rec = env.record();
    assert!(rec.contains("tools/call list_windows"), "{rec}");
    assert!(rec.contains("AFTERTHECUT"), "the server got it all");
    let audit = std::fs::read_to_string(env.state().join("audit.jsonl")).unwrap();
    assert!(audit.contains("fake.type_text"), "{audit}");
    assert!(
        !audit.contains("AFTERTHECUT"),
        "the audit log keeps what was shown only"
    );
    let log = std::fs::read_to_string(env.root.join("daemon.log")).unwrap();
    assert!(!log.contains("AFTERTHECUT"), "{log}");

    // Taint: in Full mode the chat's next command asks.
    env.ok(&["mode", "full"]).await;
    let pending = dl
        .start_call(
            "exec.start",
            json!({"stream": 1, "command": "true", "cwd": env.home.join("proj"), "ctx": {"chat": "c2"}}),
        )
        .await;
    tokio::pin!(pending);
    let a = tokio::select! {
        a = dl.notification("approval.requested", WAIT) => a.expect("the taint asks"),
        r = &mut pending => panic!("ran without asking: {r:?}"),
    };
    assert!(a["reasons"].to_string().contains("untrusted"), "{a}");
    dl.call("approval.answer", json!({"id": a["id"], "answer": "deny"}))
        .await
        .unwrap();
    assert!(pending.await.unwrap().is_err());

    // The owner's status and test.
    let st = env.ok(&["computer-use", "status"]).await;
    assert!(st.contains("fake 1.0.0: answers"), "{st}");
    assert!(st.contains("A flag file: not done"), "{st}");
    let test = env.ok(&["computer-use", "test", "--verbose"]).await;
    assert!(test.contains("pointer moved 10 px"), "{test}");
    let status = env.ok(&["status"]).await;
    assert!(
        status.contains("Computer use: consent allow until"),
        "{status}"
    );

    // The portal cannot give consent, whatever it may write.
    env.ok(&["config", "set", "portal_policy", "write"]).await;
    let doc = dl.call("policy.get", json!({})).await.unwrap();
    let mut settings = doc["settings"].clone();
    settings["policy"]["computer_use"]["until_ms"] = json!(i64::MAX);
    let e = dl
        .call("policy.set", json!({"settings": settings}))
        .await
        .unwrap_err();
    assert_eq!(e.code, sync_proto::code::DENIED);

    // Newer pins: `update` takes them and the client switches.
    env.publish(2, "1.1.0");
    let out = env.ok(&["computer-use", "update"]).await;
    assert!(out.contains("fake is now 1.1.0"), "{out}");
    let mut seen = false;
    for _ in 0..50 {
        let l = dl.call("mcp.list", json!({})).await.unwrap();
        if l["servers"][0]["version"] == "1.1.0" {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "the client took the new version");
    // An older document served again is refused.
    env.publish(1, "1.0.0");
    let (_, out) = env.run(&["computer-use", "update"]).await;
    assert!(out.contains("older"), "{out}");
    let r = env.ok(&["computer-use", "rollback"]).await;
    assert!(r.contains("back to fake 1.0.0"), "{r}");

    // Panic ends the allow; unlock does not bring it back.
    env.ok(&["panic"]).await;
    env.ok(&["unlock"]).await;
    let cfg =
        std::fs::read_to_string(env.home.join(".config/pithagoras-sync/config.toml")).unwrap();
    assert!(cfg.contains("consent = \"off\""), "{cfg}");

    // Uninstall: nothing left, the portal hears of it.
    let dl = mock
        .next_device(WAIT)
        .await
        .expect("reconnects after unlock");
    env.ok(&["computer-use", "uninstall"]).await;
    assert!(!env.state().join("mcp/fake").exists());
    let mut empty = false;
    for _ in 0..50 {
        let l = dl.call("mcp.list", json!({})).await.unwrap();
        if l["servers"].as_array().unwrap().is_empty() {
            empty = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(empty);
    stop(daemon).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_file_tools_never_reach_the_servers_folder() {
    let env = Env::new().await;
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE8888".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE8888")]).await;
    env.publish(1, "1.0.0");
    env.ok(&["computer-use", "install"]).await;
    // Full mode with the protections off: the folder is sealed all the same.
    env.ok(&["config", "set", "policy.full.protected_paths", "false"])
        .await;
    env.ok(&["mode", "full", "--expiry-hours", "0"]).await;
    let daemon = env.start();
    let dl = mock.next_device(WAIT).await.expect("connects");
    let program = env.state().join("mcp/fake/1.0.0/fake-mcp");
    for (method, extra) in [
        ("fs.stat", json!({})),
        ("fs.read", json!({"stream": 1})),
        ("fs.list", json!({})),
    ] {
        let path: &Path = if method == "fs.list" {
            program.parent().unwrap()
        } else {
            &program
        };
        let mut p = json!({"path": path, "ctx": {"chat": "c1"}});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        let e = dl.call(method, p).await.unwrap_err();
        assert_eq!(e.code, sync_proto::code::DENIED, "{method}: {e:?}");
    }
    let w = dl
        .call(
            "fs.write",
            json!({"path": program, "stream": 3, "size": 0, "ctx": {"chat": "c1"}}),
        )
        .await
        .unwrap_err();
    assert_eq!(w.code, sync_proto::code::DENIED);
    stop(daemon).await;
}
