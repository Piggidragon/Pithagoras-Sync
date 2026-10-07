#![cfg(unix)]
//! The MCP client against the fake server: the handshake, paging, content, and
//! every way a server can misbehave. Each failure stops the server.

use std::path::Path;
use std::time::Duration;

use serde_json::{Map, Value, json};
use sync_mcp::client::{Client, ClientError, Launch, Limits};
use sync_testkit::fake_mcp;

fn launch(dir: &Path, modes: &[&str]) -> Launch {
    let mut args = vec![
        "--record".to_string(),
        dir.join("record").to_string_lossy().into_owned(),
    ];
    args.extend([
        "--pid-file".into(),
        dir.join("pids").to_string_lossy().into_owned(),
    ]);
    for m in modes {
        args.extend(["--mode".to_string(), m.to_string()]);
    }
    Launch {
        program: fake_mcp::binary(),
        args,
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        cwd: dir.to_path_buf(),
        log: Some(dir.join("server.log")),
    }
}

fn limits() -> Limits {
    Limits {
        max_line: 64 * 1024,
        max_output: 1 << 20,
        max_garbage: 32,
        startup: Duration::from_secs(10),
        call: Duration::from_secs(10),
    }
}

async fn start(dir: &Path, modes: &[&str], l: Limits) -> Client {
    Client::start(&launch(dir, modes), l).await.unwrap()
}

fn args(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn record(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("record")).unwrap_or_default()
}

fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|s| {
            !s.rsplit(')')
                .next()
                .unwrap_or("")
                .trim_start()
                .starts_with('Z')
        })
        .unwrap_or(false)
}

async fn gone(pid: u32) -> bool {
    for _ in 0..100 {
        if !alive(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn pids(dir: &Path) -> Vec<u32> {
    std::fs::read_to_string(dir.join("pids"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.parse().ok())
        .collect()
}

#[tokio::test]
async fn handshake_paging_and_content() {
    let t = tempfile::tempdir().unwrap();
    let mut c = start(t.path(), &["pages"], limits()).await;
    let tools = c.list_tools().await.unwrap();
    assert_eq!(tools.len(), fake_mcp::tools(false).len());
    assert!(record(t.path()).contains("notifications/initialized"));
    let shot = c.call("screenshot", &Map::new()).await.unwrap();
    let r = sync_mcp::content::convert(&shot).unwrap();
    assert_eq!(r.content.len(), 2);
    let typed = c
        .call("type_text", &args(json!({"text": "hi"})))
        .await
        .unwrap();
    assert_eq!(
        sync_mcp::content::text_of(&sync_mcp::content::convert(&typed).unwrap()),
        "typed"
    );
    // The server's stderr went to its log, not anywhere else.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        std::fs::read_to_string(t.path().join("server.log"))
            .unwrap()
            .contains("started")
    );
    c.kill().await;
}

#[tokio::test]
async fn a_hang_times_out_and_stops_the_server() {
    let t = tempfile::tempdir().unwrap();
    let mut l = limits();
    l.call = Duration::from_secs(1);
    let mut c = start(t.path(), &["hang"], l).await;
    let pid = pids(t.path())[0];
    assert_eq!(
        c.call("screenshot", &Map::new()).await,
        Err(ClientError::Timeout)
    );
    assert!(c.is_dead());
    assert!(gone(pid).await);
}

#[tokio::test]
async fn a_crash_mid_call_is_reported() {
    let t = tempfile::tempdir().unwrap();
    let mut c = start(t.path(), &["crash"], limits()).await;
    let e = c.call("screenshot", &Map::new()).await.unwrap_err();
    assert!(matches!(e, ClientError::Crashed(_)), "{e:?}");
    assert!(c.is_dead());
    let e = c.call("screenshot", &Map::new()).await.unwrap_err();
    assert!(matches!(e, ClientError::Crashed(_)), "{e:?}");
}

#[tokio::test]
async fn an_oversized_line_or_flood_stops_the_server() {
    let t = tempfile::tempdir().unwrap();
    let mut c = start(t.path(), &["long-line"], limits()).await;
    let e = c.call("screenshot", &Map::new()).await.unwrap_err();
    assert!(matches!(e, ClientError::BadAnswer(_)), "{e:?}");
    assert!(c.is_dead());
    let t = tempfile::tempdir().unwrap();
    let mut c = start(t.path(), &["flood"], limits()).await;
    let e = c.call("screenshot", &Map::new()).await.unwrap_err();
    assert!(
        matches!(e, ClientError::BadAnswer(ref m) if m.contains("output")),
        "{e:?}"
    );
}

#[tokio::test]
async fn unknown_ids_and_garbage_are_never_taken() {
    let t = tempfile::tempdir().unwrap();
    let mut c = start(t.path(), &["unknown-id", "garbage"], limits()).await;
    let r = c
        .call("type_text", &args(json!({"text": "x"})))
        .await
        .unwrap();
    // The answer to id 99999 ("not yours") was dropped.
    assert_eq!(
        sync_mcp::content::text_of(&sync_mcp::content::convert(&r).unwrap()),
        "typed"
    );
    c.kill().await;
    let t = tempfile::tempdir().unwrap();
    let mut l = limits();
    l.max_garbage = 2;
    let mut c = start(t.path(), &["garbage"], l).await;
    assert!(matches!(
        c.call("screenshot", &Map::new()).await,
        Err(ClientError::BadAnswer(_))
    ));
}

#[tokio::test]
async fn requests_from_the_server_are_refused_not_served() {
    let t = tempfile::tempdir().unwrap();
    let mut c = start(t.path(), &["sampling"], limits()).await;
    let r = c.call("screenshot", &Map::new()).await.unwrap();
    assert!(sync_mcp::content::convert(&r).is_ok());
    // The server reads its input in order: once it answered the next request,
    // it has read both refusals.
    c.request("ping", json!({}), Duration::from_secs(5))
        .await
        .unwrap();
    c.kill().await;
    let rec = record(t.path());
    let answers: Vec<&str> = rec.lines().filter(|l| l.starts_with("answer ")).collect();
    assert_eq!(answers.len(), 2, "{rec}");
    for a in answers {
        assert!(a.contains("-32601") && a.contains("\"error\""), "{a}");
    }
}

#[tokio::test]
async fn a_bad_handshake_does_not_start() {
    let t = tempfile::tempdir().unwrap();
    for (modes, l) in [
        (vec!["bad-version"], limits()),
        (vec!["exit-at-start"], limits()),
        (
            vec!["slow-start"],
            Limits {
                startup: Duration::from_millis(500),
                ..limits()
            },
        ),
    ] {
        let e = Client::start(&launch(t.path(), &modes), l)
            .await
            .err()
            .unwrap();
        assert!(matches!(e, ClientError::Start(_)), "{modes:?}: {e:?}");
    }
}

#[tokio::test]
async fn other_content_fails_the_call() {
    let t = tempfile::tempdir().unwrap();
    let mut c = start(t.path(), &["audio"], limits()).await;
    let r = c.call("screenshot", &Map::new()).await.unwrap();
    assert!(sync_mcp::content::convert(&r).is_err());
    c.kill().await;
}

#[tokio::test]
async fn stopping_kills_the_server_and_its_children() {
    let t = tempfile::tempdir().unwrap();
    let mut c = start(t.path(), &["child"], limits()).await;
    let p = pids(t.path());
    assert_eq!(p.len(), 2, "the server and its child");
    assert!(p.iter().all(|p| alive(*p)));
    c.kill().await;
    for pid in p {
        assert!(gone(pid).await, "{pid} still runs");
    }
    // Dropping a client stops it too.
    let t = tempfile::tempdir().unwrap();
    let c = start(t.path(), &["child"], limits()).await;
    let p = pids(t.path());
    drop(c);
    for pid in p {
        assert!(gone(pid).await, "{pid} still runs after the drop");
    }
}

#[tokio::test]
async fn a_stop_ends_the_call_in_flight() {
    let t = tempfile::tempdir().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(0u64);
    let mut c = Client::start_with(&launch(t.path(), &["hang"]), limits(), rx)
        .await
        .unwrap();
    let pid = pids(t.path())[0];
    let stop = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        tx.send_modify(|g| *g += 1);
    };
    let none = Map::new();
    let (r, ()) = tokio::join!(c.call("screenshot", &none), stop);
    assert_eq!(r, Err(ClientError::Stopped));
    assert!(gone(pid).await);
}
