//! The signed pins document: a newer one is taken; an older serial, a bad
//! signature, an unknown field or a download host off the list are refused and
//! change nothing; the hard deny-list beats a document.

use serde_json::{Value, json};
use sync_mcp::pins::{self, PinStore, Taken};
use sync_testkit::minisign::TestKey;

fn server(allow: &[&str]) -> Value {
    json!({
        "name": "computer-use-linux", "platform": "linux", "version": "9.9.9",
        "files": [{"arch": "x86_64", "kind": "executable", "path": "computer-use-linux",
                   "url": "https://github.com/agent-sh/computer-use-linux/releases/download/v9.9.9/computer-use-linux-x86_64",
                   "sha256": "b".repeat(64), "size": 123}],
        "run": {"program": "computer-use-linux"},
        "allow": allow, "input": [],
        "focus": {"windows": {"tool": "list_windows"}},
        "selftest": {"screenshot": {"tool": "screenshot"}}
    })
}

fn doc(serial: u64, allow: &[&str]) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"serial": serial, "issued_ms": 1_760_000_000_000i64, "servers": [server(allow)]}),
    )
    .unwrap()
}

fn store(dir: &std::path::Path, key: &TestKey) -> PinStore {
    PinStore::new(
        dir.join("mcp"),
        dir.join("mcp-pins-serial"),
        Some(key.public_base64()),
    )
}

#[test]
fn a_newer_document_is_taken_and_an_older_one_refused() {
    let t = tempfile::tempdir().unwrap();
    let key = TestKey::generate();
    let s = store(t.path(), &key);
    assert_eq!(s.current().serial, 0, "the baseline until one is taken");
    let d5 = doc(5, &["screenshot"]);
    assert!(matches!(
        s.take(&d5, &key.sign(&d5, "t")),
        Ok(Taken::New(_))
    ));
    assert_eq!(s.seen_serial(), 5);
    assert_eq!(s.current().serial, 5);
    assert!(matches!(
        s.take(&d5, &key.sign(&d5, "t")),
        Ok(Taken::Same(_))
    ));
    let d4 = doc(4, &["screenshot", "list_windows"]);
    let e = s.take(&d4, &key.sign(&d4, "t")).unwrap_err();
    assert!(e.contains("older"), "{e}");
    assert_eq!((s.seen_serial(), s.current().serial), (5, 5));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(t.path().join("mcp-pins-serial"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(m & 0o777, 0o600);
    }
}

#[test]
fn a_bad_document_changes_nothing() {
    let t = tempfile::tempdir().unwrap();
    let key = TestKey::generate();
    let other = TestKey::generate();
    let s = store(t.path(), &key);
    let d = doc(7, &["screenshot"]);
    // Signed by another key; changed after signing.
    assert!(s.take(&d, &other.sign(&d, "t")).is_err());
    let mut changed = d.clone();
    changed[10] ^= 1;
    assert!(s.take(&changed, &key.sign(&d, "t")).is_err());
    // Well signed, but with an unknown field or a host off the list.
    let mut v: Value = serde_json::from_slice(&d).unwrap();
    v["servers"][0]["mirror"] = json!("https://evil.example");
    let unknown = serde_json::to_vec(&v).unwrap();
    assert!(
        s.take(&unknown, &key.sign(&unknown, "t"))
            .unwrap_err()
            .contains("unknown field")
    );
    let mut v: Value = serde_json::from_slice(&d).unwrap();
    v["servers"][0]["files"][0]["url"] = json!("https://evil.example/srv");
    let host = serde_json::to_vec(&v).unwrap();
    assert!(
        s.take(&host, &key.sign(&host, "t"))
            .unwrap_err()
            .contains("downloads")
    );
    assert_eq!(s.seen_serial(), 0);
    assert_eq!(s.current().serial, 0);
    assert!(!t.path().join("mcp/pins.json").exists());
    // A kept document that was changed on disk is not used.
    let good = doc(8, &["screenshot"]);
    s.take(&good, &key.sign(&good, "t")).unwrap();
    std::fs::write(
        t.path().join("mcp/pins.json"),
        doc(9, &["screenshot", "PowerShell"]),
    )
    .unwrap();
    assert_eq!(s.current().serial, 0);
    // Without a release key no document is taken at all.
    let keyless = PinStore::new(t.path().join("mcp2"), t.path().join("serial2"), None);
    assert!(keyless.take(&good, &key.sign(&good, "t")).is_err());
}

#[test]
fn the_hard_deny_list_beats_a_signed_document() {
    let t = tempfile::tempdir().unwrap();
    let key = TestKey::generate();
    let s = store(t.path(), &key);
    let d = doc(
        3,
        &[
            "screenshot",
            "perform_action",
            "set_value",
            "setup_window_targeting",
            "PowerShell",
            "FileSystem",
            "Registry",
        ],
    );
    let Taken::New(taken) = s.take(&d, &key.sign(&d, "t")).unwrap() else {
        panic!()
    };
    assert_eq!(taken.servers[0].allowed(), ["screenshot"]);
    assert_eq!(taken.overruled().len(), 6);
}

#[test]
fn the_pins_url_is_the_repositorys() {
    assert_eq!(
        pins::PINS_URL,
        "https://raw.githubusercontent.com/Piggidragon/Pithagoras-Sync/main/mcp/mcp.json"
    );
    assert!(pins::download_allowed(pins::PINS_URL).is_ok());
}
