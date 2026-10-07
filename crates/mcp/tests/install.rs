#![cfg(unix)]
//! Installing a pinned server from the local file server: the hash is checked
//! before anything is written under the final name, folders are private, a
//! changed file is not run, and uninstall leaves nothing.

mod common;

use std::os::unix::fs::PermissionsExt;

use sync_mcp::install;
use sync_testkit::files::{FileServer, Reply};

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Nothing but the server folder (and no staging) under `mcp/fake`.
fn left(mcp: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(mcp.join("fake"))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn the_right_hash_installs_into_a_private_folder() {
    let t = tempfile::tempdir().unwrap();
    let mcp = t.path().join("mcp");
    let files = FileServer::start().await;
    let pin = common::pin(&files, "1.0.0", &[], &t.path().join("record"));
    let done = common::install(&mcp, &pin).await.unwrap();
    let (folder, hash) = (done.folder, done.sha256);
    assert!(folder.starts_with("1.0.0-"), "{folder}");
    let dir = install::version_dir(&mcp, "fake", &folder);
    assert_eq!(mode(&mcp), 0o700);
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("fake-mcp")), 0o755);
    assert_eq!(install::verify(&mcp, "fake", &folder, &hash).unwrap(), dir);
    let tools = install::kept_tools(&dir).unwrap();
    assert!(tools.iter().any(|t| t.name == "screenshot"));
    assert_eq!(install::kept_pin(&dir).unwrap(), pin);
    assert_eq!(left(&mcp), std::slice::from_ref(&folder));
    // It was run once, as installed: the handshake and the tool list.
    let rec = std::fs::read_to_string(t.path().join("record")).unwrap();
    assert!(
        rec.contains("initialize") && rec.contains("tools/list"),
        "{rec}"
    );

    // A file changed afterwards is not run.
    std::fs::write(dir.join("fake-mcp"), b"#!/bin/sh\necho evil\n").unwrap();
    let e = install::verify(&mcp, "fake", &folder, &hash).unwrap_err();
    assert!(e.contains("changed"), "{e}");
    // Neither is one in a folder others may write.
    let hash = common::install(&mcp, &pin).await.unwrap().sha256;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(install::verify(&mcp, "fake", &folder, &hash).is_err());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(install::verify(&mcp, "fake", &folder, &hash).is_ok());

    install::uninstall(&mcp, "fake").unwrap();
    assert!(!mcp.join("fake").exists());
}

#[tokio::test]
async fn a_wrong_hash_or_a_short_download_writes_nothing() {
    let t = tempfile::tempdir().unwrap();
    let mcp = t.path().join("mcp");
    let files = FileServer::start().await;
    let mut pin = common::pin(&files, "1.0.0", &[], &t.path().join("record"));
    pin.files[0].sha256 = "0".repeat(64);
    let e = common::install(&mcp, &pin).await.unwrap_err();
    assert!(e.contains("sha256"), "{e}");
    assert!(left(&mcp).is_empty(), "{:?}", left(&mcp));

    let pin = common::pin(&files, "1.0.0", &[], &t.path().join("record"));
    let data = common::fake_bytes();
    files.put(
        "/1.0.0/fake-mcp",
        Reply::Short {
            body: data[..1000].to_vec(),
            len: data.len(),
        },
    );
    let e = common::install(&mcp, &pin).await.unwrap_err();
    assert!(e.contains("cut short") || e.contains("bytes came"), "{e}");
    assert!(left(&mcp).is_empty());

    // More than the pin says is refused before it is all read.
    let mut small = common::pin(&files, "1.0.0", &[], &t.path().join("record"));
    small.files[0].size = 10;
    assert!(common::install(&mcp, &small).await.is_err());
    assert!(left(&mcp).is_empty());
}

#[tokio::test]
async fn redirects_go_to_pinned_hosts_only() {
    let t = tempfile::tempdir().unwrap();
    let mcp = t.path().join("mcp");
    let files = FileServer::start().await;
    let real = common::pin(&files, "1.0.0", &[], &t.path().join("record"));
    let good = files.url.clone() + "/1.0.0/fake-mcp";
    // A redirect on the same loopback server is followed.
    let mut pin = real.clone();
    pin.files[0].url = files.put("/moved", Reply::Redirect(good));
    common::install(&mcp, &pin).await.unwrap();
    for to in [
        "http://example.org/fake-mcp".to_string(),
        "https://evil.example/fake-mcp".to_string(),
        format!(
            "http://127.0.0.2:{}/1.0.0/fake-mcp",
            files.url.rsplit(':').next().unwrap()
        ),
    ] {
        let mut pin = real.clone();
        pin.version = "2.0.0".into();
        pin.files[0].url = files.put("/away", Reply::Redirect(to.clone()));
        let e = common::install(&mcp, &pin).await.unwrap_err();
        assert!(e.contains("downloads"), "{to}: {e}");
        assert!(!install::version_dir(&mcp, "fake", &install::folder_name(&pin)).exists());
    }
}

#[tokio::test]
async fn an_unpinned_server_is_not_installed() {
    let t = tempfile::tempdir().unwrap();
    let files = FileServer::start().await;
    let mut pin = common::pin(&files, "1.0.0", &[], &t.path().join("record"));
    pin.files[0].sha256 = sync_mcp::pins::TODO_PIN.into();
    let e = common::install(&t.path().join("mcp"), &pin)
        .await
        .unwrap_err();
    assert!(e.contains("TODO-PIN"), "{e}");
    assert!(
        files.asked.lock().unwrap().is_empty(),
        "nothing was downloaded"
    );
}

#[tokio::test]
async fn zips_and_wheels_unpack_and_count_in_the_hash() {
    let t = tempfile::tempdir().unwrap();
    let mcp = t.path().join("mcp");
    let files = FileServer::start().await;
    let mut pin = common::pin(&files, "1.0.0", &[], &t.path().join("record"));
    let zip = sync_mcp::unzip::stored_zip(&[("python.exe", b"py"), ("python313._pth", b"old")]);
    let wheel = sync_mcp::unzip::stored_zip(&[
        ("pkg/__init__.py", b"x = 1"),
        ("pkg-1.0.dist-info/RECORD", b""),
        ("pkg-1.0.data/platlib/native.pyd", b"bin"),
        ("pkg-1.0.data/scripts/pkg.exe", b"left out"),
    ]);
    for (path, kind, data) in [
        ("python", "zip", &zip),
        ("python/Lib/site-packages", "wheel", &wheel),
    ] {
        pin.files.push(serde_json::from_value(serde_json::json!({
            "kind": kind, "path": path, "url": files.put(&format!("/{kind}"), Reply::Body(data.clone())),
            "sha256": sync_mcp::fsutil::sha256_hex(data), "size": data.len()
        })).unwrap());
    }
    pin.write.push(sync_mcp::pins::TextFile {
        path: "python/python313._pth".into(),
        text: "Lib\\site-packages\r\nimport site\r\n".into(),
    });
    let done = common::install(&mcp, &pin).await.unwrap();
    let (folder, hash) = (done.folder, done.sha256);
    let dir = install::version_dir(&mcp, "fake", &folder);
    let sp = dir.join("python/Lib/site-packages");
    assert_eq!(std::fs::read(sp.join("pkg/__init__.py")).unwrap(), b"x = 1");
    assert_eq!(std::fs::read(sp.join("native.pyd")).unwrap(), b"bin");
    assert!(!sp.join("pkg.exe").exists() && !sp.join("pkg-1.0.data").exists());
    assert!(
        std::fs::read_to_string(dir.join("python/python313._pth"))
            .unwrap()
            .contains("import site")
    );
    std::fs::write(sp.join("pkg/__init__.py"), b"x = 2").unwrap();
    assert!(install::verify(&mcp, "fake", &folder, &hash).is_err());
}

#[tokio::test]
async fn prune_keeps_the_current_and_the_previous_version() {
    let t = tempfile::tempdir().unwrap();
    let mcp = t.path().join("mcp");
    let files = FileServer::start().await;
    let mut folders = Vec::new();
    for v in ["1.0.0", "1.1.0", "1.2.0"] {
        let done = common::install(&mcp, &common::pin(&files, v, &[], &t.path().join("record")))
            .await
            .unwrap();
        folders.push(done.folder);
    }
    install::prune(&mcp, "fake", &[&folders[2], &folders[1]]).unwrap();
    let mut l = left(&mcp);
    l.sort();
    let mut want = vec![folders[1].clone(), folders[2].clone()];
    want.sort();
    assert_eq!(l, want);
    // The same version from another pin (a new Python, say) goes into a
    // folder of its own; the one running is not touched.
    let mut other = common::pin(&files, "1.2.0", &[], &t.path().join("record"));
    other.run.env.insert("NEW_TELEMETRY".into(), "off".into());
    let done = common::install(&mcp, &other).await.unwrap();
    assert_ne!(done.folder, folders[2]);
    assert!(install::version_dir(&mcp, "fake", &folders[2]).exists());
}
