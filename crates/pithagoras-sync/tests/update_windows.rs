#![cfg(windows)]
//! The updater on Windows: a manifest given as a local `C:\` path, and the
//! replacement of a program that is running, which goes aside to `.old`. Runs on
//! the Windows test VM (`scripts/windows-vm-test.sh`).

use std::path::PathBuf;

use pithagoras_sync::update;
use serde_json::json;
use sync_testkit::minisign::TestKey;

/// The program: next to this test when the test was copied to the VM on its own
/// (`scripts/windows-vm-test.sh`), else where cargo built it.
fn bin() -> PathBuf {
    let here = std::env::current_exe().unwrap();
    let copied = here.with_file_name("pithagoras-sync.exe");
    if copied.exists() {
        copied
    } else {
        PathBuf::from(env!("CARGO_BIN_EXE_pithagoras-sync"))
    }
}
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn sha256(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn a_release_in_a_local_folder_replaces_the_running_program() {
    let t = tempfile::tempdir().unwrap();
    let dir = PathBuf::from(sync_policy::paths::win::strip_verbatim(
        &std::fs::canonicalize(t.path()).unwrap().to_string_lossy(),
    ));
    // The release: this build, which answers `--version` with VERSION.
    let binary = std::fs::read(bin()).unwrap();
    let rel = dir.join("rel");
    std::fs::create_dir_all(&rel).unwrap();
    std::fs::write(rel.join("pithagoras-sync-bin"), &binary).unwrap();
    let manifest = json!({
        "version": VERSION,
        "released": 1_000,
        "artifacts": {
            update::target(): {
                "url": "pithagoras-sync-bin",
                "size": binary.len(),
                "sha256": sha256(&binary),
            }
        }
    })
    .to_string();
    let key = TestKey::generate();
    std::fs::write(rel.join("manifest.json"), &manifest).unwrap();
    std::fs::write(
        rel.join("manifest.json.minisig"),
        key.sign(manifest.as_bytes(), "file:manifest.json"),
    )
    .unwrap();

    // The installed program, running: some other program stands in for it.
    let exe = dir.join(r"bin\pithagoras-sync.exe");
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::copy(
        std::path::Path::new(&std::env::var_os("SystemRoot").unwrap()).join(r"System32\PING.EXE"),
        &exe,
    )
    .unwrap();
    let mut running = std::process::Command::new(&exe)
        .args(["-n", "60", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();

    // A path with backslashes: the binary is found beside the manifest.
    let source = rel.join("manifest.json").to_string_lossy().into_owned();
    let result = async {
        let seen = dir.join(r"state\update-released");
        let plan = update::check(&source, &key.public_base64(), "0.0.0", Some(&seen))
            .await?
            .plan
            .ok_or_else(|| "nothing newer".to_string())?;
        update::install(&plan, &exe).await
    }
    .await;
    let _ = running.kill();
    let _ = running.wait();
    result.unwrap();
    assert_eq!(std::fs::read(&exe).unwrap(), binary);
    assert!(update::old_path(&exe).exists());
    let leftovers: Vec<_> = std::fs::read_dir(exe.parent().unwrap())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".update."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}
