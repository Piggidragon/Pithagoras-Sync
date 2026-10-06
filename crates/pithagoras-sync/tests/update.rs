#![cfg(unix)]
//! The updater against releases in temp directories and on a loopback HTTP server:
//! signed manifests, the checks on the binary, the replacement, and the restart
//! of the running client.

use std::path::{Path, PathBuf};
use std::time::Duration;

use pithagoras_sync::update::{self, Plan};
use serde_json::json;
use sync_testkit::minisign::TestKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BIN: &str = env!("CARGO_BIN_EXE_pithagoras-sync");

/// A release: a "binary" (a script answering `--version`), its manifest and the
/// manifest's signature.
struct Release {
    _t: tempfile::TempDir,
    dir: PathBuf,
    key: TestKey,
}

fn program(version: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho \"pithagoras-sync {version}\"\n").into_bytes()
}

fn sha256(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Release {
    fn new() -> Release {
        let t = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(t.path()).unwrap();
        Release {
            _t: t,
            dir,
            key: TestKey::generate(),
        }
    }

    /// Publishes `version` with `binary`; the manifest claims `claimed` as its
    /// sha256 (the real one when `None`).
    fn publish(&self, version: &str, binary: &[u8], claimed: Option<&str>) -> String {
        self.publish_at(version, 1_000, binary, claimed)
    }

    /// Publishes as `publish`, released at `released`.
    fn publish_at(
        &self,
        version: &str,
        released: u64,
        binary: &[u8],
        claimed: Option<&str>,
    ) -> String {
        std::fs::create_dir_all(self.dir.join("rel")).unwrap();
        std::fs::write(self.dir.join("rel/pithagoras-sync-bin"), binary).unwrap();
        let manifest = json!({
            "version": version,
            "released": released,
            "artifacts": {
                update::target(): {
                    "url": "pithagoras-sync-bin",
                    "size": binary.len(),
                    "sha256": claimed.map_or_else(|| sha256(binary), str::to_string),
                }
            }
        })
        .to_string();
        let path = self.dir.join("rel/manifest.json");
        std::fs::write(&path, &manifest).unwrap();
        std::fs::write(
            self.dir.join("rel/manifest.json.minisig"),
            self.key.sign(manifest.as_bytes(), "file:manifest.json"),
        )
        .unwrap();
        path.to_string_lossy().into_owned()
    }

    /// The installed program the update replaces, and a config beside it.
    fn installed(&self) -> PathBuf {
        let exe = self.dir.join("bin/pithagoras-sync");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, program("0.1.0")).unwrap();
        exe
    }

    fn pk(&self) -> String {
        self.key.public_base64()
    }
}

/// What `check` offers to install, with no record of earlier manifests.
async fn check(source: &str, key: &str, current: &str) -> Result<Option<Plan>, String> {
    Ok(update::check(source, key, current, &[]).await?.plan)
}

fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".update."))
        .collect()
}

#[tokio::test]
async fn a_signed_newer_release_replaces_the_program() {
    let r = Release::new();
    let manifest = r.publish("0.2.0", &program("0.2.0"), None);
    let exe = r.installed();
    let plan = check(&manifest, &r.pk(), "0.1.0")
        .await
        .unwrap()
        .expect("0.2.0 is newer");
    assert_eq!(plan.version, "0.2.0");
    update::install(&plan, &exe).await.unwrap();
    assert_eq!(std::fs::read(&exe).unwrap(), program("0.2.0"));
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&exe).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }
    assert!(leftovers(exe.parent().unwrap()).is_empty());
    // The same or an older version is not taken: no downgrades.
    assert_eq!(check(&manifest, &r.pk(), "0.2.0").await.unwrap(), None);
    assert_eq!(check(&manifest, &r.pk(), "0.10.0").await.unwrap(), None);
}

#[tokio::test]
async fn a_manifest_that_does_not_verify_is_refused() {
    let r = Release::new();
    let manifest = r.publish("0.2.0", &program("0.2.0"), None);
    // Signed by another key.
    let other = TestKey::generate();
    let e = check(&manifest, &other.public_base64(), "0.1.0")
        .await
        .unwrap_err();
    assert!(e.contains("does not verify"), "{e}");
    // Changed after signing.
    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(&manifest, text.replace("0.2.0", "0.9.0")).unwrap();
    let e = check(&manifest, &r.pk(), "0.1.0").await.unwrap_err();
    assert!(e.contains("does not verify"), "{e}");
    // No signature at all.
    r.publish("0.2.0", &program("0.2.0"), None);
    std::fs::remove_file(format!("{manifest}.minisig")).unwrap();
    assert!(check(&manifest, &r.pk(), "0.1.0").await.is_err());
}

#[tokio::test]
async fn a_binary_that_does_not_match_stays_out() {
    let r = Release::new();
    let exe = r.installed();
    let before = std::fs::read(&exe).unwrap();
    // The manifest names another sha256.
    let manifest = r.publish("0.2.0", &program("0.2.0"), Some(&sha256(b"other")));
    let plan = check(&manifest, &r.pk(), "0.1.0").await.unwrap().unwrap();
    let e = update::install(&plan, &exe).await.unwrap_err();
    assert!(e.contains("sha256"), "{e}");
    assert!(
        e.ends_with("(nothing was replaced, and no client was restarted)"),
        "{e}"
    );
    // A different size than the manifest says, the sha256 right.
    let manifest = r.publish("0.2.0", &program("0.2.0"), None);
    let plan = check(&manifest, &r.pk(), "0.1.0").await.unwrap().unwrap();
    let bad = Plan {
        artifact: update::Artifact {
            size: plan.artifact.size + 1,
            ..plan.artifact.clone()
        },
        ..plan
    };
    assert!(update::install(&bad, &exe).await.is_err());
    // Signed and matching, but it is not the version the manifest promised.
    let manifest = r.publish("0.2.0", &program("0.3.0"), None);
    let plan = check(&manifest, &r.pk(), "0.1.0").await.unwrap().unwrap();
    let e = update::install(&plan, &exe).await.unwrap_err();
    assert!(e.contains("reports"), "{e}");
    assert_eq!(std::fs::read(&exe).unwrap(), before);
    assert!(leftovers(exe.parent().unwrap()).is_empty());
}

/// Serves `files` on loopback HTTP; `/latest/<name>` redirects to `/<name>`.
async fn serve(files: Vec<(String, Vec<u8>)>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                continue;
            };
            let files = files.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = head.split(' ').nth(1).unwrap_or("/").to_string();
                let resp = if let Some(rest) = path.strip_prefix("/latest/") {
                    format!("HTTP/1.1 302 Found\r\nLocation: /{rest}\r\nContent-Length: 0\r\n\r\n")
                        .into_bytes()
                } else if let Some((_, body)) = files.iter().find(|(n, _)| path == format!("/{n}"))
                {
                    let mut r = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    r.extend_from_slice(body);
                    r
                } else {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
                };
                let _ = s.write_all(&resp).await;
            });
        }
    });
    base
}

#[tokio::test]
async fn updates_over_http_follow_redirects() {
    let r = Release::new();
    let manifest = r.publish("0.2.0", &program("0.2.0"), None);
    let read = |p: &str| std::fs::read(r.dir.join("rel").join(p)).unwrap();
    let base = serve(vec![
        ("manifest.json".into(), read("manifest.json")),
        (
            "manifest.json.minisig".into(),
            read("manifest.json.minisig"),
        ),
        ("pithagoras-sync-bin".into(), read("pithagoras-sync-bin")),
    ])
    .await;
    let _ = manifest;
    let exe = r.installed();
    // The manifest's relative URL resolves against where it was fetched from.
    let plan = check(&format!("{base}/latest/manifest.json"), &r.pk(), "0.1.0")
        .await
        .unwrap()
        .unwrap();
    update::install(&plan, &exe).await.unwrap();
    assert_eq!(std::fs::read(&exe).unwrap(), program("0.2.0"));
    let e = check(&format!("{base}/missing.json"), &r.pk(), "0.1.0")
        .await
        .unwrap_err();
    assert!(e.contains("404"), "{e}");
}

#[tokio::test]
async fn this_build_updates_only_with_a_release_key_and_restarts_on_request() {
    let t = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(t.path()).unwrap();
    let cmd = |args: &[&str]| {
        let mut c = tokio::process::Command::new(BIN);
        c.args(args)
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_STATE_HOME", home.join(".local/state"))
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("USER", "tester")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        c
    };
    if update::PUBLIC_KEY.is_none() {
        let out = cmd(&["update", "--manifest", "/nowhere/manifest.json"])
            .output()
            .await
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("no update key"));
    }
    // `restart` (sent by `update` after the replacement) ends the client with a
    // failure code for its unit to start it again.
    let mut daemon = cmd(&["run"])
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let socket = home.join(".local/state/pithagoras-sync/run/control.sock");
    let mut s = None;
    for _ in 0..100 {
        if let Ok(c) = tokio::net::UnixStream::connect(&socket).await {
            s = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut s = s.expect("the client listens");
    // `update` replaces the program the running client was started from.
    s.write_all(b"{\"cmd\":\"status\"}\n").await.unwrap();
    let mut reply = String::new();
    s.read_to_string(&mut reply).await.unwrap();
    let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(
        Path::new(reply["status"]["exe"].as_str().unwrap_or_default()),
        std::fs::canonicalize(BIN).unwrap(),
        "{reply}"
    );
    let mut s = tokio::net::UnixStream::connect(&socket).await.unwrap();
    s.write_all(b"{\"cmd\":\"restart\"}\n").await.unwrap();
    let mut reply = String::new();
    s.read_to_string(&mut reply).await.unwrap();
    assert!(reply.contains("\"ok\":true"), "{reply}");
    let status = tokio::time::timeout(Duration::from_secs(15), daemon.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(i32::from(pithagoras_sync::cli::RESTART_EXIT))
    );
}

/// A program in a folder this user cannot write to: the error says who updates
/// it. Here the folder is this user's own, so not root (root's /usr/local/bin,
/// for the dedicated user `setup` makes, is in the unit tests).
#[tokio::test]
async fn a_program_this_user_cannot_replace_says_who_updates_it() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        // Root writes anywhere.
        return;
    }
    let r = Release::new();
    let manifest = r.publish("0.2.0", &program("0.2.0"), None);
    let exe = r.installed();
    let bin = exe.parent().unwrap();
    std::fs::set_permissions(bin, std::fs::Permissions::from_mode(0o555)).unwrap();
    let plan = check(&manifest, &r.pk(), "0.1.0").await.unwrap().unwrap();
    let e = update::install(&plan, &exe).await.unwrap_err();
    std::fs::set_permissions(bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        e.contains(&format!("so make it writable: chmod u+w {}", bin.display())),
        "{e}"
    );
    assert!(!e.contains("sudo"), "{e}");
    assert!(e.contains(&exe.display().to_string()), "{e}");
    assert!(!e.contains("os error"), "{e}");
    assert_eq!(std::fs::read(&exe).unwrap(), program("0.1.0"));
}

/// The floor is the higher of the program's own record (the newest manifest
/// seen for it) and this user's (the newest release this user installed). A
/// manifest only looked at for one program does not refuse an older-dated one for
/// another, but a program updated for the first time is never taken below a
/// release this user already installed.
#[tokio::test]
async fn a_program_is_never_taken_below_what_this_user_installed() {
    let r = Release::new();
    let dirs = sync_policy::config::Dirs::under(&r.dir.join("cfg"));
    let user = dirs.update_user_seen_file();
    let roots = r.installed();
    let system = r.dir.join("system/pithagoras-sync");
    std::fs::create_dir_all(system.parent().unwrap()).unwrap();
    std::fs::write(&system, program("0.1.0")).unwrap();
    let records = |p: &Path| [dirs.update_seen_file(p), user.clone()];
    let check = |m: String, p: PathBuf| {
        let k = r.pk();
        async move {
            let [own, user] = records(&p);
            update::check(&m, &k, "0.1.0", &[&own, &user]).await
        }
    };
    let earlier =
        std::fs::read_to_string(r.publish_at("0.2.0", 1_000, &program("0.2.0"), None)).unwrap();
    let earlier_sig = std::fs::read_to_string(r.dir.join("rel/manifest.json.minisig")).unwrap();
    let manifest = r.publish_at("0.2.0", 2_000, &program("0.2.0"), None);
    check(manifest.clone(), roots.clone()).await.unwrap();
    std::fs::write(&manifest, &earlier).unwrap();
    std::fs::write(format!("{manifest}.minisig"), &earlier_sig).unwrap();
    // Seen for root's client, not installed: the other program still takes the
    // earlier one; root's client does not.
    let offer = check(manifest.clone(), system.clone()).await.unwrap();
    assert_eq!(offer.plan.unwrap().version, "0.2.0");
    let e = check(manifest.clone(), roots.clone()).await.unwrap_err();
    assert!(e.contains("older than one this client already took"), "{e}");
    // Once this user installed the release of 2000, no program goes below it.
    update::record(&user, 2_000).unwrap();
    update::record(&user, 1_500).unwrap();
    assert_eq!(std::fs::read_to_string(&user).unwrap().trim(), "2000");
    let fresh = r.dir.join("fresh/pithagoras-sync");
    std::fs::create_dir_all(fresh.parent().unwrap()).unwrap();
    std::fs::write(&fresh, program("0.1.0")).unwrap();
    let e = check(manifest.clone(), fresh.clone()).await.unwrap_err();
    assert!(e.contains("older than one this client already took"), "{e}");
    // A check does not raise this user's record: only an installed release does.
    assert_eq!(std::fs::read_to_string(&user).unwrap().trim(), "2000");
    // Removing the records resets a test channel (docs/testing.md).
    let [own, user_file] = records(&fresh);
    let _ = std::fs::remove_file(own);
    std::fs::remove_file(user_file).unwrap();
    assert!(check(manifest, fresh).await.is_ok());
}

/// A program that went missing (deleted by hand) is put back in its folder.
#[tokio::test]
async fn a_missing_program_is_put_back() {
    let r = Release::new();
    let exe = r.installed();
    std::fs::remove_file(&exe).unwrap();
    let manifest = r.publish("0.2.0", &program("0.2.0"), None);
    let plan = check(&manifest, &r.pk(), "0.0.0").await.unwrap().unwrap();
    update::install(&plan, &exe).await.unwrap();
    assert_eq!(std::fs::read(&exe).unwrap(), program("0.2.0"));
}

/// A program reached through a link (/usr/local/bin/pithagoras-sync leading to
/// /opt/...): the file it leads to is replaced and the link stays, so the
/// program's record of releases is found again at the next update.
#[tokio::test]
async fn a_linked_program_keeps_its_link_and_its_record() {
    let r = Release::new();
    let dirs = sync_policy::config::Dirs::under(&r.dir.join("cfg"));
    let real = r.installed();
    let link = r.dir.join("link-to-pithagoras-sync");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let record = dirs.update_seen_file(&link);
    let manifest = r.publish("0.2.0", &program("0.2.0"), None);
    let plan = check(&manifest, &r.pk(), "0.1.0").await.unwrap().unwrap();
    update::install(&plan, &link).await.unwrap();
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&real).unwrap(), program("0.2.0"));
    assert_eq!(dirs.update_seen_file(&link), record);
    assert!(leftovers(real.parent().unwrap()).is_empty());
}

/// A release made the way `.github/workflows/release.yml` makes it, with
/// `sync-release manifest` and `sync-release sign`: the client takes it.
#[tokio::test]
async fn a_release_made_by_the_release_tool_updates_the_client() {
    let r = Release::new();
    let rel = r.dir.join("dist");
    std::fs::create_dir_all(&rel).unwrap();
    let binary = rel.join(format!("pithagoras-sync-{}", update::target()));
    std::fs::write(&binary, program("0.3.0")).unwrap();
    let other = rel.join("pithagoras-sync-x86_64-windows.exe");
    std::fs::write(&other, b"not this one").unwrap();
    let target = update::target();
    let text = sync_release::manifest(
        "0.3.0",
        1_000,
        None,
        &[
            sync_release::Binary {
                path: &binary,
                target: &target,
            },
            sync_release::Binary {
                path: &other,
                target: "x86_64-windows",
            },
        ],
    )
    .unwrap();
    let manifest = rel.join("manifest.json");
    std::fs::write(&manifest, &text).unwrap();
    std::fs::write(
        rel.join("manifest.json.minisig"),
        r.key.sign(text.as_bytes(), "file:manifest.json"),
    )
    .unwrap();
    let exe = r.installed();
    let plan = check(&manifest.to_string_lossy(), &r.pk(), "0.1.0")
        .await
        .unwrap()
        .expect("0.3.0 is newer");
    update::install(&plan, &exe).await.unwrap();
    assert_eq!(std::fs::read(&exe).unwrap(), program("0.3.0"));
}

/// Whoever controls the release listing but not the key can serve an older signed
/// manifest again; a client that took a newer one refuses it.
#[tokio::test]
async fn an_older_signed_manifest_served_again_is_refused() {
    let r = Release::new();
    let seen = r.dir.join("state/update-released");
    let old =
        std::fs::read_to_string(r.publish_at("0.2.0", 1_000, &program("0.2.0"), None)).unwrap();
    let old_sig = std::fs::read_to_string(r.dir.join("rel/manifest.json.minisig")).unwrap();
    let manifest = r.publish_at("0.3.0", 2_000, &program("0.3.0"), None);
    let offer = update::check(&manifest, &r.pk(), "0.1.0", &[&seen])
        .await
        .unwrap();
    assert_eq!(offer.released, 2_000);
    assert_eq!(offer.plan.unwrap().version, "0.3.0");
    assert_eq!(std::fs::read_to_string(&seen).unwrap().trim(), "2000");
    // The same manifest again is fine.
    assert!(
        update::check(&manifest, &r.pk(), "0.1.0", &[&seen])
            .await
            .is_ok()
    );
    // The older one, validly signed, comes back: refused, also for a client that
    // still runs a version below it, and the record keeps the newer time.
    std::fs::write(&manifest, &old).unwrap();
    std::fs::write(format!("{manifest}.minisig"), &old_sig).unwrap();
    let e = update::check(&manifest, &r.pk(), "0.1.0", &[&seen])
        .await
        .unwrap_err();
    assert!(e.contains("older than one this client already took"), "{e}");
    assert_eq!(std::fs::read_to_string(&seen).unwrap().trim(), "2000");
    // A manifest without a release time is not taken at all.
    let bare = json!({"version": "0.4.0", "artifacts": {}}).to_string();
    std::fs::write(&manifest, &bare).unwrap();
    std::fs::write(
        format!("{manifest}.minisig"),
        r.key.sign(bare.as_bytes(), "file:manifest.json"),
    )
    .unwrap();
    assert!(check(&manifest, &r.pk(), "0.1.0").await.is_err());
}
