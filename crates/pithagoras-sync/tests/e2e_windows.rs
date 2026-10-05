#![cfg(windows)]
//! The real program on Windows, end to end against the mock portal: `pair`, `folder
//! add`, the client in the background, the control pipe, PowerShell commands in Job
//! Objects, `panic` and `unlock`. The profile folders point into a temporary folder.
//! Runs on the Windows test VM (`scripts/windows-vm-test.sh`), not in CI.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use sync_testkit::{DeviceLink, MockOptions, MockPortal};
use tokio::process::{Child, Command};

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
const WAIT: Duration = Duration::from_secs(20);

struct Env {
    _t: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new() -> Env {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let root = PathBuf::from(sync_policy::paths::win::strip_verbatim(
            &root.to_string_lossy(),
        ));
        let home = root.join("home");
        for d in [
            "home/proj",
            "home/.ssh",
            "home/AppData/Roaming",
            "home/AppData/Local",
            "outside",
            "tmp",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(home.join(".ssh/id_ed25519"), "secret").unwrap();
        Env { _t: t, root, home }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        // Not env_clear: PowerShell needs SystemRoot, PATHEXT and friends.
        c.args(args)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", self.home.join("AppData/Local"))
            .env("TEMP", self.root.join("tmp"))
            .env("TMP", self.root.join("tmp"))
            // A secret in the client's own environment must not reach commands.
            .env("PORTAL_SECRET", "must-not-leak")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        c
    }

    async fn ok(&self, args: &[&str]) -> String {
        let out = self.cmd(args).output().await.unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    async fn status(&self) -> Value {
        serde_json::from_str(&self.ok(&["status", "--json"]).await).unwrap()
    }

    fn start(&self) -> Child {
        let log = std::fs::File::create(self.root.join("daemon.log")).unwrap();
        self.cmd(&["run"]).stderr(log).spawn().unwrap()
    }

    fn config(&self) -> PathBuf {
        self.home
            .join("AppData/Roaming/pithagoras-sync/config.toml")
    }

    /// A path as the portal sends it: `/c/...`.
    fn p(&self, rel: &str) -> String {
        sync_policy::paths::to_wire(&self.root.join(rel))
    }
}

/// Whether this test runs elevated: an administrator's ssh session on Windows always
/// is (the High mandatory level, S-1-16-12288).
fn elevated() -> bool {
    let out = std::process::Command::new("whoami")
        .arg("/groups")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).contains("S-1-16-12288")
}

async fn stop(mut child: Child) {
    child.kill().await.unwrap();
}

async fn exec(dl: &DeviceLink, stream: u32, command: &str, cwd: &str) -> (String, Value) {
    dl.call(
        "exec.start",
        json!({"stream": stream, "command": command, "cwd": cwd, "ctx": {"chat": "c1"}}),
    )
    .await
    .unwrap_or_else(|e| panic!("{command}: {e}"));
    let Some(exit) = dl.notification("exec.exit", WAIT).await else {
        panic!(
            "no exec.exit for {command:?}; output so far: {:?}",
            String::from_utf8_lossy(&dl.stream_data(stream))
        );
    };
    (
        String::from_utf8_lossy(&dl.stream_data(stream)).into_owned(),
        exit,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn windows_pair_run_exec_panic_unlock() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE1234".into()],
    })
    .await;

    let out = env
        .ok(&["pair", &mock.pair_uri("CODE1234"), "--name", "winbox"])
        .await;
    assert!(out.contains("Paired with"), "{out}");
    let cfg = std::fs::read_to_string(env.config()).unwrap();
    assert!(cfg.contains("profile = \"headless\""), "{cfg}");
    let folder = env.root.join("home/proj");
    env.ok(&["folder", "add", &folder.to_string_lossy(), "--rw", "--exec"])
        .await;
    env.ok(&["mode", "folders"]).await;
    env.ok(&["config", "set", "policy.approvals.timeout_secs", "2"])
        .await;
    if elevated() {
        // The client refuses an elevated session until the owner allows it.
        let out = env.cmd(&["run"]).output().await.unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{err}");
        assert!(err.contains("elevated administrator"), "{err}");
        env.ok(&["config", "set", "policy.privilege.allow_root", "true"])
            .await;
    }

    // The default Folders shell has no Landlock on Windows, so it prompts, and
    // nobody answers: commands are denied after the timeout, files in the folder work.
    let daemon = env.start();
    let dl = mock.next_device(WAIT).await.expect("the client connects");
    let shell = dl.hello["shell"].as_str().unwrap().to_string();
    assert!(shell == "pwsh" || shell == "powershell", "{shell}");
    let status = env.status().await;
    assert_eq!(status["link"]["state"], "connected");
    assert_eq!(status["folders_shell"], "prompt");
    // The control pipe is this user's and SYSTEM's alone: no Everyone or anonymous
    // entry that would let another user hold its instances.
    // Built as the client builds it from APPDATA, which the name is a hash of.
    let pipe = sync_policy::config::Dirs {
        config: env.home.join("AppData/Roaming").join("pithagoras-sync"),
        state: PathBuf::new(),
        runtime: PathBuf::new(),
    }
    .socket();
    let name = pipe.file_name().unwrap().to_string_lossy().into_owned();
    let probe = format!(
        "$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', '{name}', 'InOut'); $c.Connect(5000); $c.GetAccessControl().Sddl"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &probe])
        .output()
        .unwrap();
    let sddl = String::from_utf8_lossy(&out.stdout);
    assert!(
        sddl.contains("D:P(A;;FA;;;SY)"),
        "{sddl} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!sddl.contains(";WD)") && !sddl.contains(";AN)"), "{sddl}");
    let e = dl
        .call(
            "exec.start",
            json!({"stream": 1, "command": "Write-Output hi", "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, sync_proto::code::DENIED, "{e:?}");
    std::fs::write(env.root.join("home/proj/a.txt"), "alpha").unwrap();
    dl.call(
        "fs.read",
        json!({"path": env.p("home/proj/a.txt"), "stream": 2, "ctx": {"chat": "c1"}}),
    )
    .await
    .unwrap();
    assert_eq!(dl.stream_data(2), b"alpha");
    for (path, stream) in [("outside", 3), ("home/.ssh/id_ed25519", 4)] {
        let e = dl
            .call(
                "fs.read",
                json!({"path": env.p(path), "stream": stream, "ctx": {"chat": "c1"}}),
            )
            .await
            .unwrap_err();
        assert_eq!(e.code, sync_proto::code::DENIED, "{path}");
    }
    // A native drive path is refused rather than guessed at.
    let native = env.root.join("home/proj/a.txt");
    let e = dl
        .call(
            "fs.stat",
            json!({"path": native.to_string_lossy(), "ctx": {"chat": "c1"}}),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, sync_proto::code::BAD_PATH);
    drop(dl);
    stop(daemon).await;

    // The owner lets the shell run unconfined.
    let cfg = std::fs::read_to_string(env.config()).unwrap();
    std::fs::write(
        env.config(),
        cfg.replace(
            "folders_shell = \"landlock\"",
            "folders_shell = \"unconfined\"",
        ),
    )
    .unwrap();
    let daemon = env.start();
    let dl = mock.next_device(WAIT).await.expect("reconnects");
    let (out, exit) = exec(
        &dl,
        5,
        "Write-Output hello; Get-ChildItem env: | Out-String -Width 400; exit 3",
        &env.p("home/proj"),
    )
    .await;
    assert!(out.contains("hello"), "{out}");
    assert!(!out.contains("PORTAL_"), "{out}");
    assert!(!out.contains("must-not-leak"), "{out}");
    assert_eq!(exit["code"], 3);

    // panic while a detached process runs: the link closes, the job dies with it.
    let flag = env.root.join("home/proj/still-running");
    let cmd = format!(
        "Start-Process -WindowStyle Hidden powershell -ArgumentList '-NoProfile','-Command','Start-Sleep 6; Set-Content \"{}\" x'; Write-Output started; Start-Sleep 60",
        flag.display()
    );
    dl.call(
        "exec.start",
        json!({"stream": 6, "command": cmd, "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    env.ok(&["panic"]).await;
    assert_eq!(dl.closed(WAIT).await.unwrap().0, 1000);
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(!flag.exists(), "the detached process outlived the panic");
    assert_eq!(env.status().await["paused"], true);

    env.ok(&["unlock"]).await;
    let dl = mock
        .next_device(WAIT)
        .await
        .expect("reconnects after unlock");
    drop(dl);
    stop(daemon).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn windows_install_print() {
    let env = Env::new();
    let out = env.ok(&["install", "--print"]).await;
    assert!(out.contains("schtasks"), "{out}");
    assert!(out.contains("pithagoras-sync.exe"), "{out}");
    assert!(
        !env.home
            .join("AppData/Local/Programs/pithagoras-sync")
            .exists()
    );
}
