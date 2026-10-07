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
            // The token stays in the test's own files, out of the machine's
            // Credential Manager (the Windows default falls back to the file).
            .env("PITHAGORAS_SYNC_NO_KEYRING", "1")
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

/// Whether process `pid` runs, as `tasklist` sees it.
fn alive(pid: u32) -> bool {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).contains(&format!("\"{pid}\""))
}

/// Polls `f` for up to `WAIT` until it gives something.
async fn until<T>(mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = tokio::time::Instant::now() + WAIT;
    while tokio::time::Instant::now() < deadline {
        if let Some(v) = f() {
            return Some(v);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
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
    // The client reports the folder in the portal's form (`--json` shows it
    // so), but `status` for the owner writes it as `folder list` does, from
    // the config: `C:\...`, not `/c/...`.
    assert_eq!(status["folders"][0]["path"], env.p("home/proj"));
    let listed = env.ok(&["folder", "list"]).await;
    let text = env.ok(&["status"]).await;
    let line = text
        .lines()
        .find(|l| l.starts_with("Folder:"))
        .unwrap_or_else(|| panic!("{text}"));
    let shown = line.trim_start_matches("Folder:").trim();
    let shown = shown.split(" (").next().unwrap();
    assert!(
        shown.as_bytes()[1..3] == *b":\\",
        "a drive path, not the wire form: {line}"
    );
    assert!(
        listed.to_lowercase().contains(&shown.to_lowercase()),
        "{line}\n{listed}"
    );
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
    // Asked because Windows has no Landlock at all, not because of a kernel.
    let asked = dl
        .notification("approval.requested", WAIT)
        .await
        .expect("the portal hears of the approval");
    let reasons = asked["reasons"].to_string();
    assert!(reasons.contains("Windows has no Landlock"), "{reasons}");
    assert!(!reasons.contains("kernel"), "{reasons}");
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
    let log = std::fs::read_to_string(env.root.join("daemon.log")).unwrap();
    assert!(!log.contains('\x1b'), "{log}");
    assert_eq!(
        log.contains("running as an elevated administrator"),
        elevated(),
        "{log}"
    );

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

    // A process the shell leaves in the background outlives the shell (decision
    // 12), and dies when the connection ends.
    let pid_file = env.root.join("home/proj/bg.pid");
    let cmd = format!(
        "Start-Process -WindowStyle Hidden powershell -ArgumentList '-NoProfile','-Command','Set-Content -LiteralPath \"{}\" $PID; Start-Sleep 120'; Write-Output started",
        pid_file.display()
    );
    let (out, exit) = exec(&dl, 8, &cmd, &env.p("home/proj")).await;
    assert!(out.contains("started"), "{out}");
    assert_eq!(exit["code"], 0);
    let pid = until(|| {
        std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
    })
    .await
    .expect("the background process did not start");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(alive(pid), "the background process died with its shell");
    dl.close(1000, "the portal goes away").await;
    assert!(
        until(|| (!alive(pid)).then_some(())).await.is_some(),
        "the background process outlived the connection"
    );
    let dl = mock.next_device(WAIT).await.expect("reconnects");

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

    // The client killed while a detached process runs: the job dies with it.
    let flag = env.root.join("home/proj/outlived-the-client");
    let cmd = format!(
        "Start-Process -WindowStyle Hidden powershell -ArgumentList '-NoProfile','-Command','Start-Sleep 6; Set-Content \"{}\" x'; Write-Output started; Start-Sleep 60",
        flag.display()
    );
    dl.call(
        "exec.start",
        json!({"stream": 7, "command": cmd, "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    stop(daemon).await;
    drop(dl);
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(!flag.exists(), "the detached process outlived the client");
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

/// `uninstall --purge` on Windows: the running client is stopped first, the
/// files under the profile folders go, the program and what is next to its
/// folders stay, and the `.old` copy an update left goes. A second run finds
/// nothing. Skipped where a real logon task exists, which the purge would end
/// and delete.
#[tokio::test(flavor = "multi_thread")]
async fn windows_purge_removes_what_the_client_left_but_the_program() {
    let task = std::process::Command::new("schtasks")
        .args(["/Query", "/TN", "Pithagoras Sync"])
        .output()
        .unwrap();
    if task.status.success() {
        eprintln!("skipped: this machine has a real Pithagoras Sync logon task");
        return;
    }
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE5678".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE5678"), "--name", "winpurge"])
        .await;
    if elevated() {
        env.ok(&["config", "set", "policy.privilege.allow_root", "true"])
            .await;
    }
    let config = env.home.join("AppData/Roaming/pithagoras-sync");
    if elevated() {
        // An administrator's ssh session is elevated: the purge refuses it before
        // it changes anything, and the rest runs from a normal process only.
        let out = env
            .cmd(&["uninstall", "--purge", "--yes"])
            .output()
            .await
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{err}");
        assert!(err.contains("not an elevated one"), "{err}");
        assert!(config.join("token").exists() || config.join("config.toml").exists());
        return;
    }
    let state = env.home.join("AppData/Local/pithagoras-sync");
    std::fs::create_dir_all(&state).unwrap();
    for f in ["client.log", "update-released", "logon-task.xml"] {
        std::fs::write(state.join(f), "1").unwrap();
    }
    // Spelled as the client builds it from LOCALAPPDATA, for the output below.
    let programs = env
        .home
        .join("AppData/Local")
        .join(r"Programs\pithagoras-sync");
    std::fs::create_dir_all(&programs).unwrap();
    let program = programs.join("pithagoras-sync.exe");
    let old = programs.join("pithagoras-sync.exe.old");
    std::fs::write(&program, "installed").unwrap();
    std::fs::write(&old, "replaced").unwrap();
    let other = env.home.join("AppData/Roaming/other.txt");
    std::fs::write(&other, "keep").unwrap();
    let daemon = env.start();
    mock.next_device(WAIT).await.expect("the client connects");
    let pid = daemon.id().unwrap();

    let out = env.ok(&["uninstall", "--purge", "--print"]).await;
    assert!(
        out.contains(&format!("stop the running client (pid {pid})")),
        "{out}"
    );
    assert!(out.contains(&format!("remove {}", old.display())), "{out}");
    assert!(
        out.contains(&format!("The program itself stays: {}", program.display())),
        "{out}"
    );
    assert!(out.contains("Remove-Item -LiteralPath"), "{out}");
    assert!(config.join("config.toml").exists() && old.exists() && alive(pid));

    let out = env.ok(&["uninstall", "--purge", "--yes"]).await;
    assert!(
        out.ends_with("Removed.\n") || out.ends_with("Removed.\r\n"),
        "{out}"
    );
    assert!(
        until(|| (!alive(pid)).then_some(())).await.is_some(),
        "the client was stopped"
    );
    assert!(!config.exists() && !state.exists(), "{out}");
    assert!(!old.exists());
    assert_eq!(std::fs::read_to_string(&program).unwrap(), "installed");
    assert_eq!(std::fs::read_to_string(&other).unwrap(), "keep");

    let out = env.ok(&["uninstall", "--purge", "--yes"]).await;
    assert!(out.starts_with("Nothing to remove."), "{out}");
    drop(daemon);
}

/// Windows has no sudo: the `sudo` commands say so and fail, and change nothing.
#[tokio::test(flavor = "multi_thread")]
async fn sudo_is_linux_only() {
    let env = Env::new();
    for args in [
        &["sudo", "status"][..],
        &["sudo", "activate", "--no-password"],
        &["sudo", "set", "--stdin"],
    ] {
        let out = env.cmd(args).output().await.unwrap();
        assert!(!out.status.success(), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("sudo access is Linux only"), "{args:?}: {err}");
    }
    assert!(!env.config().exists(), "nothing was written");
}
