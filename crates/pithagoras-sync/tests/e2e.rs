#![cfg(target_os = "linux")]
//! The real program, end to end: `pair` against the mock portal, `folder add`, the
//! client running in the background, commands through the real shim, `panic`,
//! `unlock`, the control socket and the audit log. HOME and the XDG directories
//! point into a temporary directory; nothing touches the real home.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use sync_testkit::{DeviceLink, MockOptions, MockPortal};
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_pithagoras-sync");
const WAIT: Duration = Duration::from_secs(15);

struct Env {
    _t: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl Env {
    fn new() -> Env {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let home = root.join("home");
        for d in ["home/proj", "home/.ssh", "outside", "tmp"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(home.join(".ssh/id_ed25519"), "secret").unwrap();
        Env { _t: t, root, home }
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

    fn start(&self) -> Child {
        let log = std::fs::File::create(self.root.join("daemon.log")).unwrap();
        self.cmd(&["run"]).stderr(log).spawn().unwrap()
    }

    fn config(&self) -> PathBuf {
        self.home.join(".config/pithagoras-sync/config.toml")
    }

    fn p(&self, rel: &str) -> String {
        self.root.join(rel).to_string_lossy().into_owned()
    }
}

async fn stop(mut child: Child) {
    if let Some(pid) = child.id() {
        // SAFETY: plain kill(2) on our own child.
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    }
    let status = tokio::time::timeout(WAIT, child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(
        status.success(),
        "the client exits cleanly on SIGTERM: {status}"
    );
}

fn alive(pid: u32) -> bool {
    // A zombie no longer counts.
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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn read_pid(path: &Path) -> u32 {
    for _ in 0..100 {
        if let Ok(s) = std::fs::read_to_string(path)
            && let Ok(p) = s.trim().parse()
        {
            return p;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no pid in {}", path.display());
}

/// Runs a command through the portal and returns (output, exit notification).
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
    assert_eq!(exit["stream"], stream);
    (
        String::from_utf8_lossy(&dl.stream_data(stream)).into_owned(),
        exit,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn pair_run_exec_panic_unlock() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE1234".into()],
    })
    .await;

    // Pair and grant a folder, as the README says.
    let out = env
        .ok(&["pair", &mock.pair_uri("CODE1234"), "--name", "testbox"])
        .await;
    assert!(out.contains("Paired with"), "{out}");
    let token = env.home.join(".config/pithagoras-sync/token");
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&token).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let cfg = std::fs::read_to_string(env.config()).unwrap();
    assert!(cfg.contains("profile = \"headless\""), "{cfg}");
    assert!(
        !cfg.contains(&std::fs::read_to_string(&token).unwrap()),
        "the token stays out of the config"
    );
    env.ok(&["folder", "add", &env.p("home/proj"), "--rw"])
        .await;

    let daemon = env.start();
    let dl = mock.next_device(WAIT).await.expect("the client connects");
    assert_eq!(dl.hello["shell"], "bash");
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    assert_eq!(status["link"]["state"], "connected");
    assert_eq!(status["mode"], "folders");
    assert_eq!(status["name"], "testbox");

    // A command in the granted folder: output, exit code, a scrubbed environment.
    let (out, exit) = exec(&dl, 1, "echo hello; env; exit 3", &env.p("home/proj")).await;
    assert!(out.starts_with("hello\n"), "{out}");
    assert!(!out.contains("PORTAL_"), "{out}");
    assert!(!out.contains("must-not-leak"), "{out}");
    assert_eq!(exit["code"], 3);

    // Outside the folders: refused before anything runs.
    let e = dl
        .call(
            "exec.start",
            json!({"stream": 2, "command": "true", "cwd": env.p("outside"), "ctx": {"chat": "c1"}}),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, sync_proto::code::DENIED);

    // With Landlock (kernel 5.13+), the shell writes only inside its folders.
    if status["landlock"] == true {
        let cmd = format!(
            "touch {}/inside.txt; touch {}/escaped.txt; echo done",
            env.p("home/proj"),
            env.p("outside")
        );
        let (out, _) = exec(&dl, 3, &cmd, &env.p("home/proj")).await;
        assert!(out.contains("done"), "{out}");
        assert!(env.root.join("home/proj/inside.txt").exists());
        assert!(!env.root.join("outside/escaped.txt").exists(), "{out}");
    }

    // panic while a detached child runs: the link closes, the child dies.
    let pidfile = env.root.join("home/proj/bg.pid");
    let cmd = format!("setsid sleep 300 & echo $! > {}; wait", pidfile.display());
    dl.call(
        "exec.start",
        json!({"stream": 4, "command": cmd, "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
    )
    .await
    .unwrap();
    let bg = read_pid(&pidfile).await;
    assert!(alive(bg));
    env.ok(&["panic"]).await;
    assert_eq!(dl.closed(WAIT).await.unwrap().0, 1000);
    assert!(gone(bg).await, "panic kills setsid children");
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    assert_eq!(status["paused"], true);
    assert!(
        mock.next_device(Duration::from_millis(1500))
            .await
            .is_none()
    );

    // unlock (headless: the shell login is the authentication) reconnects.
    env.ok(&["unlock"]).await;
    let dl = mock
        .next_device(WAIT)
        .await
        .expect("reconnects after unlock");

    // A dropped connection kills what runs, too.
    let pidfile = env.root.join("home/proj/bg2.pid");
    let cmd = format!("setsid sleep 300 & echo $! > {}; wait", pidfile.display());
    dl.call(
        "exec.start",
        json!({"stream": 5, "command": cmd, "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
    )
    .await
    .unwrap();
    let bg = read_pid(&pidfile).await;
    dl.close(1000, "portal restart").await;
    assert!(gone(bg).await, "a disconnect kills setsid children");
    let dl = mock
        .next_device(WAIT)
        .await
        .expect("reconnects with backoff");

    // The local audit log has the decisions and the exits, but no file contents.
    let audit =
        std::fs::read_to_string(env.home.join(".local/state/pithagoras-sync/audit.jsonl")).unwrap();
    assert!(audit.contains("\"decision\":\"denied\""), "{audit}");
    assert!(audit.contains("\"tool\":\"exit\""), "{audit}");
    assert!(audit.contains("\"decision\":\"paused\""), "{audit}");

    drop(dl);
    stop(daemon).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_the_client_runs_cannot_change_its_policy() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE5678".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE5678")]).await;
    env.ok(&["folder", "add", &env.p("home/proj"), "--rw"])
        .await;
    // The owner allows an unconfined shell, so the program itself is reachable from
    // a command; the client still refuses to take orders from it.
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
    let dl = mock.next_device(WAIT).await.unwrap();

    let me = |args: &str| {
        format!(
            "HOME={h} XDG_CONFIG_HOME={h}/.config XDG_STATE_HOME={h}/.local/state {BIN} {args} </dev/null; echo \"exit=$?\"",
            h = env.home.display()
        )
    };
    let (out, _) = exec(&dl, 1, &me("mode full"), &env.p("home/proj")).await;
    assert!(out.contains("cannot come from commands"), "{out}");
    assert!(out.contains("exit=1"), "{out}");
    let (out, _) = exec(&dl, 2, &me("folder add / --rw"), &env.p("home/proj")).await;
    assert!(out.contains("exit=1"), "{out}");
    let cfg = std::fs::read_to_string(env.config()).unwrap();
    assert!(cfg.contains("mode = \"folders\""), "{cfg}");
    assert!(!cfg.contains("path = \"/\""), "{cfg}");
    // Asking the socket directly: unlock and reload are refused, status works.
    let (out, _) = exec(&dl, 3, &me("status --json"), &env.p("home/proj")).await;
    assert!(out.contains("\"mode\""), "{out}");
    // The socket itself refuses reload from a command (python3 talks to it here,
    // bypassing the CLI's own check).
    if std::process::Command::new("python3")
        .arg("-V")
        .output()
        .is_ok()
    {
        // The path is put together inside python: a command naming the client's
        // own directory would already be stopped by the protected-path hint.
        let py = r#"python3 -c 'import os, socket; p = os.path.join(os.environ["HOME"], ".local", "state", "pithagoras-" + "sync", "run", "control.sock"); s = socket.socket(socket.AF_UNIX); s.connect(p); s.sendall(b"{\"cmd\":\"reload\"}\n"); print(s.recv(4096).decode())'"#;
        let (out, _) = exec(&dl, 5, py, &env.p("home/proj")).await;
        assert!(out.contains("cannot unlock or reload"), "{out}");
    }
    // panic is allowed from anywhere: it only takes rights away. It also kills the
    // command that asked, so no exec.exit comes; the link just closes.
    dl.call(
        "exec.start",
        json!({"stream": 4, "command": me("panic"), "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
    )
    .await
    .unwrap();
    assert_eq!(dl.closed(WAIT).await.unwrap().0, 1000);
    stop(daemon).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn install_print_and_toggle() {
    let env = Env::new();
    let out = env.ok(&["install", "--print"]).await;
    assert!(
        out.contains(".config/systemd/user/pithagoras-sync.service"),
        "{out}"
    );
    assert!(out.contains("systemctl --user enable --now"), "{out}");
    // Nothing was written.
    assert!(!env.home.join(".config/systemd").exists());
    let out = env.cmd(&["toggle"]).output().await.unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = env.cmd(&["status"]).output().await.unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stdout).contains("not running"));
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_to_run_without_its_control_socket() {
    // Without the socket, `panic` could not reach the client: it must not start.
    let env = Env::new();
    let state = env.home.join(".local/state/pithagoras-sync");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("run"), "not a directory").unwrap();
    let out = tokio::time::timeout(WAIT, env.cmd(&["run"]).output())
        .await
        .expect("the client gives up instead of running")
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no control socket"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
