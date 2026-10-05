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
    env.ok(&["folder", "add", &env.p("home/proj"), "--rw", "--exec"])
        .await;
    // Ask is the default, headless too; this test works in Folders mode.
    env.ok(&["mode", "folders"]).await;

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

    // Ask mode: the portal hears of the approval, the owner answers on the device.
    env.ok(&["mode", "ask"]).await;
    let pending = dl
        .start_call(
            "exec.start",
            json!({"stream": 6, "command": "echo approved-run", "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
        )
        .await;
    let asked = dl
        .notification("approval.requested", WAIT)
        .await
        .expect("the portal hears of the approval");
    assert_eq!(asked["target"], "echo approved-run");
    let listed: Value = serde_json::from_str(&env.ok(&["approvals", "--json"]).await).unwrap();
    let id = listed[0]["id"].as_u64().unwrap();
    assert_eq!(asked["id"], id);
    let out = env.ok(&["approvals"]).await;
    assert!(out.contains("echo approved-run"), "{out}");
    env.ok(&["approve", &id.to_string()]).await;
    tokio::time::timeout(WAIT, pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let exit = dl.notification("exec.exit", WAIT).await.unwrap();
    assert_eq!(exit["stream"], 6);
    assert!(String::from_utf8_lossy(&dl.stream_data(6)).contains("approved-run"));
    let resolved = dl.notification("approval.resolved", WAIT).await.unwrap();
    assert_eq!(
        (&resolved["by"], &resolved["answer"]),
        (&json!("device"), &json!("once"))
    );
    // Denied on the device: the call fails, nothing runs.
    let pending = dl
        .start_call(
            "exec.start",
            json!({"stream": 7, "command": "touch denied-run", "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
        )
        .await;
    let mut id = None;
    for _ in 0..100 {
        let listed: Value = serde_json::from_str(&env.ok(&["approvals", "--json"]).await).unwrap();
        if let Some(i) = listed[0]["id"].as_u64() {
            id = Some(i);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    env.ok(&["deny", &id.unwrap().to_string()]).await;
    let e = tokio::time::timeout(WAIT, pending).await.unwrap().unwrap();
    assert_eq!(e.unwrap_err().code, sync_proto::code::DENIED);
    assert!(!env.root.join("home/proj/denied-run").exists());

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
    env.ok(&["folder", "add", &env.p("home/proj"), "--rw", "--exec"])
        .await;
    env.ok(&["mode", "folders"]).await;
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
    for (i, args) in [
        "config set policy.mode full",
        "config set portal_policy write",
        "approvals",
        "approve 1",
        "deny 1",
        "secret set elevation --stdin",
        "secret clear elevation",
        "update --manifest /nowhere/manifest.json",
    ]
    .iter()
    .enumerate()
    {
        let (out, _) = exec(&dl, 10 + i as u32, &me(args), &env.p("home/proj")).await;
        assert!(out.contains("exit=1"), "{args}: {out}");
        if *args != "config set policy.mode full" {
            assert!(out.contains("cannot come from commands"), "{args}: {out}");
        }
    }
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
        for (i, cmd) in [
            r#"{\"cmd\":\"reload\"}"#,
            r#"{\"cmd\":\"answer\",\"id\":1,\"answer\":\"once\"}"#,
            r#"{\"cmd\":\"approvals\"}"#,
            r#"{\"cmd\":\"secret_set\",\"name\":\"elevation\",\"value\":\"x\"}"#,
            r#"{\"cmd\":\"restart\"}"#,
        ]
        .iter()
        .enumerate()
        {
            let py = format!(
                r#"python3 -c 'import os, socket; p = os.path.join(os.environ["HOME"], ".local", "state", "pithagoras-" + "sync", "run", "control.sock"); s = socket.socket(socket.AF_UNIX); s.connect(p); s.sendall(b"{cmd}\n"); print(s.recv(4096).decode())'"#
            );
            let (out, _) = exec(&dl, 20 + i as u32, &py, &env.p("home/proj")).await;
            assert!(out.contains("cannot change"), "{cmd}: {out}");
        }
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

#[tokio::test(flavor = "multi_thread")]
async fn the_first_change_on_a_desktop_makes_a_desktop_config() {
    // `folder add` before `pair` on a desktop must not write a headless config,
    // and on a desktop it needs the owner's password in a terminal (none here).
    let env = Env::new();
    let out = env
        .cmd(&["folder", "add", &env.p("home/proj")])
        .env("WAYLAND_DISPLAY", "wayland-0")
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("terminal"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!env.config().exists());
    let out = env
        .cmd(&["mode"])
        .env("WAYLAND_DISPLAY", "wayland-0")
        .output()
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ask"));
}

/// Starts a command, answers its approval as the portal (Allow once), and waits for
/// its end.
async fn exec_approved(dl: &DeviceLink, stream: u32, command: &str, cwd: &str) -> (String, Value) {
    let pending = dl
        .start_call(
            "exec.start",
            json!({"stream": stream, "command": command, "cwd": cwd, "ctx": {"chat": "c1"}}),
        )
        .await;
    let asked = dl
        .notification("approval.requested", WAIT)
        .await
        .unwrap_or_else(|| panic!("no approval asked for {command:?}"));
    dl.call(
        "approval.answer",
        json!({"id": asked["id"], "answer": "once"}),
    )
    .await
    .unwrap();
    tokio::time::timeout(WAIT, pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap_or_else(|e| panic!("{command}: {e}"));
    let exit = dl.notification("exec.exit", WAIT).await.unwrap();
    assert_eq!(exit["stream"], stream);
    (
        String::from_utf8_lossy(&dl.stream_data(stream)).into_owned(),
        exit,
    )
}

/// The password the fake sudo takes: with a quote, a backslash and a space, so it
/// looks different inside JSON and a shell would split it.
const PW: &str = "Elev8-pw \"q\\z";

/// A stand-in for sudo: takes the password from stdin like `sudo -S`, compares
/// its hash, then runs the command as is (the test machine is never touched as
/// root).
fn fake_sudo(env: &Env) -> PathBuf {
    let mut c = std::process::Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    c.stdin.take().unwrap().write_all(PW.as_bytes()).unwrap();
    let out = c.wait_with_output().unwrap();
    let hash = String::from_utf8_lossy(&out.stdout)
        .split(' ')
        .next()
        .unwrap()
        .to_string();
    let path = env.root.join("fakesudo");
    std::fs::write(
        &path,
        format!(
            r#"#!/bin/sh
case "$1" in -n) echo "sudo: a password is required" >&2; exit 1;; esac
while [ "$1" != "--" ]; do shift; done; shift
# A sudoers rule without a password: sudo leaves stdin alone.
[ -e "$0.nopasswd" ] && FAKE_ROOT=1 exec "$@"
IFS= read -r pw || {{ echo "sudo: no password" >&2; exit 1; }}
h=$(printf '%s' "$pw" | sha256sum); pw=
[ "${{h%% *}}" = "{hash}" ] || {{ echo "sudo: 1 incorrect password attempt" >&2; exit 1; }}
FAKE_ROOT=1 exec "$@"
"#
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Whether any process's command line or environment holds `needle`.
fn in_proc(needle: &[u8]) -> Option<String> {
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        for f in ["cmdline", "environ"] {
            if let Ok(b) = std::fs::read(e.path().join(f))
                && b.windows(needle.len()).any(|w| w == needle)
            {
                return Some(format!("{}/{f}", e.path().display()));
            }
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
async fn the_elevation_password_reaches_sudo_and_nothing_else() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE1234".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE1234"), "--name", "elev"])
        .await;
    let sudo = fake_sudo(&env);
    env.ok(&["folder", "add", &env.p("home/proj"), "--rw", "--exec"])
        .await;
    env.ok(&["config", "set", "policy.privilege.elevation", "sudo"])
        .await;
    env.ok(&[
        "config",
        "set",
        "policy.privilege.sudo_path",
        &sudo.to_string_lossy(),
    ])
    .await;
    env.ok(&["mode", "full"]).await;
    // Without the patterns' questions, only root's own question asks.
    env.ok(&["config", "set", "policy.full.pattern_prompts", "false"])
        .await;
    let daemon = env.start();
    let dl = mock.next_device(WAIT).await.expect("the client connects");
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    let proj = env.p("home/proj");

    if status["cgroups"] != true {
        // Without a cgroup panic could not stop root's commands: refused.
        let e = dl
            .call(
                "exec.start",
                json!({"stream": 1, "command": "sudo true", "cwd": proj, "ctx": {"chat": "c1"}}),
            )
            .await;
        eprintln!("  (no delegated cgroup here: {e:?})");
        drop(dl);
        stop(daemon).await;
        return;
    }
    assert!(
        status["elevation"]
            .as_str()
            .unwrap()
            .starts_with("sudo, no password"),
        "{status}"
    );

    // Not on a command line: `--stdin` (or the terminal) only.
    let mut set = env.cmd(&["secret", "set", "elevation", "--stdin"]);
    set.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = set.spawn().unwrap();
    {
        use tokio::io::AsyncWriteExt;
        let mut i = child.stdin.take().unwrap();
        i.write_all(format!("{PW}\n").as_bytes()).await.unwrap();
    }
    let out = child.wait_with_output().await.unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    assert!(
        status["elevation"]
            .as_str()
            .unwrap()
            .starts_with("sudo, password set (kept in memory)"),
        "{status}"
    );

    // Watch every process's argv and environment while elevated commands run.
    let stop_watch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher = {
        let stop_watch = stop_watch.clone();
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            while !stop_watch.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some(w) = in_proc(PW.as_bytes()) {
                    seen.push(w);
                }
            }
            seen
        })
    };

    // Root's command asks even in Full mode; it runs through sudo once allowed.
    // What it can see (environment, stdin, ps, every /proc/*/cmdline and environ)
    // goes to files, which the scrubbing of output cannot hide.
    let dump = env.root.join("home/proj/dump");
    std::fs::create_dir_all(&dump).unwrap();
    let cmd = format!(
        "sudo env > {d}/env; cat > {d}/stdin; ps -eo args > {d}/ps; \
         cat /proc/[0-9]*/cmdline > {d}/cmdline 2>/dev/null; \
         cat /proc/[0-9]*/environ > {d}/environ 2>/dev/null; echo ran-as-$FAKE_ROOT",
        d = dump.display()
    );
    let (out, exit) = exec_approved(&dl, 2, &cmd, &proj).await;
    assert_eq!(exit["code"], 0, "{out}");
    assert!(out.contains("ran-as-1"), "it ran through sudo: {out}");
    assert!(
        std::fs::read_to_string(dump.join("env"))
            .unwrap()
            .contains("FAKE_ROOT=1")
    );
    assert!(
        std::fs::read_to_string(dump.join("ps"))
            .unwrap()
            .lines()
            .count()
            > 2
    );
    for f in ["env", "stdin", "ps", "cmdline", "environ"] {
        let b = std::fs::read(dump.join(f)).unwrap();
        assert!(
            !b.windows(PW.len()).any(|w| w == PW.as_bytes()),
            "{f} holds the password"
        );
    }
    assert_eq!(std::fs::read(dump.join("stdin")).unwrap(), b"");

    // A file holding the password: its output is scrubbed, elevated or not.
    std::fs::write(env.root.join("home/proj/pw.txt"), format!("x{PW}y\n")).unwrap();
    let (out, _) = exec_approved(&dl, 3, "sudo cat pw.txt", &proj).await;
    assert_eq!(out, "x[redacted]y\n");
    let (out, _) = exec(&dl, 4, "cat pw.txt; echo; cat pw.txt", &proj).await;
    assert_eq!(out, "x[redacted]y\n\nx[redacted]y\n");
    // Where sudo asks no password, the command still finds nothing on stdin.
    let nopasswd = env.root.join("fakesudo.nopasswd");
    std::fs::write(&nopasswd, "").unwrap();
    let cmd = format!("sudo cat > {}/stdin2", dump.display());
    exec_approved(&dl, 11, &cmd, &proj).await;
    std::fs::remove_file(&nopasswd).unwrap();
    assert_eq!(std::fs::read(dump.join("stdin2")).unwrap(), b"");
    // sudo's own options are not taken.
    let e = dl
        .call(
            "exec.start",
            json!({"stream": 6, "command": "sudo -u nobody true", "cwd": proj, "ctx": {"chat": "c1"}}),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, sync_proto::code::DENIED);

    stop_watch.store(true, std::sync::atomic::Ordering::Relaxed);
    let seen = watcher.join().unwrap();
    assert!(seen.is_empty(), "the password showed in {seen:?}");

    // Nor does a command naming it carry it back to the portal (in the approval
    // request) or into the audit log. (The portal sent it in the command, so it
    // is in that command's argv; the watch above has ended.)
    let (out, _) = exec_approved(&dl, 5, &format!("sudo printf %s '{PW}' | wc -c"), &proj).await;
    assert_eq!(out.trim(), PW.len().to_string());

    // A wrong password: sudo refuses, the command does not run.
    let mut set = env.cmd(&["secret", "set", "elevation", "--stdin"]);
    set.stdin(Stdio::piped());
    let mut child = set.spawn().unwrap();
    {
        use tokio::io::AsyncWriteExt;
        let mut i = child.stdin.take().unwrap();
        i.write_all(b"wrong one\n").await.unwrap();
    }
    assert!(child.wait().await.unwrap().success());
    let (out, exit) = exec_approved(&dl, 7, "sudo touch wrong-ran", &proj).await;
    assert_ne!(exit["code"], 0, "{out}");
    assert!(out.contains("incorrect password"), "{out}");
    assert!(!env.root.join("home/proj/wrong-ran").exists());

    // panic forgets a password kept in memory.
    env.ok(&["panic"]).await;
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    assert!(
        status["elevation"]
            .as_str()
            .unwrap()
            .contains("no password"),
        "{status}"
    );
    env.ok(&["unlock"]).await;
    let dl = mock.next_device(WAIT).await.unwrap();

    // Kept in a file: 0600, and no tool reaches it, whatever the mode.
    env.ok(&["config", "set", "policy.privilege.secret_storage", "file"])
        .await;
    let mut set = env.cmd(&["secret", "set", "elevation", "--stdin"]);
    set.stdin(Stdio::piped());
    let mut child = set.spawn().unwrap();
    {
        use tokio::io::AsyncWriteExt;
        let mut i = child.stdin.take().unwrap();
        i.write_all(format!("{PW}\n").as_bytes()).await.unwrap();
    }
    assert!(child.wait().await.unwrap().success());
    let stored = env.home.join(".config/pithagoras-sync/elevation.secret");
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&stored).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let e = dl
        .call(
            "fs.read",
            json!({"stream": 8, "path": stored.to_string_lossy(), "ctx": {"chat": "c1"}}),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, sync_proto::code::DENIED);
    let (out, _) = exec_approved(&dl, 9, "sudo cat pw.txt", &proj).await;
    assert_eq!(out, "x[redacted]y\n");
    drop(dl);
    stop(daemon).await;

    // It comes back with the client.
    let daemon = env.start();
    let dl = mock.next_device(WAIT).await.unwrap();
    let (out, exit) = exec_approved(&dl, 10, "sudo echo back-$FAKE_ROOT", &proj).await;
    assert_eq!((out.as_str(), &exit["code"]), ("back-1\n", &json!(0)));
    env.ok(&["secret", "clear", "elevation"]).await;
    assert!(!stored.exists());
    drop(dl);
    stop(daemon).await;

    // Never in the audit log, the client's log or anything the portal received,
    // as written or as JSON escapes it.
    let escaped = serde_json::to_string(PW).unwrap();
    let escaped = &escaped[1..escaped.len() - 1];
    let audit =
        std::fs::read_to_string(env.home.join(".local/state/pithagoras-sync/audit.jsonl")).unwrap();
    let log = std::fs::read_to_string(env.root.join("daemon.log")).unwrap();
    let transcript = mock.transcript();
    assert!(audit.contains("[redacted]"), "{audit}");
    for (what, text) in [
        ("audit", audit.as_bytes()),
        ("log", log.as_bytes()),
        ("portal", &transcript[..]),
    ] {
        for needle in [PW, escaped] {
            assert!(
                !text.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "the {what} holds the password"
            );
        }
    }
    assert!(
        String::from_utf8_lossy(&transcript).contains("approval.requested"),
        "the transcript has the traffic"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn elevated_commands_are_refused_under_landlock() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE1234".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE1234"), "--name", "elev"])
        .await;
    let sudo = fake_sudo(&env);
    env.ok(&["folder", "add", &env.p("home/proj"), "--rw", "--exec"])
        .await;
    env.ok(&["config", "set", "policy.privilege.elevation", "sudo"])
        .await;
    env.ok(&[
        "config",
        "set",
        "policy.privilege.sudo_path",
        &sudo.to_string_lossy(),
    ])
    .await;
    env.ok(&["mode", "folders"]).await;
    let daemon = env.start();
    let dl = mock.next_device(WAIT).await.unwrap();
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    if status["landlock"] == true {
        let e = dl
            .call(
                "exec.start",
                json!({"stream": 1, "command": "sudo true", "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
            )
            .await
            .unwrap_err();
        assert_eq!(e.code, sync_proto::code::DENIED);
        assert!(e.message.contains("Landlock"), "{}", e.message);
    }
    drop(dl);
    stop(daemon).await;
}
