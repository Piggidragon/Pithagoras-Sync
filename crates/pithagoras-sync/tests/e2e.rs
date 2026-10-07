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
    /// More variables every command gets (a private session bus).
    vars: Vec<(String, String)>,
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
        Env {
            _t: t,
            root,
            home,
            vars: Vec::new(),
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
            // A secret in the client's own environment must not reach commands.
            .env("PORTAL_SECRET", "must-not-leak")
            // The stand-in dialog programs (`fake_dialogs`) count as the
            // system's; the debug build alone reads this.
            .env("PITHAGORAS_SYNC_TEST_DIALOG_DIR", self.root.join("fakebin"))
            .envs(self.vars.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .kill_on_drop(true);
        // No keyring at all unless the test brings the fake one: without a bus
        // address zbus would find the real session bus of whoever runs this.
        if !self
            .vars
            .iter()
            .any(|(k, _)| k == "DBUS_SESSION_BUS_ADDRESS")
        {
            c.env("PITHAGORAS_SYNC_NO_KEYRING", "1");
        }
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
    assert_eq!(asked["cwd"], env.p("home/proj"));
    let listed: Value = serde_json::from_str(&env.ok(&["approvals", "--json"]).await).unwrap();
    let id = listed[0]["id"].as_u64().unwrap();
    assert_eq!(asked["id"], id);
    let out = env.ok(&["approvals"]).await;
    assert!(out.contains("echo approved-run"), "{out}");
    assert!(
        out.contains(&format!("in: {}", env.p("home/proj"))),
        "{out}"
    );
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
    // The client's log, written to a file, is plain text: no terminal colours.
    let log = std::fs::read_to_string(env.root.join("daemon.log")).unwrap();
    assert!(log.contains("started: profile"), "{log}");
    assert!(!log.contains('\x1b'), "{log}");
}

/// `folder list` shows a folder path as `status` does: a control character the
/// portal put there (`portal_policy = write`) is a visible escape, so it cannot
/// move the cursor and overwrite the line above.
#[tokio::test]
async fn folder_list_shows_control_characters_as_escapes() {
    let env = Env::new();
    let proj = env.p("home/proj");
    env.ok(&["folder", "add", &proj]).await;
    let cfg = std::fs::read_to_string(env.config()).unwrap();
    assert!(cfg.contains(&format!("\"{proj}\"")), "{cfg}");
    let forged = cfg.replace(&format!("\"{proj}\""), &format!("\"{proj}\\u001b[1A\""));
    std::fs::write(env.config(), forged).unwrap();
    let out = env.ok(&["folder", "list"]).await;
    assert!(!out.contains('\x1b'), "{out:?}");
    // The access spelled as in the config and `folder add`.
    assert!(out.contains(&format!("{proj}\\u{{1b}}[1A (ro)")), "{out:?}");
    let other = env.p("outside");
    let added = env.ok(&["folder", "add", &other, "--rw", "--exec"]).await;
    assert!(added.contains("(rw, commands run here)"), "{added:?}");
    let out = env.ok(&["folder", "list"]).await;
    assert!(out.contains(&format!("{other} (rw, exec)")), "{out:?}");
}

/// A step that may fail (`Action::Try`) shows the client's own note, not the
/// program's error text first (schtasks' "FEHLER: ..." on a German Windows).
/// Here a stand-in `systemctl` on PATH: nothing reaches the real systemd.
#[tokio::test]
async fn a_step_that_may_fail_shows_only_the_clients_note() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let bin = env.root.join("fakebin");
    std::fs::create_dir_all(&bin).unwrap();
    let systemctl = bin.join("systemctl");
    std::fs::write(
        &systemctl,
        "#!/bin/sh\ncase \"$2\" in disable) echo 'FEHLER: raw text of the program' >&2; exit 1;; esac\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = env
        .cmd(&["uninstall"])
        .env("PATH", path)
        .output()
        .await
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(!err.contains("FEHLER"), "{err}");
    assert!(
        err.contains("note: `systemctl --user disable --now"),
        "{err}"
    );
    assert!(err.contains("the unit was not enabled"), "{err}");
}

/// A `systemctl` and `loginctl` on PATH that write their arguments to
/// `systemctl.log` and succeed, but say no unit is active: nothing reaches the
/// real systemd. With the file `unit-state` in the test's root (two lines:
/// what `is-enabled` and `show -p ActiveState` say) they answer those as a
/// unit in that state. Returns the PATH to run with.
fn fake_systemd(env: &Env) -> String {
    use std::os::unix::fs::PermissionsExt;
    let bin = env.root.join("fakebin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = env.root.join("systemctl.log");
    let state = env.root.join("unit-state");
    for prog in ["systemctl", "loginctl"] {
        let p = bin.join(prog);
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"{prog} $*\" >> '{log}'\ncase \"$1\" in is-active) exit 3;; esac\n\
                 if [ -f '{state}' ]; then case \" $* \" in\n\
                 *' is-enabled '*) e=$(sed -n 1p '{state}'); echo \"$e\"; [ \"$e\" = enabled ]; exit;;\n\
                 *' ActiveState '*) sed -n 2p '{state}'; exit 0;;\n\
                 esac; fi\nexit 0\n",
                log = log.display(),
                state = state.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

/// `uninstall --purge` removes everything the client left but the program:
/// after a look (`--print`) and a refused confirmation nothing is gone; then
/// the running client is stopped first, and only its own files go, not the
/// files next to them. A second run finds nothing.
#[tokio::test(flavor = "multi_thread")]
async fn purge_removes_what_the_client_left_but_the_program() {
    let env = Env::new();
    let path = fake_systemd(&env);
    let run = |args: &[&str]| {
        let mut c = env.cmd(args);
        c.env("PATH", &path);
        c
    };
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE5678".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE5678"), "--name", "purgebox"])
        .await;
    env.ok(&["folder", "add", &env.p("home/proj")]).await;
    let config = env.home.join(".config/pithagoras-sync");
    let state = env.home.join(".local/state/pithagoras-sync");
    // What the client and `update` leave, and what `install` put in place.
    std::fs::create_dir_all(&state).unwrap();
    for f in [
        "client.log",
        "update-released",
        "update-released-0123456789abcdef",
    ] {
        std::fs::write(state.join(f), "1\n").unwrap();
    }
    let unit = env
        .home
        .join(".config/systemd/user/pithagoras-sync.service");
    let program = env.home.join(".local/bin/pithagoras-sync");
    for f in [&unit, &program] {
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, "installed").unwrap();
    }
    // Next to the client's folders, and not the client's.
    let others = [
        env.home.join(".config/other.toml"),
        env.home.join(".local/state/other.log"),
    ];
    for f in &others {
        std::fs::write(f, "keep").unwrap();
    }
    let daemon = env.start();
    mock.next_device(WAIT).await.expect("the client connects");
    let pid = daemon.id().unwrap();
    let everything = [
        config.join("config.toml"),
        config.join("token"),
        state.join("audit.jsonl"),
        state.join("client.log"),
        state.join("update-released"),
        state.join("update-released-0123456789abcdef"),
        state.join("run/control.sock"),
        unit.clone(),
    ];

    let out = run(&["uninstall", "--purge", "--print"])
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains(&format!("stop the running client (pid {pid})")),
        "{text}"
    );
    for f in &everything {
        assert!(text.contains(&format!("remove {}", f.display())), "{text}");
        assert!(f.exists(), "{}", f.display());
    }
    assert!(
        text.contains("remove the device in the portal as well"),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "The program itself stays: {}. Delete it with `rm {}`",
            program.display(),
            program.display()
        )),
        "{text}"
    );
    assert!(!text.contains("other"), "{text}");

    // No answer to the question (stdin is empty): nothing changes.
    let out = run(&["uninstall", "--purge"]).output().await.unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nothing changed."));
    assert!(everything.iter().all(|f| f.exists()));
    assert!(alive(pid));
    assert!(!env.root.join("systemctl.log").exists());

    let out = run(&["uninstall", "--purge", "--yes"])
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.ends_with("Removed.\n"), "{text}");
    assert!(gone(pid).await, "the client was stopped");
    assert!(!config.exists() && !state.exists(), "{text}");
    for f in &others {
        assert_eq!(std::fs::read_to_string(f).unwrap(), "keep");
    }
    assert_eq!(std::fs::read_to_string(&program).unwrap(), "installed");
    assert!(!unit.exists());
    let calls = std::fs::read_to_string(env.root.join("systemctl.log")).unwrap();
    let stop = calls.find("systemctl --user stop pithagoras-sync.service");
    let disable = calls.find("systemctl --user disable --now pithagoras-sync.service");
    assert!(stop.is_some() && stop < disable, "{calls}");

    let out = run(&["uninstall", "--purge", "--yes"])
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.starts_with("Nothing to remove.\n"), "{text}");
    assert!(text.contains("The program itself stays"), "{text}");
}

/// `uninstall --purge` with the unit's folder read-only, so it fails after the
/// stop while the unit is still there; `state` is what systemd says of the
/// unit before (`is-enabled`, then `ActiveState`), `client` whether a client
/// runs. Returns what it said on stderr and the systemctl calls after the
/// uninstall's `disable --now`.
async fn failed_purge(state: &str, client: bool) -> (String, String) {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let path = fake_systemd(&env);
    std::fs::write(env.root.join("unit-state"), state).unwrap();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE5678".into()],
    })
    .await;
    let daemon = if client {
        env.ok(&["pair", &mock.pair_uri("CODE5678"), "--name", "failpurge"])
            .await;
        let daemon = env.start();
        mock.next_device(WAIT).await.expect("the client connects");
        Some(daemon)
    } else {
        env.ok(&["mode", "ask"]).await;
        None
    };
    let unit = env
        .home
        .join(".config/systemd/user/pithagoras-sync.service");
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(&unit, "installed").unwrap();
    // The unit file cannot be removed: the uninstall fails after the stop.
    let folder = unit.parent().unwrap();
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o555)).unwrap();
    let out = env
        .cmd(&["uninstall", "--purge", "--yes"])
        .env("PATH", &path)
        .output()
        .await
        .unwrap();
    std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("Run this again"), "{err}");
    assert!(unit.exists());
    if let Some(d) = daemon {
        assert!(gone(d.id().unwrap()).await, "the client was stopped");
    }
    let calls = std::fs::read_to_string(env.root.join("systemctl.log")).unwrap();
    let disable = "systemctl --user disable --now pithagoras-sync.service\n";
    let after = calls
        .find(disable)
        .map(|i| calls[i + disable.len()..].to_string())
        .unwrap_or_else(|| panic!("no disable: {calls}"));
    (err, after)
}

/// A purge that fails while the unit is still there puts back what it
/// stopped, so the device is not left offline, and says so.
#[tokio::test(flavor = "multi_thread")]
async fn a_purge_that_fails_starts_the_unit_again() {
    if unsafe { libc::geteuid() } == 0 {
        // Root removes the unit file anyway.
        return;
    }
    let (err, after) = failed_purge("enabled\nactive\n", false).await;
    assert!(
        err.contains("The unit was switched on and started again."),
        "{err}"
    );
    assert_eq!(
        after,
        "systemctl --user enable pithagoras-sync.service\nsystemctl --user start pithagoras-sync.service\n"
    );
    // A client running beside a unit that was switched off and down: the
    // client comes back through the unit, which stays switched off.
    let (err, after) = failed_purge("disabled\ninactive\n", true).await;
    assert!(err.contains("The unit was started again."), "{err}");
    assert_eq!(after, "systemctl --user start pithagoras-sync.service\n");
}

/// A purge that fails switches on and starts nothing the owner had off: the
/// unit was switched off and no client ran, so it stays that way.
#[tokio::test(flavor = "multi_thread")]
async fn a_purge_that_fails_leaves_a_unit_that_was_off_off() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let (err, after) = failed_purge("disabled\ninactive\n", false).await;
    assert!(
        err.contains("The unit stays off, as it was before."),
        "{err}"
    );
    assert_eq!(after, "");
}

/// Uninstalling in the window prints nothing (there is no terminal): what
/// the purge would print for the owner comes as a note in the window.
#[tokio::test(flavor = "multi_thread")]
async fn the_windows_purge_shows_its_notes_in_the_window() {
    let env = Env::new();
    fake_systemd(&env);
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE5678".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE5678"), "--name", "winpurge"])
        .await;
    looks_installed(&env);
    // Not the client's: the folder stays, and the window says so.
    let config = env.home.join(".config/pithagoras-sync");
    std::fs::write(config.join("mine.txt"), "keep").unwrap();
    let path = fake_dialogs(&env, &["0|uninstall", "0|", "0|", "0|"]);
    let out = env
        .cmd(&["gui"])
        .env("PATH", &path)
        .env("DISPLAY", ":99")
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shown: Vec<String> = dialogs_shown(&env).iter().map(|d| d.join("\n")).collect();
    assert_eq!(shown.len(), 4, "{shown:#?}");
    let last = &shown[3];
    assert!(last.contains("Pithagoras Sync is uninstalled"), "{last}");
    assert!(
        last.contains(&format!(
            "Note: Kept {}: something in it is not the client's.",
            config.display()
        )),
        "{last}"
    );
    assert!(config.join("mine.txt").exists());
    assert!(!config.join("config.toml").exists());
}

/// A client folder that is a link leads to files that are not the client's to
/// delete: the purge refuses before anything goes.
#[tokio::test]
async fn purge_refuses_a_config_folder_that_is_a_link() {
    let env = Env::new();
    let path = fake_systemd(&env);
    let elsewhere = env.root.join("outside/config");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("config.toml"), "mode = \"ask\"\n").unwrap();
    std::fs::create_dir_all(env.home.join(".config")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, env.home.join(".config/pithagoras-sync")).unwrap();
    let state = env.home.join(".local/state/pithagoras-sync");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("audit.jsonl"), "{}\n").unwrap();
    let out = env
        .cmd(&["uninstall", "--purge", "--yes"])
        .env("PATH", &path)
        .output()
        .await
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("is a link"), "{err}");
    assert!(err.contains("nothing was removed"), "{err}");
    assert!(elsewhere.join("config.toml").exists());
    assert!(state.join("audit.jsonl").exists());
}

/// A config this user cannot read (another user's folder) is an error, never
/// the defaults: `mode` and `config get` do not print made-up values, and no
/// command writes defaults over it.
#[tokio::test]
async fn a_config_that_cannot_be_read_is_an_error_not_the_defaults() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        // Root reads it anyway.
        return;
    }
    let env = Env::new();
    env.ok(&["config", "set", "policy.approvals.timeout_secs", "77"])
        .await;
    let before = std::fs::read(env.config()).unwrap();
    let dir = env.config().parent().unwrap().to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut said = Vec::new();
    for args in [
        &["mode"][..],
        &["config", "get", "policy.approvals.timeout_secs"],
        &["mode", "full"],
        &["folder", "list"],
    ] {
        let out = env.cmd(args).output().await.unwrap();
        said.push((
            args,
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ));
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (args, ok, out, err) in said {
        assert!(!ok, "{args:?}: {out}");
        assert!(err.contains("cannot read"), "{args:?}: {err}");
        assert!(err.contains("Permission denied"), "{args:?}: {err}");
    }
    assert_eq!(std::fs::read(env.config()).unwrap(), before);
    let out = env
        .ok(&["config", "get", "policy.approvals.timeout_secs"])
        .await;
    assert_eq!(out.trim(), "77");
}

/// A deny rule that is slow on a long one-line command takes up to a second per
/// command to check. Those checks run beside the client's two worker threads, so
/// `status` and `panic` answer while the most commands the device starts at once
/// are being checked.
#[tokio::test(flavor = "multi_thread")]
async fn panic_answers_while_long_commands_are_checked() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE4321".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE4321"), "--name", "testbox"])
        .await;
    env.ok(&["folder", "add", &env.p("home/proj"), "--rw", "--exec"])
        .await;
    env.ok(&["mode", "folders"]).await;
    env.ok(&[
        "config",
        "add",
        "policy.commands.deny",
        r#"{"regex": "^.*(\\b\\w+\\b\\s*){10}shutdown"}"#,
    ])
    .await;
    let daemon = env.start();
    let dl = mock.next_device(WAIT).await.expect("the client connects");
    // 6 KB in 2000 two-byte words: a few seconds for this rule without a limit.
    let cmd = format!("echo{}", " ä".repeat(2000));
    let mut calls = Vec::new();
    for stream in 1..=16 {
        calls.push(
            dl.start_call(
                "exec.start",
                json!({"stream": stream, "command": cmd, "cwd": env.p("home/proj"), "ctx": {"chat": "c1"}}),
            )
            .await,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = std::time::Instant::now();
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    let status_took = started.elapsed();
    assert_eq!(status["link"]["state"], "connected");
    env.ok(&["panic"]).await;
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(4),
        "status took {status_took:?}, status and panic {took:?}"
    );
    assert_eq!(dl.closed(WAIT).await.unwrap().0, 1000);
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    assert_eq!(status["paused"], true);
    drop(calls);
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
        "sudo set --stdin",
        "sudo set --stdin --activate",
        "sudo activate",
        "sudo activate --no-password",
        "sudo deactivate",
        "sudo clear",
        "sudo clear --deactivate",
        "update --manifest /nowhere/manifest.json",
        "uninstall --purge --yes",
    ]
    .iter()
    .enumerate()
    {
        // The word `sudo` makes the command ask; the owner's check is what is tested,
        // so it is approved.
        let (n, cmd, cwd) = (10 + i as u32, me(args), env.p("home/proj"));
        let (out, _) = if args.starts_with("sudo") {
            exec_approved(&dl, n, &cmd, &cwd).await
        } else {
            exec(&dl, n, &cmd, &cwd).await
        };
        assert!(out.contains("exit=1"), "{args}: {out}");
        if *args != "config set policy.mode full" {
            assert!(out.contains("cannot come from commands"), "{args}: {out}");
        }
    }
    // The graphical flow with a link, from a command: refused before it asks
    // anything, even with a display and a dialog program that would say yes.
    let path = fake_dialogs(&env, &["0|", "0|", "0|"]);
    let evil = "pithagoras-sync://pair?portal=http://127.0.0.1:9&code=EVIL1";
    let (out, _) = exec(
        &dl,
        40,
        &format!(
            "DISPLAY=:99 PATH={path} PITHAGORAS_SYNC_TEST_DIALOG_DIR={} {}",
            env.p("fakebin"),
            me(&format!("'{evil}'"))
        ),
        &env.p("home/proj"),
    )
    .await;
    assert!(out.contains("exit=1"), "{out}");
    let shown = dialogs_shown(&env);
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert!(shown[0].contains(&"--error".to_string()), "{shown:?}");
    assert!(
        shown[0]
            .last()
            .unwrap()
            .contains("cannot come from commands"),
        "{shown:?}"
    );
    // Refused, so the audit log the owner relies on is still there.
    assert!(
        env.home
            .join(".local/state/pithagoras-sync/audit.jsonl")
            .exists()
    );
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

/// `install` in a graphical session also writes the menu entry, the icon and the
/// handler of pairing links, and `uninstall` and `uninstall --purge` take them
/// away. Stand-ins for systemctl, update-desktop-database and xdg-mime log
/// their arguments: nothing reaches the real systemd or the real `~/.local`.
#[tokio::test(flavor = "multi_thread")]
async fn install_in_a_desktop_session_registers_the_pairing_link() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let path = fake_systemd(&env);
    let log = env.root.join("systemctl.log");
    for prog in [
        "update-desktop-database",
        "xdg-mime",
        "gtk-update-icon-cache",
    ] {
        let p = env.root.join("fakebin").join(prog);
        std::fs::write(
            &p,
            format!("#!/bin/sh\necho \"{prog} $*\" >> '{}'\n", log.display()),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let data = env.root.join("data");
    let run = |args: &[&str], display: bool| {
        let mut c = env.cmd(args);
        c.env("PATH", &path).env("XDG_DATA_HOME", &data);
        if display {
            c.env("DISPLAY", ":99");
        }
        c
    };
    let entry = data.join("applications/pithagoras-sync.desktop");
    let icon = data.join("icons/hicolor/scalable/apps/pithagoras-sync.svg");
    // The raster sizes beside it, where GNOME and KDE look first.
    let png = data.join("icons/hicolor/256x256/apps/pithagoras-sync.png");
    // Over ssh (no display) nothing of the desktop's.
    let out = run(&["install", "--print"], false).output().await.unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(
        !text.contains(".desktop") && !text.contains("xdg-mime"),
        "{text}"
    );

    let out = run(&["install", "--print"], true).output().await.unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(&format!("write {}", entry.display())),
        "{text}"
    );
    assert!(
        text.contains(&format!("write {}", icon.display())),
        "{text}"
    );
    assert!(
        text.contains("xdg-mime default pithagoras-sync.desktop x-scheme-handler/pithagoras-sync"),
        "{text}"
    );
    assert!(!entry.exists());

    let out = run(&["install"], true).output().await.unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let program = env.home.join(".local/bin/pithagoras-sync");
    let desktop = std::fs::read_to_string(&entry).unwrap();
    assert!(
        desktop.contains(&format!("Exec=\"{}\" gui %u", program.display())),
        "{desktop}"
    );
    assert!(std::fs::read_to_string(&icon).unwrap().starts_with("<svg"));
    assert!(std::fs::read(&png).unwrap().starts_with(b"\x89PNG"));
    let calls = std::fs::read_to_string(&log).unwrap();
    // The icon cache of the user's hicolor folder, so the menu shows the
    // icon without a new login.
    assert!(
        calls.contains(&format!(
            "gtk-update-icon-cache -f -t {}",
            data.join("icons/hicolor").display()
        )),
        "{calls}"
    );
    assert!(
        calls.contains(&format!(
            "update-desktop-database {}",
            data.join("applications").display()
        )),
        "{calls}"
    );
    assert!(
        calls.contains("xdg-mime default pithagoras-sync.desktop x-scheme-handler/pithagoras-sync"),
        "{calls}"
    );

    // `uninstall` (no display needed) lists and removes them.
    let out = run(&["uninstall", "--print"], false)
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(&format!("remove {}", entry.display())),
        "{text}"
    );
    assert!(
        text.contains(&format!("remove {}", icon.display())),
        "{text}"
    );
    assert!(entry.exists());
    let out = run(&["uninstall"], false).output().await.unwrap();
    assert!(out.status.success());
    assert!(!entry.exists() && !icon.exists() && !png.exists());

    // Left without the unit, `--purge` still finds them.
    let out = run(&["install"], true).output().await.unwrap();
    assert!(out.status.success());
    std::fs::remove_file(
        env.home
            .join(".config/systemd/user/pithagoras-sync.service"),
    )
    .unwrap();
    let out = run(&["uninstall", "--purge", "--yes"], false)
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains(&format!("remove {}", entry.display())),
        "{text}"
    );
    assert!(!entry.exists() && !icon.exists());
    // The program stays, as `--purge` says.
    assert!(program.exists());
}

/// A stand-in `zenity` (and `kdialog`) in `fakebin`: it writes each dialog's
/// arguments, one per line and a `----` line after them, to `dialogs.log`, its
/// environment to `dialogs.env`, and answers with the next line of
/// `dialogs.answers` (`<exit code>|<output>`; none left is a cancel). It
/// says it is zenity 4.0.1 when asked (`--version`, no dialog). Returns the
/// PATH to run with.
fn fake_dialogs(env: &Env, answers: &[&str]) -> String {
    use std::os::unix::fs::PermissionsExt;
    let bin = env.root.join("fakebin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = env.root.join("dialogs.log");
    let envlog = env.root.join("dialogs.env");
    let open = env.root.join("dialogs.parent");
    let ans = env.root.join("dialogs.answers");
    std::fs::write(
        &ans,
        answers.iter().map(|a| format!("{a}\n")).collect::<String>(),
    )
    .unwrap();
    for prog in ["zenity", "kdialog"] {
        let p = bin.join(prog);
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\n[ \"$1\" = --version ] && {{ echo 4.0.1; exit 0; }}\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> '{log}'; done\necho ---- >> '{log}'\nenv >> '{envlog}'\ncat /proc/$PPID/environ >/dev/null 2>&1 && echo $PPID >> '{open}'\nline=$(head -n 1 '{ans}')\nsed -i 1d '{ans}'\n[ -z \"$line\" ] && exit 1\nout=${{line#*|}}\n[ -n \"$out\" ] && printf '%s\\n' \"$out\"\nexit ${{line%%|*}}\n",
                log = log.display(),
                envlog = envlog.display(),
                open = open.display(),
                ans = ans.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

/// Whether a dialog program could read the memory of the process that showed
/// it, as any process of the same user could (`/proc/<pid>/environ` stands in
/// for `/proc/<pid>/mem`).
fn dialog_parent_was_open(env: &Env) -> bool {
    env.root.join("dialogs.parent").exists()
}

/// The dialogs shown so far: each one's arguments.
fn dialogs_shown(env: &Env) -> Vec<Vec<String>> {
    let log = std::fs::read_to_string(env.root.join("dialogs.log")).unwrap_or_default();
    log.split("----\n")
        .filter(|d| !d.is_empty())
        .map(|d| d.lines().map(str::to_string).collect())
        .collect()
}

/// Makes the client look installed for this user (the unit file `install`
/// writes), so the graphical flow goes straight to pairing.
fn looks_installed(env: &Env) {
    let unit = env
        .home
        .join(".config/systemd/user/pithagoras-sync.service");
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(unit, "installed").unwrap();
}

/// A pairing link opened from the browser (the program started with the link
/// alone): one question showing the portal it parsed, never the raw link or its
/// code, then the pairing as `pair` does it, and the running client connects.
#[tokio::test(flavor = "multi_thread")]
async fn a_pairing_link_pairs_after_the_owner_says_yes() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE9999".into()],
    })
    .await;
    looks_installed(&env);
    // A headless config: pairing asks no password there, as `pair` asks none
    // (the desktop's password check: `pairing_in_the_window_on_a_desktop_...`).
    env.ok(&["mode", "ask"]).await;
    let path = fake_dialogs(&env, &["0|", "0|"]);
    let daemon = env.start();
    let link = mock.pair_uri("CODE9999");
    let out = env
        .cmd(&[&link])
        .env("PATH", &path)
        .env("DISPLAY", ":99")
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    mock.next_device(WAIT).await.expect("the client connects");
    let shown = dialogs_shown(&env);
    assert_eq!(shown.len(), 2, "{shown:?}");
    assert!(shown[0].contains(&"--question".to_string()), "{shown:?}");
    let question = shown[0].join("\n");
    let portal = link
        .split("portal=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .replace("%3A", ":")
        .replace("%2F", "/");
    assert!(
        question.contains(&format!("portal {portal} as \"")),
        "{question}"
    );
    assert!(!question.contains("CODE9999") && !question.contains("pithagoras-sync://"));
    assert!(shown[1].contains(&"--info".to_string()));
    assert!(
        shown[1].join("\n").contains("running, connected to"),
        "{shown:?}"
    );
    // The dialog program got a cleaned environment.
    let denv = std::fs::read_to_string(env.root.join("dialogs.env")).unwrap();
    assert!(
        !denv.contains("PORTAL_SECRET") && !denv.contains("must-not-leak"),
        "{denv}"
    );
    assert!(denv.contains("DISPLAY=:99"), "{denv}");
    let cfg = std::fs::read_to_string(env.config()).unwrap();
    assert!(cfg.contains(&format!("url = \"{portal}\"")), "{cfg}");
    stop(daemon).await;
}

/// On a desktop, pairing from the window asks for the user's password as
/// `pair` does in a terminal, and checks it with `su` (which refuses it here:
/// the test's user has none). Nothing is paired, the code stays unused, and the
/// password is in no file and no dialog's arguments.
#[tokio::test(flavor = "multi_thread")]
async fn pairing_in_the_window_on_a_desktop_needs_the_users_password() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE9999".into()],
    })
    .await;
    looks_installed(&env);
    let answer = format!("0|{PW}");
    let path = fake_dialogs(&env, &["0|", &answer, &answer, &answer]);
    let out = env
        .cmd(&["gui", "--link", &mock.pair_uri("CODE9999")])
        .env("PATH", &path)
        .env("DISPLAY", ":99")
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let shown: Vec<String> = dialogs_shown(&env).iter().map(|d| d.join("\n")).collect();
    assert!(shown[0].contains("--question"), "{shown:#?}");
    // zenity's form, after the question, for the password alone: the link
    // is the one confirmed.
    let flat = |s: &str| s.replace('\n', " ");
    assert!(
        shown[1].contains("--add-password=Login password")
            && !shown[1].contains("--add-entry")
            && flat(&shown[1]).contains("needs your login password ("),
        "{shown:#?}"
    );
    // su refused it: the form again, saying so, until it refused three; or
    // su could not check it at all (no su here): that error, and no retry.
    if shown[2].contains("--error") {
        assert_eq!(shown.len(), 3, "{shown:#?}");
        assert!(
            flat(&shown[2]).contains("Your password could not be checked"),
            "{shown:#?}"
        );
    } else {
        assert_eq!(shown.len(), 5, "{shown:#?}");
        for again in &shown[2..4] {
            assert!(
                again.contains("--forms")
                    && again.contains("--add-password=Login password")
                    && flat(again).contains("su did not accept this password"),
                "{shown:#?}"
            );
        }
        assert!(
            shown[4].contains("--error")
                && flat(&shown[4]).contains("su did not accept the password 3 times"),
            "{shown:#?}"
        );
    }
    assert!(!env.config().exists());
    assert!(!env.home.join(".config/pithagoras-sync/token").exists());
    assert_eq!(
        files_holding(&env.root, PW.as_bytes()),
        Vec::<PathBuf>::new()
    );
    // The password passed through the window, whose memory no other process
    // of the user could read.
    assert!(!dialog_parent_was_open(&env));
    // The code is still unused.
    env.ok(&["pair", &mock.pair_uri("CODE9999")]).await;
}

/// Something traces the window (a debugger, or a command of the agent that
/// attached before it could stop that): it asks for no password and says why.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn the_window_asks_for_no_password_while_traced() {
    use std::os::unix::process::CommandExt as _;
    let env = Env::new();
    looks_installed(&env);
    let answer = format!("0|{PW}");
    let path = fake_dialogs(&env, &["0|", &answer, "0|"]);
    let mut cmd = env.cmd(&[
        "gui",
        "--link",
        "pithagoras-sync://pair?portal=http://127.0.0.1:9&code=CODE9999",
    ]);
    cmd.env("PATH", &path).env("DISPLAY", ":99");
    // Spawned and traced from one thread: only that thread is its tracer.
    let code = tokio::task::spawn_blocking(move || {
        let cmd = cmd.as_std_mut();
        // SAFETY: ptrace only, async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // Reaped below with waitpid, as its tracer must.
        #[allow(clippy::zombie_processes)]
        let child = cmd.spawn().unwrap();
        let pid = child.id() as i32;
        // As the tracer: let it go on after every stop, until it exits.
        loop {
            let mut status = 0;
            // SAFETY: waits for our own child.
            if unsafe { libc::waitpid(pid, &mut status, libc::__WALL) } < 0 {
                panic!("waitpid: {}", std::io::Error::last_os_error());
            }
            if libc::WIFEXITED(status) {
                break libc::WEXITSTATUS(status);
            }
            if libc::WIFSIGNALED(status) {
                break -libc::WTERMSIG(status);
            }
            if libc::WIFSTOPPED(status) {
                let sig = match libc::WSTOPSIG(status) {
                    libc::SIGTRAP => 0,
                    s => s,
                };
                // SAFETY: the window is our tracee.
                unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, sig) };
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(code, 1);
    let shown: Vec<String> = dialogs_shown(&env).iter().map(|d| d.join("\n")).collect();
    assert_eq!(shown.len(), 1, "{shown:#?}");
    assert!(
        shown[0].contains("--error") && shown[0].contains("being traced"),
        "{shown:#?}"
    );
}

/// No to the question: nothing is paired, the code is not used.
#[tokio::test(flavor = "multi_thread")]
async fn a_pairing_link_the_owner_refuses_changes_nothing() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE9999".into()],
    })
    .await;
    looks_installed(&env);
    let path = fake_dialogs(&env, &["1|"]);
    let out = env
        .cmd(&["gui", "--link", &mock.pair_uri("CODE9999")])
        .env("PATH", &path)
        .env("DISPLAY", ":99")
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(dialogs_shown(&env).len(), 1);
    assert!(!env.config().exists());
    assert!(!env.home.join(".config/pithagoras-sync/token").exists());
    // The code is still unused: `pair` takes it.
    env.ok(&["pair", &mock.pair_uri("CODE9999")]).await;
}

/// In a German session the windows speak German, and the dialog program gets
/// the language for its buttons.
#[tokio::test(flavor = "multi_thread")]
async fn the_windows_follow_the_desktops_language() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE9999".into()],
    })
    .await;
    looks_installed(&env);
    let path = fake_dialogs(&env, &["1|"]);
    let out = env
        .cmd(&["gui", "--link", &mock.pair_uri("CODE9999")])
        .env("PATH", &path)
        .env("DISPLAY", ":99")
        .env("LANG", "de_DE.UTF-8")
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let shown = dialogs_shown(&env);
    let q = shown[0].join("\n");
    assert!(
        q.contains("Diesen Computer mit dem Pithagoras-Portal"),
        "{q}"
    );
    assert!(q.contains("koppeln?"), "{q}");
    let denv = std::fs::read_to_string(env.root.join("dialogs.env")).unwrap();
    assert!(denv.contains("LANG=de_DE.UTF-8"), "{denv}");
    // Where that locale is not installed, the dialog program gets one that is
    // (else it refuses the umlauts and shows nothing), and the language.
    if let Some(l) = denv.lines().find_map(|l| l.strip_prefix("LC_ALL=")) {
        assert!(
            l.to_lowercase().replace('-', "").ends_with(".utf8"),
            "{denv}"
        );
        assert!(denv.contains("LANGUAGE=de\n"), "{denv}");
    }
    assert!(!env.config().exists());
}

/// Every file below `dir` that holds `needle`.
fn files_holding(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return found;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() && !p.is_symlink() {
            found.extend(files_holding(&p, needle));
        } else if let Ok(b) = std::fs::read(&p)
            && b.windows(needle.len()).any(|w| w == needle)
        {
            found.push(p);
        }
    }
    found
}

/// The sudo password typed into a window: a wrong one is refused by sudo and
/// never kept; the right one goes to the running client and sudo access is
/// switched on after a yes. The password is in no dialog's arguments or
/// environment, no file and no process's command line or environment.
#[tokio::test(flavor = "multi_thread")]
async fn the_sudo_password_can_be_set_in_the_window() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE1234".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE1234"), "--name", "elev"])
        .await;
    let sudo = fake_sudo(&env);
    env.ok(&[
        "config",
        "set",
        "policy.privilege.sudo_path",
        &sudo.to_string_lossy(),
    ])
    .await;
    looks_installed(&env);
    let daemon = env.start();
    mock.next_device(WAIT).await.expect("the client connects");
    let pw_answer = format!("0|{PW}");
    let path = fake_dialogs(
        &env,
        &[
            "0|sudo",
            "0|set",
            "0|not the password",
            "0|set",
            &pw_answer,
            "0|",
            "1|",
            "1|",
        ],
    );
    let out = env
        .cmd(&["gui"])
        .env("PATH", &path)
        .env("DISPLAY", ":99")
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shown: Vec<String> = dialogs_shown(&env).iter().map(|d| d.join("\n")).collect();
    // The menu, the sudo menu, the password; the sudo menu again with why
    // sudo refused it at its top; the password, the question; the sudo menu
    // saying it is on; the menu, closed. No window of its own for a message.
    assert_eq!(shown.len(), 8, "{shown:#?}");
    assert!(shown[2].contains("--hide-text"), "{shown:#?}");
    assert!(
        shown[3].contains("sudo did not accept this password (sudo: 1 incorrect password attempt)"),
        "{shown:#?}"
    );
    assert!(shown[3].contains("--list"), "{shown:#?}");
    assert!(
        shown[5].contains("The password is stored in the running client."),
        "{shown:#?}"
    );
    assert!(shown[6].contains("Sudo access is on."), "{shown:#?}");
    assert!(
        shown[6].contains("Sudo access: on. Password: stored."),
        "{shown:#?}"
    );
    assert!(shown[6].contains("--cancel-label=Back"), "{shown:#?}");
    assert!(shown[7].contains("--cancel-label=Close"), "{shown:#?}");
    // Checked with -k, the password on stdin: two checks, each asking first
    // whether sudo needs one at all.
    let validated = std::fs::read_to_string(env.root.join("fakesudo.validated")).unwrap();
    assert_eq!(
        validated.lines().collect::<Vec<_>>(),
        ["-k -n -v", "-k -S -p  -v", "-k -n -v", "-k -S -p  -v"]
    );
    assert_eq!(env.elevation().await, "sudo");
    let r = env.run(&["sudo", "status"]).await;
    assert!(
        r.out.contains("Password:    set (kept in memory)"),
        "{}",
        r.out
    );
    assert_eq!(
        files_holding(&env.root, PW.as_bytes()),
        Vec::<PathBuf>::new()
    );
    assert_eq!(in_proc(PW.as_bytes()), None);
    stop(daemon).await;
}

/// Without a display, or without a dialog program, `gui` shows nothing: it
/// says so on stderr and in `gui.log`. Neither a start without a command
/// nor any other command starts the dialogs there.
#[tokio::test(flavor = "multi_thread")]
async fn commands_run_without_a_display_or_a_bus() {
    let env = Env::new();
    let path = fake_dialogs(&env, &["0|", "0|", "0|"]);
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE1111".into()],
    })
    .await;
    let run = |args: &[&str]| {
        let mut c = env.cmd(args);
        c.env("PATH", &path);
        c
    };
    // The program alone (no terminal, no display): the help, nothing else.
    let out = run(&[]).output().await.unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Usage:"), "{err}");
    let out = run(&["gui"]).output().await.unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot show its windows"), "{err}");
    let state = env.home.join(".local/state/pithagoras-sync");
    let log = std::fs::read_to_string(state.join("gui.log")).unwrap();
    assert!(
        log.contains("gui: Pithagoras Sync cannot show its windows"),
        "{log}"
    );
    // Not in client.log: that file there would make the windows open it as the
    // client's log later instead of the journal.
    assert!(!state.join("client.log").exists());
    let out = run(&[&mock.pair_uri("CODE1111")]).output().await.unwrap();
    assert_eq!(out.status.code(), Some(1));
    // With a display but no dialog program on PATH: the same.
    let out = env
        .cmd(&["gui"])
        .env("DISPLAY", ":99")
        .env("PATH", "/nonexistent")
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    // Dialog programs in a folder the user can write, first on PATH: not used,
    // as they could keep the passwords typed into them.
    let planted = env.root.join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    for prog in ["zenity", "kdialog"] {
        std::fs::copy(env.root.join("fakebin").join(prog), planted.join(prog)).unwrap();
    }
    let before = dialogs_shown(&env).len();
    let out = env
        .cmd(&["gui"])
        .env("DISPLAY", ":99")
        .env("PATH", format!("{}:/nonexistent", planted.display()))
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        dialogs_shown(&env).len(),
        before,
        "{:#?}",
        dialogs_shown(&env)
    );
    for args in [
        &["install", "--print"][..],
        &["uninstall", "--print"],
        &["uninstall", "--purge", "--print"],
        &["status"],
        &["status", "--json"],
        &["config", "get"],
        &["mode"],
        &["folder", "list"],
        &["sudo", "status"],
        &["setup", "--create-user", "--print"],
        &["update", "--check"],
        &["approvals"],
        &["toggle"],
        &[
            "pair",
            "pithagoras-sync://pair?portal=https://x.example&code=A B",
        ],
    ] {
        let out = tokio::time::timeout(WAIT, run(args).output())
            .await
            .unwrap_or_else(|_| panic!("{args:?} hangs"))
            .unwrap();
        // Each ends on its own (some with an error: nothing is paired or running).
        assert!(out.status.code().is_some(), "{args:?}");
    }
    env.ok(&["pair", &mock.pair_uri("CODE1111")]).await;
    let daemon = env.start();
    mock.next_device(WAIT).await.expect("the client connects");
    env.ok(&["status"]).await;
    stop(daemon).await;
    assert!(dialogs_shown(&env).is_empty(), "{:?}", dialogs_shown(&env));
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
/// root). `-v` only checks the password (`-n -v`: whether none is needed) and
/// logs its arguments to `fakesudo.validated`.
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
case " $* " in *" -v "*)
  echo "$*" >> "$0.validated"
  [ -e "$0.nopasswd" ] && exit 0
  case " $* " in *" -n "*) echo "sudo: a password is required" >&2; exit 1;; esac
  IFS= read -r pw || {{ echo "sudo: no password" >&2; exit 1; }}
  h=$(printf '%s' "$pw" | sha256sum); pw=
  [ "${{h%% *}}" = "{hash}" ] || {{ echo "sudo: 1 incorrect password attempt" >&2; exit 1; }}
  exit 0;;
esac
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
    // Not running yet and no password: the sudo group takes the explicit word that
    // a sudoers rule is meant to do without one.
    env.ok(&["sudo", "activate", "--no-password"]).await;
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
    let mut set = env.cmd(&["sudo", "set", "--stdin"]);
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
    let mut set = env.cmd(&["sudo", "set", "--stdin"]);
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
    let mut set = env.cmd(&["sudo", "set", "--stdin"]);
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
    env.ok(&["sudo", "clear"]).await;
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

/// What a finished command printed: (exit code, stdout, stderr).
struct Ran {
    code: i32,
    out: String,
    err: String,
}

impl Env {
    /// Runs a command with `input` on stdin.
    async fn run_with(&self, args: &[&str], input: &str) -> Ran {
        use tokio::io::AsyncWriteExt;
        let mut c = self.cmd(args);
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        {
            let mut i = child.stdin.take().unwrap();
            i.write_all(input.as_bytes()).await.unwrap();
        }
        let o = child.wait_with_output().await.unwrap();
        Ran {
            code: o.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&o.stdout).into_owned(),
            err: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    /// Runs a command with nothing on stdin, as a script does.
    async fn run(&self, args: &[&str]) -> Ran {
        let o = self.cmd(args).output().await.unwrap();
        Ran {
            code: o.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&o.stdout).into_owned(),
            err: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    async fn elevation(&self) -> String {
        self.ok(&["config", "get", "policy.privilege.elevation"])
            .await
            .trim()
            .to_string()
    }

    /// Runs the command in a pseudo terminal: waits for each text of `script` in
    /// the output and types its answer. Returns (exit code, everything shown).
    fn in_terminal(&self, args: &[&str], script: &[(&str, &str)]) -> Option<(i32, String)> {
        let steps: Vec<_> = script.iter().map(|(e, a)| (*e, *a, &[][..])).collect();
        self.in_terminal_racing(args, &steps)
    }

    /// Like `in_terminal`, and before each answer runs the client's own program
    /// with the arguments of the step's third part (from outside the terminal, as
    /// the owner would in a second shell), while the question waits.
    ///
    /// A text that never shows fails the run (exit code -1, "timed out" in what
    /// was shown) after 15 s, and the child is killed, so a changed prompt makes
    /// a test fail instead of hang (and `timeout` ends the helper itself after
    /// 60 s, should the helper hang).
    fn in_terminal_racing(
        &self,
        args: &[&str],
        script: &[(&str, &str, &[&str])],
    ) -> Option<(i32, String)> {
        const PY: &str = r#"
import json, os, pty, select, signal, subprocess, sys, time
exe, script, args = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    os.execv(exe, [exe] + args)
buf, pos = b"", 0
def read(until):
    # True when `until` showed (or, with None, the output ended), False on a timeout.
    global buf, pos
    end = time.time() + 15
    while until is None or buf.find(until.encode(), pos) < 0:
        left = end - time.time()
        if left <= 0:
            return False
        if select.select([fd], [], [], left)[0]:
            try:
                data = os.read(fd, 4096)
            except OSError:
                return until is None
            if not data:
                return until is None
            buf += data
    return True
def finish(note):
    # Never leaves the child behind: kills it when it still runs.
    for _ in range(50):
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        time.sleep(0.1)
    else:
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        note = note or "timed out: the command did not end"
    print(buf.decode(errors="replace"))
    if note:
        print(note)
        print("exit=-1")
    else:
        print("exit=%d" % os.waitstatus_to_exitcode(status))
    sys.exit(0)
for expect, send, outside in script:
    if not read(expect):
        os.kill(pid, signal.SIGKILL)
        finish("timed out waiting for %r" % expect)
    pos = len(buf)
    if outside:
        subprocess.run([exe] + outside, stdin=subprocess.DEVNULL, check=True, timeout=30)
    os.write(fd, send.encode())
if not read(None):
    os.kill(pid, signal.SIGKILL)
    finish("timed out waiting for the command to end")
finish(None)
"#;
        // `timeout` is the helper's own safety net: should it hang, the run fails
        // after a minute (no `exit=` in its output) instead of blocking the suite.
        let out = std::process::Command::new("timeout")
            .args(["-s", "KILL", "60", "python3", "-c", PY])
            .args([BIN, &serde_json::to_string(script).unwrap()])
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_STATE_HOME", self.home.join(".local/state"))
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("TMPDIR", self.root.join("tmp"))
            .env("LANG", "C.UTF-8")
            .env("USER", "tester")
            .env("PITHAGORAS_SYNC_NO_KEYRING", "1")
            .stdin(Stdio::null())
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (shown, code) = text.trim_end().rsplit_once("exit=")?;
        Some((code.trim().parse().ok()?, shown.to_string()))
    }
}

/// Whether the terminal tests can run: they drive the program through a pseudo
/// terminal with python3. Like the tests that need a cgroup or Landlock, they
/// skip with a notice where it is missing (CI images have python3).
fn have_python() -> bool {
    let ok = std::process::Command::new("python3")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("  (SKIPPED: no python3 to drive a terminal with)");
    }
    ok
}

/// The audit log's `policy` records, as text.
fn policy_changes(env: &Env) -> String {
    std::fs::read_to_string(env.home.join(".local/state/pithagoras-sync/audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("\"tool\":\"policy\"") && l.contains("privilege.elevation"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test(flavor = "multi_thread")]
async fn sudo_set_activate_deactivate_and_clear() {
    let env = Env::new();
    // Nothing set up, the client not running.
    let r = env.run(&["sudo", "status"]).await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("Sudo access: not active"), "{}", r.out);
    assert!(r.out.contains("Password:    not set"), "{}", r.out);
    assert!(
        r.out
            .contains("Next:        run `pithagoras-sync sudo set`")
    );

    // Without a password, and nobody to ask: refused, nothing switched on.
    let r = env.run(&["sudo", "activate"]).await;
    assert_eq!(r.code, 1);
    assert!(r.err.contains("not activated"), "{}", r.err);
    assert!(r.err.contains("sudo set"), "{}", r.err);
    assert_eq!(env.elevation().await, "off");
    // A sudoers rule that asks none is said so.
    env.ok(&["sudo", "activate", "--no-password"]).await;
    assert_eq!(env.elevation().await, "sudo");
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("Sudo access: active"), "{}", r.out);
    assert!(r.out.contains("active, but no password"), "{}", r.out);
    assert!(r.out.contains("Client:      not running"), "{}", r.out);
    // The password stays when it is switched off, and again is not an error.
    assert!(env.ok(&["sudo", "deactivate"]).await.contains("now"));
    assert_eq!(env.elevation().await, "off");
    assert!(env.ok(&["sudo", "deactivate"]).await.contains("already"));

    // A client that keeps the password in memory has to run first.
    let r = env.run_with(&["sudo", "set", "--stdin"], "pw\n").await;
    assert_eq!(r.code, 1);
    assert!(r.err.contains("start it first"), "{}", r.err);

    let daemon = env.start();
    for _ in 0..100 {
        if env
            .cmd(&["status"])
            .output()
            .await
            .unwrap()
            .status
            .success()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // `--stdin` is a script: no question, a hint, and the policy is as it was.
    let r = env
        .run_with(&["sudo", "set", "--stdin"], &format!("{PW}\n"))
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("not active yet"), "{}", r.out);
    assert!(r.out.contains("sudo activate"), "{}", r.out);
    assert_eq!(env.elevation().await, "off");
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("Sudo access: not active"), "{}", r.out);
    assert!(
        r.out.contains("Password:    set (kept in memory)"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("Next:        run `pithagoras-sync sudo activate`")
    );
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    assert_eq!(status["elevation_password"], true, "{status}");

    // The password is there, so activating asks nothing.
    let r = env.run(&["sudo", "activate"]).await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(env.elevation().await, "sudo");
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    assert!(
        status["elevation"]
            .as_str()
            .unwrap()
            .starts_with("sudo, password set"),
        "{status}"
    );
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("Sudo access: active"), "{}", r.out);
    assert!(r.out.contains("Next:        nothing to do"), "{}", r.out);
    // The change is audited with its old and new value, as a `config set` is.
    let audit = policy_changes(&env);
    assert!(audit.contains("by the device owner"), "{audit}");
    assert!(audit.contains(r#"\"off\" -> \"sudo\""#), "{audit}");

    // Off again, the password stays.
    env.ok(&["sudo", "deactivate"]).await;
    assert_eq!(env.elevation().await, "off");
    assert!(policy_changes(&env).contains(r#"\"sudo\" -> \"off\""#));
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("Password:    set"), "{}", r.out);

    // `clear` on a client where sudo is not active only forgets.
    let r = env.run(&["sudo", "clear"]).await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("forgotten"), "{}", r.out);
    assert!(!r.out.contains("stays active"), "{}", r.out);
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("Password:    not set"), "{}", r.out);

    // Set and switch on in one go; `clear` in a script leaves it on, and says so.
    let r = env
        .run_with(
            &["sudo", "set", "--stdin", "--activate"],
            &format!("{PW}\n"),
        )
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(env.elevation().await, "sudo");
    let r = env
        .run_with(&["sudo", "set", "--stdin"], &format!("{PW}\n"))
        .await;
    assert!(r.out.contains("Sudo access is active."), "{}", r.out);
    assert!(!r.out.contains("not active yet"), "{}", r.out);
    let r = env.run(&["sudo", "clear"]).await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(r.out.contains("stays active"), "{}", r.out);
    assert_eq!(env.elevation().await, "sudo");
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("active, but no password"), "{}", r.out);
    // `clear --deactivate` does both.
    let r = env
        .run_with(&["sudo", "set", "--stdin"], &format!("{PW}\n"))
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    let r = env.run(&["sudo", "clear", "--deactivate"]).await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(env.elevation().await, "off");
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("Password:    not set"), "{}", r.out);

    stop(daemon).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sudo_keeps_the_password_in_a_file_when_asked() {
    let env = Env::new();
    env.ok(&["config", "set", "policy.privilege.secret_storage", "file"])
        .await;
    // The client is not running: the file is written for its next start.
    let r = env
        .run_with(
            &["sudo", "set", "--stdin", "--activate"],
            &format!("{PW}\n"),
        )
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(!r.out.contains(PW) && !r.err.contains(PW));
    assert_eq!(env.elevation().await, "sudo");
    let stored = env.home.join(".config/pithagoras-sync/elevation.secret");
    assert!(stored.exists());
    let r = env.run(&["sudo", "status"]).await;
    assert!(
        r.out.contains("Password:    set (kept in file)"),
        "{}",
        r.out
    );
    assert!(r.out.contains("Next:        nothing to do"), "{}", r.out);
    // Activating needs no question: the stored password counts.
    env.ok(&["sudo", "deactivate"]).await;
    env.ok(&["sudo", "activate"]).await;
    let r = env.run(&["sudo", "clear", "--deactivate"]).await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(!stored.exists());
    assert_eq!(env.elevation().await, "off");
}

#[tokio::test(flavor = "multi_thread")]
async fn sudo_asks_in_a_terminal() {
    let env = Env::new();
    let daemon = env.start();
    for _ in 0..100 {
        if env
            .cmd(&["status"])
            .output()
            .await
            .unwrap()
            .status
            .success()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let ask = "Do you want to activate sudo access now? [y/N]";
    if !have_python() {
        stop(daemon).await;
        return;
    }
    // Password, then the question: yes.
    let (code, shown) = env
        .in_terminal(
            &["sudo", "set"],
            &[("not shown", &format!("{PW}\n")), (ask, "y\n")],
        )
        .expect("the terminal run");
    assert_eq!(code, 0, "{shown}");
    assert!(!shown.contains(PW), "the password was echoed: {shown}");
    assert!(shown.contains("now."), "{shown}");
    assert_eq!(env.elevation().await, "sudo");
    // Already active: no question.
    let (code, shown) = env
        .in_terminal(&["sudo", "set"], &[("not shown", &format!("{PW}\n"))])
        .unwrap();
    assert_eq!(code, 0, "{shown}");
    assert!(!shown.contains("[y/N]"), "{shown}");
    // No: it stays off, with the hint.
    env.ok(&["sudo", "deactivate"]).await;
    let (code, shown) = env
        .in_terminal(
            &["sudo", "set"],
            &[("not shown", &format!("{PW}\n")), (ask, "n\n")],
        )
        .unwrap();
    assert_eq!(code, 0, "{shown}");
    assert!(shown.contains("not active yet"), "{shown}");
    assert_eq!(env.elevation().await, "off");

    // Clear while active asks whether to deactivate: no keeps it on.
    env.ok(&["sudo", "activate"]).await;
    let q = "Deactivate it too? [y/N]";
    let (code, shown) = env.in_terminal(&["sudo", "clear"], &[(q, "n\n")]).unwrap();
    assert_eq!(code, 0, "{shown}");
    assert!(shown.contains("stays active"), "{shown}");
    assert_eq!(env.elevation().await, "sudo");
    // Activating without a password offers to set one: no refuses, yes sets it.
    let offer = "Do you want to set a password now? [y/N]";
    env.ok(&["sudo", "deactivate"]).await;
    let (code, shown) = env
        .in_terminal(&["sudo", "activate"], &[(offer, "n\n")])
        .unwrap();
    assert_eq!(code, 1, "{shown}");
    assert!(shown.contains("not activated"), "{shown}");
    assert_eq!(env.elevation().await, "off");
    let (code, shown) = env
        .in_terminal(
            &["sudo", "activate"],
            &[(offer, "y\n"), ("not shown", &format!("{PW}\n"))],
        )
        .unwrap();
    assert_eq!(code, 0, "{shown}");
    assert_eq!(env.elevation().await, "sudo");
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("Password:    set"), "{}", r.out);
    // Clear, answering yes: both gone.
    let (code, shown) = env.in_terminal(&["sudo", "clear"], &[(q, "y\n")]).unwrap();
    assert_eq!(code, 0, "{shown}");
    assert_eq!(env.elevation().await, "off");
    stop(daemon).await;
}

/// A change the owner makes in a second shell while a `sudo` question waits stays:
/// the commands save only the elevation, not the config they read before asking.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_made_while_a_sudo_question_waits_stays() {
    if !have_python() {
        return;
    }
    let env = Env::new();
    let proj = env.p("home/proj");
    env.ok(&["config", "set", "policy.privilege.secret_storage", "file"])
        .await;
    let mode = || env.ok(&["config", "get", "policy.mode"]);
    // `sudo set`: Full is narrowed to Ask while "activate now?" waits.
    env.ok(&["mode", "full"]).await;
    let ask = "Do you want to activate sudo access now? [y/N]";
    let (code, shown) = env
        .in_terminal_racing(
            &["sudo", "set"],
            &[
                ("not shown", &format!("{PW}\n"), &[]),
                (ask, "y\n", &["mode", "ask"]),
            ],
        )
        .unwrap();
    assert_eq!(code, 0, "{shown}");
    assert_eq!(env.elevation().await, "sudo");
    assert_eq!(mode().await.trim(), "ask", "the narrowing was undone");
    // `sudo activate`: a folder is granted while the password is typed.
    env.ok(&["sudo", "deactivate"]).await;
    env.ok(&["sudo", "clear"]).await;
    let (code, shown) = env
        .in_terminal_racing(
            &["sudo", "activate"],
            &[
                ("Do you want to set a password now? [y/N]", "y\n", &[]),
                (
                    "not shown",
                    &format!("{PW}\n"),
                    &["folder", "add", &proj, "--rw"],
                ),
            ],
        )
        .unwrap();
    assert_eq!(code, 0, "{shown}");
    assert_eq!(env.elevation().await, "sudo");
    let folders = env.ok(&["config", "get", "policy.folders"]).await;
    assert!(folders.contains(&proj), "the folder was lost: {folders}");
    // `sudo clear`, which asks no password even on a desktop: Full is narrowed
    // while "deactivate it too?" waits.
    env.ok(&["mode", "full"]).await;
    let q = "Deactivate it too? [y/N]";
    let (code, shown) = env
        .in_terminal_racing(&["sudo", "clear"], &[(q, "y\n", &["mode", "ask"])])
        .unwrap();
    assert_eq!(code, 0, "{shown}");
    assert_eq!(env.elevation().await, "off");
    assert_eq!(mode().await.trim(), "ask", "the narrowing was undone");
}

/// The processes of the client's program that run with this environment's home.
fn clients_left(env: &Env) -> Vec<u32> {
    let home = format!("HOME={}", env.home.display());
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let Ok(environ) = std::fs::read(entry.path().join("environ")) else {
            continue;
        };
        let runs_it = cmdline.split(|b| *b == 0).next() == Some(BIN.as_bytes());
        if runs_it && environ.split(|b| *b == 0).any(|v| v == home.as_bytes()) {
            found.push(pid);
        }
    }
    found
}

/// A terminal run that never gets its prompt fails, it does not hang, and the
/// command it ran does not stay behind. `sudo set` blocks at its password prompt,
/// so only the helper's kill ends it (`sudo status` would end by itself).
#[tokio::test(flavor = "multi_thread")]
async fn a_terminal_run_without_its_prompt_fails_instead_of_hanging() {
    if !have_python() {
        return;
    }
    let env = Env::new();
    let started = std::time::Instant::now();
    let (code, shown) = env
        .in_terminal(&["sudo", "set"], &[("never printed", "x\n")])
        .unwrap();
    assert_eq!(code, -1, "{shown}");
    assert!(shown.contains("timed out waiting"), "{shown}");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(
        clients_left(&env),
        Vec::<u32>::new(),
        "the command was left running"
    );
}

/// A password file left over from file storage is no stored password once the
/// storage is memory: the client does not load it.
#[tokio::test(flavor = "multi_thread")]
async fn a_leftover_password_file_is_no_password_under_memory_storage() {
    let env = Env::new();
    env.ok(&["config", "set", "policy.privilege.secret_storage", "file"])
        .await;
    let r = env
        .run_with(&["sudo", "set", "--stdin"], &format!("{PW}\n"))
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    let stored = env.home.join(".config/pithagoras-sync/elevation.secret");
    assert!(stored.exists());
    env.ok(&["config", "set", "policy.privilege.secret_storage", "memory"])
        .await;
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("Password:    not set"), "{}", r.out);
    assert!(!r.out.contains("Password:    set"), "{}", r.out);
    assert!(r.out.contains("old password file is ignored"), "{}", r.out);
    assert!(
        r.out.contains("run `pithagoras-sync sudo set`"),
        "{}",
        r.out
    );
    // A script gets the refusal, not a silent activation.
    let r = env.run(&["sudo", "activate"]).await;
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.err.contains("not activated"), "{}", r.err);
    assert_eq!(env.elevation().await, "off");
    // `clear` removes the leftover.
    env.ok(&["sudo", "clear"]).await;
    assert!(!stored.exists());
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

/// `run --detach` (what the Windows logon task starts) has no console: the log goes
/// to `client.log` in the state folder, as plain text, and nothing to stderr.
#[tokio::test(flavor = "multi_thread")]
async fn a_detached_client_writes_its_log_to_a_file() {
    let env = Env::new();
    let err = std::fs::File::create(env.root.join("stderr.txt")).unwrap();
    let child = env.cmd(&["run", "--detach"]).stderr(err).spawn().unwrap();
    let mut up = false;
    for _ in 0..100 {
        let out = env.cmd(&["status", "--json"]).output().await.unwrap();
        if out.status.success() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "the client answers");
    stop(child).await;
    let log =
        std::fs::read_to_string(env.home.join(".local/state/pithagoras-sync/client.log")).unwrap();
    assert!(log.contains("started: profile"), "{log}");
    assert!(log.contains("shutting down"), "{log}");
    assert!(!log.contains('\x1b'), "{log}");
    let stderr = std::fs::read_to_string(env.root.join("stderr.txt")).unwrap();
    assert!(stderr.is_empty(), "{stderr}");
}

/// Waits until `f` holds, up to `WAIT`.
async fn eventually(what: &str, f: impl Fn() -> bool) {
    let end = std::time::Instant::now() + WAIT;
    while !f() {
        assert!(std::time::Instant::now() < end, "never happened: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The client reads the password from the keyring at start, and the keyring
/// asks the owner to unlock it first. A `panic` while that prompt waits wins:
/// what is read after it is not kept, until `unlock` loads it again.
#[tokio::test(flavor = "multi_thread")]
async fn panic_while_the_keyring_prompt_waits_keeps_the_password_out() {
    use sync_testkit::keyring;
    let Some(bus) = keyring::private_bus() else {
        return;
    };
    let state = keyring::Shared::default();
    let _service = keyring::serve(&bus, state.clone()).await;
    let mut env = Env::new();
    env.vars
        .push(("DBUS_SESSION_BUS_ADDRESS".into(), bus.address.clone()));
    env.ok(&[
        "config",
        "set",
        "policy.privilege.secret_storage",
        "keyring",
    ])
    .await;
    let r = env
        .run_with(&["sudo", "set", "--stdin"], &format!("{PW}\n"))
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.answer = None;
    }
    let daemon = env.start();
    eventually("the client asks to unlock the keyring", || {
        state.lock().unwrap().prompts > 0
    })
    .await;
    env.ok(&["panic"]).await;
    keyring::answer_waiting(&state, true).await;
    let log = env.root.join("daemon.log");
    eventually("the client drops what it read after panic", || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("elevation password not loaded: panic")
    })
    .await;
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    assert_eq!(status["paused"], true);
    assert_eq!(status["elevation_password"], false, "{status}");
    // The stored one is still there for unlock.
    env.ok(&["unlock"]).await;
    let status: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
    assert_eq!(status["elevation_password"], true, "{status}");
    stop(daemon).await;
}

/// The client started before the keyring service (at login): it tries again,
/// connects and loads the password once the service is there, without the
/// owner doing anything.
/// A reload while the keyring cannot be read (locked, its prompt cancelled)
/// leaves the running link as it is.
#[tokio::test(flavor = "multi_thread")]
async fn the_link_outlasts_a_late_or_locked_keyring() {
    use sync_testkit::keyring;
    const NAME: &str = "org.freedesktop.secrets";
    let Some(bus) = keyring::private_bus() else {
        return;
    };
    let state = keyring::Shared::default();
    let service = keyring::serve(&bus, state.clone()).await;
    let mut env = Env::new();
    env.vars
        .push(("DBUS_SESSION_BUS_ADDRESS".into(), bus.address.clone()));
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE7777".into()],
    })
    .await;
    env.ok(&["config", "set", "token_storage", "keyring"]).await;
    env.ok(&["pair", &mock.pair_uri("CODE7777"), "--name", "late"])
        .await;
    env.ok(&[
        "config",
        "set",
        "policy.privilege.secret_storage",
        "keyring",
    ])
    .await;
    let r = env
        .run_with(&["sudo", "set", "--stdin"], &format!("{PW}\n"))
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    service.release_name(NAME).await.unwrap();
    let daemon = env.start();
    // Empty until the client answers.
    let detail = || async {
        let s: Value =
            serde_json::from_str(&env.run(&["status", "--json"]).await.out).unwrap_or_default();
        (
            s["link"]["state"].as_str().unwrap_or_default().to_string(),
            s["link"]["detail"].as_str().unwrap_or_default().to_string(),
        )
    };
    let end = std::time::Instant::now() + WAIT;
    loop {
        let (state, detail) = detail().await;
        if state == "stopped" && detail.contains("no keyring service") {
            assert!(detail.contains("trying again in"), "{detail}");
            break;
        }
        assert!(std::time::Instant::now() < end, "{state}: {detail}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    service.request_name(NAME).await.unwrap();
    mock.next_device(WAIT)
        .await
        .expect("connects once the keyring is there");
    // The password is read again as well.
    let end = std::time::Instant::now() + WAIT;
    loop {
        let s: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
        if s["elevation_password"] == true {
            break;
        }
        assert!(
            std::time::Instant::now() < end,
            "the password was never loaded: {s}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // A policy change reloads the client; it does not read the token again,
    // so a locked keyring shows no prompt for it and the link stays.
    let prompts = {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.answer = Some(false);
        s.prompts
    };
    let log = env.root.join("daemon.log");
    let reloads = || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .matches("config reloaded")
            .count()
    };
    let before = reloads();
    env.ok(&["mode", "ask"]).await;
    env.ok(&["mode", "full"]).await;
    eventually("the client reloaded twice", || reloads() >= before + 2).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(state.lock().unwrap().prompts, prompts, "no unlock prompt");
    assert_eq!(detail().await.0, "connected");
    stop(daemon).await;
}

/// The token and the elevation password in the keyring: the fake Secret
/// Service of the testkit on a private bus stands in for the desktop's, so no
/// real keyring is touched. The token moves with `token_storage` both ways
/// without being lost, a cancelled unlock prompt is an error and never a
/// fallback, and `unpair` and `sudo clear` take the entries out again.
#[tokio::test(flavor = "multi_thread")]
async fn the_token_and_the_password_in_the_keyring() {
    use sync_testkit::keyring;
    let Some(bus) = keyring::private_bus() else {
        return;
    };
    let state = keyring::Shared::default();
    let _service = keyring::serve(&bus, state.clone()).await;
    let mut env = Env::new();
    env.vars
        .push(("DBUS_SESSION_BUS_ADDRESS".into(), bus.address.clone()));
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE7777".into(), "CODE8888".into()],
    })
    .await;
    let in_keyring = |name: &str| {
        state
            .lock()
            .unwrap()
            .items
            .iter()
            .find(|(_, a, _)| a.get("name").map(String::as_str) == Some(name))
            .map(|(.., v)| String::from_utf8(v.clone()).unwrap())
    };
    let token_file = env.home.join(".config/pithagoras-sync/token");

    env.ok(&["config", "set", "token_storage", "keyring"]).await;
    env.ok(&["pair", &mock.pair_uri("CODE7777"), "--name", "kbox"])
        .await;
    let token = in_keyring("token").expect("the token is in the keyring");
    assert!(!token_file.exists());
    let cfg = std::fs::read_to_string(env.config()).unwrap();
    assert!(cfg.contains("token_storage = \"keyring\""), "{cfg}");
    assert!(!cfg.contains(&token));
    let daemon = env.start();
    mock.next_device(WAIT)
        .await
        .expect("connects with the keyring's token");
    let out = env.ok(&["status"]).await;
    assert!(out.contains("Token:     kept in the keyring"), "{out}");

    // To the file and back: the token goes along, the old place loses it.
    env.ok(&["config", "set", "token_storage", "file"]).await;
    assert_eq!(std::fs::read_to_string(&token_file).unwrap(), token);
    assert_eq!(in_keyring("token"), None);
    env.ok(&["config", "set", "token_storage", "keyring"]).await;
    assert_eq!(in_keyring("token").as_deref(), Some(token.as_str()));
    assert!(!token_file.exists());

    // Locked, and the owner cancels the unlock prompt: pairing again fails and
    // leaves the old token where it was; nothing lands in the file instead.
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.answer = Some(false);
    }
    let out = env
        .cmd(&["pair", &mock.pair_uri("CODE8888")])
        .output()
        .await
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        err.contains("cancelled") && err.contains("keyring"),
        "{err}"
    );
    assert!(!token_file.exists());
    {
        let mut s = state.lock().unwrap();
        s.answer = Some(true);
    }

    // The password: kept in the keyring, never in the file or the client's log.
    env.ok(&[
        "config",
        "set",
        "policy.privilege.secret_storage",
        "keyring",
    ])
    .await;
    let r = env
        .run_with(&["sudo", "set", "--stdin"], &format!("{PW}\n"))
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(in_keyring("elevation").as_deref(), Some(PW));
    assert!(
        !env.home
            .join(".config/pithagoras-sync/elevation.secret")
            .exists()
    );
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("set (kept in keyring)"), "{}", r.out);
    env.ok(&["sudo", "clear"]).await;
    assert_eq!(in_keyring("elevation"), None);

    env.ok(&["unpair"]).await;
    assert_eq!(in_keyring("token"), None);
    stop(daemon).await;
    let log = std::fs::read_to_string(env.root.join("daemon.log")).unwrap();
    assert!(!log.contains(PW) && !log.contains(&token), "{log}");
}

/// A keyring that refuses to delete (its prompt dismissed) after the setting
/// already changed: `config set token_storage` keeps the change, says what was
/// left behind and tells the running client; `unpair` lets the running client
/// go of the portal before it fails on the keyring.
#[tokio::test(flavor = "multi_thread")]
async fn a_keyring_that_will_not_delete_still_lets_the_client_hear_of_the_change() {
    use sync_testkit::keyring;
    let Some(bus) = keyring::private_bus() else {
        return;
    };
    let state = keyring::Shared::default();
    let _service = keyring::serve(&bus, state.clone()).await;
    let mut env = Env::new();
    env.vars
        .push(("DBUS_SESSION_BUS_ADDRESS".into(), bus.address.clone()));
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE7777".into()],
    })
    .await;
    env.ok(&["config", "set", "token_storage", "keyring"]).await;
    env.ok(&["pair", &mock.pair_uri("CODE7777"), "--name", "stuck"])
        .await;
    let daemon = env.start();
    let link = mock.next_device(WAIT).await.expect("connects");
    state.lock().unwrap().refuse_delete = Some("delete dismissed".into());

    let r = env.run(&["config", "set", "token_storage", "file"]).await;
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(
        r.err.contains("keyring entry stays") && r.err.contains("delete dismissed"),
        "{}",
        r.err
    );
    assert!(
        r.out.contains("The running client took the change."),
        "{}",
        r.out
    );
    let cfg = std::fs::read_to_string(env.config()).unwrap();
    assert!(cfg.contains("token_storage = \"file\""), "{cfg}");
    assert!(env.home.join(".config/pithagoras-sync/token").exists());

    env.ok(&["config", "set", "token_storage", "keyring"]).await;
    // The same token: the link was kept through both changes.
    assert!(link.closed(Duration::from_millis(500)).await.is_none());
    let r = env.run(&["unpair"]).await;
    assert_ne!(r.code, 0);
    assert!(
        r.err.contains("delete dismissed") && r.err.contains("unpair` again"),
        "{}",
        r.err
    );
    assert!(
        link.closed(WAIT).await.is_some(),
        "the running client let go of the portal"
    );
    state.lock().unwrap().refuse_delete = None;
    env.ok(&["unpair"]).await;
    assert!(state.lock().unwrap().items.is_empty());
    stop(daemon).await;
}

/// `sudo set` waits on the keyring's unlock prompt: a `panic` meanwhile keeps
/// the password out of the client's memory (the stored one comes back with
/// `unlock`), and a `sudo clear` meanwhile runs after the set and takes out
/// what it stored.
#[tokio::test(flavor = "multi_thread")]
async fn panic_or_clear_while_sudo_set_waits_on_the_keyring_wins() {
    use sync_testkit::keyring;
    let Some(bus) = keyring::private_bus() else {
        return;
    };
    let state = keyring::Shared::default();
    let _service = keyring::serve(&bus, state.clone()).await;
    let mut env = Env::new();
    env.vars
        .push(("DBUS_SESSION_BUS_ADDRESS".into(), bus.address.clone()));
    env.ok(&[
        "config",
        "set",
        "policy.privilege.secret_storage",
        "keyring",
    ])
    .await;
    let daemon = env.start();
    let end = std::time::Instant::now() + WAIT;
    while !env
        .run(&["status", "--json"])
        .await
        .out
        .contains("\"paused\"")
    {
        assert!(std::time::Instant::now() < end, "the client never answered");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stored = || {
        state
            .lock()
            .unwrap()
            .items
            .iter()
            .any(|(_, a, _)| a.get("name").map(String::as_str) == Some("elevation"))
    };
    let held = || async {
        let s: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
        s["elevation_password"].as_bool().unwrap()
    };
    let lock = || {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.answer = None;
        s.prompts
    };

    let line = format!("{PW}\n");
    let before = lock();
    let (set, ()) = tokio::join!(env.run_with(&["sudo", "set", "--stdin"], &line), async {
        eventually("sudo set asks to unlock the keyring", || {
            state.lock().unwrap().prompts > before
        })
        .await;
        env.ok(&["panic"]).await;
        keyring::answer_waiting(&state, true).await;
    });
    assert_ne!(set.code, 0);
    assert!(
        set.err.contains("panic or sudo clear came in"),
        "{}",
        set.err
    );
    assert!(!set.err.contains(PW));
    assert!(stored());
    assert!(!held().await);
    env.ok(&["unlock"]).await;
    assert!(held().await);

    let log = env.root.join("daemon.log");
    let before = lock();
    let (set, clear, ()) = tokio::join!(
        env.run_with(&["sudo", "set", "--stdin"], &line),
        async {
            eventually("sudo set asks to unlock the keyring", || {
                state.lock().unwrap().prompts > before
            })
            .await;
            env.run(&["sudo", "clear"]).await
        },
        async {
            eventually("sudo clear waits for the set", || {
                std::fs::read_to_string(&log)
                    .unwrap_or_default()
                    .contains("sudo clear waits for the sudo set before it")
            })
            .await;
            keyring::answer_waiting(&state, true).await;
        }
    );
    assert_ne!(set.code, 0, "{}", set.out);
    assert_eq!(clear.code, 0, "{}", clear.err);
    assert!(!stored(), "the clear took out what the set stored");
    assert!(!held().await);
    stop(daemon).await;
}

/// Right after the pairing changes, the link to the old portal may still be up:
/// `status` does not call that connected to the new one, so the window that
/// paired does not report a portal that turns the client away as connected.
#[tokio::test(flavor = "multi_thread")]
async fn the_old_link_is_not_reported_as_the_new_pairing() {
    let env = Env::new();
    let old = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE1234".into()],
    })
    .await;
    // Knows no token of this device: it refuses the link.
    let new = MockPortal::start(MockOptions::default()).await;
    env.ok(&["pair", &old.pair_uri("CODE1234"), "--name", "testbox"])
        .await;
    let daemon = env.start();
    let _dl = old.next_device(WAIT).await.expect("the client connects");
    let cfg = std::fs::read_to_string(env.config()).unwrap();
    assert!(cfg.contains(&old.url), "{cfg}");
    std::fs::write(env.config(), cfg.replace(&old.url, &new.url)).unwrap();
    // Any edit by the owner reloads the config.
    env.ok(&["mode", "ask"]).await;
    let end = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < end {
        let s: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
        assert_eq!(s["portal"], new.url.as_str());
        assert_ne!(s["link"]["state"], "connected", "{s}");
    }
    assert!(new.refused() > 0);
    stop(daemon).await;
}

/// A pairing the portal answers with the device id it gave before, and a new
/// token: the running client switches to that token, though only the time of
/// the pairing tells the two apart in the config.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_pairing_with_the_same_device_id_is_used() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE1234".into(), "CODE5678".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE1234"), "--name", "testbox"])
        .await;
    let daemon = env.start();
    let first = mock.next_device(WAIT).await.expect("the client connects");
    let id = first.device_id.clone();
    mock.pair_next_as(&id);
    env.ok(&["pair", &mock.pair_uri("CODE5678"), "--name", "testbox"])
        .await;
    let again = mock
        .next_device(WAIT)
        .await
        .expect("the client links again");
    assert_eq!(again.device_id, id);
    stop(daemon).await;
}

/// The portal removed the device: the client stays down until it is paired
/// again. A policy change in between does not try the refused token once more.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_link_waits_for_a_new_pairing() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE1234".into(), "CODE5678".into()],
    })
    .await;
    env.ok(&["pair", &mock.pair_uri("CODE1234"), "--name", "testbox"])
        .await;
    let daemon = env.start();
    let first = mock.next_device(WAIT).await.expect("the client connects");
    mock.revoke(&first.device_id).await;
    let end = std::time::Instant::now() + WAIT;
    loop {
        let s: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
        if s["link"]["state"] == "rejected" {
            break;
        }
        assert!(std::time::Instant::now() < end, "{s}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    env.ok(&["mode", "ask"]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(mock.refused(), 0, "the refused token was tried again");
    env.ok(&["pair", &mock.pair_uri("CODE5678"), "--name", "testbox"])
        .await;
    mock.next_device(WAIT)
        .await
        .expect("the new pairing connects");
    assert_eq!(mock.refused(), 0);
    stop(daemon).await;
}

/// A keyring prompt the owner leaves open ends the request within the client's
/// time for it (shortened here): the CLI hears an error before it stops
/// waiting, the prompt is dismissed, and nothing is taken, cleared or loaded
/// after that answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_keyring_prompt_left_open_ends_the_request_in_time() {
    use sync_testkit::keyring;
    let Some(bus) = keyring::private_bus() else {
        return;
    };
    let state = keyring::Shared::default();
    let _service = keyring::serve(&bus, state.clone()).await;
    let mut env = Env::new();
    env.vars
        .push(("DBUS_SESSION_BUS_ADDRESS".into(), bus.address.clone()));
    env.vars
        .push(("PITHAGORAS_SYNC_TEST_KEYRING_WORK_MS".into(), "1500".into()));
    env.ok(&[
        "config",
        "set",
        "policy.privilege.secret_storage",
        "keyring",
    ])
    .await;
    let daemon = env.start();
    let end = std::time::Instant::now() + WAIT;
    while !env
        .run(&["status", "--json"])
        .await
        .out
        .contains("\"paused\"")
    {
        assert!(std::time::Instant::now() < end, "the client never answered");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stored = || {
        state
            .lock()
            .unwrap()
            .items
            .iter()
            .any(|(_, a, _)| a.get("name").map(String::as_str) == Some("elevation"))
    };
    let held = || async {
        let s: Value = serde_json::from_str(&env.ok(&["status", "--json"]).await).unwrap();
        s["elevation_password"].as_bool().unwrap()
    };
    let lock = || {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.answer = None;
    };
    let dismissed = || state.lock().unwrap().dismissed;
    let line = format!("{PW}\n");

    lock();
    let started = std::time::Instant::now();
    let set = env.run_with(&["sudo", "set", "--stdin"], &line).await;
    assert_ne!(set.code, 0);
    assert!(set.err.contains("did not finish in time"), "{}", set.err);
    assert!(started.elapsed() < WAIT, "{:?}", started.elapsed());
    eventually("the set's prompt is dismissed", || dismissed() == 1).await;
    assert!(!stored());
    assert!(!held().await);

    state.lock().unwrap().locked = false;
    let set = env.run_with(&["sudo", "set", "--stdin"], &line).await;
    assert_eq!(set.code, 0, "{}", set.err);
    assert!(stored() && held().await);
    lock();
    let clear = env.run(&["sudo", "clear"]).await;
    assert_ne!(clear.code, 0);
    assert!(clear.err.contains("sudo clear` again"), "{}", clear.err);
    eventually("the clear's prompt is dismissed", || dismissed() == 2).await;
    assert!(!held().await, "forgotten in memory all the same");
    assert!(stored());
    let unlock = env.run(&["unlock"]).await;
    assert_ne!(unlock.code, 0);
    assert!(
        unlock.err.contains("did not finish in time"),
        "{}",
        unlock.err
    );
    eventually("the unlock's prompt is dismissed", || dismissed() == 3).await;
    // The owner answers at last: nothing waits on it any more.
    keyring::answer_waiting(&state, true).await;
    assert!(!held().await);
    stop(daemon).await;
}

/// The owner kept the password and the token in the keyring, then switched
/// both away from it (the token's old entry could not be removed then):
/// `sudo clear` and `uninstall --purge` still take out what is left there,
/// and a status looks without a prompt.
#[tokio::test(flavor = "multi_thread")]
async fn what_an_earlier_setting_left_in_the_keyring_is_removed_too() {
    use sync_testkit::keyring;
    let Some(bus) = keyring::private_bus() else {
        return;
    };
    let state = keyring::Shared::default();
    let _service = keyring::serve(&bus, state.clone()).await;
    let mut env = Env::new();
    env.vars
        .push(("DBUS_SESSION_BUS_ADDRESS".into(), bus.address.clone()));
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE7777".into()],
    })
    .await;
    let names = || {
        let mut n: Vec<String> = state
            .lock()
            .unwrap()
            .items
            .iter()
            .filter_map(|(_, a, _)| a.get("name").cloned())
            .collect();
        n.sort();
        n
    };
    let secret_storage = "policy.privilege.secret_storage";
    env.ok(&["config", "set", secret_storage, "keyring"]).await;
    let r = env
        .run_with(&["sudo", "set", "--stdin"], &format!("{PW}\n"))
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    // Locked: the status sees the entry without asking to unlock.
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.answer = Some(false);
    }
    let r = env.run(&["sudo", "status"]).await;
    assert!(r.out.contains("set (kept in keyring)"), "{}", r.out);
    assert_eq!(state.lock().unwrap().prompts, 0);
    state.lock().unwrap().locked = false;

    env.ok(&["config", "set", secret_storage, "memory"]).await;
    env.ok(&["sudo", "clear"]).await;
    assert!(names().is_empty(), "{:?}", names());

    env.ok(&["config", "set", secret_storage, "keyring"]).await;
    let r = env
        .run_with(&["sudo", "set", "--stdin"], &format!("{PW}\n"))
        .await;
    assert_eq!(r.code, 0, "{}", r.err);
    env.ok(&["config", "set", secret_storage, "file"]).await;
    env.ok(&["config", "set", "token_storage", "keyring"]).await;
    env.ok(&["pair", &mock.pair_uri("CODE7777"), "--name", "left"])
        .await;
    state.lock().unwrap().refuse_delete = Some("delete dismissed".into());
    env.ok(&["config", "set", "token_storage", "file"]).await;
    state.lock().unwrap().refuse_delete = None;
    assert_eq!(names(), ["elevation", "token"]);

    let path = fake_systemd(&env);
    let out = env
        .cmd(&["uninstall", "--purge", "--print"])
        .env("PATH", &path)
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("remove the connector token from the keyring")
            && text.contains("remove the elevation password from the keyring"),
        "{text}"
    );
    let out = env
        .cmd(&["uninstall", "--purge", "--yes"])
        .env("PATH", &path)
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(names().is_empty(), "{:?}", names());

    // Both set to the keyring, which holds nothing: there is nothing to
    // remove from it.
    env.ok(&["config", "set", secret_storage, "keyring"]).await;
    env.ok(&["config", "set", "token_storage", "keyring"]).await;
    let out = env
        .cmd(&["uninstall", "--purge", "--print"])
        .env("PATH", &path)
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(!text.contains("from the keyring"), "{text}");
}

/// A test without the fake keyring reaches no keyring at all: the harness
/// keeps the real session bus of whoever runs the tests out.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_fake_keyring_the_tests_reach_no_keyring() {
    let env = Env::new();
    let mock = MockPortal::start(MockOptions {
        tls: false,
        codes: vec!["CODE7777".into()],
    })
    .await;
    env.ok(&["config", "set", "token_storage", "keyring"]).await;
    let r = env.run(&["pair", &mock.pair_uri("CODE7777")]).await;
    assert_ne!(r.code, 0);
    assert!(
        r.err.contains("PITHAGORAS_SYNC_NO_KEYRING is set"),
        "{}",
        r.err
    );
}
