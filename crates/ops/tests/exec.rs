//! Exec: output, environment, timeouts, panic, signals, the output cap, Landlock and
//! cgroups. This binary is also the shim (`__exec-shim`), so the real shim runs.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::Duration;

use sync_ops::{ExecConfig, ExecOutcome, Execs, SHIM_ARG, shim_main};
use sync_policy::{Confine, Permit};
#[cfg(target_os = "linux")]
use sync_proto::methods::Signal;
use tokio::sync::mpsc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(SHIM_ARG) {
        std::process::exit(shim_main());
    }
    run_tests(&args);
}

type Test = fn() -> Pin<Box<dyn Future<Output = ()>>>;

macro_rules! tests {
    ($($name:ident),* $(,)?) => {
        vec![$((stringify!($name), (|| Box::pin($name()) as Pin<Box<dyn Future<Output = ()>>>) as Test)),*]
    };
}

#[cfg(target_os = "linux")]
fn all() -> Vec<(&'static str, Test)> {
    tests![
        output_and_exit_code,
        no_portal_environment,
        timeout_kills_detached_children,
        panic_kills_what_outlived_its_shell,
        sigint_reaches_the_command,
        sigkill_from_the_portal_ends_it,
        output_is_capped,
        scrubbed_output_stays_within_the_frame_size,
        landlock_keeps_the_shell_in_its_folders,
        a_confined_commands_tmpdir_is_its_own,
        commands_get_their_own_cgroup,
        the_shim_dies_with_the_client,
        the_shim_takes_the_secret_only_untraced,
        two_starts_cannot_share_a_stream_or_pass_the_limit,
        a_panic_during_a_start_leaves_nothing_running,
        the_environment_stays_out_of_the_command_line,
        a_root_command_outside_its_cgroup_does_not_run,
    ]
}

#[cfg(windows)]
fn all() -> Vec<(&'static str, Test)> {
    tests![
        windows_output_and_exit_code,
        windows_output_is_plain_utf8_text,
        windows_no_portal_environment,
        windows_panic_kills_the_job,
    ]
}

fn run_tests(args: &[String]) {
    let filters: Vec<&String> = args[1..].iter().filter(|a| !a.starts_with("--")).collect();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut failed = Vec::new();
    let mut ran = 0;
    for (name, test) in all() {
        if !filters.is_empty() && !filters.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        ran += 1;
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async { tokio::time::timeout(Duration::from_secs(60), test()).await })
                .expect("test timed out")
        }))
        .is_ok();
        println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
        if !ok {
            failed.push(name);
        }
    }
    println!(
        "\ntest result: {}. {} passed; {} failed",
        if failed.is_empty() { "ok" } else { "FAILED" },
        ran - failed.len(),
        failed.len()
    );
    if !failed.is_empty() {
        std::process::exit(1);
    }
}

struct Fx {
    _t: tempfile::TempDir,
    dir: PathBuf,
}

fn fx() -> Fx {
    let t = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(t.path()).unwrap();
    Fx { _t: t, dir }
}

fn config(fx: &Fx, base_env: Vec<(String, String)>) -> ExecConfig {
    ExecConfig {
        shim_program: std::env::current_exe().unwrap(),
        shim_args: vec![],
        shell: None,
        base_env,
        env_passthrough: vec!["PORTAL_SECRET".into()],
        output_cap: 1 << 20,
        max_timeout: Duration::from_secs(30),
        max_running: 8,
        tmp_base: fx.dir.join("exec-tmp"),
    }
}

fn own_env() -> Vec<(String, String)> {
    std::env::vars().collect()
}

fn permit(cwd: &Path) -> Permit {
    Permit {
        path: cwd.to_path_buf(),
        root: None,
        confine: Confine::None,
        elevate: None,
    }
}

/// Runs a command to the end; returns its output and outcome.
async fn run(
    execs: &Execs,
    stream: u32,
    cmd: &str,
    p: &Permit,
    timeout: Option<Duration>,
) -> (String, ExecOutcome) {
    let (tx, mut rx) = mpsc::channel(4);
    let started = execs.start(stream, cmd, p, timeout, tx).unwrap();
    let collect = tokio::spawn(async move {
        let mut out = Vec::new();
        while let Some(c) = rx.recv().await {
            out.extend(c);
        }
        String::from_utf8_lossy(&out).into_owned()
    });
    let outcome = started.outcome.await.unwrap();
    let out = tokio::time::timeout(Duration::from_secs(5), collect)
        .await
        .map(|r| r.unwrap())
        .unwrap_or_default();
    (out, outcome)
}

#[cfg(target_os = "linux")]
fn alive(marker: &str) -> bool {
    std::fs::read_dir("/proc").unwrap().flatten().any(|e| {
        std::fs::read(e.path().join("cmdline"))
            .map(|c| String::from_utf8_lossy(&c).contains(marker))
            .unwrap_or(false)
    })
}

#[cfg(target_os = "linux")]
async fn gone(marker: &str) -> bool {
    for _ in 0..50 {
        if !alive(marker) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[cfg(target_os = "linux")]
fn marker(n: u32) -> String {
    // `sleep` takes fractions: a unique argument per run to find the processes by.
    format!("{n}.{}", std::process::id())
}

#[cfg(target_os = "linux")]
async fn output_and_exit_code() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    let (out, o) = run(
        &e,
        1,
        "echo hello; echo oops >&2; pwd; exit 3",
        &permit(&f.dir),
        None,
    )
    .await;
    assert!(out.contains("hello") && out.contains("oops"), "{out}");
    assert!(out.contains(&f.dir.to_string_lossy().into_owned()), "{out}");
    assert_eq!(o.code, Some(3));
    assert!(!o.timed_out && !o.truncated);
}

#[cfg(target_os = "linux")]
async fn no_portal_environment() {
    let f = fx();
    let mut env = own_env();
    env.push(("PORTAL_SECRET".into(), "hunter2".into()));
    env.push(("PORTAL_ALLOW_NO_PASSWORD".into(), "1".into()));
    let e = Execs::new(config(&f, env));
    // The command's own environment and its parent's (the shim's).
    let (out, o) = run(
        &e,
        1,
        "env; echo ---; tr '\\0' '\\n' < /proc/$PPID/environ",
        &permit(&f.dir),
        None,
    )
    .await;
    assert_eq!(o.code, Some(0), "{out}");
    assert!(out.contains("PATH="), "{out}");
    assert!(!out.contains("PORTAL_"), "{out}");
    assert!(!out.contains("hunter2"), "{out}");
}

#[cfg(target_os = "linux")]
async fn timeout_kills_detached_children() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    let (a, b, c) = (marker(3001), marker(3002), marker(3003));
    let cmd = format!(
        "setsid sleep {a} >/dev/null 2>&1 < /dev/null & nohup sleep {b} >/dev/null 2>&1 & (sleep {c} &); sleep 30"
    );
    let (_, o) = run(
        &e,
        1,
        &cmd,
        &permit(&f.dir),
        Some(Duration::from_millis(800)),
    )
    .await;
    assert!(o.timed_out);
    for m in [&a, &b, &c] {
        assert!(gone(m).await, "sleep {m} survived the timeout");
    }
}

#[cfg(target_os = "linux")]
async fn panic_kills_what_outlived_its_shell() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    let m = marker(3011);
    let cmd = format!("setsid sleep {m} >/dev/null 2>&1 < /dev/null & disown; echo started");
    let (out, o) = run(&e, 1, &cmd, &permit(&f.dir), None).await;
    assert_eq!(o.code, Some(0), "{out}");
    assert!(alive(&m), "the background process should outlive its shell");
    e.kill_all().await;
    assert!(gone(&m).await, "panic left sleep {m} running");
}

#[cfg(target_os = "linux")]
async fn sigint_reaches_the_command() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    let (tx, mut rx) = mpsc::channel(4);
    let s = e.start(1, "sleep 20", &permit(&f.dir), None, tx).unwrap();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    tokio::time::sleep(Duration::from_millis(300)).await;
    e.signal(1, Signal::Int).await.unwrap();
    let o = s.outcome.await.unwrap();
    assert_eq!(o.signal.as_deref(), Some("SIGINT"), "{o:?}");
}

#[cfg(target_os = "linux")]
async fn sigkill_from_the_portal_ends_it() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    let m = marker(3021);
    let (tx, mut rx) = mpsc::channel(4);
    let cmd = format!("setsid sleep {m} >/dev/null 2>&1 < /dev/null & sleep 20");
    let s = e.start(1, &cmd, &permit(&f.dir), None, tx).unwrap();
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    tokio::time::sleep(Duration::from_millis(300)).await;
    e.signal(1, Signal::Kill).await.unwrap();
    let o = s.outcome.await.unwrap();
    assert!(o.code.is_none(), "{o:?}");
    assert!(gone(&m).await);
    assert!(
        e.signal(1, Signal::Kill).await.is_err(),
        "no longer running"
    );
}

#[cfg(target_os = "linux")]
async fn output_is_capped() {
    let f = fx();
    let mut cfg = config(&f, own_env());
    cfg.output_cap = 1000;
    let e = Execs::new(cfg);
    let (out, o) = run(
        &e,
        1,
        "head -c 200000 /dev/zero | tr '\\0' a",
        &permit(&f.dir),
        None,
    )
    .await;
    assert_eq!(out.len(), 1000);
    assert!(o.truncated);
    assert_eq!(o.code, Some(0));
}

/// With an elevation password set, the scrubbed output can be longer than it was
/// read; it still goes out in frames the portal takes (at most `MAX_CHUNK`).
#[cfg(target_os = "linux")]
async fn scrubbed_output_stays_within_the_frame_size() {
    use sync_proto::binary::MAX_CHUNK;
    let f = fx();
    let mut cfg = config(&f, own_env());
    cfg.output_cap = 8 << 20;
    let e = Execs::new(cfg);
    let slot = Arc::new(sync_policy::secret::SecretSlot::default());
    slot.set(sync_policy::secret::Secret::new("pa55word".into()));
    e.use_secrets(slot);
    // Every short secret becomes the longer `[redacted]`, and a held-back `p`
    // goes in front of the next full chunk.
    let cmd = "yes pa55word | head -c 1000000; \
               head -c 65535 /dev/zero | tr '\\0' x; printf p; head -c 300000 /dev/zero | tr '\\0' x";
    let (tx, mut rx) = mpsc::channel(4);
    let started = e.start(1, cmd, &permit(&f.dir), None, tx).unwrap();
    let (mut largest, mut total) = (0, 0);
    let mut text = Vec::new();
    while let Some(c) = rx.recv().await {
        largest = largest.max(c.len());
        total += c.len();
        text.extend(c);
    }
    let o = started.outcome.await.unwrap();
    assert_eq!(o.code, Some(0), "{o:?}");
    assert!(largest <= MAX_CHUNK, "a frame of {largest} bytes");
    let text = String::from_utf8_lossy(&text);
    assert!(!text.contains("pa55word"));
    assert_eq!(text.matches("[redacted]").count(), 1_000_000 / 9);
    assert!(total > 1_000_000 + 365_536, "{total}");
}

#[cfg(target_os = "linux")]
async fn landlock_keeps_the_shell_in_its_folders() {
    if !sync_ops::landlock_available() {
        panic!("this kernel has no Landlock; the test cannot show confinement");
    }
    let f = fx();
    let home = f.dir.join("home");
    for d in ["home/proj", "home/private", "home/.ssh", "outside", "tools"] {
        std::fs::create_dir_all(f.dir.join(d)).unwrap();
    }
    std::fs::write(f.dir.join("outside/secret"), "s").unwrap();
    std::fs::write(home.join(".ssh/id"), "key").unwrap();
    std::fs::write(home.join("private/p"), "p").unwrap();
    use std::os::unix::fs::PermissionsExt;
    for script in [home.join("proj/run.sh"), f.dir.join("tools/tool.sh")] {
        std::fs::write(&script, "#!/bin/sh\necho ran\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let protected = sync_policy::protected::Protected::new(&home, &[], &Default::default());
    let grants = vec![
        sync_policy::FolderGrant {
            path: home.clone(),
            access: sync_policy::Access::Rw,
            execute: true,
        },
        // Readable, but its programs do not run.
        sync_policy::FolderGrant {
            path: f.dir.join("tools"),
            access: sync_policy::Access::Ro,
            execute: false,
        },
    ];
    let denied = [(home.join("private"), sync_policy::config::Rights::ALL)];
    let rules = sync_policy::engine::landlock_rules(&grants, &protected, &denied);
    let p = Permit {
        path: home.join("proj"),
        root: Some(home.clone()),
        confine: Confine::Landlock(rules),
        elevate: None,
    };
    let e = Execs::new(config(&f, own_env()));
    let me = std::process::id();
    let cmd = format!(
        "echo a > {h}/proj/inside && echo WROTE_INSIDE; \
         echo b > {o}/new 2>/dev/null || echo NO_WRITE_OUTSIDE; \
         cat {o}/secret 2>/dev/null || echo NO_READ_OUTSIDE; \
         cat {h}/.ssh/id 2>/dev/null || echo NO_READ_SSH; \
         echo x > {h}/.bashrc 2>/dev/null || echo NO_WRITE_HOME_ROOT; \
         echo t > $TMPDIR/t && echo WROTE_TMP; \
         kill -0 {me} 2>/dev/null && echo SIGNAL_OUT || echo NO_SIGNAL_OUT; \
         {h}/proj/run.sh >/dev/null && echo RAN_INSIDE; \
         cat {t}/tool.sh >/dev/null && echo READ_TOOLS; \
         {t}/tool.sh 2>/dev/null || echo NO_EXEC_TOOLS; \
         cat {h}/private/p 2>/dev/null || echo NO_READ_DENIED",
        h = home.display(),
        o = f.dir.join("outside").display(),
        t = f.dir.join("tools").display(),
    );
    let (out, o) = run(&e, 1, &cmd, &p, None).await;
    assert_eq!(o.code, Some(0), "{out} {o:?}");
    for want in [
        "WROTE_INSIDE",
        "NO_WRITE_OUTSIDE",
        "NO_READ_OUTSIDE",
        "NO_READ_SSH",
        "NO_WRITE_HOME_ROOT",
        "WROTE_TMP",
        "RAN_INSIDE",
        "READ_TOOLS",
        "NO_EXEC_TOOLS",
        "NO_READ_DENIED",
    ] {
        assert!(out.contains(want), "missing {want}: {out}");
    }
    assert!(!f.dir.join("outside/new").exists());
    assert!(home.join("proj/inside").exists());
    if sync_ops::shim::landlock::abi_version().unwrap_or(0) >= 6 {
        assert!(out.contains("NO_SIGNAL_OUT"), "{out}");
    }
}

/// A confined command's private TMPDIR is its own: removed when the command is
/// gone, and never handed to a later command on the same stream number.
#[cfg(target_os = "linux")]
async fn a_confined_commands_tmpdir_is_its_own() {
    if !sync_ops::landlock_available() {
        panic!("this kernel has no Landlock; the test cannot show confinement");
    }
    let f = fx();
    let proj = f.dir.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let protected = sync_policy::protected::Protected::new(&f.dir, &[], &Default::default());
    let grants = vec![sync_policy::FolderGrant {
        path: proj.clone(),
        access: sync_policy::Access::Rw,
        execute: true,
    }];
    let p = Permit {
        path: proj.clone(),
        root: Some(proj.clone()),
        confine: Confine::Landlock(sync_policy::engine::landlock_rules(
            &grants,
            &protected,
            &[],
        )),
        elevate: None,
    };
    let e = Execs::new(config(&f, own_env()));
    let cmd = "echo secret > \"$TMPDIR/left\" && echo \"dir=$TMPDIR\"; ls -A \"$TMPDIR\"";
    let dir = |out: &str| {
        let d = out
            .lines()
            .find_map(|l| l.strip_prefix("dir="))
            .unwrap_or_else(|| panic!("no TMPDIR: {out}"));
        PathBuf::from(d)
    };
    let (out, o) = run(&e, 1, cmd, &p, None).await;
    assert_eq!(o.code, Some(0), "{out}");
    let first = dir(&out);
    assert!(first.starts_with(f.dir.join("exec-tmp")), "{out}");
    let mut removed = false;
    for _ in 0..50 {
        if !first.exists() {
            removed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(removed, "{} outlived its command", first.display());
    // The same stream number again (as after a reconnect): a fresh, empty one.
    let (out, o) = run(&e, 1, "echo \"dir=$TMPDIR\"; ls -A \"$TMPDIR\"", &p, None).await;
    assert_eq!(o.code, Some(0), "{out}");
    assert_ne!(dir(&out), first);
    assert!(!out.contains("left"), "{out}");
}

#[cfg(target_os = "linux")]
async fn commands_get_their_own_cgroup() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    if !e.uses_cgroups() {
        eprintln!("  (no delegated cgroup here; the shim's process tree is the only fence)");
        return;
    }
    let (out, _) = run(&e, 1, "cat /proc/self/cgroup", &permit(&f.dir), None).await;
    assert!(out.contains("pithagoras-exec-"), "{out}");
}

#[cfg(target_os = "linux")]
async fn the_shim_dies_with_the_client() {
    // A shim whose parent is not the client named in its spec refuses to run, so a
    // shim cannot outlive a client that died while starting it.
    let f = fx();
    let spec = sync_ops::shim::ShimSpec {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "echo should-not-run".into()],
        cwd: f.dir.clone(),
        env: vec![],
        parent: 1,
        cgroup: None,
        require_cgroup: false,
        landlock: None,
        secret_fd: false,
    };
    let out = run_shim(&serde_json::to_string(&spec).unwrap());
    assert_eq!(out.status.code(), Some(125));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("should-not-run"));
}

/// Runs the shim by hand with `spec` on its stdin, as the client starts it.
#[cfg(target_os = "linux")]
fn run_shim(spec: &str) -> std::process::Output {
    use std::io::Write;
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(SHIM_ARG)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(spec.as_bytes());
    drop(stdin);
    child.wait_with_output().unwrap()
}

/// Runs the shim with `secret_fd`, the client's end of fd 4 answering as the client
/// does; with `trace`, the test traces the shim (PTRACE_TRACEME). Returns the
/// exit code, stdout and whether the shim said it was ready for the secret.
#[cfg(target_os = "linux")]
fn shim_with_secret(dir: &Path, trace: bool) -> (i32, String, bool) {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let spec = sync_ops::shim::ShimSpec {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "printf 'got:'; cat".into()],
        cwd: dir.to_path_buf(),
        env: vec![],
        parent: std::process::id(),
        cgroup: None,
        require_cgroup: false,
        landlock: None,
        secret_fd: true,
    };
    let (mut mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let raw = theirs.as_raw_fd();
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.arg(SHIM_ARG)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    // SAFETY: dup2 and ptrace only, both async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if trace && libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Reaped below with waitpid, as its tracer must.
    #[allow(clippy::zombie_processes)]
    let mut child = cmd.spawn().unwrap();
    drop(theirs);
    let pid = child.id() as i32;
    let mut stdin = child.stdin.take().unwrap();
    let spec = serde_json::to_string(&spec).unwrap();
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(spec.as_bytes());
    });
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        s
    });
    let answer = std::thread::spawn(move || {
        let mut r = [0u8; 1];
        let ready = mine.read_exact(&mut r).is_ok() && r == *b"R";
        if ready {
            let _ = mine.write_all(b"pw-for-sudo");
        }
        ready
    });
    // As the tracer: let the shim go on after every stop, until it exits.
    let code = loop {
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
            // SAFETY: the shim is our tracee.
            unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, sig) };
        }
    };
    let ready = answer.join().unwrap();
    feeder.join().unwrap();
    (code, reader.join().unwrap(), ready)
}

#[cfg(target_os = "linux")]
async fn the_shim_takes_the_secret_only_untraced() {
    // The secret reaches the command on stdin, in one line, through a fresh pipe.
    let f = fx();
    let (code, out, ready) = shim_with_secret(&f.dir, false);
    assert_eq!((code, out.as_str(), ready), (0, "got:pw-for-sudo\n", true));
    // A traced shim is never sent the secret, and runs nothing.
    let (code, out, ready) = shim_with_secret(&f.dir, true);
    assert_eq!((code, out.as_str(), ready), (126, "", false));
}

/// Two `start` calls at once (`n` of them, each on `streams[i]`), as two portal
/// calls run on two workers; returns how many were started.
#[cfg(target_os = "linux")]
async fn start_at_once(e: &Arc<Execs>, f: &Fx, streams: [u32; 2], cmd: &str) -> usize {
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut calls = Vec::new();
    for stream in streams {
        let (e, barrier, p, cmd) = (e.clone(), barrier.clone(), permit(&f.dir), cmd.to_string());
        calls.push(tokio::task::spawn_blocking(move || {
            let (tx, _rx) = mpsc::channel(4);
            barrier.wait();
            e.start(stream, &cmd, &p, None, tx).is_ok()
        }));
    }
    let mut started = 0;
    for c in calls {
        started += usize::from(c.await.unwrap());
    }
    started
}

#[cfg(target_os = "linux")]
async fn two_starts_cannot_share_a_stream_or_pass_the_limit() {
    // Each start is checked and counted before its shim is spawned, so neither a
    // second command on a stream in use nor one over the limit gets in, and every
    // command that started is in the table that panic kills from.
    let f = fx();
    let mut cfg = config(&f, own_env());
    cfg.max_running = 1;
    let e = Arc::new(Execs::new(cfg));
    for (round, streams) in [[7, 7], [7, 8], [9, 9]].into_iter().enumerate() {
        let m = marker(3100 + round as u32);
        let started = start_at_once(&e, &f, streams, &format!("sleep {m}")).await;
        assert_eq!(started, 1, "round {round}: {started} commands started");
        assert_eq!(e.running(), 1);
        e.kill_all().await;
        assert!(
            gone(&m).await,
            "round {round}: panic left sleep {m} running"
        );
    }
}

#[cfg(target_os = "linux")]
async fn a_panic_during_a_start_leaves_nothing_running() {
    // A panic that comes while a command's shim is being spawned: the command is
    // killed when it would enter the table, and the start answers DENIED.
    let f = fx();
    let e = Arc::new(Execs::new(config(&f, own_env())));
    for round in 0..5u32 {
        let m = marker(3200 + round);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let (e2, b2, p) = (e.clone(), barrier.clone(), permit(&f.dir));
        let cmd = format!("sleep {m}");
        let start = tokio::task::spawn_blocking(move || {
            let (tx, _rx) = mpsc::channel(4);
            b2.wait();
            e2.start(8, &cmd, &p, None, tx).map(|_| ())
        });
        tokio::task::spawn_blocking(move || {
            barrier.wait();
            std::thread::sleep(Duration::from_micros(200));
        })
        .await
        .unwrap();
        e.pause().await;
        let r = start.await.unwrap();
        assert!(
            gone(&m).await,
            "round {round}: sleep {m} outlived the panic ({r:?})"
        );
        assert_eq!(e.running(), 0, "round {round}: {r:?}");
        // Paused, nothing starts; after unlock it does again.
        let (tx, _rx) = mpsc::channel(4);
        let err = e.start(9, "true", &permit(&f.dir), None, tx).err().unwrap();
        assert_eq!(err.code, sync_proto::code::DENIED);
        e.set_paused(false);
    }
    let (out, o) = run(&e, 9, "echo again", &permit(&f.dir), None).await;
    assert_eq!((out.as_str(), o.code), ("again\n", Some(0)));
}

#[cfg(target_os = "linux")]
async fn the_environment_stays_out_of_the_command_line() {
    // A passed-through variable (a token, typically) reaches the command but no
    // process's command line, which every user on the machine can read.
    let f = fx();
    let token = format!("tok-{}", marker(3301));
    let mut env = own_env();
    env.push(("SYNC_TEST_TOKEN".into(), token.clone()));
    let mut cfg = config(&f, env);
    cfg.env_passthrough = vec!["SYNC_TEST_TOKEN".into()];
    let e = Execs::new(cfg);
    let m = marker(3302);
    let (tx, mut rx) = mpsc::channel(4);
    let cmd = format!("echo \"$SYNC_TEST_TOKEN\"; sleep {m}");
    let s = e.start(1, &cmd, &permit(&f.dir), None, tx).unwrap();
    let first = rx.recv().await.unwrap();
    assert_eq!(String::from_utf8_lossy(&first).trim(), token);
    assert!(alive(&m), "the command should still run");
    assert!(!alive(&token), "the token is in a command line");
    e.signal(1, Signal::Kill).await.unwrap();
    s.outcome.await.unwrap();
}

#[cfg(target_os = "linux")]
async fn a_root_command_outside_its_cgroup_does_not_run() {
    // An elevated command must be in its cgroup, the only thing panic can kill
    // root's processes by; a shim that cannot join it runs nothing.
    let f = fx();
    let spec = serde_json::json!({
        "program": "/bin/sh",
        "args": ["-c", "echo should-not-run"],
        "cwd": f.dir,
        "env": [],
        "parent": std::process::id(),
        "cgroup": f.dir.join("no-such-cgroup"),
        "require_cgroup": true,
        "landlock": null,
        "secret_fd": false,
    });
    let out = run_shim(&spec.to_string());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("should-not-run"));
    assert_eq!(out.status.code(), Some(126));
    // A user's command still runs without one.
    let mut spec = spec;
    spec["require_cgroup"] = false.into();
    let out = run_shim(&spec.to_string());
    assert!(String::from_utf8_lossy(&out.stdout).contains("should-not-run"));
}

#[cfg(windows)]
async fn windows_output_and_exit_code() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    let (out, o) = run(&e, 1, "Write-Output hello; exit 3", &permit(&f.dir), None).await;
    assert!(out.contains("hello"), "{out}");
    assert_eq!(o.code, Some(3));
}

/// Errors as text (not CLIXML), quotes and backslashes as written, UTF-8 from
/// PowerShell and from console programs, and no console window of its own.
#[cfg(windows)]
async fn windows_output_is_plain_utf8_text() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    let cmd = r#"Write-Output ('caf' + [char]0xE9 + ' ' + [char]0x20AC)
Write-Output 'a"b' "c\d\" 'e\\f'
Write-Error boom
cmd /c echo native-%OS%
Add-Type -Name W -Namespace N -MemberDefinition '[DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();'
Write-Output "window=$([N.W]::GetConsoleWindow())"
exit 4"#;
    let (out, o) = run(&e, 1, cmd, &permit(&f.dir), None).await;
    let out = out.replace("\r\n", "\n");
    assert!(out.contains("caf\u{e9} \u{20ac}"), "{out}");
    assert!(out.contains("a\"b\nc\\d\\\ne\\\\f"), "{out}");
    assert!(out.contains("boom") && !out.contains("CLIXML"), "{out}");
    assert!(out.contains("native-Windows_NT"), "{out}");
    assert!(out.contains("window=0"), "{out}");
    assert_eq!(o.code, Some(4));
}

#[cfg(windows)]
async fn windows_no_portal_environment() {
    let f = fx();
    let mut env = own_env();
    env.push(("PORTAL_SECRET".into(), "hunter2".into()));
    let e = Execs::new(config(&f, env));
    let (out, _) = run(
        &e,
        1,
        "Get-ChildItem env: | Out-String -Width 400",
        &permit(&f.dir),
        None,
    )
    .await;
    assert!(out.contains("Path") || out.contains("PATH"), "{out}");
    assert!(!out.contains("PORTAL_"), "{out}");
}

#[cfg(windows)]
async fn windows_panic_kills_the_job() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    let flag = f.dir.join("still-running");
    let cmd = format!(
        "Start-Process -WindowStyle Hidden powershell -ArgumentList '-NoProfile','-Command','Start-Sleep 3; Set-Content \"{}\" x'; Write-Output started",
        flag.display()
    );
    let (out, _) = run(&e, 1, &cmd, &permit(&f.dir), None).await;
    assert!(out.contains("started"), "{out}");
    e.kill_all().await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!flag.exists(), "the detached process outlived the panic");
}
