//! Exec: output, environment, timeouts, panic, signals, the output cap, Landlock and
//! cgroups. This binary is also the shim (`__exec-shim`), so the real shim runs.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use sync_ops::{ExecConfig, ExecOutcome, Execs, SHIM_ARG, shim_main};
use sync_policy::{Confine, Permit};
#[cfg(target_os = "linux")]
use sync_proto::methods::Signal;
use tokio::sync::mpsc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(SHIM_ARG) {
        std::process::exit(shim_main(&args[2]));
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
        landlock_keeps_the_shell_in_its_folders,
        commands_get_their_own_cgroup,
        the_shim_dies_with_the_client,
    ]
}

#[cfg(windows)]
fn all() -> Vec<(&'static str, Test)> {
    tests![
        windows_output_and_exit_code,
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

#[cfg(target_os = "linux")]
async fn landlock_keeps_the_shell_in_its_folders() {
    if !sync_ops::landlock_available() {
        panic!("this kernel has no Landlock; the test cannot show confinement");
    }
    let f = fx();
    let home = f.dir.join("home");
    for d in ["home/proj", "home/.ssh", "outside"] {
        std::fs::create_dir_all(f.dir.join(d)).unwrap();
    }
    std::fs::write(f.dir.join("outside/secret"), "s").unwrap();
    std::fs::write(home.join(".ssh/id"), "key").unwrap();
    let protected = sync_policy::protected::Protected::new(&home, &[], &Default::default());
    let grants = vec![sync_policy::FolderGrant {
        path: home.clone(),
        access: sync_policy::Access::Rw,
    }];
    let rules = sync_policy::engine::landlock_rules(&grants, &protected);
    let p = Permit {
        path: home.join("proj"),
        root: Some(home.clone()),
        confine: Confine::Landlock(rules),
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
         kill -0 {me} 2>/dev/null && echo SIGNAL_OUT || echo NO_SIGNAL_OUT",
        h = home.display(),
        o = f.dir.join("outside").display(),
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
    ] {
        assert!(out.contains(want), "missing {want}: {out}");
    }
    assert!(!f.dir.join("outside/new").exists());
    assert!(home.join("proj/inside").exists());
    if sync_ops::shim::landlock::abi_version().unwrap_or(0) >= 6 {
        assert!(out.contains("NO_SIGNAL_OUT"), "{out}");
    }
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
        landlock: None,
    };
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(SHIM_ARG)
        .arg(serde_json::to_string(&spec).unwrap())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("should-not-run"));
}

#[cfg(windows)]
async fn windows_output_and_exit_code() {
    let f = fx();
    let e = Execs::new(config(&f, own_env()));
    let (out, o) = run(&e, 1, "Write-Output hello; exit 3", &permit(&f.dir), None).await;
    assert!(out.contains("hello"), "{out}");
    assert_eq!(o.code, Some(3));
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
