#![cfg(unix)]
//! The device's own decisions: folders, path escapes, protected paths, approvals,
//! taint, Full's expiry and pause. Every test here guards a fail-closed rule.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sync_policy::config::{CommandRule, DenyRule, GlobGrant, Hours, Rights};
use sync_policy::*;
use sync_proto::Id;
use sync_proto::methods::{Choice, PiTool};

/// Answers every prompt with a fixed answer, counting them.
struct Scripted {
    answer: Answer,
    asked: AtomicUsize,
    last: Mutex<Option<ApprovalRequest>>,
}

impl Approver for Scripted {
    fn can_prompt(&self) -> bool {
        true
    }
    fn ask<'a>(&'a self, req: &'a ApprovalRequest) -> BoxFuture<'a, Answer> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = Some(req.clone());
        let a = self.answer;
        Box::pin(async move { a })
    }
}

/// Never answers, like an owner who is away.
struct Never;

impl Approver for Never {
    fn can_prompt(&self) -> bool {
        true
    }
    fn ask<'a>(&'a self, _req: &'a ApprovalRequest) -> BoxFuture<'a, Answer> {
        Box::pin(std::future::pending())
    }
}

struct Fixture {
    _t: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    clock: Arc<AtomicI64>,
}

impl Fixture {
    fn new() -> Fixture {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let home = root.join("home");
        for d in [
            "home/.ssh",
            "home/proj/src",
            "home/proj/.git",
            "outside",
            "ro",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::write(root.join("home/.ssh/id_ed25519"), "secret").unwrap();
        fs::write(root.join("home/proj/a.txt"), "a").unwrap();
        fs::write(root.join("outside/b.txt"), "b").unwrap();
        Fixture {
            _t: t,
            root,
            home,
            clock: Arc::new(AtomicI64::new(1_000_000)),
        }
    }

    fn p(&self, rel: &str) -> String {
        self.root.join(rel).to_string_lossy().into_owned()
    }

    fn engine(&self, policy: Policy, profile: Profile, approver: Arc<dyn Approver>) -> Engine {
        let clock = self.clock.clone();
        Engine::new(
            policy,
            profile,
            EngineOptions {
                home: self.home.clone(),
                own_dirs: vec![self.home.join(".config/pithagoras-sync")],
                approver,
                audit: Arc::new(AuditLog::open(&self.root.join("state/audit.jsonl")).unwrap()),
                clock: Arc::new(move || clock.load(Ordering::SeqCst)),
                landlock: true,
            },
        )
    }

    fn folders(&self, grants: &[(&str, Access)]) -> Policy {
        Policy {
            mode: Mode::Folders,
            folders: grants
                .iter()
                .map(|(p, a)| FolderGrant {
                    path: self.root.join(p),
                    access: *a,
                    execute: true,
                })
                .collect(),
            ..Policy::default()
        }
    }

    fn audit(&self) -> Vec<AuditRecord> {
        fs::read_to_string(self.root.join("state/audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn scripted(answer: Answer) -> Arc<Scripted> {
    Arc::new(Scripted {
        answer,
        asked: AtomicUsize::new(0),
        last: Mutex::new(None),
    })
}

fn none() -> Arc<dyn Approver> {
    Arc::new(NoApprover { why: "headless" })
}

fn call(tool: &'static str) -> Call<'static> {
    Call {
        id: None,
        chat: "chat-1",
        portal_tainted: false,
        tool,
        pi_tool: None,
    }
}

async fn read(e: &Engine, path: &str) -> Result<Permit, Refusal> {
    e.authorize(&call("read"), Request::Read(path)).await
}

async fn write(e: &Engine, path: &str) -> Result<Permit, Refusal> {
    e.authorize(
        &call("write"),
        Request::Write {
            path,
            preview: Some("new content".into()),
        },
    )
    .await
}

async fn exec(e: &Engine, command: &str, cwd: &str) -> Result<Permit, Refusal> {
    e.authorize(&call("exec"), Request::Exec { command, cwd })
        .await
}

fn denied(r: Result<Permit, Refusal>) -> String {
    match r {
        Err(Refusal::Denied(m)) => m,
        other => panic!("expected a denial, got {other:?}"),
    }
}

#[tokio::test]
async fn folders_allows_only_inside_granted_folders() {
    let f = Fixture::new();
    let e = f.engine(
        f.folders(&[("home/proj", Access::Rw), ("ro", Access::Ro)]),
        Profile::Headless,
        none(),
    );
    let ok = read(&e, &f.p("home/proj/a.txt")).await.unwrap();
    assert_eq!(ok.root, Some(f.root.join("home/proj")));
    write(&e, &f.p("home/proj/src/new.rs")).await.unwrap();
    read(&e, &f.p("ro/x")).await.unwrap();
    denied(read(&e, &f.p("outside/b.txt")).await);
    denied(write(&e, &f.p("ro/x")).await);
    // A sibling whose name starts like the grant is not inside it.
    fs::create_dir(f.root.join("home/projx")).unwrap();
    denied(read(&e, &f.p("home/projx")).await);
    let log = f.audit();
    assert!(
        log.iter()
            .any(|r| r.decision == "denied" && r.tool == "write")
    );
    assert!(log.iter().any(|r| r.decision == "allowed"));
}

#[tokio::test]
async fn nested_read_only_folder_stays_read_only() {
    let f = Fixture::new();
    let e = f.engine(
        f.folders(&[("home/proj", Access::Rw), ("home/proj/src", Access::Ro)]),
        Profile::Headless,
        none(),
    );
    write(&e, &f.p("home/proj/a.txt")).await.unwrap();
    denied(write(&e, &f.p("home/proj/src/x.rs")).await);
}

#[tokio::test]
async fn path_escapes_are_denied() {
    let f = Fixture::new();
    let e = f.engine(
        f.folders(&[("home/proj", Access::Rw)]),
        Profile::Headless,
        none(),
    );
    // A symlink inside the folder pointing out.
    symlink(f.root.join("outside"), f.root.join("home/proj/out")).unwrap();
    denied(read(&e, &f.p("home/proj/out/b.txt")).await);
    denied(write(&e, &f.p("home/proj/out/new.txt")).await);
    // A symlinked file.
    symlink(
        f.root.join("home/.ssh/id_ed25519"),
        f.root.join("home/proj/key"),
    )
    .unwrap();
    denied(read(&e, &f.p("home/proj/key")).await);
    // `..` out of the folder, existing and missing.
    denied(read(&e, &f.p("home/proj/../../outside/b.txt")).await);
    denied(write(&e, &f.p("home/proj/../proj2/x")).await);
    assert!(matches!(
        write(&e, &f.p("home/proj/missing/../../../outside/x")).await,
        Err(Refusal::BadPath(_))
    ));
    // A dangling symlink could be created to point anywhere.
    symlink(
        f.root.join("outside/new"),
        f.root.join("home/proj/dangling"),
    )
    .unwrap();
    assert!(matches!(
        write(&e, &f.p("home/proj/dangling")).await,
        Err(Refusal::BadPath(_))
    ));
    // Relative and drive-letter paths are refused, not guessed.
    assert!(matches!(
        read(&e, "proj/a.txt").await,
        Err(Refusal::BadPath(_))
    ));
    assert!(matches!(
        read(&e, "C:\\Users\\x").await,
        Err(Refusal::BadPath(_))
    ));
}

#[tokio::test]
async fn case_and_unicode_variants_are_other_folders() {
    let f = Fixture::new();
    // NFC "café" granted; the NFD spelling is a different directory on Linux.
    let nfc = "caf\u{e9}";
    let nfd = "cafe\u{301}";
    fs::create_dir(f.root.join(nfc)).unwrap();
    fs::create_dir(f.root.join(nfd)).unwrap();
    fs::create_dir(f.root.join("Proj")).unwrap();
    let e = f.engine(
        f.folders(&[(nfc, Access::Rw), ("home/proj", Access::Rw)]),
        Profile::Headless,
        none(),
    );
    write(&e, &f.p(&format!("{nfc}/x"))).await.unwrap();
    denied(write(&e, &f.p(&format!("{nfd}/x"))).await);
    denied(write(&e, &f.p("home/PROJ/x")).await);
    denied(write(&e, &f.p("Proj/x")).await);
    // Look-alike dots are a name inside the folder, not a way out of it.
    let p = read(&e, &f.p("home/proj/\u{2025}/outside")).await.unwrap();
    assert!(p.path.starts_with(f.root.join("home/proj")));
}

#[tokio::test]
async fn a_protected_path_prompts_and_is_denied_headless() {
    let f = Fixture::new();
    let e = f.engine(
        f.folders(&[("home", Access::Rw)]),
        Profile::Headless,
        none(),
    );
    let m = denied(read(&e, &f.p("home/.ssh/id_ed25519")).await);
    assert!(m.contains("protected"), "{m}");
    denied(write(&e, &f.p("home/.bashrc")).await);
    // The client's own config is protected too.
    denied(write(&e, &f.p("home/.config/pithagoras-sync/config.toml")).await);
    // Inside the folder, writes to .git ask; reads do not.
    read(&e, &f.p("home/proj/.git/config")).await.unwrap();
    denied(write(&e, &f.p("home/proj/.git/hooks/pre-commit")).await);
    // Case does not get around it.
    denied(read(&e, &f.p("home/.SSH/id_ed25519")).await);
}

#[tokio::test]
async fn a_protected_path_prompts_on_a_desktop() {
    let f = Fixture::new();
    let yes = scripted(Answer::Once);
    let e = f.engine(
        f.folders(&[("home", Access::Rw)]),
        Profile::Desktop,
        yes.clone(),
    );
    read(&e, &f.p("home/.ssh/id_ed25519")).await.unwrap();
    assert_eq!(yes.asked.load(Ordering::SeqCst), 1);
    let req = yes.last.lock().unwrap().clone().unwrap();
    assert!(req.reasons.iter().any(|r| r.contains("protected")));
    assert!(!req.offer_chat);
    assert!(f.audit().iter().any(|r| r.decision == "approved"));

    let no = scripted(Answer::Deny);
    let e = f.engine(
        f.folders(&[("home", Access::Rw)]),
        Profile::Desktop,
        no.clone(),
    );
    denied(read(&e, &f.p("home/.ssh/id_ed25519")).await);
    assert_eq!(no.asked.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_approval_timeout_denies() {
    let f = Fixture::new();
    let mut policy = f.folders(&[("home", Access::Rw)]);
    policy.approvals.timeout_secs = 1;
    let queue = ApprovalQueue::new(Arc::new(|| i64::MAX));
    let e = f.engine(policy, Profile::Desktop, queue.clone());
    let mut events = queue.subscribe();
    let id = Id::Num(9);
    let c = Call {
        id: Some(&id),
        ..call("read")
    };
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        e.authorize(&c, Request::Read(&f.p("home/.ssh/id_ed25519"))),
    )
    .await
    .expect("the approval must time out on its own");
    let m = denied(r);
    assert!(m.contains("no answer"), "{m}");
    let ApprovalEvent::Requested(info) = events.recv().await.unwrap() else {
        panic!("expected the request first")
    };
    assert_eq!((info.call, info.chat.as_str()), (Some(id), "chat-1"));
    let ApprovalEvent::Resolved(r) = events.recv().await.unwrap() else {
        panic!("expected the resolution")
    };
    assert_eq!((r.answer, r.by.as_str()), (Choice::Deny, "timeout"));
    assert!(queue.list().is_empty());
}

#[tokio::test]
async fn the_owner_may_make_a_timeout_allow() {
    let f = Fixture::new();
    let mut policy = f.folders(&[("home", Access::Rw)]);
    policy.approvals.timeout_secs = 1;
    policy.approvals.on_timeout = sync_policy::config::TimeoutAnswer::Allow;
    let e = f.engine(policy, Profile::Headless, Arc::new(Never));
    read(&e, &f.p("home/.ssh/id_ed25519")).await.unwrap();
    assert!(f.audit().iter().any(|r| {
        r.decision == "approved"
            && r.reason
                .as_deref()
                .is_some_and(|m| m.contains("allows on timeout"))
    }));
}

#[tokio::test]
async fn time_and_chat_answers_last_as_long_as_the_device_says() {
    let f = Fixture::new();
    let mut policy = Policy::default();
    policy.approvals.remember_minutes = 10;
    policy.approvals.max_minutes = 30;
    let chat = scripted(Answer::ForChat);
    let e = f.engine(policy.clone(), Profile::Headless, chat.clone());
    read(&e, &f.p("outside/b.txt")).await.unwrap();
    f.clock.fetch_add(9 * 60_000, Ordering::SeqCst);
    read(&e, &f.p("outside/b.txt")).await.unwrap();
    assert_eq!(chat.asked.load(Ordering::SeqCst), 1, "still remembered");
    f.clock.fetch_add(2 * 60_000, Ordering::SeqCst);
    read(&e, &f.p("outside/b.txt")).await.unwrap();
    assert_eq!(
        chat.asked.load(Ordering::SeqCst),
        2,
        "remembered for 10 minutes"
    );

    // A time answer beyond the device's longest is cut to it.
    let timed = scripted(Answer::ForTime(600));
    let e = f.engine(policy, Profile::Headless, timed.clone());
    write(&e, &f.p("outside/c")).await.unwrap();
    f.clock.fetch_add(29 * 60_000, Ordering::SeqCst);
    write(&e, &f.p("outside/c")).await.unwrap();
    assert_eq!(timed.asked.load(Ordering::SeqCst), 1);
    f.clock.fetch_add(2 * 60_000, Ordering::SeqCst);
    write(&e, &f.p("outside/c")).await.unwrap();
    assert_eq!(timed.asked.load(Ordering::SeqCst), 2);
    // The shell is never remembered.
    exec(&e, "ls", &f.p("outside")).await.unwrap();
    exec(&e, "ls", &f.p("outside")).await.unwrap();
    assert_eq!(timed.asked.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn pause_answers_open_approvals_with_deny() {
    let f = Fixture::new();
    let queue = ApprovalQueue::new(Arc::new(|| 0));
    let e = f.engine(Policy::default(), Profile::Headless, queue.clone());
    let mut events = queue.subscribe();
    let target = f.p("outside/b.txt");
    let ask = read(&e, &target);
    let pauser = async {
        let _ = events.recv().await.unwrap();
        e.pause();
    };
    // Denied at once, not when the two-minute timeout runs out.
    let (r, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(ask, pauser)
    })
    .await
    .expect("pause answers the open approval");
    denied(r);
    assert!(queue.list().is_empty());
}

#[tokio::test]
async fn ask_mode_asks_and_remembers_only_file_scopes() {
    let f = Fixture::new();
    let yes = scripted(Answer::ForChat);
    let policy = Policy {
        mode: Mode::Ask,
        ..Policy::default()
    };
    let e = f.engine(policy, Profile::Desktop, yes.clone());
    read(&e, &f.p("outside/b.txt")).await.unwrap();
    read(&e, &f.p("outside/b.txt")).await.unwrap();
    assert_eq!(yes.asked.load(Ordering::SeqCst), 1, "reads remembered");
    write(&e, &f.p("outside/c.txt")).await.unwrap();
    assert_eq!(
        yes.asked.load(Ordering::SeqCst),
        2,
        "writes asked separately"
    );
    exec(&e, "ls", &f.p("outside")).await.unwrap();
    exec(&e, "ls", &f.p("outside")).await.unwrap();
    assert_eq!(yes.asked.load(Ordering::SeqCst), 4, "the shell always asks");
    // Another chat starts over.
    let other = Call {
        chat: "chat-2",
        ..call("read")
    };
    e.authorize(&other, Request::Read(&f.p("outside/b.txt")))
        .await
        .unwrap();
    assert_eq!(yes.asked.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn a_tainted_write_prompts_in_default_full() {
    let f = Fixture::new();
    let mut policy = Policy::default();
    policy.set_mode(Mode::Full, f.clock.load(Ordering::SeqCst));
    let e = f.engine(policy.clone(), Profile::Headless, none());
    write(&e, &f.p("outside/x")).await.unwrap();
    exec(&e, "true", &f.p("outside")).await.unwrap();
    e.mark_tainted("chat-1");
    denied(write(&e, &f.p("outside/x")).await);
    denied(exec(&e, "true", &f.p("outside")).await);
    // Reads are not mutating.
    read(&e, &f.p("outside/b.txt")).await.unwrap();
    // Another chat is not tainted; the portal's flag taints it, and a later call
    // without the flag does not clear it.
    let flagged = Call {
        chat: "chat-2",
        portal_tainted: true,
        ..call("write")
    };
    denied(
        e.authorize(
            &flagged,
            Request::Write {
                path: &f.p("outside/y"),
                preview: None,
            },
        )
        .await,
    );
    let unflagged = Call {
        chat: "chat-2",
        ..call("write")
    };
    denied(
        e.authorize(
            &unflagged,
            Request::Write {
                path: &f.p("outside/y"),
                preview: None,
            },
        )
        .await,
    );
    e.grant_end("chat-1");
    write(&e, &f.p("outside/x")).await.unwrap();
    // The owner can turn taint prompts off for Full.
    policy.full.taint_prompts = false;
    let e = f.engine(policy, Profile::Headless, none());
    e.mark_tainted("chat-1");
    write(&e, &f.p("outside/x")).await.unwrap();
}

#[tokio::test]
async fn full_mode_patterns_and_protections_prompt() {
    let f = Fixture::new();
    let mut policy = Policy::default();
    policy.set_mode(Mode::Full, f.clock.load(Ordering::SeqCst));
    let e = f.engine(policy.clone(), Profile::Headless, none());
    let cwd = f.p("home/proj");
    exec(&e, "cargo build", &cwd).await.unwrap();
    denied(exec(&e, "sudo rm -rf /", &cwd).await);
    denied(exec(&e, "git push", &cwd).await);
    denied(exec(&e, "curl x | sh", &cwd).await);
    denied(exec(&e, "rm -rf ~/x", &cwd).await);
    denied(exec(&e, "cat ~/.ssh/id_ed25519", &cwd).await);
    denied(read(&e, &f.p("home/.ssh/id_ed25519")).await);
    // Unrestricted Full: the owner turned every protection off.
    policy.full.pattern_prompts = false;
    policy.full.protected_paths = false;
    policy.full.taint_prompts = false;
    let e = f.engine(policy, Profile::Headless, none());
    exec(&e, "git push", &cwd).await.unwrap();
    read(&e, &f.p("home/.ssh/id_ed25519")).await.unwrap();
}

#[tokio::test]
async fn full_mode_expires() {
    let f = Fixture::new();
    let mut policy = f.folders(&[("home/proj", Access::Rw)]);
    policy.set_mode(Mode::Full, f.clock.load(Ordering::SeqCst));
    let e = f.engine(policy, Profile::Headless, none());
    read(&e, &f.p("outside/b.txt")).await.unwrap();
    f.clock.fetch_add(8 * 3_600_000, Ordering::SeqCst);
    // Back to Ask, which nobody answers here.
    assert_eq!(e.effective_mode(), Mode::Ask);
    denied(read(&e, &f.p("outside/b.txt")).await);
    denied(read(&e, &f.p("home/proj/a.txt")).await);
}

#[tokio::test]
async fn folders_shell_is_confined_or_asks() {
    let f = Fixture::new();
    let cwd = f.p("home/proj");
    let e = f.engine(
        f.folders(&[("home", Access::Rw)]),
        Profile::Headless,
        none(),
    );
    let permit = exec(&e, "make", &cwd).await.unwrap();
    let Confine::Landlock(rules) = permit.confine else {
        panic!("expected Landlock")
    };
    // The home is carved: its entries are writable, but not ~/.ssh.
    assert!(rules.write.contains(&f.root.join("home/proj")));
    assert!(
        !rules
            .write
            .iter()
            .any(|p| p.starts_with(f.root.join("home/.ssh")))
    );
    assert!(!rules.write.contains(&f.root.join("home")));
    assert!(rules.read.contains(&PathBuf::from("/usr")));
    assert!(rules.exec.contains(&PathBuf::from("/usr")));
    assert!(rules.exec.contains(&f.root.join("home/proj")));
    assert!(
        !rules
            .exec
            .iter()
            .any(|p| p.starts_with(f.root.join("home/.ssh")))
    );
    denied(exec(&e, "ls", &f.p("outside")).await);

    let prompt = Policy {
        folders_shell: FoldersShell::Prompt,
        ..f.folders(&[("home", Access::Rw)])
    };
    let e = f.engine(prompt, Profile::Headless, none());
    denied(exec(&e, "ls", &cwd).await);

    let unconfined = Policy {
        folders_shell: FoldersShell::Unconfined,
        ..f.folders(&[("home", Access::Rw)])
    };
    let e = f.engine(unconfined, Profile::Headless, none());
    assert_eq!(exec(&e, "ls", &cwd).await.unwrap().confine, Confine::None);
    denied(exec(&e, "sudo ls", &cwd).await);
}

#[tokio::test]
async fn without_landlock_the_folders_shell_asks() {
    let f = Fixture::new();
    let clock = f.clock.clone();
    let e = Engine::new(
        f.folders(&[("home/proj", Access::Rw)]),
        Profile::Headless,
        EngineOptions {
            home: f.home.clone(),
            own_dirs: vec![],
            approver: none(),
            audit: Arc::new(AuditLog::open(&f.root.join("state/audit.jsonl")).unwrap()),
            clock: Arc::new(move || clock.load(Ordering::SeqCst)),
            landlock: false,
        },
    );
    let m = denied(exec(&e, "ls", &f.p("home/proj")).await);
    assert!(m.contains("Landlock"), "{m}");
}

#[tokio::test]
async fn pause_denies_everything_until_unlocked() {
    let f = Fixture::new();
    let mut policy = Policy::default();
    policy.set_mode(Mode::Full, f.clock.load(Ordering::SeqCst));
    let e = f.engine(policy, Profile::Headless, none());
    e.pause();
    denied(read(&e, &f.p("outside/b.txt")).await);
    denied(exec(&e, "true", &f.p("outside")).await);
    e.unlock();
    read(&e, &f.p("outside/b.txt")).await.unwrap();
    let log = f.audit();
    assert!(log.iter().any(|r| r.decision == "paused"));
}

#[tokio::test]
async fn a_folder_that_does_not_exist_grants_nothing() {
    let f = Fixture::new();
    let e = f.engine(
        f.folders(&[("not-yet", Access::Rw)]),
        Profile::Headless,
        none(),
    );
    denied(write(&e, &f.p("not-yet/x")).await);
}

#[tokio::test]
async fn a_search_walk_skips_protected_paths() {
    let f = Fixture::new();
    let e = f.engine(
        f.folders(&[("home", Access::Rw)]),
        Profile::Headless,
        none(),
    );
    // grep over the whole home folder may start, but its walk must not read keys.
    read(&e, &f.p("home")).await.unwrap();
    let ok = e.walk_filter();
    assert!(ok(&f.root.join("home/proj/a.txt")));
    assert!(!ok(&f.root.join("home/.ssh/id_ed25519")));
    assert!(!ok(&f.root.join("home/.SSH/id_ed25519")));
    // Outside the granted folders nothing is read in Folders mode.
    assert!(!ok(&f.root.join("outside/b.txt")));
    // Full mode with protections off reads everything.
    let mut policy = Policy::default();
    policy.set_mode(Mode::Full, f.clock.load(Ordering::SeqCst));
    policy.full.protected_paths = false;
    e.reload(policy, Profile::Headless);
    assert!(e.walk_filter()(&f.root.join("home/.ssh/id_ed25519")));
}

fn with(mut policy: Policy, edit: impl FnOnce(&mut Policy)) -> Policy {
    edit(&mut policy);
    policy
}

fn full(f: &Fixture) -> Policy {
    let mut policy = Policy::default();
    policy.set_mode(Mode::Full, f.clock.load(Ordering::SeqCst));
    policy
}

#[tokio::test]
async fn a_folder_without_the_execute_right_runs_no_commands() {
    let f = Fixture::new();
    let mut policy = f.folders(&[("home/proj", Access::Rw), ("ro", Access::Ro)]);
    policy.folders[1].execute = false;
    let e = f.engine(policy, Profile::Headless, none());
    exec(&e, "ls", &f.p("home/proj")).await.unwrap();
    let m = denied(exec(&e, "ls", &f.p("ro")).await);
    assert!(m.contains("execute"), "{m}");
    let Confine::Landlock(rules) = exec(&e, "ls", &f.p("home/proj")).await.unwrap().confine else {
        panic!("expected Landlock")
    };
    assert!(rules.read.contains(&f.root.join("ro")));
    assert!(!rules.exec.contains(&f.root.join("ro")));
}

async fn write_as(e: &Engine, tool: PiTool, path: &str) -> Result<Permit, Refusal> {
    let c = Call {
        pi_tool: Some(tool),
        ..call("write")
    };
    e.authorize(
        &c,
        Request::Write {
            path,
            preview: None,
        },
    )
    .await
}

#[tokio::test]
async fn switched_off_tools_are_refused() {
    let f = Fixture::new();
    let policy = with(full(&f), |p| {
        p.tools.write = false;
        p.tools.bash = false;
    });
    let e = f.engine(policy, Profile::Headless, none());
    denied(exec(&e, "true", &f.p("outside")).await);
    // An unlabelled write still serves the edit tool, which is on.
    write(&e, &f.p("outside/x")).await.unwrap();
    let target = f.p("outside/x");
    denied(write_as(&e, PiTool::Write, &target).await);
    write_as(&e, PiTool::Edit, &target).await.unwrap();
    // A label that does not fit the method is refused, not trusted.
    denied(write_as(&e, PiTool::Read, &target).await);
    // With write and edit off nothing writes, however it is labelled.
    let policy = with(full(&f), |p| {
        p.tools.write = false;
        p.tools.edit = false;
    });
    let e = f.engine(policy, Profile::Headless, none());
    denied(write(&e, &f.p("outside/x")).await);
    read(&e, &f.p("outside/b.txt")).await.unwrap();
}

#[tokio::test]
async fn deny_rules_hold_in_every_mode() {
    let f = Fixture::new();
    let deny = |p: &mut Policy| {
        p.deny = vec![
            DenyRule {
                path: f.p("outside"),
                rights: "r".parse().unwrap(),
            },
            DenyRule {
                path: "~/proj/**/*.secret".into(),
                rights: Rights::ALL,
            },
            DenyRule {
                path: "~/proj/src".into(),
                rights: "wx".parse().unwrap(),
            },
            DenyRule {
                path: "~/proj/docs".into(),
                rights: "r".parse().unwrap(),
            },
        ];
    };
    fs::create_dir(f.root.join("home/proj/docs")).unwrap();
    // Unrestricted Full.
    let policy = with(full(&f), |p| {
        p.full.pattern_prompts = false;
        p.full.protected_paths = false;
        deny(p);
    });
    let e = f.engine(policy, Profile::Headless, none());
    denied(read(&e, &f.p("outside/b.txt")).await);
    write(&e, &f.p("outside/new")).await.unwrap();
    fs::write(f.root.join("home/proj/src/k.secret"), "k").unwrap();
    denied(read(&e, &f.p("home/proj/src/k.secret")).await);
    denied(read(&e, &f.p("home/proj/K.SECRET")).await);
    read(&e, &f.p("home/proj/src")).await.unwrap();
    denied(write(&e, &f.p("home/proj/src/x.rs")).await);
    denied(exec(&e, "ls", &f.p("home/proj/src")).await);
    exec(&e, "ls", &f.p("home/proj")).await.unwrap();
    // A search walk skips what is denied.
    let ok = e.walk_filter();
    assert!(!ok(&f.root.join("outside/b.txt")));
    assert!(!ok(&f.root.join("home/proj/src/k.secret")));
    assert!(ok(&f.root.join("home/proj/a.txt")));

    // Folders mode: Landlock leaves the denied paths out.
    let policy = with(
        f.folders(&[("home/proj", Access::Rw), ("outside", Access::Ro)]),
        deny,
    );
    let e = f.engine(policy, Profile::Headless, none());
    let Confine::Landlock(rules) = exec(&e, "make", &f.p("home/proj")).await.unwrap().confine
    else {
        panic!("expected Landlock")
    };
    assert!(!rules.read.contains(&f.root.join("outside")));
    assert!(
        !rules
            .write
            .iter()
            .any(|p| p.starts_with(f.root.join("home/proj/src")))
    );
    assert!(rules.write.contains(&f.root.join("home/proj/a.txt")));
    // Read-denied inside a writable folder: no write rule either, which would read.
    assert!(
        !rules
            .write
            .iter()
            .any(|p| p.starts_with(f.root.join("home/proj/docs")))
    );
    assert!(
        !rules
            .read
            .iter()
            .any(|p| p.starts_with(f.root.join("home/proj/docs")))
    );
    // Write-denied only: still readable, not runnable.
    assert!(rules.read.contains(&f.root.join("home/proj/src")));
    assert!(
        !rules
            .exec
            .iter()
            .any(|p| p.starts_with(f.root.join("home/proj/src")))
    );
}

#[tokio::test]
async fn glob_grants_open_files_outside_the_folders() {
    let f = Fixture::new();
    let policy = with(f.folders(&[("home/proj", Access::Rw)]), |p| {
        p.allow_globs = vec![GlobGrant {
            glob: f.p("outside/*.txt"),
            access: Access::Ro,
        }];
    });
    let e = f.engine(policy, Profile::Headless, none());
    let permit = read(&e, &f.p("outside/b.txt")).await.unwrap();
    assert_eq!(permit.root, Some(f.root.join("outside")));
    denied(write(&e, &f.p("outside/b.txt")).await);
    denied(read(&e, &f.p("outside/c.md")).await);
    // Commands do not run there: a glob is no folder grant.
    denied(exec(&e, "ls", &f.p("outside")).await);
    assert!(e.walk_filter()(&f.root.join("outside/b.txt")));
}

fn rule(prefix: &str) -> CommandRule {
    CommandRule {
        prefix: Some(prefix.into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn command_lists_deny_allow_and_ask() {
    let f = Fixture::new();
    let cwd = f.p("home/proj");
    let open_full = |f: &Fixture| {
        with(full(f), |p| {
            p.full.pattern_prompts = false;
            p.full.protected_paths = false;
            p.full.taint_prompts = false;
        })
    };
    // Deny and always-ask hold even in unrestricted Full.
    let policy = with(open_full(&f), |p| {
        p.commands.deny = vec![rule("shutdown")];
        p.commands.always_ask = vec![rule("git push")];
    });
    let yes = scripted(Answer::Once);
    let e = f.engine(policy, Profile::Headless, yes.clone());
    let m = denied(exec(&e, "true && shutdown -h now", &cwd).await);
    assert!(m.contains("deny rule"), "{m}");
    exec(&e, "git status", &cwd).await.unwrap();
    assert_eq!(yes.asked.load(Ordering::SeqCst), 0);
    exec(&e, "git push origin", &cwd).await.unwrap();
    assert_eq!(yes.asked.load(Ordering::SeqCst), 1);

    // An allow list refuses everything else, and anything compound.
    let policy = with(open_full(&f), |p| {
        p.commands.allow = vec![rule("cargo ")];
    });
    let e = f.engine(policy, Profile::Headless, none());
    exec(&e, "cargo build", &cwd).await.unwrap();
    denied(exec(&e, "ls", &cwd).await);
    denied(exec(&e, "cargo build; ls", &cwd).await);
}

#[tokio::test]
async fn never_ask_skips_the_mode_but_not_taint() {
    let f = Fixture::new();
    let cwd = f.p("home/proj");
    let policy = with(Policy::default(), |p| {
        p.commands.never_ask = vec![rule("cargo test")];
    });
    let e = f.engine(policy, Profile::Headless, none());
    // Ask mode, nobody to answer: only the never-ask command runs.
    exec(&e, "cargo test -q", &cwd).await.unwrap();
    denied(exec(&e, "cargo build", &cwd).await);
    denied(exec(&e, "cargo test; rm -rf ~", &cwd).await);
    e.mark_tainted("chat-1");
    denied(exec(&e, "cargo test -q", &cwd).await);
}

#[tokio::test]
async fn outside_the_hours_everything_is_refused() {
    let f = Fixture::new();
    // The fixture's clock stands at 00:16:40 UTC on 1 January 1970, a Thursday.
    let hours = |from: &str, to: &str, days: &[&str]| Hours {
        days: days.iter().map(|d| d.to_string()).collect(),
        from: from.into(),
        to: to.into(),
        utc_offset_minutes: Some(0),
    };
    let policy = with(full(&f), |p| p.hours = Some(hours("08:00", "18:00", &[])));
    let e = f.engine(policy, Profile::Headless, none());
    let m = denied(read(&e, &f.p("outside/b.txt")).await);
    assert!(m.contains("hours"), "{m}");
    let policy = with(full(&f), |p| {
        p.hours = Some(hours("22:00", "06:00", &["wed"]))
    });
    let e = f.engine(policy, Profile::Headless, none());
    read(&e, &f.p("outside/b.txt")).await.unwrap();
    let policy = with(full(&f), |p| {
        p.hours = Some(hours("22:00", "06:00", &["thu"]))
    });
    let e = f.engine(policy, Profile::Headless, none());
    denied(read(&e, &f.p("outside/b.txt")).await);
}

#[tokio::test]
async fn a_broken_rule_refuses_everything() {
    let f = Fixture::new();
    // validate() keeps such a file from loading; the engine fails closed anyway.
    let policy = with(full(&f), |p| {
        p.commands.deny = vec![CommandRule {
            regex: Some("(".into()),
            ..Default::default()
        }];
    });
    let e = f.engine(policy, Profile::Headless, none());
    let m = denied(read(&e, &f.p("outside/b.txt")).await);
    assert!(m.contains("broken rule"), "{m}");
    assert!(!e.walk_filter()(&f.root.join("outside/b.txt")));
}

#[tokio::test]
async fn the_tool_config_list_is_the_owners() {
    let f = Fixture::new();
    let policy = with(f.folders(&[("home/proj", Access::Rw)]), |p| {
        p.protected.tool_config.retain(|t| t != ".git");
        p.protected.tool_config.push("Makefile".into());
    });
    let e = f.engine(policy, Profile::Headless, none());
    write(&e, &f.p("home/proj/.git/config")).await.unwrap();
    denied(write(&e, &f.p("home/proj/Makefile")).await);
}
