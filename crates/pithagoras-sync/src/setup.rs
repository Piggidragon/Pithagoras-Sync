//! `sudo pithagoras-sync setup --create-user`: a dedicated user for a server
//! (spec 10.1). Shows a preview and asks first; never touches an existing user;
//! `setup --remove` undoes it, and only for a user it created.

use std::path::Path;

use crate::actions::{Action, Runner, argv};
use crate::install::{UNIT_NAME, system_plan};

pub const DEFAULT_USER: &str = "pithagoras-sync";
/// The comment (GECOS) field that marks a user as created by `setup`.
pub const MARKER: &str = "Pithagoras Sync";

pub fn valid_user_name(n: &str) -> bool {
    (1..=32).contains(&n.len())
        && n.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// The comment field of `name`, or `None` when the user does not exist.
fn gecos(runner: &dyn Runner, name: &str) -> Option<String> {
    let line = runner.run(&argv(&["getent", "passwd", name])).ok()?;
    let line = line.lines().next()?;
    Some(line.split(':').nth(4).unwrap_or("").to_string())
}

/// The steps that create the user and its unit; refused when the user exists.
pub fn create_plan(
    runner: &dyn Runner,
    root: &Path,
    name: &str,
    exe: &Path,
) -> Result<Vec<Action>, String> {
    if !valid_user_name(name) {
        return Err(format!("{name:?} is not a valid user name"));
    }
    if gecos(runner, name).is_some() {
        return Err(format!(
            "user {name} already exists; setup never changes existing users (use install --system --user {name} for it)"
        ));
    }
    // The bash tool needs a normal shell.
    let shell = if crate::actions::rooted(root, Path::new("/bin/bash")).exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    };
    let mut v = vec![
        Action::Run {
            argv: argv(&[
                "useradd",
                "--create-home",
                "--user-group",
                "--shell",
                shell,
                "--comment",
                MARKER,
                name,
            ]),
        },
        // No password: nobody logs in as this user with one.
        Action::Run {
            argv: argv(&["usermod", "--lock", name]),
        },
    ];
    let mut unit = system_plan(exe, Some(name));
    // Enabled, not started: it has nothing to connect to until it is paired.
    if let Some(Action::Run { argv: a }) = unit.last_mut() {
        *a = argv(&["systemctl", "enable", UNIT_NAME]);
    }
    v.extend(unit);
    Ok(v)
}

/// Whether `prog` is a file in one of the `PATH` folders.
pub fn on_path(prog: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(prog).is_file()))
}

/// What to do after `create_plan` ran. `setfacl`: whether that program is
/// installed (Debian and Ubuntu leave it out until the `acl` package is).
pub fn next_steps(name: &str, setfacl: bool) -> String {
    let acl = if setfacl {
        String::new()
    } else {
        format!(
            "     setfacl is not installed: sudo apt install acl (Debian, Ubuntu; elsewhere the acl
     package), or give the project to the user: sudo chown -R {name}: /path/to/project
"
        )
    };
    format!(
        "Next steps:
  1. Grant folders (ACLs; the user needs x on every parent folder too):
{acl}       sudo setfacl -R -m u:{name}:rwX /path/to/project
       sudo setfacl -R -d -m u:{name}:rwX /path/to/project
       sudo -H -u {name} pithagoras-sync folder add /path/to/project --rw --exec
  2. Pair:  sudo -H -u {name} pithagoras-sync pair '<uri from the portal>'
  3. Mode:  Ask (every call waits for your approval) until you switch:
       sudo -H -u {name} pithagoras-sync mode folders
  4. Start: sudo systemctl start {UNIT_NAME}
"
    )
}

/// The steps that remove the unit and the user (with its home); refused unless
/// `setup --create-user` made that user.
pub fn remove_plan(runner: &dyn Runner, name: &str) -> Result<Vec<Action>, String> {
    if !valid_user_name(name) {
        return Err(format!("{name:?} is not a valid user name"));
    }
    match gecos(runner, name) {
        None => return Err(format!("there is no user {name}")),
        Some(g) if g != MARKER => {
            return Err(format!(
                "user {name} was not created by pithagoras-sync setup; it is left alone"
            ));
        }
        Some(_) => {}
    }
    Ok(vec![
        Action::Try {
            argv: argv(&["systemctl", "disable", "--now", UNIT_NAME]),
            hint: "the unit was not enabled".into(),
        },
        Action::Remove {
            path: Path::new("/etc/systemd/system").join(UNIT_NAME),
        },
        Action::Run {
            argv: argv(&["systemctl", "daemon-reload"]),
        },
        Action::Run {
            argv: argv(&["userdel", "--remove", name]),
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{Fake, apply};

    fn exists(name: &str, gecos: &str) -> Fake {
        Fake {
            answers: vec![(
                "getent passwd".into(),
                Ok(format!("{name}:x:990:990:{gecos}:/home/{name}:/bin/bash\n")),
            )],
            ..Fake::default()
        }
    }

    fn missing() -> Fake {
        Fake {
            answers: vec![("getent passwd".into(), Err("exit 2".into()))],
            ..Fake::default()
        }
    }

    #[test]
    fn creates_a_locked_user_and_an_enabled_unit() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("bin")).unwrap();
        std::fs::write(root.path().join("bin/bash"), "").unwrap();
        let exe = root.path().join("exe");
        std::fs::write(&exe, b"x").unwrap();
        let fake = missing();
        let plan = create_plan(&fake, root.path(), DEFAULT_USER, &exe).unwrap();
        apply(&plan, root.path(), &fake).unwrap();
        let ran = fake.ran.lock().unwrap().clone();
        assert_eq!(
            ran[1],
            argv(&[
                "useradd",
                "--create-home",
                "--user-group",
                "--shell",
                "/bin/bash",
                "--comment",
                MARKER,
                DEFAULT_USER
            ])
        );
        assert_eq!(ran[2], argv(&["usermod", "--lock", DEFAULT_USER]));
        assert_eq!(
            ran.last().unwrap(),
            &argv(&["systemctl", "enable", UNIT_NAME])
        );
        let unit = std::fs::read_to_string(root.path().join("etc/systemd/system").join(UNIT_NAME))
            .unwrap();
        assert!(unit.contains("User=pithagoras-sync"));
    }

    #[test]
    fn next_steps_say_when_setfacl_is_missing() {
        let with = next_steps("ps", true);
        assert!(with.contains("sudo setfacl -R -m u:ps:rwX"), "{with}");
        assert!(!with.contains("apt install acl"), "{with}");
        let without = next_steps("ps", false);
        assert!(without.contains("sudo apt install acl"), "{without}");
        assert!(
            without.contains("sudo chown -R ps: /path/to/project"),
            "{without}"
        );
        assert!(on_path("sh"));
        assert!(!on_path("no-such-program-pithagoras-sync-test"));
    }

    #[test]
    fn never_touches_existing_users() {
        let root = tempfile::tempdir().unwrap();
        let exe = root.path().join("exe");
        let e = create_plan(&exists("alice", "Alice"), root.path(), "alice", &exe).unwrap_err();
        assert!(e.contains("already exists"));
        // Removing a user setup did not create is refused.
        let e = remove_plan(&exists("alice", "Alice"), "alice").unwrap_err();
        assert!(e.contains("left alone"));
        assert!(remove_plan(&missing(), "nobody-here").is_err());
        assert!(create_plan(&missing(), root.path(), "Bad Name", &exe).is_err());
        assert!(create_plan(&missing(), root.path(), "-rf", &exe).is_err());
    }

    #[test]
    fn removes_what_it_created() {
        let fake = exists(DEFAULT_USER, MARKER);
        let plan = remove_plan(&fake, DEFAULT_USER).unwrap();
        let root = tempfile::tempdir().unwrap();
        let unit = root.path().join("etc/systemd/system").join(UNIT_NAME);
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(&unit, "x").unwrap();
        apply(&plan, root.path(), &fake).unwrap();
        assert!(!unit.exists());
        let ran = fake.ran.lock().unwrap().clone();
        assert_eq!(
            ran.last().unwrap(),
            &argv(&["userdel", "--remove", DEFAULT_USER])
        );
    }
}
