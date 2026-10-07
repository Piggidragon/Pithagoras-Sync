//! The elevation secret on the device: typed in a terminal (`sudo
//! set`), handed to the running client over the control channel, and kept in the
//! client's memory only (the default; panic and restarts forget it), in a file
//! only this user can read, or in the OS keyring (`secret_storage = keyring`,
//! Linux). It never goes to the portal, into a command's argv or environment, the
//! audit log or the client's own log.
//!
//! Memory is the default because it is the only place other processes of the user
//! cannot read: the client makes itself undumpable. A keyring unlocked for this
//! user, like a 0600 file, gives the secret to any unconfined process of the user,
//! and a server has none; it is there for owners who want the password to survive
//! a restart without a file. A keyring the owner chose never falls back to the
//! file or to memory: no keyring, a locked one or a cancelled prompt is an error.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use sync_policy::Dirs;
use sync_policy::config::SecretStorage;
use sync_policy::keyring::SecretStore;
use sync_policy::secret::{Secret, SecretSlot};

/// The only secret there is.
pub const ELEVATION: &str = "elevation";

/// The longest secret taken (the shim takes as much).
pub const MAX_LEN: usize = 1024;

pub fn file(dirs: &Dirs) -> PathBuf {
    dirs.config.join("elevation.secret")
}

/// Checks a typed secret: one line, not empty, not too long.
pub fn check(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("the password is empty".into());
    }
    if s.len() > MAX_LEN || s.contains(['\n', '\r', '\0']) {
        return Err(format!(
            "the password must be one line of at most {MAX_LEN} bytes"
        ));
    }
    Ok(())
}

pub fn save(path: &Path, s: &Secret) -> Result<(), String> {
    sync_policy::config::write_private(path, s.expose().as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The stored secret, if there is one. A file others could read is refused, not
/// used.
pub fn load(path: &Path) -> Result<Option<Secret>, String> {
    let mut bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path).map_err(|e| e.to_string())?;
        // SAFETY: geteuid cannot fail.
        let me = unsafe { libc::geteuid() };
        if m.mode() & 0o077 != 0 || m.uid() != me {
            bytes.fill(0);
            return Err(format!(
                "{} can be read by others; not using it (chmod 600, or set the password again)",
                path.display()
            ));
        }
    }
    let s = String::from_utf8(std::mem::take(&mut bytes)).map_err(|e| {
        let mut b = e.into_bytes();
        b.fill(0);
        format!("{} is not text", path.display())
    })?;
    let s = Secret::new(s);
    check(s.expose())?;
    Ok(Some(s))
}

pub fn remove(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{}: {e}", path.display()))
        }
        _ => Ok(()),
    }
}

/// The stored password, wherever `storage` keeps it; memory keeps none on disk.
pub async fn load_stored(
    dirs: &Dirs,
    storage: SecretStorage,
    keyring: &dyn SecretStore,
) -> Result<Option<Secret>, String> {
    match storage {
        SecretStorage::Memory => Ok(None),
        SecretStorage::File => load(&file(dirs)),
        SecretStorage::Keyring => {
            let s = keyring
                .get(ELEVATION)
                .await
                .map_err(|e| format!("not loaded from the keyring: {e}"))?;
            if let Some(s) = &s {
                check(s.expose())?;
            }
            Ok(s)
        }
    }
}

/// Keeps the password where `storage` says (nothing to do for memory).
pub async fn store(
    dirs: &Dirs,
    storage: SecretStorage,
    keyring: &dyn SecretStore,
    value: &Secret,
) -> Result<(), String> {
    match storage {
        SecretStorage::Memory => Ok(()),
        SecretStorage::File => save(&file(dirs), value),
        SecretStorage::Keyring => keyring
            .set(ELEVATION, value)
            .await
            .map_err(|e| format!("cannot keep the password in the keyring: {e}")),
    }
}

/// Forgets the stored password: the file always (an old one may be left from
/// another storage), the keyring entry where the keyring keeps it or one is
/// left from when it did. Another storage asks the keyring only whether there
/// is an entry, which needs no unlock: without one it never asks for a prompt.
pub async fn forget(
    dirs: &Dirs,
    storage: SecretStorage,
    keyring: &dyn SecretStore,
) -> Result<(), String> {
    remove(&file(dirs))?;
    if storage == SecretStorage::Keyring || keyring.has(ELEVATION).await == Ok(true) {
        keyring
            .delete(ELEVATION)
            .await
            .map_err(|e| format!("cannot remove the password from the keyring: {e}"))?;
    }
    Ok(())
}

/// What sudo says to a password (`check_with_sudo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SudoCheck {
    Accepted,
    /// sudo asks this user no password: any text would pass, so a password
    /// proves nothing and there is none to store.
    NoPasswordNeeded,
    /// Refused, with the last line sudo wrote (not escaped).
    Refused(String),
}

/// How long a check may take (PAM may wait for a fingerprint reader first).
pub const SUDO_CHECK_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Checks `pw` with the sudo the client runs, as the windows' proof that the
/// owner types it (a command of the agent does not know it) and against typos.
/// First `sudo -k -n -v`: if that passes, sudo asks no password here. Then
/// `sudo -k -S -p "" -v` with the password on stdin, never in argv or the
/// environment. `-k` neither uses nor leaves cached credentials, so the check
/// unlocks nothing for later. sudo gets an empty environment but `PATH` and
/// `LC_ALL=C`.
#[cfg(unix)]
pub async fn check_with_sudo(sudo: &Path, pw: &Secret) -> Result<SudoCheck, String> {
    let (ok, _) = sudo_run(sudo, &["-k", "-n", "-v"], None).await?;
    if ok {
        return Ok(SudoCheck::NoPasswordNeeded);
    }
    let (ok, said) = sudo_run(sudo, &["-k", "-S", "-p", "", "-v"], Some(pw)).await?;
    Ok(if ok {
        SudoCheck::Accepted
    } else {
        SudoCheck::Refused(said)
    })
}

/// Runs sudo once: whether it succeeded, and its last line on stderr.
#[cfg(unix)]
async fn sudo_run(
    sudo: &Path,
    args: &[&str],
    input: Option<&Secret>,
) -> Result<(bool, String), String> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(sudo)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("{}: {e}", sudo.display()))?;
    if let (Some(pw), Some(mut stdin)) = (input, child.stdin.take()) {
        // Written as it is, then the line end: no copy is made. A sudo that
        // reads nothing (or exits) is no error here; its exit code tells.
        let _ = stdin.write_all(pw.expose().as_bytes()).await;
        let _ = stdin.write_all(b"\n").await;
    }
    let out = tokio::time::timeout(SUDO_CHECK_WAIT, child.wait_with_output())
        .await
        .map_err(|_| format!("{} did not answer in time", sudo.display()))?
        .map_err(|e| format!("{}: {e}", sudo.display()))?;
    Ok((out.status.success(), last_line(&out.stderr, input)))
}

/// The last line a program wrote, as plain text for a message (a window shows
/// it, and puts it in its dialog program's argv): nothing when it holds the
/// password, since a program may echo what it was given.
#[cfg(unix)]
pub fn last_line(out: &[u8], pw: Option<&Secret>) -> String {
    let line = String::from_utf8_lossy(out)
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>();
    match pw.map(Secret::expose) {
        Some(pw) if !pw.is_empty() && line.contains(pw) => String::new(),
        _ => line,
    }
}

/// Reads a line from the terminal without echoing it. Never from a command line or
/// the environment.
#[cfg(unix)]
pub fn read_from_tty(prompt: &str) -> Result<Secret, String> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("no terminal to type the password in ({e})"))?;
    let fd = tty.as_raw_fd();
    // SAFETY: termios is plain data; tcgetattr fills it.
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd is the open terminal.
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        return Err("cannot switch off the terminal's echo".into());
    }
    let mut quiet = old;
    quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
    quiet.c_lflag |= libc::ICANON;
    // SAFETY: as above.
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
        return Err("cannot switch off the terminal's echo".into());
    }
    let _ = tty.write_all(prompt.as_bytes());
    let mut line = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    let read = loop {
        match tty.read(&mut byte) {
            Ok(0) => break Ok(()),
            Ok(_) if byte[0] == b'\n' => break Ok(()),
            Ok(_) if line.len() > MAX_LEN => {}
            Ok(_) => line.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => break Err(e.to_string()),
        }
    };
    // SAFETY: restores what tcgetattr returned.
    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &old) };
    let _ = tty.write_all(b"\n");
    byte.fill(0);
    if let Err(e) = read {
        line.fill(0);
        return Err(e);
    }
    secret_from(line)
}

#[cfg(windows)]
pub fn read_from_tty(_prompt: &str) -> Result<Secret, String> {
    Err("elevation is Linux only (sudo); Windows has none".into())
}

/// One line from stdin (a script piping it in); never from a command line.
pub fn read_from_stdin() -> Result<Secret, String> {
    use std::io::Read;
    let mut line = Vec::with_capacity(128);
    std::io::stdin()
        .lock()
        .take(MAX_LEN as u64 + 2)
        .read_to_end(&mut line)
        .map_err(|e| e.to_string())?;
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    secret_from(line)
}

fn secret_from(mut line: Vec<u8>) -> Result<Secret, String> {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    match String::from_utf8(line) {
        Ok(s) => {
            let s = Secret::new(s);
            check(s.expose())?;
            Ok(s)
        }
        Err(e) => {
            e.into_bytes().fill(0);
            Err("the password is not text".into())
        }
    }
}

/// The running client's secret, for the log writer.
static LOG_SECRETS: OnceLock<Arc<SecretSlot>> = OnceLock::new();

/// The client's log leaves the secret out from here on.
pub fn scrub_log_with(slot: Arc<SecretSlot>) {
    let _ = LOG_SECRETS.set(slot);
}

/// Where the log goes instead of stderr, once `log_to_file` set it.
static LOG_FILE: OnceLock<std::sync::Mutex<crate::logfile::LogFile>> = OnceLock::new();

/// The client's log goes to `path` (capped, see `logfile`) from here on, instead of
/// stderr: a client without a console has nowhere else to write it.
pub fn log_to_file(path: PathBuf) -> std::io::Result<()> {
    let file = crate::logfile::LogFile::open(path, crate::logfile::MAX_BYTES)?;
    let _ = LOG_FILE.set(std::sync::Mutex::new(file));
    Ok(())
}

/// stderr (or the log file) for the log, one event at a time, with the secret
/// taken out.
pub struct LogWriter;

pub struct LogEvent(Vec<u8>);

impl Write for LogEvent {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LogEvent {
    fn drop(&mut self) {
        let text = scrubbed_for_log(std::mem::take(&mut self.0));
        match LOG_FILE.get() {
            Some(f) => {
                if let Ok(mut f) = f.lock() {
                    f.write_event(&text);
                }
            }
            None => {
                let _ = std::io::stderr().lock().write_all(&text);
            }
        }
    }
}

fn scrubbed_for_log(line: Vec<u8>) -> Vec<u8> {
    match LOG_SECRETS.get() {
        Some(s) if s.is_set() => s.scrub_bytes(&line),
        _ => line,
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogEvent;

    fn make_writer(&'a self) -> LogEvent {
        LogEvent(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_privately_and_refuses_a_file_others_can_read() {
        let dir = std::env::temp_dir().join(format!("pitha-secret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("elevation.secret");
        assert_eq!(load(&path), Ok(None));
        save(&path, &Secret::new("pw one".into())).unwrap();
        assert_eq!(load(&path).unwrap().unwrap().expose(), "pw one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(load(&path).unwrap_err().contains("read by others"));
        }
        remove(&path).unwrap();
        assert_eq!(load(&path), Ok(None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_log_leaves_the_secret_out() {
        let slot = Arc::new(SecretSlot::default());
        scrub_log_with(slot.clone());
        assert_eq!(scrubbed_for_log(b"a pw1 b".to_vec()), b"a pw1 b");
        slot.set(Secret::new("pw1".into()));
        assert_eq!(scrubbed_for_log(b"a pw1 b".to_vec()), b"a [redacted] b");
    }

    #[tokio::test]
    async fn the_keyring_keeps_the_password_only_when_chosen() {
        use sync_policy::keyring::FakeStore;
        let t = tempfile::tempdir().unwrap();
        let dirs = Dirs::under(t.path());
        let ks = FakeStore::default();
        let pw = Secret::new("pw one".into());
        store(&dirs, SecretStorage::Keyring, &ks, &pw)
            .await
            .unwrap();
        assert!(!file(&dirs).exists(), "nothing on disk");
        let got = load_stored(&dirs, SecretStorage::Keyring, &ks).await;
        assert_eq!(got.unwrap().unwrap().expose(), "pw one");
        // Memory storage does not read the keyring, but `sudo clear` takes out
        // what keyring storage left there before the owner switched away.
        assert_eq!(
            load_stored(&dirs, SecretStorage::Memory, &ks).await,
            Ok(None)
        );
        forget(&dirs, SecretStorage::Memory, &ks).await.unwrap();
        assert!(ks.entries.lock().unwrap().is_empty());
        forget(&dirs, SecretStorage::File, &ks).await.unwrap();
        store(&dirs, SecretStorage::Keyring, &ks, &pw)
            .await
            .unwrap();
        forget(&dirs, SecretStorage::File, &ks).await.unwrap();
        assert!(ks.entries.lock().unwrap().is_empty());
        store(&dirs, SecretStorage::Keyring, &ks, &pw)
            .await
            .unwrap();
        // A keyring that fails is an error, never the file or nothing.
        *ks.fail.lock().unwrap() = Some("the prompt was cancelled".into());
        let e = load_stored(&dirs, SecretStorage::Keyring, &ks)
            .await
            .unwrap_err();
        assert!(e.contains("cancelled"), "{e}");
        let e = store(&dirs, SecretStorage::Keyring, &ks, &pw)
            .await
            .unwrap_err();
        assert!(e.contains("cancelled"), "{e}");
        assert!(!file(&dirs).exists());
        *ks.fail.lock().unwrap() = None;
        forget(&dirs, SecretStorage::Keyring, &ks).await.unwrap();
        assert!(ks.entries.lock().unwrap().is_empty());
        // No keyring at all: another storage forgets without an error.
        *ks.fail.lock().unwrap() = Some("no keyring service".into());
        forget(&dirs, SecretStorage::Memory, &ks).await.unwrap();
    }

    /// A stand-in sudo: it logs its arguments and environment, passes `-n`
    /// when `nopw` exists, and takes "right pw" on stdin.
    #[cfg(unix)]
    fn fake_sudo(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("sudo");
        let log = dir.join("log");
        let nopw = dir.join("nopw");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{log}'\nenv >> '{log}'\ncase \"$*\" in *-n*) [ -e '{nopw}' ] && exit 0; echo 'sudo: a password is required' >&2; exit 1;; esac\nread -r pw\n[ \"$pw\" = 'right pw' ] && exit 0\ncase \"$pw\" in echoed*) echo \"sudo: no user named $pw\" >&2; exit 1;; esac\necho 'Sorry, try again.' >&2\necho 'sudo: 1 incorrect password attempt' >&2\nexit 1\n",
                log = log.display(),
                nopw = nopw.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sudo_checks_the_password_from_stdin_and_caches_nothing() {
        let t = tempfile::tempdir().unwrap();
        let sudo = fake_sudo(t.path());
        let right = Secret::new("right pw".into());
        assert_eq!(
            check_with_sudo(&sudo, &right).await,
            Ok(SudoCheck::Accepted)
        );
        let wrong = Secret::new("wrong pw".into());
        assert_eq!(
            check_with_sudo(&sudo, &wrong).await,
            Ok(SudoCheck::Refused(
                "sudo: 1 incorrect password attempt".into()
            ))
        );
        // A sudo (or a PAM module) that echoes the password: its line is not
        // passed on, since the window puts it in a dialog program's argv.
        let echoed = Secret::new("echoed pw".into());
        assert_eq!(
            check_with_sudo(&sudo, &echoed).await,
            Ok(SudoCheck::Refused(String::new()))
        );
        let log = std::fs::read_to_string(t.path().join("log")).unwrap();
        // Never in argv or the environment; no cached credentials used or kept.
        assert!(
            !log.contains("right pw") && !log.contains("wrong pw") && !log.contains("echoed"),
            "{log}"
        );
        assert!(
            log.contains("-k -n -v") && log.contains("-k -S -p  -v"),
            "{log}"
        );
        assert!(!log.contains("HOME="), "{log}");
        // sudo asks no password: nothing is proven.
        std::fs::write(t.path().join("nopw"), "").unwrap();
        assert_eq!(
            check_with_sudo(&sudo, &wrong).await,
            Ok(SudoCheck::NoPasswordNeeded)
        );
        // No sudo there.
        assert!(
            check_with_sudo(&t.path().join("none"), &right)
                .await
                .is_err()
        );
    }

    #[test]
    fn takes_one_line_only() {
        assert!(check("").is_err());
        assert!(check("a\nb").is_err());
        assert!(check(&"x".repeat(MAX_LEN + 1)).is_err());
        assert!(check("pw with spaces").is_ok());
        assert_eq!(secret_from(b"pw\r".to_vec()).unwrap().expose(), "pw");
    }
}
