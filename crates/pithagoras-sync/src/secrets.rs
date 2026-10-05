//! The elevation secret on the device: typed in a terminal (`secret set
//! elevation`), handed to the running client over the control channel, and kept
//! either in the client's memory only (the default; panic and restarts forget it)
//! or in a file only this user can read. It never goes to the portal, into a
//! command's argv or environment, the audit log or the client's own log.
//!
//! The OS keyring is not used: a keyring unlocked for this user gives the secret to
//! every process of the user, which is what a 0600 file does as well, and a server
//! has none. Memory is the safer place: the client makes itself undumpable, so other
//! processes of the user cannot read it there.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use sync_policy::Dirs;
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
    Err("elevation is built for Linux (sudo) only in this version".into())
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

/// stderr for the log, one event at a time, with the secret taken out.
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
        let _ = std::io::stderr().lock().write_all(&text);
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

    #[test]
    fn takes_one_line_only() {
        assert!(check("").is_err());
        assert!(check("a\nb").is_err());
        assert!(check(&"x".repeat(MAX_LEN + 1)).is_err());
        assert!(check("pw with spaces").is_ok());
        assert_eq!(secret_from(b"pw\r".to_vec()).unwrap().expose(), "pw");
    }
}
