//! The client's log as a file, for a client without a console: the Windows logon
//! task starts `run --detach`, which has no terminal and no journal to write to.
//! The file is capped: once it would grow past `MAX_BYTES` it moves aside to
//! `<name>.1` (replacing the one before) and a new file starts, so the log never
//! takes more than about twice the cap.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// One file's cap; with the one moved aside the log keeps at most twice this.
pub const MAX_BYTES: u64 = 1024 * 1024;

pub struct LogFile {
    path: PathBuf,
    file: Option<File>,
    len: u64,
    max: u64,
}

/// `client.log` becomes `client.log.1`.
pub fn rotated(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".1");
    path.with_file_name(name)
}

impl LogFile {
    /// Opens `path` to append to it, creating it and its folder (private to the
    /// user) when they are missing.
    pub fn open(path: PathBuf, max: u64) -> io::Result<LogFile> {
        if let Some(dir) = path.parent() {
            sync_policy::private::private_dir(dir)?;
        }
        let file = sync_policy::private::private_options()
            .create(true)
            .append(true)
            .open(&path)?;
        let len = file.metadata()?.len();
        Ok(LogFile {
            path,
            file: Some(file),
            len,
            max,
        })
    }

    /// Writes one event, moving the file aside first when the event would take it
    /// past the cap. Errors are dropped: the log must never stop the client.
    pub fn write_event(&mut self, event: &[u8]) {
        if self.len > 0 && self.len + event.len() as u64 > self.max {
            self.rotate();
        }
        if let Some(f) = &mut self.file
            && f.write_all(event).is_ok()
        {
            self.len += event.len() as u64;
        }
    }

    fn rotate(&mut self) {
        // Closed first: Windows does not rename a file this process holds open.
        self.file = None;
        let old = rotated(&self.path);
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(&self.path, &old);
        // Truncating, in case the rename failed (another program holding the file):
        // the cap holds either way.
        self.file = sync_policy::private::private_options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)
            .ok();
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_moves_aside_at_its_cap_and_keeps_two_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs/client.log");
        let mut log = LogFile::open(path.clone(), 100).unwrap();
        for i in 0..30 {
            log.write_event(format!("event {i:02} of the client\n").as_bytes());
        }
        let now = std::fs::read_to_string(&path).unwrap();
        let before = std::fs::read_to_string(rotated(&path)).unwrap();
        assert!(
            now.len() <= 100 && before.len() <= 100,
            "{now:?} {before:?}"
        );
        assert!(now.ends_with("event 29 of the client\n"), "{now:?}");
        assert!(before.ends_with(&format!(
            "event {:02} of the client\n",
            29 - now.lines().count()
        )));
        let files = std::fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(files, 2);
        // A client started again appends to what is there and keeps the cap.
        drop(log);
        let mut log = LogFile::open(path.clone(), 100).unwrap();
        log.write_event(b"after a restart\n");
        assert!(std::fs::metadata(&path).unwrap().len() <= 100);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .ends_with("after a restart\n")
        );
    }
}
