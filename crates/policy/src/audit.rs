//! The local audit log: append-only JSONL, one line per call and decision. It never
//! holds file contents, only what was asked and what the device decided.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Above this size the log moves to `audit.jsonl.1` and a new one starts.
const ROTATE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub time_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat: Option<String>,
    /// `read`, `write`, `list`, `grep`, `find`, `exec`, `exit`, `mode`, `pause`, ...
    pub tool: String,
    /// Path or command.
    pub target: String,
    /// `allowed` (by policy), `approved` (by the owner), `denied`, or for `exit` and
    /// state changes a short word of their own.
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl AuditRecord {
    /// Whether the portal's Audit page gets this record: decisions, not every call.
    pub fn mirrored(&self) -> bool {
        self.decision != "allowed" && self.tool != "exit"
    }
}

pub struct AuditLog {
    path: PathBuf,
    file: Mutex<Option<File>>,
}

impl AuditLog {
    pub fn open(path: &Path) -> io::Result<AuditLog> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let f = Self::open_file(path)?;
        Ok(AuditLog {
            path: path.to_path_buf(),
            file: Mutex::new(Some(f)),
        })
    }

    fn open_file(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
    }

    /// Appends one record. A failure is logged, never fatal: the decision stands.
    pub fn append(&self, rec: &AuditRecord) {
        if let Err(e) = self.try_append(rec) {
            tracing::error!("audit log {}: {e}", self.path.display());
        }
    }

    fn try_append(&self, rec: &AuditRecord) -> io::Result<()> {
        let mut line = serde_json::to_vec(rec).map_err(io::Error::other)?;
        line.push(b'\n');
        let mut guard = self.file.lock().unwrap();
        if let Some(f) = guard.as_ref()
            && f.metadata()?.len() > ROTATE_BYTES
        {
            *guard = None;
            let mut old = self.path.clone().into_os_string();
            old.push(".1");
            fs::rename(&self.path, old)?;
        }
        if guard.is_none() {
            *guard = Some(Self::open_file(&self.path)?);
        }
        // One write per record: with O_APPEND each line lands whole.
        guard.as_mut().unwrap().write_all(&line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_private_jsonl() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("s/audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        let rec = AuditRecord {
            time_ms: 1,
            chat: Some("c".into()),
            tool: "write".into(),
            target: "/w/a".into(),
            decision: "denied".into(),
            reason: Some("outside".into()),
            exit_code: None,
        };
        log.append(&rec);
        log.append(&rec);
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<AuditRecord> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines, vec![rec.clone(), rec]);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
