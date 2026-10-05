//! A cgroup per command, inside the client's own delegated cgroup (`Delegate=yes` in
//! the systemd unit). Killing the cgroup kills everything a command started, however
//! it detached. Without a writable cgroup the shim's process tree is the only fence.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct CgroupBase {
    dir: PathBuf,
}

impl CgroupBase {
    /// The client's own cgroup v2 directory, if it may create children there.
    pub fn detect() -> Option<CgroupBase> {
        let text = fs::read_to_string("/proc/self/cgroup").ok()?;
        let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
        let dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
        let probe = dir.join(format!("pithagoras-probe-{}", std::process::id()));
        fs::create_dir(&probe).ok()?;
        let kill = probe.join("cgroup.kill").exists();
        let _ = fs::remove_dir(&probe);
        kill.then_some(CgroupBase { dir })
    }

    /// A base at `dir`, for tests.
    #[cfg(test)]
    pub fn at(dir: PathBuf) -> CgroupBase {
        CgroupBase { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn create(&self) -> io::Result<PathBuf> {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let cg = self
            .dir
            .join(format!("pithagoras-exec-{}-{n}", std::process::id()));
        fs::create_dir(&cg)?;
        Ok(cg)
    }
}

/// Kills every process in the cgroup at once (`cgroup.kill`, Linux 5.14+).
pub fn kill(cg: &Path) {
    let _ = fs::write(cg.join("cgroup.kill"), "1");
}

/// Whether any process is left in the cgroup.
pub fn populated(cg: &Path) -> bool {
    fs::read_to_string(cg.join("cgroup.procs"))
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// Removes an empty cgroup; a few tries while the last processes are reaped.
pub async fn remove(cg: PathBuf) {
    for _ in 0..50 {
        if fs::remove_dir(&cg).is_ok() || !cg.exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    tracing::warn!("could not remove {}", cg.display());
}
