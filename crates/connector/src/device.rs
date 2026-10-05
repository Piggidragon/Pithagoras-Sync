//! The device as the connector serves it: policy engine, commands, and its facts.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use sync_ops::{Execs, info};
use sync_policy::paths::to_wire;
use sync_policy::{Engine, FoldersShell, Mode};
use sync_proto::methods::{CAPABILITIES, DeviceInfo, FolderInfo, Hello};
use tokio::sync::watch;

pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Device {
    pub engine: Arc<Engine>,
    pub execs: Arc<Execs>,
    name: RwLock<String>,
    pub home: PathBuf,
    paused: watch::Sender<bool>,
}

impl Device {
    pub fn new(engine: Arc<Engine>, execs: Arc<Execs>, name: String, home: PathBuf) -> Arc<Device> {
        let (paused, _) = watch::channel(engine.is_paused());
        Arc::new(Device {
            engine,
            execs,
            name: RwLock::new(name),
            home,
            paused,
        })
    }

    pub fn name(&self) -> String {
        self.name.read().unwrap().clone()
    }

    /// The owner paired again under another name.
    pub fn set_name(&self, name: String) {
        *self.name.write().unwrap() = name;
    }

    /// Panic: the engine denies everything, the link closes, and every command and
    /// what it left behind is killed. Stays so until `unlock`.
    pub async fn pause(&self) {
        self.engine.pause();
        self.paused.send_replace(true);
        self.execs.kill_all().await;
    }

    pub fn unlock(&self) {
        self.engine.unlock();
        self.paused.send_replace(false);
    }

    pub fn is_paused(&self) -> bool {
        *self.paused.borrow()
    }

    pub fn paused(&self) -> watch::Receiver<bool> {
        self.paused.subscribe()
    }

    /// How the Folders shell really runs here (Landlock falls back to prompting
    /// where the kernel lacks it).
    pub fn folders_shell(&self) -> &'static str {
        let (policy, _) = self.engine.policy();
        match policy.folders_shell {
            FoldersShell::Landlock if !self.engine.landlock_available() => "prompt",
            s => s.as_str(),
        }
    }

    pub fn info(&self) -> DeviceInfo {
        let (policy, _) = self.engine.policy();
        let mode = self.engine.effective_mode();
        let (user, uid) = info::user();
        DeviceInfo {
            name: self.name(),
            os: info::os().into(),
            arch: info::arch().into(),
            os_release: info::os_release(),
            hostname: info::hostname(),
            user,
            uid,
            home: to_wire(&self.home),
            shell: self.execs.shell_name(),
            session: info::session().into(),
            mode,
            mode_expires_ms: if mode == Mode::Full {
                policy.full.until_ms
            } else {
                None
            },
            folders: policy
                .folders
                .iter()
                .map(|f| FolderInfo {
                    path: to_wire(&f.path),
                    access: f.access,
                })
                .collect(),
            folders_shell: self.folders_shell().into(),
            mcp_tools: Vec::new(),
            client_version: CLIENT_VERSION.into(),
        }
    }

    pub fn hello(&self, device_id: &str) -> Hello {
        Hello {
            proto: sync_proto::PROTO_VERSION,
            device_id: device_id.into(),
            client_version: CLIENT_VERSION.into(),
            os: info::os().into(),
            user: info::user().0,
            shell: self.execs.shell_name(),
            capabilities: CAPABILITIES.iter().map(|c| c.to_string()).collect(),
        }
    }
}
