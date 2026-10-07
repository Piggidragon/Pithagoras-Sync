//! The device as the connector serves it: policy engine, commands, and its facts.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use sync_ops::{Execs, info};
use sync_policy::config::PortalPolicy;
use sync_policy::paths::to_wire;
use sync_policy::secret::SecretSlot;
use sync_policy::{ApprovalQueue, Engine, FoldersShell, Mode};
use sync_proto::methods::{
    CAP_APPROVALS, CAP_POLICY, CAPABILITIES, DeviceInfo, FolderInfo, Hello, PiTool,
};

use crate::settings::ConfigStore;
use tokio::sync::watch;

pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Device {
    pub engine: Arc<Engine>,
    pub execs: Arc<Execs>,
    name: RwLock<String>,
    pub home: PathBuf,
    paused: watch::Sender<bool>,
    /// The engine's approver, when it asks through the portal and the local CLI.
    pub approvals: Option<Arc<ApprovalQueue>>,
    /// The config, when the portal may see it (`policy.get`, `policy.set`).
    pub store: Option<Arc<ConfigStore>>,
    /// The elevation secret: commands get it through sudo, and the engine's audit
    /// log, the commands' output and every text frame to the portal leave it out.
    pub secrets: Arc<SecretSlot>,
}

impl Device {
    pub fn new(engine: Arc<Engine>, execs: Arc<Execs>, name: String, home: PathBuf) -> Arc<Device> {
        Device::with_parts(engine, execs, name, home, None, None)
    }

    pub fn with_parts(
        engine: Arc<Engine>,
        execs: Arc<Execs>,
        name: String,
        home: PathBuf,
        approvals: Option<Arc<ApprovalQueue>>,
        store: Option<Arc<ConfigStore>>,
    ) -> Arc<Device> {
        let (paused, _) = watch::channel(engine.is_paused());
        let secrets = Arc::new(SecretSlot::default());
        engine.scrub_with(secrets.clone());
        execs.use_secrets(secrets.clone());
        execs.set_paused(engine.is_paused());
        Arc::new(Device {
            engine,
            execs,
            name: RwLock::new(name),
            home,
            paused,
            approvals,
            store,
            secrets,
        })
    }

    /// Whether the portal may read the settings now.
    pub fn shares_policy(&self) -> bool {
        self.store
            .as_ref()
            .is_some_and(|s| s.portal_policy() != PortalPolicy::Off)
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
        self.execs.pause().await;
    }

    pub fn unlock(&self) {
        self.execs.set_paused(false);
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
                    execute: f.execute,
                })
                .collect(),
            folders_shell: self.folders_shell().into(),
            tools: PiTool::ALL
                .into_iter()
                .filter(|t| policy.tools.enabled(*t))
                .collect(),
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
            capabilities: CAPABILITIES
                .iter()
                .copied()
                .chain(self.approvals.is_some().then_some(CAP_APPROVALS))
                .chain(self.shares_policy().then_some(CAP_POLICY))
                .map(str::to_string)
                .collect(),
            mcp_version: None,
        }
    }
}
