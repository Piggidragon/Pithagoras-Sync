//! The device's config as the running client holds it: the owner's file, applied to
//! the engine and the command runner, and shown to (or, where the owner allows it,
//! changed by) the portal.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sync_ops::Execs;
use sync_policy::config::PortalPolicy;
use sync_policy::settings::{self, SetError};
use sync_policy::{DeviceConfig, Engine, system_clock};
use sync_proto::methods::{PolicyDocument, PolicySetParams};
use sync_proto::{RpcError, code};
use tokio::sync::broadcast;

pub struct ConfigStore {
    file: PathBuf,
    cfg: Mutex<DeviceConfig>,
    engine: Arc<Engine>,
    execs: Arc<Execs>,
    changed: broadcast::Sender<()>,
}

impl ConfigStore {
    /// `cfg` is what `file` held when the engine and runner were built from it.
    pub fn new(
        file: PathBuf,
        cfg: DeviceConfig,
        engine: Arc<Engine>,
        execs: Arc<Execs>,
    ) -> Arc<ConfigStore> {
        let (changed, _) = broadcast::channel(16);
        Arc::new(ConfigStore {
            file,
            cfg: Mutex::new(cfg),
            engine,
            execs,
            changed,
        })
    }

    pub fn config(&self) -> DeviceConfig {
        self.cfg.lock().unwrap().clone()
    }

    /// Fires after every change that took effect (`policy.changed`).
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.changed.subscribe()
    }

    /// Loads the file as it is now; the profile stays what the client started
    /// with. A bad file leaves everything as it was.
    fn load(&self) -> Result<DeviceConfig, String> {
        let mut cfg = DeviceConfig::load(&self.file)?;
        if cfg.policy.date_full(system_clock()()) {
            cfg.save(&self.file)?;
        }
        cfg.profile = self.cfg.lock().unwrap().profile;
        Ok(cfg)
    }

    /// The owner changed the file (CLI or by hand): take it.
    pub fn reload(&self) -> Result<DeviceConfig, String> {
        let cfg = self.load()?;
        self.apply(cfg.clone(), "the device owner");
        Ok(cfg)
    }

    fn apply(&self, cfg: DeviceConfig, by: &str) {
        self.engine.reload_by(cfg.policy.clone(), cfg.profile, by);
        self.execs.set_limits(
            cfg.exec.env_passthrough.clone(),
            cfg.exec.output_cap_bytes,
            Duration::from_secs(cfg.exec.max_timeout_secs),
            cfg.exec.max_running as usize,
        );
        let changed = *self.cfg.lock().unwrap() != cfg;
        *self.cfg.lock().unwrap() = cfg;
        if changed {
            let _ = self.changed.send(());
        }
    }

    pub fn portal_policy(&self) -> PortalPolicy {
        self.cfg.lock().unwrap().portal_policy
    }

    /// `policy.get`, and the body of `policy.changed`.
    pub fn document_for_portal(&self) -> Result<PolicyDocument, RpcError> {
        let cfg = self.cfg.lock().unwrap();
        if cfg.portal_policy == PortalPolicy::Off {
            return Err(RpcError::denied(
                "this device does not share its settings with the portal",
            ));
        }
        Ok(settings::document(&cfg))
    }

    /// `policy.set`: only with `portal_policy = write`. Based on the file as it is
    /// now, so a change the owner just made is not overwritten unseen (the
    /// portal's `if_version` then conflicts). Each changed setting is audited.
    pub fn set_from_portal(&self, params: PolicySetParams) -> Result<PolicyDocument, RpcError> {
        // One change at a time, from the file onwards.
        static SETTING: Mutex<()> = Mutex::new(());
        let _one = SETTING.lock().unwrap();
        let current = self.load().map_err(|e| RpcError::new(code::IO, e))?;
        let (next, changes) = settings::apply_from_portal(&current, params, system_clock()())
            .map_err(|e| match e {
                SetError::Denied(m) => RpcError::denied(m),
                SetError::Conflict(m) => RpcError::new(code::CONFLICT, m),
                SetError::Invalid(m) => RpcError::new(code::INVALID_PARAMS, m),
            })?;
        next.save(&self.file)
            .map_err(|e| RpcError::new(code::IO, e))?;
        for c in &changes {
            self.engine.record(
                None,
                "policy",
                &c.key,
                "changed",
                Some(format!("by the portal: {} -> {}", c.old, c.new)),
            );
        }
        self.apply(next.clone(), "the owner's portal session");
        Ok(settings::document(&next))
    }
}
