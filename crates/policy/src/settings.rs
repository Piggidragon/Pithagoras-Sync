//! The settings document the portal's Devices tab reads (`policy.get`) and, where
//! the owner switched `portal_policy` to `write`, replaces (`policy.set`).
//!
//! The document is the config file's `[policy]` and `[exec]` tables. Never in it:
//! the pairing, the profile, `portal_policy` itself and the elevation secret. A few
//! settings in it are the device's alone (the shell and sudo the client runs, where
//! the secret is kept): a portal that could point them elsewhere could make the
//! device hand the secret to a program of its choosing.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sync_proto::methods::{Mode, PolicyDocument, PolicySetParams};

use crate::config::{DeviceConfig, ExecOptions, Policy, PortalPolicy};

/// Settings only the device changes; `policy.set` must leave them as they are.
pub const DEVICE_ONLY: &[&str] = &[
    "exec.shell",
    "policy.privilege.sudo_path",
    "policy.privilege.secret_storage",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub policy: Policy,
    pub exec: ExecOptions,
}

pub fn settings_value(cfg: &DeviceConfig) -> Value {
    serde_json::to_value(Settings {
        policy: cfg.policy.clone(),
        exec: cfg.exec.clone(),
    })
    .unwrap_or(Value::Null)
}

/// A hash of the settings (FNV-1a over the JSON, whose object keys serde_json
/// keeps sorted): it changes whenever they do.
pub fn version(settings: &Value) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in settings.to_string().bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// What `policy.get` returns and `policy.changed` carries.
pub fn document(cfg: &DeviceConfig) -> PolicyDocument {
    let settings = settings_value(cfg);
    PolicyDocument {
        portal_policy: cfg.portal_policy.as_str().into(),
        version: version(&settings),
        settings,
        device_only: DEVICE_ONLY.iter().map(|s| s.to_string()).collect(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    /// Dotted path of the setting (`policy.mode`, `policy.tools.bash`).
    pub key: String,
    pub old: Value,
    pub new: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetError {
    Denied(String),
    Conflict(String),
    Invalid(String),
}

/// The config after the portal's `policy.set`, and what changed. Only with
/// `portal_policy = write`; device-only settings must be unchanged.
pub fn apply_from_portal(
    cfg: &DeviceConfig,
    params: PolicySetParams,
    now_ms: i64,
) -> Result<(DeviceConfig, Vec<Change>), SetError> {
    match cfg.portal_policy {
        PortalPolicy::Write => {}
        PortalPolicy::Read => {
            return Err(SetError::Denied(
                "this device lets the portal read its settings, not change them".into(),
            ));
        }
        PortalPolicy::Off => {
            return Err(SetError::Denied(
                "this device does not share its settings with the portal".into(),
            ));
        }
    }
    let current = settings_value(cfg);
    if let Some(v) = &params.if_version
        && *v != version(&current)
    {
        return Err(SetError::Conflict(
            "the settings changed on the device meanwhile; read them again".into(),
        ));
    }
    let new: Settings =
        serde_json::from_value(params.settings).map_err(|e| SetError::Invalid(e.to_string()))?;
    let device_only = [
        ("exec.shell", new.exec.shell != cfg.exec.shell),
        (
            "policy.privilege.sudo_path",
            new.policy.privilege.sudo_path != cfg.policy.privilege.sudo_path,
        ),
        (
            "policy.privilege.secret_storage",
            new.policy.privilege.secret_storage != cfg.policy.privilege.secret_storage,
        ),
    ];
    if let Some((key, _)) = device_only.iter().find(|(_, changed)| *changed) {
        return Err(SetError::Denied(format!(
            "{key} can only be changed on the device"
        )));
    }
    let mut next = cfg.clone();
    next.policy = new.policy;
    next.exec = new.exec;
    // When Full ends is the device's to date, from when it was switched on.
    let old = &cfg.policy;
    next.policy.full.until_ms = old.full.until_ms;
    if next.policy.mode == Mode::Full {
        if old.effective_mode(cfg.profile, now_ms) != Mode::Full
            || old.full.expiry_hours != next.policy.full.expiry_hours
        {
            next.policy.set_mode(Mode::Full, now_ms);
        }
    } else {
        next.policy.full.until_ms = None;
    }
    next.policy
        .validate(next.profile)
        .and_then(|()| next.exec.validate())
        .map_err(SetError::Invalid)?;
    // A folder path is printed to the owner's terminal; the portal cannot put
    // control characters there that would redraw what the owner reads.
    if let Some(f) = next.policy.folders.iter().find(|f| {
        f.path.to_string_lossy().chars().any(char::is_control)
            && !cfg.policy.folders.iter().any(|o| o.path == f.path)
    }) {
        return Err(SetError::Invalid(format!(
            "folder {:?}: a folder path has no control characters",
            f.path
        )));
    }
    let mut changes = Vec::new();
    diff("", &current, &settings_value(&next), &mut changes);
    Ok((next, changes))
}

/// The settings that differ, by dotted path; lists count as one setting.
pub fn diff(prefix: &str, old: &Value, new: &Value, out: &mut Vec<Change>) {
    match (old, new) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                diff(
                    &key,
                    a.get(k).unwrap_or(&Value::Null),
                    b.get(k).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        (a, b) if a != b => out.push(Change {
            key: prefix.to_string(),
            old: a.clone(),
            new: b.clone(),
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Elevation;

    fn cfg(pp: PortalPolicy) -> DeviceConfig {
        DeviceConfig {
            portal_policy: pp,
            ..Default::default()
        }
    }

    fn set(
        c: &DeviceConfig,
        edit: impl FnOnce(&mut Value),
    ) -> Result<(DeviceConfig, Vec<Change>), SetError> {
        let mut v = settings_value(c);
        edit(&mut v);
        apply_from_portal(
            c,
            PolicySetParams {
                settings: v,
                if_version: None,
            },
            1_000,
        )
    }

    #[test]
    fn off_and_read_refuse_every_change() {
        for pp in [PortalPolicy::Off, PortalPolicy::Read] {
            let c = cfg(pp);
            let r = set(&c, |v| v["policy"]["mode"] = "full".into());
            assert!(matches!(r, Err(SetError::Denied(_))), "{pp:?}: {r:?}");
            let r =
                set(
                    &c,
                    |v| {
                        v["policy"]["folders"] =
                            serde_json::json!([{"path": "/", "access": "rw", "execute": true}])
                    },
                );
            assert!(matches!(r, Err(SetError::Denied(_))), "{pp:?}");
            let r = set(&c, |v| {
                v["policy"]["full"]["protected_paths"] = false.into()
            });
            assert!(matches!(r, Err(SetError::Denied(_))), "{pp:?}");
        }
    }

    #[test]
    fn write_may_widen_and_reports_each_change() {
        let c = cfg(PortalPolicy::Write);
        let (next, changes) = set(&c, |v| {
            v["policy"]["mode"] = "full".into();
            v["policy"]["full"]["protected_paths"] = false.into();
            v["policy"]["privilege"]["elevation"] = "sudo".into();
            v["policy"]["tools"]["bash"] = false.into();
        })
        .unwrap();
        assert_eq!(next.policy.mode, Mode::Full);
        assert_eq!(next.policy.full.until_ms, Some(1_000 + 8 * 3_600_000));
        assert_eq!(next.policy.privilege.elevation, Elevation::Sudo);
        let keys: Vec<&str> = changes.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "policy.full.protected_paths",
                "policy.full.until_ms",
                "policy.mode",
                "policy.privilege.elevation",
                "policy.tools.bash",
            ]
        );
        let mode = &changes[2];
        assert_eq!(
            (mode.old.as_str(), mode.new.as_str()),
            (Some("ask"), Some("full"))
        );
    }

    #[test]
    fn device_only_settings_and_portal_policy_stay_on_the_device() {
        let c = cfg(PortalPolicy::Write);
        for edit in [
            |v: &mut Value| v["exec"]["shell"] = "/tmp/evil".into(),
            |v: &mut Value| v["policy"]["privilege"]["sudo_path"] = "/tmp/sudo".into(),
            |v: &mut Value| v["policy"]["privilege"]["secret_storage"] = "file".into(),
        ] {
            assert!(matches!(set(&c, edit), Err(SetError::Denied(_))));
        }
        // Neither the switch nor the pairing is in the document at all.
        for edit in [
            |v: &mut Value| v["portal_policy"] = "write".into(),
            |v: &mut Value| v["portal"] = serde_json::json!({}),
            |v: &mut Value| v["secret"] = "x".into(),
        ] {
            assert!(matches!(set(&c, edit), Err(SetError::Invalid(_))));
        }
    }

    #[test]
    fn a_folder_path_from_the_portal_has_no_control_characters() {
        let c = cfg(PortalPolicy::Write);
        // Absolute on every platform.
        let proj = std::env::temp_dir()
            .join("proj")
            .to_string_lossy()
            .into_owned();
        let forged = format!("{proj}\u{1b}[1A\u{1b}[2K\r{proj} (Rw)");
        let r = set(
            &c,
            |v| {
                v["policy"]["folders"] =
                    serde_json::json!([{"path": forged, "access": "ro", "execute": false}])
            },
        );
        assert!(matches!(r, Err(SetError::Invalid(_))), "{r:?}");
        let (next, _) =
            set(
                &c,
                |v| {
                    v["policy"]["folders"] =
                        serde_json::json!([{"path": proj, "access": "ro", "execute": false}])
                },
            )
            .unwrap();
        assert_eq!(next.policy.folders.len(), 1);
    }

    #[test]
    fn a_stale_version_conflicts_and_bad_settings_are_refused() {
        let c = cfg(PortalPolicy::Write);
        let r = apply_from_portal(
            &c,
            PolicySetParams {
                settings: settings_value(&c),
                if_version: Some("0".into()),
            },
            0,
        );
        assert!(matches!(r, Err(SetError::Conflict(_))));
        let r = apply_from_portal(
            &c,
            PolicySetParams {
                settings: settings_value(&c),
                if_version: Some(document(&c).version),
            },
            0,
        );
        assert_eq!(r.unwrap().1, []);
        let r = set(&c, |v| {
            v["policy"]["commands"]["deny"] = serde_json::json!([{"regex": "("}])
        });
        assert!(matches!(r, Err(SetError::Invalid(_))));
        // The portal cannot date Full's end itself.
        let (next, _) = set(&c, |v| {
            v["policy"]["mode"] = "full".into();
            v["policy"]["full"]["until_ms"] = i64::MAX.into();
        })
        .unwrap();
        assert_eq!(next.policy.full.until_ms, Some(1_000 + 8 * 3_600_000));
    }
}
