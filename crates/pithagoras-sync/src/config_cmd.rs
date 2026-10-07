//! `pithagoras-sync config get|set|unset|add|remove`: any setting by its dotted
//! name (`policy.tools.bash`, `exec.max_running`), as docs/permissions.md lists
//! them. Values are JSON where they parse as JSON, text otherwise.

use serde_json::Value;
use sync_policy::config::SecretStorage;
use sync_policy::{Consent, DeviceConfig, Mode};

pub enum Op {
    Set(Value),
    /// Back to the default.
    Unset,
    /// Append to a list.
    Add(Value),
    /// Take every equal entry out of a list.
    Remove(Value),
}

/// `true`, `8`, `["a"]` and `{"path": "~/x"}` are JSON; anything else is text.
pub fn parse_value(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.to_string()))
}

fn as_value(cfg: &DeviceConfig) -> Result<Value, String> {
    serde_json::to_value(cfg).map_err(|e| e.to_string())
}

fn lookup<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('.').try_fold(v, |v, k| v.get(k))
}

fn check_key(key: &str) -> Result<(), String> {
    match key.split('.').next() {
        Some("portal") => Err("the pairing changes with `pair` and `unpair`".into()),
        Some("profile" | "portal_policy" | "token_storage" | "policy" | "exec")
            if !key.is_empty() =>
        {
            Ok(())
        }
        _ => Err(format!(
            "{key}: settings start with policy., exec., portal_policy, token_storage or profile"
        )),
    }
}

pub fn get(cfg: &DeviceConfig, key: Option<&str>) -> Result<Value, String> {
    let mut v = as_value(cfg)?;
    if let Some(o) = v.as_object_mut() {
        o.remove("portal");
    }
    match key {
        None => Ok(v),
        Some(k) => lookup(&v, k)
            .cloned()
            .ok_or_else(|| format!("there is no setting {k}")),
    }
}

/// The config with one setting changed, checked as a whole.
pub fn edit(cfg: &DeviceConfig, key: &str, op: Op, now_ms: i64) -> Result<DeviceConfig, String> {
    edit_on(cfg, key, op, now_ms, cfg!(windows))
}

/// `edit` as on Windows (`windows`) or Linux.
pub fn edit_on(
    cfg: &DeviceConfig,
    key: &str,
    op: Op,
    now_ms: i64,
    windows: bool,
) -> Result<DeviceConfig, String> {
    check_key(key)?;
    let mut v = as_value(cfg)?;
    let default = as_value(&DeviceConfig::default())?;
    let (parent_key, last) = match key.rsplit_once('.') {
        Some((p, l)) => (Some(p), l),
        None => (None, key),
    };
    let parent = match parent_key {
        Some(p) => p
            .split('.')
            .try_fold(&mut v, |v, k| v.get_mut(k))
            .ok_or_else(|| format!("there is no setting {p}"))?,
        None => &mut v,
    };
    let obj = parent
        .as_object_mut()
        .ok_or_else(|| format!("{} holds no settings", parent_key.unwrap_or(key)))?;
    if !obj.contains_key(last) {
        return Err(format!("there is no setting {key}"));
    }
    match op {
        Op::Set(x) => {
            obj.insert(last.to_string(), x);
        }
        Op::Unset => {
            let d = lookup(&default, key).cloned().unwrap_or(Value::Null);
            obj.insert(last.to_string(), d);
        }
        Op::Add(x) => match obj.get_mut(last) {
            Some(Value::Array(a)) => {
                if !a.contains(&x) {
                    a.push(x);
                }
            }
            _ => return Err(format!("{key} is not a list")),
        },
        Op::Remove(x) => match obj.get_mut(last) {
            Some(Value::Array(a)) => {
                let before = a.len();
                a.retain(|e| *e != x);
                if a.len() == before {
                    return Err(format!("{key} has no entry {x}"));
                }
            }
            _ => return Err(format!("{key} is not a list")),
        },
    }
    let mut next: DeviceConfig = serde_json::from_value(v).map_err(|e| format!("{key}: {e}"))?;
    // Full's end is dated here, from when it is switched on or its length changes.
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
    // An allow of computer use always has an end, dated here by its own command.
    let (old_cu, new_cu) = (&cfg.policy.computer_use, &mut next.policy.computer_use);
    if new_cu.until_ms != old_cu.until_ms {
        return Err("policy.computer_use.until_ms is set by `pithagoras-sync computer-use allow --minutes N`".into());
    }
    if new_cu.consent != old_cu.consent {
        if new_cu.consent == Consent::Allow {
            return Err("allowing computer use takes a time: `pithagoras-sync computer-use allow --minutes N` (at most 480)".into());
        }
        new_cu.until_ms = None;
    }
    // The password in the keyring is for sudo, which Windows has not.
    if windows
        && next.policy.privilege.secret_storage == SecretStorage::Keyring
        && cfg.policy.privilege.secret_storage != SecretStorage::Keyring
    {
        return Err(
            "policy.privilege.secret_storage = keyring is Linux only: Windows has no sudo, so there is no password to keep".into(),
        );
    }
    next.policy.validate(next.profile)?;
    next.exec.validate()?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync_policy::config::PortalPolicy;

    #[test]
    fn sets_lists_and_defaults_by_name() {
        let cfg = DeviceConfig::default();
        let c = edit(&cfg, "policy.tools.bash", Op::Set(parse_value("false")), 0).unwrap();
        assert!(!c.policy.tools.bash);
        let c = edit(&c, "portal_policy", Op::Set(parse_value("write")), 0).unwrap();
        assert_eq!(c.portal_policy, PortalPolicy::Write);
        let rule = parse_value(r#"{"path": "~/secret", "rights": "rw"}"#);
        let c = edit(&c, "policy.deny", Op::Add(rule.clone()), 0).unwrap();
        assert_eq!(c.policy.deny.len(), 1);
        let c = edit(&c, "policy.deny", Op::Remove(rule), 0).unwrap();
        assert!(c.policy.deny.is_empty());
        let c = edit(&c, "policy.tools.bash", Op::Unset, 0).unwrap();
        assert!(c.policy.tools.bash);
        let c = edit(&c, "policy.mode", Op::Set(parse_value("full")), 5).unwrap();
        assert_eq!(c.policy.full.until_ms, Some(5 + 8 * 3_600_000));
        let h = parse_value(r#"{"from": "08:00", "to": "18:00"}"#);
        let c = edit(&c, "policy.hours", Op::Set(h), 0).unwrap();
        assert!(c.policy.hours.is_some());
        assert_eq!(get(&c, Some("policy.hours.from")).unwrap(), "08:00");
    }

    #[test]
    fn refuses_unknown_names_bad_values_and_the_pairing() {
        let cfg = DeviceConfig::default();
        for (key, value) in [
            ("policy.tools.sudo", "true"),
            ("policy.mood", "full"),
            ("policy.mode", "fully"),
            ("policy.approvals.timeout_secs", "0"),
            ("portal", "{}"),
            ("portal.url", "x"),
            ("policy.commands.deny", r#"[{"regex": "("}]"#),
        ] {
            assert!(
                edit(&cfg, key, Op::Set(parse_value(value)), 0).is_err(),
                "{key}"
            );
        }
        assert!(edit(&cfg, "policy.mode", Op::Add(parse_value("x")), 0).is_err());
    }

    #[test]
    fn computer_use_is_allowed_only_for_a_time() {
        let cfg = DeviceConfig::default();
        let key = "policy.computer_use.consent";
        assert!(edit(&cfg, key, Op::Set(parse_value("allow")), 0).is_err());
        assert!(
            edit(
                &cfg,
                "policy.computer_use.until_ms",
                Op::Set(parse_value("99999999999999")),
                0
            )
            .is_err()
        );
        let c = edit(&cfg, key, Op::Set(parse_value("ask")), 0).unwrap();
        assert_eq!(c.policy.computer_use.consent, Consent::Ask);
        let mut allowed = cfg.clone();
        allowed
            .policy
            .computer_use
            .set(Consent::Allow, Some(5), 0)
            .unwrap();
        let c = edit(&allowed, key, Op::Set(parse_value("off")), 0).unwrap();
        assert_eq!(c.policy.computer_use.until_ms, None);
        let c = edit(
            &cfg,
            "policy.computer_use.auto_update",
            Op::Set(parse_value("false")),
            0,
        )
        .unwrap();
        assert!(!c.policy.computer_use.auto_update);
        // The installed servers are the device's record, not a setting.
        assert!(edit(&cfg, "mcp", Op::Set(parse_value("{}")), 0).is_err());
    }

    #[test]
    fn token_storage_is_a_setting_of_its_own() {
        use sync_policy::config::TokenStorage;
        let cfg = DeviceConfig::default();
        assert_eq!(get(&cfg, Some("token_storage")).unwrap(), Value::Null);
        let c = edit(&cfg, "token_storage", Op::Set(parse_value("keyring")), 0).unwrap();
        assert_eq!(c.token_storage, Some(TokenStorage::Keyring));
        let c = edit(&c, "token_storage", Op::Unset, 0).unwrap();
        assert_eq!(c.token_storage, None);
        assert!(edit(&c, "token_storage", Op::Set(parse_value("wallet")), 0).is_err());
    }

    #[test]
    fn the_password_keyring_is_refused_on_windows() {
        let cfg = DeviceConfig::default();
        let key = "policy.privilege.secret_storage";
        let e = edit_on(&cfg, key, Op::Set(parse_value("keyring")), 0, true).unwrap_err();
        assert!(e.contains("Linux only"), "{e}");
        assert!(edit_on(&cfg, key, Op::Set(parse_value("file")), 0, true).is_ok());
        let c = edit_on(&cfg, key, Op::Set(parse_value("keyring")), 0, false).unwrap();
        assert_eq!(c.policy.privilege.secret_storage, SecretStorage::Keyring);
    }
}
