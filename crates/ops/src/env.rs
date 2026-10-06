//! The environment a command gets: the device's own, scrubbed to an allow-list.
//!
//! pi hands its bash operations the portal's `process.env` (with `PORTAL_SECRET` and
//! provider keys); `exec.start` carries no environment at all, and the device builds
//! one from its own variables. `PORTAL_*` never passes, even when the owner lists it.
//! The session bus (`DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`) and the ssh agent
//! are left out by default: through them a command could act outside its confinement.

#[cfg(not(windows))]
const ALLOWED: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LANGUAGE",
    "TZ",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_DATA_DIRS",
    "XDG_CONFIG_DIRS",
];

#[cfg(windows)]
const ALLOWED: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SystemDrive",
    "windir",
    "ComSpec",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
    "PSModulePath",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
];

fn forbidden(name: &str) -> bool {
    name.to_ascii_uppercase().starts_with("PORTAL_")
}

/// Builds a command's environment from `base` (the client's own variables).
pub fn scrubbed(base: &[(String, String)], passthrough: &[String]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = base
        .iter()
        .filter(|(k, _)| !forbidden(k))
        .filter(|(k, _)| {
            let same = |a: &str| {
                if cfg!(windows) {
                    a.eq_ignore_ascii_case(k)
                } else {
                    a == k
                }
            };
            ALLOWED.iter().any(|a| same(a))
                || k.starts_with("LC_")
                || passthrough.iter().any(|p| same(p))
        })
        .cloned()
        .collect();
    out.retain(|(k, _)| k != "TERM");
    out.push(("TERM".into(), "dumb".into()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_portal_variables_and_secrets() {
        let base: Vec<(String, String)> = [
            ("PATH", "/usr/bin"),
            ("HOME", "/home/u"),
            ("PORTAL_SECRET", "s"),
            ("portal_x", "s"),
            ("OPENAI_API_KEY", "k"),
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1/bus"),
            ("LC_ALL", "C"),
            ("TERM", "xterm"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let env = scrubbed(&base, &["PORTAL_SECRET".into(), "OPENAI_API_KEY".into()]);
        let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"PATH"));
        assert!(names.contains(&"LC_ALL"));
        assert!(
            names.contains(&"OPENAI_API_KEY"),
            "the owner passed it through"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.to_uppercase().starts_with("PORTAL_"))
        );
        assert!(!names.contains(&"DBUS_SESSION_BUS_ADDRESS"));
        assert!(env.contains(&("TERM".into(), "dumb".into())));
    }
}
