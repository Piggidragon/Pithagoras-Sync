//! The environment a server runs in: the desktop session it drives and nothing
//! else of the client's. On Linux that is the display, the session bus and the
//! runtime folder (which a client started by a systemd user unit may lack
//! when the desktop did not import them, so they are found from the runtime
//! folder), the locale and a fixed `PATH`; on Windows the variables a program
//! needs to run in the user's session. The server's own pins add theirs
//! (telemetry off). Kept apart from MCP, so a native screen capture can use
//! it too.

/// The variables passed on from the client's environment where present.
#[cfg(not(windows))]
const PASS: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LANGUAGE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP",
    "DESKTOP_SESSION",
    "DBUS_SESSION_BUS_ADDRESS",
    "AT_SPI_BUS_ADDRESS",
];

#[cfg(windows)]
const PASS: &[&str] = &[
    "SystemRoot",
    "windir",
    "SystemDrive",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "USERNAME",
    "USERDOMAIN",
    "APPDATA",
    "LOCALAPPDATA",
    "HOMEDRIVE",
    "HOMEPATH",
    "COMPUTERNAME",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "CommonProgramFiles",
];

/// The server's environment from the client's (`base`) and the pin's own
/// (`extra`, which wins). `uid` and `exists` find the runtime folder's
/// session bus and Wayland socket where the variables are missing.
pub fn environment(
    base: &[(String, String)],
    extra: &[(String, String)],
    uid: u32,
    exists: &dyn Fn(&str) -> bool,
) -> Vec<(String, String)> {
    let get = |k: &str| {
        base.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.clone())
    };
    let mut env: Vec<(String, String)> = PASS
        .iter()
        .filter_map(|k| get(k).map(|v| (k.to_string(), v)))
        .collect();
    let set = |env: &mut Vec<(String, String)>, k: &str, v: String| {
        env.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
        env.push((k.to_string(), v));
    };
    if cfg!(windows) {
        let root = get("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        set(
            &mut env,
            "PATH",
            format!(
                r"{root}\System32;{root};{root}\System32\Wbem;{root}\System32\WindowsPowerShell\v1.0"
            ),
        );
    } else {
        set(&mut env, "PATH", "/usr/local/bin:/usr/bin:/bin".into());
        let runtime = get("XDG_RUNTIME_DIR").unwrap_or_else(|| format!("/run/user/{uid}"));
        if get("XDG_RUNTIME_DIR").is_none() && exists(&runtime) {
            set(&mut env, "XDG_RUNTIME_DIR", runtime.clone());
        }
        if get("DBUS_SESSION_BUS_ADDRESS").is_none() && exists(&format!("{runtime}/bus")) {
            set(
                &mut env,
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={runtime}/bus"),
            );
        }
        if get("WAYLAND_DISPLAY").is_none() && get("DISPLAY").is_none() {
            if exists(&format!("{runtime}/wayland-0")) {
                set(&mut env, "WAYLAND_DISPLAY", "wayland-0".into());
            } else if exists("/tmp/.X11-unix/X0") {
                set(&mut env, "DISPLAY", ":0".into());
            }
        }
    }
    for (k, v) in extra {
        set(&mut env, k, v.clone());
    }
    env
}

/// `environment` from this process's environment and the real file system.
pub fn current(extra: &[(String, String)]) -> Vec<(String, String)> {
    let base: Vec<(String, String)> = std::env::vars().collect();
    #[cfg(unix)]
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    #[cfg(not(unix))]
    let uid = 0;
    environment(&base, extra, uid, &|p| std::path::Path::new(p).exists())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[cfg(not(windows))]
    #[test]
    fn the_session_passes_and_nothing_else() {
        let base = pairs(&[
            ("HOME", "/home/u"),
            ("WAYLAND_DISPLAY", "wayland-1"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("PORTAL_TOKEN", "secret"),
            ("LD_PRELOAD", "/tmp/x.so"),
            ("PATH", "/home/u/bin:/usr/bin"),
        ]);
        let env = environment(&base, &pairs(&[("NO_TELEMETRY", "1")]), 1000, &|_| false);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("WAYLAND_DISPLAY"), Some("wayland-1"));
        assert_eq!(get("PATH"), Some("/usr/local/bin:/usr/bin:/bin"));
        assert_eq!(get("NO_TELEMETRY"), Some("1"));
        assert_eq!(get("PORTAL_TOKEN"), None);
        assert_eq!(get("LD_PRELOAD"), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn a_unit_without_the_session_finds_it_in_the_runtime_folder() {
        let env = environment(&pairs(&[("HOME", "/h")]), &[], 1000, &|p| {
            matches!(
                p,
                "/run/user/1000" | "/run/user/1000/bus" | "/run/user/1000/wayland-0"
            )
        });
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("XDG_RUNTIME_DIR"), Some("/run/user/1000"));
        assert_eq!(
            get("DBUS_SESSION_BUS_ADDRESS"),
            Some("unix:path=/run/user/1000/bus")
        );
        assert_eq!(get("WAYLAND_DISPLAY"), Some("wayland-0"));
    }
}
