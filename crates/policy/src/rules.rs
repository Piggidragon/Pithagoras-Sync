//! The owner's finer rules on top of the mode: which tools are on, paths and globs
//! denied in every mode, glob grants for Folders mode, command lists and the hours
//! the device works. Each defaults to the side that allows nothing extra.
//!
//! Path rules are exact for the file tools (they judge the resolved path). For the
//! shell only Landlock enforces paths, and only plain paths, not globs. Command
//! rules see the command's text: a deny or always-ask rule catches accidents, not an
//! attacker who spells the command differently; an allow or never-ask rule only
//! matches a simple command (no `;`, `&`, `|`, redirects, substitutions or
//! newlines), so it cannot be stretched to cover a second command.

use std::fmt;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sync_proto::methods::{Access, PiTool};

use crate::paths::{resolve, within};
use crate::protected::{expand, fold};

/// The pi tools the device serves; each can be switched off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Tools {
    pub read: bool,
    pub write: bool,
    pub edit: bool,
    pub bash: bool,
    pub grep: bool,
    pub find: bool,
    pub ls: bool,
}

impl Default for Tools {
    fn default() -> Self {
        Tools {
            read: true,
            write: true,
            edit: true,
            bash: true,
            grep: true,
            find: true,
            ls: true,
        }
    }
}

impl Tools {
    pub fn enabled(&self, t: PiTool) -> bool {
        match t {
            PiTool::Read => self.read,
            PiTool::Write => self.write,
            PiTool::Edit => self.edit,
            PiTool::Bash => self.bash,
            PiTool::Grep => self.grep,
            PiTool::Find => self.find,
            PiTool::Ls => self.ls,
        }
    }

    pub fn set(&mut self, t: PiTool, on: bool) {
        match t {
            PiTool::Read => self.read = on,
            PiTool::Write => self.write = on,
            PiTool::Edit => self.edit = on,
            PiTool::Bash => self.bash = on,
            PiTool::Grep => self.grep = on,
            PiTool::Find => self.find = on,
            PiTool::Ls => self.ls = on,
        }
    }

    /// Why a call of `method` (labelled `label` by the portal) is refused, if it is.
    /// A method serves several pi tools (`fs.read` serves `read` and `edit`); the
    /// call passes when its label is one of them and on, or, unlabelled, when any
    /// of them is on.
    pub fn refusal(&self, method: &str, label: Option<PiTool>) -> Option<String> {
        let serves = method_tools(method);
        match label {
            Some(t) if !serves.contains(&t) => Some(format!(
                "the {} tool does not make {method} calls",
                t.name()
            )),
            Some(t) if !self.enabled(t) => {
                Some(format!("the {} tool is off on this device", t.name()))
            }
            Some(_) => None,
            None if serves.iter().any(|t| self.enabled(*t)) => None,
            None => Some(format!(
                "the tools that make {method} calls are off on this device"
            )),
        }
    }
}

/// The pi tools a method serves. Unknown methods serve none, so they are refused.
pub fn method_tools(method: &str) -> &'static [PiTool] {
    use PiTool::*;
    match method {
        "stat" => &[Read, Write, Edit, Grep, Find, Ls],
        "ls" => &[Ls],
        "read" => &[Read, Edit],
        "write" => &[Write, Edit],
        "grep" => &[Grep],
        "find" => &[Find],
        "exec" => &[Bash],
        _ => &[],
    }
}

/// Read, write and execute rights, written `rwx` (any non-empty subset, in order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rights {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Rights {
    pub const ALL: Rights = Rights {
        read: true,
        write: true,
        execute: true,
    };
    pub const READ: Rights = Rights {
        read: true,
        write: false,
        execute: false,
    };
    pub const WRITE: Rights = Rights {
        read: false,
        write: true,
        execute: false,
    };
    pub const EXECUTE: Rights = Rights {
        read: false,
        write: false,
        execute: true,
    };

    fn all() -> Rights {
        Rights::ALL
    }

    /// Whether these rights share any right with `other`.
    pub fn overlaps(self, other: Rights) -> bool {
        (self.read && other.read) || (self.write && other.write) || (self.execute && other.execute)
    }
}

impl std::str::FromStr for Rights {
    type Err = String;

    fn from_str(s: &str) -> Result<Rights, String> {
        let bad = || format!("rights {s:?}: use a non-empty subset of rwx, in that order");
        let mut r = Rights {
            read: false,
            write: false,
            execute: false,
        };
        let mut rest = s;
        for (c, flag) in [
            ('r', &mut r.read),
            ('w', &mut r.write),
            ('x', &mut r.execute),
        ] {
            if let Some(t) = rest.strip_prefix(c) {
                *flag = true;
                rest = t;
            }
        }
        if !rest.is_empty() || s.is_empty() {
            return Err(bad());
        }
        Ok(r)
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (c, on) in [('r', self.read), ('w', self.write), ('x', self.execute)] {
            if on {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

impl Serialize for Rights {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Rights {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Rights, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A path (and everything below it) or a glob the device refuses, in every mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyRule {
    /// Absolute or `~/...`. With `*`, `?`, `[` or `{` it is a glob (`**` crosses
    /// folders), which only the file tools can enforce.
    pub path: String,
    #[serde(default = "Rights::all")]
    pub rights: Rights,
}

/// A glob the file tools may reach in Folders mode, outside the granted folders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobGrant {
    /// Absolute or `~/...`, matched against the resolved path (`**` crosses folders).
    pub glob: String,
    pub access: Access,
}

/// One command rule: exactly one of the four kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CommandRule {
    /// The whole command, spaces between words normalised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    /// The command starts with this text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// A shell-style glob over the whole command (`*` matches anything).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<String>,
    /// A regular expression searched in the command (anchor it with `^...$`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
}

impl fmt::Display for CommandRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.exact, &self.prefix, &self.glob, &self.regex) {
            (Some(s), ..) => write!(f, "exact {s:?}"),
            (_, Some(s), ..) => write!(f, "prefix {s:?}"),
            (_, _, Some(s), _) => write!(f, "glob {s:?}"),
            (.., Some(s)) => write!(f, "regex {s:?}"),
            _ => write!(f, "empty rule"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Commands {
    /// When not empty, only simple commands matching one of these run at all.
    pub allow: Vec<CommandRule>,
    /// Commands containing a match are refused.
    pub deny: Vec<CommandRule>,
    /// Commands containing a match ask the owner, in every mode.
    pub always_ask: Vec<CommandRule>,
    /// Simple commands matching one of these skip the mode's and the patterns'
    /// questions (not the taint question, not deny rules, not Folders' limits).
    pub never_ask: Vec<CommandRule>,
}

/// The hours the device serves calls; outside them every call is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hours {
    /// `mon` ... `sun`; empty means every day. A range past midnight counts for the
    /// day it starts on.
    #[serde(default)]
    pub days: Vec<String>,
    /// `HH:MM`, local time.
    pub from: String,
    /// `HH:MM`, exclusive; earlier than `from` runs past midnight.
    pub to: String,
    /// A fixed offset from UTC in minutes instead of the system's time zone.
    #[serde(default)]
    pub utc_offset_minutes: Option<i32>,
}

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn parse_hhmm(s: &str) -> Result<u32, String> {
    let bad = || format!("time {s:?}: use HH:MM");
    let (h, m) = s.split_once(':').ok_or_else(bad)?;
    let (h, m): (u32, u32) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if h > 24 || m > 59 || (h == 24 && m != 0) || s.len() != 5 {
        return Err(bad());
    }
    Ok(h * 60 + m)
}

impl Hours {
    pub fn validate(&self) -> Result<(), String> {
        for d in &self.days {
            if !DAYS.contains(&d.as_str()) {
                return Err(format!(
                    "day {d:?}: use mon, tue, wed, thu, fri, sat or sun"
                ));
            }
        }
        if parse_hhmm(&self.from)? == parse_hhmm(&self.to)? {
            return Err("hours: from and to are the same time".into());
        }
        if let Some(o) = self.utc_offset_minutes
            && o.abs() > 14 * 60
        {
            return Err("hours: utc_offset_minutes must be within 14 hours".into());
        }
        Ok(())
    }

    /// Whether `now_ms` (Unix ms) falls in the hours.
    pub fn allows(&self, now_ms: i64) -> bool {
        let (Ok(from), Ok(to)) = (parse_hhmm(&self.from), parse_hhmm(&self.to)) else {
            return false;
        };
        let offset = match self.utc_offset_minutes {
            Some(m) => i64::from(m) * 60_000,
            None => local_offset_ms(now_ms),
        };
        let local = now_ms + offset;
        let day = local.div_euclid(86_400_000);
        let minute = (local.rem_euclid(86_400_000) / 60_000) as u32;
        // 1970-01-01 was a Thursday: index 3 from Monday.
        let weekday = |d: i64| DAYS[(d + 3).rem_euclid(7) as usize];
        let day_ok = |d: i64| self.days.is_empty() || self.days.iter().any(|x| x == weekday(d));
        if from < to {
            day_ok(day) && minute >= from && minute < to
        } else {
            (day_ok(day) && minute >= from) || (day_ok(day - 1) && minute < to)
        }
    }
}

/// The system time zone's offset from UTC at `now_ms`.
#[cfg(unix)]
fn local_offset_ms(now_ms: i64) -> i64 {
    // Typed by localtime_r: naming libc's time_t is deprecated on musl.
    let t = (now_ms / 1000) as _;
    // SAFETY: localtime_r writes into the zeroed tm we own.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return 0;
    }
    tm.tm_gmtoff * 1000
}

#[cfg(windows)]
fn local_offset_ms(now_ms: i64) -> i64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::Storage::FileSystem::FileTimeToLocalFileTime;
    // FILETIME counts 100 ns from 1601; Unix time starts 11644473600 s later.
    let ticks = (now_ms + 11_644_473_600_000) * 10_000;
    let utc = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut local = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: both structs are ours and valid.
    if unsafe { FileTimeToLocalFileTime(&utc, &mut local) } == 0 {
        return 0;
    }
    let l = (i64::from(local.dwHighDateTime) << 32) | i64::from(local.dwLowDateTime);
    (l - ticks) / 10_000
}

fn is_glob(s: &str) -> bool {
    s.contains(['*', '?', '[', '{'])
}

fn path_glob(home: &Path, s: &str) -> Result<GlobMatcher, String> {
    let expanded = expand(home, s).ok_or_else(|| format!("{s}: not absolute or ~/..."))?;
    let text = fold(&expanded).to_string_lossy().replace('\\', "/");
    GlobBuilder::new(&text)
        .literal_separator(true)
        .backslash_escape(false)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| format!("{s}: {e}"))
}

fn command_glob(s: &str) -> Result<GlobMatcher, String> {
    GlobBuilder::new(s)
        .literal_separator(false)
        .backslash_escape(false)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| format!("glob {s:?}: {e}"))
}

enum PathMatch {
    /// The path as written and resolved, each also folded for matching.
    Below {
        real: Vec<PathBuf>,
        folded: Vec<PathBuf>,
    },
    Glob(GlobMatcher),
}

impl PathMatch {
    fn new(home: &Path, s: &str) -> Result<PathMatch, String> {
        if is_glob(s) {
            return path_glob(home, s).map(PathMatch::Glob);
        }
        let p = expand(home, s).ok_or_else(|| format!("{s}: not absolute or ~/..."))?;
        let mut real = vec![p.clone()];
        if let Ok(r) = resolve(&p) {
            real.push(r);
        }
        real.dedup();
        let mut folded: Vec<PathBuf> = real.iter().map(|p| fold(p)).collect();
        folded.dedup();
        Ok(PathMatch::Below { real, folded })
    }

    fn matches(&self, folded: &Path) -> bool {
        match self {
            PathMatch::Below { folded: ps, .. } => ps.iter().any(|p| within(folded, p)),
            PathMatch::Glob(g) => g.is_match(folded.to_string_lossy().replace('\\', "/")),
        }
    }
}

enum CmdMatch {
    Exact(String),
    Prefix(String),
    Glob(GlobMatcher),
    Regex(Regex),
}

impl CmdMatch {
    fn new(r: &CommandRule) -> Result<CmdMatch, String> {
        match (&r.exact, &r.prefix, &r.glob, &r.regex) {
            (Some(s), None, None, None) => Ok(CmdMatch::Exact(normalise(s))),
            (None, Some(s), None, None) if !s.trim().is_empty() => {
                // Kept as written: a trailing space (`rm `) marks the end of a word.
                Ok(CmdMatch::Prefix(s.trim_start().to_string()))
            }
            (None, None, Some(s), None) => command_glob(s).map(CmdMatch::Glob),
            (None, None, None, Some(s)) => Regex::new(s)
                .map(CmdMatch::Regex)
                .map_err(|e| format!("regex {s:?}: {e}")),
            _ => Err(format!(
                "command rule {r}: give exactly one of exact, prefix, glob or regex, not empty"
            )),
        }
    }

    fn matches(&self, cmd: &str) -> bool {
        match self {
            CmdMatch::Exact(s) => cmd == s,
            CmdMatch::Prefix(s) => cmd.starts_with(s.as_str()),
            CmdMatch::Glob(g) => g.is_match(cmd),
            CmdMatch::Regex(r) => r.is_match(cmd),
        }
    }
}

/// Whitespace runs to single spaces, trimmed.
fn normalise(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A command with no way to run a second one or touch files by redirection.
pub fn simple_command(cmd: &str) -> bool {
    !cmd.contains([
        ';', '&', '|', '`', '$', '<', '>', '(', ')', '\n', '\r', '\\',
    ])
}

/// The pieces of a command a deny or always-ask rule is checked against: the whole
/// command, and each part between separators from every word on, so that
/// `sudo -u x rm ...` or `env A=1 rm ...` still meet a rule about `rm`.
fn pieces(cmd: &str) -> Vec<String> {
    let mut out = vec![normalise(cmd)];
    for part in cmd.split([';', '&', '|', '`', '(', ')', '\n', '\r', '{', '}']) {
        let words: Vec<&str> = part.split_whitespace().collect();
        for i in 0..words.len() {
            out.push(words[i..].join(" ").trim_start_matches('$').to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The rules of a policy, compiled.
pub struct Compiled {
    deny: Vec<(DenyRule, PathMatch)>,
    glob_grants: Vec<(GlobGrant, GlobMatcher)>,
    allow: Vec<(CommandRule, CmdMatch)>,
    deny_cmd: Vec<(CommandRule, CmdMatch)>,
    always_ask: Vec<(CommandRule, CmdMatch)>,
    never_ask: Vec<(CommandRule, CmdMatch)>,
    hours: Option<Hours>,
}

impl Compiled {
    pub fn new(
        home: &Path,
        deny: &[DenyRule],
        glob_grants: &[GlobGrant],
        commands: &Commands,
        hours: Option<&Hours>,
    ) -> Result<Compiled, String> {
        let cmds = |rules: &[CommandRule]| -> Result<Vec<(CommandRule, CmdMatch)>, String> {
            rules
                .iter()
                .map(|r| Ok((r.clone(), CmdMatch::new(r)?)))
                .collect()
        };
        if let Some(h) = hours {
            h.validate()?;
        }
        Ok(Compiled {
            deny: deny
                .iter()
                .map(|r| Ok((r.clone(), PathMatch::new(home, &r.path)?)))
                .collect::<Result<_, String>>()?,
            glob_grants: glob_grants
                .iter()
                .map(|g| Ok((g.clone(), path_glob(home, &g.glob)?)))
                .collect::<Result<_, String>>()?,
            allow: cmds(&commands.allow)?,
            deny_cmd: cmds(&commands.deny)?,
            always_ask: cmds(&commands.always_ask)?,
            never_ask: cmds(&commands.never_ask)?,
            hours: hours.cloned(),
        })
    }

    /// The deny rule that refuses `right` on `path` (resolved), if one does.
    pub fn denied(&self, path: &Path, right: Rights) -> Option<&DenyRule> {
        let folded = fold(path);
        self.deny
            .iter()
            .find(|(r, m)| r.rights.overlaps(right) && m.matches(&folded))
            .map(|(r, _)| r)
    }

    /// Plain-path deny rules (as written and resolved, not folded) with their
    /// rights, for Landlock; globs are left to the file tools.
    pub fn denied_paths(&self) -> Vec<(PathBuf, Rights)> {
        let mut out = Vec::new();
        for (r, m) in &self.deny {
            if let PathMatch::Below { real: ps, .. } = m {
                for p in ps {
                    out.push((p.clone(), r.rights));
                }
            }
        }
        out
    }

    /// The glob grant holding `path` (resolved); a read-write one wins.
    pub fn glob_grant(&self, path: &Path) -> Option<&GlobGrant> {
        let s = fold(path).to_string_lossy().replace('\\', "/");
        let mut hits = self
            .glob_grants
            .iter()
            .filter(|(_, m)| m.is_match(&s))
            .map(|(g, _)| g);
        let first = hits.next()?;
        Some(
            std::iter::once(first)
                .chain(hits)
                .find(|g| g.access == Access::Rw)
                .unwrap_or(first),
        )
    }

    pub fn has_glob_grants(&self) -> bool {
        !self.glob_grants.is_empty()
    }

    /// Why `cmd` is refused by the command lists, if it is.
    pub fn command_refusal(&self, cmd: &str) -> Option<String> {
        let ps = pieces(cmd);
        if let Some((r, _)) = self
            .deny_cmd
            .iter()
            .find(|(_, m)| ps.iter().any(|p| m.matches(p)))
        {
            return Some(format!("the command matches the deny rule {r}"));
        }
        if !self.allow.is_empty() {
            let whole = normalise(cmd);
            if !simple_command(cmd) {
                return Some(
                    "only simple commands run on this device (it has an allow list), and this one has separators, redirects or substitutions".into(),
                );
            }
            if !self.allow.iter().any(|(_, m)| m.matches(&whole)) {
                return Some("the command is not on this device's allow list".into());
            }
        }
        None
    }

    /// Whether `cmd` is a simple command on the never-ask list.
    pub fn never_ask(&self, cmd: &str) -> bool {
        simple_command(cmd) && {
            let whole = normalise(cmd);
            self.never_ask.iter().any(|(_, m)| m.matches(&whole))
        }
    }

    /// The always-ask rule `cmd` matches, if any.
    pub fn always_ask(&self, cmd: &str) -> Option<&CommandRule> {
        let ps = pieces(cmd);
        self.always_ask
            .iter()
            .find(|(_, m)| ps.iter().any(|p| m.matches(p)))
            .map(|(r, _)| r)
    }

    pub fn within_hours(&self, now_ms: i64) -> bool {
        self.hours.as_ref().is_none_or(|h| h.allows(now_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: &str, s: &str) -> CommandRule {
        let mut r = CommandRule::default();
        match kind {
            "exact" => r.exact = Some(s.into()),
            "prefix" => r.prefix = Some(s.into()),
            "glob" => r.glob = Some(s.into()),
            _ => r.regex = Some(s.into()),
        }
        r
    }

    fn compiled(commands: Commands) -> Compiled {
        Compiled::new(Path::new("/home/u"), &[], &[], &commands, None).unwrap()
    }

    #[test]
    fn rights_parse_and_print() {
        assert_eq!("rwx".parse::<Rights>().unwrap(), Rights::ALL);
        assert_eq!("w".parse::<Rights>().unwrap(), Rights::WRITE);
        assert_eq!("rx".parse::<Rights>().unwrap().to_string(), "rx");
        for bad in ["", "xr", "rr", "a", "rwxx"] {
            assert!(bad.parse::<Rights>().is_err(), "{bad}");
        }
    }

    #[test]
    fn a_command_rule_needs_exactly_one_kind() {
        assert!(CmdMatch::new(&CommandRule::default()).is_err());
        let mut two = rule("exact", "ls");
        two.prefix = Some("ls".into());
        assert!(CmdMatch::new(&two).is_err());
        assert!(CmdMatch::new(&rule("regex", "(")).is_err());
        assert!(CmdMatch::new(&rule("prefix", " ")).is_err());
    }

    #[test]
    fn deny_rules_match_anywhere_in_the_command() {
        let c = compiled(Commands {
            deny: vec![rule("prefix", "rm "), rule("regex", r"\bshutdown\b")],
            ..Default::default()
        });
        for cmd in [
            "rm -rf x",
            "ls; rm x",
            "true && sudo rm x",
            "echo $(rm x)",
            "env A=1 rm x",
            "/usr/bin/sudo -u root rm x",
            "systemctl poweroff || shutdown now",
        ] {
            assert!(c.command_refusal(cmd).is_some(), "{cmd}");
        }
        assert!(c.command_refusal("ls -la").is_none());
        assert!(c.command_refusal("echo rm").is_none());
    }

    #[test]
    fn an_allow_list_takes_simple_matching_commands_only() {
        let c = compiled(Commands {
            allow: vec![rule("exact", "git status"), rule("glob", "cargo *")],
            ..Default::default()
        });
        assert!(c.command_refusal("git   status").is_none());
        assert!(c.command_refusal("cargo build --release").is_none());
        for cmd in [
            "git status; rm -rf ~",
            "cargo build && curl x",
            "cargo build > /etc/x",
            "cargo $(rm x)",
            "cargo build\nrm x",
            "ls",
        ] {
            assert!(c.command_refusal(cmd).is_some(), "{cmd}");
        }
    }

    #[test]
    fn never_ask_only_covers_simple_commands() {
        let c = compiled(Commands {
            never_ask: vec![rule("prefix", "cargo test")],
            always_ask: vec![rule("prefix", "git push")],
            ..Default::default()
        });
        assert!(c.never_ask("cargo test -p x"));
        assert!(!c.never_ask("cargo test; rm -rf ~"));
        assert!(c.always_ask("ls && git push origin").is_some());
        assert!(c.always_ask("git status").is_none());
    }

    // Linux paths; the Windows form is the test below.
    #[cfg(unix)]
    #[test]
    fn deny_paths_and_globs() {
        let c = Compiled::new(
            Path::new("/home/u"),
            &[
                DenyRule {
                    path: "~/secret".into(),
                    rights: Rights::ALL,
                },
                DenyRule {
                    path: "/srv/**/*.key".into(),
                    rights: Rights::READ,
                },
                DenyRule {
                    path: "/srv/ro".into(),
                    rights: Rights::WRITE,
                },
            ],
            &[],
            &Commands::default(),
            None,
        )
        .unwrap();
        assert!(
            c.denied(Path::new("/home/u/secret/a"), Rights::READ)
                .is_some()
        );
        assert!(
            c.denied(Path::new("/home/u/SECRET"), Rights::EXECUTE)
                .is_some()
        );
        assert!(
            c.denied(Path::new("/home/u/secrets"), Rights::READ)
                .is_none()
        );
        assert!(
            c.denied(Path::new("/srv/a/b/x.key"), Rights::READ)
                .is_some()
        );
        assert!(
            c.denied(Path::new("/srv/a/b/x.key"), Rights::WRITE)
                .is_none()
        );
        assert!(c.denied(Path::new("/srv/ro/f"), Rights::WRITE).is_some());
        assert!(c.denied(Path::new("/srv/ro/f"), Rights::READ).is_none());
        let paths = c.denied_paths();
        assert!(paths.iter().any(|(p, _)| p == Path::new("/home/u/secret")));
        assert!(!paths.iter().any(|(p, _)| p.to_string_lossy().contains('*')));
    }

    #[cfg(windows)]
    #[test]
    fn deny_paths_and_globs_on_windows() {
        let c = Compiled::new(
            Path::new(r"C:\Users\u"),
            &[
                DenyRule {
                    path: "~/secret".into(),
                    rights: Rights::ALL,
                },
                DenyRule {
                    path: "C:/srv/**/*.key".into(),
                    rights: Rights::READ,
                },
                DenyRule {
                    path: r"D:\ro".into(),
                    rights: Rights::WRITE,
                },
            ],
            &[GlobGrant {
                glob: "~/notes/*.md".into(),
                access: Access::Ro,
            }],
            &Commands::default(),
            None,
        )
        .unwrap();
        let denied = |p: &str, r| c.denied(Path::new(p), r).is_some();
        assert!(denied(r"C:\Users\U\Secret\a", Rights::READ));
        assert!(!denied(r"C:\Users\u\secrets", Rights::READ));
        assert!(denied(r"c:\SRV\a\b\X.KEY", Rights::READ));
        assert!(!denied(r"C:\srv\a\b\x.key", Rights::WRITE));
        assert!(denied(r"d:\RO\f", Rights::WRITE));
        assert!(!denied(r"D:\rofl", Rights::WRITE));
        assert!(c.glob_grant(Path::new(r"C:\Users\U\Notes\A.md")).is_some());
        assert!(
            c.glob_grant(Path::new(r"C:\Users\u\notes\sub\a.md"))
                .is_none()
        );
    }

    #[test]
    fn glob_grants_stay_in_one_folder_level_per_star() {
        let c = Compiled::new(
            Path::new("/home/u"),
            &[],
            &[GlobGrant {
                glob: "~/notes/*.md".into(),
                access: Access::Ro,
            }],
            &Commands::default(),
            None,
        )
        .unwrap();
        assert!(c.glob_grant(Path::new("/home/u/notes/a.md")).is_some());
        assert!(c.glob_grant(Path::new("/home/u/notes/sub/a.md")).is_none());
        assert!(c.glob_grant(Path::new("/home/u/notes/a.txt")).is_none());
    }

    #[test]
    fn hours_by_day_and_past_midnight() {
        // 2026-10-05 is a Monday; 10:00 UTC.
        let monday_10 = 1_791_194_400_000;
        let h = |days: &[&str], from: &str, to: &str| Hours {
            days: days.iter().map(|d| d.to_string()).collect(),
            from: from.into(),
            to: to.into(),
            utc_offset_minutes: Some(0),
        };
        assert!(h(&[], "09:00", "17:00").allows(monday_10));
        assert!(!h(&[], "11:00", "17:00").allows(monday_10));
        assert!(h(&["mon"], "09:00", "17:00").allows(monday_10));
        assert!(!h(&["tue"], "09:00", "17:00").allows(monday_10));
        // 22:00-06:00 started on Sunday covers Monday 03:00, not Monday 10:00.
        let monday_3 = monday_10 - 7 * 3_600_000;
        assert!(h(&["sun"], "22:00", "06:00").allows(monday_3));
        assert!(!h(&["mon"], "22:00", "06:00").allows(monday_3));
        assert!(!h(&["sun"], "22:00", "06:00").allows(monday_10));
        // The offset moves the clock: UTC+2 makes it 12:00.
        let mut plus2 = h(&[], "11:30", "12:30");
        plus2.utc_offset_minutes = Some(120);
        assert!(plus2.allows(monday_10));
        assert!(h(&[], "08:00", "07:00").validate().is_ok());
        assert!(h(&[], "08:00", "08:00").validate().is_err());
        assert!(h(&["monday"], "08:00", "09:00").validate().is_err());
        assert!(h(&[], "8:00", "09:00").validate().is_err());
    }
}
