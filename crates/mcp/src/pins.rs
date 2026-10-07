//! The pins: which MCP server, in which exact version, from which files with
//! which sha256, run how, and which of its tools the portal may call. One
//! table entry per server (`ServerPin`), no code per server.
//!
//! The pins come from two places only: the baseline compiled into the client
//! (`pins/baseline.json`), and a newer document the owner signs with the
//! release key (`mcp.json` and `mcp.json.minisig`, docs/mcp-pins.md). A signed
//! document is taken whole or not at all: one that does not verify, is older
//! than one taken before, names an unknown field or a download host off the
//! list is ignored with a note. Whatever a document allows, the hard deny-list
//! in this file wins.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Where the client looks for a newer signed pins document. The signature, not
/// the host, is the trust.
pub const PINS_URL: &str =
    "https://raw.githubusercontent.com/Piggidragon/Pithagoras-Sync/main/mcp/mcp.json";

/// Set (debug builds only) to another pins URL or a local file: the tests'
/// document. A release build ignores it.
pub const TEST_PINS_URL: &str = "PITHAGORAS_SYNC_TEST_MCP_PINS";

/// `PINS_URL`, or in a debug build the tests' document.
pub fn pins_url() -> String {
    #[cfg(debug_assertions)]
    if let Ok(u) = std::env::var(TEST_PINS_URL)
        && !u.is_empty()
    {
        return u;
    }
    PINS_URL.to_string()
}

/// The hosts a document may name for downloads; subdomains of
/// `githubusercontent.com` too (release assets redirect there).
pub const DOWNLOAD_HOSTS: &[&str] = &[
    "github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "www.python.org",
];

/// The baseline marks a value it does not know yet with this; such a server
/// cannot be installed until a signed document pins it.
pub const TODO_PIN: &str = "TODO-PIN";

/// Most bytes of a pins document.
pub const MAX_DOCUMENT: usize = 256 * 1024;
/// Most bytes of one pinned file.
pub const MAX_FILE: u64 = 512 << 20;

/// Tool names no document can allow, compared after `normalized`: whatever
/// installs or reconfigures, acts beyond pointer and keys on Linux
/// (`perform_action`, `set_value`), or on Windows starts programs, runs a
/// shell, reaches files, the registry, processes or the clipboard, or reads
/// pages (`App`, `Shortcut`, `Clipboard`, `Scrape`, `MultiEdit`, PowerShell,
/// FileSystem, Registry, Process).
pub const HARD_DENY: &[&str] = &[
    "setupwindowtargeting",
    "performaction",
    "setvalue",
    "app",
    "launch",
    "shortcut",
    "clipboard",
    "scrape",
    "multiedit",
    "powershell",
    "shell",
    "filesystem",
    "file",
    "files",
    "registry",
    "process",
    "processes",
    "run",
    "exec",
    "execute",
    "command",
    "terminal",
    "install",
    "setup",
];

/// Parts of a name that deny it wherever they stand.
pub const HARD_DENY_PARTS: &[&str] = &[
    "powershell",
    "shell",
    "registry",
    "clipboard",
    "filesystem",
    "process",
    "install",
    "setup",
    "exec",
    "command",
    "scrape",
    "launch",
];

/// A tool name as the deny-list compares it: lowercase, without `-`, `_` and
/// spaces, and without a trailing `tool` (`Powershell-Tool` is `powershell`).
pub fn normalized(name: &str) -> String {
    let n: String = name
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | ' ' | '.'))
        .flat_map(char::to_lowercase)
        .collect();
    match n.strip_suffix("tool") {
        Some(rest) if !rest.is_empty() => rest.to_string(),
        _ => n,
    }
}

/// Whether the hard deny-list forbids `name`, whatever a document says.
pub fn hard_denied(name: &str) -> bool {
    let n = normalized(name);
    HARD_DENY.contains(&n.as_str()) || HARD_DENY_PARTS.iter().any(|p| n.contains(p))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    /// Only ever grows; the client refuses a document with a lower one than it
    /// took before.
    pub serial: u64,
    /// When the owner's tool made it (Unix ms).
    pub issued_ms: i64,
    pub servers: Vec<ServerPin>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    /// A program, written 0755.
    Executable,
    /// Any other file, 0644.
    File,
    /// A zip file unpacked into `path` (the embeddable Python).
    Zip,
    /// A Python wheel unpacked into `path` (site-packages); its `.data`
    /// folders' `purelib` and `platlib` go there too, the rest is left out.
    Wheel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinFile {
    /// For this architecture only (`x86_64`, `aarch64`); absent: every one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    pub kind: FileKind,
    /// Where it goes in the version's folder (`/`-separated).
    pub path: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

/// A small text file the install writes itself (Python's `._pth`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextFile {
    pub path: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    /// The program, in the version's folder.
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Added to the clean environment the server gets (telemetry off, say).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// A call of one of the server's tools, made by the device itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub tool: String,
    #[serde(default)]
    pub args: Map<String, Value>,
}

/// The tools of the focus check: the window list, and where the server has
/// one of its own, the focused window. Not listed to the portal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Focus {
    pub windows: ToolCall,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focused: Option<ToolCall>,
}

/// The pointer step of `computer-use test`: read the position, move it.
/// `"$x"` and `"$y"` in `move_to`'s arguments are replaced by numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pointer {
    pub position: ToolCall,
    pub move_to: ToolCall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfTest {
    pub screenshot: ToolCall,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<Pointer>,
    /// Python modules the server imports, checked with the server's own Python
    /// at install (`-c "import ..."`), so a missing one fails the install by
    /// name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<String>,
}

/// A command a setup step can check or run, as argv. The program is absolute,
/// or `{dir}/...` for one in the version's folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub argv: Vec<String>,
    /// What its output (trimmed) must be for the step to count as done.
    pub expect: String,
}

/// One step of `computer-use setup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupStep {
    pub id: String,
    pub title: String,
    pub text: String,
    /// `gnome`, `kde` or absent for every desktop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<Check>,
    /// What the step would change, run only after the owner's yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPin {
    pub name: String,
    /// `linux` or `windows`.
    pub platform: String,
    pub version: String,
    pub files: Vec<PinFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<TextFile>,
    pub run: Run,
    /// The tools the portal may call, exact names of this version.
    pub allow: Vec<String>,
    /// Which of them only look (screenshots, the window list): every other
    /// allowed tool counts as input, and the focus check runs before it.
    #[serde(default)]
    pub observe: Vec<String>,
    pub focus: Focus,
    pub selftest: SelfTest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub setup: Vec<SetupStep>,
}

impl ServerPin {
    /// The files for `arch`.
    pub fn files_for<'a>(&'a self, arch: &'a str) -> impl Iterator<Item = &'a PinFile> + 'a {
        self.files
            .iter()
            .filter(move |f| f.arch.as_deref().is_none_or(|a| a == arch))
    }

    /// The allow-list in force: the document's, minus the hard deny-list.
    pub fn allowed(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .allow
            .iter()
            .filter(|t| !hard_denied(t))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Whether the focus check runs before `tool`: for every tool the pin
    /// does not name as one that only looks.
    pub fn is_input(&self, tool: &str) -> bool {
        !self.observe.iter().any(|t| t == tool)
    }

    /// What is not pinned yet for `arch` (`TODO-PIN`), if anything: such a
    /// server cannot be installed.
    pub fn unpinned(&self, arch: &str) -> Option<String> {
        let mut files = self.files_for(arch).peekable();
        if files.peek().is_none() {
            return Some(format!("no files for {arch}"));
        }
        files
            .find(|f| f.sha256 == TODO_PIN || f.url.contains(TODO_PIN))
            .map(|f| format!("{} has no pinned hash yet ({TODO_PIN})", f.path))
            .or_else(|| {
                (self.version.contains(TODO_PIN))
                    .then(|| format!("no version pinned yet ({TODO_PIN})"))
            })
    }
}

fn plain_name(s: &str, what: &str) -> Result<(), String> {
    if s.is_empty()
        || s.len() > 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!("{what} {s:?}: 1 to 64 of a-z, 0-9 and -"));
    }
    Ok(())
}

fn version_ok(v: &str) -> Result<(), String> {
    if v.is_empty()
        || v.len() > 64
        || v.starts_with('.')
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
    {
        return Err(format!(
            "version {v:?}: letters, digits, . - + _ (and a folder name)"
        ));
    }
    Ok(())
}

fn tool_name_ok(t: &str) -> Result<(), String> {
    if t.is_empty()
        || t.len() > sync_proto::methods::MAX_MCP_NAME
        || t.chars().any(char::is_control)
    {
        return Err(format!(
            "tool name {t:?}: 1 to 64 bytes, no control characters"
        ));
    }
    Ok(())
}

/// The host of an `https://` URL, or of an `http://` one on loopback (debug
/// builds only: the tests' local server).
fn url_host(url: &str) -> Result<String, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("{url:?} is not a URL"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err(format!("{url:?}: no user info"));
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or("").to_string(),
        None => authority
            .split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase(),
    };
    match scheme {
        "https" => Ok(host),
        "http" if cfg!(debug_assertions) && is_loopback(&host) => Ok(host),
        _ => Err(format!("{url:?}: downloads are https only")),
    }
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

/// Whether a download may come from (or be redirected to) `url`: https to a
/// host on `DOWNLOAD_HOSTS` (or below `githubusercontent.com`); in debug builds
/// also plain http on loopback, for the tests.
pub fn download_allowed(url: &str) -> Result<(), String> {
    let host = url_host(url)?;
    if DOWNLOAD_HOSTS.contains(&host.as_str())
        || host.ends_with(".githubusercontent.com")
        || (cfg!(debug_assertions) && is_loopback(&host))
    {
        Ok(())
    } else {
        Err(format!(
            "{url:?}: downloads come only from {} and *.githubusercontent.com",
            DOWNLOAD_HOSTS.join(", ")
        ))
    }
}

/// Whether `path` is a relative, `/`-separated path that stays in its folder.
fn rel_path_ok(path: &str) -> Result<(), String> {
    crate::unzip::safe_name(path)
        .map_err(|_| format!("path {path:?} must stay inside the server's folder"))
}

/// Environment variables a pin may set besides a `..._TELEMETRY` switch: what
/// keeps a server quiet and its text UTF-8, nothing that changes what it
/// loads or runs.
const PIN_ENV: &[&str] = &[
    "DO_NOT_TRACK",
    "NO_COLOR",
    "PYTHONUTF8",
    "PYTHONIOENCODING",
    "PYTHONUNBUFFERED",
];

fn env_name_ok(k: &str) -> Result<(), String> {
    let telemetry = k.ends_with("_TELEMETRY")
        && k.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !(PIN_ENV.contains(&k) || telemetry) {
        return Err(format!(
            "environment variable {k:?} is not one a pin may set (a ..._TELEMETRY switch, or {})",
            PIN_ENV.join(", ")
        ));
    }
    Ok(())
}

impl Document {
    /// Parses and checks a document. `baseline`: the one compiled into the
    /// client, which may leave values `TODO-PIN`.
    pub fn parse(data: &[u8], baseline: bool) -> Result<Document, String> {
        if data.len() > MAX_DOCUMENT {
            return Err("the pins document is too large".into());
        }
        let d: Document = serde_json::from_slice(data)
            .map_err(|e| format!("the pins document is unreadable: {e}"))?;
        d.validate(baseline)?;
        Ok(d)
    }

    /// Every rule a document has to keep, before any of it is used.
    pub fn validate(&self, baseline: bool) -> Result<(), String> {
        if !baseline && (self.serial == 0 || self.issued_ms <= 0) {
            return Err("a signed pins document needs a serial above 0 and issued_ms".into());
        }
        if !baseline && serde_json::to_string(self).is_ok_and(|t| t.contains(TODO_PIN)) {
            return Err(format!("a signed pins document holds no {TODO_PIN}"));
        }
        let mut names = std::collections::HashSet::new();
        for s in &self.servers {
            let what = |e: String| format!("server {}: {e}", s.name);
            plain_name(&s.name, "server").map_err(what)?;
            if !matches!(s.platform.as_str(), "linux" | "windows") {
                return Err(what(format!(
                    "platform {:?} is not linux or windows",
                    s.platform
                )));
            }
            if !names.insert((s.name.clone(), s.platform.clone())) {
                return Err(what("named twice for one platform".into()));
            }
            let todo = baseline && s.version == TODO_PIN;
            if !todo {
                version_ok(&s.version).map_err(what)?;
            }
            if s.files.is_empty() {
                return Err(what("no files".into()));
            }
            let mut paths = std::collections::HashSet::new();
            for f in &s.files {
                rel_path_ok(&f.path).map_err(what)?;
                if let Some(a) = &f.arch {
                    plain_name(a, "arch")
                        .or_else(|_| {
                            (a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
                                .then_some(())
                                .ok_or(format!("arch {a:?}"))
                        })
                        .map_err(what)?;
                }
                if !paths.insert((f.path.clone(), f.arch.clone(), f.kind)) {
                    return Err(what(format!("{} is pinned twice", f.path)));
                }
                let unpinned = baseline && (f.sha256 == TODO_PIN || f.url.contains(TODO_PIN));
                if unpinned {
                    continue;
                }
                download_allowed(&f.url).map_err(what)?;
                if !crate::fsutil::is_sha256(&f.sha256) {
                    return Err(what(format!(
                        "{}: sha256 must be 64 lowercase hex digits",
                        f.path
                    )));
                }
                if f.size == 0 || f.size > MAX_FILE {
                    return Err(what(format!(
                        "{}: a size from 1 to {MAX_FILE} bytes",
                        f.path
                    )));
                }
            }
            for w in &s.write {
                rel_path_ok(&w.path).map_err(what)?;
                if w.text.len() > 64 * 1024 {
                    return Err(what(format!("{}: text over 64 KiB", w.path)));
                }
            }
            rel_path_ok(&s.run.program).map_err(what)?;
            if s.run.args.len() > 64
                || s.run
                    .args
                    .iter()
                    .any(|a| a.len() > 4096 || a.contains('\0'))
            {
                return Err(what("run.args: at most 64, each up to 4 KiB".into()));
            }
            for (k, v) in &s.run.env {
                env_name_ok(k).map_err(what)?;
                if v.len() > 4096 || v.contains('\0') {
                    return Err(what(format!("environment variable {k}: value too long")));
                }
            }
            for t in s.allow.iter().chain(&s.observe) {
                tool_name_ok(t).map_err(what)?;
            }
            if let Some(t) = s.observe.iter().find(|t| !s.allow.contains(t)) {
                return Err(what(format!("observe tool {t} is not on the allow-list")));
            }
            let mut device_tools = vec![&s.focus.windows];
            device_tools.extend(&s.focus.focused);
            for c in device_tools {
                tool_name_ok(&c.tool).map_err(what)?;
                if hard_denied(&c.tool) {
                    return Err(what(format!(
                        "focus tool {} is on the hard deny-list",
                        c.tool
                    )));
                }
            }
            let mut test_tools = vec![&s.selftest.screenshot];
            if let Some(p) = &s.selftest.pointer {
                test_tools.extend([&p.position, &p.move_to]);
            }
            for c in test_tools {
                if !s.allow.contains(&c.tool) || hard_denied(&c.tool) {
                    return Err(what(format!("self-test tool {} is not allowed", c.tool)));
                }
            }
            for m in &s.selftest.imports {
                if m.is_empty()
                    || !m
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
                {
                    return Err(what(format!("import {m:?} is not a module name")));
                }
            }
            for st in &s.setup {
                plain_name(&st.id, "setup step").map_err(what)?;
                for argv in st.check.iter().map(|c| &c.argv).chain(st.run.iter()) {
                    let Some(p) = argv.first() else {
                        return Err(what(format!("setup step {}: an empty command", st.id)));
                    };
                    let absolute = p.starts_with('/') || p.starts_with("{dir}/");
                    if !absolute {
                        return Err(what(format!(
                            "setup step {}: {p:?} is neither absolute nor in the server's folder",
                            st.id
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// The servers for this platform.
    pub fn for_platform<'a>(&'a self, os: &'a str) -> impl Iterator<Item = &'a ServerPin> + 'a {
        self.servers.iter().filter(move |s| s.platform == os)
    }

    pub fn server(&self, name: &str, os: &str) -> Option<&ServerPin> {
        self.servers
            .iter()
            .find(|s| s.platform == os && s.name == name)
    }

    /// Hard-denied tools a document names on an allow-list: they are dropped,
    /// and the client says so once.
    pub fn overruled(&self) -> Vec<String> {
        self.servers
            .iter()
            .flat_map(|s| {
                s.allow
                    .iter()
                    .filter(|t| hard_denied(t))
                    .map(move |t| format!("{}: {t}", s.name))
            })
            .collect()
    }
}

const BASELINE: &str = include_str!("../pins/baseline.json");

/// The pins compiled into this client.
pub fn baseline() -> Document {
    Document::parse(BASELINE.as_bytes(), true).expect("the built-in pins are valid")
}

/// What taking a signed document did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Taken {
    /// Newer than any before: recorded and kept.
    New(Document),
    /// The same serial as the newest taken (nothing new).
    Same(Document),
}

/// The newest pins this user's client has taken, kept beside the servers:
/// the signed document as it came (`pins.json`, `pins.json.minisig`, checked
/// again on every read) and the highest serial seen (a 0600 file).
pub struct PinStore {
    pub dir: PathBuf,
    pub serial_file: PathBuf,
    /// The release key; without one no signed document is taken.
    pub key: Option<String>,
}

impl PinStore {
    pub fn new(dir: PathBuf, serial_file: PathBuf, key: Option<String>) -> PinStore {
        PinStore {
            dir,
            serial_file,
            key,
        }
    }

    fn doc_file(&self) -> PathBuf {
        self.dir.join("pins.json")
    }

    /// The highest serial taken; 0 when none (or unreadable, which only
    /// weakens the replay check, never a signature).
    pub fn seen_serial(&self) -> u64 {
        let recorded = std::fs::read_to_string(&self.serial_file)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        // A record that went missing does not let an older document replace
        // the one kept.
        recorded.max(self.kept().map_or(0, |d| d.serial))
    }

    /// The kept signed document, checked again; `None` when there is none or it
    /// no longer verifies.
    pub fn kept(&self) -> Option<Document> {
        let key = self.key.as_deref()?;
        let data = std::fs::read(self.doc_file()).ok()?;
        let sig = std::fs::read_to_string(self.dir.join("pins.json.minisig")).ok()?;
        verify(&data, &sig, key).ok()
    }

    /// The pins in force: the kept signed document when its serial is above
    /// the baseline's, else the baseline.
    pub fn current(&self) -> Document {
        let base = baseline();
        match self.kept() {
            Some(d) if d.serial > base.serial => d,
            _ => base,
        }
    }

    /// Takes a signed document: verified, checked, not older than any taken.
    /// Only then is anything written.
    pub fn take(&self, data: &[u8], sig: &str) -> Result<Taken, String> {
        let key = self
            .key
            .as_deref()
            .ok_or("this build has no release key, so it takes no signed pins")?;
        let doc = verify(data, sig, key)?;
        let seen = self.seen_serial();
        if doc.serial < seen {
            return Err(format!(
                "the pins document has serial {}, older than serial {seen} taken before: an older document is being served again, so it is ignored",
                doc.serial
            ));
        }
        if doc.serial == seen && self.kept().is_some() {
            return Ok(Taken::Same(doc));
        }
        sync_policy::config::write_private(&self.doc_file(), data)
            .and_then(|()| {
                sync_policy::config::write_private(
                    &self.dir.join("pins.json.minisig"),
                    sig.as_bytes(),
                )
            })
            .map_err(|e| format!("cannot keep the pins document: {e}"))?;
        if doc.serial > seen {
            sync_policy::config::write_private(
                &self.serial_file,
                format!("{}\n", doc.serial).as_bytes(),
            )
            .map_err(|e| format!("cannot record the pins serial: {e}"))?;
        }
        Ok(Taken::New(doc))
    }
}

/// A signed pins document: the signature against the release key (the same
/// check as the update manifest's), then the document's own rules.
pub fn verify(data: &[u8], sig: &str, key: &str) -> Result<Document, String> {
    sync_connector::signed::verify(data, sig, key, "pins document")?;
    Document::parse(data, false)
}

/// Fetches `url` (https, or a local file) with at most `max` bytes; a
/// download from a host off `DOWNLOAD_HOSTS` is refused, redirects included.
pub async fn fetch(url: &str, max: usize, hosts_checked: bool) -> Result<Vec<u8>, String> {
    if url.starts_with("https://") || url.starts_with("http://") {
        return if hosts_checked {
            sync_connector::http::get_checked(url, max, &download_allowed).await
        } else {
            sync_connector::http::get(url, max).await
        };
    }
    let path = Path::new(url.strip_prefix("file://").unwrap_or(url));
    let len = std::fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    if len > max as u64 {
        return Err(format!("{}: too large", path.display()));
    }
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Fetches and checks the signed document at `url` as `check` does, without
/// keeping anything: what `install --print` shows.
pub async fn peek(store: &PinStore, url: &str) -> Result<Document, String> {
    let key = store
        .key
        .as_deref()
        .ok_or("this build has no release key")?;
    let data = fetch(url, MAX_DOCUMENT, false).await?;
    let sig = fetch(&format!("{url}.minisig"), 4096, false).await?;
    let sig = String::from_utf8(sig).map_err(|_| "the pins signature is not text".to_string())?;
    let doc = verify(&data, &sig, key)?;
    if doc.serial < store.seen_serial() {
        return Err(format!(
            "the pins document has serial {}, older than one taken before",
            doc.serial
        ));
    }
    Ok(doc)
}

/// Fetches the signed document at `url` and takes it into `store`.
pub async fn check(store: &PinStore, url: &str) -> Result<Taken, String> {
    let data = fetch(url, MAX_DOCUMENT, false).await?;
    let sig = fetch(&format!("{url}.minisig"), 4096, false).await?;
    let sig = String::from_utf8(sig).map_err(|_| "the pins signature is not text".to_string())?;
    store.take(&data, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub fn server(name: &str, allow: &[&str]) -> Value {
        json!({
            "name": name, "platform": "linux", "version": "1.0.0",
            "files": [{"kind": "executable", "path": "srv", "url": "https://github.com/o/r/releases/download/v1/srv", "sha256": "a".repeat(64), "size": 10}],
            "run": {"program": "srv", "args": ["--stdio"], "env": {"NO_TELEMETRY": "1"}},
            "allow": allow, "observe": [],
            "focus": {"windows": {"tool": "list_windows"}},
            "selftest": {"screenshot": {"tool": allow[0]}}
        })
    }

    fn doc(servers: Vec<Value>) -> Value {
        json!({"serial": 2, "issued_ms": 1, "servers": servers})
    }

    fn parse(v: &Value) -> Result<Document, String> {
        Document::parse(v.to_string().as_bytes(), false)
    }

    #[test]
    fn the_baseline_is_valid_and_keeps_the_deny_list() {
        let b = baseline();
        assert_eq!(b.serial, 0);
        assert!(b.overruled().is_empty(), "{:?}", b.overruled());
        for s in &b.servers {
            for t in s.allowed() {
                assert!(!hard_denied(&t), "{t}");
            }
        }
        // Telemetry of the Windows server is off.
        let w = b.server("windows-mcp", "windows").unwrap();
        assert_eq!(
            w.run.env.get("ANONYMIZED_TELEMETRY").map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn the_hard_deny_list_wins_in_every_spelling() {
        for t in [
            "PowerShell",
            "Powershell-Tool",
            "powershell_tool",
            "FileSystem",
            "File-Tool",
            "Registry",
            "Process",
            "App",
            "App-Tool",
            "Shortcut",
            "Clipboard",
            "Scrape",
            "MultiEdit",
            "setup_window_targeting",
            "perform_action",
            "set_value",
            "Set-Value",
            "run_shell_command",
            "launch_app",
        ] {
            assert!(hard_denied(t), "{t}");
        }
        for t in [
            "screenshot",
            "Click",
            "Type",
            "type_text",
            "press_key",
            "Move",
            "Scroll",
            "list_windows",
        ] {
            assert!(!hard_denied(t), "{t}");
        }
        let d = parse(&doc(vec![server(
            "s",
            &["screenshot", "PowerShell", "set_value"],
        )]))
        .unwrap();
        assert_eq!(d.servers[0].allowed(), ["screenshot"]);
        assert_eq!(d.overruled().len(), 2);
    }

    #[test]
    fn a_document_is_checked_whole() {
        assert!(parse(&doc(vec![server("s", &["screenshot"])])).is_ok());
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["extra"] = json!(1);
        assert!(parse(&v).is_err(), "unknown top-level field");
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["servers"][0]["files"][0]["mirror"] = json!("x");
        assert!(parse(&v).is_err(), "unknown nested field");
        for host in [
            "https://evil.example/srv",
            "http://github.com/srv",
            "https://github.com.evil.example/srv",
            "https://user@github.com/srv",
            "ftp://github.com/srv",
        ] {
            let mut v = doc(vec![server("s", &["screenshot"])]);
            v["servers"][0]["files"][0]["url"] = json!(host);
            assert!(parse(&v).is_err(), "{host}");
        }
        for ok in [
            "https://objects.githubusercontent.com/x",
            "https://files.pythonhosted.org/packages/x.whl",
            "https://www.python.org/ftp/python/3.12.10/x.zip",
        ] {
            let mut v = doc(vec![server("s", &["screenshot"])]);
            v["servers"][0]["files"][0]["url"] = json!(ok);
            assert!(parse(&v).is_ok(), "{ok}");
        }
        for (field, bad) in [
            ("sha256", json!("TODO-PIN")),
            ("sha256", json!("A".repeat(64))),
            ("size", json!(0)),
            ("path", json!("../srv")),
            ("path", json!("/usr/bin/srv")),
        ] {
            let mut v = doc(vec![server("s", &["screenshot"])]);
            v["servers"][0]["files"][0][field] = bad.clone();
            assert!(parse(&v).is_err(), "{field} {bad}");
        }
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["servers"][0]["run"]["env"] = json!({"LD_PRELOAD": "/tmp/x.so"});
        assert!(parse(&v).is_err());
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["servers"][0]["version"] = json!("../1");
        assert!(parse(&v).is_err());
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["servers"][0]["observe"] = json!(["click"]);
        assert!(parse(&v).is_err(), "observe not on the allow-list");
        for (k, ok) in [
            ("FAKE_TELEMETRY", true),
            ("PYTHONUTF8", true),
            ("PYTHONWARNINGS", false),
            ("GTK_MODULES", false),
            ("BASH_ENV", false),
            ("COMSPEC", false),
        ] {
            let mut v = doc(vec![server("s", &["screenshot"])]);
            v["servers"][0]["run"]["env"] = json!({ k: "1" });
            assert_eq!(parse(&v).is_ok(), ok, "{k}");
        }
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["servers"][0]["write"] = json!([{"path": "python/pythonTODO-PIN._pth", "text": "x"}]);
        assert!(parse(&v).is_err(), "TODO-PIN anywhere in a signed document");
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["servers"][0]["focus"]["windows"]["tool"] = json!("PowerShell");
        assert!(parse(&v).is_err());
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["serial"] = json!(0);
        assert!(parse(&v).is_err());
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["servers"][0]["setup"] =
            json!([{"id": "x", "title": "t", "text": "t", "run": ["gsettings", "set"]}]);
        assert!(parse(&v).is_err(), "a setup program from PATH");
    }

    #[test]
    fn todo_pins_are_for_the_baseline_and_block_the_install() {
        let mut v = doc(vec![server("s", &["screenshot"])]);
        v["servers"][0]["files"][0]["sha256"] = json!(TODO_PIN);
        assert!(parse(&v).is_err());
        let d = Document::parse(v.to_string().as_bytes(), true).unwrap();
        assert!(d.servers[0].unpinned("x86_64").is_some());
        let d = parse(&doc(vec![server("s", &["screenshot"])])).unwrap();
        assert_eq!(d.servers[0].unpinned("x86_64"), None);
    }
}
