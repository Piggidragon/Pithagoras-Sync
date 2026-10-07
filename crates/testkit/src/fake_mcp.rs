//! A fake MCP server on stdin and stdout, for the tests of the device's MCP
//! client and of computer use end to end: the same JSON-RPC lines as a real
//! server, with tools named like `computer-use-linux`'s, a pointer it keeps in
//! memory, and switches for every way a server can misbehave. The program is
//! `sync-fake-mcp`; `binary()` finds (or builds) it for a test.
//!
//! ```text
//! sync-fake-mcp [--mode <m>]... [--record <file>] [--pid-file <file>]
//! ```
//!
//! Modes: `hang` (never answers a tool call), `crash` (exits on a tool call),
//! `garbage` (writes lines that are not JSON before each answer), `long-line`
//! (answers a tool call with one huge line), `flood` (writes 2 MiB of
//! notifications before an answer), `unknown-id` (answers id 99999 first),
//! `sampling` (asks the client for `sampling/createMessage` first and records
//! the answer), `no-move` (the pointer does not move), `new-tool` (lists a tool
//! `new_tool` too), `bad-version` (speaks MCP 1999-01-01), `slow-start` (waits
//! 3 s before answering `initialize`), `exit-at-start`, `windows-error` (the
//! window list fails), `sync-window` (a window titled `Pithagoras Sync: ...` is
//! open), `pages` (lists tools two per page), `child` (starts a child process
//! that sleeps, its pid in the pid file), `audio` (answers a call with audio
//! content).

use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde_json::{Value, json};

/// A 1x1 PNG.
pub const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

/// The tools the fake lists, with their schemas.
pub fn tools(new_tool: bool) -> Vec<Value> {
    let xy = json!({"type": "object", "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}}, "required": ["x", "y"]});
    let mut t = vec![
        json!({"name": "screenshot", "description": "Take a screenshot of the screen.", "inputSchema": {"type": "object", "properties": {}}}),
        json!({"name": "list_windows", "description": "List the open windows.", "inputSchema": {"type": "object", "properties": {}}}),
        json!({"name": "get_cursor_position", "description": "Where the pointer is.", "inputSchema": {"type": "object", "properties": {}}}),
        json!({"name": "mouse_move", "description": "Move the pointer.", "inputSchema": xy}),
        json!({"name": "mouse_click", "description": "Click.", "inputSchema": {"type": "object", "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}, "button": {"type": "string", "enum": ["left", "right"]}}, "required": ["x", "y"]}}),
        json!({"name": "type_text", "description": "Type text.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}}),
        json!({"name": "press_key", "description": "Press a key.", "inputSchema": {"type": "object", "properties": {"key": {"type": "string"}}, "required": ["key"]}}),
        json!({"name": "set_value", "description": "Set an element's value.", "inputSchema": {"type": "object", "properties": {"value": {"type": "string"}}}}),
        json!({"name": "PowerShell", "description": "Run a command.", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}}),
    ];
    if new_tool {
        t.push(json!({"name": "new_tool", "description": "Added in a newer version.", "inputSchema": {"type": "object", "properties": {}}}));
    }
    t
}

struct Fake {
    modes: Vec<String>,
    record: Option<PathBuf>,
    pointer: (i64, i64),
    out: std::io::Stdout,
}

impl Fake {
    fn has(&self, m: &str) -> bool {
        self.modes.iter().any(|x| x == m)
    }

    fn note(&self, line: &str) {
        if let Some(p) = &self.record
            && let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
        {
            let _ = writeln!(f, "{line}");
        }
    }

    fn send(&mut self, v: &Value) {
        let mut o = self.out.lock();
        let _ = writeln!(o, "{v}");
        let _ = o.flush();
    }

    fn raw(&mut self, line: &str) {
        let mut o = self.out.lock();
        let _ = writeln!(o, "{line}");
        let _ = o.flush();
    }

    fn text(t: impl Into<String>) -> Value {
        json!({"content": [{"type": "text", "text": t.into()}]})
    }

    fn call(&mut self, name: &str, args: &Value) -> Value {
        match name {
            "screenshot" => {
                json!({"content": [{"type": "image", "data": PNG, "mimeType": "image/png"}, {"type": "text", "text": "1 screen"}]})
            }
            "list_windows" if self.has("windows-error") => {
                json!({"content": [{"type": "text", "text": "no session"}], "isError": true})
            }
            "list_windows" => {
                let mut w = String::from("101 Terminal\n102 Firefox: the portal");
                if self.has("sync-window") {
                    w.push_str("\n103 Pithagoras Sync: pair this computer");
                }
                Fake::text(w)
            }
            "get_cursor_position" => Fake::text(format!(
                "{{\"x\": {}, \"y\": {}}}",
                self.pointer.0, self.pointer.1
            )),
            "mouse_move" => {
                if !self.has("no-move") {
                    self.pointer = (
                        args["x"].as_i64().unwrap_or(0),
                        args["y"].as_i64().unwrap_or(0),
                    );
                }
                Fake::text("moved")
            }
            "mouse_click" => Fake::text("clicked"),
            "type_text" => Fake::text("typed"),
            "press_key" => Fake::text("pressed"),
            other => {
                json!({"content": [{"type": "text", "text": format!("ran {other}")}], "isError": false})
            }
        }
    }
}

/// Runs the fake on this process's stdin and stdout.
pub fn main_with(args: &[String]) {
    let mut modes = Vec::new();
    let mut record = None;
    let mut pid_file = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--mode" => modes.extend(it.next().cloned()),
            "--record" => record = it.next().map(PathBuf::from),
            "--pid-file" => pid_file = it.next().map(PathBuf::from),
            _ => {}
        }
    }
    let mut fake = Fake {
        modes,
        record,
        pointer: (100, 200),
        out: std::io::stdout(),
    };
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut pids: Vec<String> = Vec::from([std::process::id().to_string()]);
    #[cfg(unix)]
    if fake.has("child")
        && let Ok(c) = std::process::Command::new("/bin/sleep").arg("1000").spawn()
    {
        pids.push(c.id().to_string());
    }
    if let Some(p) = &pid_file {
        let _ = std::fs::write(p, pids.join("\n") + "\n");
    }
    if fake.has("exit-at-start") {
        std::process::exit(3);
    }
    eprintln!("fake MCP server started");
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let method = msg["method"].as_str().unwrap_or("").to_string();
        let id = msg.get("id").cloned();
        if method.is_empty() {
            // The client's answer to our own request.
            fake.note(&format!("answer {}", msg));
            continue;
        }
        let tool = msg["params"]["name"].as_str().unwrap_or("").to_string();
        fake.note(&if tool.is_empty() {
            method.clone()
        } else {
            format!("{method} {tool} {}", msg["params"]["arguments"])
        });
        let Some(id) = id else { continue };
        let result = match method.as_str() {
            "initialize" => {
                if fake.has("slow-start") {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                }
                let v = if fake.has("bad-version") {
                    "1999-01-01"
                } else {
                    "2025-06-18"
                };
                json!({"protocolVersion": v, "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}})
            }
            "ping" => json!({}),
            "tools/list" => {
                let all = tools(fake.has("new-tool"));
                if fake.has("pages") {
                    let start: usize = msg["params"]["cursor"]
                        .as_str()
                        .and_then(|c| c.parse().ok())
                        .unwrap_or(0);
                    let page: Vec<Value> = all.iter().skip(start).take(2).cloned().collect();
                    let mut r = json!({"tools": page});
                    if start + 2 < all.len() {
                        r["nextCursor"] = json!((start + 2).to_string());
                    }
                    r
                } else {
                    json!({"tools": all})
                }
            }
            "tools/call" => {
                if fake.has("hang") {
                    continue;
                }
                if fake.has("crash") {
                    std::process::exit(9);
                }
                if fake.has("garbage") {
                    for _ in 0..3 {
                        fake.raw("this is not JSON");
                    }
                }
                if fake.has("long-line") {
                    let big = "x".repeat(1 << 20);
                    fake.raw(&format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"{big}\"}}]}}}}"));
                    continue;
                }
                if fake.has("flood") {
                    let pad = "y".repeat(32 * 1024);
                    for _ in 0..64 {
                        fake.send(&json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": pad}}));
                    }
                }
                if fake.has("unknown-id") {
                    fake.send(&json!({"jsonrpc": "2.0", "id": 99999, "result": {"content": [{"type": "text", "text": "not yours"}]}}));
                }
                if fake.has("sampling") {
                    fake.send(&json!({"jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage", "params": {"messages": []}}));
                    fake.send(&json!({"jsonrpc": "2.0", "id": "r1", "method": "roots/list", "params": {}}));
                }
                if fake.has("audio") {
                    fake.send(&json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "audio", "data": "AA==", "mimeType": "audio/wav"}]}}));
                    continue;
                }
                let args = msg["params"]["arguments"].clone();
                fake.call(&tool, &args)
            }
            _ => {
                fake.send(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no such method"}}));
                continue;
            }
        };
        fake.send(&json!({"jsonrpc": "2.0", "id": id, "result": result}));
    }
}

/// The `sync-fake-mcp` program: next to the test's own binary (the target's
/// `debug` folder), built with cargo first when it is not there yet.
pub fn binary() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary");
    // target/debug/deps/<test> -> target/debug
    let dir = exe
        .parent()
        .and_then(|d| {
            if d.ends_with("deps") {
                d.parent()
            } else {
                Some(d)
            }
        })
        .expect("a target folder")
        .to_path_buf();
    let name = format!("sync-fake-mcp{}", std::env::consts::EXE_SUFFIX);
    let path = dir.join(&name);
    // Built again only when its source is newer (a test run of one crate does
    // not build another crate's programs).
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fake_mcp.rs");
    let modified = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let current = matches!((modified(&path), modified(&source)), (Some(b), Some(s)) if b >= s);
    static BUILT: std::sync::Once = std::sync::Once::new();
    BUILT.call_once(|| {
        if current {
            return;
        }
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = std::process::Command::new(cargo)
            .args([
                "build",
                "-q",
                "-p",
                "sync-testkit",
                "--bin",
                "sync-fake-mcp",
            ])
            .status();
        assert!(
            status.is_ok_and(|s| s.success()) || path.exists(),
            "cannot build sync-fake-mcp"
        );
    });
    assert!(path.exists(), "{} is missing", path.display());
    path
}
