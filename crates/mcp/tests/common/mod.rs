//! A server pin for the fake MCP server, served by the local file server.
#![allow(dead_code)]

use std::path::Path;
use std::time::Duration;

use serde_json::json;
use sync_mcp::client::Limits;
use sync_mcp::fsutil::sha256_hex;
use sync_mcp::pins::ServerPin;
use sync_testkit::fake_mcp;
use sync_testkit::files::{FileServer, Reply};

pub fn limits() -> Limits {
    Limits {
        max_line: 1 << 20,
        max_output: 4 << 20,
        max_garbage: 32,
        startup: Duration::from_secs(10),
        call: Duration::from_secs(5),
    }
}

pub fn fake_bytes() -> Vec<u8> {
    std::fs::read(fake_mcp::binary()).unwrap()
}

/// The pin of `fake` `version`, its program served at `/<version>/fake-mcp`.
pub fn pin(files: &FileServer, version: &str, modes: &[&str], record: &Path) -> ServerPin {
    let data = fake_bytes();
    let url = files.put(&format!("/{version}/fake-mcp"), Reply::Body(data.clone()));
    let mut args = vec![
        "--record".to_string(),
        record.to_string_lossy().into_owned(),
    ];
    for m in modes {
        args.extend(["--mode".to_string(), m.to_string()]);
    }
    serde_json::from_value(json!({
        "name": "fake", "platform": sync_mcp::os(), "version": version,
        "files": [{"kind": "executable", "path": "fake-mcp", "url": url, "sha256": sha256_hex(&data), "size": data.len()}],
        "run": {"program": "fake-mcp", "args": args, "env": {"FAKE_TELEMETRY": "off"}},
        "allow": ["screenshot", "list_windows", "get_cursor_position", "mouse_move", "mouse_click", "type_text", "press_key", "set_value", "PowerShell", "new_tool"],
        "observe": ["screenshot", "list_windows", "get_cursor_position"],
        "focus": {"windows": {"tool": "list_windows"}},
        "selftest": {
            "screenshot": {"tool": "screenshot"},
            "pointer": {"position": {"tool": "get_cursor_position"}, "move_to": {"tool": "mouse_move", "args": {"x": "$x", "y": "$y"}}}
        }
    }))
    .unwrap()
}

pub fn env() -> Vec<(String, String)> {
    vec![("HOME".into(), "/nonexistent".into())]
}

pub async fn install(mcp: &Path, pin: &ServerPin) -> Result<sync_mcp::install::Installed, String> {
    let mut said = Vec::new();
    sync_mcp::install::install(
        mcp,
        pin,
        sync_mcp::arch(),
        &env(),
        &limits(),
        |url, max| async move { sync_mcp::pins::fetch(&url, max, true).await },
        &mut |s| said.push(s),
    )
    .await
}
