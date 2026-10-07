//! The fake MCP server answers the handshake. This test also makes `cargo
//! test` build the `sync-fake-mcp` program the other crates' tests start.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn the_fake_server_answers_initialize() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sync-fake-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("2025-06-18"), "{line}");
    drop(stdin);
    child.wait().unwrap();
}
