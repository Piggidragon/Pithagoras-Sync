//! A fake MCP server for tests (`sync_testkit::fake_mcp`).

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    sync_testkit::fake_mcp::main_with(&args);
}
