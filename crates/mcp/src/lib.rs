//! Computer use of Pithagoras Sync: the agent sees the screen and uses the
//! pointer and keyboard through an MCP server the client installs and runs
//! itself (`computer-use-linux`, Windows-MCP). The device is the MCP client.
//!
//! - `pins`: which server, version, files and tools; the hard deny-list.
//! - `install`: download, check, unpack, test once, record a hash.
//! - `client`: the MCP client over the server's stdin and stdout.
//! - `service`: `mcp.list` and `mcp.call` with the allow-list, the schema, the
//!   consent, the focus check and the taint.
//! - `selftest`, `setup`: `computer-use test` and `computer-use setup`.

pub mod client;
pub mod content;
pub mod fsutil;
mod inflate;
pub mod install;
pub mod pins;
pub mod proc;
pub mod schema;
pub mod selftest;
pub mod service;
pub mod session;
pub mod setup;
pub mod unzip;

pub use client::{Client, ClientError, Launch, Limits};
pub use pins::{Document, PinStore, ServerPin};
pub use service::Service;

/// The architecture as the pins name it (Rust's `x86_64`, `aarch64`).
pub fn arch() -> &'static str {
    std::env::consts::ARCH
}

/// The platform as the pins name it.
pub fn os() -> &'static str {
    if cfg!(windows) { "windows" } else { "linux" }
}
