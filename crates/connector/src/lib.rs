//! Connector client of Pithagoras Sync: pairing, TLS, the WebSocket link to the
//! portal, and serving the portal's calls through the device's policy.

pub mod device;
pub mod http;
pub mod link;
pub mod net;
pub mod pair;
pub mod session;
pub mod tls;
pub mod url;

pub use device::Device;
pub use link::{LinkConfig, LinkEnd, LinkState, LinkStatus};

/// Waits until a flag has `value`. The guard `wait_for` returns is dropped here, so
/// callers can await after it.
pub(crate) async fn until(rx: &mut tokio::sync::watch::Receiver<bool>, value: bool) {
    let _ = rx.wait_for(|v| *v == value).await;
}
