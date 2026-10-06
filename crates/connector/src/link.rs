//! The link to the portal over time: connect, run a session, back off, reconnect;
//! stay down while paused; stop for good when the portal refuses the token.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sync_policy::PortalConfig;
use sync_proto::{CONNECT_PATH, close};
use tokio::sync::watch;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, USER_AGENT};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{info, warn};

use crate::device::{CLIENT_VERSION, Device};
use crate::net::BoxIo;
use crate::session::{self, End};
use crate::url::PortalUrl;

/// Text frames are small; binary frames carry at most 64 KiB.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// A connection that lasted this long resets the backoff.
const STABLE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkState {
    Connecting,
    Connected,
    /// Waiting before the next attempt.
    Waiting,
    /// The portal refused this device; it needs pairing again (or an update).
    Rejected,
    Paused,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkStatus {
    pub state: LinkState,
    pub detail: Option<String>,
    pub since_ms: i64,
}

impl LinkStatus {
    pub fn new(state: LinkState, detail: Option<String>) -> LinkStatus {
        LinkStatus {
            state,
            detail,
            since_ms: now_ms(),
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub struct LinkConfig {
    pub portal: PortalConfig,
    pub token: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LinkEnd {
    Shutdown,
    Rejected(String),
}

pub enum ConnectError {
    /// HTTP 401 on the upgrade: the token is unknown or revoked.
    Unauthorized,
    Other(String),
}

/// 1 s doubling to 60 s, with a little jitter so many devices do not reconnect in
/// step after a portal restart.
pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            next: Duration::from_secs(1),
        }
    }
}

impl Backoff {
    pub const MAX: Duration = Duration::from_secs(60);

    pub fn next_delay(&mut self) -> Duration {
        let d = self.next;
        self.next = (self.next * 2).min(Self::MAX);
        let jitter_ms = (d.as_millis() as u64 / 10).max(1);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos() as u64)
            .unwrap_or(0);
        // Jitter shortens the wait, so the minute stays the longest one.
        d - Duration::from_millis(nanos % jitter_ms)
    }

    pub fn reset(&mut self) {
        *self = Backoff::default();
    }
}

pub async fn connect(
    url: &PortalUrl,
    cfg: &LinkConfig,
) -> Result<WebSocketStream<BoxIo>, ConnectError> {
    let io = crate::net::open(url, cfg.portal.spki_sha256.as_deref())
        .await
        .map_err(ConnectError::Other)?;
    let mut req = url
        .ws(CONNECT_PATH)
        .into_client_request()
        .map_err(|e| ConnectError::Other(e.to_string()))?;
    let auth = HeaderValue::from_str(&format!("Bearer {}", cfg.token))
        .map_err(|_| ConnectError::Other("the token is not a valid header value".into()))?;
    req.headers_mut().insert(AUTHORIZATION, auth);
    req.headers_mut().insert(
        USER_AGENT,
        HeaderValue::from_str(&format!("pithagoras-sync/{CLIENT_VERSION}")).unwrap(),
    );
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let handshake = tokio_tungstenite::client_async_with_config(req, io, Some(config));
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Err(_) => Err(ConnectError::Other(
            "the WebSocket handshake timed out".into(),
        )),
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => {
            let status = resp.status().as_u16();
            if status == 401 {
                Err(ConnectError::Unauthorized)
            } else if status == 409 {
                Err(ConnectError::Other(
                    "the portal already has a live connection of this device".into(),
                ))
            } else {
                Err(ConnectError::Other(format!(
                    "the portal answered {status} instead of a WebSocket"
                )))
            }
        }
        Ok(Err(e)) => Err(ConnectError::Other(e.to_string())),
    }
}

/// Keeps the device connected until shutdown or until the portal refuses it.
pub async fn run(
    device: Arc<Device>,
    cfg: LinkConfig,
    status: watch::Sender<LinkStatus>,
    mut shutdown: watch::Receiver<bool>,
) -> LinkEnd {
    let set = |state: LinkState, detail: Option<String>| {
        status.send_replace(LinkStatus::new(state, detail));
    };
    let url = match PortalUrl::parse(&cfg.portal.url) {
        Ok(u) => u,
        Err(e) => {
            set(LinkState::Rejected, Some(e.clone()));
            return LinkEnd::Rejected(e);
        }
    };
    let mut backoff = Backoff::default();
    let mut paused = device.paused();
    loop {
        if *shutdown.borrow() {
            set(LinkState::Stopped, None);
            return LinkEnd::Shutdown;
        }
        if *paused.borrow() {
            set(
                LinkState::Paused,
                Some("run `pithagoras-sync unlock` to reconnect".into()),
            );
            tokio::select! {
                _ = crate::until(&mut paused, false) => {
                    backoff.reset();
                    continue;
                }
                _ = crate::until(&mut shutdown, true) => continue,
            }
        }
        set(LinkState::Connecting, Some(url.to_string()));
        let detail = match connect(&url, &cfg).await {
            Ok(ws) => {
                info!("connected to {url}");
                set(LinkState::Connected, Some(url.to_string()));
                let t0 = Instant::now();
                let end =
                    session::run(device.clone(), ws, &cfg.portal.device_id, &mut shutdown).await;
                if t0.elapsed() >= STABLE {
                    backoff.reset();
                }
                info!("connection ended: {end:?}");
                match end {
                    End::Shutdown | End::Paused => continue,
                    End::Closed(Some(close::REVOKED), _) => {
                        let why = "the portal removed this device; pair it again".to_string();
                        set(LinkState::Rejected, Some(why.clone()));
                        return LinkEnd::Rejected(why);
                    }
                    End::Closed(Some(close::UNSUPPORTED), reason) => {
                        let why = format!(
                            "the portal does not support this client version ({reason}); update pithagoras-sync"
                        );
                        set(LinkState::Rejected, Some(why.clone()));
                        return LinkEnd::Rejected(why);
                    }
                    End::Closed(code, reason) => format!(
                        "the portal closed the connection ({}{})",
                        code.map(|c| c.to_string())
                            .unwrap_or_else(|| "no code".into()),
                        if reason.is_empty() {
                            String::new()
                        } else {
                            format!(": {reason}")
                        }
                    ),
                    End::Dead => "the portal stopped answering".into(),
                    End::Error(e) => e,
                }
            }
            Err(ConnectError::Unauthorized) => {
                let why = "the portal refused the token (device removed or revoked); pair it again"
                    .to_string();
                set(LinkState::Rejected, Some(why.clone()));
                return LinkEnd::Rejected(why);
            }
            Err(ConnectError::Other(e)) => e,
        };
        let wait = backoff.next_delay();
        warn!("{detail}; retrying in {}s", wait.as_secs());
        set(
            LinkState::Waiting,
            Some(format!("{detail}; retrying in {}s", wait.as_secs())),
        );
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = crate::until(&mut shutdown, true) => {}
            _ = crate::until(&mut paused, true) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_a_minute() {
        let mut b = Backoff::default();
        for base in [1, 2, 4, 8, 16, 32, 60, 60, 60] {
            let d = b.next_delay().as_millis() as u64;
            assert!(d <= base * 1000 && d >= base * 900, "{d} for {base}");
        }
        b.reset();
        assert!(b.next_delay() <= Duration::from_secs(1));
    }
}
