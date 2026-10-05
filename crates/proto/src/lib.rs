//! Wire protocol of Pithagoras Sync: JSON-RPC frames, binary frames, method types.
//!
//! `docs/protocol.md` is the prose version of this crate; change both together.
//! Everything the portal sends is parsed with `deny_unknown_fields`, so a field the
//! device does not know (say an `env` on `exec.start` or a `mode` on a file call) is
//! an error instead of being silently dropped.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod binary;
pub mod methods;

pub use binary::{BinaryFrame, FrameKind};

/// Protocol version sent in `hello`.
pub const PROTO_VERSION: u32 = 1;
/// WebSocket endpoint, relative to the portal's base URL.
pub const CONNECT_PATH: &str = "/sync/v1/connect";
/// Pairing endpoint, relative to the portal's base URL.
pub const PAIR_PATH: &str = "/sync/v1/pair";

/// JSON-RPC error codes. The standard ones plus the device's own range.
pub mod code {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL: i64 = -32603;
    /// The device's policy refused the call, or an approval was denied or timed out.
    pub const DENIED: i64 = -32001;
    pub const NOT_FOUND: i64 = -32002;
    /// `fs.write` with an `if_match` that no longer matches the file.
    pub const CONFLICT: i64 = -32003;
    pub const TOO_LARGE: i64 = -32004;
    pub const IO: i64 = -32005;
    /// A device limit (running commands, open streams) is reached.
    pub const BUSY: i64 = -32006;
    /// A path the device refuses to interpret: relative, a drive letter, a NUL byte.
    pub const BAD_PATH: i64 = -32007;
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn denied(reason: impl Into<String>) -> Self {
        RpcError::new(code::DENIED, reason)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for RpcError {}

/// A request id: JSON-RPC allows numbers and strings; null and others are refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    Num(i64),
    Str(String),
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Id::Num(n) => write!(f, "{n}"),
            Id::Str(s) => write!(f, "{s}"),
        }
    }
}

/// A text frame as the device receives it.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    Request {
        id: Id,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
}

/// Why an incoming text frame could not be used. `id` is set when the frame had a
/// usable id, so the error can still be answered.
#[derive(Debug, Clone, PartialEq)]
pub struct FrameError {
    pub id: Option<Id>,
    pub error: RpcError,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFrame {
    jsonrpc: String,
    // A present `"id": null` must stay distinguishable from a missing id.
    #[serde(default, deserialize_with = "present")]
    id: Option<Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Value>,
}

fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

/// Parses a text frame from the portal. The portal only sends requests and
/// notifications; the device never sends requests, so a response is invalid here.
pub fn parse_incoming(text: &str) -> Result<Incoming, FrameError> {
    let raw: RawFrame = serde_json::from_str(text).map_err(|e| FrameError {
        id: None,
        error: RpcError::new(code::PARSE_ERROR, format!("bad frame: {e}")),
    })?;
    let id = match raw.id {
        None => None,
        Some(v) => match serde_json::from_value::<Id>(v) {
            Ok(id) => Some(id),
            Err(_) => {
                return Err(FrameError {
                    id: None,
                    error: RpcError::new(code::INVALID_REQUEST, "id must be a number or string"),
                });
            }
        },
    };
    let invalid = |msg: &str| FrameError {
        id: id.clone(),
        error: RpcError::new(code::INVALID_REQUEST, msg),
    };
    if raw.jsonrpc != "2.0" {
        return Err(invalid("jsonrpc must be \"2.0\""));
    }
    let Some(method) = raw.method else {
        return Err(invalid("missing method"));
    };
    let params = raw.params.unwrap_or(Value::Object(Default::default()));
    if !params.is_object() {
        return Err(FrameError {
            id: id.clone(),
            error: RpcError::new(code::INVALID_PARAMS, "params must be an object"),
        });
    }
    Ok(match id {
        Some(id) => Incoming::Request { id, method, params },
        None => Incoming::Notification { method, params },
    })
}

/// A response to one portal request.
pub fn response(id: &Id, result: Result<Value, RpcError>) -> String {
    let v = match result {
        Ok(result) => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => serde_json::json!({"jsonrpc": "2.0", "id": id, "error": error}),
    };
    v.to_string()
}

/// An error response to a frame that had no usable id.
pub fn error_without_id(error: &RpcError) -> String {
    serde_json::json!({"jsonrpc": "2.0", "id": null, "error": error}).to_string()
}

/// A notification from the device (`hello`, `exec.exit`, `audit`, `approval.waiting`).
pub fn notification(method: &str, params: impl Serialize) -> String {
    serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requests_and_notifications() {
        let r =
            parse_incoming(r#"{"jsonrpc":"2.0","id":7,"method":"fs.stat","params":{"path":"/a"}}"#)
                .unwrap();
        assert_eq!(
            r,
            Incoming::Request {
                id: Id::Num(7),
                method: "fs.stat".into(),
                params: serde_json::json!({"path": "/a"})
            }
        );
        let n = parse_incoming(r#"{"jsonrpc":"2.0","method":"grant.end","params":{"chat":"c"}}"#)
            .unwrap();
        assert!(matches!(n, Incoming::Notification { .. }));
        let s = parse_incoming(r#"{"jsonrpc":"2.0","id":"x","method":"device.info"}"#).unwrap();
        assert!(matches!(s, Incoming::Request { id: Id::Str(_), .. }));
    }

    #[test]
    fn refuses_malformed_frames() {
        assert_eq!(
            parse_incoming("nope").unwrap_err().error.code,
            code::PARSE_ERROR
        );
        // A response or an unknown top-level field is not something the portal sends.
        let e = parse_incoming(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).unwrap_err();
        assert_eq!(e.error.code, code::PARSE_ERROR);
        let e = parse_incoming(r#"{"jsonrpc":"2.0","id":1}"#).unwrap_err();
        assert_eq!(
            (e.id, e.error.code),
            (Some(Id::Num(1)), code::INVALID_REQUEST)
        );
        let e = parse_incoming(r#"{"jsonrpc":"1.0","id":1,"method":"x"}"#).unwrap_err();
        assert_eq!(e.error.code, code::INVALID_REQUEST);
        let e = parse_incoming(r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#).unwrap_err();
        assert_eq!(e.error.code, code::INVALID_REQUEST);
        let e =
            parse_incoming(r#"{"jsonrpc":"2.0","id":1,"method":"x","params":[1]}"#).unwrap_err();
        assert_eq!(e.error.code, code::INVALID_PARAMS);
    }

    #[test]
    fn writes_responses() {
        let ok = response(&Id::Num(3), Ok(serde_json::json!({"a": 1})));
        let v: Value = serde_json::from_str(&ok).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"jsonrpc": "2.0", "id": 3, "result": {"a": 1}})
        );
        let err = response(&Id::Str("q".into()), Err(RpcError::denied("no")));
        let v: Value = serde_json::from_str(&err).unwrap();
        assert_eq!(v["error"]["code"], code::DENIED);
        assert_eq!(v["id"], "q");
    }
}
