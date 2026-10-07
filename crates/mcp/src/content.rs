//! A server's `tools/call` result as the portal gets it: text and images only,
//! within the protocol's limits (`docs/protocol.md`, `mcp.call`). Anything
//! else the server answers fails the call; nothing of it is passed on half.

use base64::Engine as _;
use serde_json::Value;
use sync_proto::methods::{
    MAX_MCP_IMAGE, MAX_MCP_ITEMS, MAX_MCP_RESULT, MAX_MCP_TEXT, MCP_IMAGE_TYPES, McpCallResult,
    McpContent,
};

/// Keys a content item may carry beside its own; their values are not passed on.
const IGNORED: &[&str] = &["annotations", "_meta"];

pub fn convert(result: &Value) -> Result<McpCallResult, String> {
    let items = result
        .get("content")
        .and_then(Value::as_array)
        .ok_or("the result has no content list")?;
    if items.len() > MAX_MCP_ITEMS {
        return Err(format!("more than {MAX_MCP_ITEMS} content items"));
    }
    let is_error = match result.get("isError") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("isError is not a boolean".into()),
    };
    let mut text_total = 0usize;
    let mut content = Vec::new();
    for item in items {
        let obj = item
            .as_object()
            .ok_or("a content item that is not an object")?;
        let kind = obj.get("type").and_then(Value::as_str).unwrap_or("");
        let own: &[&str] = match kind {
            "text" => &["type", "text"],
            "image" => &["type", "data", "mimeType"],
            other => {
                return Err(format!(
                    "content of type {:?} is not passed on",
                    other.chars().take(32).collect::<String>()
                ));
            }
        };
        if let Some(k) = obj
            .keys()
            .find(|k| !own.contains(&k.as_str()) && !IGNORED.contains(&k.as_str()))
        {
            return Err(format!("a {kind} item with an unknown field {k:?}"));
        }
        match kind {
            "text" => {
                let text = obj
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or("a text item without text")?;
                text_total += text.len();
                if text_total > MAX_MCP_TEXT {
                    return Err(format!("more than {MAX_MCP_TEXT} bytes of text"));
                }
                content.push(McpContent::Text {
                    text: text.to_string(),
                });
            }
            _ => {
                let data = obj
                    .get("data")
                    .and_then(Value::as_str)
                    .ok_or("an image without data")?;
                let mime = obj
                    .get("mimeType")
                    .and_then(Value::as_str)
                    .ok_or("an image without a type")?;
                if !MCP_IMAGE_TYPES.contains(&mime) {
                    return Err(format!(
                        "an image of type {:?} is not passed on",
                        mime.chars().take(32).collect::<String>()
                    ));
                }
                if data.len() > MAX_MCP_IMAGE {
                    return Err(format!("an image over {MAX_MCP_IMAGE} bytes of base64"));
                }
                if base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .is_err()
                {
                    return Err("an image whose data is not base64".into());
                }
                content.push(McpContent::Image {
                    mime: mime.to_string(),
                    data: data.to_string(),
                });
            }
        }
    }
    let r = McpCallResult { content, is_error };
    let size = serde_json::to_string(&r)
        .map(|s| s.len())
        .unwrap_or(usize::MAX);
    if size > MAX_MCP_RESULT {
        return Err(format!("the result is over {MAX_MCP_RESULT} bytes"));
    }
    Ok(r)
}

/// All text of a result, for the device's own checks (the focus check, the
/// self-test).
pub fn text_of(r: &McpCallResult) -> String {
    r.content
        .iter()
        .filter_map(|c| match c {
            McpContent::Text { text } => Some(text.as_str()),
            McpContent::Image { .. } => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_and_images_pass_within_the_limits() {
        let r = convert(&json!({"content": [
            {"type": "text", "text": "ok", "annotations": {"audience": ["user"]}},
            {"type": "image", "data": "iVBORw0KGgo=", "mimeType": "image/png"}
        ]}))
        .unwrap();
        assert_eq!(r.content.len(), 2);
        assert!(!r.is_error);
        assert!(
            convert(&json!({"content": [], "isError": true}))
                .unwrap()
                .is_error
        );
    }

    #[test]
    fn anything_else_fails_the_call() {
        for bad in [
            json!({}),
            json!({"content": [{"type": "audio", "data": "AA==", "mimeType": "audio/wav"}]}),
            json!({"content": [{"type": "resource", "resource": {"uri": "file:///etc/passwd"}}]}),
            json!({"content": [{"type": "image", "data": "AA==", "mimeType": "image/svg+xml"}]}),
            json!({"content": [{"type": "image", "data": "not base64!", "mimeType": "image/png"}]}),
            json!({"content": [{"type": "text", "text": "x", "uri": "x"}]}),
            json!({"content": [{"type": "text"}]}),
            json!({"content": [{"type": "text", "text": "x"}], "isError": "yes"}),
            json!({"content": vec![json!({"type": "text", "text": "x"}); MAX_MCP_ITEMS + 1]}),
            json!({"content": [{"type": "text", "text": "x".repeat(MAX_MCP_TEXT + 1)}]}),
            json!({"content": [{"type": "image", "data": "A".repeat(MAX_MCP_IMAGE + 4), "mimeType": "image/png"}]}),
        ] {
            assert!(
                convert(&bad).is_err(),
                "{}",
                bad.to_string().chars().take(120).collect::<String>()
            );
        }
    }
}
