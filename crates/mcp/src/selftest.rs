//! `computer-use test`: does the server answer, see the screen and move the
//! pointer? Each step says what it did and what failed, verbose enough to find
//! the cause on a machine nobody here can see.

use serde_json::{Map, Value, json};

use crate::client::Client;
use crate::pins::{ServerPin, ToolCall};

/// One line of the report; `ok` false marks a failed step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Step {
    pub ok: bool,
    pub text: String,
}

/// The pointer is moved this far to the right and back.
pub const NUDGE: i64 = 10;

/// Runs the steps on a started client: the tool list, a screenshot (a
/// non-empty image), and the pointer moved `NUDGE` pixels, read back and moved
/// back.
pub async fn run(client: &mut Client, pin: &ServerPin, verbose: bool) -> Vec<Step> {
    let mut out = Vec::new();
    let mut step = |ok: bool, text: String| out.push(Step { ok, text });
    match client.list_tools().await {
        Ok(tools) => {
            let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
            let allowed = pin.allowed();
            let missing: Vec<&String> = allowed
                .iter()
                .filter(|a| !names.contains(&a.as_str()))
                .collect();
            step(
                missing.is_empty(),
                format!(
                    "{} {} answers and lists {} tools{}",
                    pin.name,
                    pin.version,
                    tools.len(),
                    if missing.is_empty() {
                        String::new()
                    } else {
                        format!("; allowed but not offered: {}", join(&missing))
                    }
                ),
            );
            if verbose {
                let denied: Vec<&&str> = names
                    .iter()
                    .filter(|n| !allowed.iter().any(|a| a == **n))
                    .collect();
                step(true, format!("  offered: {}", names.join(", ")));
                step(true, format!("  not allowed here: {}", join(&denied)));
            }
        }
        Err(e) => {
            step(false, format!("tools/list failed: {e}"));
            return out;
        }
    }
    match call(client, &pin.selftest.screenshot, verbose).await {
        Ok(r) => match first_image(&r) {
            Some((mime, bytes)) if bytes > 0 => {
                step(true, format!("screenshot: a {mime} image of {bytes} bytes"))
            }
            _ => step(
                false,
                format!("screenshot: no image in the answer: {}", clip(&r)),
            ),
        },
        Err(e) => step(
            false,
            format!("screenshot ({}): {e}", pin.selftest.screenshot.tool),
        ),
    }
    let Some(p) = &pin.selftest.pointer else {
        step(
            true,
            "pointer: this server has no position to read back; not tested".into(),
        );
        return out;
    };
    let pos = match call(client, &p.position, verbose)
        .await
        .map(|r| position(&r))
    {
        Ok(Some(pos)) => pos,
        Ok(None) => {
            step(
                false,
                format!("pointer: {} gave no position", p.position.tool),
            );
            return out;
        }
        Err(e) => {
            step(false, format!("pointer: {}: {e}", p.position.tool));
            return out;
        }
    };
    step(true, format!("pointer is at {}, {}", pos.0, pos.1));
    let target = (pos.0 + NUDGE, pos.1);
    if let Err(e) = call(client, &with_xy(&p.move_to, target), verbose).await {
        step(false, format!("pointer: {} failed: {e}", p.move_to.tool));
        return out;
    }
    match call(client, &p.position, verbose)
        .await
        .map(|r| position(&r))
    {
        Ok(Some(now)) if (now.0 - target.0).abs() <= 1 && (now.1 - target.1).abs() <= 1 => step(
            true,
            format!(
                "pointer moved {NUDGE} px to {}, {} and was read back",
                now.0, now.1
            ),
        ),
        Ok(Some(now)) => step(
            false,
            format!(
                "pointer: moved to {}, {} but it is at {}, {} (on GNOME: did you allow pointer and keyboard in the remote desktop prompt?)",
                target.0, target.1, now.0, now.1
            ),
        ),
        Ok(None) => step(false, "pointer: no position after the move".into()),
        Err(e) => step(false, format!("pointer: {e}")),
    }
    match call(client, &with_xy(&p.move_to, pos), verbose).await {
        Ok(_) => step(true, format!("pointer moved back to {}, {}", pos.0, pos.1)),
        Err(e) => step(false, format!("pointer: moving back failed: {e}")),
    }
    out
}

async fn call(client: &mut Client, c: &ToolCall, _verbose: bool) -> Result<Value, String> {
    let raw = client
        .call(&c.tool, &c.args)
        .await
        .map_err(|e| e.to_string())?;
    if raw.get("isError") == Some(&Value::Bool(true)) {
        return Err(format!("the tool reported an error: {}", clip(&raw)));
    }
    Ok(raw)
}

fn join<T: AsRef<str>>(v: &[T]) -> String {
    if v.is_empty() {
        return "none".into();
    }
    v.iter().map(|s| s.as_ref()).collect::<Vec<_>>().join(", ")
}

fn clip(v: &Value) -> String {
    let s = v.to_string();
    sync_policy::approve::visible(&s.chars().take(300).collect::<String>())
}

fn first_image(r: &Value) -> Option<(String, usize)> {
    use base64::Engine as _;
    r.get("content")?.as_array()?.iter().find_map(|c| {
        (c.get("type")? == "image").then(|| {
            let data = c.get("data").and_then(Value::as_str).unwrap_or("");
            let n = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map(|d| d.len())
                .unwrap_or(0);
            (
                c.get("mimeType")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_string(),
                n,
            )
        })
    })
}

/// A position from a tool's answer: `x` and `y` of a JSON object in the text
/// (or `structuredContent`), else the first two integers of the text.
pub fn position(r: &Value) -> Option<(i64, i64)> {
    let xy = |v: &Value| Some((v.get("x")?.as_f64()? as i64, v.get("y")?.as_f64()? as i64));
    if let Some(p) = r.get("structuredContent").and_then(xy) {
        return Some(p);
    }
    let texts: Vec<&str> = r
        .get("content")?
        .as_array()?
        .iter()
        .filter_map(|c| c.get("text").and_then(Value::as_str))
        .collect();
    for t in &texts {
        if let Ok(v) = serde_json::from_str::<Value>(t)
            && let Some(p) = xy(&v)
        {
            return Some(p);
        }
    }
    let text = texts.join(" ");
    let mut nums = text
        .split(|c: char| !(c.is_ascii_digit() || c == '-'))
        .filter_map(|w| w.parse::<i64>().ok());
    Some((nums.next()?, nums.next()?))
}

/// `move_to` with `"$x"` and `"$y"` replaced by the position.
fn with_xy(c: &ToolCall, (x, y): (i64, i64)) -> ToolCall {
    fn fill(v: &Value, x: i64, y: i64) -> Value {
        match v {
            Value::String(s) if s == "$x" => json!(x),
            Value::String(s) if s == "$y" => json!(y),
            Value::Array(a) => Value::Array(a.iter().map(|v| fill(v, x, y)).collect()),
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, v)| (k.clone(), fill(v, x, y)))
                    .collect::<Map<_, _>>(),
            ),
            v => v.clone(),
        }
    }
    ToolCall {
        tool: c.tool.clone(),
        args: c
            .args
            .iter()
            .map(|(k, v)| (k.clone(), fill(v, x, y)))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_are_read_in_several_forms() {
        let text = |t: &str| json!({"content": [{"type": "text", "text": t}]});
        assert_eq!(position(&text("{\"x\": 10, \"y\": 20}")), Some((10, 20)));
        assert_eq!(position(&text("Cursor at (300, 400)")), Some((300, 400)));
        assert_eq!(
            position(&json!({"content": [], "structuredContent": {"x": 1.0, "y": 2.0}})),
            Some((1, 2))
        );
        assert_eq!(position(&text("nowhere")), None);
        let c = ToolCall {
            tool: "move".into(),
            args: json!({"x": "$x", "y": "$y", "to": ["$x", "$y"]})
                .as_object()
                .unwrap()
                .clone(),
        };
        let m = with_xy(&c, (5, 6));
        assert_eq!(Value::Object(m.args), json!({"x": 5, "y": 6, "to": [5, 6]}));
    }
}
