//! Checking a call's arguments against the input schema the server listed,
//! before the server sees them. A subset of JSON Schema, the part tool schemas
//! use: `type` (one or several), `properties`, `required`, `enum`, `const`,
//! array `items`, and the bounds of numbers, strings and arrays. A property
//! the schema does not name is refused at every depth, whatever
//! `additionalProperties` says: the device takes only what it can show and
//! check. Keywords outside this subset add no check.

use serde_json::{Map, Value};

/// How deep the arguments and the schema may nest.
const MAX_DEPTH: usize = 32;

/// Checks `args` against `schema` (a tool's `inputSchema`, an object schema).
pub fn check(schema: &Value, args: &Map<String, Value>) -> Result<(), String> {
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err("the tool's input schema is not an object schema".into());
    }
    check_value(schema, &Value::Object(args.clone()), "args", 0)
}

fn type_ok(t: &str, v: &Value) -> bool {
    match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "number" => v.is_number(),
        "integer" => {
            v.as_i64().is_some()
                || v.as_u64().is_some()
                || v.as_f64()
                    .is_some_and(|f| f.fract() == 0.0 && f.is_finite())
        }
        _ => false,
    }
}

fn check_value(schema: &Value, v: &Value, at: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{at}: nested too deep"));
    }
    let Some(s) = schema.as_object() else {
        // `true` takes anything; `false` nothing.
        return match schema {
            Value::Bool(false) => Err(format!("{at}: not allowed")),
            _ => Ok(()),
        };
    };
    match s.get("type") {
        Some(Value::String(t)) if !type_ok(t, v) => {
            return Err(format!("{at}: must be {t}"));
        }
        Some(Value::Array(ts)) if !ts.iter().filter_map(Value::as_str).any(|t| type_ok(t, v)) => {
            return Err(format!("{at}: has none of the types the tool takes"));
        }
        _ => {}
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array)
        && !e.contains(v)
    {
        return Err(format!("{at}: not one of the values the tool takes"));
    }
    if let Some(c) = s.get("const")
        && c != v
    {
        return Err(format!("{at}: not the value the tool takes"));
    }
    if let Some(n) = v.as_f64() {
        if let Some(min) = s.get("minimum").and_then(Value::as_f64)
            && n < min
        {
            return Err(format!("{at}: below {min}"));
        }
        if let Some(max) = s.get("maximum").and_then(Value::as_f64)
            && n > max
        {
            return Err(format!("{at}: above {max}"));
        }
    }
    if let Some(text) = v.as_str() {
        let n = text.chars().count() as u64;
        if s.get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n > m)
        {
            return Err(format!("{at}: too long"));
        }
        if s.get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n < m)
        {
            return Err(format!("{at}: too short"));
        }
    }
    if let Some(items) = v.as_array() {
        let n = items.len() as u64;
        if s.get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| n > m)
        {
            return Err(format!("{at}: too many items"));
        }
        if s.get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| n < m)
        {
            return Err(format!("{at}: too few items"));
        }
        if let Some(item) = s.get("items") {
            for (i, x) in items.iter().enumerate() {
                check_value(item, x, &format!("{at}[{i}]"), depth + 1)?;
            }
        }
    }
    if let Some(obj) = v.as_object() {
        let props = s.get("properties").and_then(Value::as_object);
        let empty = Map::new();
        let props = props.unwrap_or(&empty);
        for (k, x) in obj {
            let Some(p) = props.get(k) else {
                return Err(format!("{at}: the tool takes no property {k:?}"));
            };
            check_value(p, x, &format!("{at}.{k}"), depth + 1)?;
        }
        if let Some(req) = s.get("required").and_then(Value::as_array) {
            for r in req.iter().filter_map(Value::as_str) {
                if !obj.contains_key(r) {
                    return Err(format!("{at}: {r:?} is required"));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn checks_types_required_and_unknown_properties() {
        let schema = json!({
            "type": "object",
            "properties": {
                "x": {"type": "integer", "minimum": 0},
                "y": {"type": "integer"},
                "button": {"type": "string", "enum": ["left", "right"]},
                "text": {"type": "string", "maxLength": 5},
                "keys": {"type": "array", "items": {"type": "string"}},
                "opt": {"type": ["string", "null"]},
                "point": {"type": "object", "properties": {"x": {"type": "number"}}}
            },
            "required": ["x", "y"]
        });
        assert!(check(&schema, &args(json!({"x": 1, "y": 2}))).is_ok());
        assert!(check(&schema, &args(json!({"x": 1, "y": 2, "button": "left", "keys": ["a"], "opt": null, "point": {"x": 1.5}}))).is_ok());
        for bad in [
            json!({"x": 1}),
            json!({"x": "1", "y": 2}),
            json!({"x": 1.5, "y": 2}),
            json!({"x": -1, "y": 2}),
            json!({"x": 1, "y": 2, "button": "middle"}),
            json!({"x": 1, "y": 2, "text": "toolong"}),
            json!({"x": 1, "y": 2, "keys": ["a", 1]}),
            json!({"x": 1, "y": 2, "opt": 3}),
            json!({"x": 1, "y": 2, "z": 3}),
            json!({"x": 1, "y": 2, "point": {"x": 1, "cmd": "rm"}}),
        ] {
            assert!(check(&schema, &args(bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_schema_that_names_nothing_takes_nothing() {
        let schema = json!({"type": "object"});
        assert!(check(&schema, &Map::new()).is_ok());
        assert!(check(&schema, &args(json!({"a": 1}))).is_err());
        // additionalProperties does not open the door.
        let open = json!({"type": "object", "additionalProperties": true});
        assert!(check(&open, &args(json!({"a": 1}))).is_err());
        assert!(check(&json!({"type": "string"}), &Map::new()).is_err());
    }
}
