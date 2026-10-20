//! Canonical JSON, as the extension requires for anything that gets signed.
//!
//! The rule is the one the text states: an identifier must recompute from the body. That only
//! works if both sides serialise the same way, so keys are sorted and no whitespace is emitted.

use serde_json::{Map, Value};

pub fn canonical(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|key| {
                    let name = serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string());
                    format!("{}:{}", name, canonical(&map[*key]))
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

pub fn object(pairs: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

pub fn strings(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|item| Value::String(item.to_string())).collect())
}
