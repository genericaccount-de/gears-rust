//! MCP tool name / schema / description normalization.
//!
//! Tool names, descriptions, and input schemas reported by MCP servers are
//! untrusted. Before an MCP tool is exposed to an LLM provider it must be
//! rewritten into a provider-safe shape:
//!
//! - **Exposed name** — `mcp__<hash>__<tool>` with a bounded length and a
//!   restricted character set. The `<hash>` disambiguates identical tool names
//!   across servers; reversal to the origin server/tool is done through the
//!   per-request routing map, never by decoding the name.
//! - **Input schema** — reduced to the provider-supported JSON Schema subset
//!   (drop `$`-prefixed and unsupported keywords, force an object root).
//! - **Description** — stripped of control characters and truncated.
//!
//! All functions are pure; size caps are applied by callers (the resolver)
//! against `mcp.max_tool_schema_bytes` so an oversized schema becomes a
//! recorded diagnostic rather than a normalization failure.

use serde_json::Value;
use uuid::Uuid;

/// Provider function-name limit. Both `OpenAI` and Anthropic cap tool/function
/// names at 64 characters.
pub const EXPOSED_NAME_MAX: usize = 64;

/// Fixed prefix marking a mini-chat MCP-exposed tool. Used both to build
/// exposed names and to recognize MCP tools among generic function tools.
pub const MCP_TOOL_PREFIX: &str = "mcp__";

/// Length of the hex hash segment embedded in the exposed name.
const HASH_LEN: usize = 8;

/// JSON Schema keywords the provider function-tool subset does not accept.
/// Any `$`-prefixed key is also dropped (covers `$schema`, `$id`, `$ref`,
/// `$defs`, `$comment`, `$anchor`, `$dynamicRef`, `$dynamicAnchor`, …).
const UNSUPPORTED_KEYS: &[&str] = &["definitions"];

/// Build a deterministic, provider-safe exposed name for a tool.
///
/// Format: `mcp__<hash8>__<sanitized_tool_name>`, bounded to
/// [`EXPOSED_NAME_MAX`]. The hash is derived from the server id so identical
/// tool names on different servers never collide.
#[must_use]
pub fn exposed_name(server_id: Uuid, original: &str) -> String {
    let hash = format!("{:016x}", fnv1a_64(server_id.as_bytes()));
    let head = format!("{MCP_TOOL_PREFIX}{}__", &hash[..HASH_LEN]);
    let budget = EXPOSED_NAME_MAX.saturating_sub(head.len());
    let sanitized: String = original
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(budget)
        .collect();
    format!("{head}{sanitized}")
}

/// Reduce an MCP tool input schema to the provider-supported JSON Schema
/// subset: recursively drop `$`-prefixed and unsupported keywords and force an
/// object root (providers require `type: "object"` for function parameters).
#[must_use]
pub fn normalize_schema(schema: &Value) -> Value {
    let stripped = strip_unsupported(schema);
    match stripped {
        Value::Object(mut map) => {
            map.entry("type")
                .or_insert_with(|| Value::String("object".to_owned()));
            Value::Object(map)
        }
        // A non-object schema cannot be a function-parameter root; replace it
        // with a permissive empty object schema.
        _ => serde_json::json!({ "type": "object", "properties": {} }),
    }
}

/// Serialized byte length of a (normalized) schema, used by callers to enforce
/// the `max_tool_schema_bytes` cap.
#[must_use]
pub fn serialized_len(schema: &Value) -> usize {
    serde_json::to_vec(schema).map_or(0, |v| v.len())
}

/// Strip control characters, collapse runs of whitespace, and truncate a tool
/// description to `max_chars`.
#[must_use]
pub fn sanitize_description(desc: &str, max_chars: usize) -> String {
    // Drop non-whitespace control chars; keep whitespace controls (\n, \t, …)
    // so adjacent words stay separated, then let split_whitespace collapse runs.
    let cleaned: String = desc
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max_chars {
        collapsed
    } else {
        collapsed.chars().take(max_chars).collect()
    }
}

/// Stable digest of a schema, used for routing/observability and change
/// detection (never for argument validation).
#[must_use]
pub fn schema_hash(schema: &Value) -> String {
    format!("{:016x}", fnv1a_64(&serde_json::to_vec(schema).unwrap_or_default()))
}

/// FNV-1a 64-bit hash (stable, dependency-free).
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Recursively remove `$`-prefixed and unsupported keys from an object schema.
fn strip_unsupported(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                if k.starts_with('$') || UNSUPPORTED_KEYS.contains(&k.as_str()) {
                    continue;
                }
                out.insert(k.clone(), strip_unsupported(val));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(strip_unsupported).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposed_name_is_deterministic_and_safe() {
        let sid = Uuid::now_v7();
        let a = exposed_name(sid, "weird name!/*");
        let b = exposed_name(sid, "weird name!/*");
        assert_eq!(a, b);
        assert!(a.starts_with("mcp__"));
        assert!(a.len() <= EXPOSED_NAME_MAX);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
    }

    #[test]
    fn exposed_name_differs_across_servers() {
        let a = exposed_name(Uuid::now_v7(), "search");
        let b = exposed_name(Uuid::now_v7(), "search");
        assert_ne!(a, b);
    }

    #[test]
    fn exposed_name_is_length_bounded_for_long_tool_names() {
        let long = "a".repeat(200);
        let name = exposed_name(Uuid::now_v7(), &long);
        assert!(name.len() <= EXPOSED_NAME_MAX);
        assert!(name.starts_with("mcp__"));
    }

    #[test]
    fn normalize_forces_object_root() {
        let normalized = normalize_schema(&serde_json::json!("not-an-object"));
        assert_eq!(normalized["type"], "object");
    }

    #[test]
    fn normalize_adds_missing_type() {
        let normalized = normalize_schema(&serde_json::json!({
            "properties": { "q": { "type": "string" } }
        }));
        assert_eq!(normalized["type"], "object");
        assert!(normalized["properties"]["q"].is_object());
    }

    #[test]
    fn normalize_strips_dollar_and_unsupported_keys() {
        let normalized = normalize_schema(&serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:x",
            "type": "object",
            "definitions": { "X": { "type": "string" } },
            "properties": {
                "a": { "$ref": "#/definitions/X", "type": "string" }
            }
        }));
        let obj = normalized.as_object().unwrap();
        assert!(!obj.contains_key("$schema"));
        assert!(!obj.contains_key("$id"));
        assert!(!obj.contains_key("definitions"));
        let a = &normalized["properties"]["a"];
        assert!(a.get("$ref").is_none());
        assert_eq!(a["type"], "string");
    }

    #[test]
    fn sanitize_description_strips_controls_and_truncates() {
        let out = sanitize_description("  hello\n\tworld\u{0007}  ", 100);
        assert_eq!(out, "hello world");
        let capped = sanitize_description(&"x".repeat(50), 10);
        assert_eq!(capped.chars().count(), 10);
    }

    #[test]
    fn schema_hash_is_stable_and_distinguishing() {
        let s1 = serde_json::json!({"type": "object"});
        let s2 = serde_json::json!({"type": "string"});
        assert_eq!(schema_hash(&s1), schema_hash(&s1));
        assert_ne!(schema_hash(&s1), schema_hash(&s2));
    }
}
