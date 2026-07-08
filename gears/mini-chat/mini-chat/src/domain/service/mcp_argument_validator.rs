//! Pre-dispatch validation of LLM-generated MCP tool arguments.
//!
//! Every `tools/call` dispatch MUST validate the model's arguments against the
//! tool's normalized JSON Schema (the source of truth carried in the routing
//! map) *before* the MCP server is contacted. Arguments are untrusted model
//! output; a malformed call is rejected locally and surfaced back to the model
//! as a bounded `function_call_output` so it can correct itself, without ever
//! reaching the server.
//!
//! The function is pure and side-effect free apart from a diagnostic log when a
//! tool's own schema cannot be compiled. In that (rare) case validation is
//! skipped — the schema was already size-capped and normalized at resolution
//! time, and permanently blocking a tool because its advertised schema is not a
//! strict JSON Schema would be worse than forwarding the call.

use serde_json::Value;
use tracing::warn;

/// Maximum number of individual schema violations included in the summary.
const MAX_ERRORS: usize = 5;
/// Maximum characters kept per individual violation message.
const MAX_ERROR_CHARS: usize = 200;
/// Maximum characters kept for the joined summary returned to the model.
const MAX_SUMMARY_CHARS: usize = 512;

/// Validate `arguments` against `schema`.
///
/// Returns `Ok(())` when the arguments conform, or when the schema itself
/// cannot be compiled (validation skipped, logged). Returns `Err(summary)`
/// with a bounded, human-readable description of the violations otherwise.
pub fn validate_arguments(arguments: &Value, schema: &Value) -> Result<(), String> {
    let validator = match jsonschema::validator_for(schema) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                error = %e,
                "MCP tool input schema failed to compile; skipping argument validation"
            );
            return Ok(());
        }
    };

    if validator.is_valid(arguments) {
        return Ok(());
    }

    let mut messages: Vec<String> = Vec::with_capacity(MAX_ERRORS);
    for err in validator.iter_errors(arguments).take(MAX_ERRORS) {
        let path = err.instance_path().to_string();
        let raw = if path.is_empty() {
            err.to_string()
        } else {
            format!("{path}: {err}")
        };
        messages.push(truncate_chars(&raw, MAX_ERROR_CHARS));
    }

    if messages.is_empty() {
        // Defensive: is_valid said invalid but no errors were yielded.
        messages.push("arguments did not match the tool schema".to_owned());
    }

    Err(truncate_chars(&messages.join("; "), MAX_SUMMARY_CHARS))
}

/// Recursively drop object members whose value is JSON `null`.
///
/// Models frequently emit explicit `null` for optional tool arguments they do
/// not want to set (e.g. `{"fields": null, "comment_limit": null}`). Most MCP
/// tool schemas type those properties as `string`/`integer`/… (not nullable),
/// so a literal `null` fails schema validation, is rejected pre-dispatch, and
/// the model retries — often looping until the tool-use budget is exhausted.
/// Stripping null members matches the model's intent ("not provided") and keeps
/// the call clean for the server. Array elements are preserved (position is
/// significant); nested objects are normalized recursively.
#[must_use]
pub fn strip_null_object_members(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, strip_null_object_members(v)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(strip_null_object_members).collect())
        }
        other => other,
    }
}

/// Truncate `s` to at most `max` characters on a char boundary, appending an
/// ellipsis marker when truncation occurs.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let keep = max.saturating_sub(3);
    let mut out: String = s.chars().take(keep).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
#[path = "mcp_argument_validator_test.rs"]
mod mcp_argument_validator_test;
