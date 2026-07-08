use serde_json::json;

use super::{strip_null_object_members, validate_arguments};

fn object_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "query": { "type": "string" },
            "limit": { "type": "integer", "minimum": 1 }
        },
        "required": ["query"],
        "additionalProperties": false
    })
}

#[test]
fn accepts_conforming_arguments() {
    let schema = object_schema();
    let args = json!({ "query": "hello", "limit": 3 });
    assert!(validate_arguments(&args, &schema).is_ok());
}

#[test]
fn rejects_missing_required_field() {
    let schema = object_schema();
    let args = json!({ "limit": 3 });
    let err = validate_arguments(&args, &schema).unwrap_err();
    assert!(!err.is_empty());
    assert!(err.to_lowercase().contains("query") || err.to_lowercase().contains("required"));
}

#[test]
fn rejects_wrong_type() {
    let schema = object_schema();
    let args = json!({ "query": 123 });
    assert!(validate_arguments(&args, &schema).is_err());
}

#[test]
fn rejects_unknown_property() {
    let schema = object_schema();
    let args = json!({ "query": "x", "unexpected": true });
    assert!(validate_arguments(&args, &schema).is_err());
}

#[test]
fn skips_validation_when_schema_uncompilable() {
    // A schema whose `type` is not a valid JSON Schema type keyword makes
    // compilation fail; validation is skipped (Ok) rather than blocking.
    let bad_schema = json!({ "type": 42 });
    let args = json!({ "anything": true });
    assert!(validate_arguments(&args, &bad_schema).is_ok());
}

#[test]
fn empty_object_schema_accepts_anything() {
    let schema = json!({ "type": "object" });
    let args = json!({ "a": 1, "b": "two" });
    assert!(validate_arguments(&args, &schema).is_ok());
}

#[test]
fn summary_is_bounded() {
    // Many violations must still yield a bounded summary string.
    let schema = json!({
        "type": "object",
        "properties": {
            "a": { "type": "string" },
            "b": { "type": "string" },
            "c": { "type": "string" },
            "d": { "type": "string" },
            "e": { "type": "string" },
            "f": { "type": "string" }
        },
        "additionalProperties": false
    });
    let args = json!({ "a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6, "g": 7 });
    let err = validate_arguments(&args, &schema).unwrap_err();
    assert!(err.chars().count() <= 512);
}

// ── strip_null_object_members ────────────────────────────────────────

#[test]
fn strip_nulls_removes_null_optional_args_and_passes_validation() {
    let schema = object_schema();
    // Model emits explicit nulls for the optional `limit`.
    let raw = json!({ "query": "hello", "limit": null });
    assert!(
        validate_arguments(&raw, &schema).is_err(),
        "raw null must fail against a non-nullable integer schema"
    );

    let cleaned = strip_null_object_members(raw);
    assert_eq!(cleaned, json!({ "query": "hello" }));
    assert!(validate_arguments(&cleaned, &schema).is_ok());
}

#[test]
fn strip_nulls_recurses_into_nested_objects() {
    let value = json!({
        "a": 1,
        "b": null,
        "nested": { "keep": "x", "drop": null }
    });
    assert_eq!(
        strip_null_object_members(value),
        json!({ "a": 1, "nested": { "keep": "x" } })
    );
}

#[test]
fn strip_nulls_preserves_array_element_positions() {
    // Nulls inside arrays are positionally significant and must be kept;
    // null members of objects *within* arrays are still stripped.
    let value = json!({ "arr": [1, null, { "k": "v", "gone": null }] });
    assert_eq!(
        strip_null_object_members(value),
        json!({ "arr": [1, null, { "k": "v" }] })
    );
}

#[test]
fn strip_nulls_leaves_missing_required_field_missing() {
    let schema = object_schema();
    // A required field emitted as null is dropped, surfacing a clear
    // "missing required" error rather than a "wrong type" one.
    let cleaned = strip_null_object_members(json!({ "query": null, "limit": 2 }));
    assert_eq!(cleaned, json!({ "limit": 2 }));
    assert!(validate_arguments(&cleaned, &schema).is_err());
}
