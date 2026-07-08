//! DLP (data-loss-prevention) redaction for MCP tool output.
//!
//! MCP `tools/call` output is untrusted external data that re-enters the model
//! conversation as a `function_call_output`. Operators may configure regex
//! patterns (`mcp.dlp_redaction_patterns`) whose matches are replaced with a
//! fixed placeholder before the output is truncated and injected, so sensitive
//! strings surfaced by a tool never reach the model or the transcript.
//!
//! The policy is operator-driven (no built-in PII heuristics), so there are no
//! false-positive surprises: an empty pattern set is a no-op and leaves output
//! untouched. Patterns are compiled once at construction; invalid patterns are
//! rejected by config validation and defensively skipped here.

use regex::Regex;

/// Replacement substituted for each DLP match.
const REDACTION_PLACEHOLDER: &str = "[REDACTED]";

/// Operator-configured redactor applied to MCP tool output. Holds compiled
/// patterns; an empty set is a no-op (redaction disabled).
#[derive(Default)]
pub struct DlpRedactor {
    patterns: Vec<Regex>,
}

impl DlpRedactor {
    /// Compile `patterns` into a redactor. Patterns that fail to compile are
    /// logged and skipped (config validation rejects them up front, so this is
    /// a defensive fallback). An empty slice yields a no-op redactor.
    #[must_use]
    pub fn new(patterns: &[String]) -> Self {
        let compiled = patterns
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(re) => Some(re),
                Err(e) => {
                    tracing::warn!(
                        pattern = %p,
                        error = %e,
                        "invalid MCP DLP redaction pattern; skipping"
                    );
                    None
                }
            })
            .collect();
        Self { patterns: compiled }
    }

    /// Replace every match of every configured pattern in `input` with the
    /// redaction placeholder. Returns `input` unchanged when no patterns are
    /// configured.
    #[must_use]
    pub fn redact(&self, input: &str) -> String {
        if self.patterns.is_empty() {
            return input.to_owned();
        }
        let mut out = input.to_owned();
        for re in &self.patterns {
            out = re.replace_all(&out, REDACTION_PLACEHOLDER).into_owned();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_redactor_is_noop() {
        let redactor = DlpRedactor::new(&[]);
        assert_eq!(redactor.redact("secret token abc123"), "secret token abc123");
    }

    #[test]
    fn redacts_single_pattern() {
        let redactor = DlpRedactor::new(&[r"\bsk-[A-Za-z0-9]{6,}\b".to_owned()]);
        let out = redactor.redact("key is sk-abcdef123456 ok");
        assert_eq!(out, "key is [REDACTED] ok");
    }

    #[test]
    fn redacts_multiple_patterns_and_occurrences() {
        let redactor = DlpRedactor::new(&[
            r"\d{3}-\d{2}-\d{4}".to_owned(),
            r"[\w.]+@[\w.]+".to_owned(),
        ]);
        let out = redactor.redact("ssn 123-45-6789 mail a@b.com and 987-65-4321");
        assert_eq!(out, "ssn [REDACTED] mail [REDACTED] and [REDACTED]");
    }

    #[test]
    fn invalid_pattern_is_skipped() {
        // First pattern is invalid (unbalanced paren); second is valid.
        let redactor = DlpRedactor::new(&["(".to_owned(), r"top-secret".to_owned()]);
        assert_eq!(redactor.redact("this is top-secret data"), "this is [REDACTED] data");
    }
}
