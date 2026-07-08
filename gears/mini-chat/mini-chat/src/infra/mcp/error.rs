//! Error types for the MCP client layer.

use thiserror::Error;

/// Errors produced by the MCP transport / client / pool.
#[derive(Debug, Error)]
pub enum McpError {
    /// The OAGW proxy call failed (network, gateway, or upstream error).
    #[error("MCP transport error: {0}")]
    Transport(String),

    /// The server returned an HTTP status indicating session expiry (404).
    #[error("MCP session expired")]
    SessionExpired,

    /// The server returned a non-success HTTP status.
    #[error("MCP HTTP error: status {status}")]
    Http { status: u16 },

    /// The JSON-RPC response contained an `error` object.
    #[error("MCP JSON-RPC error {code}: {message}")]
    JsonRpc { code: i64, message: String },

    /// The response body could not be parsed.
    #[error("MCP protocol error: {0}")]
    Protocol(String),

    /// A response body exceeded the configured byte limit.
    #[error("MCP response exceeded {limit} byte limit")]
    ResponseTooLarge { limit: usize },

    /// The per-call timeout elapsed.
    #[error("MCP call timed out after {secs}s")]
    Timeout { secs: u64 },

    /// The per-server circuit breaker is open.
    #[error("MCP server circuit breaker open")]
    CircuitOpen,

    /// A referenced server is not registered in the pool.
    #[error("MCP server not found: {0}")]
    ServerNotFound(String),
}

impl McpError {
    /// A short, stable class label for metrics/audit (never includes detail).
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            Self::Transport(_) => "transport",
            Self::SessionExpired => "session_expired",
            Self::Http { .. } => "http",
            Self::JsonRpc { .. } => "jsonrpc",
            Self::Protocol(_) => "protocol",
            Self::ResponseTooLarge { .. } => "response_too_large",
            Self::Timeout { .. } => "timeout",
            Self::CircuitOpen => "circuit_open",
            Self::ServerNotFound(_) => "server_not_found",
        }
    }

    /// A bounded, non-leaky message describing this failure to the model as a
    /// `function_call_output`, so it can recover within the agentic loop.
    ///
    /// The wording is class-specific and actionable — never echoes raw server
    /// detail. A timeout in particular nudges the model to retry with a
    /// *narrower* request (fewer fields / smaller expansions) rather than
    /// repeating the same expensive call or giving up, which is the common
    /// cause of a slow tool (e.g. a Jira lookup with `fields: "*all"`).
    #[must_use]
    pub fn model_facing_message(&self, tool_name: &str) -> String {
        match self {
            Self::Timeout { secs } => format!(
                "Tool `{tool_name}` timed out after {secs}s. The request was likely too large \
                 or the server too slow. Retry with a narrower request (for example, ask for \
                 fewer or specific `fields` and avoid large expansions), or answer using the \
                 information already available."
            ),
            Self::CircuitOpen | Self::ServerNotFound(_) => format!(
                "Tool `{tool_name}` is temporarily unavailable ({}); answer without it or try \
                 again later.",
                self.class()
            ),
            _ => format!(
                "Tool `{tool_name}` failed ({}); answer without it or try a different approach.",
                self.class()
            ),
        }
    }
}

pub type McpResult<T> = Result<T, McpError>;

#[cfg(test)]
mod tests {
    use super::McpError;

    #[test]
    fn timeout_message_nudges_narrower_request() {
        let msg = McpError::Timeout { secs: 30 }.model_facing_message("jira_get_issue");
        assert!(msg.contains("jira_get_issue"));
        assert!(msg.contains("30s"));
        assert!(msg.to_lowercase().contains("narrower"));
        assert!(msg.contains("`fields`"));
    }

    #[test]
    fn unavailable_classes_are_retryable_wording() {
        for e in [
            McpError::CircuitOpen,
            McpError::ServerNotFound("srv".to_owned()),
        ] {
            let msg = e.model_facing_message("t");
            assert!(msg.contains("temporarily unavailable"), "got: {msg}");
            assert!(msg.contains(e.class()));
        }
    }

    #[test]
    fn other_errors_use_generic_message() {
        let msg = McpError::Transport("boom".to_owned()).model_facing_message("t");
        assert!(msg.contains("failed (transport)"));
        // Never echoes raw server detail.
        assert!(!msg.contains("boom"));
    }
}
