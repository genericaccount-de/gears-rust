//! MCP (Model Context Protocol) wire and domain types.
//!
//! Only the `tools/*` subset of the MCP specification is modelled — see
//! DESIGN.md §"MCP Scope Exclusions" (`resources/*` and `prompts/*` are out
//! of scope). Transport is HTTP Streamable via OAGW only; stdio is not
//! supported.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// MCP protocol version negotiated during `initialize`.
///
/// Sent as the `Mcp-Protocol-Version` header on every request after a
/// successful handshake (see [`OagwTransport`](crate::infra::mcp::OagwTransport)).
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// JSON-RPC version string (MCP mandates JSON-RPC 2.0).
pub const JSONRPC_VERSION: &str = "2.0";

/// HTTP header carrying the MCP session id across a session's lifetime.
pub const HEADER_MCP_SESSION_ID: &str = "mcp-session-id";
/// HTTP header carrying the negotiated MCP protocol version.
pub const HEADER_MCP_PROTOCOL_VERSION: &str = "mcp-protocol-version";
/// OAGW header used to pin a session to a specific upstream endpoint
/// (multi-endpoint session affinity — see DESIGN.md §"Session affinity").
pub const HEADER_OAGW_TARGET_HOST: &str = "x-oagw-target-host";

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Authentication configuration for an MCP server.
///
/// Mini-chat never resolves secrets directly. Each variant maps to an OAGW
/// built-in auth plugin (see `oagw_upstream::auth_config_for`). `secret_ref`
/// / `*_ref` values are credstore references (`cred://` URIs), never raw
/// secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpAuth {
    /// No authentication (maps to OAGW `noop` plugin).
    #[default]
    None,
    /// Bearer token in the `Authorization` header (maps to OAGW `apikey`).
    Bearer { secret_ref: String },
    /// Custom API-key header (maps to OAGW `apikey`).
    ApiKey { header: String, secret_ref: String },
    /// OAuth 2.0 client-credentials flow (maps to OAGW `oauth2_client_cred`).
    #[serde(rename = "oauth2", alias = "o_auth2")]
    OAuth2 {
        client_id_ref: String,
        client_secret_ref: String,
        token_url: String,
        #[serde(default)]
        scopes: Vec<String>,
    },
    /// Interactive OAuth 2.0 authorization-code flow (per-user). Carries no
    /// secret refs: OAGW owns dynamic client registration, PKCE, and the
    /// per-user token store. Maps to the OAGW `oauth2_auth_code` plugin.
    #[serde(
        rename = "oauth2_authorization_code",
        alias = "o_auth2_authorization_code"
    )]
    OAuth2AuthorizationCode {
        #[serde(default)]
        scopes: Vec<String>,
    },
}

impl McpAuth {
    /// Stable discriminant used for the `mcp_servers.auth_type` column.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bearer { .. } => "bearer",
            Self::ApiKey { .. } => "api_key",
            Self::OAuth2 { .. } => "oauth2",
            Self::OAuth2AuthorizationCode { .. } => "oauth2_auth_code",
        }
    }
}

// ---------------------------------------------------------------------------
// Trust level
// ---------------------------------------------------------------------------

/// Trust classification for a tool's output handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpTrustLevel {
    /// Output may be surfaced with minimal sanitization.
    Trusted,
    /// Output is sanitized and capped.
    Restricted,
    /// Output is fully sanitized, capped, and treated as hostile.
    #[default]
    Untrusted,
}

impl McpTrustLevel {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Restricted => "restricted",
            Self::Untrusted => "untrusted",
        }
    }

    #[must_use]
    pub fn from_str_or_default(s: &str) -> Self {
        match s {
            "trusted" => Self::Trusted,
            "restricted" => Self::Restricted,
            _ => Self::Untrusted,
        }
    }
}

// ---------------------------------------------------------------------------
// JSON-RPC envelopes
// ---------------------------------------------------------------------------

/// A JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    #[must_use]
    pub fn new(id: u64, method: &'static str, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            method,
            params,
        }
    }
}

/// A JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcResponse {
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    #[allow(dead_code)]
    pub id: Option<serde_json::Value>,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------

/// Result of the `initialize` handshake (subset we care about).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct InitializeResult {
    #[serde(default, rename = "protocolVersion")]
    pub protocol_version: Option<String>,
    #[serde(default, rename = "serverInfo")]
    pub server_info: Option<ServerInfo>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServerInfo {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
}

// ---------------------------------------------------------------------------
// tools/list
// ---------------------------------------------------------------------------

/// A single tool definition as reported by an MCP server's `tools/list`.
#[derive(Debug, Clone, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Raw JSON Schema for the tool's arguments. Untrusted; must be
    /// normalized before provider injection.
    #[serde(default, rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Result of a `tools/list` call.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ListToolsResult {
    #[serde(default)]
    pub tools: Vec<McpToolDefinition>,
    #[serde(default, rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// A single server descriptor advertised by an MCP hub registry
/// (`servers/list`).
///
/// The hub is queried over the MCP protocol like any other endpoint. This is
/// the minimal, **provisional** discovery contract (name + url + description);
/// extend it as the hub schema firms up (open questions #1/#2). `name` is the
/// stable unique identifier within the hub namespace and becomes the server's
/// `external_id`.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryServer {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub url: String,
}

/// Result of a registry `servers/list` call (cursor-paginated like
/// `tools/list`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ListServersResult {
    #[serde(default)]
    pub servers: Vec<RegistryServer>,
    #[serde(default, rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// tools/call
// ---------------------------------------------------------------------------

/// A typed content block returned by `tools/call`.
///
/// Unknown block types deserialize to [`McpContent::Unknown`] so a malicious
/// or newer server cannot break parsing.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpContent {
    Text {
        #[serde(default)]
        text: String,
    },
    Image {
        #[serde(default)]
        data: Option<String>,
        #[serde(default, rename = "mimeType")]
        mime_type: Option<String>,
    },
    Resource {
        #[serde(default)]
        resource: serde_json::Value,
    },
    #[serde(other)]
    Unknown,
}

/// Result of a `tools/call` invocation.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct McpToolResult {
    #[serde(default)]
    pub content: Vec<McpContent>,
    /// Structured result (MCP `2025-06-18`). Tools that declare an
    /// `outputSchema` return their data here; spec-compliant servers SHOULD
    /// also mirror it into a `content` text block, but many (e.g. REST-wrapping
    /// servers) populate only this field, leaving `content` empty. Surfaced as
    /// a fallback so such results are not lost.
    #[serde(default, rename = "structuredContent")]
    pub structured_content: Option<serde_json::Value>,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// Mutable per-connection session state tracked by the transport.
#[derive(Debug, Clone, Default)]
pub struct McpSession {
    /// `Mcp-Session-Id` returned by the server on `initialize`.
    pub session_id: Option<String>,
    /// Endpoint host that served `initialize`, pinned for session affinity.
    pub pinned_host: Option<String>,
    /// Negotiated protocol version (defaults to [`MCP_PROTOCOL_VERSION`]).
    pub protocol_version: Option<String>,
}

impl McpSession {
    /// Clear session-affinity state after an expiry (HTTP 404).
    pub fn reset(&mut self) {
        self.session_id = None;
        self.pinned_host = None;
    }

    /// Extra headers to attach to a proxied request for this session.
    #[must_use]
    pub fn headers(&self) -> HashMap<&'static str, String> {
        let mut h = HashMap::new();
        h.insert(
            HEADER_MCP_PROTOCOL_VERSION,
            self.protocol_version
                .clone()
                .unwrap_or_else(|| MCP_PROTOCOL_VERSION.to_owned()),
        );
        if let Some(sid) = &self.session_id {
            h.insert(HEADER_MCP_SESSION_ID, sid.clone());
        }
        if let Some(host) = &self.pinned_host {
            h.insert(HEADER_OAGW_TARGET_HOST, host.clone());
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_kind_str_matches_variant() {
        assert_eq!(McpAuth::None.kind_str(), "none");
        assert_eq!(
            McpAuth::Bearer {
                secret_ref: "r".into()
            }
            .kind_str(),
            "bearer"
        );
        assert_eq!(
            McpAuth::ApiKey {
                header: "x".into(),
                secret_ref: "r".into()
            }
            .kind_str(),
            "api_key"
        );
        assert_eq!(
            McpAuth::OAuth2 {
                client_id_ref: "c".into(),
                client_secret_ref: "s".into(),
                token_url: "u".into(),
                scopes: vec![]
            }
            .kind_str(),
            "oauth2"
        );
    }

    #[test]
    fn trust_level_round_trips() {
        for lvl in [
            McpTrustLevel::Trusted,
            McpTrustLevel::Restricted,
            McpTrustLevel::Untrusted,
        ] {
            assert_eq!(McpTrustLevel::from_str_or_default(lvl.as_str()), lvl);
        }
        assert_eq!(
            McpTrustLevel::from_str_or_default("bogus"),
            McpTrustLevel::Untrusted
        );
    }

    #[test]
    fn session_reset_clears_affinity_but_keeps_protocol() {
        let mut s = McpSession {
            session_id: Some("sid".into()),
            pinned_host: Some("host".into()),
            protocol_version: Some("v".into()),
        };
        s.reset();
        assert!(s.session_id.is_none());
        assert!(s.pinned_host.is_none());
        assert_eq!(s.protocol_version.as_deref(), Some("v"));
    }

    #[test]
    fn session_headers_include_protocol_default() {
        let s = McpSession::default();
        let h = s.headers();
        assert_eq!(
            h.get(HEADER_MCP_PROTOCOL_VERSION).map(String::as_str),
            Some(MCP_PROTOCOL_VERSION)
        );
        assert!(!h.contains_key(HEADER_MCP_SESSION_ID));
    }

    #[test]
    fn unknown_content_block_parses() {
        let r: McpToolResult =
            serde_json::from_str(r#"{"content":[{"type":"video","url":"x"}],"isError":false}"#)
                .unwrap();
        assert_eq!(r.content.len(), 1);
        assert!(matches!(r.content[0], McpContent::Unknown));
    }

    #[test]
    fn tool_call_error_flag_parses() {
        let r: McpToolResult =
            serde_json::from_str(r#"{"content":[{"type":"text","text":"boom"}],"isError":true}"#)
                .unwrap();
        assert!(r.is_error);
        assert!(matches!(&r.content[0], McpContent::Text { text } if text == "boom"));
    }
}
