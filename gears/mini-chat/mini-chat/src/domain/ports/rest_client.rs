//! Domain port for outbound REST "connector" tool calls.
//!
//! The [`RestClient`] trait decouples the agentic connector-tool dispatch from
//! the concrete HTTP transport. The direct-`reqwest` implementation (with a
//! host allowlist + SSRF safeguards) lives in
//! `infra/rest/reqwest_rest_client.rs`. This mirrors the [`KnowledgeRetriever`]
//! port / adapter split.
//!
//! [`KnowledgeRetriever`]: crate::domain::ports::knowledge_retriever::KnowledgeRetriever

use async_trait::async_trait;
use toolkit_macros::domain_model;
use toolkit_security::SecurityContext;

/// HTTP method supported by a REST connector. Intentionally limited to the
/// read/create verbs the connector tool surfaces.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestMethod {
    Get,
    Post,
}

/// A fully-formed outbound REST request built by the connector registry.
///
/// `url` already includes any query string assembled from the connector's
/// query params; `query` is kept separate only for adapters that prefer to
/// attach query pairs structurally. `headers` carries the connector's
/// env-expanded static headers + auth (the model never supplies these).
#[domain_model]
#[derive(Debug, Clone)]
pub struct RestRequest {
    pub method: RestMethod,
    pub url: String,
    /// Query pairs assembled by the registry. The URL already embeds these; the
    /// field is retained for adapters that prefer to attach them structurally.
    #[allow(dead_code)]
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Option<serde_json::Value>,
}

/// Response returned by a REST connector call.
#[domain_model]
#[derive(Debug, Clone)]
pub struct RestResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body_text: String,
    /// `true` when the body was truncated at the configured byte cap.
    pub truncated: bool,
}

/// Errors from outbound REST connector operations.
#[domain_model]
#[derive(Debug, thiserror::Error)]
pub enum RestError {
    /// The request was rejected before sending (host not on allowlist,
    /// blocked IP, malformed URL, reserved header).
    #[error("rest request rejected: {0}")]
    Rejected(String),
    /// Transport-level failure (connect/timeout/read error).
    #[error("rest service unavailable: {0}")]
    Unavailable(String),
    /// Misconfiguration (e.g. allowlist could not be built).
    #[error("rest configuration error: {0}")]
    Configuration(String),
    /// The remote returned a redirect or otherwise forbidden response that the
    /// adapter refuses to follow (auto-redirects are disabled). Reserved for
    /// adapters that map redirects to an error rather than a surfaced response.
    #[allow(dead_code)]
    #[error("rest request forbidden: {0}")]
    Forbidden(String),
}

/// Port for outbound REST connector calls.
///
/// Implementations MUST enforce the host allowlist and SSRF safeguards before
/// performing any DNS resolution or connection.
#[async_trait]
pub trait RestClient: Send + Sync {
    async fn call(
        &self,
        ctx: SecurityContext,
        req: RestRequest,
    ) -> Result<RestResponse, RestError>;
}
