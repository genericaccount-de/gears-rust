//! MCP transport abstraction.
//!
//! [`McpTransport`] is a thin request/response port. The sole production
//! implementation, [`OagwTransport`], forwards every MCP HTTP request through
//! the Outbound API Gateway via the in-process `ServiceGatewayClientV1` SDK —
//! mini-chat never opens a direct socket to an MCP server. Session and
//! JSON-RPC semantics live in [`McpClient`](crate::infra::mcp::client::McpClient),
//! keeping this layer trivially mockable.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use oagw_sdk::{Body, ServiceGatewayClientV1};
use toolkit_security::SecurityContext;

use super::error::{McpError, McpResult};

/// A single MCP HTTP request to be proxied.
#[derive(Debug, Clone)]
pub struct McpHttpRequest {
    pub method: http::Method,
    /// Serialized JSON-RPC body (empty for `DELETE` session-close).
    pub body: Bytes,
    /// Additional headers to attach (session id, protocol version, target host).
    pub headers: Vec<(String, String)>,
}

/// The proxied HTTP response, reduced to what the client needs.
#[derive(Debug, Clone)]
pub struct McpHttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
}

/// Port over which MCP JSON-RPC requests are sent.
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Send one request and return the raw response.
    async fn send(
        &self,
        ctx: &SecurityContext,
        req: McpHttpRequest,
    ) -> McpResult<McpHttpResponse>;
}

/// OAGW-backed transport for a single MCP server.
///
/// Holds the server's OAGW upstream alias (`mcp-{server_id}`) and the path
/// component of the server URL (forwarded verbatim by the catch-all route).
/// Credential injection, SSRF protection, and rate limiting are handled by
/// OAGW using the caller's `SecurityContext`.
pub struct OagwTransport {
    gateway: Arc<dyn ServiceGatewayClientV1>,
    alias: String,
    base_path: String,
    max_response_bytes: usize,
}

impl OagwTransport {
    /// Create a transport for the given upstream `alias` and MCP endpoint
    /// `base_path` (e.g. `/mcp`; may be empty).
    #[must_use]
    pub fn new(
        gateway: Arc<dyn ServiceGatewayClientV1>,
        alias: impl Into<String>,
        base_path: impl Into<String>,
        max_response_bytes: usize,
    ) -> Self {
        let base_path = normalize_base_path(&base_path.into());
        Self {
            gateway,
            alias: alias.into(),
            base_path,
            max_response_bytes,
        }
    }

    fn uri(&self) -> String {
        format!("/{}{}", self.alias, self.base_path)
    }
}

/// Ensure the path is either empty or starts with `/`.
///
/// A trailing slash is preserved verbatim: some MCP servers mount their
/// endpoint at `/mcp/` and 307-redirect a request to `/mcp`. A bare root path
/// (`/`) carries no routing information and collapses to empty.
fn normalize_base_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return String::new();
    }
    if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("/{trimmed}")
    }
}

#[async_trait]
impl McpTransport for OagwTransport {
    async fn send(
        &self,
        ctx: &SecurityContext,
        req: McpHttpRequest,
    ) -> McpResult<McpHttpResponse> {
        let mut builder = http::Request::builder().method(req.method).uri(self.uri());

        // Content negotiation for MCP Streamable transport.
        builder = builder
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::ACCEPT, "application/json, text/event-stream");

        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        let body = if req.body.is_empty() {
            Body::Empty
        } else {
            Body::Bytes(req.body)
        };

        let http_req = builder
            .body(body)
            .map_err(|e| McpError::Transport(format!("failed to build request: {e}")))?;

        let response = self
            .gateway
            .proxy_request(ctx.clone(), http_req)
            .await
            .map_err(|e| McpError::Transport(e.to_string()))?;

        let (parts, resp_body) = response.into_parts();
        let status = parts.status.as_u16();

        let mut headers = HashMap::new();
        for (name, value) in &parts.headers {
            if let Ok(v) = value.to_str() {
                headers.insert(name.as_str().to_ascii_lowercase(), v.to_owned());
            }
        }

        let bytes = resp_body
            .into_bytes()
            .await
            .map_err(|e| McpError::Transport(format!("failed to read response body: {e}")))?;

        if bytes.len() > self.max_response_bytes {
            return Err(McpError::ResponseTooLarge {
                limit: self.max_response_bytes,
            });
        }

        Ok(McpHttpResponse {
            status,
            headers,
            body: bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_base_path_variants() {
        assert_eq!(normalize_base_path(""), "");
        assert_eq!(normalize_base_path("/"), "");
        assert_eq!(normalize_base_path("mcp"), "/mcp");
        assert_eq!(normalize_base_path("/mcp"), "/mcp");
        // Trailing slash is preserved (avoids upstream 307 redirects).
        assert_eq!(normalize_base_path("/mcp/"), "/mcp/");
        assert_eq!(normalize_base_path("/a/b/"), "/a/b/");
    }

    #[test]
    fn uri_composes_alias_and_path() {
        let gw: Arc<dyn ServiceGatewayClientV1> =
            Arc::new(crate::infra::mcp::test_support::NoopGateway);
        let t = OagwTransport::new(gw, "mcp-srv1", "/mcp", 1024);
        assert_eq!(t.uri(), "/mcp-srv1/mcp");
    }

    #[test]
    fn uri_preserves_trailing_slash() {
        let gw: Arc<dyn ServiceGatewayClientV1> =
            Arc::new(crate::infra::mcp::test_support::NoopGateway);
        let t = OagwTransport::new(gw, "mcp-srv1", "/mcp/", 1024);
        assert_eq!(t.uri(), "/mcp-srv1/mcp/");
    }

    /// Gateway that records the headers of the proxied request and returns an
    /// empty 200 response.
    struct CapturingGateway {
        headers: parking_lot::Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl ServiceGatewayClientV1 for CapturingGateway {
        async fn create_upstream(
            &self,
            _: SecurityContext,
            _: oagw_sdk::CreateUpstreamRequest,
        ) -> Result<oagw_sdk::Upstream, toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn get_upstream(
            &self,
            _: SecurityContext,
            _: uuid::Uuid,
        ) -> Result<oagw_sdk::Upstream, toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn list_upstreams(
            &self,
            _: SecurityContext,
            _: &oagw_sdk::ListQuery,
        ) -> Result<Vec<oagw_sdk::Upstream>, toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn update_upstream(
            &self,
            _: SecurityContext,
            _: uuid::Uuid,
            _: oagw_sdk::UpdateUpstreamRequest,
        ) -> Result<oagw_sdk::Upstream, toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn delete_upstream(
            &self,
            _: SecurityContext,
            _: uuid::Uuid,
        ) -> Result<(), toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn create_route(
            &self,
            _: SecurityContext,
            _: oagw_sdk::CreateRouteRequest,
        ) -> Result<oagw_sdk::Route, toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn get_route(
            &self,
            _: SecurityContext,
            _: uuid::Uuid,
        ) -> Result<oagw_sdk::Route, toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn list_routes(
            &self,
            _: SecurityContext,
            _: Option<uuid::Uuid>,
            _: &oagw_sdk::ListQuery,
        ) -> Result<Vec<oagw_sdk::Route>, toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn update_route(
            &self,
            _: SecurityContext,
            _: uuid::Uuid,
            _: oagw_sdk::UpdateRouteRequest,
        ) -> Result<oagw_sdk::Route, toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn delete_route(
            &self,
            _: SecurityContext,
            _: uuid::Uuid,
        ) -> Result<(), toolkit_canonical_errors::CanonicalError> {
            unimplemented!()
        }
        async fn resolve_proxy_target(
            &self,
            _: SecurityContext,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(oagw_sdk::Upstream, oagw_sdk::Route), toolkit_canonical_errors::CanonicalError>
        {
            unimplemented!()
        }
        async fn proxy_request(
            &self,
            _: SecurityContext,
            req: http::Request<Body>,
        ) -> Result<http::Response<Body>, toolkit_canonical_errors::CanonicalError> {
            let mut recorded = self.headers.lock();
            for (name, value) in req.headers() {
                if let Ok(v) = value.to_str() {
                    recorded.push((name.as_str().to_owned(), v.to_owned()));
                }
            }
            Ok(http::Response::builder().status(200).body(Body::Empty).unwrap())
        }
    }

    async fn send_and_capture() -> Vec<(String, String)> {
        let gw = Arc::new(CapturingGateway {
            headers: parking_lot::Mutex::new(Vec::new()),
        });
        let transport = OagwTransport::new(
            Arc::clone(&gw) as Arc<dyn ServiceGatewayClientV1>,
            "mcp-srv1",
            "/mcp",
            1024,
        );
        let ctx = crate::infra::mcp::test_support::test_ctx();
        transport
            .send(
                &ctx,
                McpHttpRequest {
                    method: http::Method::POST,
                    body: Bytes::from_static(b"{}"),
                    headers: vec![],
                },
            )
            .await
            .unwrap();
        gw.headers.lock().clone()
    }

    #[tokio::test]
    async fn forwards_content_negotiation_headers() {
        let headers = send_and_capture().await;
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "accept" && v.contains("text/event-stream")),
            "Accept header must be forwarded for MCP Streamable transport"
        );
    }
}
