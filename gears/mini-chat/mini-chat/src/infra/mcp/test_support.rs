//! Shared test doubles for the MCP client layer.
//!
//! Compiled for tests and available to sibling modules' unit tests.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use oagw_sdk::{Body, ServiceGatewayClientV1};
use parking_lot::Mutex;
use toolkit_canonical_errors::CanonicalError;
use toolkit_security::SecurityContext;

use super::error::McpResult;
use super::transport::{McpHttpRequest, McpHttpResponse, McpTransport};

/// A gateway that panics on every call — used only where a concrete
/// `ServiceGatewayClientV1` is structurally required but never invoked.
pub struct NoopGateway;

#[async_trait]
impl ServiceGatewayClientV1 for NoopGateway {
    async fn create_upstream(
        &self,
        _: SecurityContext,
        _: oagw_sdk::CreateUpstreamRequest,
    ) -> Result<oagw_sdk::Upstream, CanonicalError> {
        unimplemented!()
    }
    async fn get_upstream(
        &self,
        _: SecurityContext,
        _: uuid::Uuid,
    ) -> Result<oagw_sdk::Upstream, CanonicalError> {
        unimplemented!()
    }
    async fn list_upstreams(
        &self,
        _: SecurityContext,
        _: &oagw_sdk::ListQuery,
    ) -> Result<Vec<oagw_sdk::Upstream>, CanonicalError> {
        unimplemented!()
    }
    async fn update_upstream(
        &self,
        _: SecurityContext,
        _: uuid::Uuid,
        _: oagw_sdk::UpdateUpstreamRequest,
    ) -> Result<oagw_sdk::Upstream, CanonicalError> {
        unimplemented!()
    }
    async fn delete_upstream(&self, _: SecurityContext, _: uuid::Uuid) -> Result<(), CanonicalError> {
        unimplemented!()
    }
    async fn create_route(
        &self,
        _: SecurityContext,
        _: oagw_sdk::CreateRouteRequest,
    ) -> Result<oagw_sdk::Route, CanonicalError> {
        unimplemented!()
    }
    async fn get_route(
        &self,
        _: SecurityContext,
        _: uuid::Uuid,
    ) -> Result<oagw_sdk::Route, CanonicalError> {
        unimplemented!()
    }
    async fn list_routes(
        &self,
        _: SecurityContext,
        _: Option<uuid::Uuid>,
        _: &oagw_sdk::ListQuery,
    ) -> Result<Vec<oagw_sdk::Route>, CanonicalError> {
        unimplemented!()
    }
    async fn update_route(
        &self,
        _: SecurityContext,
        _: uuid::Uuid,
        _: oagw_sdk::UpdateRouteRequest,
    ) -> Result<oagw_sdk::Route, CanonicalError> {
        unimplemented!()
    }
    async fn delete_route(&self, _: SecurityContext, _: uuid::Uuid) -> Result<(), CanonicalError> {
        unimplemented!()
    }
    async fn resolve_proxy_target(
        &self,
        _: SecurityContext,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<(oagw_sdk::Upstream, oagw_sdk::Route), CanonicalError> {
        unimplemented!()
    }
    async fn proxy_request(
        &self,
        _: SecurityContext,
        _: http::Request<Body>,
    ) -> Result<http::Response<Body>, CanonicalError> {
        unimplemented!()
    }
}

/// A gateway that answers `oauth_connection_status` with a fixed value and
/// panics on every other call. Used to exercise per-user interactive-OAuth
/// gating in the effective resolver.
pub struct ConnGateway {
    /// Value returned from `oauth_connection_status`.
    pub connected: bool,
}

#[async_trait]
impl ServiceGatewayClientV1 for ConnGateway {
    async fn create_upstream(
        &self,
        _: SecurityContext,
        _: oagw_sdk::CreateUpstreamRequest,
    ) -> Result<oagw_sdk::Upstream, CanonicalError> {
        unimplemented!()
    }
    async fn get_upstream(
        &self,
        _: SecurityContext,
        _: uuid::Uuid,
    ) -> Result<oagw_sdk::Upstream, CanonicalError> {
        unimplemented!()
    }
    async fn list_upstreams(
        &self,
        _: SecurityContext,
        _: &oagw_sdk::ListQuery,
    ) -> Result<Vec<oagw_sdk::Upstream>, CanonicalError> {
        unimplemented!()
    }
    async fn update_upstream(
        &self,
        _: SecurityContext,
        _: uuid::Uuid,
        _: oagw_sdk::UpdateUpstreamRequest,
    ) -> Result<oagw_sdk::Upstream, CanonicalError> {
        unimplemented!()
    }
    async fn delete_upstream(&self, _: SecurityContext, _: uuid::Uuid) -> Result<(), CanonicalError> {
        unimplemented!()
    }
    async fn create_route(
        &self,
        _: SecurityContext,
        _: oagw_sdk::CreateRouteRequest,
    ) -> Result<oagw_sdk::Route, CanonicalError> {
        unimplemented!()
    }
    async fn get_route(
        &self,
        _: SecurityContext,
        _: uuid::Uuid,
    ) -> Result<oagw_sdk::Route, CanonicalError> {
        unimplemented!()
    }
    async fn list_routes(
        &self,
        _: SecurityContext,
        _: Option<uuid::Uuid>,
        _: &oagw_sdk::ListQuery,
    ) -> Result<Vec<oagw_sdk::Route>, CanonicalError> {
        unimplemented!()
    }
    async fn update_route(
        &self,
        _: SecurityContext,
        _: uuid::Uuid,
        _: oagw_sdk::UpdateRouteRequest,
    ) -> Result<oagw_sdk::Route, CanonicalError> {
        unimplemented!()
    }
    async fn delete_route(&self, _: SecurityContext, _: uuid::Uuid) -> Result<(), CanonicalError> {
        unimplemented!()
    }
    async fn resolve_proxy_target(
        &self,
        _: SecurityContext,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<(oagw_sdk::Upstream, oagw_sdk::Route), CanonicalError> {
        unimplemented!()
    }
    async fn proxy_request(
        &self,
        _: SecurityContext,
        _: http::Request<Body>,
    ) -> Result<http::Response<Body>, CanonicalError> {
        unimplemented!()
    }
    async fn oauth_connection_status(
        &self,
        _: SecurityContext,
        _: uuid::Uuid,
    ) -> Result<oagw_sdk::OAuthConnectionStatus, CanonicalError> {
        Ok(oagw_sdk::OAuthConnectionStatus {
            connected: self.connected,
            expires_at_unix: None,
        })
    }
}

/// A programmable [`McpTransport`] that returns queued responses and records
/// every request it received.
#[derive(Default)]
pub struct MockTransport {
    responses: Mutex<VecDeque<McpResult<McpHttpResponse>>>,
    pub recorded: Mutex<Vec<McpHttpRequest>>,
}

impl MockTransport {
    #[must_use]
    pub fn new(responses: Vec<McpResult<McpHttpResponse>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            recorded: Mutex::new(Vec::new()),
        }
    }

    /// Build an OK JSON response with a `Mcp-Session-Id` header.
    #[must_use]
    pub fn json_ok(body: &str) -> McpHttpResponse {
        McpHttpResponse {
            status: 200,
            headers: std::collections::HashMap::new(),
            body: Bytes::from(body.to_owned()),
        }
    }

    #[must_use]
    pub fn json_ok_with_session(body: &str, session_id: &str, host: Option<&str>) -> McpHttpResponse {
        let mut headers = std::collections::HashMap::new();
        headers.insert(
            super::types::HEADER_MCP_SESSION_ID.to_owned(),
            session_id.to_owned(),
        );
        if let Some(h) = host {
            headers.insert(super::types::HEADER_OAGW_TARGET_HOST.to_owned(), h.to_owned());
        }
        McpHttpResponse {
            status: 200,
            headers,
            body: Bytes::from(body.to_owned()),
        }
    }

    #[must_use]
    pub fn status(status: u16) -> McpHttpResponse {
        McpHttpResponse {
            status,
            headers: std::collections::HashMap::new(),
            body: Bytes::new(),
        }
    }

    #[must_use]
    pub fn call_count(&self) -> usize {
        self.recorded.lock().len()
    }
}

#[async_trait]
impl McpTransport for MockTransport {
    async fn send(
        &self,
        _ctx: &SecurityContext,
        req: McpHttpRequest,
    ) -> McpResult<McpHttpResponse> {
        self.recorded.lock().push(req);
        self.responses
            .lock()
            .pop_front()
            .unwrap_or_else(|| Ok(Self::json_ok("{}")))
    }
}

/// Convenience: an `Arc<MockTransport>` usable both as the transport and for
/// assertions.
#[must_use]
pub fn mock_transport(responses: Vec<McpResult<McpHttpResponse>>) -> Arc<MockTransport> {
    Arc::new(MockTransport::new(responses))
}

/// Build a minimal `SecurityContext` for MCP unit tests.
#[must_use]
pub fn test_ctx() -> SecurityContext {
    SecurityContext::builder()
        .subject_id(uuid::Uuid::new_v4())
        .subject_tenant_id(uuid::Uuid::new_v4())
        .build()
        .expect("failed to build SecurityContext")
}
