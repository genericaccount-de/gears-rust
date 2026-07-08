//! JSON-RPC MCP client over a pluggable [`McpTransport`].
//!
//! Owns per-connection session state and implements the `tools/*` subset:
//! `initialize`, `tools/list` (with cursor pagination), and `tools/call`.
//! Session affinity and single-retry-on-404 re-initialization live here so the
//! transport stays a dumb proxy.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use toolkit_security::SecurityContext;

use super::error::{McpError, McpResult};
use super::transport::{McpHttpRequest, McpHttpResponse, McpTransport};
use super::types::{
    HEADER_MCP_SESSION_ID, HEADER_OAGW_TARGET_HOST, InitializeResult, JsonRpcRequest,
    JsonRpcResponse, ListServersResult, ListToolsResult, McpSession, McpToolDefinition,
    McpToolResult, RegistryServer,
};

/// Maximum `tools/list` pages fetched to bound pathological servers.
const MAX_TOOL_LIST_PAGES: usize = 32;

/// A JSON-RPC MCP client bound to a single server.
pub struct McpClient {
    transport: Arc<dyn McpTransport>,
    session: Mutex<McpSession>,
    next_id: AtomicU64,
    initialized: Mutex<bool>,
}

impl McpClient {
    #[must_use]
    pub fn new(transport: Arc<dyn McpTransport>) -> Self {
        Self {
            transport,
            session: Mutex::new(McpSession::default()),
            next_id: AtomicU64::new(1),
            initialized: Mutex::new(false),
        }
    }

    fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Perform the MCP `initialize` handshake, capturing session id and the
    /// serving endpoint host for session affinity.
    pub async fn initialize(&self, ctx: &SecurityContext) -> McpResult<InitializeResult> {
        let params = serde_json::json!({
            "protocolVersion": super::types::MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "mini-chat", "version": env!("CARGO_PKG_VERSION") },
        });
        let value = self
            .rpc_once(ctx, "initialize", Some(params), /*is_initialize=*/ true)
            .await?;
        let result: InitializeResult = serde_json::from_value(value)
            .map_err(|e| McpError::Protocol(format!("invalid initialize result: {e}")))?;

        // MCP lifecycle: after a successful `initialize` the client MUST send a
        // `notifications/initialized` notification before issuing any other
        // request. Strict servers (e.g. FastMCP-based) reject `tools/list` with
        // -32602 until they receive it. Sent with the freshly captured session
        // headers (see `absorb_session_headers`).
        self.notify(ctx, "notifications/initialized", None).await?;
        *self.initialized.lock() = true;
        Ok(result)
    }

    async fn ensure_initialized(&self, ctx: &SecurityContext) -> McpResult<()> {
        if !*self.initialized.lock() {
            self.initialize(ctx).await?;
        }
        Ok(())
    }

    /// List all tools exposed by the server (following `nextCursor` pages).
    pub async fn list_tools(&self, ctx: &SecurityContext) -> McpResult<Vec<McpToolDefinition>> {
        self.ensure_initialized(ctx).await?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_TOOL_LIST_PAGES {
            let params = cursor
                .as_ref()
                .map(|c| serde_json::json!({ "cursor": c }));
            let value = self.rpc(ctx, "tools/list", params).await?;
            let page: ListToolsResult = serde_json::from_value(value)
                .map_err(|e| McpError::Protocol(format!("invalid tools/list result: {e}")))?;
            all.extend(page.tools);
            match page.next_cursor {
                Some(next) if !next.is_empty() => cursor = Some(next),
                _ => return Ok(all),
            }
        }
        Ok(all)
    }

    /// List servers advertised by an MCP hub registry (`servers/list`),
    /// following `nextCursor` pages. The hub is just another MCP endpoint
    /// reached over this client's transport.
    pub async fn list_registry_servers(
        &self,
        ctx: &SecurityContext,
    ) -> McpResult<Vec<RegistryServer>> {
        self.ensure_initialized(ctx).await?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_TOOL_LIST_PAGES {
            let params = cursor
                .as_ref()
                .map(|c| serde_json::json!({ "cursor": c }));
            let value = self.rpc(ctx, "servers/list", params).await?;
            let page: ListServersResult = serde_json::from_value(value)
                .map_err(|e| McpError::Protocol(format!("invalid servers/list result: {e}")))?;
            all.extend(page.servers);
            match page.next_cursor {
                Some(next) if !next.is_empty() => cursor = Some(next),
                _ => return Ok(all),
            }
        }
        Ok(all)
    }

    /// Invoke a tool by its original (server-reported) name.
    ///
    /// `tools/call` is never retried on transport errors (tools may mutate
    /// external state); only session-expiry (404) triggers a single re-init.
    pub async fn call_tool(
        &self,
        ctx: &SecurityContext,
        name: &str,
        arguments: &serde_json::Value,
    ) -> McpResult<McpToolResult> {
        self.ensure_initialized(ctx).await?;
        let params = serde_json::json!({ "name": name, "arguments": arguments });
        let value = self.rpc(ctx, "tools/call", Some(params)).await?;
        serde_json::from_value(value)
            .map_err(|e| McpError::Protocol(format!("invalid tools/call result: {e}")))
    }

    /// Send a JSON-RPC request, retrying once through re-initialization if the
    /// session expired (HTTP 404).
    async fn rpc(
        &self,
        ctx: &SecurityContext,
        method: &'static str,
        params: Option<serde_json::Value>,
    ) -> McpResult<serde_json::Value> {
        match self.rpc_once(ctx, method, params.clone(), false).await {
            Err(McpError::SessionExpired) => {
                self.session.lock().reset();
                self.initialize(ctx).await?;
                self.rpc_once(ctx, method, params, false).await
            }
            other => other,
        }
    }

    async fn rpc_once(
        &self,
        ctx: &SecurityContext,
        method: &'static str,
        params: Option<serde_json::Value>,
        is_initialize: bool,
    ) -> McpResult<serde_json::Value> {
        let req = JsonRpcRequest::new(self.alloc_id(), method, params);
        let body = serde_json::to_vec(&req)
            .map_err(|e| McpError::Protocol(format!("failed to serialize request: {e}")))?;

        let headers: Vec<(String, String)> = self
            .session
            .lock()
            .headers()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();

        let http_req = McpHttpRequest {
            method: http::Method::POST,
            body: body.into(),
            headers,
        };

        let resp = self.transport.send(ctx, http_req).await?;

        if resp.status == 404 {
            return Err(McpError::SessionExpired);
        }
        if !(200..300).contains(&resp.status) {
            return Err(McpError::Http { status: resp.status });
        }

        self.absorb_session_headers(&resp, is_initialize);
        parse_jsonrpc_result(&resp)
    }

    /// Send a JSON-RPC notification (no `id`, no result expected).
    ///
    /// Notifications carry no `id` and elicit no JSON-RPC response body; MCP
    /// Streamable HTTP servers acknowledge with `202 Accepted`. A `404` is still
    /// treated as session expiry so callers can re-initialize.
    async fn notify(
        &self,
        ctx: &SecurityContext,
        method: &'static str,
        params: Option<serde_json::Value>,
    ) -> McpResult<()> {
        let mut msg = serde_json::json!({
            "jsonrpc": super::types::JSONRPC_VERSION,
            "method": method,
        });
        if let Some(p) = params {
            msg["params"] = p;
        }
        let body = serde_json::to_vec(&msg)
            .map_err(|e| McpError::Protocol(format!("failed to serialize notification: {e}")))?;

        let headers: Vec<(String, String)> = self
            .session
            .lock()
            .headers()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();

        let resp = self
            .transport
            .send(
                ctx,
                McpHttpRequest {
                    method: http::Method::POST,
                    body: body.into(),
                    headers,
                },
            )
            .await?;

        if resp.status == 404 {
            return Err(McpError::SessionExpired);
        }
        if !(200..300).contains(&resp.status) {
            return Err(McpError::Http { status: resp.status });
        }
        Ok(())
    }

    /// Capture `Mcp-Session-Id` (any response) and pin the serving host from
    /// the `initialize` response for multi-endpoint session affinity.
    fn absorb_session_headers(&self, resp: &McpHttpResponse, is_initialize: bool) {
        let mut session = self.session.lock();
        if let Some(sid) = resp.headers.get(HEADER_MCP_SESSION_ID) {
            session.session_id = Some(sid.clone());
        }
        if let (true, Some(host)) = (is_initialize, resp.headers.get(HEADER_OAGW_TARGET_HOST)) {
            session.pinned_host = Some(host.clone());
        }
    }
}

/// Parse a JSON-RPC result from a raw response body, tolerating either a
/// direct JSON body or an SSE (`text/event-stream`) framing.
fn parse_jsonrpc_result(resp: &McpHttpResponse) -> McpResult<serde_json::Value> {
    let text = std::str::from_utf8(&resp.body)
        .map_err(|e| McpError::Protocol(format!("non-utf8 response: {e}")))?;

    let json_text = extract_json_payload(text);

    let parsed: JsonRpcResponse = serde_json::from_str(json_text)
        .map_err(|e| McpError::Protocol(format!("invalid JSON-RPC response: {e}")))?;

    if let Some(err) = parsed.error {
        // Fold the optional `data` payload into the message: MCP servers place
        // the specific validation detail there (e.g. the rejected field), which
        // is otherwise lost from logs.
        let message = match &err.data {
            Some(data) => format!("{} (data: {data})", err.message),
            None => err.message,
        };
        return Err(McpError::JsonRpc {
            code: err.code,
            message,
        });
    }
    Ok(parsed.result.unwrap_or(serde_json::Value::Null))
}

/// Extract the JSON payload from either a plain JSON body or the last `data:`
/// line of an SSE stream.
fn extract_json_payload(text: &str) -> &str {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return trimmed;
    }
    // SSE framing: take the last non-empty `data:` line.
    text.lines()
        .rev()
        .find_map(|line| line.strip_prefix("data:").map(str::trim))
        .filter(|s| !s.is_empty())
        .unwrap_or(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::mcp::test_support::{MockTransport, mock_transport, test_ctx};

    fn ctx() -> SecurityContext {
        test_ctx()
    }

    fn init_ok() -> McpHttpResponse {
        MockTransport::json_ok_with_session(
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"srv","version":"1"}}}"#,
            "sess-123",
            Some("replica-a"),
        )
    }

    /// Ack for the `notifications/initialized` message sent after `initialize`
    /// (202 Accepted, no body), mirroring MCP Streamable HTTP servers.
    fn initialized_ack() -> McpHttpResponse {
        MockTransport::status(202)
    }

    #[tokio::test]
    async fn initialize_captures_session_and_host() {
        let t = mock_transport(vec![Ok(init_ok()), Ok(initialized_ack())]);
        let client = McpClient::new(t.clone());
        let res = client.initialize(&ctx()).await.unwrap();
        assert_eq!(res.protocol_version.as_deref(), Some("2025-06-18"));
        assert_eq!(t.call_count(), 2, "initialize then initialized notification");
        let s = client.session.lock();
        assert_eq!(s.session_id.as_deref(), Some("sess-123"));
        assert_eq!(s.pinned_host.as_deref(), Some("replica-a"));
    }

    #[tokio::test]
    async fn initialize_sends_initialized_notification() {
        let t = mock_transport(vec![Ok(init_ok()), Ok(initialized_ack())]);
        let client = McpClient::new(t.clone());
        client.initialize(&ctx()).await.unwrap();
        let recorded = t.recorded.lock();
        assert_eq!(recorded.len(), 2);
        let body: serde_json::Value = serde_json::from_slice(&recorded[1].body).unwrap();
        assert_eq!(body["method"], "notifications/initialized");
        assert!(body.get("id").is_none(), "notifications carry no id");
    }

    #[tokio::test]
    async fn list_tools_auto_initializes_and_parses() {
        let tools = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","description":"d","inputSchema":{"type":"object"}}]}}"#;
        let t = mock_transport(vec![
            Ok(init_ok()),
            Ok(initialized_ack()),
            Ok(MockTransport::json_ok(tools)),
        ]);
        let client = McpClient::new(t.clone());
        let list = client.list_tools(&ctx()).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "search");
        assert_eq!(t.call_count(), 3, "initialize, initialized notification, then list");
    }

    #[tokio::test]
    async fn list_tools_follows_cursor_pages() {
        let page1 = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}],"nextCursor":"c1"}}"#;
        let page2 = r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"b"}]}}"#;
        let t = mock_transport(vec![
            Ok(init_ok()),
            Ok(initialized_ack()),
            Ok(MockTransport::json_ok(page1)),
            Ok(MockTransport::json_ok(page2)),
        ]);
        let client = McpClient::new(t);
        let list = client.list_tools(&ctx()).await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "a");
        assert_eq!(list[1].name, "b");
    }

    #[tokio::test]
    async fn list_registry_servers_parses_and_follows_pages() {
        let page1 = r#"{"jsonrpc":"2.0","id":2,"result":{"servers":[{"name":"srv-a","description":"A","url":"https://a/mcp"}],"nextCursor":"c1"}}"#;
        let page2 = r#"{"jsonrpc":"2.0","id":3,"result":{"servers":[{"name":"srv-b","url":"https://b/mcp"}]}}"#;
        let t = mock_transport(vec![
            Ok(init_ok()),
            Ok(initialized_ack()),
            Ok(MockTransport::json_ok(page1)),
            Ok(MockTransport::json_ok(page2)),
        ]);
        let client = McpClient::new(t);
        let servers = client.list_registry_servers(&ctx()).await.unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "srv-a");
        assert_eq!(servers[0].url, "https://a/mcp");
        assert_eq!(servers[1].name, "srv-b");
        assert_eq!(servers[1].description, "", "description defaults to empty");
    }

    #[tokio::test]
    async fn session_expiry_triggers_single_reinit_and_retry() {
        // initialize, then tools/call → 404, then re-initialize, then success.
        let call_ok = r#"{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}"#;
        let t = mock_transport(vec![
            Ok(init_ok()),
            Ok(initialized_ack()),
            Ok(MockTransport::status(404)),
            Ok(init_ok()),
            Ok(initialized_ack()),
            Ok(MockTransport::json_ok(call_ok)),
        ]);
        let client = McpClient::new(t.clone());
        let res = client
            .call_tool(&ctx(), "search", &serde_json::json!({}))
            .await
            .unwrap();
        assert!(!res.is_error);
        assert_eq!(t.call_count(), 6);
    }

    #[tokio::test]
    async fn jsonrpc_error_is_surfaced() {
        let err = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"method not found"}}"#;
        let t = mock_transport(vec![
            Ok(init_ok()),
            Ok(initialized_ack()),
            Ok(MockTransport::json_ok(err)),
        ]);
        let client = McpClient::new(t);
        let e = client.list_tools(&ctx()).await.unwrap_err();
        assert!(matches!(e, McpError::JsonRpc { code: -32601, .. }));
    }

    #[tokio::test]
    async fn call_tool_parses_sse_framed_body() {
        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"hi\"}],\"isError\":false}}\n\n";
        let t = mock_transport(vec![
            Ok(init_ok()),
            Ok(initialized_ack()),
            Ok(MockTransport::json_ok(sse)),
        ]);
        let client = McpClient::new(t);
        let res = client
            .call_tool(&ctx(), "search", &serde_json::json!({}))
            .await
            .unwrap();
        assert!(matches!(&res.content[0], crate::infra::mcp::types::McpContent::Text { text } if text == "hi"));
    }

    #[test]
    fn extract_json_payload_handles_plain_and_sse() {
        assert_eq!(extract_json_payload(r#"{"a":1}"#), r#"{"a":1}"#);
        assert_eq!(
            extract_json_payload("event: x\ndata: {\"a\":1}\n\n"),
            r#"{"a":1}"#
        );
    }
}
