//! Connection + tool-cache manager for all registered MCP servers.
//!
//! Owns one [`McpClient`] per server (preserving session affinity across
//! calls), a per-server concurrency semaphore and circuit breaker, and a
//! read-through TTL cache of tool metadata. The cache is a read-through of the
//! `mcp_server_tools` DB table — the caller supplies the DB loader so this
//! infra layer stays decoupled from the domain repositories.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oagw_sdk::ServiceGatewayClientV1;
use parking_lot::{Mutex, RwLock};
use toolkit_security::SecurityContext;

use super::cache::TtlCache;
use super::client::McpClient;
use super::error::{McpError, McpResult};
use super::transport::OagwTransport;
use super::types::{McpToolDefinition, McpToolResult, McpTrustLevel, RegistryServer};

/// Stream-time dispatch surface for MCP tool calls.
///
/// Abstracts [`McpPool::call_tool`] so the agentic loop in the domain layer can
/// dispatch a `tools/call` without depending on the concrete pool, and so tests
/// can substitute a stub. Kept object-safe (`Arc<dyn McpDispatcher>`).
#[async_trait::async_trait]
pub trait McpDispatcher: Send + Sync {
    /// Invoke `original_name` on `server_id` with `arguments`, enforcing the
    /// per-server circuit breaker, concurrency cap, and per-call timeout.
    async fn dispatch(
        &self,
        ctx: &SecurityContext,
        server_id: &str,
        original_name: &str,
        arguments: &serde_json::Value,
    ) -> McpResult<McpToolResult>;
}

#[async_trait::async_trait]
impl McpDispatcher for McpPool {
    async fn dispatch(
        &self,
        ctx: &SecurityContext,
        server_id: &str,
        original_name: &str,
        arguments: &serde_json::Value,
    ) -> McpResult<McpToolResult> {
        self.call_tool(ctx, server_id, original_name, arguments)
            .await
    }
}

/// A tool resolved from cache/DB, neutral to the DB entity representation.
#[derive(Debug, Clone)]
pub struct CachedTool {
    pub original_name: String,
    pub exposed_name: String,
    pub description: String,
    pub input_schema: Arc<serde_json::Value>,
    pub schema_hash: String,
    pub enabled: bool,
    pub trust_level: McpTrustLevel,
}

/// Immutable per-server connection parameters.
#[derive(Debug, Clone)]
pub struct McpServerConn {
    /// OAGW upstream alias (`mcp-{server_id}`).
    pub alias: String,
    /// Path component of the MCP server URL (e.g. `/mcp`; may be empty).
    pub base_path: String,
    /// Per-call timeout.
    pub call_timeout: Duration,
    /// Max concurrent `tools/call` requests for this server.
    pub max_concurrent_calls: usize,
}

/// Circuit-breaker tuning.
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    pub failure_threshold: u32,
    pub open_duration: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
        }
    }
}

#[derive(Default)]
struct BreakerInner {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

struct CircuitBreaker {
    cfg: BreakerConfig,
    inner: Mutex<BreakerInner>,
}

impl CircuitBreaker {
    fn new(cfg: BreakerConfig) -> Self {
        Self {
            cfg,
            inner: Mutex::new(BreakerInner::default()),
        }
    }

    fn check(&self) -> McpResult<()> {
        let mut inner = self.inner.lock();
        if let Some(until) = inner.open_until {
            if Instant::now() < until {
                return Err(McpError::CircuitOpen);
            }
            // Half-open: allow a trial request.
            inner.open_until = None;
        }
        Ok(())
    }

    fn record_success(&self) {
        let mut inner = self.inner.lock();
        inner.consecutive_failures = 0;
        inner.open_until = None;
    }

    fn record_failure(&self) {
        let mut inner = self.inner.lock();
        inner.consecutive_failures += 1;
        if inner.consecutive_failures >= self.cfg.failure_threshold {
            inner.open_until = Some(Instant::now() + self.cfg.open_duration);
        }
    }
}

struct ServerState {
    conn: McpServerConn,
    client: Arc<McpClient>,
    semaphore: Arc<tokio::sync::Semaphore>,
    breaker: CircuitBreaker,
}

/// Manages MCP clients and tool caches across all registered servers.
pub struct McpPool {
    gateway: Arc<dyn ServiceGatewayClientV1>,
    servers: RwLock<HashMap<String, Arc<ServerState>>>,
    tool_cache: TtlCache<String, Arc<[CachedTool]>>,
    max_response_bytes: usize,
    breaker_cfg: BreakerConfig,
}

impl McpPool {
    #[must_use]
    pub fn new(
        gateway: Arc<dyn ServiceGatewayClientV1>,
        tool_cache_ttl: Duration,
        max_response_bytes: usize,
        breaker_cfg: BreakerConfig,
    ) -> Self {
        Self {
            gateway,
            servers: RwLock::new(HashMap::new()),
            tool_cache: TtlCache::new(tool_cache_ttl),
            max_response_bytes,
            breaker_cfg,
        }
    }

    /// Register or replace a server's connection parameters. Replacing resets
    /// the client (new session) and clears the tool cache for that server.
    pub fn upsert_server(&self, server_id: impl Into<String>, conn: McpServerConn) {
        let server_id = server_id.into();
        let transport = Arc::new(OagwTransport::new(
            Arc::clone(&self.gateway),
            conn.alias.clone(),
            conn.base_path.clone(),
            self.max_response_bytes,
        ));
        let max_calls = conn.max_concurrent_calls.max(1);
        let state = Arc::new(ServerState {
            conn,
            client: Arc::new(McpClient::new(transport)),
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_calls)),
            breaker: CircuitBreaker::new(self.breaker_cfg),
        });
        self.servers.write().insert(server_id.clone(), state);
        self.tool_cache.invalidate(&server_id);
    }

    /// Immediately evict a server (disabled or deleted).
    pub fn remove_server(&self, server_id: &str) {
        self.servers.write().remove(server_id);
        self.tool_cache.invalidate(&server_id.to_owned());
    }

    fn state(&self, server_id: &str) -> McpResult<Arc<ServerState>> {
        self.servers
            .read()
            .get(server_id)
            .cloned()
            .ok_or_else(|| McpError::ServerNotFound(server_id.to_owned()))
    }

    /// Read tools for a server via the read-through cache. On a miss, `loader`
    /// is invoked (typically a `mcp_server_tools` DB read). Never performs an
    /// outbound `tools/list` — that is the background/admin refresh path only.
    pub async fn get_tools<F, Fut>(
        &self,
        server_id: &str,
        loader: F,
    ) -> McpResult<Arc<[CachedTool]>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = McpResult<Arc<[CachedTool]>>>,
    {
        self.tool_cache.get_with(server_id.to_owned(), loader).await
    }

    /// Discover tools directly from the server via `tools/list` (background /
    /// admin refresh path only — never on the stream hot path).
    pub async fn discover_tools(
        &self,
        ctx: &SecurityContext,
        server_id: &str,
    ) -> McpResult<Vec<McpToolDefinition>> {
        let state = self.state(server_id)?;
        state.client.list_tools(ctx).await
    }

    /// List servers advertised by the hub registry connection `hub_id`
    /// (registered like any server via [`Self::upsert_server`]). Used by the
    /// background hub-sync path only — never on the stream hot path.
    pub async fn list_registry_servers(
        &self,
        ctx: &SecurityContext,
        hub_id: &str,
    ) -> McpResult<Vec<RegistryServer>> {
        let state = self.state(hub_id)?;
        state.client.list_registry_servers(ctx).await
    }

    /// Invoke a tool on a server, enforcing the circuit breaker, per-server
    /// concurrency cap, and per-call timeout. `tools/call` is never retried.
    pub async fn call_tool(
        &self,
        ctx: &SecurityContext,
        server_id: &str,
        original_name: &str,
        arguments: &serde_json::Value,
    ) -> McpResult<McpToolResult> {
        let state = self.state(server_id)?;
        state.breaker.check()?;

        let _permit = state
            .semaphore
            .acquire()
            .await
            .map_err(|_| McpError::Transport("semaphore closed".to_owned()))?;

        let timeout = state.conn.call_timeout;
        let fut = state.client.call_tool(ctx, original_name, arguments);
        let result = match tokio::time::timeout(timeout, fut).await {
            Ok(inner) => inner,
            Err(_) => Err(McpError::Timeout {
                secs: timeout.as_secs(),
            }),
        };

        match &result {
            Ok(_) => state.breaker.record_success(),
            Err(_) => state.breaker.record_failure(),
        }
        result
    }

    /// Number of registered servers (test/observability helper).
    #[must_use]
    pub fn server_count(&self) -> usize {
        self.servers.read().len()
    }

    /// Graceful shutdown: drop all clients and clear caches.
    pub fn shutdown(&self) {
        self.servers.write().clear();
        self.tool_cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::mcp::test_support::NoopGateway;

    fn pool() -> McpPool {
        McpPool::new(
            Arc::new(NoopGateway),
            Duration::from_secs(30),
            1024 * 1024,
            BreakerConfig::default(),
        )
    }

    fn conn() -> McpServerConn {
        McpServerConn {
            alias: "mcp-srv1".into(),
            base_path: "/mcp".into(),
            call_timeout: Duration::from_secs(5),
            max_concurrent_calls: 2,
        }
    }

    #[test]
    fn upsert_and_remove_server() {
        let pool = pool();
        pool.upsert_server("srv1", conn());
        assert_eq!(pool.server_count(), 1);
        pool.remove_server("srv1");
        assert_eq!(pool.server_count(), 0);
    }

    #[tokio::test]
    async fn get_tools_uses_cache() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pool = pool();
        let calls = AtomicUsize::new(0);
        let loader = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<Arc<[CachedTool]>, McpError>(Arc::from(Vec::<CachedTool>::new()))
        };
        pool.get_tools("srv1", loader).await.unwrap();
        pool.get_tools("srv1", loader).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn call_tool_unknown_server_errors() {
        let pool = pool();
        let ctx = crate::infra::mcp::test_support::test_ctx();
        let e = pool
            .call_tool(&ctx, "missing", "t", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(e, McpError::ServerNotFound(_)));
    }

    #[test]
    fn circuit_breaker_opens_after_threshold() {
        let cb = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 2,
            open_duration: Duration::from_secs(30),
        });
        assert!(cb.check().is_ok());
        cb.record_failure();
        assert!(cb.check().is_ok());
        cb.record_failure();
        assert!(matches!(cb.check(), Err(McpError::CircuitOpen)));
        cb.record_success();
        assert!(cb.check().is_ok());
    }
}
