//! MCP background tool-refresh worker.
//!
//! Periodically re-discovers each config-seeded MCP server's tool set
//! (`tools/list`) and upserts the normalized metadata into `mcp_server_tools`,
//! keeping the DB — the canonical source consulted by the stream hot path —
//! fresh without an outbound call per turn.
//!
//! Requires leader election: exactly one active refresher per environment so
//! replicas don't hammer upstreams or race on the shared table. A fresh service
//! `SecurityContext` is obtained each cycle so OAGW authorization never runs
//! with an expired token.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use toolkit_security::SecurityContext;
use tracing::{debug, info, warn};

use crate::domain::service::McpToolRefresher;
use crate::infra::leader::{LeaderElector, work_fn};

/// Runtime configuration for the refresh worker, derived from `mcp` config.
#[derive(Debug, Clone, Copy)]
pub struct McpRefreshConfig {
    /// Whether MCP support (and therefore the refresh worker) is enabled.
    pub enabled: bool,
    /// Interval between refresh cycles.
    pub interval: Duration,
}

/// Supplies a service `SecurityContext` for outbound OAGW calls.
///
/// Implemented in the gear layer (client-credentials exchange). Re-invoked each
/// cycle so the worker always authorizes with a non-expired token.
#[async_trait]
pub trait SystemContextProvider: Send + Sync {
    async fn system_context(&self) -> anyhow::Result<SecurityContext>;
}

/// Dependencies for the refresh loop.
pub struct McpRefreshDeps {
    pub refresher: Arc<dyn McpToolRefresher>,
    pub ctx_provider: Arc<dyn SystemContextProvider>,
}

/// Run the MCP refresh worker under leader election.
///
/// Returns when `cancel` fires (gear shutdown). Individual cycle failures are
/// logged and never terminate the loop.
pub async fn run(
    elector: Arc<dyn LeaderElector>,
    config: McpRefreshConfig,
    deps: McpRefreshDeps,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    if !config.enabled {
        info!("mcp_refresh: disabled, skipping");
        return Ok(());
    }

    info!(
        interval_secs = config.interval.as_secs(),
        "mcp_refresh: starting"
    );

    let deps = Arc::new(deps);

    elector
        .run_role(
            "mcp-tool-refresh",
            cancel,
            work_fn(move |cancel| {
                let interval = config.interval;
                let deps = Arc::clone(&deps);
                async move {
                    let mut ticker = tokio::time::interval(interval);
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                    loop {
                        tokio::select! {
                            _ = ticker.tick() => {
                                refresh_once(&deps).await;
                            }
                            () = cancel.cancelled() => {
                                info!("mcp_refresh: shutting down");
                                return Ok(());
                            }
                        }
                    }
                }
            }),
        )
        .await
}

/// Execute a single refresh cycle: obtain a fresh context, then refresh all
/// enabled config servers. All failure paths are logged and swallowed.
#[tracing::instrument(name = "worker", skip_all, fields(worker = "mcp_refresh"))]
async fn refresh_once(deps: &McpRefreshDeps) {
    let ctx = match deps.ctx_provider.system_context().await {
        Ok(ctx) => ctx,
        Err(e) => {
            warn!(error = %e, "mcp_refresh: failed to obtain service context; skipping cycle");
            return;
        }
    };

    // Reconcile hub-advertised servers first so newly discovered (and approved)
    // servers are visible to the tool refresh that follows. A no-op when no hub
    // is configured; failures are logged and never abort the cycle.
    match deps.refresher.sync_hub(&ctx).await {
        Ok(summary) if summary.discovered == 0 => {
            debug!("mcp_refresh: no hub servers advertised");
        }
        Ok(summary) => {
            info!(
                discovered = summary.discovered,
                added = summary.added,
                retired = summary.retired,
                failed = summary.failed,
                "mcp_refresh: hub sync completed"
            );
        }
        Err(e) => {
            warn!(error = %e, "mcp_refresh: hub sync failed");
        }
    }

    match deps.refresher.refresh_all(&ctx).await {
        Ok(summary) if summary.attempted == 0 => {
            debug!("mcp_refresh: no enabled servers to refresh");
        }
        Ok(summary) => {
            info!(
                attempted = summary.attempted,
                succeeded = summary.succeeded,
                failed = summary.failed,
                tools_upserted = summary.tools_upserted,
                "mcp_refresh: cycle completed"
            );
        }
        Err(e) => {
            warn!(error = %e, "mcp_refresh: cycle failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::DomainError;
    use crate::domain::service::McpRefreshSummary;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingRefresher {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl McpToolRefresher for CountingRefresher {
        async fn refresh_all(
            &self,
            _ctx: &SecurityContext,
        ) -> Result<McpRefreshSummary, DomainError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(McpRefreshSummary::default())
        }
    }

    struct StubCtxProvider;

    #[async_trait]
    impl SystemContextProvider for StubCtxProvider {
        async fn system_context(&self) -> anyhow::Result<SecurityContext> {
            SecurityContext::builder()
                .subject_id(uuid::Uuid::new_v4())
                .subject_tenant_id(uuid::Uuid::new_v4())
                .build()
                .map_err(|e| anyhow::anyhow!("build ctx: {e}"))
        }
    }

    #[tokio::test]
    async fn disabled_returns_immediately() {
        let deps = McpRefreshDeps {
            refresher: Arc::new(CountingRefresher {
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            ctx_provider: Arc::new(StubCtxProvider),
        };
        let config = McpRefreshConfig {
            enabled: false,
            interval: Duration::from_mins(5),
        };
        let result = run(
            crate::infra::leader::noop(),
            config,
            deps,
            CancellationToken::new(),
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn runs_initial_cycle_then_shuts_down_on_cancel() {
        let calls = Arc::new(AtomicUsize::new(0));
        let deps = McpRefreshDeps {
            refresher: Arc::new(CountingRefresher {
                calls: Arc::clone(&calls),
            }),
            ctx_provider: Arc::new(StubCtxProvider),
        };
        let config = McpRefreshConfig {
            enabled: true,
            interval: Duration::from_mins(5),
        };
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        let handle = tokio::spawn(async move {
            run(crate::infra::leader::noop(), config, deps, c).await
        });

        // The interval's first tick fires immediately, so at least one cycle
        // runs before we request shutdown.
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();

        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(matches!(result, Ok(Ok(Ok(())))));
        assert!(calls.load(Ordering::SeqCst) >= 1);
    }
}
