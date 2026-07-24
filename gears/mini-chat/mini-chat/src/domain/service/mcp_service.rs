//! MCP server management domain service.
//!
//! `McpService` owns three responsibilities:
//!
//! 1. **Config-seeded provisioning** (`sync_config_servers`) — a system-path
//!    reconciliation run at startup that upserts `source='config'` global
//!    servers, creates/updates their OAGW upstreams, evicts removed ones, and
//!    populates the [`McpPool`].
//! 2. **User-facing reads** (`list_servers`, `get_server`, `list_tools`) —
//!    PEP-authorized, tenant-scoped listings of servers and their persisted
//!    tool metadata.
//! 3. **Admin operations** (`refresh_tools`, role attach/detach) — operator
//!    tool re-discovery and role→server grant management.
//!
//! Server registration/update/deletion is intentionally *not* a user-facing
//! operation: servers originate from application config (`source='config'`) or
//! the MCP hub (`source='hub'`, Phase 4). The exposed-name / schema-hash used
//! by `refresh_tools` here is provisional and will be superseded by the
//! dedicated `mcp_schema_sanitizer` in Phase 2.

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use authz_resolver_sdk::PolicyEnforcer;
use oagw_sdk::{
    BeginOAuthAuthorizationRequest, CompleteOAuthAuthorizationRequest, ServiceGatewayClientV1,
};
use time::OffsetDateTime;
use toolkit_macros::domain_model;
use toolkit_security::SecurityContext;
use tracing::instrument;
use uuid::Uuid;

use crate::config::McpServerConfig;
use crate::domain::error::DomainError;
use crate::domain::ports::MiniChatMetricsPort;
use crate::domain::repos::{
    AttachRoleMcpServerParams, CreateMcpServerParams, McpServerRepository, McpServerToolRepository,
    Patch, RoleMcpServerRepository, UpdateMcpServerParams, UpsertMcpToolParams,
};
use crate::infra::db::entity::mcp_server::{
    McpAuthKind, McpHealthStatus, McpSource, McpTrustLevel, Model as McpServerModel,
};
use crate::infra::db::entity::mcp_server_tool::Model as McpToolModel;
use crate::infra::db::entity::role_mcp_server::Model as RoleMcpServerModel;
use crate::infra::mcp::{
    McpAuth, McpPool, McpServerConn, McpToolDefinition, RegistryServer, oagw_upstream,
};

use super::{DbProvider, actions, mcp_schema_sanitizer, resources};

/// Per-server concurrency cap applied when registering a server in the pool.
/// Not currently exposed via config; a conservative default.
const DEFAULT_MAX_CONCURRENT_CALLS: usize = 8;

/// Reserved synthetic server id for the MCP hub's own OAGW upstream + pool
/// entry (alias `mcp-hub`). Real server ids are UUIDs, so this never collides.
const HUB_SERVER_ID: &str = "hub";

/// Deterministic ordering priority assigned to hub-discovered servers.
const HUB_SERVER_PRIORITY: i32 = 100;

/// Parameters for attaching an MCP server to a role (service-layer input,
/// mapped from the REST DTO by the handler in Phase 1e).
#[derive(Debug, Clone)]
pub struct AssignServerToRoleInput {
    pub server_id: Uuid,
    pub enabled: bool,
    pub allowed_tools: Option<Vec<String>>,
    pub denied_tools: Option<Vec<String>>,
    pub priority: Option<i32>,
}

/// Domain service for MCP server management and OAGW upstream lifecycle.
#[domain_model]
pub struct McpService<
    MSR: McpServerRepository,
    MTR: McpServerToolRepository,
    RMSR: RoleMcpServerRepository,
> {
    db: Arc<DbProvider>,
    server_repo: Arc<MSR>,
    tool_repo: Arc<MTR>,
    role_repo: Arc<RMSR>,
    enforcer: PolicyEnforcer,
    gateway: Arc<dyn ServiceGatewayClientV1>,
    pool: Arc<McpPool>,
    config_servers: Vec<McpServerConfig>,
    /// Optional MCP hub base URL for periodic server discovery.
    hub_url: Option<String>,
    /// Auth for the hub (present iff `hub_url` is set; config-validated).
    hub_auth: Option<McpAuth>,
    default_call_timeout_secs: u64,
    metrics: Arc<dyn MiniChatMetricsPort>,
}

// Methods beyond `sync_config_servers` (a startup system path) are wired into
// the REST layer in Phase 1e; allow dead_code until then.
#[allow(dead_code)]
impl<MSR: McpServerRepository, MTR: McpServerToolRepository, RMSR: RoleMcpServerRepository>
    McpService<MSR, MTR, RMSR>
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        db: Arc<DbProvider>,
        server_repo: Arc<MSR>,
        tool_repo: Arc<MTR>,
        role_repo: Arc<RMSR>,
        enforcer: PolicyEnforcer,
        gateway: Arc<dyn ServiceGatewayClientV1>,
        pool: Arc<McpPool>,
        config_servers: Vec<McpServerConfig>,
        hub_url: Option<String>,
        hub_auth: Option<McpAuth>,
        default_call_timeout_secs: u64,
        metrics: Arc<dyn MiniChatMetricsPort>,
    ) -> Self {
        Self {
            db,
            server_repo,
            tool_repo,
            role_repo,
            enforcer,
            gateway,
            pool,
            config_servers,
            hub_url,
            hub_auth,
            default_call_timeout_secs,
            metrics,
        }
    }

    /// Shared MCP connection pool (used for shutdown wiring and stream-time
    /// tool dispatch in later phases).
    pub(crate) fn pool(&self) -> &Arc<McpPool> {
        &self.pool
    }

    // ── System path: config-seeded reconciliation ──────────────────────────

    /// Reconcile `source='config'` global servers against `mcp.servers[]`.
    ///
    /// Creates OAGW upstreams for new servers, updates existing ones, and
    /// soft-disables (plus evicts + de-provisions) servers no longer present
    /// in config. Runs with a system `SecurityContext` at startup; per-server
    /// failures are logged and do not abort the run.
    #[instrument(skip_all, fields(count = self.config_servers.len()))]
    pub(crate) async fn sync_config_servers(
        &self,
        ctx: &SecurityContext,
    ) -> Result<(), DomainError> {
        let conn = self.db.conn().map_err(DomainError::from)?;
        let existing = self
            .server_repo
            .list_by_source(&conn, None, McpSource::Config)
            .await?;
        let configured_ids: HashSet<&str> =
            self.config_servers.iter().map(|c| c.id.as_str()).collect();

        for cfg in &self.config_servers {
            let current = existing.iter().find(|m| m.external_id == cfg.id);
            if let Err(e) = self.sync_one(&conn, ctx, cfg, current).await {
                tracing::warn!(server = %cfg.id, error = %e, "MCP config server sync failed");
            }
        }

        for srv in &existing {
            if !configured_ids.contains(srv.external_id.as_str())
                && let Err(e) = self.retire_server(&conn, ctx, srv).await
            {
                tracing::warn!(
                    server = %srv.external_id,
                    error = %e,
                    "MCP config server retirement failed"
                );
            }
        }
        Ok(())
    }

    async fn sync_one<C: toolkit_db::secure::DBRunner>(
        &self,
        conn: &C,
        ctx: &SecurityContext,
        cfg: &McpServerConfig,
        current: Option<&McpServerModel>,
    ) -> Result<(), DomainError> {
        let timeout_secs = cfg.call_timeout_secs.unwrap_or(self.default_call_timeout_secs);
        let call_timeout_secs = cfg
            .call_timeout_secs
            .map(|s| i32::try_from(s).unwrap_or(i32::MAX));
        let auth_config = serde_json::to_value(&cfg.auth)
            .map_err(|e| DomainError::internal(format!("serialize mcp auth: {e}")))?;

        match current {
            None => {
                let id = Uuid::now_v7();
                let provisioned =
                    oagw_upstream::create(&self.gateway, ctx, &id.to_string(), &cfg.url, &cfg.auth, true)
                        .await
                        .map_err(map_mcp_err)?;

                self.server_repo
                    .create(
                        conn,
                        CreateMcpServerParams {
                            id,
                            tenant_id: None,
                            source: McpSource::Config,
                            external_id: cfg.id.clone(),
                            name: display_name(cfg),
                            description: cfg.description.clone(),
                            url: cfg.url.clone(),
                            enabled: true,
                            trust_level: McpTrustLevel::Untrusted,
                            auth_kind: auth_kind_of(&cfg.auth),
                            auth_config,
                            oagw_upstream_id: Some(provisioned.upstream_id.clone()),
                            priority: cfg.priority,
                            allowed_tools: cfg.allowed_tools.clone(),
                            denied_tools: cfg.denied_tools.clone(),
                            call_timeout_secs,
                            auto_attach: cfg.auto_attach,
                        },
                    )
                    .await?;

                self.pool.upsert_server(
                    id.to_string(),
                    pool_conn(provisioned.alias, provisioned.base_path, timeout_secs),
                );
            }
            Some(srv) => {
                let (alias, base_path, upstream_id) =
                    self.ensure_upstream(ctx, srv, &cfg.url, &cfg.auth).await?;

                self.server_repo
                    .update(
                        conn,
                        None,
                        srv.id,
                        UpdateMcpServerParams {
                            name: Some(display_name(cfg)),
                            description: Some(cfg.description.clone()),
                            url: Some(cfg.url.clone()),
                            enabled: Some(true),
                            trust_level: None,
                            auth_kind: Some(auth_kind_of(&cfg.auth)),
                            auth_config: Some(auth_config),
                            oagw_upstream_id: Patch::Set(upstream_id),
                            priority: Some(cfg.priority),
                            allowed_tools: patch_from_opt(cfg.allowed_tools.clone()),
                            denied_tools: patch_from_opt(cfg.denied_tools.clone()),
                            call_timeout_secs: match call_timeout_secs {
                                Some(s) => Patch::Set(s),
                                None => Patch::Clear,
                            },
                            auto_attach: Some(cfg.auto_attach),
                        },
                    )
                    .await?;

                self.pool
                    .upsert_server(srv.id.to_string(), pool_conn(alias, base_path, timeout_secs));
            }
        }
        Ok(())
    }

    /// Idempotently provision the server's OAGW upstream, returning
    /// `(alias, base_path, upstream_id)`.
    ///
    /// Uses the find-by-alias → create-or-update [`oagw_upstream::ensure`]
    /// pattern (same as the hub path) rather than trusting the stored
    /// `oagw_upstream_id`. OAGW's upstream store is in-memory and does not
    /// survive an OAGW restart, so a persisted id can dangle; `ensure` locates
    /// the upstream by its deterministic alias and re-creates it when missing.
    /// The (possibly new) `upstream_id` is written back to the server row by
    /// the caller.
    async fn ensure_upstream(
        &self,
        ctx: &SecurityContext,
        srv: &McpServerModel,
        url: &str,
        auth: &McpAuth,
    ) -> Result<(String, String, String), DomainError> {
        let p = oagw_upstream::ensure(&self.gateway, ctx, &srv.id.to_string(), url, auth, true)
            .await
            .map_err(map_mcp_err)?;
        Ok((p.alias, p.base_path, p.upstream_id))
    }

    async fn retire_server<C: toolkit_db::secure::DBRunner>(
        &self,
        conn: &C,
        ctx: &SecurityContext,
        srv: &McpServerModel,
    ) -> Result<(), DomainError> {
        self.server_repo
            .update(
                conn,
                None,
                srv.id,
                UpdateMcpServerParams {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .await?;
        self.pool.remove_server(&srv.id.to_string());
        if let Some(uid) = &srv.oagw_upstream_id {
            oagw_upstream::delete(&self.gateway, ctx, uid)
                .await
                .map_err(map_mcp_err)?;
            self.server_repo.set_oagw_upstream_id(conn, srv.id, None).await?;
        }
        Ok(())
    }

    // ── User-facing reads ──────────────────────────────────────────────────

    /// List all servers visible to the caller's tenant (own + global).
    #[instrument(skip(self, ctx))]
    pub(crate) async fn list_servers(
        &self,
        ctx: &SecurityContext,
    ) -> Result<Vec<McpServerModel>, DomainError> {
        self.enforcer
            .access_scope(ctx, &resources::MCP_SERVER, actions::LIST_MCP_SERVERS, None)
            .await?;
        let conn = self.db.conn().map_err(DomainError::from)?;
        self.server_repo.list_all(&conn, ctx.subject_tenant_id()).await
    }

    /// Fetch a single server visible to the caller's tenant.
    #[instrument(skip(self, ctx), fields(server_id = %id))]
    pub(crate) async fn get_server(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<McpServerModel, DomainError> {
        self.enforcer
            .access_scope(ctx, &resources::MCP_SERVER, actions::READ_MCP_SERVER, Some(id))
            .await?;
        let conn = self.db.conn().map_err(DomainError::from)?;
        self.server_repo
            .get(&conn, ctx.subject_tenant_id(), id)
            .await?
            .ok_or_else(|| DomainError::not_found("mcp_server", id))
    }

    /// List persisted tool metadata for a server visible to the caller.
    #[instrument(skip(self, ctx), fields(server_id = %id))]
    pub(crate) async fn list_tools(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<Vec<McpToolModel>, DomainError> {
        self.enforcer
            .access_scope(ctx, &resources::MCP_SERVER, actions::LIST_MCP_TOOLS, Some(id))
            .await?;
        let conn = self.db.conn().map_err(DomainError::from)?;
        self.server_repo
            .get(&conn, ctx.subject_tenant_id(), id)
            .await?
            .ok_or_else(|| DomainError::not_found("mcp_server", id))?;
        self.tool_repo.list_by_server(&conn, id).await
    }

    // ── Admin: tool refresh ────────────────────────────────────────────────

    /// Re-discover tools from a server via `tools/list` and persist them.
    ///
    /// The server must be present in the [`McpPool`] (config-provisioned).
    /// Returns the refreshed persisted tool set.
    #[instrument(skip(self, ctx), fields(server_id = %id))]
    pub(crate) async fn refresh_tools(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<Vec<McpToolModel>, DomainError> {
        self.enforcer
            .access_scope(ctx, &resources::MCP_SERVER, actions::REFRESH_MCP_TOOLS, Some(id))
            .await?;
        let conn = self.db.conn().map_err(DomainError::from)?;
        let server = self
            .server_repo
            .get(&conn, ctx.subject_tenant_id(), id)
            .await?
            .ok_or_else(|| DomainError::not_found("mcp_server", id))?;

        self.refresh_server_tools(&conn, ctx, &server).await?;
        self.tool_repo.list_by_server(&conn, server.id).await
    }

    /// Discovery + persistence core shared by the admin `refresh_tools`
    /// endpoint and the background refresh worker. Performs an outbound
    /// `tools/list`, records discovery latency, and replaces the persisted
    /// tool set. Returns the number of tools discovered.
    ///
    /// Requires the server to be registered in the [`McpPool`]; callers are
    /// responsible for authorization (the admin path enforces a PEP check, the
    /// system worker runs with a service context).
    async fn refresh_server_tools<C: toolkit_db::secure::DBRunner>(
        &self,
        conn: &C,
        ctx: &SecurityContext,
        server: &McpServerModel,
    ) -> Result<usize, DomainError> {
        let server_id_str = server.id.to_string();
        let discovery_start = std::time::Instant::now();
        let discovered = match self.pool.discover_tools(ctx, &server_id_str).await {
            Ok(tools) => tools,
            Err(e) => {
                // A probe failure is the signal for server health: mark
                // unhealthy with a bounded error string so admins can triage.
                let mapped = map_mcp_err(e);
                self.record_health(
                    conn,
                    server.id,
                    McpHealthStatus::Unhealthy,
                    Some(health_error_string(&mapped)),
                )
                .await;
                return Err(mapped);
            }
        };
        self.metrics.record_mcp_tool_discovery_ms(
            &server_id_str,
            discovery_start.elapsed().as_secs_f64() * 1000.0,
        );

        let params: Vec<UpsertMcpToolParams> = discovered
            .iter()
            .map(|d| to_upsert_params(server.id, d))
            .collect();
        let count = params.len();

        self.tool_repo.replace_for_server(conn, server.id, params).await?;
        self.server_repo
            .set_last_refreshed(conn, server.id, OffsetDateTime::now_utc())
            .await?;
        // Successful discovery + persistence ⇒ healthy; clear any prior error.
        self.record_health(conn, server.id, McpHealthStatus::Healthy, None).await;
        Ok(count)
    }

    /// Persist a server health transition, logging (but never propagating)
    /// failures — health is advisory telemetry and must not fail a refresh.
    async fn record_health<C: toolkit_db::secure::DBRunner>(
        &self,
        conn: &C,
        id: Uuid,
        status: McpHealthStatus,
        last_error: Option<String>,
    ) {
        if let Err(e) = self.server_repo.set_health(conn, id, status, last_error).await {
            tracing::warn!(
                server_id = %id,
                error = %e,
                "failed to persist MCP server health status"
            );
        }
    }

    /// System path: re-discover and persist tools for every enabled
    /// config-seeded server (`source='config'`, global namespace).
    ///
    /// Runs with a service `SecurityContext` on the background refresh worker
    /// under leader election. Per-server failures are logged and never abort
    /// the run — one unreachable server must not stall the rest. Returns an
    /// aggregate summary for observability.
    #[instrument(skip_all)]
    pub(crate) async fn refresh_all_config_servers(
        &self,
        ctx: &SecurityContext,
    ) -> Result<McpRefreshSummary, DomainError> {
        let conn = self.db.conn().map_err(DomainError::from)?;
        let servers = self
            .server_repo
            .list_by_source(&conn, None, McpSource::Config)
            .await?;

        let mut summary = McpRefreshSummary::default();
        for srv in &servers {
            if !srv.enabled {
                continue;
            }
            summary.attempted += 1;
            match self.refresh_server_tools(&conn, ctx, srv).await {
                Ok(count) => {
                    summary.succeeded += 1;
                    summary.tools_upserted += count;
                }
                Err(e) => {
                    summary.failed += 1;
                    tracing::warn!(
                        server = %srv.external_id,
                        error = %e,
                        "MCP background tool refresh failed for server"
                    );
                }
            }
        }

        // Refresh the role→server assignment gauge from the same leader-elected
        // cycle (single writer, periodic snapshot). Best-effort: a count failure
        // must not fail the refresh run.
        match self.role_repo.count_all(&conn).await {
            Ok(count) => self.metrics.set_mcp_role_server_assignments(count),
            Err(e) => tracing::warn!(
                error = %e,
                "failed to count MCP role-server assignments for gauge"
            ),
        }

        Ok(summary)
    }

    // ── System path: hub discovery ─────────────────────────────────────────

    /// Discover servers advertised by the configured MCP hub and reconcile
    /// them into the `source='hub'` global namespace.
    ///
    /// The hub is queried over the MCP protocol (`servers/list`) like any other
    /// endpoint. Discovered servers are recorded **disabled** pending admin
    /// approval ([`Self::approve_server`]), which is when their per-server OAGW
    /// upstream is provisioned. Servers no longer advertised are retired.
    ///
    /// A no-op (empty summary) when no hub is configured. Runs with a service
    /// `SecurityContext` on the background worker; per-server failures are
    /// logged and never abort the run.
    #[instrument(skip_all)]
    pub(crate) async fn sync_hub_servers(
        &self,
        ctx: &SecurityContext,
    ) -> Result<HubSyncSummary, DomainError> {
        let (Some(hub_url), Some(hub_auth)) = (self.hub_url.as_deref(), self.hub_auth.as_ref())
        else {
            return Ok(HubSyncSummary::default());
        };

        // Ensure the hub's own OAGW upstream exists and register it in the pool
        // so the registry call can be routed. Idempotent across restarts.
        let provisioned =
            oagw_upstream::ensure(&self.gateway, ctx, HUB_SERVER_ID, hub_url, hub_auth, true)
                .await
                .map_err(map_mcp_err)?;
        self.pool.upsert_server(
            HUB_SERVER_ID,
            pool_conn(
                provisioned.alias,
                provisioned.base_path,
                self.default_call_timeout_secs,
            ),
        );

        let advertised = self
            .pool
            .list_registry_servers(ctx, HUB_SERVER_ID)
            .await
            .map_err(map_mcp_err)?;

        let conn = self.db.conn().map_err(DomainError::from)?;
        let existing = self
            .server_repo
            .list_by_source(&conn, None, McpSource::Hub)
            .await?;
        let advertised_ids: HashSet<&str> = advertised.iter().map(|s| s.name.as_str()).collect();

        let mut summary = HubSyncSummary::default();
        for adv in &advertised {
            summary.discovered += 1;
            let current = existing.iter().find(|m| m.external_id == adv.name);
            match self.upsert_hub_server(&conn, adv, current).await {
                Ok(true) => summary.added += 1,
                Ok(false) => {}
                Err(e) => {
                    summary.failed += 1;
                    tracing::warn!(server = %adv.name, error = %e, "MCP hub server upsert failed");
                }
            }
        }

        for srv in &existing {
            if advertised_ids.contains(srv.external_id.as_str()) {
                continue;
            }
            match self.retire_server(&conn, ctx, srv).await {
                Ok(()) => summary.retired += 1,
                Err(e) => tracing::warn!(
                    server = %srv.external_id,
                    error = %e,
                    "MCP hub server retirement failed"
                ),
            }
        }

        Ok(summary)
    }

    /// Create or update a single hub-advertised server. Returns whether a new
    /// row was created. Never flips `enabled` or touches the OAGW upstream --
    /// approval owns enablement/provisioning; re-discovery only refreshes the
    /// advertised metadata (name/description/url).
    async fn upsert_hub_server<C: toolkit_db::secure::DBRunner>(
        &self,
        conn: &C,
        adv: &RegistryServer,
        current: Option<&McpServerModel>,
    ) -> Result<bool, DomainError> {
        match current {
            None => {
                self.server_repo
                    .create(
                        conn,
                        CreateMcpServerParams {
                            id: Uuid::now_v7(),
                            tenant_id: None,
                            source: McpSource::Hub,
                            external_id: adv.name.clone(),
                            name: adv.name.clone(),
                            description: adv.description.clone(),
                            url: adv.url.clone(),
                            enabled: false,
                            trust_level: McpTrustLevel::Untrusted,
                            auth_kind: McpAuthKind::None,
                            auth_config: serde_json::json!({}),
                            oagw_upstream_id: None,
                            priority: HUB_SERVER_PRIORITY,
                            allowed_tools: None,
                            denied_tools: None,
                            call_timeout_secs: None,
                            auto_attach: false,
                        },
                    )
                    .await?;
                Ok(true)
            }
            Some(srv) => {
                self.server_repo
                    .update(
                        conn,
                        None,
                        srv.id,
                        UpdateMcpServerParams {
                            name: Some(adv.name.clone()),
                            description: Some(adv.description.clone()),
                            url: Some(adv.url.clone()),
                            ..Default::default()
                        },
                    )
                    .await?;
                Ok(false)
            }
        }
    }

    // ── Admin: hub server approval ─────────────────────────────────────────

    /// Approve a hub-discovered server: provision its OAGW upstream, enable it,
    /// and register it in the pool. Admin-only. Idempotent -- re-approving an
    /// already-enabled server re-ensures the upstream and returns the row.
    #[instrument(skip(self, ctx), fields(server_id = %id))]
    pub(crate) async fn approve_server(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<McpServerModel, DomainError> {
        self.enforcer
            .access_scope(ctx, &resources::MCP_SERVER, actions::APPROVE_MCP_SERVER, Some(id))
            .await?;
        let conn = self.db.conn().map_err(DomainError::from)?;
        let server = self
            .server_repo
            .get(&conn, ctx.subject_tenant_id(), id)
            .await?
            .ok_or_else(|| DomainError::not_found("mcp_server", id))?;

        if server.source != McpSource::Hub {
            return Err(DomainError::validation(
                "approval applies only to hub-discovered servers",
            ));
        }

        // Hub-discovered servers carry no credentials in the provisional
        // registry contract; provision the upstream without auth (OAGW noop).
        let timeout_secs = server
            .call_timeout_secs
            .and_then(|s| u64::try_from(s).ok())
            .unwrap_or(self.default_call_timeout_secs);
        let provisioned = oagw_upstream::ensure(
            &self.gateway,
            ctx,
            &server.id.to_string(),
            &server.url,
            &McpAuth::None,
            true,
        )
        .await
        .map_err(map_mcp_err)?;

        let updated = self
            .server_repo
            .update(
                &conn,
                None,
                server.id,
                UpdateMcpServerParams {
                    enabled: Some(true),
                    oagw_upstream_id: Patch::Set(provisioned.upstream_id.clone()),
                    ..Default::default()
                },
            )
            .await?;

        self.pool.upsert_server(
            server.id.to_string(),
            pool_conn(provisioned.alias, provisioned.base_path, timeout_secs),
        );

        Ok(updated)
    }

    // ── Admin: role → server grants ────────────────────────────────────────

    /// Attach a server to a role (idempotent upsert).
    #[instrument(skip(self, ctx, input), fields(role = %role, server_id = %input.server_id))]
    pub(crate) async fn assign_server_to_role(
        &self,
        ctx: &SecurityContext,
        role: &str,
        input: AssignServerToRoleInput,
    ) -> Result<RoleMcpServerModel, DomainError> {
        let scope = self
            .enforcer
            .access_scope(
                ctx,
                &resources::MCP_SERVER,
                actions::ASSIGN_MCP_SERVER_ROLE,
                Some(input.server_id),
            )
            .await?;
        let tenant_id = ctx.subject_tenant_id();
        let conn = self.db.conn().map_err(DomainError::from)?;

        self.server_repo
            .get(&conn, tenant_id, input.server_id)
            .await?
            .ok_or_else(|| DomainError::not_found("mcp_server", input.server_id))?;

        self.role_repo
            .attach(
                &conn,
                &scope.tenant_only(),
                AttachRoleMcpServerParams {
                    id: Uuid::now_v7(),
                    tenant_id,
                    role: role.to_owned(),
                    server_id: input.server_id,
                    enabled: input.enabled,
                    allowed_tools: input.allowed_tools,
                    denied_tools: input.denied_tools,
                    priority: input.priority,
                },
            )
            .await
    }

    /// Detach a server from a role. Returns whether an attachment was removed.
    #[instrument(skip(self, ctx), fields(role = %role, server_id = %server_id))]
    pub(crate) async fn revoke_server_from_role(
        &self,
        ctx: &SecurityContext,
        role: &str,
        server_id: Uuid,
    ) -> Result<bool, DomainError> {
        let scope = self
            .enforcer
            .access_scope(
                ctx,
                &resources::MCP_SERVER,
                actions::REVOKE_MCP_SERVER_ROLE,
                Some(server_id),
            )
            .await?;
        let role_scope = scope.tenant_only();
        let conn = self.db.conn().map_err(DomainError::from)?;

        let attachments = self.role_repo.list_by_server(&conn, &role_scope, server_id).await?;
        for attachment in attachments {
            if attachment.role == role {
                return self.role_repo.detach(&conn, &role_scope, attachment.id).await;
            }
        }
        Ok(false)
    }

    /// List enabled server attachments for a role within the tenant scope.
    #[instrument(skip(self, ctx), fields(role = %role))]
    pub(crate) async fn list_role_servers(
        &self,
        ctx: &SecurityContext,
        role: &str,
    ) -> Result<Vec<RoleMcpServerModel>, DomainError> {
        let scope = self
            .enforcer
            .access_scope(ctx, &resources::MCP_SERVER, actions::LIST_ROLE_MCP_SERVERS, None)
            .await?;
        let conn = self.db.conn().map_err(DomainError::from)?;
        let roles = [role.to_owned()];
        self.role_repo
            .list_by_roles(&conn, &scope.tenant_only(), &roles)
            .await
    }

    // ── Interactive per-user OAuth connections ──────────────────────────────

    /// Resolve a server that must use the interactive authorization-code flow,
    /// returning the row and its provisioned OAGW upstream id.
    async fn require_oauth_upstream(
        &self,
        ctx: &SecurityContext,
        server_id: Uuid,
    ) -> Result<(McpServerModel, Uuid), DomainError> {
        let conn = self.db.conn().map_err(DomainError::from)?;
        let server = self
            .server_repo
            .get(&conn, ctx.subject_tenant_id(), server_id)
            .await?
            .ok_or_else(|| DomainError::not_found("mcp_server", server_id))?;
        if server.auth_kind != McpAuthKind::OAuth2AuthCode {
            return Err(DomainError::validation(
                "server does not use interactive OAuth authorization",
            ));
        }
        let upstream_id = server
            .oagw_upstream_id
            .as_deref()
            .ok_or_else(|| DomainError::validation("server has no provisioned OAGW upstream"))?;
        let uuid = Uuid::from_str(upstream_id)
            .map_err(|e| DomainError::internal(format!("invalid upstream id '{upstream_id}': {e}")))?;
        Ok((server, uuid))
    }

    /// Begin an interactive OAuth authorization for the caller against a
    /// server's OAGW upstream. Returns the browser URL + CSRF state.
    #[instrument(skip(self, ctx, redirect_uri), fields(server_id = %server_id))]
    pub(crate) async fn begin_oauth_connection(
        &self,
        ctx: &SecurityContext,
        server_id: Uuid,
        redirect_uri: String,
    ) -> Result<McpConnectionBegin, DomainError> {
        self.enforcer
            .access_scope(
                ctx,
                &resources::MCP_SERVER,
                actions::MANAGE_MCP_CONNECTION,
                Some(server_id),
            )
            .await?;
        let (server, upstream_id) = self.require_oauth_upstream(ctx, server_id).await?;
        let scopes = oauth_scopes_of(&server);
        let resp = self
            .gateway
            .begin_oauth_authorization(
                ctx.clone(),
                BeginOAuthAuthorizationRequest {
                    upstream_id,
                    scopes,
                    redirect_uri,
                    client_name: server.name.clone(),
                },
            )
            .await
            .map_err(map_gateway_err)?;
        Ok(McpConnectionBegin {
            authorization_url: resp.authorization_url,
            state: resp.state,
        })
    }

    /// Complete an authorization after the browser callback (exchange code).
    #[instrument(skip(self, ctx, state, code))]
    pub(crate) async fn complete_oauth_connection(
        &self,
        ctx: &SecurityContext,
        state: String,
        code: String,
    ) -> Result<(), DomainError> {
        self.enforcer
            .access_scope(ctx, &resources::MCP_SERVER, actions::MANAGE_MCP_CONNECTION, None)
            .await?;
        self.gateway
            .complete_oauth_authorization(
                ctx.clone(),
                CompleteOAuthAuthorizationRequest { state, code },
            )
            .await
            .map_err(map_gateway_err)?;

        // Eagerly discover the just-connected server's tools with the caller's
        // context. The background refresh worker runs as the service principal,
        // which has no per-user auth-code token and therefore can never discover
        // tools for interactive-OAuth servers; without this, tools would stay
        // absent until (and unless) a differently-scoped refresh happened to
        // succeed. Best-effort: discovery failures never fail the connection.
        self.discover_tools_for_connected_user_servers(ctx).await;
        Ok(())
    }

    /// Discover and persist tools for every enabled config-seeded auth-code
    /// server the caller currently has a stored token for, using the caller's
    /// context. Invoked after a successful interactive connection so a freshly
    /// connected server's tools appear without waiting on the service-identity
    /// background worker (which cannot read per-user tokens).
    ///
    /// The completion endpoint is server-agnostic (OAGW returns no id), so all
    /// connected auth-code servers are probed; discovery for an already-populated
    /// server is idempotent. Every failure path is logged and swallowed — tool
    /// discovery must never fail the connection the user just completed.
    async fn discover_tools_for_connected_user_servers(&self, ctx: &SecurityContext) {
        let conn = match self.db.conn() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "on-connect MCP tool discovery: db conn failed");
                return;
            }
        };
        let servers = match self
            .server_repo
            .list_by_source(&conn, None, McpSource::Config)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "on-connect MCP tool discovery: list servers failed");
                return;
            }
        };
        for srv in &servers {
            if !srv.enabled || srv.auth_kind != McpAuthKind::OAuth2AuthCode {
                continue;
            }
            let Some(upstream_id) = srv.oagw_upstream_id.as_deref() else {
                continue;
            };
            let Ok(upstream_uuid) = Uuid::from_str(upstream_id) else {
                continue;
            };
            // Only discover for servers the caller actually holds a token for;
            // probing an unconnected server would just 401.
            match self.gateway.oauth_connection_status(ctx.clone(), upstream_uuid).await {
                Ok(status) if status.connected => {}
                Ok(_) => continue,
                Err(e) => {
                    tracing::warn!(
                        server = %srv.external_id,
                        error = %e,
                        "on-connect MCP tool discovery: connection status check failed"
                    );
                    continue;
                }
            }
            match self.refresh_server_tools(&conn, ctx, srv).await {
                Ok(count) => tracing::info!(
                    server = %srv.external_id,
                    tools = count,
                    "on-connect MCP tool discovery succeeded"
                ),
                Err(e) => tracing::warn!(
                    server = %srv.external_id,
                    error = %e,
                    "on-connect MCP tool discovery failed"
                ),
            }
        }
    }

    /// Revoke the caller's stored authorization for a server.
    #[instrument(skip(self, ctx), fields(server_id = %server_id))]
    pub(crate) async fn revoke_oauth_connection(
        &self,
        ctx: &SecurityContext,
        server_id: Uuid,
    ) -> Result<(), DomainError> {
        self.enforcer
            .access_scope(
                ctx,
                &resources::MCP_SERVER,
                actions::MANAGE_MCP_CONNECTION,
                Some(server_id),
            )
            .await?;
        let (_server, upstream_id) = self.require_oauth_upstream(ctx, server_id).await?;
        self.gateway
            .revoke_oauth_authorization(ctx.clone(), upstream_id)
            .await
            .map_err(map_gateway_err)
    }

    /// Report the caller's connection status for a server.
    #[instrument(skip(self, ctx), fields(server_id = %server_id))]
    pub(crate) async fn oauth_connection_status(
        &self,
        ctx: &SecurityContext,
        server_id: Uuid,
    ) -> Result<McpConnectionStatus, DomainError> {
        self.enforcer
            .access_scope(ctx, &resources::MCP_SERVER, actions::READ_MCP_SERVER, Some(server_id))
            .await?;
        let (_server, upstream_id) = self.require_oauth_upstream(ctx, server_id).await?;
        let status = self
            .gateway
            .oauth_connection_status(ctx.clone(), upstream_id)
            .await
            .map_err(map_gateway_err)?;
        Ok(McpConnectionStatus {
            connected: status.connected,
            expires_at_unix: status.expires_at_unix,
        })
    }
}

/// Aggregate outcome of one background refresh cycle across all servers.
#[derive(Debug, Clone, Copy, Default)]
pub struct McpRefreshSummary {
    /// Enabled config servers a refresh was attempted for.
    pub attempted: usize,
    /// Servers whose tools were successfully re-discovered and persisted.
    pub succeeded: usize,
    /// Servers whose refresh failed (logged, non-fatal).
    pub failed: usize,
    /// Total tools persisted across all successful servers.
    pub tools_upserted: usize,
}

/// Aggregate outcome of one hub discovery/reconciliation cycle.
#[derive(Debug, Clone, Copy, Default)]
pub struct HubSyncSummary {
    /// Servers advertised by the hub this cycle.
    pub discovered: usize,
    /// Newly recorded servers (pending approval).
    pub added: usize,
    /// Previously-known servers retired (no longer advertised).
    pub retired: usize,
    /// Upserts that failed (logged, non-fatal).
    pub failed: usize,
}

/// System-path tool refresh surface, decoupled from `McpService`'s repository
/// generics so the background worker can hold an `Arc<dyn McpToolRefresher>`.
#[async_trait::async_trait]
pub trait McpToolRefresher: Send + Sync {
    /// Re-discover and persist tools for every enabled config-seeded server.
    async fn refresh_all(
        &self,
        ctx: &SecurityContext,
    ) -> Result<McpRefreshSummary, DomainError>;

    /// Discover and reconcile hub-advertised servers. Defaults to a no-op so
    /// implementations without a hub need not override it.
    async fn sync_hub(
        &self,
        _ctx: &SecurityContext,
    ) -> Result<HubSyncSummary, DomainError> {
        Ok(HubSyncSummary::default())
    }
}

#[async_trait::async_trait]
impl<MSR: McpServerRepository, MTR: McpServerToolRepository, RMSR: RoleMcpServerRepository>
    McpToolRefresher for McpService<MSR, MTR, RMSR>
{
    async fn refresh_all(
        &self,
        ctx: &SecurityContext,
    ) -> Result<McpRefreshSummary, DomainError> {
        self.refresh_all_config_servers(ctx).await
    }

    async fn sync_hub(&self, ctx: &SecurityContext) -> Result<HubSyncSummary, DomainError> {
        self.sync_hub_servers(ctx).await
    }
}

/// Result of beginning an interactive OAuth connection.
#[derive(Debug, Clone)]
pub struct McpConnectionBegin {
    /// URL to open in the user's browser to obtain consent.
    pub authorization_url: String,
    /// Opaque CSRF state, echoed back on the callback for completion.
    pub state: String,
}

/// Caller's connection status for a server.
#[derive(Debug, Clone, Copy)]
pub struct McpConnectionStatus {
    /// Whether a usable per-user token is stored in the gateway.
    pub connected: bool,
    /// Access-token expiry (Unix seconds), when connected.
    pub expires_at_unix: Option<i64>,
}

// ── Free helpers ───────────────────────────────────────────────────────────

/// Map an infra-layer MCP error to a client-safe domain error. Consumed by
/// value so it composes with `Result::map_err`.
#[allow(clippy::needless_pass_by_value)]
fn map_mcp_err(e: crate::infra::mcp::McpError) -> DomainError {
    DomainError::service_unavailable(format!("mcp: {e}"))
}

/// Map an OAGW gateway failure to a client-safe domain error. The gateway
/// already emits canonical AIP-193 errors; surface them as a
/// service-unavailable so the client sees a stable, client-safe message.
#[allow(clippy::needless_pass_by_value)]
fn map_gateway_err(e: impl std::fmt::Display) -> DomainError {
    DomainError::service_unavailable(format!("oagw: {e}"))
}

/// Extract the requested OAuth scopes from a server's stored `auth_config`.
/// Returns an empty list when the config is absent or not the auth-code
/// variant (the authorization server intersects against what it advertises).
fn oauth_scopes_of(server: &McpServerModel) -> Vec<String> {
    match serde_json::from_value::<McpAuth>(server.auth_config.clone()) {
        Ok(McpAuth::OAuth2AuthorizationCode { scopes }) => scopes,
        _ => Vec::new(),
    }
}

/// Bounded, char-boundary-safe error string for the `mcp_servers.last_error`
/// column (avoids persisting unbounded upstream diagnostics).
const MAX_HEALTH_ERROR_CHARS: usize = 500;
fn health_error_string(e: &DomainError) -> String {
    e.to_string().chars().take(MAX_HEALTH_ERROR_CHARS).collect()
}

/// Effective display name for a config server (falls back to its id).
fn display_name(cfg: &McpServerConfig) -> String {
    if cfg.name.trim().is_empty() {
        cfg.id.clone()
    } else {
        cfg.name.clone()
    }
}

/// Denormalized auth kind for the `auth_kind` column.
fn auth_kind_of(auth: &McpAuth) -> McpAuthKind {
    match auth {
        McpAuth::None => McpAuthKind::None,
        McpAuth::Bearer { .. } => McpAuthKind::Bearer,
        McpAuth::ApiKey { .. } => McpAuthKind::ApiKey,
        McpAuth::OAuth2 { .. } => McpAuthKind::OAuth2,
        McpAuth::OAuth2AuthorizationCode { .. } => McpAuthKind::OAuth2AuthCode,
    }
}

/// A config allow/deny list overwrites the stored value (`None` clears it).
fn patch_from_opt(value: Option<Vec<String>>) -> Patch<Vec<String>> {
    match value {
        Some(v) => Patch::Set(v),
        None => Patch::Clear,
    }
}

/// Build pool connection parameters for a server.
fn pool_conn(alias: String, base_path: String, timeout_secs: u64) -> McpServerConn {
    McpServerConn {
        alias,
        base_path,
        call_timeout: Duration::from_secs(timeout_secs),
        max_concurrent_calls: DEFAULT_MAX_CONCURRENT_CALLS,
    }
}

/// Convert a discovered tool definition to persistence params.
///
/// The input schema is normalized to the provider-supported JSON Schema subset
/// at store time so the `mcp_server_tools` table is the canonical, provider-safe
/// source of truth; the schema hash is taken over the normalized form.
fn to_upsert_params(server_id: Uuid, def: &McpToolDefinition) -> UpsertMcpToolParams {
    let input_schema = mcp_schema_sanitizer::normalize_schema(&def.input_schema);
    let schema_hash = mcp_schema_sanitizer::schema_hash(&input_schema);
    UpsertMcpToolParams {
        id: Uuid::now_v7(),
        server_id,
        original_name: def.name.clone(),
        exposed_name: mcp_schema_sanitizer::exposed_name(server_id, &def.name),
        description: def.description.clone(),
        input_schema,
        schema_hash,
        enabled: true,
    }
}

#[cfg(test)]
#[path = "mcp_service_test.rs"]
mod tests;
