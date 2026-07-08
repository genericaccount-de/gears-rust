//! Effective MCP tool resolution for the chat hot path.
//!
//! Given a caller's tenant, resolves the set of MCP tools that should be
//! injected into the LLM request and the routing map used (in Phase 3) to
//! dispatch tool calls back to their origin server. Resolution is:
//!
//! - **Read-only** — it reads server rows (`mcp_servers`) and previously
//!   discovered, already-normalized tool metadata (`mcp_server_tools`). It never
//!   performs an outbound `tools/list`; the background refresh worker keeps the
//!   metadata fresh.
//! - **Cached** — keyed by tenant with a short TTL (single-flight) so repeated
//!   turns in the same tenant don't re-query the database.
//! - **Deterministic** — servers are ordered by `(priority, name)` and tools by
//!   exposed name, so the injected tool list and any truncation are stable.
//!
//! For this phase the effective server set is limited to **auto-attach**
//! servers visible to the tenant (own + global). Role-grant matching is added
//! in a later phase once stream-time role resolution is settled.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use oagw_sdk::ServiceGatewayClientV1;
use toolkit_macros::domain_model;
use toolkit_security::SecurityContext;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

use crate::config::McpConfig;
use crate::domain::error::DomainError;
use crate::domain::llm::LlmTool;
use crate::domain::repos::{McpServerRepository, McpServerToolRepository};
use crate::infra::db::entity::mcp_server::{McpAuthKind, McpHealthStatus, Model as McpServerModel};
use crate::infra::mcp::McpTrustLevel;

/// Per-user OAuth connection-status cache TTL. Kept short so a user who
/// completes (or loses) an authorization sees the effective tool set update
/// promptly, while still sparing the OAGW status endpoint on repeated turns.
const OAUTH_STATUS_TTL: Duration = Duration::from_secs(30);

use super::mcp_schema_sanitizer;
use super::DbProvider;

/// Upper bound on an injected MCP tool description (characters). Descriptions
/// are advisory text for the model; anything longer is truncated.
const MAX_DESCRIPTION_CHARS: usize = 1024;

/// A resolved route from a provider-facing exposed tool name back to its origin
/// MCP server and original tool. Consumed by the agentic loop (Phase 3) to
/// dispatch a tool call; carries everything dispatch needs without a second DB
/// lookup.
#[domain_model]
#[derive(Debug, Clone)]
// Fields are populated during resolution and read by the Phase 3 dispatch
// loop; allow dead_code until that lands.
#[allow(dead_code)]
pub struct McpToolRoute {
    /// Registry id of the origin server.
    pub server_id: Uuid,
    /// Stable external id of the origin server (for logs/diagnostics).
    pub server_external_id: String,
    /// Original tool name as reported by the server (used on the wire).
    pub original_name: String,
    /// Provider-facing exposed name (`mcp__<hash>__<tool>`).
    pub exposed_name: String,
    /// Output-handling trust level of the origin server.
    pub trust_level: McpTrustLevel,
    /// Effective per-call timeout for this tool.
    pub call_timeout: Duration,
    /// Normalized input schema — the source of truth for argument validation
    /// before dispatch.
    pub input_schema: serde_json::Value,
}

/// Maps provider-facing exposed tool names to their origin server/tool.
///
/// May contain routes for tools that were ultimately dropped from the injected
/// request by a downstream cap; that is harmless — only tools actually present
/// in the request can be called by the model.
#[domain_model]
#[derive(Debug, Clone, Default)]
pub struct McpToolRoutingMap {
    routes: HashMap<String, McpToolRoute>,
}

// Routing-map accessors are consumed by the agentic MCP dispatch loop
// (Phase 3); allow dead_code until that lands.
#[allow(dead_code)]
impl McpToolRoutingMap {
    /// Look up the route for an exposed tool name.
    #[must_use]
    pub fn get(&self, exposed_name: &str) -> Option<&McpToolRoute> {
        self.routes.get(exposed_name)
    }

    /// Resolve a model-supplied tool name to a route.
    ///
    /// Prefers an exact exposed-name (`mcp__{hash}__{original}`) match. Some
    /// models occasionally emit the tool's *original* (unprefixed) name; when
    /// the exposed lookup misses, fall back to a unique `original_name` match.
    /// Ambiguous original names (the same tool exposed by multiple servers) do
    /// not resolve, keeping dispatch deterministic.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&McpToolRoute> {
        if let Some(route) = self.routes.get(name) {
            return Some(route);
        }
        let mut matches = self.routes.values().filter(|r| r.original_name == name);
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    }

    /// Number of routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// A non-fatal condition encountered while resolving tools, surfaced for
/// observability. Resolution never fails on these — the offending tool is
/// simply omitted.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpResolutionDiagnostic {
    /// A tool's normalized schema exceeded `mcp.max_tool_schema_bytes`.
    SchemaTooLarge {
        server_id: Uuid,
        tool: String,
        bytes: usize,
        max: usize,
    },
    /// A tool was excluded by the server's deny list.
    ToolDenied { server_id: Uuid, tool: String },
    /// The eligible tool count exceeded `mcp.max_tools_per_chat`; the list was
    /// truncated to `cap` (built-in tools take priority downstream).
    ToolCapExceeded { total: usize, cap: usize },
    /// A server was skipped because its last health probe (background refresh
    /// worker) marked it `unhealthy`. Only hard-down servers are hidden;
    /// `unknown`/`degraded`/`healthy` servers remain eligible.
    ServerUnhealthy { server_id: Uuid },
    /// An interactive-OAuth server was hidden for the caller because they have
    /// not completed (or have lost) their per-user authorization. The user must
    /// (re-)connect via the connection endpoints before its tools appear.
    ServerNotConnected { server_id: Uuid },
}

/// Outcome of effective resolution for one tenant.
#[domain_model]
#[derive(Debug, Clone, Default)]
pub struct EffectiveResolution {
    /// Provider-facing MCP tools (already normalized `Function` tools), ordered
    /// deterministically and capped at `mcp.max_tools_per_chat`.
    pub tools: Vec<LlmTool>,
    /// Exposed-name → origin routing map for the tools above. Consumed by the
    /// Phase 3 dispatch loop.
    #[allow(dead_code)]
    pub routing_map: McpToolRoutingMap,
    /// Non-fatal conditions recorded during resolution.
    pub diagnostics: Vec<McpResolutionDiagnostic>,
}

impl EffectiveResolution {
    /// Whether any MCP tool was resolved. Consumed by the Phase 3 dispatch loop.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Build the compliance snapshot of effective MCP servers/tools for the
    /// turn audit event. Returns `None` when no MCP tool was exposed. Servers
    /// and tools are ordered deterministically for stable audit output.
    #[must_use]
    pub fn effective_snapshot(&self) -> Option<mini_chat_sdk::McpEffectiveSnapshot> {
        if self.routing_map.routes.is_empty() {
            return None;
        }
        let mut by_server: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for route in self.routing_map.routes.values() {
            by_server
                .entry(route.server_id.to_string())
                .or_default()
                .push(route.original_name.clone());
        }
        let tool_count = u32::try_from(self.routing_map.routes.len()).unwrap_or(u32::MAX);
        let servers = by_server
            .into_iter()
            .map(|(server_id, mut tools)| {
                tools.sort();
                mini_chat_sdk::McpEffectiveServer { server_id, tools }
            })
            .collect();
        Some(mini_chat_sdk::McpEffectiveSnapshot {
            servers,
            tool_count,
        })
    }
}

/// A server whose tools are gated behind a per-user interactive OAuth
/// authorization. Recorded during tenant-level resolution; the per-user gating
/// pass in [`EffectiveMcpResolver::resolve`] checks the caller's live
/// connection status against OAGW and drops the tools when unconnected.
#[derive(Debug, Clone)]
struct GatedServer {
    /// Registry id of the origin server (for diagnostics).
    server_id: Uuid,
    /// OAGW upstream id the per-user token is stored against.
    upstream_id: Uuid,
    /// Exposed tool names contributed by this server that are present in the
    /// base resolution's routing map.
    exposed_names: Vec<String>,
}

/// Tenant-level resolution cached with a short TTL. Carries the shared tool set
/// plus the metadata needed to apply per-user OAuth gating without re-querying
/// the database.
#[derive(Debug, Clone)]
struct CachedTenantResolution {
    /// The full (ungated) resolution for the tenant.
    base: Arc<EffectiveResolution>,
    /// Servers requiring per-user interactive-OAuth gating. Empty for the
    /// common case, enabling a zero-cost fast path in `resolve`.
    gated: Vec<GatedServer>,
}

/// Object-safe port for resolving the effective MCP tool set for a caller.
///
/// Lets the stream hot path depend on MCP resolution without threading the
/// resolver's repository generics through [`StreamService`]. The concrete
/// implementation is [`EffectiveMcpResolver`]; tests can substitute a stub.
#[async_trait::async_trait]
pub trait McpToolResolver: Send + Sync {
    /// Resolve the effective MCP tools for the caller's tenant.
    async fn resolve(
        &self,
        ctx: &SecurityContext,
    ) -> Result<Arc<EffectiveResolution>, DomainError>;

    /// Drop the cached resolution for a tenant (e.g. after an admin change).
    /// Wired to admin mutation flows in a later phase.
    #[allow(dead_code)]
    fn invalidate(&self, tenant_id: Uuid);
}

/// Resolves and caches the effective MCP tool set per tenant.
#[domain_model]
pub struct EffectiveMcpResolver<MSR: McpServerRepository, MTR: McpServerToolRepository> {
    db: Arc<DbProvider>,
    server_repo: Arc<MSR>,
    tool_repo: Arc<MTR>,
    /// OAGW gateway used to check the caller's per-user OAuth connection status
    /// for interactive-auth servers.
    gateway: Arc<dyn ServiceGatewayClientV1>,
    cache: crate::infra::mcp::cache::TtlCache<Uuid, Arc<CachedTenantResolution>>,
    /// Per-user connection-status cache keyed by `(subject_id, upstream_id)`.
    status_cache: crate::infra::mcp::cache::TtlCache<(Uuid, Uuid), bool>,
    enabled: bool,
    max_tools_per_chat: usize,
    max_tool_schema_bytes: usize,
    default_call_timeout_secs: u64,
}

impl<MSR: McpServerRepository, MTR: McpServerToolRepository> EffectiveMcpResolver<MSR, MTR> {
    /// Build a resolver from the shared DB provider, repositories, and MCP
    /// configuration.
    #[must_use]
    pub(crate) fn new(
        db: Arc<DbProvider>,
        server_repo: Arc<MSR>,
        tool_repo: Arc<MTR>,
        gateway: Arc<dyn ServiceGatewayClientV1>,
        config: &McpConfig,
    ) -> Self {
        Self {
            db,
            server_repo,
            tool_repo,
            gateway,
            cache: crate::infra::mcp::cache::TtlCache::new(Duration::from_secs(
                config.tool_cache_ttl_secs,
            )),
            status_cache: crate::infra::mcp::cache::TtlCache::new(OAUTH_STATUS_TTL),
            enabled: config.enabled,
            max_tools_per_chat: config.max_tools_per_chat,
            max_tool_schema_bytes: config.max_tool_schema_bytes,
            default_call_timeout_secs: config.call_timeout_secs,
        }
    }

    /// Whether the caller currently has a usable per-user OAuth token for an
    /// upstream, cached briefly. A gateway error is treated as *not connected*
    /// for this turn and is **not** cached, so a transient OAGW blip only hides
    /// the tools until the next turn.
    async fn is_connected(
        &self,
        ctx: &SecurityContext,
        subject: Uuid,
        upstream_id: Uuid,
    ) -> bool {
        let result = self
            .status_cache
            .get_with((subject, upstream_id), || async {
                let probe = self
                    .gateway
                    .oauth_connection_status(ctx.clone(), upstream_id)
                    .await;
                match &probe {
                    Ok(s) => warn!(
                        %subject,
                        %upstream_id,
                        connected = s.connected,
                        "MCP-INVESTIGATE: OAGW oauth_connection_status probe (cache miss)"
                    ),
                    Err(e) => warn!(
                        %subject,
                        %upstream_id,
                        error = %e,
                        "MCP-INVESTIGATE: OAGW oauth_connection_status probe FAILED (treated as not connected, not cached)"
                    ),
                }
                probe
                    .map(|s| s.connected)
                    .map_err(|e| DomainError::service_unavailable(format!("oagw status: {e}")))
            })
            .await
            .unwrap_or(false);
        warn!(
            %subject,
            %upstream_id,
            connected = result,
            "MCP-INVESTIGATE: is_connected decision (may be a cached value)"
        );
        result
    }

    /// Load (uncached) the effective resolution for a tenant, plus the
    /// per-server gating metadata used to apply per-user OAuth gating.
    async fn load(&self, tenant_id: Uuid) -> Result<Arc<CachedTenantResolution>, DomainError> {
        let conn = self.db.conn().map_err(DomainError::from)?;
        let servers = self.server_repo.list_effective(&conn, tenant_id).await?;

        let mut diagnostics = Vec::new();
        // (LlmTool, McpToolRoute) candidates, collected in deterministic order.
        let mut candidates: Vec<(LlmTool, McpToolRoute)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        // server_id -> OAGW upstream id for interactive-OAuth servers, used to
        // build the per-user gating list once the routing map is final.
        // `build_gated_servers` intersects this against the actual routes, so it
        // is safe to include servers regardless of eligibility here.
        let oauth_upstreams: HashMap<Uuid, Uuid> = servers
            .iter()
            .filter_map(|s| oauth_upstream_of(s).map(|u| (s.id, u)))
            .collect();

        for server in &servers {
            if !server_eligible(server, &mut diagnostics) {
                continue;
            }
            let allowed = parse_string_list(server.allowed_tools.as_ref());
            let denied = parse_string_list(server.denied_tools.as_ref());
            let timeout = Duration::from_secs(
                server
                    .call_timeout_secs
                    .and_then(|s| u64::try_from(s).ok())
                    .unwrap_or(self.default_call_timeout_secs),
            );

            let mut tools = self.tool_repo.list_by_server(&conn, server.id).await?;
            tools.sort_by(|a, b| a.exposed_name.cmp(&b.exposed_name));

            for tool in tools {
                if !tool.enabled {
                    continue;
                }
                if let Some(allow) = &allowed
                    && !allow.iter().any(|n| n == &tool.original_name)
                {
                    continue;
                }
                if let Some(deny) = &denied
                    && deny.iter().any(|n| n == &tool.original_name)
                {
                    diagnostics.push(McpResolutionDiagnostic::ToolDenied {
                        server_id: server.id,
                        tool: tool.original_name.clone(),
                    });
                    continue;
                }
                let bytes = mcp_schema_sanitizer::serialized_len(&tool.input_schema);
                if bytes > self.max_tool_schema_bytes {
                    diagnostics.push(McpResolutionDiagnostic::SchemaTooLarge {
                        server_id: server.id,
                        tool: tool.original_name.clone(),
                        bytes,
                        max: self.max_tool_schema_bytes,
                    });
                    continue;
                }
                if !seen.insert(tool.exposed_name.clone()) {
                    continue;
                }

                let description =
                    mcp_schema_sanitizer::sanitize_description(&tool.description, MAX_DESCRIPTION_CHARS);
                let llm_tool = LlmTool::Function {
                    name: tool.exposed_name.clone(),
                    description,
                    parameters: tool.input_schema.clone(),
                };
                let route = McpToolRoute {
                    server_id: server.id,
                    server_external_id: server.external_id.clone(),
                    original_name: tool.original_name.clone(),
                    exposed_name: tool.exposed_name.clone(),
                    trust_level: server.trust_level.into(),
                    call_timeout: timeout,
                    input_schema: tool.input_schema.clone(),
                };
                candidates.push((llm_tool, route));
            }
        }

        // Tool-count guard: built-in tools take priority downstream, so cap the
        // MCP set at max_tools_per_chat here as an upper bound.
        let total = candidates.len();
        if total > self.max_tools_per_chat {
            candidates.truncate(self.max_tools_per_chat);
            diagnostics.push(McpResolutionDiagnostic::ToolCapExceeded {
                total,
                cap: self.max_tools_per_chat,
            });
        }

        let mut tools = Vec::with_capacity(candidates.len());
        let mut routes = HashMap::with_capacity(candidates.len());
        for (tool, route) in candidates {
            routes.insert(route.exposed_name.clone(), route);
            tools.push(tool);
        }

        // Build the gating list from the final routing map so it reflects any
        // dedup/cap truncation above.
        let gated = build_gated_servers(&routes, &oauth_upstreams);

        for g in &gated {
            warn!(
                tenant_id = %tenant_id,
                server_id = %g.server_id,
                upstream_id = %g.upstream_id,
                tools = g.exposed_names.len(),
                exposed_tools = ?g.exposed_names,
                "MCP-INVESTIGATE: gated server registered (tenant resolution, cached)"
            );
        }

        debug!(
            tenant_id = %tenant_id,
            tool_count = tools.len(),
            diagnostics = diagnostics.len(),
            gated_servers = gated.len(),
            "resolved effective MCP tools"
        );

        Ok(Arc::new(CachedTenantResolution {
            base: Arc::new(EffectiveResolution {
                tools,
                routing_map: McpToolRoutingMap { routes },
                diagnostics,
            }),
            gated,
        }))
    }
}

#[async_trait::async_trait]
impl<MSR: McpServerRepository, MTR: McpServerToolRepository> McpToolResolver
    for EffectiveMcpResolver<MSR, MTR>
{
    /// Resolve the effective MCP tools for the caller's tenant.
    ///
    /// Returns an empty resolution (no DB access) when MCP is globally disabled,
    /// so the chat hot path pays nothing when the feature is off.
    #[instrument(skip_all, fields(tenant_id = %ctx.subject_tenant_id()))]
    async fn resolve(
        &self,
        ctx: &SecurityContext,
    ) -> Result<Arc<EffectiveResolution>, DomainError> {
        if !self.enabled {
            return Ok(Arc::new(EffectiveResolution::default()));
        }
        let tenant_id = ctx.subject_tenant_id();
        let cached = self
            .cache
            .get_with(tenant_id, || self.load(tenant_id))
            .await?;

        // Fast path: no interactive-OAuth servers for this tenant, so the shared
        // resolution applies to every caller unchanged.
        if cached.gated.is_empty() {
            return Ok(Arc::clone(&cached.base));
        }

        // Per-user gating: drop tools of interactive-OAuth servers the caller is
        // not currently connected to.
        let subject = ctx.subject_id();
        warn!(
            %subject,
            gated_servers = cached.gated.len(),
            "MCP-INVESTIGATE: applying per-user OAuth gating"
        );
        let mut drop_names: HashSet<String> = HashSet::new();
        let mut disconnected: Vec<Uuid> = Vec::new();
        for g in &cached.gated {
            let connected = self.is_connected(ctx, subject, g.upstream_id).await;
            if connected {
                warn!(
                    server_id = %g.server_id,
                    upstream_id = %g.upstream_id,
                    tools = g.exposed_names.len(),
                    "MCP-INVESTIGATE: gating KEEP (server connected)"
                );
            } else {
                warn!(
                    server_id = %g.server_id,
                    upstream_id = %g.upstream_id,
                    tools = g.exposed_names.len(),
                    dropped_tools = ?g.exposed_names,
                    "MCP-INVESTIGATE: gating DROP (server not connected)"
                );
                disconnected.push(g.server_id);
                drop_names.extend(g.exposed_names.iter().cloned());
            }
        }
        warn!(
            %subject,
            gated_servers = cached.gated.len(),
            dropped_servers = disconnected.len(),
            dropped_tool_names = drop_names.len(),
            "MCP-INVESTIGATE: per-user OAuth gating summary"
        );
        if drop_names.is_empty() {
            return Ok(Arc::clone(&cached.base));
        }

        let base = &cached.base;
        let tools = base
            .tools
            .iter()
            .filter(|t| !function_name_in(t, &drop_names))
            .cloned()
            .collect();
        let routes: HashMap<String, McpToolRoute> = base
            .routing_map
            .routes
            .iter()
            .filter(|(name, _)| !drop_names.contains(*name))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut diagnostics = base.diagnostics.clone();
        for server_id in disconnected {
            diagnostics.push(McpResolutionDiagnostic::ServerNotConnected { server_id });
        }
        Ok(Arc::new(EffectiveResolution {
            tools,
            routing_map: McpToolRoutingMap { routes },
            diagnostics,
        }))
    }

    fn invalidate(&self, tenant_id: Uuid) {
        self.cache.invalidate(&tenant_id);
    }
}

/// Whether a server is eligible for tool injection. Records a diagnostic and
/// returns `false` for servers that are hidden from the effective set.
///
/// - Non-`auto_attach` servers are out of scope for the current phase.
/// - Servers last probed as `Unhealthy` by the refresh worker are hidden;
///   `Unknown` (never probed / worker disabled), `Degraded`, and `Healthy`
///   remain eligible so a server is never dropped without a positive down
///   signal.
fn server_eligible(
    server: &McpServerModel,
    diagnostics: &mut Vec<McpResolutionDiagnostic>,
) -> bool {
    if !server.auto_attach {
        return false;
    }
    if server.health_status == McpHealthStatus::Unhealthy {
        diagnostics.push(McpResolutionDiagnostic::ServerUnhealthy {
            server_id: server.id,
        });
        return false;
    }
    true
}

/// The provisioned OAGW upstream id for a server, when it uses the interactive
/// authorization-code flow and has a parseable upstream id. `None` means the
/// server's tools are not per-user gated.
fn oauth_upstream_of(server: &McpServerModel) -> Option<Uuid> {
    if server.auth_kind != McpAuthKind::OAuth2AuthCode {
        return None;
    }
    server
        .oagw_upstream_id
        .as_deref()
        .and_then(|s| Uuid::from_str(s).ok())
}

/// Group the routing map's exposed names by their interactive-OAuth origin
/// server, producing the per-user gating list. Servers without a provisioned
/// upstream in `oauth_upstreams` are not gated.
fn build_gated_servers(
    routes: &HashMap<String, McpToolRoute>,
    oauth_upstreams: &HashMap<Uuid, Uuid>,
) -> Vec<GatedServer> {
    let mut gated_map: HashMap<Uuid, GatedServer> = HashMap::new();
    for route in routes.values() {
        if let Some(upstream_id) = oauth_upstreams.get(&route.server_id) {
            gated_map
                .entry(route.server_id)
                .or_insert_with(|| GatedServer {
                    server_id: route.server_id,
                    upstream_id: *upstream_id,
                    exposed_names: Vec::new(),
                })
                .exposed_names
                .push(route.exposed_name.clone());
        }
    }
    gated_map.into_values().collect()
}

/// Whether `tool` is a `Function` tool whose (exposed) name is in `names`.
/// Non-function tools are never MCP tools and so are never dropped.
fn function_name_in(tool: &LlmTool, names: &HashSet<String>) -> bool {
    matches!(tool, LlmTool::Function { name, .. } if names.contains(name))
}

/// Parse a nullable JSON array column into a list of tool names. A present but
/// malformed value is treated as an empty list (deny-all for allow-lists).
fn parse_string_list(value: Option<&serde_json::Value>) -> Option<Vec<String>> {
    value.map(|v| {
        v.as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    })
}

#[cfg(test)]
#[path = "effective_mcp_resolver_test.rs"]
mod tests;
