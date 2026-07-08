//! MCP server registry repository.
//!
//! `mcp_servers.tenant_id` is nullable — a NULL tenant denotes a **global**
//! server visible to every tenant. Because `SecureORM`'s tenant-scoped helpers
//! assume a non-null tenant, reads use a dedicated union predicate
//! (`tenant_id = <tenant> OR tenant_id IS NULL`) executed through the sanctioned
//! secure runner with an `AccessScope::allow_all` scope; PEP authorization is
//! enforced by the service layer before these methods are called.

use async_trait::async_trait;
use time::OffsetDateTime;
use toolkit_db::secure::DBRunner;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::infra::db::entity::mcp_server::{
    McpAuthKind, McpHealthStatus, McpSource, McpTrustLevel, Model as McpServerModel,
};

/// Parameters for registering a new MCP server.
#[derive(Debug, Clone)]
pub struct CreateMcpServerParams {
    pub id: Uuid,
    /// `None` registers a global (all-tenant) server.
    pub tenant_id: Option<Uuid>,
    pub source: McpSource,
    pub external_id: String,
    pub name: String,
    pub description: String,
    pub url: String,
    pub enabled: bool,
    pub trust_level: McpTrustLevel,
    pub auth_kind: McpAuthKind,
    pub auth_config: serde_json::Value,
    pub oagw_upstream_id: Option<String>,
    pub priority: i32,
    pub allowed_tools: Option<Vec<String>>,
    pub denied_tools: Option<Vec<String>>,
    pub call_timeout_secs: Option<i32>,
    pub auto_attach: bool,
}

/// A three-state update for a nullable column: keep the current value, set a
/// new value, or clear it to NULL. Avoids the ambiguous `Option<Option<T>>`.
#[derive(Debug, Clone, Default)]
pub enum Patch<T> {
    /// Leave the column unchanged.
    #[default]
    Keep,
    /// Overwrite with a concrete value.
    Set(T),
    /// Set the column to NULL.
    Clear,
}

/// Partial update. `Option` fields overwrite when `Some`; `Patch` fields cover
/// nullable columns with explicit keep / set / clear semantics.
#[derive(Debug, Clone, Default)]
pub struct UpdateMcpServerParams {
    pub name: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub enabled: Option<bool>,
    pub trust_level: Option<McpTrustLevel>,
    pub auth_kind: Option<McpAuthKind>,
    pub auth_config: Option<serde_json::Value>,
    pub oagw_upstream_id: Patch<String>,
    pub priority: Option<i32>,
    pub allowed_tools: Patch<Vec<String>>,
    pub denied_tools: Patch<Vec<String>>,
    pub call_timeout_secs: Patch<i32>,
    pub auto_attach: Option<bool>,
}

#[async_trait]
pub trait McpServerRepository: Send + Sync {
    /// Register a new server (tenant-scoped or global).
    async fn create<C: DBRunner>(
        &self,
        runner: &C,
        params: CreateMcpServerParams,
    ) -> Result<McpServerModel, DomainError>;

    /// Fetch a single non-deleted server visible to `tenant_id`
    /// (own tenant or global).
    async fn get<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<McpServerModel>, DomainError>;

    /// Look up a server by its `(tenant_id, source, external_id)` natural key.
    /// `tenant_id = None` targets the global namespace. Used by config/hub sync.
    async fn find_by_external<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Option<Uuid>,
        source: McpSource,
        external_id: &str,
    ) -> Result<Option<McpServerModel>, DomainError>;

    /// All enabled, non-deleted servers visible to `tenant_id` (own + global),
    /// ordered by `(priority ASC, name ASC)`. Backs the effective resolver.
    async fn list_effective<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Uuid,
    ) -> Result<Vec<McpServerModel>, DomainError>;

    /// All non-deleted servers visible to `tenant_id` (own + global), including
    /// disabled ones. Backs the admin listing endpoint.
    async fn list_all<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Uuid,
    ) -> Result<Vec<McpServerModel>, DomainError>;

    /// All non-deleted servers with the given `(tenant_id, source)`
    /// (`tenant_id = None` targets the global namespace), including disabled
    /// ones. Backs config-seeded startup reconciliation.
    async fn list_by_source<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Option<Uuid>,
        source: McpSource,
    ) -> Result<Vec<McpServerModel>, DomainError>;

    /// Apply a partial update to a server owned by `tenant_id`
    /// (`None` = global). Returns the updated row.
    async fn update<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Option<Uuid>,
        id: Uuid,
        params: UpdateMcpServerParams,
    ) -> Result<McpServerModel, DomainError>;

    /// System path: record health status (background refresh worker).
    async fn set_health<C: DBRunner>(
        &self,
        runner: &C,
        id: Uuid,
        status: McpHealthStatus,
        last_error: Option<String>,
    ) -> Result<(), DomainError>;

    /// System path: record last successful tool refresh timestamp.
    async fn set_last_refreshed<C: DBRunner>(
        &self,
        runner: &C,
        id: Uuid,
        at: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// System path: bind or clear the provisioned OAGW upstream id.
    async fn set_oagw_upstream_id<C: DBRunner>(
        &self,
        runner: &C,
        id: Uuid,
        upstream_id: Option<String>,
    ) -> Result<(), DomainError>;

    /// Soft-delete a server owned by `tenant_id` (`None` = global). Returns
    /// whether a row was affected.
    async fn soft_delete<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Option<Uuid>,
        id: Uuid,
    ) -> Result<bool, DomainError>;
}
