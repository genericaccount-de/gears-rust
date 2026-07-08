//! Per-tenant role → MCP server attachment repository. Fully tenant-scoped, so
//! it uses the standard `SecureORM` helpers with the caller's [`AccessScope`].

use async_trait::async_trait;
use toolkit_db::secure::DBRunner;
use toolkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::infra::db::entity::role_mcp_server::Model as RoleMcpServerModel;

/// Parameters for attaching (or re-attaching) a server to a role.
#[derive(Debug, Clone)]
pub struct AttachRoleMcpServerParams {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
    pub server_id: Uuid,
    pub enabled: bool,
    pub allowed_tools: Option<Vec<String>>,
    pub denied_tools: Option<Vec<String>>,
    pub priority: Option<i32>,
}

#[async_trait]
pub trait RoleMcpServerRepository: Send + Sync {
    /// Attach a server to a role (idempotent upsert on
    /// `(tenant_id, role, server_id)`).
    async fn attach<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: AttachRoleMcpServerParams,
    ) -> Result<RoleMcpServerModel, DomainError>;

    /// List enabled attachments for a set of roles within the tenant scope.
    async fn list_by_roles<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        roles: &[String],
    ) -> Result<Vec<RoleMcpServerModel>, DomainError>;

    /// List all attachments for a given server within the tenant scope.
    async fn list_by_server<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        server_id: Uuid,
    ) -> Result<Vec<RoleMcpServerModel>, DomainError>;

    /// Detach a server from a role by attachment id. Returns whether a row was
    /// removed.
    async fn detach<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<bool, DomainError>;

    /// System path: count all role→server attachments across every tenant.
    /// Backs the `mcp_role_server_assignments` gauge, refreshed from the
    /// leader-elected background worker.
    async fn count_all<C: DBRunner>(&self, runner: &C) -> Result<u64, DomainError>;
}
