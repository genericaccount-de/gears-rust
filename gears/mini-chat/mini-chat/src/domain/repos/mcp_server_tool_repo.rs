//! MCP server tool metadata repository — backing store for the read-through
//! tool cache. Rows are always accessed by `server_id` after the parent server
//! has been authorized in the caller's scope.

use async_trait::async_trait;
use toolkit_db::secure::DBRunner;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::infra::db::entity::mcp_server_tool::Model as McpToolModel;

/// Parameters for upserting a discovered tool.
#[derive(Debug, Clone)]
pub struct UpsertMcpToolParams {
    pub id: Uuid,
    pub server_id: Uuid,
    pub original_name: String,
    pub exposed_name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub schema_hash: String,
    pub enabled: bool,
}

#[async_trait]
pub trait McpServerToolRepository: Send + Sync {
    /// Replace the full tool set for a server: upsert the provided tools (keyed
    /// by `(server_id, original_name)`) and delete any rows no longer present.
    async fn replace_for_server<C: DBRunner>(
        &self,
        runner: &C,
        server_id: Uuid,
        tools: Vec<UpsertMcpToolParams>,
    ) -> Result<(), DomainError>;

    /// List all tools for a server.
    async fn list_by_server<C: DBRunner>(
        &self,
        runner: &C,
        server_id: Uuid,
    ) -> Result<Vec<McpToolModel>, DomainError>;

    /// Toggle a single tool's enabled flag by exposed name. Returns whether a
    /// row was affected.
    async fn set_enabled<C: DBRunner>(
        &self,
        runner: &C,
        server_id: Uuid,
        exposed_name: &str,
        enabled: bool,
    ) -> Result<bool, DomainError>;

    /// Delete all tools for a server (used on server removal / cache purge).
    async fn delete_by_server<C: DBRunner>(
        &self,
        runner: &C,
        server_id: Uuid,
    ) -> Result<u64, DomainError>;
}
