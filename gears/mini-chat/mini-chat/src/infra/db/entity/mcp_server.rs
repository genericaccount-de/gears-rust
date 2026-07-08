use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use toolkit_db::secure::Scopable;
use uuid::Uuid;

/// MCP server registry row.
///
/// `tenant_id` is nullable: a NULL tenant denotes a **global** server visible
/// to every tenant. Because `SecureORM`'s `secure_insert`/`secure_update` helpers
/// assume a non-null tenant, global rows are written via direct `SeaORM` in the
/// repo layer, and reads use a dedicated scope-aware union query
/// (`tenant_id = <scope> OR tenant_id IS NULL`).
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Scopable)]
#[sea_orm(table_name = "mcp_servers")]
#[secure(tenant_col = "tenant_id", resource_col = "id", no_owner, no_type)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub source: McpSource,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub external_id: String,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    #[sea_orm(column_type = "Text")]
    pub url: String,
    pub enabled: bool,
    pub trust_level: McpTrustLevel,
    pub auth_kind: McpAuthKind,
    #[sea_orm(column_type = "JsonBinary")]
    pub auth_config: serde_json::Value,
    #[sea_orm(column_type = "String(StringLen::N(64))", nullable)]
    pub oagw_upstream_id: Option<String>,
    pub priority: i32,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub allowed_tools: Option<serde_json::Value>,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub denied_tools: Option<serde_json::Value>,
    pub call_timeout_secs: Option<i32>,
    pub auto_attach: bool,
    pub health_status: McpHealthStatus,
    pub last_refreshed_at: Option<OffsetDateTime>,
    #[sea_orm(column_type = "Text", nullable)]
    pub last_error: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

/// Provenance of a registered server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum McpSource {
    #[sea_orm(string_value = "config")]
    Config,
    #[sea_orm(string_value = "hub")]
    Hub,
    #[sea_orm(string_value = "api")]
    Api,
}

/// Output-handling trust level (mirrors [`crate::infra::mcp::McpTrustLevel`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum McpTrustLevel {
    #[sea_orm(string_value = "trusted")]
    Trusted,
    #[sea_orm(string_value = "restricted")]
    Restricted,
    #[sea_orm(string_value = "untrusted")]
    Untrusted,
}

impl From<McpTrustLevel> for crate::infra::mcp::McpTrustLevel {
    fn from(v: McpTrustLevel) -> Self {
        match v {
            McpTrustLevel::Trusted => Self::Trusted,
            McpTrustLevel::Restricted => Self::Restricted,
            McpTrustLevel::Untrusted => Self::Untrusted,
        }
    }
}

impl From<crate::infra::mcp::McpTrustLevel> for McpTrustLevel {
    fn from(v: crate::infra::mcp::McpTrustLevel) -> Self {
        match v {
            crate::infra::mcp::McpTrustLevel::Trusted => Self::Trusted,
            crate::infra::mcp::McpTrustLevel::Restricted => Self::Restricted,
            crate::infra::mcp::McpTrustLevel::Untrusted => Self::Untrusted,
        }
    }
}

/// Authentication kind (denormalized from `auth_config` for filtering).
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum McpAuthKind {
    #[sea_orm(string_value = "none")]
    None,
    #[sea_orm(string_value = "bearer")]
    Bearer,
    #[sea_orm(string_value = "api_key")]
    ApiKey,
    #[sea_orm(string_value = "oauth2")]
    OAuth2,
    #[sea_orm(string_value = "oauth2_auth_code")]
    OAuth2AuthCode,
}

/// Last-observed health of a server (updated by the background refresh worker).
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum McpHealthStatus {
    #[sea_orm(string_value = "unknown")]
    Unknown,
    #[sea_orm(string_value = "healthy")]
    Healthy,
    #[sea_orm(string_value = "degraded")]
    Degraded,
    #[sea_orm(string_value = "unhealthy")]
    Unhealthy,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::mcp_server_tool::Entity")]
    Tools,
    #[sea_orm(has_many = "super::role_mcp_server::Entity")]
    RoleAttachments,
}

impl Related<super::mcp_server_tool::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Tools.def()
    }
}

impl Related<super::role_mcp_server::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RoleAttachments.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
