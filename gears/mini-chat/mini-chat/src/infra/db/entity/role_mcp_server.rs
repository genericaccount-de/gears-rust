use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use toolkit_db::secure::Scopable;
use uuid::Uuid;

/// Per-tenant attachment of an MCP server to a role, with optional tool
/// allow/deny and priority overrides layered on top of the server defaults.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Scopable)]
#[sea_orm(table_name = "role_mcp_servers")]
#[secure(tenant_col = "tenant_id", resource_col = "id", no_owner, no_type)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub role: String,
    pub server_id: Uuid,
    pub enabled: bool,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub allowed_tools: Option<serde_json::Value>,
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub denied_tools: Option<serde_json::Value>,
    pub priority: Option<i32>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::mcp_server::Entity",
        from = "Column::ServerId",
        to = "super::mcp_server::Column::Id",
        on_delete = "Cascade"
    )]
    Server,
}

impl Related<super::mcp_server::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Server.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
