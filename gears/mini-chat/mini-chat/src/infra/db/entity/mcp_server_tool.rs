use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use toolkit_db::secure::Scopable;
use uuid::Uuid;

/// Discovered tool metadata for an MCP server — the backing store for the
/// read-through tool cache.
///
/// Marked `#[secure(unrestricted)]`: rows carry no tenant of their own and are
/// always accessed by `server_id` **after** the parent [`super::mcp_server`]
/// has been authorized in the caller's scope.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Scopable)]
#[sea_orm(table_name = "mcp_server_tools")]
#[secure(unrestricted)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub server_id: Uuid,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub original_name: String,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub exposed_name: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub input_schema: serde_json::Value,
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub schema_hash: String,
    pub enabled: bool,
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
