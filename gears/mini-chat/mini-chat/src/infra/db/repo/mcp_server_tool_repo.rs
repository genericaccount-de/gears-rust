//! `McpServerToolRepository` implementation.
//!
//! The entity is `#[secure(unrestricted)]`; rows are keyed by `server_id`,
//! which the service authorizes via the parent server before calling here. All
//! queries run through the secure runner with an [`AccessScope::allow_all`]
//! scope for a uniform execution path.

use async_trait::async_trait;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder,
};
use time::OffsetDateTime;
use toolkit_db::secure::{
    DBRunner, SecureDeleteExt, SecureEntityExt, SecureInsertExt, SecureOnConflict, SecureUpdateExt,
};
use toolkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::UpsertMcpToolParams;
use crate::infra::db::entity::mcp_server_tool::{
    ActiveModel, Column, Entity as McpToolEntity, Model as McpToolModel,
};

pub struct McpServerToolRepository;

#[async_trait]
impl crate::domain::repos::McpServerToolRepository for McpServerToolRepository {
    async fn replace_for_server<C: DBRunner>(
        &self,
        runner: &C,
        server_id: Uuid,
        tools: Vec<UpsertMcpToolParams>,
    ) -> Result<(), DomainError> {
        let now = OffsetDateTime::now_utc();
        let incoming: Vec<String> = tools.iter().map(|t| t.original_name.clone()).collect();

        for tool in tools {
            let am = ActiveModel {
                id: Set(tool.id),
                server_id: Set(tool.server_id),
                original_name: Set(tool.original_name),
                exposed_name: Set(tool.exposed_name),
                description: Set(tool.description),
                input_schema: Set(tool.input_schema),
                schema_hash: Set(tool.schema_hash),
                enabled: Set(tool.enabled),
                created_at: Set(now),
                updated_at: Set(now),
            };
            let on_conflict =
                SecureOnConflict::<McpToolEntity>::columns([Column::ServerId, Column::OriginalName])
                    .update_columns([
                        Column::ExposedName,
                        Column::Description,
                        Column::InputSchema,
                        Column::SchemaHash,
                        Column::Enabled,
                        Column::UpdatedAt,
                    ])?;

            McpToolEntity::insert(am.clone())
                .secure()
                .scope_with_model(&AccessScope::allow_all(), &am)?
                .on_conflict(on_conflict)
                .exec(runner)
                .await?;
        }

        // Prune tools no longer advertised by the server.
        let mut cond = Condition::all().add(Column::ServerId.eq(server_id));
        if !incoming.is_empty() {
            cond = cond.add(Column::OriginalName.is_not_in(incoming));
        }
        McpToolEntity::delete_many()
            .filter(cond)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(runner)
            .await?;

        Ok(())
    }

    async fn list_by_server<C: DBRunner>(
        &self,
        runner: &C,
        server_id: Uuid,
    ) -> Result<Vec<McpToolModel>, DomainError> {
        Ok(McpToolEntity::find()
            .filter(Column::ServerId.eq(server_id))
            .order_by_asc(Column::ExposedName)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .all(runner)
            .await?)
    }

    async fn set_enabled<C: DBRunner>(
        &self,
        runner: &C,
        server_id: Uuid,
        exposed_name: &str,
        enabled: bool,
    ) -> Result<bool, DomainError> {
        let now = OffsetDateTime::now_utc();
        let result = McpToolEntity::update_many()
            .col_expr(Column::Enabled, Expr::value(enabled))
            .col_expr(Column::UpdatedAt, Expr::value(now))
            .filter(
                Condition::all()
                    .add(Column::ServerId.eq(server_id))
                    .add(Column::ExposedName.eq(exposed_name)),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(runner)
            .await?;
        Ok(result.rows_affected > 0)
    }

    async fn delete_by_server<C: DBRunner>(
        &self,
        runner: &C,
        server_id: Uuid,
    ) -> Result<u64, DomainError> {
        let result = McpToolEntity::delete_many()
            .filter(Column::ServerId.eq(server_id))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(runner)
            .await?;
        Ok(result.rows_affected)
    }
}

#[cfg(test)]
#[path = "mcp_server_tool_repo_test.rs"]
mod tests;
