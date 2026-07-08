//! `RoleMcpServerRepository` implementation — fully tenant-scoped, using the
//! standard `SecureORM` helpers with the caller's [`AccessScope`].

use async_trait::async_trait;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder,
};
use time::OffsetDateTime;
use toolkit_db::secure::{
    DBRunner, SecureDeleteExt, SecureEntityExt, SecureInsertExt, SecureOnConflict,
};
use toolkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::AttachRoleMcpServerParams;
use crate::infra::db::entity::role_mcp_server::{
    ActiveModel, Column, Entity as RoleMcpServerEntity, Model as RoleMcpServerModel,
};

pub struct RoleMcpServerRepository;

fn tools_to_json(tools: Option<Vec<String>>) -> Option<serde_json::Value> {
    tools.map(|t| serde_json::json!(t))
}

#[async_trait]
impl crate::domain::repos::RoleMcpServerRepository for RoleMcpServerRepository {
    async fn attach<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        params: AttachRoleMcpServerParams,
    ) -> Result<RoleMcpServerModel, DomainError> {
        let now = OffsetDateTime::now_utc();
        let am = ActiveModel {
            id: Set(params.id),
            tenant_id: Set(params.tenant_id),
            role: Set(params.role.clone()),
            server_id: Set(params.server_id),
            enabled: Set(params.enabled),
            allowed_tools: Set(tools_to_json(params.allowed_tools)),
            denied_tools: Set(tools_to_json(params.denied_tools)),
            priority: Set(params.priority),
            created_at: Set(now),
            updated_at: Set(now),
        };

        let on_conflict = SecureOnConflict::<RoleMcpServerEntity>::columns([
            Column::TenantId,
            Column::Role,
            Column::ServerId,
        ])
        .update_columns([
            Column::Enabled,
            Column::AllowedTools,
            Column::DeniedTools,
            Column::Priority,
            Column::UpdatedAt,
        ])?;

        RoleMcpServerEntity::insert(am.clone())
            .secure()
            .scope_with_model(scope, &am)?
            .on_conflict(on_conflict)
            .exec(runner)
            .await?;

        RoleMcpServerEntity::find()
            .filter(
                Condition::all()
                    .add(Column::TenantId.eq(params.tenant_id))
                    .add(Column::Role.eq(params.role))
                    .add(Column::ServerId.eq(params.server_id)),
            )
            .secure()
            .scope_with(scope)
            .one(runner)
            .await?
            .ok_or_else(|| {
                DomainError::database("role_mcp_server row missing after upsert".to_owned())
            })
    }

    async fn list_by_roles<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        roles: &[String],
    ) -> Result<Vec<RoleMcpServerModel>, DomainError> {
        if roles.is_empty() {
            return Ok(Vec::new());
        }
        Ok(RoleMcpServerEntity::find()
            .filter(
                Condition::all()
                    .add(Column::Role.is_in(roles.iter().cloned()))
                    .add(Column::Enabled.eq(true)),
            )
            .order_by_asc(Column::Role)
            .secure()
            .scope_with(scope)
            .all(runner)
            .await?)
    }

    async fn list_by_server<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        server_id: Uuid,
    ) -> Result<Vec<RoleMcpServerModel>, DomainError> {
        Ok(RoleMcpServerEntity::find()
            .filter(Column::ServerId.eq(server_id))
            .order_by_asc(Column::Role)
            .secure()
            .scope_with(scope)
            .all(runner)
            .await?)
    }

    async fn detach<C: DBRunner>(
        &self,
        runner: &C,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<bool, DomainError> {
        let result = RoleMcpServerEntity::delete_many()
            .filter(Column::Id.eq(id))
            .secure()
            .scope_with(scope)
            .exec(runner)
            .await?;
        Ok(result.rows_affected > 0)
    }

    async fn count_all<C: DBRunner>(&self, runner: &C) -> Result<u64, DomainError> {
        // Deployment-wide gauge: count across all tenants via an unscoped
        // (system) read. The service layer restricts this to the background
        // worker's service context.
        Ok(RoleMcpServerEntity::find()
            .secure()
            .scope_with(&AccessScope::allow_all())
            .count(runner)
            .await?)
    }
}

#[cfg(test)]
#[path = "role_mcp_server_repo_test.rs"]
mod tests;
