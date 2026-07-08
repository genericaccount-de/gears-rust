//! `McpServerRepository` implementation.
//!
//! Global (NULL-tenant) rows can't use `SecureORM`'s tenant-scoped helpers, so
//! reads run through the secure runner with an [`AccessScope::allow_all`] scope
//! plus an explicit `tenant_id = <tenant> OR tenant_id IS NULL` predicate.
//! PEP authorization is enforced by the service layer before these calls.

use async_trait::async_trait;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveEnum, ActiveValue::Set, ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder,
    Value,
};
use time::OffsetDateTime;
use toolkit_db::secure::{
    DBRunner, SecureEntityExt, SecureInsertExt, SecureOnConflict, SecureUpdateExt,
};
use toolkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::{CreateMcpServerParams, Patch, UpdateMcpServerParams};
use crate::infra::db::entity::mcp_server::{
    ActiveModel, Column, Entity as McpServerEntity, McpHealthStatus, McpSource,
    Model as McpServerModel,
};

pub struct McpServerRepository;

/// Serialize an optional tool-name list to the JSON column representation.
fn tools_to_json(tools: Option<Vec<String>>) -> Option<serde_json::Value> {
    tools.map(|t| serde_json::json!(t))
}

/// Apply a [`Patch`] to a nullable scalar column.
fn apply_patch<T>(patch: Patch<T>, existing: Option<T>) -> Option<T> {
    match patch {
        Patch::Keep => existing,
        Patch::Set(v) => Some(v),
        Patch::Clear => None,
    }
}

/// Apply a [`Patch`] to a nullable JSON tool-name-list column.
fn apply_tools_patch(
    patch: Patch<Vec<String>>,
    existing: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    match patch {
        Patch::Keep => existing,
        Patch::Set(v) => Some(serde_json::json!(v)),
        Patch::Clear => None,
    }
}

/// `deleted_at IS NULL AND (tenant_id = <tenant> OR tenant_id IS NULL)`.
fn visible_to_tenant(tenant_id: Uuid) -> Condition {
    Condition::all().add(Column::DeletedAt.is_null()).add(
        Condition::any()
            .add(Column::TenantId.eq(tenant_id))
            .add(Column::TenantId.is_null()),
    )
}

/// Exact tenant ownership predicate (`None` → global rows only).
fn owned_by(tenant_id: Option<Uuid>) -> Condition {
    match tenant_id {
        Some(t) => Condition::all().add(Column::TenantId.eq(t)),
        None => Condition::all().add(Column::TenantId.is_null()),
    }
}

#[async_trait]
impl crate::domain::repos::McpServerRepository for McpServerRepository {
    async fn create<C: DBRunner>(
        &self,
        runner: &C,
        params: CreateMcpServerParams,
    ) -> Result<McpServerModel, DomainError> {
        let now = OffsetDateTime::now_utc();
        let am = ActiveModel {
            id: Set(params.id),
            tenant_id: Set(params.tenant_id),
            source: Set(params.source),
            external_id: Set(params.external_id),
            name: Set(params.name),
            description: Set(params.description),
            url: Set(params.url),
            enabled: Set(params.enabled),
            trust_level: Set(params.trust_level),
            auth_kind: Set(params.auth_kind),
            auth_config: Set(params.auth_config),
            oagw_upstream_id: Set(params.oagw_upstream_id),
            priority: Set(params.priority),
            allowed_tools: Set(tools_to_json(params.allowed_tools)),
            denied_tools: Set(tools_to_json(params.denied_tools)),
            call_timeout_secs: Set(params.call_timeout_secs),
            auto_attach: Set(params.auto_attach),
            health_status: Set(McpHealthStatus::Unknown),
            last_refreshed_at: Set(None),
            last_error: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
        };

        McpServerEntity::insert(am.clone())
            .secure()
            .scope_with_model(&AccessScope::allow_all(), &am)?
            .exec(runner)
            .await?;

        self.get_any(runner, params.id)
            .await?
            .ok_or_else(|| DomainError::database("mcp_server row missing after insert".to_owned()))
    }

    async fn get<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<McpServerModel>, DomainError> {
        Ok(McpServerEntity::find()
            .filter(visible_to_tenant(tenant_id).add(Column::Id.eq(id)))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .one(runner)
            .await?)
    }

    async fn find_by_external<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Option<Uuid>,
        source: McpSource,
        external_id: &str,
    ) -> Result<Option<McpServerModel>, DomainError> {
        Ok(McpServerEntity::find()
            .filter(
                owned_by(tenant_id)
                    .add(Column::DeletedAt.is_null())
                    .add(Column::Source.eq(source))
                    .add(Column::ExternalId.eq(external_id)),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .one(runner)
            .await?)
    }

    async fn list_effective<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Uuid,
    ) -> Result<Vec<McpServerModel>, DomainError> {
        Ok(McpServerEntity::find()
            .filter(visible_to_tenant(tenant_id).add(Column::Enabled.eq(true)))
            .order_by_asc(Column::Priority)
            .order_by_asc(Column::Name)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .all(runner)
            .await?)
    }

    async fn list_all<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Uuid,
    ) -> Result<Vec<McpServerModel>, DomainError> {
        Ok(McpServerEntity::find()
            .filter(visible_to_tenant(tenant_id))
            .order_by_asc(Column::Priority)
            .order_by_asc(Column::Name)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .all(runner)
            .await?)
    }

    async fn list_by_source<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Option<Uuid>,
        source: McpSource,
    ) -> Result<Vec<McpServerModel>, DomainError> {
        Ok(McpServerEntity::find()
            .filter(
                owned_by(tenant_id)
                    .add(Column::DeletedAt.is_null())
                    .add(Column::Source.eq(source)),
            )
            .order_by_asc(Column::Name)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .all(runner)
            .await?)
    }

    async fn update<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Option<Uuid>,
        id: Uuid,
        params: UpdateMcpServerParams,
    ) -> Result<McpServerModel, DomainError> {
        let existing = McpServerEntity::find()
            .filter(owned_by(tenant_id).add(Column::DeletedAt.is_null()).add(Column::Id.eq(id)))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .one(runner)
            .await?
            .ok_or_else(|| DomainError::not_found("mcp_server", id))?;

        let now = OffsetDateTime::now_utc();
        // Field order mirrors the entity `Model` definition (clippy
        // `inconsistent_struct_constructor`). Identity/system columns are
        // preserved; mutable columns apply the requested overrides.
        let am = ActiveModel {
            id: Set(existing.id),
            tenant_id: Set(existing.tenant_id),
            source: Set(existing.source),
            external_id: Set(existing.external_id),
            name: Set(params.name.unwrap_or(existing.name)),
            description: Set(params.description.unwrap_or(existing.description)),
            url: Set(params.url.unwrap_or(existing.url)),
            enabled: Set(params.enabled.unwrap_or(existing.enabled)),
            trust_level: Set(params.trust_level.unwrap_or(existing.trust_level)),
            auth_kind: Set(params.auth_kind.unwrap_or(existing.auth_kind)),
            auth_config: Set(params.auth_config.unwrap_or(existing.auth_config)),
            oagw_upstream_id: Set(apply_patch(params.oagw_upstream_id, existing.oagw_upstream_id)),
            priority: Set(params.priority.unwrap_or(existing.priority)),
            allowed_tools: Set(apply_tools_patch(params.allowed_tools, existing.allowed_tools)),
            denied_tools: Set(apply_tools_patch(params.denied_tools, existing.denied_tools)),
            call_timeout_secs: Set(apply_patch(
                params.call_timeout_secs,
                existing.call_timeout_secs,
            )),
            auto_attach: Set(params.auto_attach.unwrap_or(existing.auto_attach)),
            health_status: Set(existing.health_status),
            last_refreshed_at: Set(existing.last_refreshed_at),
            last_error: Set(existing.last_error),
            created_at: Set(existing.created_at),
            updated_at: Set(now),
            deleted_at: Set(existing.deleted_at),
        };

        let on_conflict = SecureOnConflict::<McpServerEntity>::columns([Column::Id])
            .update_columns([
                Column::Name,
                Column::Description,
                Column::Url,
                Column::Enabled,
                Column::TrustLevel,
                Column::AuthKind,
                Column::AuthConfig,
                Column::OagwUpstreamId,
                Column::Priority,
                Column::AllowedTools,
                Column::DeniedTools,
                Column::CallTimeoutSecs,
                Column::AutoAttach,
                Column::UpdatedAt,
            ])?;

        McpServerEntity::insert(am.clone())
            .secure()
            .scope_with_model(&AccessScope::allow_all(), &am)?
            .on_conflict(on_conflict)
            .exec(runner)
            .await?;

        self.get_any(runner, id)
            .await?
            .ok_or_else(|| DomainError::database("mcp_server row missing after update".to_owned()))
    }

    async fn set_health<C: DBRunner>(
        &self,
        runner: &C,
        id: Uuid,
        status: McpHealthStatus,
        last_error: Option<String>,
    ) -> Result<(), DomainError> {
        let now = OffsetDateTime::now_utc();
        let err_expr = match last_error {
            Some(s) => Expr::value(s),
            None => Expr::value(Value::String(None)),
        };
        McpServerEntity::update_many()
            .col_expr(Column::HealthStatus, Expr::value(status.to_value()))
            .col_expr(Column::LastError, err_expr)
            .col_expr(Column::UpdatedAt, Expr::value(now))
            .filter(Column::Id.eq(id))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(runner)
            .await?;
        Ok(())
    }

    async fn set_last_refreshed<C: DBRunner>(
        &self,
        runner: &C,
        id: Uuid,
        at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let now = OffsetDateTime::now_utc();
        McpServerEntity::update_many()
            .col_expr(Column::LastRefreshedAt, Expr::value(at))
            .col_expr(Column::UpdatedAt, Expr::value(now))
            .filter(Column::Id.eq(id))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(runner)
            .await?;
        Ok(())
    }

    async fn set_oagw_upstream_id<C: DBRunner>(
        &self,
        runner: &C,
        id: Uuid,
        upstream_id: Option<String>,
    ) -> Result<(), DomainError> {
        let now = OffsetDateTime::now_utc();
        let expr = match upstream_id {
            Some(s) => Expr::value(s),
            None => Expr::value(Value::String(None)),
        };
        McpServerEntity::update_many()
            .col_expr(Column::OagwUpstreamId, expr)
            .col_expr(Column::UpdatedAt, Expr::value(now))
            .filter(Column::Id.eq(id))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(runner)
            .await?;
        Ok(())
    }

    async fn soft_delete<C: DBRunner>(
        &self,
        runner: &C,
        tenant_id: Option<Uuid>,
        id: Uuid,
    ) -> Result<bool, DomainError> {
        let now = OffsetDateTime::now_utc();
        let result = McpServerEntity::update_many()
            .col_expr(Column::DeletedAt, Expr::value(now))
            .col_expr(Column::UpdatedAt, Expr::value(now))
            .filter(
                owned_by(tenant_id)
                    .add(Column::Id.eq(id))
                    .add(Column::DeletedAt.is_null()),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(runner)
            .await?;
        Ok(result.rows_affected > 0)
    }
}

impl McpServerRepository {
    /// Fetch by primary key regardless of tenant (used to read back a row we
    /// just wrote by id).
    async fn get_any<C: DBRunner>(
        &self,
        runner: &C,
        id: Uuid,
    ) -> Result<Option<McpServerModel>, DomainError> {
        Ok(McpServerEntity::find()
            .filter(Column::Id.eq(id))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .one(runner)
            .await?)
    }
}

#[cfg(test)]
#[path = "mcp_server_repo_test.rs"]
mod tests;
