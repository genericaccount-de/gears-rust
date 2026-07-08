use std::sync::Arc;

use toolkit_db::DBProvider;
use toolkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::repos::{
    AttachRoleMcpServerParams, CreateMcpServerParams, McpServerRepository as _,
    RoleMcpServerRepository as _,
};
use crate::domain::service::test_helpers::{inmem_db, mock_db_provider};
use crate::infra::db::entity::mcp_server::{McpAuthKind, McpSource, McpTrustLevel};
use crate::infra::db::repo::mcp_server_repo::McpServerRepository;
use crate::infra::db::repo::role_mcp_server_repo::RoleMcpServerRepository;

type Db = Arc<DBProvider<toolkit_db::DbError>>;

async fn test_db() -> Db {
    mock_db_provider(inmem_db().await)
}

async fn seed_server(db: &Db, tenant: Uuid) -> Uuid {
    let conn = db.conn().unwrap();
    McpServerRepository
        .create(
            &conn,
            CreateMcpServerParams {
                id: Uuid::now_v7(),
                tenant_id: Some(tenant),
                source: McpSource::Config,
                external_id: "srv".to_owned(),
                name: "srv".to_owned(),
                description: String::new(),
                url: "https://x/mcp".to_owned(),
                enabled: true,
                trust_level: McpTrustLevel::Untrusted,
                auth_kind: McpAuthKind::None,
                auth_config: serde_json::json!({}),
                oagw_upstream_id: None,
                priority: 100,
                allowed_tools: None,
                denied_tools: None,
                call_timeout_secs: None,
                auto_attach: false,
            },
        )
        .await
        .expect("seed server")
        .id
}

fn attach_params(tenant: Uuid, role: &str, server_id: Uuid) -> AttachRoleMcpServerParams {
    AttachRoleMcpServerParams {
        id: Uuid::now_v7(),
        tenant_id: tenant,
        role: role.to_owned(),
        server_id,
        enabled: true,
        allowed_tools: None,
        denied_tools: None,
        priority: None,
    }
}

#[tokio::test]
async fn attach_is_idempotent_upsert() {
    let db = test_db().await;
    let tenant = Uuid::new_v4();
    let server_id = seed_server(&db, tenant).await;
    let conn = db.conn().unwrap();
    let repo = RoleMcpServerRepository;
    let scope = AccessScope::for_tenant(tenant);

    let first = repo.attach(&conn, &scope, attach_params(tenant, "admin", server_id)).await.expect("attach");
    let mut p = attach_params(tenant, "admin", server_id);
    p.priority = Some(5);
    let second = repo.attach(&conn, &scope, p).await.expect("re-attach");

    assert_eq!(first.id, second.id, "same natural key -> same row");
    assert_eq!(second.priority, Some(5));
}

#[tokio::test]
async fn list_by_roles_filters_enabled_and_scope() {
    let db = test_db().await;
    let tenant = Uuid::new_v4();
    let server_id = seed_server(&db, tenant).await;
    let conn = db.conn().unwrap();
    let repo = RoleMcpServerRepository;
    let scope = AccessScope::for_tenant(tenant);

    repo.attach(&conn, &scope, attach_params(tenant, "admin", server_id)).await.expect("a1");
    let mut disabled = attach_params(tenant, "guest", server_id);
    disabled.enabled = false;
    repo.attach(&conn, &scope, disabled).await.expect("a2");

    let rows = repo
        .list_by_roles(&conn, &scope, &["admin".to_owned(), "guest".to_owned()])
        .await
        .expect("list");
    assert_eq!(rows.len(), 1, "only enabled attachments are returned");
    assert_eq!(rows[0].role, "admin");

    assert!(repo.list_by_roles(&conn, &scope, &[]).await.expect("empty").is_empty());
}

#[tokio::test]
async fn list_by_roles_tenant_isolation() {
    let db = test_db().await;
    let tenant_a = Uuid::new_v4();
    let server_id = seed_server(&db, tenant_a).await;
    let conn = db.conn().unwrap();
    let repo = RoleMcpServerRepository;

    let scope_a = AccessScope::for_tenant(tenant_a);
    repo.attach(&conn, &scope_a, attach_params(tenant_a, "admin", server_id)).await.expect("attach");

    let tenant_b = Uuid::new_v4();
    let scope_b = AccessScope::for_tenant(tenant_b);
    let rows = repo.list_by_roles(&conn, &scope_b, &["admin".to_owned()]).await.expect("list");
    assert!(rows.is_empty(), "tenant B must not see tenant A's attachments");
}

#[tokio::test]
async fn count_all_spans_every_tenant() {
    let db = test_db().await;
    let conn = db.conn().unwrap();
    let repo = RoleMcpServerRepository;

    let tenant_a = Uuid::new_v4();
    let server_a = seed_server(&db, tenant_a).await;
    let scope_a = AccessScope::for_tenant(tenant_a);
    repo.attach(&conn, &scope_a, attach_params(tenant_a, "admin", server_a)).await.expect("a1");
    repo.attach(&conn, &scope_a, attach_params(tenant_a, "guest", server_a)).await.expect("a2");

    let tenant_b = Uuid::new_v4();
    let server_b = seed_server(&db, tenant_b).await;
    let scope_b = AccessScope::for_tenant(tenant_b);
    repo.attach(&conn, &scope_b, attach_params(tenant_b, "admin", server_b)).await.expect("b1");

    // Unscoped system count must include rows from both tenants.
    assert_eq!(repo.count_all(&conn).await.expect("count"), 3);
}

#[tokio::test]
async fn detach_removes_row() {
    let db = test_db().await;
    let tenant = Uuid::new_v4();
    let server_id = seed_server(&db, tenant).await;
    let conn = db.conn().unwrap();
    let repo = RoleMcpServerRepository;
    let scope = AccessScope::for_tenant(tenant);

    let row = repo.attach(&conn, &scope, attach_params(tenant, "admin", server_id)).await.expect("attach");
    assert!(repo.detach(&conn, &scope, row.id).await.expect("detach"));
    assert!(!repo.detach(&conn, &scope, row.id).await.expect("detach2"));
    assert!(repo.list_by_server(&conn, &scope, server_id).await.expect("list").is_empty());
}
