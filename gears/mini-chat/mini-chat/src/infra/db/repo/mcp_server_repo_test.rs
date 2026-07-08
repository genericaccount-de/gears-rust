use std::sync::Arc;

use toolkit_db::DBProvider;
use uuid::Uuid;

use crate::domain::repos::{
    CreateMcpServerParams, McpServerRepository as _, Patch, UpdateMcpServerParams,
};
use crate::domain::service::test_helpers::{inmem_db, mock_db_provider};
use crate::infra::db::entity::mcp_server::{McpAuthKind, McpHealthStatus, McpSource, McpTrustLevel};
use crate::infra::db::repo::mcp_server_repo::McpServerRepository;

type Db = Arc<DBProvider<toolkit_db::DbError>>;

async fn test_db() -> Db {
    mock_db_provider(inmem_db().await)
}

fn params(tenant_id: Option<Uuid>, external_id: &str) -> CreateMcpServerParams {
    CreateMcpServerParams {
        id: Uuid::now_v7(),
        tenant_id,
        source: McpSource::Config,
        external_id: external_id.to_owned(),
        name: format!("server-{external_id}"),
        description: "desc".to_owned(),
        url: "https://mcp.example.com/mcp".to_owned(),
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
    }
}

#[tokio::test]
async fn create_and_get_tenant_server() {
    let db = test_db().await;
    let conn = db.conn().unwrap();
    let repo = McpServerRepository;
    let tenant = Uuid::new_v4();

    let created = repo.create(&conn, params(Some(tenant), "a")).await.expect("create");
    assert_eq!(created.tenant_id, Some(tenant));

    let fetched = repo.get(&conn, tenant, created.id).await.expect("get");
    assert_eq!(fetched.map(|m| m.id), Some(created.id));
}

#[tokio::test]
async fn global_server_visible_to_any_tenant() {
    let db = test_db().await;
    let conn = db.conn().unwrap();
    let repo = McpServerRepository;

    let created = repo.create(&conn, params(None, "global")).await.expect("create global");
    assert_eq!(created.tenant_id, None);

    let some_tenant = Uuid::new_v4();
    let fetched = repo.get(&conn, some_tenant, created.id).await.expect("get");
    assert!(fetched.is_some(), "global server must be visible to any tenant");

    let effective = repo.list_effective(&conn, some_tenant).await.expect("list");
    assert!(effective.iter().any(|m| m.id == created.id));
}

#[tokio::test]
async fn tenant_isolation_on_get() {
    let db = test_db().await;
    let conn = db.conn().unwrap();
    let repo = McpServerRepository;
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    let created = repo.create(&conn, params(Some(tenant_a), "a")).await.expect("create");

    let cross = repo.get(&conn, tenant_b, created.id).await.expect("get");
    assert!(cross.is_none(), "tenant B must not see tenant A's server");
}

#[tokio::test]
async fn find_by_external_natural_key() {
    let db = test_db().await;
    let conn = db.conn().unwrap();
    let repo = McpServerRepository;
    let tenant = Uuid::new_v4();

    repo.create(&conn, params(Some(tenant), "ext-1")).await.expect("create");

    let found = repo
        .find_by_external(&conn, Some(tenant), McpSource::Config, "ext-1")
        .await
        .expect("find");
    assert!(found.is_some());

    let missing = repo
        .find_by_external(&conn, None, McpSource::Config, "ext-1")
        .await
        .expect("find global");
    assert!(missing.is_none(), "tenant row must not match global lookup");
}

#[tokio::test]
async fn update_applies_partial_changes() {
    let db = test_db().await;
    let conn = db.conn().unwrap();
    let repo = McpServerRepository;
    let tenant = Uuid::new_v4();

    let created = repo.create(&conn, params(Some(tenant), "a")).await.expect("create");

    let updated = repo
        .update(
            &conn,
            Some(tenant),
            created.id,
            UpdateMcpServerParams {
                name: Some("renamed".to_owned()),
                enabled: Some(false),
                trust_level: Some(McpTrustLevel::Trusted),
                allowed_tools: Patch::Set(vec!["search".to_owned()]),
                ..Default::default()
            },
        )
        .await
        .expect("update");

    assert_eq!(updated.name, "renamed");
    assert!(!updated.enabled);
    assert_eq!(updated.trust_level, McpTrustLevel::Trusted);
    assert_eq!(updated.allowed_tools, Some(serde_json::json!(["search"])));
    // Unchanged fields preserved.
    assert_eq!(updated.url, created.url);
}

#[tokio::test]
async fn list_effective_excludes_disabled_but_list_all_includes() {
    let db = test_db().await;
    let conn = db.conn().unwrap();
    let repo = McpServerRepository;
    let tenant = Uuid::new_v4();

    let mut p = params(Some(tenant), "disabled");
    p.enabled = false;
    let created = repo.create(&conn, p).await.expect("create");

    let effective = repo.list_effective(&conn, tenant).await.expect("effective");
    assert!(!effective.iter().any(|m| m.id == created.id));

    let all = repo.list_all(&conn, tenant).await.expect("all");
    assert!(all.iter().any(|m| m.id == created.id));
}

#[tokio::test]
async fn soft_delete_hides_row() {
    let db = test_db().await;
    let conn = db.conn().unwrap();
    let repo = McpServerRepository;
    let tenant = Uuid::new_v4();

    let created = repo.create(&conn, params(Some(tenant), "a")).await.expect("create");

    let deleted = repo.soft_delete(&conn, Some(tenant), created.id).await.expect("delete");
    assert!(deleted);
    assert!(repo.get(&conn, tenant, created.id).await.expect("get").is_none());

    let again = repo.soft_delete(&conn, Some(tenant), created.id).await.expect("delete2");
    assert!(!again, "second soft-delete is a no-op");
}

#[tokio::test]
async fn system_setters_update_row() {
    let db = test_db().await;
    let conn = db.conn().unwrap();
    let repo = McpServerRepository;
    let tenant = Uuid::new_v4();

    let created = repo.create(&conn, params(Some(tenant), "a")).await.expect("create");

    repo.set_health(&conn, created.id, McpHealthStatus::Healthy, None).await.expect("health");
    repo.set_oagw_upstream_id(&conn, created.id, Some("up-123".to_owned())).await.expect("upstream");
    let at = time::OffsetDateTime::now_utc();
    repo.set_last_refreshed(&conn, created.id, at).await.expect("refresh");

    let fetched = repo.get(&conn, tenant, created.id).await.expect("get").expect("some");
    assert_eq!(fetched.health_status, McpHealthStatus::Healthy);
    assert_eq!(fetched.oagw_upstream_id.as_deref(), Some("up-123"));
    assert!(fetched.last_refreshed_at.is_some());
}
