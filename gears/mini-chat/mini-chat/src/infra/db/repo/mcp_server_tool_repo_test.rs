use std::sync::Arc;

use toolkit_db::DBProvider;
use uuid::Uuid;

use crate::domain::repos::{
    CreateMcpServerParams, McpServerRepository as _, McpServerToolRepository as _,
    UpsertMcpToolParams,
};
use crate::domain::service::test_helpers::{inmem_db, mock_db_provider};
use crate::infra::db::entity::mcp_server::{McpAuthKind, McpSource, McpTrustLevel};
use crate::infra::db::repo::mcp_server_repo::McpServerRepository;
use crate::infra::db::repo::mcp_server_tool_repo::McpServerToolRepository;

type Db = Arc<DBProvider<toolkit_db::DbError>>;

async fn test_db() -> Db {
    mock_db_provider(inmem_db().await)
}

async fn seed_server(db: &Db, tenant: Uuid) -> Uuid {
    let conn = db.conn().unwrap();
    let repo = McpServerRepository;
    repo.create(
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

fn tool(server_id: Uuid, original: &str) -> UpsertMcpToolParams {
    UpsertMcpToolParams {
        id: Uuid::now_v7(),
        server_id,
        original_name: original.to_owned(),
        exposed_name: format!("srv__{original}"),
        description: "d".to_owned(),
        input_schema: serde_json::json!({"type": "object"}),
        schema_hash: "hash".to_owned(),
        enabled: true,
    }
}

#[tokio::test]
async fn replace_inserts_then_prunes() {
    let db = test_db().await;
    let tenant = Uuid::new_v4();
    let server_id = seed_server(&db, tenant).await;
    let conn = db.conn().unwrap();
    let repo = McpServerToolRepository;

    repo.replace_for_server(&conn, server_id, vec![tool(server_id, "a"), tool(server_id, "b")])
        .await
        .expect("replace 1");
    let listed = repo.list_by_server(&conn, server_id).await.expect("list");
    assert_eq!(listed.len(), 2);

    // Second replace drops "b", keeps "a", adds "c".
    repo.replace_for_server(&conn, server_id, vec![tool(server_id, "a"), tool(server_id, "c")])
        .await
        .expect("replace 2");
    let listed = repo.list_by_server(&conn, server_id).await.expect("list");
    let names: Vec<_> = listed.iter().map(|t| t.original_name.clone()).collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"a".to_owned()));
    assert!(names.contains(&"c".to_owned()));
    assert!(!names.contains(&"b".to_owned()));
}

#[tokio::test]
async fn replace_empty_prunes_all() {
    let db = test_db().await;
    let tenant = Uuid::new_v4();
    let server_id = seed_server(&db, tenant).await;
    let conn = db.conn().unwrap();
    let repo = McpServerToolRepository;

    repo.replace_for_server(&conn, server_id, vec![tool(server_id, "a")])
        .await
        .expect("replace");
    repo.replace_for_server(&conn, server_id, vec![]).await.expect("replace empty");
    assert!(repo.list_by_server(&conn, server_id).await.expect("list").is_empty());
}

#[tokio::test]
async fn set_enabled_toggles() {
    let db = test_db().await;
    let tenant = Uuid::new_v4();
    let server_id = seed_server(&db, tenant).await;
    let conn = db.conn().unwrap();
    let repo = McpServerToolRepository;

    repo.replace_for_server(&conn, server_id, vec![tool(server_id, "a")]).await.expect("replace");
    let changed = repo.set_enabled(&conn, server_id, "srv__a", false).await.expect("toggle");
    assert!(changed);
    let listed = repo.list_by_server(&conn, server_id).await.expect("list");
    assert!(!listed[0].enabled);

    let missing = repo.set_enabled(&conn, server_id, "nope", true).await.expect("toggle missing");
    assert!(!missing);
}

#[tokio::test]
async fn delete_by_server_removes_all() {
    let db = test_db().await;
    let tenant = Uuid::new_v4();
    let server_id = seed_server(&db, tenant).await;
    let conn = db.conn().unwrap();
    let repo = McpServerToolRepository;

    repo.replace_for_server(&conn, server_id, vec![tool(server_id, "a"), tool(server_id, "b")])
        .await
        .expect("replace");
    let removed = repo.delete_by_server(&conn, server_id).await.expect("delete");
    assert_eq!(removed, 2);
    assert!(repo.list_by_server(&conn, server_id).await.expect("list").is_empty());
}
