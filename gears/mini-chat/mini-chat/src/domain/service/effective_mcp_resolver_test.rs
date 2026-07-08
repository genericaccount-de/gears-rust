use std::sync::Arc;

use uuid::Uuid;

use crate::config::McpConfig;
use crate::domain::llm::LlmTool;
use crate::domain::repos::{
    CreateMcpServerParams, McpServerRepository as _, McpServerToolRepository as _,
    UpsertMcpToolParams,
};
use crate::domain::service::test_helpers::{inmem_db, mock_db_provider, test_security_ctx};
use crate::infra::db::entity::mcp_server::{
    McpAuthKind, McpHealthStatus, McpSource, McpTrustLevel,
};
use crate::infra::db::repo::mcp_server_repo::McpServerRepository as OrmServerRepo;
use crate::infra::db::repo::mcp_server_tool_repo::McpServerToolRepository as OrmToolRepo;

use oagw_sdk::ServiceGatewayClientV1;

use super::{EffectiveMcpResolver, McpResolutionDiagnostic, McpToolResolver as _};

type Db = Arc<crate::domain::service::DbProvider>;
type Resolver = EffectiveMcpResolver<OrmServerRepo, OrmToolRepo>;

async fn test_db() -> Db {
    mock_db_provider(inmem_db().await)
}

fn enabled_cfg() -> McpConfig {
    McpConfig {
        enabled: true,
        ..McpConfig::default()
    }
}

fn resolver(db: &Db, cfg: &McpConfig) -> Resolver {
    resolver_with_gateway(
        db,
        cfg,
        Arc::new(crate::infra::mcp::test_support::NoopGateway),
    )
}

fn resolver_with_gateway(
    db: &Db,
    cfg: &McpConfig,
    gateway: Arc<dyn ServiceGatewayClientV1>,
) -> Resolver {
    EffectiveMcpResolver::new(
        Arc::clone(db),
        Arc::new(OrmServerRepo),
        Arc::new(OrmToolRepo),
        gateway,
        cfg,
    )
}

#[allow(clippy::too_many_arguments)]
async fn seed_server(
    db: &Db,
    external_id: &str,
    auto_attach: bool,
    priority: i32,
    allowed_tools: Option<Vec<String>>,
    denied_tools: Option<Vec<String>>,
) -> Uuid {
    let conn = db.conn().expect("conn");
    let id = Uuid::now_v7();
    OrmServerRepo
        .create(
            &conn,
            CreateMcpServerParams {
                id,
                tenant_id: None, // global server
                source: McpSource::Config,
                external_id: external_id.to_owned(),
                name: format!("Server {external_id}"),
                description: "test".to_owned(),
                url: "https://mcp.example.com/mcp".to_owned(),
                enabled: true,
                trust_level: McpTrustLevel::Trusted,
                auth_kind: McpAuthKind::None,
                auth_config: serde_json::json!({}),
                oagw_upstream_id: None,
                priority,
                allowed_tools,
                denied_tools,
                call_timeout_secs: None,
                auto_attach,
            },
        )
        .await
        .expect("create server");
    id
}

/// Seed an interactive-OAuth (`oauth2_auth_code`) server with a provisioned
/// OAGW upstream id, so the resolver treats its tools as per-user gated.
async fn seed_oauth_server(db: &Db, external_id: &str, upstream_id: Uuid) -> Uuid {
    let conn = db.conn().expect("conn");
    let id = Uuid::now_v7();
    OrmServerRepo
        .create(
            &conn,
            CreateMcpServerParams {
                id,
                tenant_id: None,
                source: McpSource::Config,
                external_id: external_id.to_owned(),
                name: format!("Server {external_id}"),
                description: "test".to_owned(),
                url: "https://mcp.example.com/mcp".to_owned(),
                enabled: true,
                trust_level: McpTrustLevel::Trusted,
                auth_kind: McpAuthKind::OAuth2AuthCode,
                auth_config: serde_json::json!({ "type": "oauth2_authorization_code" }),
                oagw_upstream_id: Some(upstream_id.to_string()),
                priority: 100,
                allowed_tools: None,
                denied_tools: None,
                call_timeout_secs: None,
                auto_attach: true,
            },
        )
        .await
        .expect("create oauth server");
    id
}

async fn seed_tools(db: &Db, server_id: Uuid, tools: Vec<(&str, &str, serde_json::Value, bool)>) {
    let conn = db.conn().expect("conn");
    let params: Vec<UpsertMcpToolParams> = tools
        .into_iter()
        .map(|(original, exposed, schema, enabled)| UpsertMcpToolParams {
            id: Uuid::now_v7(),
            server_id,
            original_name: original.to_owned(),
            exposed_name: exposed.to_owned(),
            description: "a tool".to_owned(),
            input_schema: schema,
            schema_hash: "hash".to_owned(),
            enabled,
        })
        .collect();
    OrmToolRepo
        .replace_for_server(&conn, server_id, params)
        .await
        .expect("seed tools");
}

fn obj_schema() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": {} })
}

fn tool_names(tools: &[LlmTool]) -> Vec<String> {
    tools
        .iter()
        .filter_map(|t| match t {
            LlmTool::Function { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn disabled_returns_empty_without_db() {
    let db = test_db().await;
    let cfg = McpConfig::default(); // enabled = false
    let r = resolver(&db, &cfg);
    let ctx = test_security_ctx(Uuid::now_v7());
    let res = r.resolve(&ctx).await.expect("resolve");
    assert!(res.is_empty());
    assert!(res.routing_map.is_empty());
}

#[tokio::test]
async fn unhealthy_server_is_hidden_with_diagnostic() {
    let db = test_db().await;
    let healthy = seed_server(&db, "srv-ok", true, 100, None, None).await;
    let down = seed_server(&db, "srv-down", true, 200, None, None).await;
    seed_tools(
        &db,
        healthy,
        vec![("search", "mcp__aaaa0001__search", obj_schema(), true)],
    )
    .await;
    seed_tools(
        &db,
        down,
        vec![("dead", "mcp__bbbb0002__dead", obj_schema(), true)],
    )
    .await;

    // Mark the second server hard-down (as the refresh worker would).
    {
        let conn = db.conn().expect("conn");
        OrmServerRepo
            .set_health(&conn, down, McpHealthStatus::Unhealthy, Some("boom".to_owned()))
            .await
            .expect("set_health");
    }

    let cfg = enabled_cfg();
    let r = resolver(&db, &cfg);
    let ctx = test_security_ctx(Uuid::now_v7());
    let res = r.resolve(&ctx).await.expect("resolve");

    let names = tool_names(&res.tools);
    assert_eq!(names, vec!["mcp__aaaa0001__search".to_owned()]);
    assert!(res.routing_map.get("mcp__bbbb0002__dead").is_none());
    assert!(res.diagnostics.iter().any(|d| matches!(
        d,
        McpResolutionDiagnostic::ServerUnhealthy { server_id } if *server_id == down
    )));
}

#[tokio::test]
async fn unknown_health_server_remains_eligible() {
    let db = test_db().await;
    // seed_server leaves health_status at its default (`unknown`).
    let sid = seed_server(&db, "srv-unknown", true, 100, None, None).await;
    seed_tools(
        &db,
        sid,
        vec![("search", "mcp__aaaa0001__search", obj_schema(), true)],
    )
    .await;

    let cfg = enabled_cfg();
    let r = resolver(&db, &cfg);
    let ctx = test_security_ctx(Uuid::now_v7());
    let res = r.resolve(&ctx).await.expect("resolve");

    assert_eq!(tool_names(&res.tools).len(), 1);
    assert!(res.diagnostics.is_empty());
}

#[tokio::test]
async fn auto_attach_tools_are_resolved_with_routes() {
    let db = test_db().await;
    let sid = seed_server(&db, "srv-a", true, 100, None, None).await;
    seed_tools(
        &db,
        sid,
        vec![
            ("search", "mcp__aaaa0001__search", obj_schema(), true),
            ("fetch", "mcp__aaaa0001__fetch", obj_schema(), true),
        ],
    )
    .await;

    let cfg = enabled_cfg();
    let r = resolver(&db, &cfg);
    let ctx = test_security_ctx(Uuid::now_v7());
    let res = r.resolve(&ctx).await.expect("resolve");

    let names = tool_names(&res.tools);
    assert_eq!(names.len(), 2);
    // Deterministic order: sorted by exposed name (fetch < search).
    assert_eq!(names[0], "mcp__aaaa0001__fetch");
    assert_eq!(names[1], "mcp__aaaa0001__search");

    let route = res
        .routing_map
        .get("mcp__aaaa0001__search")
        .expect("route present");
    assert_eq!(route.original_name, "search");
    assert_eq!(route.server_id, sid);
    assert_eq!(route.server_external_id, "srv-a");
    assert!(res.diagnostics.is_empty());
}

#[tokio::test]
async fn resolve_falls_back_to_original_name() {
    let db = test_db().await;
    let sid = seed_server(&db, "srv-a", true, 100, None, None).await;
    seed_tools(
        &db,
        sid,
        vec![("search", "mcp__aaaa0001__search", obj_schema(), true)],
    )
    .await;

    let cfg = enabled_cfg();
    let r = resolver(&db, &cfg);
    let ctx = test_security_ctx(Uuid::now_v7());
    let res = r.resolve(&ctx).await.expect("resolve");

    // Exposed name resolves.
    assert!(res.routing_map.resolve("mcp__aaaa0001__search").is_some());
    // Some models emit the unprefixed original name; it must still resolve.
    let by_original = res
        .routing_map
        .resolve("search")
        .expect("original name resolves via fallback");
    assert_eq!(by_original.original_name, "search");
    // A genuinely unknown name does not resolve.
    assert!(res.routing_map.resolve("nonexistent_tool").is_none());
}

#[tokio::test]
async fn non_auto_attach_server_is_excluded() {
    let db = test_db().await;
    let sid = seed_server(&db, "srv-b", false, 100, None, None).await;
    seed_tools(
        &db,
        sid,
        vec![("t", "mcp__bbbb0001__t", obj_schema(), true)],
    )
    .await;

    let cfg = enabled_cfg();
    let res = resolver(&db, &cfg)
        .resolve(&test_security_ctx(Uuid::now_v7()))
        .await
        .expect("resolve");
    assert!(res.is_empty());
}

#[tokio::test]
async fn disabled_tool_is_excluded() {
    let db = test_db().await;
    let sid = seed_server(&db, "srv-c", true, 100, None, None).await;
    seed_tools(
        &db,
        sid,
        vec![
            ("on", "mcp__cccc0001__on", obj_schema(), true),
            ("off", "mcp__cccc0001__off", obj_schema(), false),
        ],
    )
    .await;

    let cfg = enabled_cfg();
    let res = resolver(&db, &cfg)
        .resolve(&test_security_ctx(Uuid::now_v7()))
        .await
        .expect("resolve");
    assert_eq!(tool_names(&res.tools), vec!["mcp__cccc0001__on"]);
}

#[tokio::test]
async fn allow_list_restricts_and_deny_list_excludes() {
    let db = test_db().await;
    // allow only "keep"
    let a = seed_server(&db, "srv-allow", true, 100, Some(vec!["keep".to_owned()]), None).await;
    seed_tools(
        &db,
        a,
        vec![
            ("keep", "mcp__allow001__keep", obj_schema(), true),
            ("drop", "mcp__allow001__drop", obj_schema(), true),
        ],
    )
    .await;
    // deny "bad"
    let d = seed_server(&db, "srv-deny", true, 200, None, Some(vec!["bad".to_owned()])).await;
    seed_tools(
        &db,
        d,
        vec![
            ("good", "mcp__deny0001__good", obj_schema(), true),
            ("bad", "mcp__deny0001__bad", obj_schema(), true),
        ],
    )
    .await;

    let cfg = enabled_cfg();
    let res = resolver(&db, &cfg)
        .resolve(&test_security_ctx(Uuid::now_v7()))
        .await
        .expect("resolve");
    let names = tool_names(&res.tools);
    assert!(names.contains(&"mcp__allow001__keep".to_owned()));
    assert!(!names.contains(&"mcp__allow001__drop".to_owned()));
    assert!(names.contains(&"mcp__deny0001__good".to_owned()));
    assert!(!names.contains(&"mcp__deny0001__bad".to_owned()));
    assert!(res.diagnostics.iter().any(|d| matches!(
        d,
        McpResolutionDiagnostic::ToolDenied { tool, .. } if tool == "bad"
    )));
}

#[tokio::test]
async fn oversized_schema_is_excluded_with_diagnostic() {
    let db = test_db().await;
    let sid = seed_server(&db, "srv-big", true, 100, None, None).await;
    let big_desc = "y".repeat(64);
    let big = serde_json::json!({
        "type": "object",
        "properties": { "x": { "type": "string", "description": big_desc } }
    });
    seed_tools(
        &db,
        sid,
        vec![("big", "mcp__big00001__big", big, true)],
    )
    .await;

    let cfg = McpConfig {
        max_tool_schema_bytes: 10,
        ..enabled_cfg()
    };
    let res = resolver(&db, &cfg)
        .resolve(&test_security_ctx(Uuid::now_v7()))
        .await
        .expect("resolve");
    assert!(res.is_empty());
    assert!(res.diagnostics.iter().any(|d| matches!(
        d,
        McpResolutionDiagnostic::SchemaTooLarge { tool, .. } if tool == "big"
    )));
}

#[tokio::test]
async fn tool_cap_truncates_with_diagnostic() {
    let db = test_db().await;
    let sid = seed_server(&db, "srv-cap", true, 100, None, None).await;
    seed_tools(
        &db,
        sid,
        vec![
            ("a", "mcp__cap00001__a", obj_schema(), true),
            ("b", "mcp__cap00001__b", obj_schema(), true),
            ("c", "mcp__cap00001__c", obj_schema(), true),
        ],
    )
    .await;

    let cfg = McpConfig {
        max_tools_per_chat: 2,
        ..enabled_cfg()
    };
    let res = resolver(&db, &cfg)
        .resolve(&test_security_ctx(Uuid::now_v7()))
        .await
        .expect("resolve");
    assert_eq!(res.tools.len(), 2);
    assert_eq!(res.routing_map.len(), 2);
    assert!(res.diagnostics.iter().any(|d| matches!(
        d,
        McpResolutionDiagnostic::ToolCapExceeded { total: 3, cap: 2 }
    )));
}

#[tokio::test]
async fn oauth_server_tools_hidden_when_not_connected() {
    let db = test_db().await;
    let upstream = Uuid::now_v7();
    let sid = seed_oauth_server(&db, "srv-oauth", upstream).await;
    seed_tools(
        &db,
        sid,
        vec![("read", "mcp__oauth001__read", obj_schema(), true)],
    )
    .await;

    let cfg = enabled_cfg();
    let r = resolver_with_gateway(
        &db,
        &cfg,
        Arc::new(crate::infra::mcp::test_support::ConnGateway { connected: false }),
    );
    let res = r
        .resolve(&test_security_ctx(Uuid::now_v7()))
        .await
        .expect("resolve");

    assert!(res.tools.is_empty());
    assert!(res.routing_map.get("mcp__oauth001__read").is_none());
    assert!(res.diagnostics.iter().any(|d| matches!(
        d,
        McpResolutionDiagnostic::ServerNotConnected { server_id } if *server_id == sid
    )));
}

#[tokio::test]
async fn oauth_server_tools_present_when_connected() {
    let db = test_db().await;
    let upstream = Uuid::now_v7();
    let sid = seed_oauth_server(&db, "srv-oauth", upstream).await;
    seed_tools(
        &db,
        sid,
        vec![("read", "mcp__oauth001__read", obj_schema(), true)],
    )
    .await;

    let cfg = enabled_cfg();
    let r = resolver_with_gateway(
        &db,
        &cfg,
        Arc::new(crate::infra::mcp::test_support::ConnGateway { connected: true }),
    );
    let res = r
        .resolve(&test_security_ctx(Uuid::now_v7()))
        .await
        .expect("resolve");

    assert_eq!(tool_names(&res.tools), vec!["mcp__oauth001__read".to_owned()]);
    assert!(res.routing_map.get("mcp__oauth001__read").is_some());
    assert!(!res.diagnostics.iter().any(|d| matches!(
        d,
        McpResolutionDiagnostic::ServerNotConnected { .. }
    )));
}
