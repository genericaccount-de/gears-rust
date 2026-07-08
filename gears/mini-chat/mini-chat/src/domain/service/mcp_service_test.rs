use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use async_trait::async_trait;
use oagw_sdk::{Body, Server, ServiceGatewayClientV1};
use toolkit_canonical_errors::CanonicalError;
use uuid::Uuid;

use crate::config::McpServerConfig;
use crate::domain::repos::{CreateMcpServerParams, McpServerRepository as _};
use crate::domain::service::test_helpers::{
    inmem_db, mock_db_provider, mock_tenant_only_enforcer, test_security_ctx,
};
use crate::infra::db::entity::mcp_server::{McpAuthKind, McpSource, McpTrustLevel};
use crate::infra::db::repo::mcp_server_repo::McpServerRepository as OrmServerRepo;
use crate::infra::db::repo::mcp_server_tool_repo::McpServerToolRepository as OrmToolRepo;
use crate::infra::db::repo::role_mcp_server_repo::RoleMcpServerRepository as OrmRoleRepo;
use crate::infra::mcp::{BreakerConfig, McpAuth, McpPool};

use super::{AssignServerToRoleInput, McpService};

type Db = Arc<crate::domain::service::DbProvider>;
type Svc = McpService<OrmServerRepo, OrmToolRepo, OrmRoleRepo>;

// ── Recording OAGW gateway ──────────────────────────────────────────────────

/// Gateway that records upstream lifecycle calls and stores created upstreams.
///
/// Mirrors OAGW closely enough to exercise the idempotent find-by-alias sync
/// path: `create_upstream` retains the upstream and `list_upstreams` returns
/// it, so a second sync locates it by alias and takes the update path.
#[derive(Default)]
struct RecordingGateway {
    ops: StdMutex<Vec<String>>,
    upstreams: StdMutex<Vec<oagw_sdk::Upstream>>,
}

impl RecordingGateway {
    fn ops(&self) -> Vec<String> {
        self.ops.lock().unwrap().clone()
    }

    /// Simulate an OAGW restart by dropping the in-memory upstream store,
    /// leaving mini-chat's persisted `oagw_upstream_id` dangling.
    fn clear_upstreams(&self) {
        self.upstreams.lock().unwrap().clear();
    }
}

fn canned_upstream() -> oagw_sdk::Upstream {
    oagw_sdk::Upstream {
        id: Uuid::now_v7(),
        tenant_id: Uuid::nil(),
        // Matches the OAGW-derived alias for `cfg_server`'s hostname endpoint
        // (`https://mcp.example.com/mcp` → `mcp.example.com`), so the sync's
        // find-by-alias lookup resolves it on subsequent runs.
        alias: "mcp.example.com".to_owned(),
        server: Server { endpoints: vec![] },
        protocol: String::new(),
        enabled: true,
        auth: None,
        headers: None,
        plugins: None,
        rate_limit: None,
        cors: None,
        tags: vec![],
    }
}

fn canned_route() -> oagw_sdk::Route {
    oagw_sdk::Route {
        id: Uuid::now_v7(),
        tenant_id: Uuid::nil(),
        upstream_id: Uuid::now_v7(),
        match_rules: oagw_sdk::MatchRules { http: None, grpc: None },
        plugins: None,
        rate_limit: None,
        cors: None,
        tags: vec![],
        priority: 0,
        enabled: true,
    }
}

#[async_trait]
impl ServiceGatewayClientV1 for RecordingGateway {
    async fn create_upstream(
        &self,
        _: toolkit_security::SecurityContext,
        _: oagw_sdk::CreateUpstreamRequest,
    ) -> Result<oagw_sdk::Upstream, CanonicalError> {
        self.ops.lock().unwrap().push("create_upstream".to_owned());
        let upstream = canned_upstream();
        self.upstreams.lock().unwrap().push(upstream.clone());
        Ok(upstream)
    }
    async fn get_upstream(
        &self,
        _: toolkit_security::SecurityContext,
        _: Uuid,
    ) -> Result<oagw_sdk::Upstream, CanonicalError> {
        unimplemented!()
    }
    async fn list_upstreams(
        &self,
        _: toolkit_security::SecurityContext,
        query: &oagw_sdk::ListQuery,
    ) -> Result<Vec<oagw_sdk::Upstream>, CanonicalError> {
        self.ops.lock().unwrap().push("list_upstreams".to_owned());
        let all = self.upstreams.lock().unwrap().clone();
        let skip = usize::try_from(query.skip).unwrap_or(usize::MAX);
        let top = usize::try_from(query.top).unwrap_or(usize::MAX);
        Ok(all.into_iter().skip(skip).take(top).collect())
    }
    async fn update_upstream(
        &self,
        _: toolkit_security::SecurityContext,
        _: Uuid,
        _: oagw_sdk::UpdateUpstreamRequest,
    ) -> Result<oagw_sdk::Upstream, CanonicalError> {
        self.ops.lock().unwrap().push("update_upstream".to_owned());
        Ok(canned_upstream())
    }
    async fn delete_upstream(
        &self,
        _: toolkit_security::SecurityContext,
        _: Uuid,
    ) -> Result<(), CanonicalError> {
        self.ops.lock().unwrap().push("delete_upstream".to_owned());
        Ok(())
    }
    async fn create_route(
        &self,
        _: toolkit_security::SecurityContext,
        _: oagw_sdk::CreateRouteRequest,
    ) -> Result<oagw_sdk::Route, CanonicalError> {
        self.ops.lock().unwrap().push("create_route".to_owned());
        Ok(canned_route())
    }
    async fn get_route(
        &self,
        _: toolkit_security::SecurityContext,
        _: Uuid,
    ) -> Result<oagw_sdk::Route, CanonicalError> {
        unimplemented!()
    }
    async fn list_routes(
        &self,
        _: toolkit_security::SecurityContext,
        _: Option<Uuid>,
        _: &oagw_sdk::ListQuery,
    ) -> Result<Vec<oagw_sdk::Route>, CanonicalError> {
        unimplemented!()
    }
    async fn update_route(
        &self,
        _: toolkit_security::SecurityContext,
        _: Uuid,
        _: oagw_sdk::UpdateRouteRequest,
    ) -> Result<oagw_sdk::Route, CanonicalError> {
        unimplemented!()
    }
    async fn delete_route(
        &self,
        _: toolkit_security::SecurityContext,
        _: Uuid,
    ) -> Result<(), CanonicalError> {
        unimplemented!()
    }
    async fn resolve_proxy_target(
        &self,
        _: toolkit_security::SecurityContext,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<(oagw_sdk::Upstream, oagw_sdk::Route), CanonicalError> {
        unimplemented!()
    }
    async fn proxy_request(
        &self,
        _: toolkit_security::SecurityContext,
        _: http::Request<Body>,
    ) -> Result<http::Response<Body>, CanonicalError> {
        unimplemented!()
    }
}

// ── Fixtures ────────────────────────────────────────────────────────────────

async fn test_db() -> Db {
    mock_db_provider(inmem_db().await)
}

fn pool(gateway: Arc<dyn ServiceGatewayClientV1>) -> Arc<McpPool> {
    Arc::new(McpPool::new(
        gateway,
        Duration::from_secs(30),
        1024 * 1024,
        BreakerConfig::default(),
    ))
}

fn build_service(
    db: &Db,
    gateway: Arc<dyn ServiceGatewayClientV1>,
    mcp_pool: Arc<McpPool>,
    config_servers: Vec<McpServerConfig>,
) -> Svc {
    McpService::new(
        Arc::clone(db),
        Arc::new(OrmServerRepo),
        Arc::new(OrmToolRepo),
        Arc::new(OrmRoleRepo),
        mock_tenant_only_enforcer(),
        gateway,
        mcp_pool,
        config_servers,
        None,
        None,
        30,
        Arc::new(crate::domain::ports::metrics::NoopMetrics),
    )
}

fn cfg_server(id: &str) -> McpServerConfig {
    McpServerConfig {
        id: id.to_owned(),
        url: "https://mcp.example.com/mcp".to_owned(),
        name: format!("Server {id}"),
        description: "test".to_owned(),
        auto_attach: false,
        priority: 100,
        call_timeout_secs: None,
        allowed_tools: None,
        denied_tools: None,
        auth: McpAuth::None,
    }
}

async fn seed_tenant_server(db: &Db, tenant: Uuid) -> Uuid {
    let conn = db.conn().unwrap();
    let id = Uuid::now_v7();
    OrmServerRepo
        .create(
            &conn,
            CreateMcpServerParams {
                id,
                tenant_id: Some(tenant),
                source: McpSource::Api,
                external_id: format!("ext-{id}"),
                name: "seeded".to_owned(),
                description: String::new(),
                url: "https://mcp.example.com/mcp".to_owned(),
                enabled: true,
                trust_level: McpTrustLevel::Untrusted,
                auth_kind: McpAuthKind::None,
                auth_config: serde_json::json!({"type": "none"}),
                oagw_upstream_id: None,
                priority: 100,
                allowed_tools: None,
                denied_tools: None,
                call_timeout_secs: None,
                auto_attach: false,
            },
        )
        .await
        .expect("seed server");
    id
}

// ── Config sync ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn sync_creates_provisions_and_pools_config_server() {
    let db = test_db().await;
    let gw = Arc::new(RecordingGateway::default());
    let gw_dyn: Arc<dyn ServiceGatewayClientV1> = gw.clone();
    let p = pool(gw_dyn.clone());
    let svc = build_service(&db, gw_dyn, Arc::clone(&p), vec![cfg_server("alpha")]);
    let ctx = test_security_ctx(Uuid::new_v4());

    svc.sync_config_servers(&ctx).await.expect("sync");

    let conn = db.conn().unwrap();
    let rows = OrmServerRepo
        .list_by_source(&conn, None, McpSource::Config)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].enabled);
    assert!(rows[0].oagw_upstream_id.is_some());
    assert_eq!(p.server_count(), 1);
    assert!(gw.ops().contains(&"create_upstream".to_owned()));
    assert!(gw.ops().contains(&"create_route".to_owned()));
}

#[tokio::test]
async fn sync_is_idempotent_and_uses_update_path() {
    let db = test_db().await;
    let gw = Arc::new(RecordingGateway::default());
    let gw_dyn: Arc<dyn ServiceGatewayClientV1> = gw.clone();
    let p = pool(gw_dyn.clone());
    let svc = build_service(&db, gw_dyn, Arc::clone(&p), vec![cfg_server("alpha")]);
    let ctx = test_security_ctx(Uuid::new_v4());

    svc.sync_config_servers(&ctx).await.expect("sync 1");
    svc.sync_config_servers(&ctx).await.expect("sync 2");

    let conn = db.conn().unwrap();
    let rows = OrmServerRepo
        .list_by_source(&conn, None, McpSource::Config)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "no duplicate rows");
    assert_eq!(p.server_count(), 1);
    // Second run took the update path (existing row + upstream id).
    assert!(gw.ops().contains(&"update_upstream".to_owned()));
}

#[tokio::test]
async fn sync_reprovisions_after_oagw_restart() {
    let db = test_db().await;
    let gw = Arc::new(RecordingGateway::default());
    let gw_dyn: Arc<dyn ServiceGatewayClientV1> = gw.clone();
    let p = pool(gw_dyn.clone());
    let svc = build_service(&db, gw_dyn, Arc::clone(&p), vec![cfg_server("alpha")]);
    let ctx = test_security_ctx(Uuid::new_v4());

    // First run provisions the upstream and pools the server.
    svc.sync_config_servers(&ctx).await.expect("sync 1");
    assert_eq!(p.server_count(), 1);

    // Simulate an OAGW restart: its in-memory upstream store is wiped, but the
    // mini-chat DB still holds the now-dangling upstream id.
    gw.clear_upstreams();

    // Second run must self-heal: find-by-alias misses, so `ensure` re-creates
    // the upstream instead of failing on the stale id — otherwise the server
    // would never be pooled and the refresh worker would report "not found".
    svc.sync_config_servers(&ctx).await.expect("sync 2");

    let conn = db.conn().unwrap();
    let rows = OrmServerRepo
        .list_by_source(&conn, None, McpSource::Config)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "no duplicate rows");
    assert!(rows[0].oagw_upstream_id.is_some(), "upstream id re-bound");
    assert_eq!(p.server_count(), 1, "server remains pooled after re-provision");
    let creates = gw.ops().iter().filter(|o| o.as_str() == "create_upstream").count();
    assert_eq!(creates, 2, "upstream re-created after OAGW restart");
}

#[tokio::test]
async fn sync_retires_removed_config_server() {
    let db = test_db().await;
    let gw = Arc::new(RecordingGateway::default());
    let gw_dyn: Arc<dyn ServiceGatewayClientV1> = gw.clone();
    let p = pool(gw_dyn.clone());
    let ctx = test_security_ctx(Uuid::new_v4());

    // First sync registers "alpha".
    let svc = build_service(&db, gw_dyn.clone(), Arc::clone(&p), vec![cfg_server("alpha")]);
    svc.sync_config_servers(&ctx).await.expect("sync 1");
    assert_eq!(p.server_count(), 1);

    // Config now empty → "alpha" must be retired.
    let svc_empty = build_service(&db, gw_dyn, Arc::clone(&p), vec![]);
    svc_empty.sync_config_servers(&ctx).await.expect("sync 2");

    let conn = db.conn().unwrap();
    let rows = OrmServerRepo
        .list_by_source(&conn, None, McpSource::Config)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].enabled, "retired server is disabled");
    assert!(rows[0].oagw_upstream_id.is_none(), "upstream id cleared");
    assert_eq!(p.server_count(), 0, "evicted from pool");
    assert!(gw.ops().contains(&"delete_upstream".to_owned()));
}

// ── Reads ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_and_get_server_visible_to_tenant() {
    let db = test_db().await;
    let gw: Arc<dyn ServiceGatewayClientV1> = Arc::new(RecordingGateway::default());
    let p = pool(gw.clone());
    let svc = build_service(&db, gw, p, vec![]);
    let tenant = Uuid::new_v4();
    let ctx = test_security_ctx(tenant);
    let id = seed_tenant_server(&db, tenant).await;

    let all = svc.list_servers(&ctx).await.expect("list");
    assert_eq!(all.len(), 1);
    let one = svc.get_server(&ctx, id).await.expect("get");
    assert_eq!(one.id, id);
}

#[tokio::test]
async fn get_missing_server_is_not_found() {
    let db = test_db().await;
    let gw: Arc<dyn ServiceGatewayClientV1> = Arc::new(RecordingGateway::default());
    let p = pool(gw.clone());
    let svc = build_service(&db, gw, p, vec![]);
    let ctx = test_security_ctx(Uuid::new_v4());

    let err = svc.get_server(&ctx, Uuid::now_v7()).await.unwrap_err();
    assert!(matches!(err, crate::domain::error::DomainError::NotFound { .. }));
}

// ── Role grants ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn assign_list_and_revoke_role_server() {
    let db = test_db().await;
    let gw: Arc<dyn ServiceGatewayClientV1> = Arc::new(RecordingGateway::default());
    let p = pool(gw.clone());
    let svc = build_service(&db, gw, p, vec![]);
    let tenant = Uuid::new_v4();
    let ctx = test_security_ctx(tenant);
    let server_id = seed_tenant_server(&db, tenant).await;

    let input = AssignServerToRoleInput {
        server_id,
        enabled: true,
        allowed_tools: None,
        denied_tools: None,
        priority: Some(10),
    };
    let attached = svc
        .assign_server_to_role(&ctx, "admin", input)
        .await
        .expect("assign");
    assert_eq!(attached.server_id, server_id);
    assert_eq!(attached.role, "admin");

    let listed = svc.list_role_servers(&ctx, "admin").await.expect("list role");
    assert_eq!(listed.len(), 1);

    let removed = svc
        .revoke_server_from_role(&ctx, "admin", server_id)
        .await
        .expect("revoke");
    assert!(removed);

    let after = svc.list_role_servers(&ctx, "admin").await.expect("list role 2");
    assert!(after.is_empty());
}

#[tokio::test]
async fn assign_to_missing_server_is_not_found() {
    let db = test_db().await;
    let gw: Arc<dyn ServiceGatewayClientV1> = Arc::new(RecordingGateway::default());
    let p = pool(gw.clone());
    let svc = build_service(&db, gw, p, vec![]);
    let ctx = test_security_ctx(Uuid::new_v4());

    let input = AssignServerToRoleInput {
        server_id: Uuid::now_v7(),
        enabled: true,
        allowed_tools: None,
        denied_tools: None,
        priority: None,
    };
    let err = svc
        .assign_server_to_role(&ctx, "admin", input)
        .await
        .unwrap_err();
    assert!(matches!(err, crate::domain::error::DomainError::NotFound { .. }));
}

#[tokio::test]
async fn revoke_absent_attachment_returns_false() {
    let db = test_db().await;
    let gw: Arc<dyn ServiceGatewayClientV1> = Arc::new(RecordingGateway::default());
    let p = pool(gw.clone());
    let svc = build_service(&db, gw, p, vec![]);
    let tenant = Uuid::new_v4();
    let ctx = test_security_ctx(tenant);
    let server_id = seed_tenant_server(&db, tenant).await;

    let removed = svc
        .revoke_server_from_role(&ctx, "admin", server_id)
        .await
        .expect("revoke");
    assert!(!removed);
}

// ── Hub approval ────────────────────────────────────────────────────────────

async fn seed_hub_server(db: &Db, external_id: &str, enabled: bool) -> Uuid {
    let conn = db.conn().unwrap();
    let id = Uuid::now_v7();
    OrmServerRepo
        .create(
            &conn,
            CreateMcpServerParams {
                id,
                tenant_id: None,
                source: McpSource::Hub,
                external_id: external_id.to_owned(),
                name: external_id.to_owned(),
                description: String::new(),
                url: "https://hub-srv.example.com/mcp".to_owned(),
                enabled,
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
        .expect("seed hub server");
    id
}

#[tokio::test]
async fn approve_hub_server_provisions_enables_and_pools() {
    let db = test_db().await;
    let gw = Arc::new(RecordingGateway::default());
    let gw_dyn: Arc<dyn ServiceGatewayClientV1> = gw.clone();
    let p = pool(gw_dyn.clone());
    let svc = build_service(&db, gw_dyn, Arc::clone(&p), vec![]);
    let ctx = test_security_ctx(Uuid::new_v4());
    let id = seed_hub_server(&db, "hub-alpha", false).await;

    let approved = svc.approve_server(&ctx, id).await.expect("approve");
    assert!(approved.enabled);
    assert!(approved.oagw_upstream_id.is_some());
    assert_eq!(p.server_count(), 1, "registered in pool");

    let ops = gw.ops();
    assert!(ops.contains(&"list_upstreams".to_owned()), "ensure scans upstreams");
    assert!(ops.contains(&"create_upstream".to_owned()));
    assert!(ops.contains(&"create_route".to_owned()));
}

#[tokio::test]
async fn approve_non_hub_server_is_rejected() {
    let db = test_db().await;
    let gw: Arc<dyn ServiceGatewayClientV1> = Arc::new(RecordingGateway::default());
    let p = pool(gw.clone());
    let svc = build_service(&db, gw, p, vec![]);
    let tenant = Uuid::new_v4();
    let ctx = test_security_ctx(tenant);
    // seed_tenant_server registers a `source='api'` server.
    let id = seed_tenant_server(&db, tenant).await;

    let err = svc.approve_server(&ctx, id).await.unwrap_err();
    assert!(matches!(err, crate::domain::error::DomainError::Validation { .. }));
}

#[tokio::test]
async fn sync_hub_without_hub_configured_is_noop() {
    let db = test_db().await;
    let gw: Arc<dyn ServiceGatewayClientV1> = Arc::new(RecordingGateway::default());
    let p = pool(gw.clone());
    let svc = build_service(&db, gw, p, vec![]);
    let ctx = test_security_ctx(Uuid::new_v4());

    let summary = svc.sync_hub_servers(&ctx).await.expect("sync hub");
    assert_eq!(summary.discovered, 0);
    assert_eq!(summary.added, 0);
    assert_eq!(summary.retired, 0);
}

// ── Pure helpers ────────────────────────────────────────────────────────────

#[test]
fn auth_kind_mapping() {
    assert_eq!(super::auth_kind_of(&McpAuth::None), McpAuthKind::None);
    assert_eq!(
        super::auth_kind_of(&McpAuth::Bearer { secret_ref: "cred://t".into() }),
        McpAuthKind::Bearer
    );
    assert_eq!(
        super::auth_kind_of(&McpAuth::ApiKey {
            header: "x".into(),
            secret_ref: "cred://k".into(),
        }),
        McpAuthKind::ApiKey
    );
}

#[test]
fn display_name_falls_back_to_id() {
    let mut c = cfg_server("srv1");
    c.name = String::new();
    assert_eq!(super::display_name(&c), "srv1");
    c.name = "Named".to_owned();
    assert_eq!(super::display_name(&c), "Named");
}
