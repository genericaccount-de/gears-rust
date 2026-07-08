use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use credstore_sdk::{
    CredStoreClientV1, CredStoreError, GetSecretResponse, SecretRef, SecretValue, SharingMode,
    TenantId as CredstoreTenantId,
};
use httpmock::prelude::*;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use super::*;
use crate::domain::model;

const TOKEN_REF: &str = "mcp_oauth_upstream_token";

fn test_ctx() -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::nil())
        .subject_tenant_id(Uuid::nil())
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Stateful in-memory credstore (interior mutability for begin -> complete)
// ---------------------------------------------------------------------------

struct StatefulCredStore {
    store: Mutex<HashMap<String, Vec<u8>>>,
}

impl StatefulCredStore {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }

    fn with(entries: Vec<(String, Vec<u8>)>) -> Self {
        Self {
            store: Mutex::new(entries.into_iter().collect()),
        }
    }

    fn contains(&self, key: &str) -> bool {
        self.store.lock().unwrap().contains_key(key)
    }

    fn get_raw(&self, key: &str) -> Option<Vec<u8>> {
        self.store.lock().unwrap().get(key).cloned()
    }
}

#[async_trait]
impl CredStoreClientV1 for StatefulCredStore {
    async fn get(
        &self,
        _ctx: &SecurityContext,
        key: &SecretRef,
    ) -> Result<Option<GetSecretResponse>, CredStoreError> {
        Ok(self
            .store
            .lock()
            .unwrap()
            .get(key.as_ref())
            .map(|v| GetSecretResponse {
                value: SecretValue::new(v.clone()),
                owner_tenant_id: CredstoreTenantId::nil(),
                sharing: SharingMode::default(),
                is_inherited: false,
            }))
    }

    async fn put(
        &self,
        _ctx: &SecurityContext,
        key: &SecretRef,
        value: SecretValue,
        _sharing: SharingMode,
    ) -> Result<(), CredStoreError> {
        self.store
            .lock()
            .unwrap()
            .insert(key.as_ref().to_owned(), value.as_bytes().to_vec());
        Ok(())
    }

    async fn delete(
        &self,
        _ctx: &SecurityContext,
        key: &SecretRef,
    ) -> Result<(), CredStoreError> {
        self.store.lock().unwrap().remove(key.as_ref());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Minimal ControlPlaneService: only get_upstream is meaningful
// ---------------------------------------------------------------------------

struct MockCp {
    upstream: Option<model::Upstream>,
}

fn upstream_with_auth(resource: &str, token_ref: &str) -> model::Upstream {
    let mut config = HashMap::new();
    config.insert(CONFIG_RESOURCE.to_owned(), resource.to_owned());
    config.insert(CONFIG_TOKEN_REF.to_owned(), token_ref.to_owned());
    model::Upstream {
        id: Uuid::nil(),
        tenant_id: Uuid::nil(),
        alias: "corp-mcp".to_owned(),
        server: model::Server { endpoints: vec![] },
        protocol: "http".to_owned(),
        enabled: true,
        auth: Some(model::AuthConfig {
            plugin_type: "oauth2_auth_code".to_owned(),
            sharing: model::SharingMode::Private,
            config: Some(config),
        }),
        headers: None,
        plugins: None,
        rate_limit: None,
        cors: None,
        tags: vec![],
    }
}

#[async_trait]
impl ControlPlaneService for MockCp {
    async fn create_upstream(
        &self,
        _ctx: &SecurityContext,
        _req: model::CreateUpstreamRequest,
    ) -> Result<model::Upstream, DomainError> {
        unimplemented!()
    }

    async fn get_upstream(
        &self,
        _ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<model::Upstream, DomainError> {
        self.upstream
            .clone()
            .ok_or_else(|| DomainError::not_found("upstream", id))
    }

    async fn list_upstreams(
        &self,
        _ctx: &SecurityContext,
        _query: &model::ListQuery,
    ) -> Result<Vec<model::Upstream>, DomainError> {
        unimplemented!()
    }

    async fn update_upstream(
        &self,
        _ctx: &SecurityContext,
        _id: Uuid,
        _req: model::UpdateUpstreamRequest,
    ) -> Result<model::Upstream, DomainError> {
        unimplemented!()
    }

    async fn delete_upstream(
        &self,
        _ctx: &SecurityContext,
        _id: Uuid,
    ) -> Result<Vec<Uuid>, DomainError> {
        unimplemented!()
    }

    async fn create_route(
        &self,
        _ctx: &SecurityContext,
        _req: model::CreateRouteRequest,
    ) -> Result<model::Route, DomainError> {
        unimplemented!()
    }

    async fn get_route(
        &self,
        _ctx: &SecurityContext,
        _id: Uuid,
    ) -> Result<model::Route, DomainError> {
        unimplemented!()
    }

    async fn list_routes(
        &self,
        _ctx: &SecurityContext,
        _upstream_id: Option<Uuid>,
        _query: &model::ListQuery,
    ) -> Result<Vec<model::Route>, DomainError> {
        unimplemented!()
    }

    async fn update_route(
        &self,
        _ctx: &SecurityContext,
        _id: Uuid,
        _req: model::UpdateRouteRequest,
    ) -> Result<model::Route, DomainError> {
        unimplemented!()
    }

    async fn delete_route(
        &self,
        _ctx: &SecurityContext,
        _id: Uuid,
    ) -> Result<(), DomainError> {
        unimplemented!()
    }

    async fn resolve_proxy_target(
        &self,
        _ctx: &SecurityContext,
        _alias: &str,
        _method: &str,
        _path: &str,
    ) -> Result<(model::Upstream, model::Route), DomainError> {
        unimplemented!()
    }
}

fn test_http() -> toolkit_http::HttpClientConfig {
    toolkit_http::HttpClientConfig::for_testing()
}

/// Mount the discovery + registration endpoints on `server`, pointing at
/// itself as both resource origin and issuer.
fn mount_discovery(server: &MockServer) {
    let base = format!("http://localhost:{}", server.port());
    server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/oauth-protected-resource");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(r#"{{"authorization_servers":["{base}"]}}"#));
    });
    server.mock(|when, then| {
        when.method(GET)
            .path("/.well-known/oauth-authorization-server");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{"issuer":"{base}","authorization_endpoint":"{base}/authorize","token_endpoint":"{base}/token","registration_endpoint":"{base}/register","scopes_supported":["read","write"]}}"#
            ));
    });
    server.mock(|when, then| {
        when.method(POST).path("/register");
        then.status(201)
            .header("content-type", "application/json")
            .body(r#"{"client_id":"dcr-client-1"}"#);
    });
}

fn service_with(
    upstream: Option<model::Upstream>,
    credstore: Arc<StatefulCredStore>,
) -> OAuthEnrollmentServiceImpl {
    let cp: Arc<dyn ControlPlaneService> = Arc::new(MockCp { upstream });
    OAuthEnrollmentServiceImpl::with_http_config(cp, credstore, test_http())
}

#[tokio::test]
async fn begin_returns_url_and_persists_pending() {
    let server = MockServer::start();
    mount_discovery(&server);
    let resource = format!("http://localhost:{}/mcp", server.port());

    let credstore = Arc::new(StatefulCredStore::new());
    let svc = service_with(
        Some(upstream_with_auth(&resource, TOKEN_REF)),
        credstore.clone(),
    );

    let outcome = svc
        .begin(
            &test_ctx(),
            Uuid::nil(),
            vec!["read".to_owned()],
            "http://localhost:6274/callback".to_owned(),
            "mini-chat".to_owned(),
        )
        .await
        .unwrap();

    assert!(outcome.authorization_url.contains("/authorize"));
    assert!(outcome.authorization_url.contains(&format!("state={}", outcome.state)));
    assert!(outcome.authorization_url.contains("client_id=dcr-client-1"));
    assert!(credstore.contains(&format!("oagw-oauth-pending-{}", outcome.state)));
}

#[tokio::test]
async fn begin_then_complete_persists_token_record() {
    let server = MockServer::start();
    mount_discovery(&server);
    server.mock(|when, then| {
        when.method(POST)
            .path("/token")
            .body_includes("grant_type=authorization_code")
            .body_includes("code=auth-code-xyz");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"token_type":"Bearer"}"#);
    });
    let resource = format!("http://localhost:{}/mcp", server.port());

    let credstore = Arc::new(StatefulCredStore::new());
    let svc = service_with(
        Some(upstream_with_auth(&resource, TOKEN_REF)),
        credstore.clone(),
    );

    let outcome = svc
        .begin(
            &test_ctx(),
            Uuid::nil(),
            vec![],
            "http://localhost:6274/callback".to_owned(),
            "mini-chat".to_owned(),
        )
        .await
        .unwrap();

    svc.complete(&test_ctx(), outcome.state.clone(), "auth-code-xyz".to_owned())
        .await
        .unwrap();

    // Token record persisted, pending record cleaned up.
    let raw = credstore.get_raw(TOKEN_REF).expect("token record persisted");
    let record: OAuthTokenRecord = serde_json::from_slice(&raw).unwrap();
    assert_eq!(record.access_token, "at-1");
    assert_eq!(record.refresh_token.as_deref(), Some("rt-1"));
    assert!(!credstore.contains(&format!("oagw-oauth-pending-{}", outcome.state)));
}

#[tokio::test]
async fn complete_unknown_state_is_validation_error() {
    let credstore = Arc::new(StatefulCredStore::new());
    let svc = service_with(
        Some(upstream_with_auth("http://localhost/mcp", TOKEN_REF)),
        credstore,
    );
    let err = svc
        .complete(&test_ctx(), "does-not-exist".to_owned(), "code".to_owned())
        .await
        .unwrap_err();
    assert!(matches!(err, DomainError::Validation { .. }));
}

#[tokio::test]
async fn status_reports_connected_when_record_present() {
    let record = OAuthTokenRecord {
        client_id: "c".to_owned(),
        client_secret: None,
        token_endpoint: "http://localhost/token".to_owned(),
        access_token: "at".to_owned(),
        refresh_token: None,
        expires_at_unix: 1_000,
        scope: None,
    };
    let credstore = Arc::new(StatefulCredStore::with(vec![(
        TOKEN_REF.to_owned(),
        serde_json::to_vec(&record).unwrap(),
    )]));
    let svc = service_with(
        Some(upstream_with_auth("http://localhost/mcp", TOKEN_REF)),
        credstore,
    );

    let status = svc.status(&test_ctx(), Uuid::nil()).await.unwrap();
    assert!(status.connected);
    assert_eq!(status.expires_at_unix, Some(1_000));
}

#[tokio::test]
async fn status_reports_disconnected_when_absent() {
    let credstore = Arc::new(StatefulCredStore::new());
    let svc = service_with(
        Some(upstream_with_auth("http://localhost/mcp", TOKEN_REF)),
        credstore,
    );
    let status = svc.status(&test_ctx(), Uuid::nil()).await.unwrap();
    assert!(!status.connected);
    assert_eq!(status.expires_at_unix, None);
}

#[tokio::test]
async fn revoke_deletes_token_record() {
    let credstore = Arc::new(StatefulCredStore::with(vec![(
        TOKEN_REF.to_owned(),
        b"{}".to_vec(),
    )]));
    let svc = service_with(
        Some(upstream_with_auth("http://localhost/mcp", TOKEN_REF)),
        credstore.clone(),
    );

    svc.revoke(&test_ctx(), Uuid::nil()).await.unwrap();
    assert!(!credstore.contains(TOKEN_REF));
}

#[tokio::test]
async fn begin_missing_upstream_is_not_found() {
    let credstore = Arc::new(StatefulCredStore::new());
    let svc = service_with(None, credstore);
    let err = svc
        .begin(
            &test_ctx(),
            Uuid::nil(),
            vec![],
            "http://localhost:6274/callback".to_owned(),
            "mini-chat".to_owned(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DomainError::NotFound { .. }));
}
