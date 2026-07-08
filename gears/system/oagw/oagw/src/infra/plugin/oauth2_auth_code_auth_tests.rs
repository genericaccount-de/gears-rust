use std::collections::HashMap;
use std::sync::Arc;

use httpmock::prelude::*;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use super::*;
use crate::domain::plugin::AuthContext;
use crate::domain::test_support::MockCredStoreClient;

const TOKEN_REF: &str = "mcp_oauth_test_upstream";

fn test_http() -> toolkit_http::HttpClientConfig {
    toolkit_http::HttpClientConfig::for_testing()
}

fn ctx_with_token_ref() -> AuthContext {
    let mut config = HashMap::new();
    config.insert("token_ref".to_owned(), TOKEN_REF.to_owned());
    config.insert(
        "resource".to_owned(),
        "https://mcp.example.com/mcp".to_owned(),
    );
    AuthContext {
        headers: HashMap::new(),
        config,
        security_context: SecurityContext::builder()
            .subject_id(Uuid::nil())
            .subject_tenant_id(Uuid::nil())
            .build()
            .unwrap(),
    }
}

fn record_json(expires_at: i64, refresh: Option<&str>, token_endpoint: &str) -> String {
    let record = OAuthTokenRecord {
        client_id: "client-1".to_owned(),
        client_secret: None,
        token_endpoint: token_endpoint.to_owned(),
        access_token: "at-current".to_owned(),
        refresh_token: refresh.map(String::from),
        expires_at_unix: expires_at,
        scope: None,
    };
    serde_json::to_string(&record).unwrap()
}

fn plugin_with(store: Vec<(String, String)>) -> OAuth2AuthCodeAuthPlugin {
    let credstore = Arc::new(MockCredStoreClient::with_secrets(store));
    OAuth2AuthCodeAuthPlugin::with_http_config(credstore, test_http())
}

#[tokio::test]
async fn valid_token_injects_bearer() {
    let record = record_json(now_unix() + 3600, Some("rt"), "https://unused.example.com/token");
    let plugin = plugin_with(vec![(TOKEN_REF.to_owned(), record)]);
    let mut ctx = ctx_with_token_ref();

    plugin.authenticate(&mut ctx).await.unwrap();
    assert_eq!(ctx.headers.get("authorization").unwrap(), "Bearer at-current");
}

#[tokio::test]
async fn missing_record_requires_authorization() {
    let plugin = plugin_with(vec![]);
    let mut ctx = ctx_with_token_ref();

    let err = plugin.authenticate(&mut ctx).await.unwrap_err();
    assert!(matches!(err, PluginError::AuthorizationRequired(_)));
}

#[tokio::test]
async fn expired_without_refresh_requires_authorization() {
    let record = record_json(now_unix() - 10, None, "https://unused.example.com/token");
    let plugin = plugin_with(vec![(TOKEN_REF.to_owned(), record)]);
    let mut ctx = ctx_with_token_ref();

    let err = plugin.authenticate(&mut ctx).await.unwrap_err();
    assert!(matches!(err, PluginError::AuthorizationRequired(_)));
}

#[tokio::test]
async fn invalid_config_missing_token_ref() {
    let plugin = plugin_with(vec![]);
    let mut ctx = ctx_with_token_ref();
    ctx.config.remove("token_ref");

    let err = plugin.authenticate(&mut ctx).await.unwrap_err();
    assert!(matches!(err, PluginError::InvalidConfig(_)));
}

#[tokio::test]
async fn expired_with_refresh_injects_new_bearer() {
    let server = MockServer::start();
    let token_ep = format!("http://localhost:{}/token", server.port());
    let m = server.mock(|when, then| {
        when.method(POST)
            .path("/token")
            .body_includes("grant_type=refresh_token")
            .body_includes("refresh_token=rt-old");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"access_token":"at-new","refresh_token":"rt-new","expires_in":3600,"token_type":"Bearer"}"#);
    });

    let record = record_json(now_unix() - 10, Some("rt-old"), &token_ep);
    let plugin = plugin_with(vec![(TOKEN_REF.to_owned(), record)]);
    let mut ctx = ctx_with_token_ref();

    plugin.authenticate(&mut ctx).await.unwrap();
    assert_eq!(ctx.headers.get("authorization").unwrap(), "Bearer at-new");
    m.assert();
}

#[tokio::test]
async fn refresh_rejected_requires_authorization() {
    let server = MockServer::start();
    let token_ep = format!("http://localhost:{}/token", server.port());
    let _m = server.mock(|when, then| {
        when.method(POST).path("/token");
        then.status(400)
            .header("content-type", "application/json")
            .body(r#"{"error":"invalid_grant"}"#);
    });

    let record = record_json(now_unix() - 10, Some("rt-old"), &token_ep);
    let plugin = plugin_with(vec![(TOKEN_REF.to_owned(), record)]);
    let mut ctx = ctx_with_token_ref();

    let err = plugin.authenticate(&mut ctx).await.unwrap_err();
    assert!(matches!(err, PluginError::AuthorizationRequired(_)));
}
