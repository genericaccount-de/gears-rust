use super::*;
use httpmock::prelude::*;

fn test_client() -> HttpClient {
    toolkit_http::HttpClientBuilder::with_config(toolkit_http::HttpClientConfig::for_testing())
        .build()
        .unwrap()
}

fn base_url(server: &MockServer) -> String {
    format!("http://localhost:{}", server.port())
}

// ── PKCE ─────────────────────────────────────────────────────────────────

#[test]
fn pkce_challenge_is_sha256_of_verifier() {
    let pkce = Pkce::generate();
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce.verifier.expose().as_bytes()));
    assert_eq!(pkce.challenge, expected);
    assert_eq!(pkce.method(), "S256");
}

#[test]
fn pkce_pairs_are_unique() {
    let a = Pkce::generate();
    let b = Pkce::generate();
    assert_ne!(a.verifier.expose(), b.verifier.expose());
    assert_ne!(a.challenge, b.challenge);
}

#[test]
fn pkce_debug_redacts_verifier() {
    let pkce = Pkce::generate();
    let dbg = format!("{pkce:?}");
    assert!(!dbg.contains(pkce.verifier.expose()));
    assert!(dbg.contains("[REDACTED]"));
}

#[test]
fn generate_state_is_unique_and_urlsafe() {
    let s1 = generate_state();
    let s2 = generate_state();
    assert_ne!(s1, s2);
    assert!(!s1.contains('+') && !s1.contains('/') && !s1.contains('='));
}

// ── Authorize URL ──────────────────────────────────────────────────────────

#[test]
fn build_authorize_url_includes_all_params() {
    let url = build_authorize_url(
        "https://as.example.com/authorize",
        "client-123",
        "https://app.example.com/cb",
        &["openid".to_owned(), "mcp".to_owned()],
        "state-xyz",
        "challenge-abc",
    )
    .unwrap();

    let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs["response_type"], "code");
    assert_eq!(pairs["client_id"], "client-123");
    assert_eq!(pairs["redirect_uri"], "https://app.example.com/cb");
    assert_eq!(pairs["state"], "state-xyz");
    assert_eq!(pairs["code_challenge"], "challenge-abc");
    assert_eq!(pairs["code_challenge_method"], "S256");
    assert_eq!(pairs["scope"], "openid mcp");
}

#[test]
fn build_authorize_url_omits_scope_when_empty() {
    let url = build_authorize_url(
        "https://as.example.com/authorize",
        "c",
        "https://app/cb",
        &[],
        "s",
        "ch",
    )
    .unwrap();
    assert!(url.query_pairs().all(|(k, _)| k != "scope"));
}

#[test]
fn build_authorize_url_rejects_invalid_endpoint() {
    let err = build_authorize_url("not a url", "c", "r", &[], "s", "ch").unwrap_err();
    assert!(matches!(err, TokenError::ConfigError(_)));
}

// ── Discovery ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn discover_from_resource_chains_prm_then_as() {
    let server = MockServer::start();
    let issuer = base_url(&server);

    let prm = server.mock(|when, then| {
        when.method(GET).path("/.well-known/oauth-protected-resource");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(r#"{{"authorization_servers":["{issuer}"]}}"#));
    });
    let asm = server.mock(|when, then| {
        when.method(GET).path("/.well-known/oauth-authorization-server");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","registration_endpoint":"{issuer}/register"}}"#
            ));
    });

    let client = test_client();
    // Resource URL carries a /mcp path that must be stripped for discovery.
    let resource = Url::parse(&format!("{issuer}/mcp")).unwrap();
    let meta = discover_from_resource(&client, &resource).await.unwrap();

    assert_eq!(meta.token_endpoint, format!("{issuer}/token"));
    assert_eq!(meta.registration_endpoint.as_deref(), Some(format!("{issuer}/register").as_str()));
    prm.assert();
    asm.assert();
}

#[tokio::test]
async fn discover_from_resource_errors_without_authorization_servers() {
    let server = MockServer::start();
    let _prm = server.mock(|when, then| {
        when.method(GET).path("/.well-known/oauth-protected-resource");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"authorization_servers":[]}"#);
    });

    let client = test_client();
    let resource = Url::parse(&base_url(&server)).unwrap();
    let err = discover_from_resource(&client, &resource).await.unwrap_err();
    assert!(matches!(err, TokenError::InvalidResponse(_)));
}

#[tokio::test]
async fn discover_protected_resource_http_error() {
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(GET).path("/.well-known/oauth-protected-resource");
        then.status(500).body("boom");
    });
    let client = test_client();
    let resource = Url::parse(&base_url(&server)).unwrap();
    let err = discover_protected_resource(&client, &resource).await.unwrap_err();
    assert!(matches!(err, TokenError::Http(_)));
}

// ── Dynamic client registration ──────────────────────────────────────────

#[tokio::test]
async fn register_client_returns_credentials() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.method(POST).path("/register");
        then.status(201)
            .header("content-type", "application/json")
            .body(r#"{"client_id":"dcr-client","client_secret":"dcr-secret"}"#);
    });

    let client = test_client();
    let reg = register_client(
        &client,
        &format!("{}/register", base_url(&server)),
        "mini-chat",
        &["https://app/cb".to_owned()],
        &["openid".to_owned()],
    )
    .await
    .unwrap();

    assert_eq!(reg.client_id, "dcr-client");
    assert_eq!(reg.client_secret.as_ref().unwrap().expose(), "dcr-secret");
    m.assert();
}

#[tokio::test]
async fn register_client_public_has_no_secret() {
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(POST).path("/register");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"client_id":"public-client"}"#);
    });

    let client = test_client();
    let reg = register_client(
        &client,
        &format!("{}/register", base_url(&server)),
        "mini-chat",
        &["https://app/cb".to_owned()],
        &[],
    )
    .await
    .unwrap();
    assert_eq!(reg.client_id, "public-client");
    assert!(reg.client_secret.is_none());
}

#[tokio::test]
async fn register_client_failure_maps_to_registration_failed() {
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(POST).path("/register");
        then.status(400).body(r#"{"error":"invalid_redirect_uri"}"#);
    });

    let client = test_client();
    let err = register_client(
        &client,
        &format!("{}/register", base_url(&server)),
        "mini-chat",
        &["bad".to_owned()],
        &[],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, TokenError::RegistrationFailed(_)));
}

// ── Code exchange ──────────────────────────────────────────────────────────

#[tokio::test]
async fn exchange_code_returns_token_set() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.method(POST)
            .path("/token")
            .body_includes("grant_type=authorization_code")
            .body_includes("code=auth-code-1")
            .body_includes("code_verifier=verifier-1");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"token_type":"Bearer","scope":"mcp"}"#);
    });

    let client = test_client();
    let verifier = SecretString::new("verifier-1");
    let req = AuthCodeExchange {
        token_endpoint: &format!("{}/token", base_url(&server)),
        client_id: "client-1",
        client_secret: None,
        code: "auth-code-1",
        redirect_uri: "https://app/cb",
        code_verifier: &verifier,
    };
    let tokens = exchange_code(&client, &req).await.unwrap();

    assert_eq!(tokens.access_token.expose(), "at-1");
    assert_eq!(tokens.refresh_token.as_ref().unwrap().expose(), "rt-1");
    assert_eq!(tokens.expires_in, Duration::from_hours(1));
    assert_eq!(tokens.scope.as_deref(), Some("mcp"));
    m.assert();
}

#[tokio::test]
async fn exchange_code_defaults_ttl_when_missing() {
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(POST).path("/token");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"access_token":"at","token_type":"Bearer"}"#);
    });

    let client = test_client();
    let verifier = SecretString::new("v");
    let req = AuthCodeExchange {
        token_endpoint: &format!("{}/token", base_url(&server)),
        client_id: "c",
        client_secret: None,
        code: "code",
        redirect_uri: "https://app/cb",
        code_verifier: &verifier,
    };
    let tokens = exchange_code(&client, &req).await.unwrap();
    assert_eq!(tokens.expires_in, DEFAULT_TOKEN_TTL);
    assert!(tokens.refresh_token.is_none());
}

#[tokio::test]
async fn exchange_code_unsupported_token_type() {
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(POST).path("/token");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"access_token":"at","token_type":"mac"}"#);
    });

    let client = test_client();
    let verifier = SecretString::new("v");
    let req = AuthCodeExchange {
        token_endpoint: &format!("{}/token", base_url(&server)),
        client_id: "c",
        client_secret: None,
        code: "code",
        redirect_uri: "https://app/cb",
        code_verifier: &verifier,
    };
    let err = exchange_code(&client, &req).await.unwrap_err();
    assert!(matches!(err, TokenError::UnsupportedTokenType(ref t) if t == "mac"));
}

// ── Refresh ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn refresh_rotates_refresh_token() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.method(POST)
            .path("/token")
            .body_includes("grant_type=refresh_token")
            .body_includes("refresh_token=rt-old");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"access_token":"at-new","refresh_token":"rt-new","expires_in":1800,"token_type":"Bearer"}"#);
    });

    let client = test_client();
    let rt = SecretString::new("rt-old");
    let tokens = refresh_token(
        &client,
        &format!("{}/token", base_url(&server)),
        "client-1",
        None,
        &rt,
        &[],
    )
    .await
    .unwrap();

    assert_eq!(tokens.access_token.expose(), "at-new");
    assert_eq!(tokens.refresh_token.as_ref().unwrap().expose(), "rt-new");
    assert_eq!(tokens.expires_in, Duration::from_mins(30));
    m.assert();
}

#[tokio::test]
async fn refresh_invalid_grant_maps_to_refresh_rejected() {
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(POST).path("/token");
        then.status(400)
            .header("content-type", "application/json")
            .body(r#"{"error":"invalid_grant"}"#);
    });

    let client = test_client();
    let rt = SecretString::new("rt-old");
    let err = refresh_token(
        &client,
        &format!("{}/token", base_url(&server)),
        "client-1",
        None,
        &rt,
        &[],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, TokenError::RefreshRejected(_)));
}

#[tokio::test]
async fn refresh_server_error_is_not_refresh_rejected() {
    let server = MockServer::start();
    let _m = server.mock(|when, then| {
        when.method(POST).path("/token");
        then.status(500).body("boom");
    });

    let client = test_client();
    let rt = SecretString::new("rt-old");
    let err = refresh_token(
        &client,
        &format!("{}/token", base_url(&server)),
        "client-1",
        None,
        &rt,
        &[],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, TokenError::Http(_)));
}

#[tokio::test]
async fn token_set_debug_redacts_secrets() {
    let tokens = TokenSet {
        access_token: SecretString::new("super-secret-at"),
        refresh_token: Some(SecretString::new("super-secret-rt")),
        expires_in: Duration::from_mins(1),
        scope: None,
    };
    let dbg = format!("{tokens:?}");
    assert!(!dbg.contains("super-secret-at"));
    assert!(!dbg.contains("super-secret-rt"));
    assert!(dbg.contains("[REDACTED]"));
}
