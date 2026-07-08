//! Interactive `OAuth2` authorization-code flow client (per-user).
//!
//! Unlike the client-credentials path elsewhere in this module, this
//! implements the browser-driven authorization-code flow used to obtain
//! per-user tokens for corporate resources (e.g. MCP servers behind OAGW):
//!
//! - Metadata discovery: RFC 9728 protected-resource metadata to locate the
//!   authorization server, then RFC 8414 authorization-server metadata.
//! - Dynamic Client Registration (RFC 7591) for public clients.
//! - PKCE (RFC 7636, S256) challenge/verifier generation.
//! - Authorization-request URL construction.
//! - Authorization-code exchange and refresh-token rotation, with a distinct
//!   [`TokenError::RefreshRejected`] so callers can trigger re-authorization
//!   instead of retrying.
//!
//! All secret material is wrapped in [`SecretString`] and never logged.

use std::fmt;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use toolkit_http::HttpClient;
use toolkit_utils::SecretString;
use url::Url;

use super::error::TokenError;
use crate::http_error::format_http_error;

/// Default access-token lifetime applied when the authorization server omits
/// `expires_in` from a token response.
const DEFAULT_TOKEN_TTL: Duration = Duration::from_hours(1);

// ---------------------------------------------------------------------------
// Metadata discovery
// ---------------------------------------------------------------------------

/// RFC 9728 protected-resource metadata (subset).
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// Authorization server issuer identifiers that can issue tokens for this
    /// resource. The first entry is used.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
}

/// RFC 8414 authorization-server metadata (subset).
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// Authorization server issuer identifier.
    pub issuer: String,
    /// Endpoint used to build the browser authorization request.
    pub authorization_endpoint: String,
    /// Endpoint used for code exchange and refresh.
    pub token_endpoint: String,
    /// Optional RFC 7591 dynamic client registration endpoint.
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    /// Scopes advertised by the server; callers must not request scopes
    /// outside this list when present.
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    /// PKCE code-challenge methods supported (should contain `S256`).
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Return the scheme/host/port origin of `url`, dropping path/query/fragment.
fn origin_of(url: &Url) -> Url {
    let mut origin = url.clone();
    origin.set_path("");
    origin.set_query(None);
    origin.set_fragment(None);
    origin
}

async fn fetch_json<T>(client: &HttpClient, url: &str, ctx: &str) -> Result<T, TokenError>
where
    T: serde::de::DeserializeOwned,
{
    client
        .get(url)
        .send()
        .await
        .map_err(|e| TokenError::Http(format_http_error(&e, ctx)))?
        .error_for_status()
        .map_err(|e| TokenError::Http(format_http_error(&e, ctx)))?
        .json()
        .await
        .map_err(|e| TokenError::InvalidResponse(format_http_error(&e, ctx)))
}

/// Fetch RFC 9728 protected-resource metadata for `resource_url`.
///
/// The well-known path is resolved against the resource *origin* (any
/// resource path such as `/mcp` is stripped first).
///
/// # Errors
///
/// Returns [`TokenError::Http`] on transport/status failures and
/// [`TokenError::InvalidResponse`] on unparseable bodies.
pub async fn discover_protected_resource(
    client: &HttpClient,
    resource_url: &Url,
) -> Result<ProtectedResourceMetadata, TokenError> {
    let origin = origin_of(resource_url);
    let base = origin.as_str().trim_end_matches('/');
    let url = format!("{base}/.well-known/oauth-protected-resource");
    fetch_json(client, &url, "OAuth protected-resource discovery").await
}

/// Fetch RFC 8414 authorization-server metadata for `issuer`.
///
/// # Errors
///
/// Returns [`TokenError::Http`] on transport/status failures and
/// [`TokenError::InvalidResponse`] on unparseable bodies.
pub async fn discover_authorization_server(
    client: &HttpClient,
    issuer: &Url,
) -> Result<AuthorizationServerMetadata, TokenError> {
    let base = issuer.as_str().trim_end_matches('/');
    let url = format!("{base}/.well-known/oauth-authorization-server");
    fetch_json(client, &url, "OAuth authorization-server discovery").await
}

/// Resolve authorization-server metadata starting from a protected resource
/// URL: protected-resource metadata -> first authorization server -> its
/// authorization-server metadata.
///
/// # Errors
///
/// Returns [`TokenError::InvalidResponse`] if no authorization server is
/// advertised or the advertised URL is invalid, otherwise propagates the
/// discovery errors.
pub async fn discover_from_resource(
    client: &HttpClient,
    resource_url: &Url,
) -> Result<AuthorizationServerMetadata, TokenError> {
    let prm = discover_protected_resource(client, resource_url).await?;
    let issuer_str = prm.authorization_servers.into_iter().next().ok_or_else(|| {
        TokenError::InvalidResponse(
            "protected-resource metadata advertised no authorization_servers".to_owned(),
        )
    })?;
    let issuer = Url::parse(&issuer_str).map_err(|e| {
        TokenError::InvalidResponse(format!("invalid authorization server URL: {e}"))
    })?;
    discover_authorization_server(client, &issuer).await
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

/// A PKCE (RFC 7636) verifier/challenge pair using the `S256` method.
pub struct Pkce {
    /// High-entropy verifier, sent with the code exchange. Kept secret.
    pub verifier: SecretString,
    /// `BASE64URL(SHA256(verifier))`, sent in the authorization request.
    pub challenge: String,
}

impl fmt::Debug for Pkce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkce")
            .field("verifier", &"[REDACTED]")
            .field("challenge", &self.challenge)
            .finish()
    }
}

impl Pkce {
    /// Generate a fresh PKCE pair from 32 bytes of randomness.
    #[must_use]
    pub fn generate() -> Self {
        let raw: [u8; 32] = rand::random();
        let verifier = URL_SAFE_NO_PAD.encode(raw);
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        Self {
            verifier: SecretString::new(verifier),
            challenge,
        }
    }

    /// The code-challenge method identifier (`S256`).
    #[must_use]
    pub fn method(&self) -> &'static str {
        "S256"
    }
}

/// Generate an opaque, URL-safe CSRF `state` value (32 bytes of entropy).
#[must_use]
pub fn generate_state() -> String {
    let raw: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(raw)
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct RegistrationRequest<'a> {
    client_name: &'a str,
    redirect_uris: &'a [String],
    grant_types: Vec<&'a str>,
    response_types: Vec<&'a str>,
    token_endpoint_auth_method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct RegistrationResponse {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
}

/// A client registered via RFC 7591 Dynamic Client Registration.
pub struct RegisteredClient {
    /// Issued client identifier.
    pub client_id: String,
    /// Issued client secret, if the server registered a confidential client.
    /// Public (PKCE-only) clients have `None`.
    pub client_secret: Option<SecretString>,
}

impl fmt::Debug for RegisteredClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredClient")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Register a public (PKCE) client via RFC 7591 Dynamic Client Registration.
///
/// # Errors
///
/// Returns [`TokenError::RegistrationFailed`] on non-success status and
/// [`TokenError::InvalidResponse`] if the response cannot be parsed.
pub async fn register_client(
    client: &HttpClient,
    registration_endpoint: &str,
    client_name: &str,
    redirect_uris: &[String],
    scopes: &[String],
) -> Result<RegisteredClient, TokenError> {
    let scope = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };
    let body = RegistrationRequest {
        client_name,
        redirect_uris,
        grant_types: vec!["authorization_code", "refresh_token"],
        response_types: vec!["code"],
        token_endpoint_auth_method: "none",
        scope,
    };

    let ctx = "OAuth dynamic client registration";
    let resp = client
        .post(registration_endpoint)
        .json(&body)
        .map_err(|e| TokenError::Http(format_http_error(&e, ctx)))?
        .send()
        .await
        .map_err(|e| TokenError::Http(format_http_error(&e, ctx)))?;

    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| TokenError::Http(format_http_error(&e, ctx)))?;
    if !status.is_success() {
        return Err(TokenError::RegistrationFailed(format!(
            "{ctx}: HTTP {}",
            status.as_u16()
        )));
    }

    let parsed: RegistrationResponse = serde_json::from_slice(&bytes)
        .map_err(|e| TokenError::InvalidResponse(format!("{ctx}: {e}")))?;
    Ok(RegisteredClient {
        client_id: parsed.client_id,
        client_secret: parsed.client_secret.map(SecretString::new),
    })
}

// ---------------------------------------------------------------------------
// Authorization request URL
// ---------------------------------------------------------------------------

/// Build the browser authorization-request URL (RFC 6749 §4.1.1 + PKCE).
///
/// Only scopes advertised by the server should be passed in `scopes`.
///
/// # Errors
///
/// Returns [`TokenError::ConfigError`] if `authorization_endpoint` is not a
/// valid URL.
pub fn build_authorize_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    pkce_challenge: &str,
) -> Result<Url, TokenError> {
    let mut url = Url::parse(authorization_endpoint).map_err(|e| {
        TokenError::ConfigError(format!("invalid authorization_endpoint URL: {e}"))
    })?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("state", state);
        q.append_pair("code_challenge", pkce_challenge);
        q.append_pair("code_challenge_method", "S256");
        if !scopes.is_empty() {
            q.append_pair("scope", &scopes.join(" "));
        }
    }
    Ok(url)
}

// ---------------------------------------------------------------------------
// Token exchange / refresh
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthCodeTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// Tokens returned by an authorization-code exchange or refresh.
pub struct TokenSet {
    /// Bearer access token.
    pub access_token: SecretString,
    /// Refresh token, when the server issues one (or rotates it).
    pub refresh_token: Option<SecretString>,
    /// Access-token lifetime (server `expires_in`, or a default).
    pub expires_in: Duration,
    /// Granted scope, if the server echoed one.
    pub scope: Option<String>,
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Parameters for an authorization-code exchange.
pub struct AuthCodeExchange<'a> {
    /// Authorization-server token endpoint.
    pub token_endpoint: &'a str,
    /// Client identifier (from config or DCR).
    pub client_id: &'a str,
    /// Client secret for confidential clients; `None` for public/PKCE clients.
    pub client_secret: Option<&'a SecretString>,
    /// Authorization code returned to the redirect URI.
    pub code: &'a str,
    /// Redirect URI used in the authorization request (must match).
    pub redirect_uri: &'a str,
    /// PKCE code verifier matching the challenge sent earlier.
    pub code_verifier: &'a SecretString,
}

/// Exchange an authorization code for tokens (RFC 6749 §4.1.3 + PKCE).
///
/// # Errors
///
/// Returns [`TokenError::Http`] on transport/non-success status,
/// [`TokenError::InvalidResponse`] on parse failures, and
/// [`TokenError::UnsupportedTokenType`] for non-Bearer tokens.
pub async fn exchange_code(
    client: &HttpClient,
    req: &AuthCodeExchange<'_>,
) -> Result<TokenSet, TokenError> {
    let secret_expose = req.client_secret.map(|s| s.expose().to_owned());
    let mut fields: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", req.code),
        ("redirect_uri", req.redirect_uri),
        ("client_id", req.client_id),
        ("code_verifier", req.code_verifier.expose()),
    ];
    if let Some(ref secret) = secret_expose {
        fields.push(("client_secret", secret));
    }

    post_token(client, req.token_endpoint, &fields, "OAuth code exchange", false).await
}

/// Perform a refresh-token grant (RFC 6749 §6), rotating the refresh token
/// when the server returns a new one.
///
/// # Errors
///
/// Returns [`TokenError::RefreshRejected`] when the server rejects the refresh
/// token (HTTP 400/401 or `invalid_grant`), signalling that the caller should
/// re-authorize. Other failures map to [`TokenError::Http`] /
/// [`TokenError::InvalidResponse`].
pub async fn refresh_token(
    client: &HttpClient,
    token_endpoint: &str,
    client_id: &str,
    client_secret: Option<&SecretString>,
    refresh_token: &SecretString,
    scopes: &[String],
) -> Result<TokenSet, TokenError> {
    let secret_expose = client_secret.map(|s| s.expose().to_owned());
    let scope_joined = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };

    let mut fields: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.expose()),
        ("client_id", client_id),
    ];
    if let Some(ref secret) = secret_expose {
        fields.push(("client_secret", secret));
    }
    if let Some(ref scope) = scope_joined {
        fields.push(("scope", scope));
    }

    post_token(client, token_endpoint, &fields, "OAuth token refresh", true).await
}

/// POST a token-endpoint form and parse the response.
///
/// When `reject_as_refresh` is set, HTTP 400/401 or an `invalid_grant` body is
/// surfaced as [`TokenError::RefreshRejected`] rather than a generic HTTP
/// error.
async fn post_token(
    client: &HttpClient,
    token_endpoint: &str,
    fields: &[(&str, &str)],
    ctx: &str,
    reject_as_refresh: bool,
) -> Result<TokenSet, TokenError> {
    let resp = client
        .post(token_endpoint)
        .form(fields)
        .map_err(|e| TokenError::Http(format_http_error(&e, ctx)))?
        .send()
        .await
        .map_err(|e| TokenError::Http(format_http_error(&e, ctx)))?;

    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| TokenError::Http(format_http_error(&e, ctx)))?;

    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        let is_invalid_grant = body.contains("invalid_grant");
        if reject_as_refresh
            && (status.as_u16() == 400 || status.as_u16() == 401 || is_invalid_grant)
        {
            return Err(TokenError::RefreshRejected(format!(
                "{ctx}: HTTP {}",
                status.as_u16()
            )));
        }
        return Err(TokenError::Http(format!("{ctx}: HTTP {}", status.as_u16())));
    }

    let parsed: AuthCodeTokenResponse = serde_json::from_slice(&bytes)
        .map_err(|e| TokenError::InvalidResponse(format!("{ctx}: {e}")))?;

    if let Some(ref tt) = parsed.token_type
        && !tt.eq_ignore_ascii_case("bearer")
    {
        return Err(TokenError::UnsupportedTokenType(tt.clone()));
    }

    Ok(TokenSet {
        access_token: SecretString::new(parsed.access_token),
        refresh_token: parsed.refresh_token.map(SecretString::new),
        expires_in: parsed
            .expires_in
            .map_or(DEFAULT_TOKEN_TTL, Duration::from_secs),
        scope: parsed.scope,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "authcode_tests.rs"]
mod authcode_tests;
