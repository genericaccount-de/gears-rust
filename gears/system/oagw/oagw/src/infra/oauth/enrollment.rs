//! credstore-backed implementation of the interactive OAuth2
//! authorization-code enrollment service.
//!
//! The flow spans two calls:
//!
//! 1. [`begin`](OAuthEnrollmentServiceImpl::begin) discovers the authorization
//!    server for the upstream's protected resource, dynamically registers a
//!    public (PKCE) client, generates PKCE + CSRF state, persists a short-lived
//!    [`PendingAuthorization`] record keyed by `state`, and returns the browser
//!    authorization URL.
//! 2. [`complete`](OAuthEnrollmentServiceImpl::complete) loads the pending
//!    record by `state`, exchanges the authorization `code`, persists the
//!    resulting per-user [`OAuthTokenRecord`] under the upstream's configured
//!    `token_ref`, and deletes the pending record.
//!
//! [`revoke`](OAuthEnrollmentServiceImpl::revoke) and
//! [`status`](OAuthEnrollmentServiceImpl::status) act on the stored token
//! record. All secret material is scoped to the calling subject via credstore
//! `Private` sharing.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use credstore_sdk::{CredStoreClientV1, SecretRef, SecretValue, SharingMode};
use serde::{Deserialize, Serialize};
use toolkit_auth::oauth2::authcode;
use toolkit_auth::oauth2::types::SecretString;
use toolkit_security::SecurityContext;
use url::Url;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::services::{
    ControlPlaneService, OAuthBeginOutcome, OAuthConnectionStatus, OAuthEnrollmentService,
};
use crate::infra::plugin::oauth2_auth_code_auth::OAuthTokenRecord;

/// Config key on the upstream auth binding naming the protected-resource URL
/// used to discover the authorization server.
const CONFIG_RESOURCE: &str = "resource";
/// Config key naming the credstore `SecretRef` under which the per-user token
/// record is stored (the `oauth2_auth_code` plugin reads the same key).
const CONFIG_TOKEN_REF: &str = "token_ref";

/// Short-lived state persisted between `begin` and `complete`, keyed by the
/// CSRF `state`. Holds everything needed to complete the code exchange without
/// re-discovering or re-registering.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingAuthorization {
    upstream_id: Uuid,
    token_ref: String,
    token_endpoint: String,
    client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    code_verifier: String,
    redirect_uri: String,
    #[serde(default)]
    scopes: Vec<String>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Strip an optional `cred://` scheme prefix and validate as a `SecretRef`.
fn parse_secret_ref(raw: &str) -> Result<SecretRef, DomainError> {
    let stripped = raw.strip_prefix("cred://").unwrap_or(raw);
    SecretRef::new(stripped)
        .map_err(|e| DomainError::validation(format!("invalid token_ref '{stripped}': {e}")))
}

/// Deterministic credstore ref for the pending record of a given `state`.
///
/// `state` is URL-safe base64 (`[A-Za-z0-9_-]`), so the joined ref stays within
/// the `SecretRef` charset.
fn pending_ref(state: &str) -> Result<SecretRef, DomainError> {
    SecretRef::new(format!("oagw-oauth-pending-{state}"))
        .map_err(|e| DomainError::internal(format!("invalid pending state ref: {e}")))
}

/// Enrollment service backed by the control plane (upstream lookup), credstore
/// (state + token store), and an HTTP client (discovery / DCR / exchange).
pub(crate) struct OAuthEnrollmentServiceImpl {
    cp: Arc<dyn ControlPlaneService>,
    credstore: Arc<dyn CredStoreClientV1>,
    /// HTTP client config; the client is built per operation so construction
    /// does not require a live Tokio runtime at wiring time.
    http_config: toolkit_http::HttpClientConfig,
}

impl OAuthEnrollmentServiceImpl {
    /// Build with the default token-endpoint HTTP client config.
    #[must_use]
    pub(crate) fn new(
        cp: Arc<dyn ControlPlaneService>,
        credstore: Arc<dyn CredStoreClientV1>,
    ) -> Self {
        Self::with_http_config(cp, credstore, toolkit_http::HttpClientConfig::token_endpoint())
    }

    /// Build with an explicit HTTP client config (test seam).
    #[must_use]
    pub(crate) fn with_http_config(
        cp: Arc<dyn ControlPlaneService>,
        credstore: Arc<dyn CredStoreClientV1>,
        http_config: toolkit_http::HttpClientConfig,
    ) -> Self {
        Self {
            cp,
            credstore,
            http_config,
        }
    }

    fn http(&self) -> Result<toolkit_http::HttpClient, DomainError> {
        toolkit_http::HttpClientBuilder::with_config(self.http_config.clone())
            .build()
            .map_err(|e| DomainError::internal(format!("failed to build HTTP client: {e}")))
    }

    /// Read `(resource, token_ref)` from an upstream's `oauth2_auth_code` auth
    /// binding config.
    async fn resolve_binding(
        &self,
        ctx: &SecurityContext,
        upstream_id: Uuid,
    ) -> Result<(String, String), DomainError> {
        let upstream = self.cp.get_upstream(ctx, upstream_id).await?;
        let auth = upstream
            .auth
            .ok_or_else(|| DomainError::validation("upstream has no auth configuration"))?;
        let config = auth
            .config
            .ok_or_else(|| DomainError::validation("upstream auth binding has no config"))?;
        let resource = config
            .get(CONFIG_RESOURCE)
            .cloned()
            .ok_or_else(|| DomainError::validation("auth binding missing 'resource'"))?;
        let token_ref = config
            .get(CONFIG_TOKEN_REF)
            .cloned()
            .ok_or_else(|| DomainError::validation("auth binding missing 'token_ref'"))?;
        Ok((resource, token_ref))
    }

    async fn load_pending(
        &self,
        ctx: &SecurityContext,
        state_ref: &SecretRef,
    ) -> Result<PendingAuthorization, DomainError> {
        let resp = self
            .credstore
            .get(ctx, state_ref)
            .await
            .map_err(|e| DomainError::internal(format!("credstore get error: {e}")))?
            .ok_or_else(|| DomainError::validation("unknown or expired authorization state"))?;
        serde_json::from_slice(resp.value.as_bytes())
            .map_err(|e| DomainError::internal(format!("corrupt pending state: {e}")))
    }
}

#[async_trait]
impl OAuthEnrollmentService for OAuthEnrollmentServiceImpl {
    async fn begin(
        &self,
        ctx: &SecurityContext,
        upstream_id: Uuid,
        scopes: Vec<String>,
        redirect_uri: String,
        client_name: String,
    ) -> Result<OAuthBeginOutcome, DomainError> {
        let (resource, token_ref) = self.resolve_binding(ctx, upstream_id).await?;
        // Validate the destination ref early so a misconfigured upstream fails
        // before any network round-trips.
        let _ = parse_secret_ref(&token_ref)?;

        let resource_url = Url::parse(&resource)
            .map_err(|e| DomainError::validation(format!("invalid 'resource' URL: {e}")))?;

        let http = self.http()?;
        let meta = authcode::discover_from_resource(&http, &resource_url)
            .await
            .map_err(|e| DomainError::internal(format!("authorization-server discovery failed: {e}")))?;

        // Intersect requested scopes with what the server advertises.
        let effective_scopes: Vec<String> = match meta.scopes_supported.as_ref() {
            Some(supported) if !scopes.is_empty() => scopes
                .into_iter()
                .filter(|s| supported.contains(s))
                .collect(),
            _ => scopes,
        };

        let registration_endpoint = meta.registration_endpoint.as_ref().ok_or_else(|| {
            DomainError::validation(
                "authorization server does not support dynamic client registration",
            )
        })?;
        let registered = authcode::register_client(
            &http,
            registration_endpoint,
            &client_name,
            std::slice::from_ref(&redirect_uri),
            &effective_scopes,
        )
        .await
        .map_err(|e| DomainError::internal(format!("dynamic client registration failed: {e}")))?;

        let pkce = authcode::Pkce::generate();
        let state = authcode::generate_state();

        let url = authcode::build_authorize_url(
            &meta.authorization_endpoint,
            &registered.client_id,
            &redirect_uri,
            &effective_scopes,
            &state,
            &pkce.challenge,
        )
        .map_err(|e| DomainError::internal(format!("failed to build authorization URL: {e}")))?;

        let pending = PendingAuthorization {
            upstream_id,
            token_ref,
            token_endpoint: meta.token_endpoint,
            client_id: registered.client_id,
            client_secret: registered.client_secret.map(|s| s.expose().to_owned()),
            code_verifier: pkce.verifier.expose().to_owned(),
            redirect_uri,
            scopes: effective_scopes,
        };
        let json = serde_json::to_vec(&pending)
            .map_err(|e| DomainError::internal(format!("serialize pending state: {e}")))?;
        let state_ref = pending_ref(&state)?;
        self.credstore
            .put(ctx, &state_ref, SecretValue::new(json), SharingMode::Private)
            .await
            .map_err(|e| DomainError::internal(format!("credstore put error: {e}")))?;

        Ok(OAuthBeginOutcome {
            authorization_url: url.to_string(),
            state,
        })
    }

    async fn complete(
        &self,
        ctx: &SecurityContext,
        state: String,
        code: String,
    ) -> Result<(), DomainError> {
        let state_ref = pending_ref(&state)?;
        let pending = self.load_pending(ctx, &state_ref).await?;

        let http = self.http()?;
        let client_secret = pending.client_secret.as_ref().map(|s| SecretString::new(s.clone()));
        let code_verifier = SecretString::new(pending.code_verifier.clone());
        let exchange = authcode::AuthCodeExchange {
            token_endpoint: &pending.token_endpoint,
            client_id: &pending.client_id,
            client_secret: client_secret.as_ref(),
            code: &code,
            redirect_uri: &pending.redirect_uri,
            code_verifier: &code_verifier,
        };
        let tokens = authcode::exchange_code(&http, &exchange)
            .await
            .map_err(|e| DomainError::internal(format!("authorization-code exchange failed: {e}")))?;

        let record = OAuthTokenRecord {
            client_id: pending.client_id.clone(),
            client_secret: pending.client_secret.clone(),
            token_endpoint: pending.token_endpoint.clone(),
            access_token: tokens.access_token.expose().to_owned(),
            refresh_token: tokens.refresh_token.as_ref().map(|s| s.expose().to_owned()),
            expires_at_unix: now_unix() + i64::try_from(tokens.expires_in.as_secs()).unwrap_or(0),
            scope: tokens
                .scope
                .clone()
                .or_else(|| Some(pending.scopes.join(" ")).filter(|s| !s.is_empty())),
        };
        let json = serde_json::to_vec(&record)
            .map_err(|e| DomainError::internal(format!("serialize token record: {e}")))?;
        let token_ref = parse_secret_ref(&pending.token_ref)?;
        self.credstore
            .put(ctx, &token_ref, SecretValue::new(json), SharingMode::Private)
            .await
            .map_err(|e| DomainError::internal(format!("credstore put error: {e}")))?;

        // Best-effort cleanup of the pending record; failure here does not
        // invalidate the successful enrollment.
        let _ = self.credstore.delete(ctx, &state_ref).await;
        Ok(())
    }

    async fn revoke(&self, ctx: &SecurityContext, upstream_id: Uuid) -> Result<(), DomainError> {
        let (_resource, token_ref) = self.resolve_binding(ctx, upstream_id).await?;
        let token_ref = parse_secret_ref(&token_ref)?;
        self.credstore
            .delete(ctx, &token_ref)
            .await
            .map_err(|e| DomainError::internal(format!("credstore delete error: {e}")))?;
        Ok(())
    }

    async fn status(
        &self,
        ctx: &SecurityContext,
        upstream_id: Uuid,
    ) -> Result<OAuthConnectionStatus, DomainError> {
        let (_resource, token_ref) = self.resolve_binding(ctx, upstream_id).await?;
        let token_ref = parse_secret_ref(&token_ref)?;
        let resp = self
            .credstore
            .get(ctx, &token_ref)
            .await
            .map_err(|e| DomainError::internal(format!("credstore get error: {e}")))?;
        let Some(resp) = resp else {
            return Ok(OAuthConnectionStatus {
                connected: false,
                expires_at_unix: None,
            });
        };
        let record: OAuthTokenRecord = serde_json::from_slice(resp.value.as_bytes())
            .map_err(|e| DomainError::internal(format!("corrupt token record: {e}")))?;
        Ok(OAuthConnectionStatus {
            connected: true,
            expires_at_unix: Some(record.expires_at_unix),
        })
    }
}

#[cfg(test)]
#[path = "enrollment_tests.rs"]
mod enrollment_tests;
