//! Interactive per-user `OAuth2` authorization-code auth plugin.
//!
//! Unlike [`OAuth2ClientCredAuthPlugin`](super::oauth2_client_cred_auth), this
//! plugin does not mint tokens itself. Per-user tokens are provisioned
//! out-of-band by the OAGW management API (the browser authorization-code
//! flow) and stored in credstore as a JSON [`OAuthTokenRecord`] under a
//! deterministic, per-upstream `SecretRef`. credstore's `Private` sharing
//! mode scopes the record to the calling subject.
//!
//! On each request the plugin:
//! 1. Loads the caller's token record from credstore.
//! 2. Injects the bearer token when it is still valid.
//! 3. Refreshes (and persists the rotated record) when it has expired and a
//!    refresh token is present.
//! 4. Returns [`PluginError::AuthorizationRequired`] when there is no record
//!    or the refresh token was rejected, signalling that the user must
//!    (re-)authorize.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use credstore_sdk::{CredStoreClientV1, SecretRef, SecretValue, SharingMode};
use serde::{Deserialize, Serialize};
use toolkit_auth::oauth2::types::SecretString;
use tracing::warn;

use crate::domain::plugin::{AuthContext, AuthPlugin, PluginError};

/// Default safety margin: refresh once the token is within this window of
/// expiry so it does not lapse mid-request.
const DEFAULT_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// Per-user token record persisted in credstore (JSON) by the OAGW management
/// API and consumed by this plugin.
///
/// Self-contained so the plugin needs only the credstore `token_ref` in its
/// binding config; the authorization-server coordinates travel with the record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenRecord {
    /// Client identifier (from static config or dynamic registration).
    pub client_id: String,
    /// Client secret for confidential clients; absent for public/PKCE clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Authorization-server token endpoint used for refresh.
    pub token_endpoint: String,
    /// Current bearer access token.
    pub access_token: String,
    /// Refresh token, when the server issued one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Absolute access-token expiry (Unix seconds).
    pub expires_at_unix: i64,
    /// Granted scope, space-separated, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Auth plugin implementing the interactive authorization-code flow token
/// store (read + refresh).
pub struct OAuth2AuthCodeAuthPlugin {
    credstore: Arc<dyn CredStoreClientV1>,
    /// HTTP client config for refresh requests. The client is built lazily on
    /// first refresh so construction does not require a Tokio runtime.
    http_config: toolkit_http::HttpClientConfig,
    refresh_margin: Duration,
}

impl OAuth2AuthCodeAuthPlugin {
    /// Build the plugin with the default token-endpoint HTTP client config.
    #[must_use]
    pub fn new(credstore: Arc<dyn CredStoreClientV1>) -> Self {
        Self::with_http_config(credstore, toolkit_http::HttpClientConfig::token_endpoint())
    }

    /// Build the plugin with an explicit HTTP client config (test seam).
    #[must_use]
    pub fn with_http_config(
        credstore: Arc<dyn CredStoreClientV1>,
        http_config: toolkit_http::HttpClientConfig,
    ) -> Self {
        Self {
            credstore,
            http_config,
            refresh_margin: DEFAULT_REFRESH_MARGIN,
        }
    }

    fn parse_config(ctx: &AuthContext) -> Result<(SecretRef, String), PluginError> {
        let token_ref = ctx
            .config
            .get("token_ref")
            .ok_or_else(|| PluginError::InvalidConfig("missing token_ref".into()))?;
        let raw = token_ref.strip_prefix("cred://").unwrap_or(token_ref);
        let secret_ref = SecretRef::new(raw)
            .map_err(|e| PluginError::InvalidConfig(format!("invalid token_ref '{raw}': {e}")))?;
        let resource = ctx.config.get("resource").cloned().unwrap_or_default();
        Ok((secret_ref, resource))
    }

    async fn load_record(
        &self,
        ctx: &AuthContext,
        secret_ref: &SecretRef,
    ) -> Result<Option<OAuthTokenRecord>, PluginError> {
        let resp = self
            .credstore
            .get(&ctx.security_context, secret_ref)
            .await
            .map_err(|e| PluginError::Internal(format!("credstore error: {e}")))?;
        let Some(resp) = resp else {
            return Ok(None);
        };
        let record: OAuthTokenRecord = serde_json::from_slice(resp.value.as_bytes())
            .map_err(|e| PluginError::Internal(format!("corrupt token record: {e}")))?;
        Ok(Some(record))
    }

    async fn persist(
        &self,
        ctx: &AuthContext,
        secret_ref: &SecretRef,
        record: &OAuthTokenRecord,
    ) -> Result<(), PluginError> {
        let json = serde_json::to_vec(record)
            .map_err(|e| PluginError::Internal(format!("serialize token record: {e}")))?;
        self.credstore
            .put(
                &ctx.security_context,
                secret_ref,
                SecretValue::new(json),
                SharingMode::Private,
            )
            .await
            .map_err(|e| PluginError::Internal(format!("credstore put error: {e}")))
    }

    async fn refresh(
        &self,
        record: &OAuthTokenRecord,
    ) -> Result<toolkit_auth::oauth2::TokenSet, PluginError> {
        let refresh = record.refresh_token.as_ref().ok_or_else(|| {
            PluginError::AuthorizationRequired("no refresh token available".to_owned())
        })?;
        let client_secret = record.client_secret.as_ref().map(|s| SecretString::new(s.clone()));
        let refresh_ss = SecretString::new(refresh.clone());
        let scopes: Vec<String> = record
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default();

        let http = toolkit_http::HttpClientBuilder::with_config(self.http_config.clone())
            .build()
            .map_err(|e| PluginError::Internal(format!("failed to build HTTP client: {e}")))?;

        toolkit_auth::oauth2::refresh_token(
            &http,
            &record.token_endpoint,
            &record.client_id,
            client_secret.as_ref(),
            &refresh_ss,
            &scopes,
        )
        .await
        .map_err(|e| match e {
            toolkit_auth::oauth2::TokenError::RefreshRejected(_) => {
                PluginError::AuthorizationRequired("refresh token rejected".to_owned())
            }
            other => PluginError::Internal(format!("token refresh failed: {other}")),
        })
    }
}

fn inject_bearer(ctx: &mut AuthContext, token: &str) {
    ctx.headers
        .insert("authorization".into(), format!("Bearer {token}"));
}

#[async_trait::async_trait]
impl AuthPlugin for OAuth2AuthCodeAuthPlugin {
    async fn authenticate(&self, ctx: &mut AuthContext) -> Result<(), PluginError> {
        let (secret_ref, resource) = Self::parse_config(ctx)?;

        let subject = ctx.security_context.subject_id();
        let tenant = ctx.security_context.subject_tenant_id();
        let record = match self.load_record(ctx, &secret_ref).await? {
            Some(r) => r,
            None => {
                warn!(
                    %subject,
                    %tenant,
                    token_ref = ?secret_ref,
                    %resource,
                    "MCP-INVESTIGATE: auth-code plugin found NO token record -> AuthorizationRequired"
                );
                return Err(PluginError::AuthorizationRequired(resource));
            }
        };

        let margin = i64::try_from(self.refresh_margin.as_secs()).unwrap_or(60);
        if record.expires_at_unix > now_unix() + margin {
            warn!(
                %subject,
                %tenant,
                token_ref = ?secret_ref,
                expires_at_unix = record.expires_at_unix,
                "MCP-INVESTIGATE: auth-code plugin injecting valid bearer token"
            );
            inject_bearer(ctx, &record.access_token);
            return Ok(());
        }

        warn!(
            %subject,
            %tenant,
            token_ref = ?secret_ref,
            expires_at_unix = record.expires_at_unix,
            now_unix = now_unix(),
            has_refresh_token = record.refresh_token.is_some(),
            "MCP-INVESTIGATE: auth-code plugin token expired/near-expiry -> attempting refresh"
        );

        // Expired (or near-expiry): attempt a refresh.
        match self.refresh(&record).await {
            Ok(tokens) => {
                let refreshed = OAuthTokenRecord {
                    client_id: record.client_id.clone(),
                    client_secret: record.client_secret.clone(),
                    token_endpoint: record.token_endpoint.clone(),
                    access_token: tokens.access_token.expose().to_owned(),
                    refresh_token: tokens
                        .refresh_token
                        .as_ref()
                        .map(|s| s.expose().to_owned())
                        .or_else(|| record.refresh_token.clone()),
                    expires_at_unix: now_unix()
                        + i64::try_from(tokens.expires_in.as_secs()).unwrap_or(0),
                    scope: tokens.scope.clone().or_else(|| record.scope.clone()),
                };
                self.persist(ctx, &secret_ref, &refreshed).await?;
                warn!(
                    %subject,
                    %tenant,
                    token_ref = ?secret_ref,
                    expires_at_unix = refreshed.expires_at_unix,
                    "MCP-INVESTIGATE: auth-code plugin refreshed and persisted token"
                );
                inject_bearer(ctx, &refreshed.access_token);
                Ok(())
            }
            Err(PluginError::AuthorizationRequired(_)) => {
                // Refresh rejected or unavailable: drop the stale record and
                // require the user to re-authorize.
                warn!(
                    %subject,
                    %tenant,
                    token_ref = ?secret_ref,
                    "MCP-INVESTIGATE: auth-code plugin DELETING token record (refresh rejected/unavailable) -> server will report NOT connected until re-auth"
                );
                let _ = self
                    .credstore
                    .delete(&ctx.security_context, &secret_ref)
                    .await;
                Err(PluginError::AuthorizationRequired(resource))
            }
            Err(other) => {
                warn!(
                    %subject,
                    %tenant,
                    token_ref = ?secret_ref,
                    error = %other,
                    "MCP-INVESTIGATE: auth-code plugin refresh failed (non-auth error, token retained)"
                );
                Err(other)
            }
        }
    }
}

#[cfg(test)]
#[path = "oauth2_auth_code_auth_tests.rs"]
mod oauth2_auth_code_auth_tests;
