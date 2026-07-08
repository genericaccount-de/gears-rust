//! DTOs for the interactive per-user OAuth authorization-code management API.
//!
//! These drive the out-of-band browser enrollment flow for upstreams whose
//! auth plugin is `oauth2_auth_code`: the consumer (e.g. mini-chat) begins an
//! authorization, redirects the user to the returned URL, and completes the
//! flow on the OAuth callback. OAGW owns dynamic client registration, PKCE,
//! and the per-user token store (credstore); no secrets cross this boundary.

use uuid::Uuid;

/// Begin an interactive authorization for `upstream_id` on behalf of the
/// calling user.
#[derive(Debug, Clone)]
pub struct BeginOAuthAuthorizationRequest {
    /// The upstream to authorize against (must use the `oauth2_auth_code` auth
    /// plugin).
    pub upstream_id: Uuid,
    /// Additional scopes to request (intersected with what the authorization
    /// server advertises).
    pub scopes: Vec<String>,
    /// Absolute redirect URI the authorization server will call back; must be
    /// registered and matched on completion.
    pub redirect_uri: String,
    /// Human-readable client name used for dynamic client registration.
    pub client_name: String,
}

/// Result of [`begin_oauth_authorization`](crate::ServiceGatewayClientV1::begin_oauth_authorization).
#[derive(Debug, Clone)]
pub struct BeginOAuthAuthorizationResponse {
    /// The URL to open in the user's browser to obtain consent.
    pub authorization_url: String,
    /// Opaque CSRF state; echoed back on the callback and required by
    /// [`complete_oauth_authorization`](crate::ServiceGatewayClientV1::complete_oauth_authorization).
    pub state: String,
}

/// Complete an authorization after the browser callback.
#[derive(Debug, Clone)]
pub struct CompleteOAuthAuthorizationRequest {
    /// The `state` returned by `begin_oauth_authorization`.
    pub state: String,
    /// The authorization `code` delivered to the redirect URI.
    pub code: String,
}

/// Per-user connection status for an upstream's OAuth authorization.
#[derive(Debug, Clone)]
pub struct OAuthConnectionStatus {
    /// `true` if a usable (unexpired or refreshable) token is stored.
    pub connected: bool,
    /// Access-token expiry (Unix seconds), when connected.
    pub expires_at_unix: Option<i64>,
}
