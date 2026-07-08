//! REST handlers for the interactive per-user OAuth authorization-code flow.
//!
//! These endpoints drive the out-of-band browser enrollment for upstreams
//! whose auth plugin is `oauth2_auth_code`. They delegate to the domain
//! [`OAuthEnrollmentService`](crate::domain::services::OAuthEnrollmentService)
//! exposed on [`AppState`].

use axum::Json;
use axum::extract::{Extension, Path};
use axum::response::IntoResponse;
use http::StatusCode;
use toolkit_canonical_errors::Problem;
use toolkit_security::SecurityContext;

use crate::api::rest::dto::{
    BeginOAuthRequest, BeginOAuthResponse, CompleteOAuthRequest, OAuthConnectionStatusResponse,
};
use crate::api::rest::error::domain_error_to_problem;
use crate::api::rest::extractors::parse_gts_id;
use crate::domain::gts_helpers as gts;
use crate::gear::AppState;

/// POST /oagw/v1/upstreams/{id}/oauth/authorize
pub async fn begin_authorization(
    Extension(state): Extension<AppState>,
    Extension(ctx): Extension<SecurityContext>,
    Path(id): Path<String>,
    Json(req): Json<BeginOAuthRequest>,
) -> Result<impl IntoResponse, Problem> {
    let instance = format!("/oagw/v1/upstreams/{id}/oauth/authorize");
    let uuid = parse_gts_id(&id, gts::UPSTREAM_SCHEMA, &instance)?;
    let outcome = state
        .oauth
        .begin(&ctx, uuid, req.scopes, req.redirect_uri, req.client_name)
        .await
        .map_err(|e| domain_error_to_problem(e, &instance))?;
    Ok(Json(BeginOAuthResponse {
        authorization_url: outcome.authorization_url,
        state: outcome.state,
    }))
}

/// POST /oagw/v1/oauth/complete
pub async fn complete_authorization(
    Extension(state): Extension<AppState>,
    Extension(ctx): Extension<SecurityContext>,
    Json(req): Json<CompleteOAuthRequest>,
) -> Result<impl IntoResponse, Problem> {
    let instance = "/oagw/v1/oauth/complete";
    state
        .oauth
        .complete(&ctx, req.state, req.code)
        .await
        .map_err(|e| domain_error_to_problem(e, instance))?;
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /oagw/v1/upstreams/{id}/oauth
pub async fn revoke_authorization(
    Extension(state): Extension<AppState>,
    Extension(ctx): Extension<SecurityContext>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    let instance = format!("/oagw/v1/upstreams/{id}/oauth");
    let uuid = parse_gts_id(&id, gts::UPSTREAM_SCHEMA, &instance)?;
    state
        .oauth
        .revoke(&ctx, uuid)
        .await
        .map_err(|e| domain_error_to_problem(e, &instance))?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /oagw/v1/upstreams/{id}/oauth
pub async fn connection_status(
    Extension(state): Extension<AppState>,
    Extension(ctx): Extension<SecurityContext>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    let instance = format!("/oagw/v1/upstreams/{id}/oauth");
    let uuid = parse_gts_id(&id, gts::UPSTREAM_SCHEMA, &instance)?;
    let status = state
        .oauth
        .status(&ctx, uuid)
        .await
        .map_err(|e| domain_error_to_problem(e, &instance))?;
    Ok(Json(OAuthConnectionStatusResponse {
        connected: status.connected,
        expires_at_unix: status.expires_at_unix,
    }))
}
