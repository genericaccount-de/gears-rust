use axum::Router;
use toolkit::api::OpenApiRegistry;
use toolkit::api::operation_builder::OperationBuilder;

use super::super::dto;
use super::super::handlers;
use super::License;

const API_TAG: &str = "OAGW OAuth";

pub(super) fn register(
    mut router: Router,
    openapi: &dyn OpenApiRegistry,
    writable: bool,
) -> Router {
    // GET /oagw/v1/upstreams/{id}/oauth — Connection status (read-only)
    router = OperationBuilder::get("/oagw/v1/upstreams/{id}/oauth")
        .operation_id("oagw.oauth_connection_status")
        .summary("Get OAuth connection status")
        .description("Report whether the caller has a usable OAuth authorization for an upstream")
        .tag(API_TAG)
        .path_param("id", "Upstream GTS identifier")
        .authenticated()
        .require_license_features::<License>([])
        .handler(handlers::oauth::connection_status)
        .json_response_with_schema::<dto::OAuthConnectionStatusResponse>(
            openapi,
            http::StatusCode::OK,
            "OAuth connection status",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    if writable {
        // POST /oagw/v1/upstreams/{id}/oauth/authorize — Begin authorization
        router = OperationBuilder::post("/oagw/v1/upstreams/{id}/oauth/authorize")
            .operation_id("oagw.begin_oauth_authorization")
            .summary("Begin OAuth authorization")
            .description(
                "Start an interactive authorization-code flow and return the browser URL + state",
            )
            .tag(API_TAG)
            .path_param("id", "Upstream GTS identifier")
            .authenticated()
            .require_license_features::<License>([])
            .json_request::<dto::BeginOAuthRequest>(openapi, "Authorization parameters")
            .handler(handlers::oauth::begin_authorization)
            .json_response_with_schema::<dto::BeginOAuthResponse>(
                openapi,
                http::StatusCode::OK,
                "Authorization URL and state",
            )
            .standard_errors(openapi)
            .register(router, openapi);

        // POST /oagw/v1/oauth/complete — Complete authorization
        router = OperationBuilder::post("/oagw/v1/oauth/complete")
            .operation_id("oagw.complete_oauth_authorization")
            .summary("Complete OAuth authorization")
            .description("Exchange the authorization code and persist the per-user token")
            .tag(API_TAG)
            .authenticated()
            .require_license_features::<License>([])
            .json_request::<dto::CompleteOAuthRequest>(openapi, "State and authorization code")
            .handler(handlers::oauth::complete_authorization)
            .json_response(http::StatusCode::NO_CONTENT, "Authorization completed")
            .standard_errors(openapi)
            .register(router, openapi);

        // DELETE /oagw/v1/upstreams/{id}/oauth — Revoke authorization
        router = OperationBuilder::delete("/oagw/v1/upstreams/{id}/oauth")
            .operation_id("oagw.revoke_oauth_authorization")
            .summary("Revoke OAuth authorization")
            .description("Delete the caller's stored OAuth token for an upstream")
            .tag(API_TAG)
            .path_param("id", "Upstream GTS identifier")
            .authenticated()
            .require_license_features::<License>([])
            .handler(handlers::oauth::revoke_authorization)
            .json_response(http::StatusCode::NO_CONTENT, "Authorization revoked")
            .standard_errors(openapi)
            .register(router, openapi);
    }

    router
}
