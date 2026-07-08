//! REST handlers for MCP server discovery, tool metadata, and admin role
//! grants. All authorization is enforced in `McpService` via the PEP; handlers
//! only translate between DTOs and service inputs.

use std::sync::Arc;

use axum::Extension;
use axum::extract::Path;
use toolkit::api::canonical_prelude::*;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use crate::api::rest::dto::{
    AssignMcpServerToRoleReq, BeginMcpConnectionReq, BeginMcpConnectionResp,
    CompleteMcpConnectionReq, McpConnectionStatusDto, McpServerInfo, McpServerListDto, McpToolInfo,
    McpToolListDto, RoleMcpServerInfo, RoleMcpServerListDto,
};
use crate::domain::service::AssignServerToRoleInput;
use crate::gear::AppServices;

/// GET /mini-chat/v1/mcp-servers
#[tracing::instrument(skip(svc, ctx))]
pub(crate) async fn list_servers(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
) -> ApiResult<JsonBody<McpServerListDto>> {
    let servers = svc.mcp.list_servers(&ctx).await?;
    let items = servers.into_iter().map(McpServerInfo::from).collect();
    Ok(Json(McpServerListDto { items }))
}

/// GET /mini-chat/v1/mcp-servers/{id}
#[tracing::instrument(skip(svc, ctx), fields(server_id = %id))]
pub(crate) async fn get_server(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path(id): Path<Uuid>,
) -> ApiResult<JsonBody<McpServerInfo>> {
    let server = svc.mcp.get_server(&ctx, id).await?;
    Ok(Json(McpServerInfo::from(server)))
}

/// GET /mini-chat/v1/mcp-servers/{id}/tools
#[tracing::instrument(skip(svc, ctx), fields(server_id = %id))]
pub(crate) async fn list_tools(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path(id): Path<Uuid>,
) -> ApiResult<JsonBody<McpToolListDto>> {
    let tools = svc.mcp.list_tools(&ctx, id).await?;
    let items = tools.into_iter().map(McpToolInfo::from).collect();
    Ok(Json(McpToolListDto { items }))
}

/// POST /mini-chat/v1/mcp-servers/{id}/tools:refresh
#[tracing::instrument(skip(svc, ctx), fields(server_id = %id))]
pub(crate) async fn refresh_tools(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path(id): Path<Uuid>,
) -> ApiResult<JsonBody<McpToolListDto>> {
    let tools = svc.mcp.refresh_tools(&ctx, id).await?;
    let items = tools.into_iter().map(McpToolInfo::from).collect();
    Ok(Json(McpToolListDto { items }))
}

/// POST /mini-chat/v1/admin/mcp-servers/{id}/approve
#[tracing::instrument(skip(svc, ctx), fields(server_id = %id))]
pub(crate) async fn approve_server(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path(id): Path<Uuid>,
) -> ApiResult<JsonBody<McpServerInfo>> {
    let server = svc.mcp.approve_server(&ctx, id).await?;
    Ok(Json(McpServerInfo::from(server)))
}

/// POST /mini-chat/v1/admin/roles/{role}/mcp-servers
#[tracing::instrument(skip(svc, ctx, req_body), fields(role = %role))]
pub(crate) async fn assign_server(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path(role): Path<String>,
    Json(req_body): Json<AssignMcpServerToRoleReq>,
) -> ApiResult<JsonBody<RoleMcpServerInfo>> {
    let input = AssignServerToRoleInput {
        server_id: req_body.server_id,
        enabled: req_body.enabled.unwrap_or(true),
        allowed_tools: req_body.allowed_tools,
        denied_tools: req_body.denied_tools,
        priority: req_body.priority,
    };
    let attachment = svc.mcp.assign_server_to_role(&ctx, &role, input).await?;
    Ok(Json(RoleMcpServerInfo::from(attachment)))
}

/// DELETE /mini-chat/v1/admin/roles/{role}/mcp-servers/{sid}
///
/// Idempotent: returns `204 No Content` whether or not an attachment existed.
#[tracing::instrument(skip(svc, ctx), fields(role = %role, server_id = %sid))]
pub(crate) async fn revoke_server(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path((role, sid)): Path<(String, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    svc.mcp.revoke_server_from_role(&ctx, &role, sid).await?;
    Ok(no_content().into_response())
}

/// GET /mini-chat/v1/admin/roles/{role}/mcp-servers
#[tracing::instrument(skip(svc, ctx), fields(role = %role))]
pub(crate) async fn list_role_servers(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path(role): Path<String>,
) -> ApiResult<JsonBody<RoleMcpServerListDto>> {
    let grants = svc.mcp.list_role_servers(&ctx, &role).await?;
    let items = grants.into_iter().map(RoleMcpServerInfo::from).collect();
    Ok(Json(RoleMcpServerListDto { items }))
}

/// POST /mini-chat/v1/mcp-servers/{id}/connection:authorize
#[tracing::instrument(skip(svc, ctx, req_body), fields(server_id = %id))]
pub(crate) async fn begin_connection(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path(id): Path<Uuid>,
    Json(req_body): Json<BeginMcpConnectionReq>,
) -> ApiResult<JsonBody<BeginMcpConnectionResp>> {
    let begin = svc
        .mcp
        .begin_oauth_connection(&ctx, id, req_body.redirect_uri)
        .await?;
    Ok(Json(BeginMcpConnectionResp {
        authorization_url: begin.authorization_url,
        state: begin.state,
    }))
}

/// POST /mini-chat/v1/mcp-connections:complete
#[tracing::instrument(skip(svc, ctx, req_body))]
pub(crate) async fn complete_connection(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Json(req_body): Json<CompleteMcpConnectionReq>,
) -> ApiResult<impl IntoResponse> {
    svc.mcp
        .complete_oauth_connection(&ctx, req_body.state, req_body.code)
        .await?;
    Ok(no_content().into_response())
}

/// DELETE /mini-chat/v1/mcp-servers/{id}/connection
#[tracing::instrument(skip(svc, ctx), fields(server_id = %id))]
pub(crate) async fn revoke_connection(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    svc.mcp.revoke_oauth_connection(&ctx, id).await?;
    Ok(no_content().into_response())
}

/// GET /mini-chat/v1/mcp-servers/{id}/connection
#[tracing::instrument(skip(svc, ctx), fields(server_id = %id))]
pub(crate) async fn connection_status(
    Extension(ctx): Extension<SecurityContext>,
    Extension(svc): Extension<Arc<AppServices>>,
    Path(id): Path<Uuid>,
) -> ApiResult<JsonBody<McpConnectionStatusDto>> {
    let status = svc.mcp.oauth_connection_status(&ctx, id).await?;
    Ok(Json(McpConnectionStatusDto {
        connected: status.connected,
        expires_at_unix: status.expires_at_unix,
    }))
}
