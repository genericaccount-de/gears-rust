use axum::Router;
use toolkit::api::OpenApiRegistry;
use toolkit::api::operation_builder::OperationBuilder;

use super::AiChatLicense;
use crate::api::rest::{dto, handlers};

const API_TAG: &str = "Mini Chat MCP";

pub(super) fn register_mcp_routes(
    mut router: Router,
    openapi: &dyn OpenApiRegistry,
    prefix: &str,
) -> Router {
    // GET {prefix}/v1/mcp-servers
    router = OperationBuilder::get(format!("{prefix}/v1/mcp-servers"))
        .operation_id("mini_chat.list_mcp_servers")
        .summary("List MCP servers available to the tenant")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .handler(handlers::mcp::list_servers)
        .json_response_with_schema::<dto::McpServerListDto>(
            openapi,
            http::StatusCode::OK,
            "List of MCP servers",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    // GET {prefix}/v1/mcp-servers/{id}
    router = OperationBuilder::get(format!("{prefix}/v1/mcp-servers/{{id}}"))
        .operation_id("mini_chat.get_mcp_server")
        .summary("Get MCP server details")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("id", "MCP server UUID")
        .handler(handlers::mcp::get_server)
        .json_response_with_schema::<dto::McpServerInfo>(
            openapi,
            http::StatusCode::OK,
            "MCP server details",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    // GET {prefix}/v1/mcp-servers/{id}/tools
    router = OperationBuilder::get(format!("{prefix}/v1/mcp-servers/{{id}}/tools"))
        .operation_id("mini_chat.list_mcp_tools")
        .summary("List tools exposed by an MCP server (cached metadata)")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("id", "MCP server UUID")
        .handler(handlers::mcp::list_tools)
        .json_response_with_schema::<dto::McpToolListDto>(
            openapi,
            http::StatusCode::OK,
            "List of MCP tools",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    // POST {prefix}/v1/mcp-servers/{id}/tools:refresh
    router = OperationBuilder::post(format!("{prefix}/v1/mcp-servers/{{id}}/tools:refresh"))
        .operation_id("mini_chat.refresh_mcp_tools")
        .summary("Refresh tool metadata from an MCP server (admin/operator)")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("id", "MCP server UUID")
        .handler(handlers::mcp::refresh_tools)
        .json_response_with_schema::<dto::McpToolListDto>(
            openapi,
            http::StatusCode::OK,
            "Refreshed list of MCP tools",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    // POST {prefix}/v1/admin/mcp-servers/{id}/approve
    router = OperationBuilder::post(format!("{prefix}/v1/admin/mcp-servers/{{id}}/approve"))
        .operation_id("mini_chat.approve_mcp_server")
        .summary("Approve a hub-discovered MCP server (admin-only)")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("id", "MCP server UUID")
        .handler(handlers::mcp::approve_server)
        .json_response_with_schema::<dto::McpServerInfo>(
            openapi,
            http::StatusCode::OK,
            "Approved MCP server",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    // POST {prefix}/v1/admin/roles/{role}/mcp-servers
    router = OperationBuilder::post(format!("{prefix}/v1/admin/roles/{{role}}/mcp-servers"))
        .operation_id("mini_chat.assign_mcp_server_to_role")
        .summary("Assign an MCP server to a role (admin-only)")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("role", "Role name")
        .json_request::<dto::AssignMcpServerToRoleReq>(openapi, "Server to assign")
        .handler(handlers::mcp::assign_server)
        .json_response_with_schema::<dto::RoleMcpServerInfo>(
            openapi,
            http::StatusCode::OK,
            "Role-server grant",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    // DELETE {prefix}/v1/admin/roles/{role}/mcp-servers/{sid}
    router = OperationBuilder::delete(format!(
        "{prefix}/v1/admin/roles/{{role}}/mcp-servers/{{sid}}"
    ))
    .operation_id("mini_chat.revoke_mcp_server_from_role")
    .summary("Revoke an MCP server from a role (admin-only)")
    .tag(API_TAG)
    .authenticated()
    .require_license_features([&AiChatLicense])
    .path_param("role", "Role name")
    .path_param("sid", "MCP server UUID")
    .handler(handlers::mcp::revoke_server)
    .json_response(http::StatusCode::NO_CONTENT, "Server revoked from role")
    .standard_errors(openapi)
    .register(router, openapi);

    // GET {prefix}/v1/admin/roles/{role}/mcp-servers
    router = OperationBuilder::get(format!("{prefix}/v1/admin/roles/{{role}}/mcp-servers"))
        .operation_id("mini_chat.list_role_mcp_servers")
        .summary("List MCP servers assigned to a role (admin-only)")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("role", "Role name")
        .handler(handlers::mcp::list_role_servers)
        .json_response_with_schema::<dto::RoleMcpServerListDto>(
            openapi,
            http::StatusCode::OK,
            "List of role-server grants",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    // POST {prefix}/v1/mcp-servers/{id}/connection:authorize
    router = OperationBuilder::post(format!(
        "{prefix}/v1/mcp-servers/{{id}}/connection:authorize"
    ))
    .operation_id("mini_chat.begin_mcp_connection")
    .summary("Begin an interactive OAuth connection to an MCP server")
    .tag(API_TAG)
    .authenticated()
    .require_license_features([&AiChatLicense])
    .path_param("id", "MCP server UUID")
    .json_request::<dto::BeginMcpConnectionReq>(openapi, "Redirect URI for the callback")
    .handler(handlers::mcp::begin_connection)
    .json_response_with_schema::<dto::BeginMcpConnectionResp>(
        openapi,
        http::StatusCode::OK,
        "Authorization URL and CSRF state",
    )
    .standard_errors(openapi)
    .register(router, openapi);

    // POST {prefix}/v1/mcp-connections:complete
    router = OperationBuilder::post(format!("{prefix}/v1/mcp-connections:complete"))
        .operation_id("mini_chat.complete_mcp_connection")
        .summary("Complete an interactive OAuth connection after the browser callback")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .json_request::<dto::CompleteMcpConnectionReq>(openapi, "State and authorization code")
        .handler(handlers::mcp::complete_connection)
        .json_response(http::StatusCode::NO_CONTENT, "Connection completed")
        .standard_errors(openapi)
        .register(router, openapi);

    // GET {prefix}/v1/mcp-servers/{id}/connection
    router = OperationBuilder::get(format!("{prefix}/v1/mcp-servers/{{id}}/connection"))
        .operation_id("mini_chat.mcp_connection_status")
        .summary("Get the caller's OAuth connection status for an MCP server")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("id", "MCP server UUID")
        .handler(handlers::mcp::connection_status)
        .json_response_with_schema::<dto::McpConnectionStatusDto>(
            openapi,
            http::StatusCode::OK,
            "Connection status",
        )
        .standard_errors(openapi)
        .register(router, openapi);

    // DELETE {prefix}/v1/mcp-servers/{id}/connection
    router = OperationBuilder::delete(format!("{prefix}/v1/mcp-servers/{{id}}/connection"))
        .operation_id("mini_chat.revoke_mcp_connection")
        .summary("Revoke the caller's OAuth connection to an MCP server")
        .tag(API_TAG)
        .authenticated()
        .require_license_features([&AiChatLicense])
        .path_param("id", "MCP server UUID")
        .handler(handlers::mcp::revoke_connection)
        .json_response(http::StatusCode::NO_CONTENT, "Connection revoked")
        .standard_errors(openapi)
        .register(router, openapi);

    router
}
