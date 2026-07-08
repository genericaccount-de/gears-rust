//! HTTP DTOs (serde/utoipa) — REST-only request and response types.
//!
//! All REST DTOs live here; SDK `models.rs` stays transport-agnostic.
//! Provide `From` conversions between SDK models and DTOs in this file.
//!
//! Stream event types live in `domain::stream_events`; SSE wire conversion
//! and ordering enforcement live in `api::rest::sse`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::domain::models::{AttachmentSummary, ChatDetail, ImgThumbnail};
use crate::infra::db::entity::attachment::Model as AttachmentModel;
use crate::infra::db::entity::mcp_server::{
    McpAuthKind, McpHealthStatus, McpSource, McpTrustLevel, Model as McpServerModel,
};
use crate::infra::db::entity::mcp_server_tool::Model as McpToolModel;
use crate::infra::db::entity::role_mcp_server::Model as RoleMcpServerModel;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

// ════════════════════════════════════════════════════════════════════════════
// Chat CRUD DTOs
// ════════════════════════════════════════════════════════════════════════════

/// Request DTO for creating a new chat.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct CreateChatReq {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Request DTO for updating a chat title.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct UpdateChatReq {
    pub title: String,
}

/// Response DTO for chat details.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct ChatDetailDto {
    pub id: Uuid,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub is_temporary: bool,
    pub message_count: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<ChatDetail> for ChatDetailDto {
    fn from(d: ChatDetail) -> Self {
        Self {
            id: d.id,
            model: d.model,
            title: d.title,
            is_temporary: d.is_temporary,
            message_count: d.message_count,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Message DTOs
// ════════════════════════════════════════════════════════════════════════════

/// Response DTO for a message in the list endpoint.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct MessageDto {
    pub id: Uuid,
    pub request_id: Uuid,
    pub role: String,
    pub content: String,
    pub attachments: Vec<AttachmentSummaryDto>,
    pub my_reaction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<i64>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<crate::domain::models::Message> for MessageDto {
    fn from(m: crate::domain::models::Message) -> Self {
        Self {
            id: m.id,
            request_id: m.request_id,
            role: m.role,
            content: m.content,
            attachments: m
                .attachments
                .into_iter()
                .map(AttachmentSummaryDto::from)
                .collect(),
            my_reaction: m.my_reaction.map(|r| r.as_str().to_owned()),
            model: m.model,
            input_tokens: m.input_tokens,
            output_tokens: m.output_tokens,
            created_at: m.created_at,
        }
    }
}

/// Lightweight attachment metadata embedded in Message responses.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct AttachmentSummaryDto {
    pub attachment_id: Uuid,
    pub kind: String,
    pub filename: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub img_thumbnail: Option<ImgThumbnailDto>,
}

impl From<AttachmentSummary> for AttachmentSummaryDto {
    fn from(a: AttachmentSummary) -> Self {
        Self {
            attachment_id: a.attachment_id,
            kind: a.kind,
            filename: a.filename,
            status: a.status,
            img_thumbnail: a.img_thumbnail.map(ImgThumbnailDto::from),
        }
    }
}

/// Server-generated preview thumbnail for an image attachment.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct ImgThumbnailDto {
    pub content_type: String,
    pub width: i32,
    pub height: i32,
    pub data_base64: String,
}

impl From<ImgThumbnail> for ImgThumbnailDto {
    fn from(t: ImgThumbnail) -> Self {
        Self {
            content_type: t.content_type,
            width: t.width,
            height: t.height,
            data_base64: t.data_base64,
        }
    }
}

/// Full attachment details returned by the GET attachment endpoint.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct AttachmentDetailDto {
    pub id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub status: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub img_thumbnail: Option<ImgThumbnailDto>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub summary_updated_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<AttachmentModel> for AttachmentDetailDto {
    fn from(m: AttachmentModel) -> Self {
        let img_thumbnail = m
            .img_thumbnail
            .zip(m.img_thumbnail_width)
            .zip(m.img_thumbnail_height)
            .map(|((bytes, w), h)| ImgThumbnailDto {
                content_type: "image/webp".to_owned(),
                width: w,
                height: h,
                data_base64: BASE64.encode(&bytes),
            });

        Self {
            id: m.id,
            filename: m.filename,
            content_type: m.content_type,
            size_bytes: m.size_bytes,
            status: m.status.to_string(),
            kind: m.attachment_kind.to_string(),
            error_code: m.error_code,
            doc_summary: m.doc_summary,
            img_thumbnail,
            summary_updated_at: m.summary_updated_at,
            created_at: m.created_at,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Reaction DTOs
// ════════════════════════════════════════════════════════════════════════════

/// Request DTO for setting a reaction.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct SetReactionReq {
    pub reaction: String,
}

/// Response DTO for a reaction.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct ReactionDto {
    pub message_id: Uuid,
    pub reaction: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<crate::domain::models::Reaction> for ReactionDto {
    fn from(r: crate::domain::models::Reaction) -> Self {
        Self {
            message_id: r.message_id,
            reaction: r.kind.as_str().to_owned(),
            created_at: r.created_at,
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Model DTOs
// ════════════════════════════════════════════════════════════════════════════

/// Response DTO for a single model.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct ModelDto {
    pub model_id: String,
    pub display_name: String,
    pub tier: String,
    pub multiplier_display: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub multimodal_capabilities: Vec<String>,
    pub context_window: u32,
}

impl From<crate::domain::models::ResolvedModel> for ModelDto {
    fn from(m: crate::domain::models::ResolvedModel) -> Self {
        Self {
            model_id: m.model_id,
            display_name: m.display_name,
            tier: m.tier,
            multiplier_display: m.multiplier_display,
            description: m.description,
            multimodal_capabilities: m.multimodal_capabilities,
            context_window: m.context_window,
        }
    }
}

/// Response DTO for the model list endpoint.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct ModelListDto {
    pub items: Vec<ModelDto>,
}

// ════════════════════════════════════════════════════════════════════════════
// Streaming request DTOs
// ════════════════════════════════════════════════════════════════════════════

/// Request body for `POST /v1/chats/{id}/messages:stream`.
#[derive(Debug, Clone, serde::Deserialize, ToSchema)]
pub struct StreamMessageRequest {
    /// Message content (must be non-empty).
    pub content: String,
    /// Client-generated idempotency key (UUID v4). Optional in P1.
    #[serde(default)]
    pub request_id: Option<uuid::Uuid>,
    /// Attachment IDs to include.
    #[serde(default)]
    pub attachment_ids: Vec<uuid::Uuid>,
    /// Web search configuration.
    #[serde(default)]
    pub web_search: Option<WebSearchConfig>,
}

impl toolkit::api::api_dto::RequestApiDto for StreamMessageRequest {}

/// Web search toggle.
#[derive(Debug, Clone, serde::Deserialize, ToSchema)]
pub struct WebSearchConfig {
    pub enabled: bool,
}

// ════════════════════════════════════════════════════════════════════════════
// MCP DTOs
// ════════════════════════════════════════════════════════════════════════════

/// User-facing MCP server metadata. Deliberately omits `url`, auth
/// configuration, and internal provisioning IDs (`oagw_upstream_id`).
// Independent status flags mirroring the server row; grouping them into an enum
// would obscure the wire contract.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct McpServerInfo {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub auto_attach: bool,
    pub priority: i32,
    pub source: String,
    pub trust_level: String,
    pub health_status: String,
    /// `true` when the server uses the interactive per-user OAuth
    /// authorization-code flow (`auth_kind = oauth2_auth_code`). Such servers'
    /// tools stay hidden for a user until they complete a connection via the
    /// `connection:authorize` / `mcp-connections:complete` endpoints. Clients
    /// use this flag to decide whether to surface a "Connect" affordance and
    /// query per-user status via `GET /v1/mcp-servers/{id}/connection`.
    pub requires_user_connection: bool,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub last_refreshed_at: Option<OffsetDateTime>,
}

impl From<McpServerModel> for McpServerInfo {
    fn from(m: McpServerModel) -> Self {
        Self {
            id: m.id,
            name: m.name,
            description: m.description,
            enabled: m.enabled,
            auto_attach: m.auto_attach,
            priority: m.priority,
            source: mcp_source_str(m.source).to_owned(),
            trust_level: mcp_trust_str(m.trust_level).to_owned(),
            health_status: mcp_health_str(m.health_status).to_owned(),
            requires_user_connection: m.auth_kind == McpAuthKind::OAuth2AuthCode,
            last_refreshed_at: m.last_refreshed_at,
        }
    }
}

/// Response DTO for the server list endpoint.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct McpServerListDto {
    pub items: Vec<McpServerInfo>,
}

/// Persisted MCP tool metadata exposed by a server.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct McpToolInfo {
    pub original_name: String,
    pub exposed_name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub schema_hash: String,
    pub enabled: bool,
}

impl From<McpToolModel> for McpToolInfo {
    fn from(m: McpToolModel) -> Self {
        Self {
            original_name: m.original_name,
            exposed_name: m.exposed_name,
            description: m.description,
            input_schema: m.input_schema,
            schema_hash: m.schema_hash,
            enabled: m.enabled,
        }
    }
}

/// Response DTO for the tool list / refresh endpoints.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct McpToolListDto {
    pub items: Vec<McpToolInfo>,
}

/// Request DTO for assigning an MCP server to a role.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct AssignMcpServerToRoleReq {
    pub server_id: Uuid,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_tools: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
}

/// A role → MCP server grant, with optional per-role tool/priority overrides.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct RoleMcpServerInfo {
    pub role: String,
    pub server_id: Uuid,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied_tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
}

impl From<RoleMcpServerModel> for RoleMcpServerInfo {
    fn from(m: RoleMcpServerModel) -> Self {
        Self {
            role: m.role,
            server_id: m.server_id,
            enabled: m.enabled,
            allowed_tools: json_to_string_vec(m.allowed_tools),
            denied_tools: json_to_string_vec(m.denied_tools),
            priority: m.priority,
        }
    }
}

/// Response DTO for the role-server list endpoint.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct RoleMcpServerListDto {
    pub items: Vec<RoleMcpServerInfo>,
}

/// Request DTO to begin an interactive OAuth connection to an MCP server.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct BeginMcpConnectionReq {
    /// Absolute redirect URI the authorization server calls back after consent.
    /// Must be registered and matched on completion.
    pub redirect_uri: String,
}

/// Response DTO carrying the browser authorization URL and CSRF state.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct BeginMcpConnectionResp {
    /// URL to open in the user's browser to grant consent.
    pub authorization_url: String,
    /// Opaque CSRF state; echoed back to the completion endpoint.
    pub state: String,
}

/// Request DTO to complete an OAuth connection after the browser callback.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct CompleteMcpConnectionReq {
    /// The `state` returned by the begin call.
    pub state: String,
    /// The authorization `code` delivered to the redirect URI.
    pub code: String,
}

/// Response DTO reporting the caller's connection status for a server.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct McpConnectionStatusDto {
    /// Whether the caller has a usable per-user token stored.
    pub connected: bool,
    /// Access-token expiry (Unix seconds), when connected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
}

const fn mcp_source_str(source: McpSource) -> &'static str {
    match source {
        McpSource::Config => "config",
        McpSource::Hub => "hub",
        McpSource::Api => "api",
    }
}

const fn mcp_trust_str(trust: McpTrustLevel) -> &'static str {
    match trust {
        McpTrustLevel::Trusted => "trusted",
        McpTrustLevel::Restricted => "restricted",
        McpTrustLevel::Untrusted => "untrusted",
    }
}

const fn mcp_health_str(status: McpHealthStatus) -> &'static str {
    match status {
        McpHealthStatus::Unknown => "unknown",
        McpHealthStatus::Healthy => "healthy",
        McpHealthStatus::Degraded => "degraded",
        McpHealthStatus::Unhealthy => "unhealthy",
    }
}

/// Parse a stored JSON array column into a `Vec<String>`, treating malformed
/// or non-array values as absent.
fn json_to_string_vec(value: Option<serde_json::Value>) -> Option<Vec<String>> {
    value.and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
}

#[cfg(test)]
mod mcp_dto_tests {
    use super::*;
    use crate::infra::db::entity::mcp_server::McpAuthKind;
    use serde_json::json;
    use time::macros::datetime;

    fn server_model() -> McpServerModel {
        McpServerModel {
            id: Uuid::nil(),
            tenant_id: None,
            source: McpSource::Config,
            external_id: "ext".to_owned(),
            name: "srv".to_owned(),
            description: "desc".to_owned(),
            url: "https://example.com".to_owned(),
            enabled: true,
            trust_level: McpTrustLevel::Restricted,
            auth_kind: McpAuthKind::None,
            auth_config: json!({}),
            oagw_upstream_id: Some("up-1".to_owned()),
            priority: 7,
            allowed_tools: None,
            denied_tools: None,
            call_timeout_secs: Some(30),
            auto_attach: true,
            health_status: McpHealthStatus::Healthy,
            last_refreshed_at: Some(datetime!(2026-05-20 12:00:00 UTC)),
            last_error: None,
            created_at: datetime!(2026-05-20 10:00:00 UTC),
            updated_at: datetime!(2026-05-20 11:00:00 UTC),
            deleted_at: None,
        }
    }

    #[test]
    fn server_model_maps_to_info_and_omits_sensitive_fields() {
        let info = McpServerInfo::from(server_model());
        assert_eq!(info.id, Uuid::nil());
        assert_eq!(info.name, "srv");
        assert_eq!(info.description, "desc");
        assert!(info.enabled);
        assert!(info.auto_attach);
        assert_eq!(info.priority, 7);
        assert_eq!(info.source, "config");
        assert_eq!(info.trust_level, "restricted");
        assert_eq!(info.health_status, "healthy");
        assert_eq!(info.last_refreshed_at, Some(datetime!(2026-05-20 12:00:00 UTC)));

        // Sensitive/internal fields must not leak into the serialized payload.
        let v = serde_json::to_value(&info).unwrap();
        assert!(v.get("url").is_none());
        assert!(v.get("auth_config").is_none());
        assert!(v.get("oagw_upstream_id").is_none());
        assert!(v.get("tenant_id").is_none());
    }

    #[test]
    fn tool_model_maps_to_info() {
        let model = McpToolModel {
            id: Uuid::nil(),
            server_id: Uuid::nil(),
            original_name: "orig".to_owned(),
            exposed_name: "srv__orig".to_owned(),
            description: "d".to_owned(),
            input_schema: json!({"type": "object"}),
            schema_hash: "hash".to_owned(),
            enabled: true,
            created_at: datetime!(2026-05-20 10:00:00 UTC),
            updated_at: datetime!(2026-05-20 11:00:00 UTC),
        };
        let info = McpToolInfo::from(model);
        assert_eq!(info.original_name, "orig");
        assert_eq!(info.exposed_name, "srv__orig");
        assert_eq!(info.input_schema, json!({"type": "object"}));
        assert_eq!(info.schema_hash, "hash");
        assert!(info.enabled);
    }

    #[test]
    fn role_server_model_parses_tool_json_columns() {
        let model = RoleMcpServerModel {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            role: "admin".to_owned(),
            server_id: Uuid::nil(),
            enabled: true,
            allowed_tools: Some(json!(["a", "b"])),
            denied_tools: Some(json!("not-an-array")),
            priority: Some(3),
            created_at: datetime!(2026-05-20 10:00:00 UTC),
            updated_at: datetime!(2026-05-20 11:00:00 UTC),
        };
        let info = RoleMcpServerInfo::from(model);
        assert_eq!(info.role, "admin");
        assert_eq!(info.allowed_tools, Some(vec!["a".to_owned(), "b".to_owned()]));
        // Malformed (non-array) JSON is treated as absent.
        assert_eq!(info.denied_tools, None);
        assert_eq!(info.priority, Some(3));
    }

    #[test]
    fn enum_string_helpers_cover_all_variants() {
        assert_eq!(mcp_source_str(McpSource::Config), "config");
        assert_eq!(mcp_source_str(McpSource::Hub), "hub");
        assert_eq!(mcp_source_str(McpSource::Api), "api");

        assert_eq!(mcp_trust_str(McpTrustLevel::Trusted), "trusted");
        assert_eq!(mcp_trust_str(McpTrustLevel::Restricted), "restricted");
        assert_eq!(mcp_trust_str(McpTrustLevel::Untrusted), "untrusted");

        assert_eq!(mcp_health_str(McpHealthStatus::Unknown), "unknown");
        assert_eq!(mcp_health_str(McpHealthStatus::Healthy), "healthy");
        assert_eq!(mcp_health_str(McpHealthStatus::Degraded), "degraded");
        assert_eq!(mcp_health_str(McpHealthStatus::Unhealthy), "unhealthy");
    }

    #[test]
    fn json_to_string_vec_handles_absent_and_malformed() {
        assert_eq!(json_to_string_vec(None), None);
        assert_eq!(json_to_string_vec(Some(json!(42))), None);
        assert_eq!(json_to_string_vec(Some(json!([1, 2]))), None);
        assert_eq!(
            json_to_string_vec(Some(json!(["x"]))),
            Some(vec!["x".to_owned()])
        );
    }
}
