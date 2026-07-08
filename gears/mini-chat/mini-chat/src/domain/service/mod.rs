use std::sync::Arc;

use tokio::sync::Semaphore;

use opentelemetry::trace::TraceContextExt as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use authz_resolver_sdk::pep::ResourceType;
use authz_resolver_sdk::{AuthZResolverClient, PolicyEnforcer};
use toolkit_db::DBProvider;
use toolkit_macros::domain_model;

use crate::config::{
    ContextConfig, EstimationBudgets, QuotaConfig, RagConfig, StreamingConfig, ThumbnailConfig,
};
use oagw_sdk::ServiceGatewayClientV1;

use crate::domain::ports::MiniChatMetricsPort;
use crate::domain::repos::{
    AttachmentRepository, ChatRepository, McpServerRepository, McpServerToolRepository,
    MessageAttachmentRepository, MessageRepository, ModelResolver, OutboxEnqueuer,
    PolicySnapshotProvider, QuotaUsageRepository, ReactionRepository, RoleMcpServerRepository,
    ThreadSummaryRepository, TurnRepository, UserLimitsProvider, VectorStoreRepository,
};
use crate::domain::service::quota_settler::QuotaSettler;
use crate::infra::llm::provider_resolver::ProviderResolver;
use crate::infra::mcp::McpPool;

mod attachment_service;
mod chat_service;
pub(crate) mod context_assembly;
pub(crate) mod credit_arithmetic;
mod effective_mcp_resolver;
pub(crate) mod finalization_service;
mod mcp_argument_validator;
mod mcp_dlp;
mod mcp_output_sanitizer;
mod mcp_rate_limiter;
mod mcp_schema_sanitizer;
mod mcp_service;
mod message_service;
mod model_service;
mod quota_service;
pub(crate) mod quota_settler;
mod reaction_service;
pub(crate) mod replay;
mod stream_service;
#[cfg(test)]
pub(crate) mod test_helpers;
pub(crate) mod thumbnail;
pub(crate) mod token_estimator;
mod turn_service;

pub(crate) use crate::domain::model::audit_envelope::AuditEnvelope;
pub(crate) use attachment_service::AttachmentService;
#[allow(unused_imports)]
pub(crate) use effective_mcp_resolver::{
    EffectiveMcpResolver, EffectiveResolution, McpResolutionDiagnostic, McpToolResolver,
    McpToolRoute, McpToolRoutingMap,
};
pub(crate) use chat_service::ChatService;
pub(crate) use finalization_service::FinalizationService;
pub(crate) use mcp_dlp::DlpRedactor;
pub(crate) use mcp_rate_limiter::McpRateLimiter;
pub(crate) use mcp_service::{AssignServerToRoleInput, McpService, McpToolRefresher};
#[allow(unused_imports)] // referenced by the mcp_refresh_worker test module
pub(crate) use mcp_service::{HubSyncSummary, McpRefreshSummary};
pub(crate) use message_service::MessageService;
pub(crate) use model_service::ModelService;
pub(crate) use quota_service::QuotaService;
pub(crate) use reaction_service::ReactionService;
pub(crate) use stream_service::{StreamError, StreamService};
pub(crate) use turn_service::{MutationError, MutationResult, TurnService};

/// Extract the W3C trace ID from the current tracing span.
///
/// Returns `None` when there is no active `OTel` span (e.g. in tests or
/// background tasks that were started outside a traced request).
/// Must be called as a plain (non-async) function so it inherits the
/// caller's span context without switching async task context.
pub(super) fn current_otel_trace_id() -> Option<String> {
    let ctx = tracing::Span::current().context();
    let tid = ctx.span().span_context().trace_id();
    (tid != opentelemetry::trace::TraceId::INVALID).then(|| tid.to_string())
}

pub(crate) type DbProvider = DBProvider<toolkit_db::DbError>;

/// Authorization resource type for mini-chat.
///
/// All sub-resources (message, turn, attachment, reaction) inherit
/// authorization from the chat level — there is a single GTS resource type.
/// TODO: discuss with the team about resource type GTS identifier.
#[allow(dead_code)]
pub(crate) mod resources {
    use super::ResourceType;
    use toolkit_security::pep_properties;

    pub const CHAT: ResourceType = ResourceType::from_static(
        "gts.cf.core.ai_chat.chat.v1~cf.core.mini_chat.chat.v1~",
        &[
            pep_properties::OWNER_TENANT_ID,
            pep_properties::OWNER_ID,
            pep_properties::RESOURCE_ID,
        ],
    );

    pub const MODEL: ResourceType = ResourceType::from_static(
        "gts.cf.core.ai_chat.model.v1~cf.core.mini_chat.model.v1~",
        &[pep_properties::OWNER_TENANT_ID],
    );

    pub const USER_QUOTA: ResourceType = ResourceType::from_static(
        "gts.cf.core.ai_chat.user_quota.v1~cf.core.mini_chat.user_quota.v1~",
        &[pep_properties::OWNER_TENANT_ID, pep_properties::OWNER_ID],
    );

    // MCP servers are `no_owner` (tenant-scoped or global). Global servers
    // carry a NULL tenant; authorization for admin/read actions is evaluated
    // against the caller's tenant.
    // TODO: discuss with the team about resource type GTS identifier.
    pub const MCP_SERVER: ResourceType = ResourceType::from_static(
        "gts.cf.core.ai_chat.mcp_server.v1~cf.core.mini_chat.mcp_server.v1~",
        &[pep_properties::OWNER_TENANT_ID, pep_properties::RESOURCE_ID],
    );
}

#[allow(dead_code)]
pub(crate) mod actions {
    pub const CREATE: &str = "create";
    pub const READ: &str = "read";
    pub const LIST: &str = "list";
    pub const UPDATE: &str = "update";
    pub const DELETE: &str = "delete";
    pub const LIST_MESSAGES: &str = "list_messages";
    pub const SEND_MESSAGE: &str = "send_message";
    pub const READ_TURN: &str = "read_turn";
    pub const RETRY_TURN: &str = "retry_turn";
    pub const EDIT_TURN: &str = "edit_turn";
    pub const DELETE_TURN: &str = "delete_turn";
    pub const UPLOAD_ATTACHMENT: &str = "upload_attachment";
    pub const READ_ATTACHMENT: &str = "read_attachment";
    pub const DELETE_ATTACHMENT: &str = "delete_attachment";
    pub const SET_REACTION: &str = "set_reaction";
    pub const DELETE_REACTION: &str = "delete_reaction";
    pub const READ_MCP_SERVER: &str = "read_mcp_server";
    pub const LIST_MCP_SERVERS: &str = "list_mcp_servers";
    pub const LIST_MCP_TOOLS: &str = "list_mcp_tools";
    pub const REFRESH_MCP_TOOLS: &str = "refresh_mcp_tools";
    pub const ASSIGN_MCP_SERVER_ROLE: &str = "assign_mcp_server_role";
    pub const REVOKE_MCP_SERVER_ROLE: &str = "revoke_mcp_server_role";
    pub const LIST_ROLE_MCP_SERVERS: &str = "list_role_mcp_servers";
    pub const APPROVE_MCP_SERVER: &str = "approve_mcp_server";
    pub const MANAGE_MCP_CONNECTION: &str = "manage_mcp_connection";
}

/// All repository instances passed to `AppServices::new` as a single bundle.
#[domain_model]
pub(crate) struct Repositories<
    TR: TurnRepository,
    MR: MessageRepository,
    QR: QuotaUsageRepository,
    RR: ReactionRepository,
    CR: ChatRepository,
    TSR: ThreadSummaryRepository,
    AR: AttachmentRepository,
    VSR: VectorStoreRepository,
    MAR: MessageAttachmentRepository,
    MSR: McpServerRepository,
    MTR: McpServerToolRepository,
    RMSR: RoleMcpServerRepository,
> {
    pub(crate) chat: Arc<CR>,
    pub(crate) attachment: Arc<AR>,
    pub(crate) message: Arc<MR>,
    pub(crate) quota: Arc<QR>,
    pub(crate) turn: Arc<TR>,
    pub(crate) reaction: Arc<RR>,
    pub(crate) thread_summary: Arc<TSR>,
    pub(crate) vector_store: Arc<VSR>,
    pub(crate) message_attachment: Arc<MAR>,
    pub(crate) mcp_server: Arc<MSR>,
    pub(crate) mcp_tool: Arc<MTR>,
    pub(crate) role_mcp_server: Arc<RMSR>,
}

/// DI container — aggregates all domain services.
///
/// Created once during `Gear::init` and shared with handlers via `Arc`.
/// Services acquire database connections internally via `DbProvider`;
/// handlers call service methods with business parameters only.
#[domain_model]
#[allow(dead_code)]
pub(crate) struct AppServices<
    TR: TurnRepository + 'static,
    MR: MessageRepository + 'static,
    QR: QuotaUsageRepository + 'static,
    RR: ReactionRepository + 'static,
    CR: ChatRepository + 'static,
    TSR: ThreadSummaryRepository + 'static,
    AR: AttachmentRepository + 'static,
    VSR: VectorStoreRepository + 'static,
    MAR: MessageAttachmentRepository + 'static,
    MSR: McpServerRepository + 'static,
    MTR: McpServerToolRepository + 'static,
    RMSR: RoleMcpServerRepository + 'static,
> {
    pub(crate) chats: ChatService<CR, AR, TSR>,
    pub(crate) messages: MessageService<MR, CR, RR>,
    pub(crate) stream: StreamService<TR, MR, QR, CR, TSR, AR, VSR, MAR>,
    pub(crate) turns: TurnService<TR, MR, CR, MAR>,
    pub(crate) reactions: ReactionService<RR, MR, CR>,
    pub(crate) attachments: AttachmentService<CR, AR, VSR>,
    pub(crate) mcp: Arc<McpService<MSR, MTR, RMSR>>,
    pub(crate) models: ModelService,
    pub(crate) quota: Arc<QuotaService<QR>>,
    pub(crate) finalization: Arc<FinalizationService<TR, MR>>,
    pub(crate) db: Arc<DbProvider>,
    pub(crate) message_repo: Arc<MR>,
    pub(crate) turn_repo: Arc<TR>,
    pub(crate) enforcer: PolicyEnforcer,
    pub(crate) metrics: Arc<dyn MiniChatMetricsPort>,
    /// Semaphore bounding concurrent in-flight uploads for memory backpressure.
    pub(crate) upload_semaphore: Arc<Semaphore>,
}

impl<
    TR: TurnRepository + 'static,
    MR: MessageRepository + 'static,
    QR: QuotaUsageRepository + 'static,
    RR: ReactionRepository + 'static,
    CR: ChatRepository + 'static,
    TSR: ThreadSummaryRepository + 'static,
    AR: AttachmentRepository + 'static,
    VSR: VectorStoreRepository + 'static,
    MAR: MessageAttachmentRepository + 'static,
    MSR: McpServerRepository + 'static,
    MTR: McpServerToolRepository + 'static,
    RMSR: RoleMcpServerRepository + 'static,
> AppServices<TR, MR, QR, RR, CR, TSR, AR, VSR, MAR, MSR, MTR, RMSR>
{
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub(crate) fn new(
        repos: &Repositories<TR, MR, QR, RR, CR, TSR, AR, VSR, MAR, MSR, MTR, RMSR>,
        db: Arc<DbProvider>,
        authz: Arc<dyn AuthZResolverClient>,
        gateway: Arc<dyn ServiceGatewayClientV1>,
        mcp_pool: Arc<McpPool>,
        mcp_config: crate::config::McpConfig,
        model_resolver: &Arc<dyn ModelResolver>,
        provider_resolver: &Arc<ProviderResolver>,
        streaming_config: StreamingConfig,
        policy_provider: Arc<dyn PolicySnapshotProvider>,
        limits_provider: Arc<dyn UserLimitsProvider>,
        estimation_budgets: EstimationBudgets,
        quota_config: QuotaConfig,
        outbox_enqueuer: &Arc<dyn OutboxEnqueuer>,
        context_config: ContextConfig,
        file_storage: Arc<dyn crate::domain::ports::FileStorageProvider>,
        vector_store_provider: Arc<dyn crate::domain::ports::VectorStoreProvider>,
        rag_config: RagConfig,
        thumbnail_config: ThumbnailConfig,
        metrics: Arc<dyn MiniChatMetricsPort>,
        summary_config: crate::config::background::ThreadSummaryWorkerConfig,
        knowledge_search_config: crate::config::KnowledgeSearchConfig,
        knowledge_retriever: Option<Arc<dyn crate::domain::ports::KnowledgeRetriever>>,
        anthropic_files_client: Option<
            Arc<crate::infra::llm::providers::anthropic_files_client::AnthropicFilesClient>,
        >,
    ) -> Self {
        let enforcer = PolicyEnforcer::new(authz);

        // Shared QuotaService used by both StreamService (preflight) and
        // FinalizationService (settlement via QuotaSettler trait).
        let quota_svc = Arc::new(QuotaService::new(
            Arc::clone(&db),
            Arc::clone(&repos.quota),
            policy_provider,
            limits_provider,
            estimation_budgets,
            quota_config,
        ));

        let finalization = Arc::new(FinalizationService::new(
            Arc::clone(&db),
            Arc::clone(&repos.turn),
            Arc::clone(&repos.message),
            Arc::clone(&quota_svc) as Arc<dyn QuotaSettler>,
            Arc::clone(outbox_enqueuer),
            Arc::clone(&metrics),
            summary_config,
        ));

        let turns = TurnService::new(
            Arc::clone(&db),
            Arc::clone(&repos.turn),
            Arc::clone(&repos.message),
            Arc::clone(&repos.chat),
            Arc::clone(&repos.message_attachment),
            enforcer.clone(),
            Arc::clone(outbox_enqueuer),
            Arc::clone(&metrics),
        );

        let upload_semaphore = Arc::new(Semaphore::new(rag_config.max_concurrent_uploads.into()));

        // Effective MCP tool resolver shared by the stream hot path. Built
        // unconditionally; `resolve` short-circuits to an empty set when
        // `mcp.enabled` is false, so the chat path pays nothing when MCP is off.
        let mcp_max_tools_per_chat = mcp_config.max_tools_per_chat;
        let mcp_resolver: Option<Arc<dyn McpToolResolver>> =
            Some(Arc::new(EffectiveMcpResolver::new(
                Arc::clone(&db),
                Arc::clone(&repos.mcp_server),
                Arc::clone(&repos.mcp_tool),
                Arc::clone(&gateway),
                &mcp_config,
            )));

        // Stream-time MCP `tools/call` dispatch surface (shares the pool used
        // by `McpService`). Wired only when MCP is enabled; the pool is moved
        // into `McpService` below, so clone the dispatch handle first.
        let mcp_dispatcher: Option<Arc<dyn crate::infra::mcp::McpDispatcher>> = if mcp_config.enabled
        {
            Some(Arc::clone(&mcp_pool) as Arc<dyn crate::infra::mcp::McpDispatcher>)
        } else {
            None
        };
        let mcp_max_calls_per_message = mcp_config.max_mcp_calls_per_message;
        let mcp_max_tool_output_chars = mcp_config.max_tool_output_chars;

        Self {
            chats: ChatService::new(
                Arc::clone(&db),
                Arc::clone(&repos.chat),
                Arc::clone(&repos.attachment),
                Arc::clone(&repos.thread_summary),
                Arc::clone(outbox_enqueuer),
                enforcer.clone(),
                Arc::clone(model_resolver),
                Arc::clone(provider_resolver),
            ),
            messages: MessageService::new(
                Arc::clone(&db),
                Arc::clone(&repos.message),
                Arc::clone(&repos.chat),
                Arc::clone(&repos.reaction),
                enforcer.clone(),
            ),
            stream: StreamService::new(
                Arc::clone(&db),
                Arc::clone(&repos.turn),
                Arc::clone(&repos.message),
                Arc::clone(&repos.chat),
                enforcer.clone(),
                Arc::clone(provider_resolver),
                streaming_config,
                Arc::clone(&finalization),
                Arc::clone(&quota_svc),
                Arc::clone(&repos.thread_summary),
                Arc::clone(&repos.attachment),
                Arc::clone(&repos.vector_store),
                Arc::clone(&repos.message_attachment),
                context_config,
                rag_config.clone(),
                Arc::clone(&metrics),
                knowledge_search_config,
                knowledge_retriever,
                mcp_resolver,
                mcp_max_tools_per_chat,
                mcp_dispatcher,
                mcp_max_calls_per_message,
                mcp_max_tool_output_chars,
                mcp_config.max_mcp_calls_per_minute_per_tenant,
                &mcp_config.dlp_redaction_patterns,
            ),
            turns,
            reactions: ReactionService::new(
                Arc::clone(&db),
                Arc::clone(&repos.reaction),
                Arc::clone(&repos.message),
                Arc::clone(&repos.chat),
                enforcer.clone(),
            ),
            attachments: AttachmentService::new(
                Arc::clone(&db),
                Arc::clone(&repos.attachment),
                Arc::clone(&repos.chat),
                Arc::clone(&repos.vector_store),
                Arc::clone(outbox_enqueuer),
                enforcer.clone(),
                file_storage,
                vector_store_provider,
                Arc::clone(provider_resolver),
                Arc::clone(model_resolver),
                rag_config,
                thumbnail_config,
                Arc::clone(&metrics),
                anthropic_files_client,
            ),
            mcp: Arc::new(McpService::new(
                Arc::clone(&db),
                Arc::clone(&repos.mcp_server),
                Arc::clone(&repos.mcp_tool),
                Arc::clone(&repos.role_mcp_server),
                enforcer.clone(),
                gateway,
                mcp_pool,
                mcp_config.servers,
                mcp_config.hub_url,
                mcp_config.hub_auth,
                mcp_config.call_timeout_secs,
                Arc::clone(&metrics),
            )),
            models: ModelService::new(
                Arc::clone(&db),
                enforcer.clone(),
                Arc::clone(model_resolver),
            ),
            quota: Arc::clone(&quota_svc),
            finalization,
            db,
            message_repo: Arc::clone(&repos.message),
            turn_repo: Arc::clone(&repos.turn),
            enforcer,
            metrics,
            upload_semaphore,
        }
    }
}
