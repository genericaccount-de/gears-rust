#![allow(
    clippy::doc_markdown,
    clippy::map_unwrap_or,
    clippy::redundant_closure_for_method_calls,
    clippy::cast_precision_loss,
    clippy::non_ascii_literal
)]

use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use toolkit_security::SecurityContext;
use tracing::{Instrument, debug, info, warn};

use crate::domain::llm::ToolPhase;
use crate::domain::ports::knowledge_retriever::{
    KnowledgeRetriever, RetrievalRequest, RetrievedChunk,
};
use crate::domain::ports::metric_labels::{stage, trigger};
use crate::domain::ports::rest_client::{RestClient, RestError, RestResponse};
use crate::domain::service::rest_connectors::RestAPIConnectorRegistry;
use crate::domain::repos::{MessageRepository, ToolCallType, TurnRepository};
use crate::domain::stream_events::{DoneData, ErrorData, StreamEvent};
use crate::infra::db::entity::chat_turn::TurnState;
use crate::infra::llm::{
    ClientSseEvent, LlmMessage, LlmProvider, LlmProviderError, LlmRequestBuilder, LlmTool,
    RequestMetadata, RequestType, TerminalOutcome,
};

use toolkit_macros::domain_model;

use super::timer_store::TimerStore;
use super::types::{
    ActiveStreamGuard, FinalizationCtx, PROGRESS_UPDATE_INTERVAL, StreamOutcome, StreamTerminal,
    determine_features, normalize_error,
};

/// Parameters for knowledge search (RAG) within the agentic loop.
#[domain_model]
pub(super) struct KnowledgeSearchParams {
    pub retriever: Arc<dyn KnowledgeRetriever>,
    pub vector_store_id: String,
    /// Pre-resolved OAGW upstream alias for the knowledge provider.
    pub upstream_alias: String,
    pub api_version: String,
    pub top_k: usize,
    pub max_calls: u32,
    /// Maximum characters kept per chunk after post-processing (text truncation).
    pub max_chunk_chars: usize,
    /// When `true`, format chunks as a JSON array of `search_result` blocks
    /// (required by Anthropic Messages API for citations). When `false`, use
    /// plain `[SOURCE_N]` text labels (OpenAI / Azure providers).
    pub use_search_result_blocks: bool,
}

/// Model and provider configuration for a single provider task invocation.
#[domain_model]
pub(super) struct ProviderTaskConfig {
    pub llm: Arc<dyn LlmProvider>,
    pub upstream_alias: String,
    pub messages: Vec<LlmMessage>,
    pub system_instructions: Option<String>,
    pub tools: Vec<LlmTool>,
    pub model: String,
    pub provider_model_id: String,
    pub max_output_tokens: u32,
    pub max_tool_calls: u32,
    pub web_search_max_calls: u32,
    pub code_interpreter_max_calls: u32,
    pub api_params: mini_chat_sdk::ModelApiParams,
    pub provider_file_id_map: std::collections::HashMap<String, crate::domain::llm::AttachmentRef>,
    /// `provider_file_id → anthropic_file_id` lookup for chat attachments
    /// uploaded to Anthropic Files API. Forwarded to the Anthropic adapter
    /// via `LlmRequest::anthropic_file_ids`. Empty for non-Anthropic chats.
    pub anthropic_file_ids: std::collections::HashMap<String, String>,
    /// Knowledge search parameters; `None` when the feature is disabled.
    pub knowledge_search: Option<KnowledgeSearchParams>,
    /// Timer tool parameters; `None` when the feature is disabled.
    pub timer: Option<TimerToolParams>,
    /// REST connector tool parameters; `None` when the feature is disabled.
    pub rest: Option<RestToolParams>,
}

/// Parameters for the `timer` custom tool within the agentic loop.
#[domain_model]
pub(super) struct TimerToolParams {
    /// Process-local store of named timers, shared across requests.
    pub store: TimerStore,
    /// Maximum `timer` calls per message in the agentic loop.
    pub max_calls: u32,
}

/// Parameters for the REST connector tools within the agentic loop.
#[domain_model]
pub(super) struct RestToolParams {
    /// Config-derived registry of connectors (tool schemas + request builder).
    pub registry: Arc<RestAPIConnectorRegistry>,
    /// Transport for outbound REST calls (host-allowlisted, SSRF-guarded).
    pub client: Arc<dyn RestClient>,
    /// Maximum connector calls per message in the agentic loop.
    pub max_calls: u32,
}

/// All five terminal paths (provider done, incomplete, provider error,
/// client disconnect, pre-stream error) route through `finalize_turn_cas()`.
/// SSE terminal events (Done/Error) are emitted only after the CAS winner
/// commits the transaction (D3).
#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::let_underscore_must_use,
    clippy::cast_possible_truncation
)]
pub(super) fn spawn_provider_task<TR: TurnRepository + 'static, MR: MessageRepository + 'static>(
    ctx: SecurityContext,
    config: ProviderTaskConfig,
    cancel: CancellationToken,
    tx: mpsc::Sender<StreamEvent>,
    fin_ctx: Option<FinalizationCtx<TR, MR>>,
) -> tokio::task::JoinHandle<StreamOutcome> {
    let ProviderTaskConfig {
        llm,
        upstream_alias,
        messages,
        system_instructions,
        tools,
        model,
        provider_model_id,
        max_output_tokens,
        max_tool_calls,
        web_search_max_calls,
        code_interpreter_max_calls,
        api_params,
        provider_file_id_map,
        anthropic_file_ids,
        knowledge_search,
        timer,
        rest,
    } = config;

    let span = if let Some(ref fctx) = fin_ctx {
        tracing::info_span!(
            "provider_stream",
            chat_id = %fctx.chat_id,
            turn_request_id = %fctx.request_id,
            turn_id = %fctx.turn_id,
            model = %model,
        )
    } else {
        tracing::info_span!("provider_stream", model = %model)
    };

    tokio::spawn(async move {
        let stream_start = std::time::Instant::now();
        let mut first_token_time: Option<std::time::Duration> = None;

        // ── Metrics: stream started + active gauge ──
        // ActiveStreamGuard ensures decrement on every exit path (Drop-based).
        let _stream_guard = if let Some(ref fctx) = fin_ctx {
            fctx.metrics
                .record_stream_started(&fctx.provider_id, &fctx.effective_model);
            fctx.metrics.increment_active_streams();
            Some(ActiveStreamGuard(Arc::clone(&fctx.metrics)))
        } else {
            None
        };

        // ── Agentic-level mutable state (persists across search_knowledge iterations) ──
        let mut accumulated_text = String::new();
        let mut cancelled = false;
        let mut web_search_call_count: u32 = 0;
        let mut web_search_completed_count: u32 = 0;
        let mut code_interpreter_call_count: u32 = 0;
        let mut code_interpreter_completed_count: u32 = 0;
        // raw_input_items grows with each search_knowledge call/output pair.
        let mut raw_input_items: Vec<serde_json::Value> = Vec::new();
        let mut knowledge_call_count: u32 = 0;
        // Counts `timer` tool calls for the per-message soft cap.
        let mut timer_call_count: u32 = 0;
        // Counts REST connector tool calls for the per-message soft cap.
        let mut rest_call_count: u32 = 0;

        // Hard cap on agentic-loop iterations. Without it, a model that keeps
        // emitting `search_knowledge` after the soft per-message limit fires
        // would loop forever (each iteration injects another "limit reached"
        // notice but never terminates). The cap is `max_calls + 2`: the
        // searches themselves, plus one buffer iteration so the model can
        // summarise after the soft notice, plus one more in case the model
        // ignores the notice once. Iterations beyond that are forced into
        // a `Failed` terminal via `agentic_iterations_exceeded` below.
        //
        // When neither knowledge_search nor timer is enabled the loop body always
        // returns inside the first iteration (any ToolUse falls through to
        // `unexpected_tool_use`), so the cap is effectively 1. When function tools
        // are enabled the cap is the sum of their per-message budgets plus a small
        // buffer so the model can summarise after the soft-limit notices fire.
        let knowledge_budget = knowledge_search.as_ref().map_or(0, |ks| ks.max_calls);
        let timer_budget = timer.as_ref().map_or(0, |t| t.max_calls);
        let rest_budget = rest.as_ref().map_or(0, |r| r.max_calls);
        let max_agentic_iterations: u32 =
            if knowledge_budget == 0 && timer_budget == 0 && rest_budget == 0 {
                1
            } else {
                knowledge_budget
                    .saturating_add(timer_budget)
                    .saturating_add(rest_budget)
                    .saturating_add(2)
            };
        let mut agentic_iteration: u32 = 0;

        'agentic: loop {
            agentic_iteration = agentic_iteration.saturating_add(1);
            if agentic_iteration > max_agentic_iterations {
                warn!(
                    agentic_iteration,
                    max_agentic_iterations,
                    knowledge_call_count,
                    "agentic loop iteration cap exceeded; finalizing as failed"
                );
                let code = "agentic_iterations_exceeded".to_owned();
                let message = "Model exceeded the maximum number of tool-use iterations \
                               for this message"
                    .to_owned();
                if let Some(ref fctx) = fin_ctx {
                    let elapsed = stream_start.elapsed();
                    let finput = fctx.to_finalization_input(
                        TurnState::Failed,
                        &accumulated_text,
                        None,
                        Some(code.clone()),
                        None,
                        None,
                        web_search_completed_count,
                        code_interpreter_completed_count,
                        knowledge_call_count,
                        first_token_time.map(|d| d.as_millis() as u64),
                        Some(elapsed.as_millis() as u64),
                    );
                    match fctx.finalization_svc.finalize_turn_cas(finput).await {
                        Ok(outcome) if outcome.won_cas => {
                            let _ = tx
                                .send(StreamEvent::Error(ErrorData {
                                    code: code.clone(),
                                    message,
                                }))
                                .await;
                        }
                        Ok(_) => {}
                        Err(fe) => {
                            warn!(error = %fe, "finalization failed on agentic iteration cap");
                            let _ = tx
                                .send(StreamEvent::Error(ErrorData {
                                    code: code.clone(),
                                    message,
                                }))
                                .await;
                        }
                    }
                    let ms = stream_start.elapsed().as_secs_f64() * 1000.0;
                    fctx.metrics.record_stream_failed(
                        &fctx.provider_id,
                        &fctx.effective_model,
                        &code,
                    );
                    fctx.metrics.record_stream_total_latency_ms(
                        &fctx.provider_id,
                        &fctx.effective_model,
                        ms,
                    );
                } else {
                    let _ = tx
                        .send(StreamEvent::Error(ErrorData {
                            code: code.clone(),
                            message,
                        }))
                        .await;
                }
                let has_partial = !accumulated_text.is_empty();
                return StreamOutcome {
                    terminal: StreamTerminal::Failed,
                    accumulated_text,
                    usage: None,
                    effective_model: model,
                    error_code: Some(code),
                    provider_response_id: None,
                    provider_partial_usage: has_partial,
                };
            }

        // Build the LLM request using provider_model_id (the actual provider-facing name)
        let mut builder = LlmRequestBuilder::new(&provider_model_id)
            .messages(messages.clone())
            .max_output_tokens(u64::from(max_output_tokens))
            .max_tool_calls(max_tool_calls)
            .raw_input_items(raw_input_items.clone());
        if let Some(ref instructions) = system_instructions {
            builder = builder.system_instructions(instructions.clone());
        }
        let features = determine_features(&tools);
        for tool in &tools {
            builder = builder.tool(tool.clone());
        }
        let metadata = RequestMetadata {
            tenant_id: ctx.subject_tenant_id().to_string(),
            user_id: ctx.subject_id().to_string(),
            chat_id: fin_ctx
                .as_ref()
                .map_or_else(String::new, |f| f.chat_id.to_string()),
            request_type: RequestType::Chat,
            features,
        };
        builder = builder.metadata(metadata);

        // Forward typed model-policy API params; each adapter selects the
        // fields its protocol supports.
        builder = builder.api_params(api_params.clone());

        // Forward the Anthropic file-id substitution map so the Anthropic
        // adapter can replace primary `provider_file_id` references in image /
        // document blocks with the actual `anthropic_file_id`. Empty for
        // non-Anthropic chats — other adapters ignore the field.
        if !anthropic_file_ids.is_empty() {
            builder = builder.anthropic_file_ids(anthropic_file_ids.clone());
        }

        let request = builder.build_streaming();

        // Use a child token for the provider HTTP stream so that calling
        // provider_stream.cancel() in tool-limit-exceeded branches only stops
        // the provider without cancelling the parent token used by SseRelay.
        // Client-disconnect cancellation still propagates via the token hierarchy.
        let provider_cancel = cancel.child_token();

        // Call the provider to start streaming
        let stream_result = llm
            .stream(ctx.clone(), request, &upstream_alias, provider_cancel)
            .await;

        let mut provider_stream = match stream_result {
            Ok(s) => s,
            Err(e) => {
                // Provider failed before any events — finalize first, then emit error.
                warn!(
                    error = %e,
                    raw_detail = e.raw_detail().unwrap_or(""),
                    "LLM provider failed before stream start"
                );
                let (code, message) = normalize_error(&e);

                if let Some(ref fctx) = fin_ctx {
                    let input = fctx.to_finalization_input(
                        TurnState::Failed,
                        "",
                        None,
                        Some(code.clone()),
                        None,
                        None,
                        0,
                        0,
                        knowledge_call_count,
                        None,
                        None,
                    );
                    match fctx.finalization_svc.finalize_turn_cas(input).await {
                        Ok(outcome) if outcome.won_cas => {
                            let _ = tx
                                .send(StreamEvent::Error(ErrorData {
                                    code: code.clone(),
                                    message,
                                }))
                                .await;
                        }
                        Ok(_) => { /* CAS loser — no SSE emission */ }
                        Err(fe) => {
                            warn!(error = %fe, "finalization failed on pre-stream error");
                            // Still emit error so client isn't left hanging
                            let _ = tx
                                .send(StreamEvent::Error(ErrorData {
                                    code: code.clone(),
                                    message,
                                }))
                                .await;
                        }
                    }
                } else {
                    let _ = tx
                        .send(StreamEvent::Error(ErrorData {
                            code: code.clone(),
                            message,
                        }))
                        .await;
                }

                // Metrics: pre-stream failure
                if let Some(ref fctx) = fin_ctx {
                    let ms = stream_start.elapsed().as_secs_f64() * 1000.0;
                    fctx.metrics.record_stream_failed(&fctx.provider_id, &fctx.effective_model, &code);
                    fctx.metrics.record_stream_total_latency_ms(&fctx.provider_id, &fctx.effective_model, ms);
                }

                return StreamOutcome {
                    terminal: StreamTerminal::Failed,
                    accumulated_text: String::new(),
                    usage: None,
                    effective_model: model,
                    error_code: Some(code),
                    provider_response_id: None,
                    provider_partial_usage: false,
                };
            }
        };

        // Read events from provider, translate and forward through channel
        let mut last_progress_update = std::time::Instant::now();
        // TODO(P2): web_search_call_count (Start) is used for enforcement,
        // web_search_completed_count (Done) is used for settlement. If a search
        // starts but never completes (provider error between Start/Done), the
        // daily quota under-counts by one. Acceptable for P1 since OpenAI always
        // pairs searching→completed; revisit if we add providers that don't.

        loop {
            tokio::select! {
                biased;

                () = cancel.cancelled() => {
                    debug!("stream cancelled, aborting provider");
                    if let Some(ref fctx) = fin_ctx {
                        fctx.metrics.record_cancel_requested(trigger::DISCONNECT);
                        let disconnect_stage = if first_token_time.is_none() {
                            stage::BEFORE_FIRST_TOKEN
                        } else {
                            stage::MID_STREAM
                        };
                        fctx.metrics.record_stream_disconnected(disconnect_stage);
                    }
                    provider_stream.cancel();
                    cancelled = true;
                    break;
                }

                event = provider_stream.next() => {
                    match event {
                        Some(Ok(client_event)) => {
                            let is_first_token = matches!(client_event, ClientSseEvent::Delta { .. })
                                && first_token_time.is_none();

                            if let ClientSseEvent::Delta { r#type, ref content } = client_event {
                                if first_token_time.is_none() {
                                    let ttft = stream_start.elapsed();
                                    first_token_time = Some(ttft);
                                    info!(
                                        time_to_first_token_ms = ttft.as_millis() as u64,
                                        "first token received"
                                    );
                                    if let Some(ref fctx) = fin_ctx {
                                        let ms = ttft.as_secs_f64() * 1000.0;
                                        fctx.metrics.record_ttft_provider_ms(&fctx.provider_id, &fctx.effective_model, ms);
                                    }
                                }
                                // Only accumulate visible text for DB storage;
                                // reasoning deltas are streamed to the client
                                // but excluded from the persisted content.
                                if r#type == "text" {
                                    accumulated_text.push_str(content);
                                }

                                // Throttled progress timestamp update for orphan detection.
                                // Timer resets only on success — retry sooner on transient
                                // failures to avoid stale last_progress_at triggering false
                                // orphan detection.
                                if let Some(ref fctx) = fin_ctx
                                    && last_progress_update.elapsed() >= PROGRESS_UPDATE_INTERVAL
                                {
                                    let ok = match fctx.db.conn() {
                                        Ok(conn) => {
                                            match fctx.turn_repo.update_progress_at(&conn, &fctx.scope, fctx.turn_id).await {
                                                Ok(_) => true,
                                                Err(e) => {
                                                    warn!(turn_id = %fctx.turn_id, error = %e, "failed to update progress timestamp");
                                                    false
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(turn_id = %fctx.turn_id, error = %e, "failed to get DB connection for progress update");
                                            false
                                        }
                                    };
                                    if ok {
                                        last_progress_update = std::time::Instant::now();
                                    }
                                }
                            }

                            // Track web search tool calls for per-message limit
                            if let ClientSseEvent::Tool { ref phase, name, .. } = client_event
                                && name == "web_search"
                            {
                                match phase {
                                    ToolPhase::Start => {
                                        web_search_call_count += 1;
                                        if web_search_call_count > web_search_max_calls {
                                            warn!(
                                                web_search_call_count,
                                                limit = web_search_max_calls,
                                                "web search per-message limit exceeded"
                                            );
                                            let code = "web_search_calls_exceeded".to_owned();
                                            let message = "Web search calls exceeded for this message".to_owned();

                                            // Cancel provider first so it stops executing the
                                            // over-limit tool call during the finalization await.
                                            provider_stream.cancel();

                                            // Finalize as failed, then emit error (D3)
                                            if let Some(ref fctx) = fin_ctx {
                                                let input = fctx.to_finalization_input(
                                                    TurnState::Failed,
                                                    &accumulated_text,
                                                    None,
                                                    Some(code.clone()),
                                                    None,
                                                    None,
                                                    web_search_completed_count,
                                                    code_interpreter_completed_count,
                                                    knowledge_call_count,
                                                    None,
                                                    None,
                                                );
                                                match fctx.finalization_svc.finalize_turn_cas(input).await {
                                                    Ok(outcome) if outcome.won_cas => {
                                                        let _ = tx.send(StreamEvent::Error(ErrorData {
                                                            code: code.clone(),
                                                            message,
                                                        })).await;
                                                    }
                                                    Ok(_) => {}
                                                    Err(fe) => {
                                                        warn!(error = %fe, "finalization failed on ws limit exceeded");
                                                        let _ = tx.send(StreamEvent::Error(ErrorData {
                                                            code: code.clone(),
                                                            message,
                                                        })).await;
                                                    }
                                                }
                                            } else {
                                                let _ = tx.send(StreamEvent::Error(ErrorData {
                                                    code: code.clone(),
                                                    message,
                                                })).await;
                                            }

                                            // Metrics: web search limit exceeded
                                            if let Some(ref fctx) = fin_ctx {
                                                let ms = stream_start.elapsed().as_secs_f64() * 1000.0;
                                                fctx.metrics.record_stream_failed(
                                                    &fctx.provider_id,
                                                    &fctx.effective_model,
                                                    &code,
                                                );
                                                fctx.metrics.record_stream_total_latency_ms(
                                                    &fctx.provider_id,
                                                    &fctx.effective_model,
                                                    ms,
                                                );
                                            }

                                            let has_partial = !accumulated_text.is_empty();
                                            return StreamOutcome {
                                                terminal: StreamTerminal::Failed,
                                                accumulated_text,
                                                usage: None,
                                                effective_model: model,
                                                error_code: Some(code),
                                                provider_response_id: None,
                                                provider_partial_usage: has_partial,
                                            };
                                        }
                                    }
                                    ToolPhase::Done => {
                                        web_search_completed_count += 1;
                                        if let Some(ref fctx) = fin_ctx {
                                            match fctx.db.conn() {
                                                Ok(conn) => {
                                                    if let Err(e) = fctx.turn_repo.increment_tool_calls(&conn, &fctx.scope, fctx.turn_id, ToolCallType::WebSearch).await {
                                                        warn!(turn_id = %fctx.turn_id, error = %e, "failed to persist web_search_completed_count");
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!(turn_id = %fctx.turn_id, error = %e, "failed to acquire DB connection for web_search_completed_count");
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Track code interpreter tool calls
                            if let ClientSseEvent::Tool { ref phase, name, .. } = client_event
                                && name == "code_interpreter"
                            {
                                match phase {
                                    ToolPhase::Start => {
                                        code_interpreter_call_count += 1;
                                        if code_interpreter_call_count > code_interpreter_max_calls {
                                            warn!(
                                                code_interpreter_call_count,
                                                limit = code_interpreter_max_calls,
                                                "code interpreter per-message limit exceeded"
                                            );
                                            let code = "code_interpreter_calls_exceeded".to_owned();
                                            let message = "Code interpreter calls exceeded for this message".to_owned();

                                            // Cancel provider first so it stops executing the
                                            // over-limit tool call during the finalization await.
                                            provider_stream.cancel();

                                            if let Some(ref fctx) = fin_ctx {
                                                let input = fctx.to_finalization_input(
                                                    TurnState::Failed,
                                                    &accumulated_text,
                                                    None,
                                                    Some(code.clone()),
                                                    None,
                                                    None,
                                                    web_search_completed_count,
                                                    code_interpreter_completed_count,
                                                    knowledge_call_count,
                                                    None,
                                                    None,
                                                );
                                                match fctx.finalization_svc.finalize_turn_cas(input).await {
                                                    Ok(outcome) if outcome.won_cas => {
                                                        let _ = tx.send(StreamEvent::Error(ErrorData {
                                                            code: code.clone(),
                                                            message,
                                                        })).await;
                                                    }
                                                    Ok(_) => {}
                                                    Err(fe) => {
                                                        warn!(error = %fe, "finalization failed on ci limit exceeded");
                                                        let _ = tx.send(StreamEvent::Error(ErrorData {
                                                            code: code.clone(),
                                                            message,
                                                        })).await;
                                                    }
                                                }
                                            } else {
                                                let _ = tx.send(StreamEvent::Error(ErrorData {
                                                    code: code.clone(),
                                                    message,
                                                })).await;
                                            }

                                            if let Some(ref fctx) = fin_ctx {
                                                let ms = stream_start.elapsed().as_secs_f64() * 1000.0;
                                                fctx.metrics.record_stream_failed(
                                                    &fctx.provider_id,
                                                    &fctx.effective_model,
                                                    &code,
                                                );
                                                fctx.metrics.record_stream_total_latency_ms(
                                                    &fctx.provider_id,
                                                    &fctx.effective_model,
                                                    ms,
                                                );
                                            }

                                            let has_partial = !accumulated_text.is_empty();
                                            return StreamOutcome {
                                                terminal: StreamTerminal::Failed,
                                                accumulated_text,
                                                usage: None,
                                                effective_model: model,
                                                error_code: Some(code),
                                                provider_response_id: None,
                                                provider_partial_usage: has_partial,
                                            };
                                        }
                                    }
                                    ToolPhase::Done => {
                                        code_interpreter_completed_count += 1;
                                        if let Some(ref fctx) = fin_ctx {
                                            match fctx.db.conn() {
                                                Ok(conn) => {
                                                    if let Err(e) = fctx.turn_repo.increment_tool_calls(&conn, &fctx.scope, fctx.turn_id, ToolCallType::CodeInterpreter).await {
                                                        warn!(turn_id = %fctx.turn_id, error = %e, "failed to persist code_interpreter_completed_count");
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!(turn_id = %fctx.turn_id, error = %e, "failed to acquire DB connection for code_interpreter_completed_count");
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            let stream_event = StreamEvent::from(client_event);
                            if tx.send(stream_event).await.is_err() {
                                // Receiver dropped (client disconnect handled by relay)
                                info!("channel closed (client disconnect), exiting provider task");
                                break;
                            }

                            // TTFT overhead: time from provider first-byte to channel send.
                            if is_first_token
                                && let (Some(fctx), Some(provider_ttft)) =
                                    (&fin_ctx, first_token_time)
                                {
                                    let total = stream_start.elapsed().as_secs_f64() * 1000.0;
                                    let provider_ms = provider_ttft.as_secs_f64() * 1000.0;
                                    fctx.metrics.record_ttft_overhead_ms(
                                        &fctx.provider_id,
                                        &fctx.effective_model,
                                        total - provider_ms,
                                    );
                                }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "provider stream error");
                            let (code, message) =
                                normalize_error(&LlmProviderError::StreamError(e));

                            // Finalize first, emit error only if CAS winner (D3)
                            if let Some(ref fctx) = fin_ctx {
                                let mid_elapsed = stream_start.elapsed();
                                let input = fctx.to_finalization_input(
                                    TurnState::Failed,
                                    &accumulated_text,
                                    None,
                                    Some(code.clone()),
                                    None,
                                    None,
                                    web_search_completed_count,
                                    code_interpreter_completed_count,
                                    knowledge_call_count,
                                    first_token_time.map(|d| d.as_millis() as u64),
                                    Some(mid_elapsed.as_millis() as u64),
                                );
                                match fctx.finalization_svc.finalize_turn_cas(input).await {
                                    Ok(outcome) if outcome.won_cas => {
                                        let _ = tx
                                            .send(StreamEvent::Error(ErrorData {
                                                code: code.clone(),
                                                message,
                                            }))
                                            .await;
                                    }
                                    Ok(_) => {}
                                    Err(fe) => {
                                        warn!(error = %fe, "finalization failed on stream error");
                                        let _ = tx
                                            .send(StreamEvent::Error(ErrorData {
                                                code: code.clone(),
                                                message,
                                            }))
                                            .await;
                                    }
                                }
                            } else {
                                let _ = tx
                                    .send(StreamEvent::Error(ErrorData {
                                        code: code.clone(),
                                        message,
                                    }))
                                    .await;
                            }

                            // Metrics: mid-stream failure
                            if let Some(ref fctx) = fin_ctx {
                                let ms = stream_start.elapsed().as_secs_f64() * 1000.0;
                                fctx.metrics.record_stream_failed(&fctx.provider_id, &fctx.effective_model, &code);
                                fctx.metrics.record_stream_total_latency_ms(&fctx.provider_id, &fctx.effective_model, ms);
                            }

                            provider_stream.cancel();
                            let has_partial = !accumulated_text.is_empty();
                            return StreamOutcome {
                                terminal: StreamTerminal::Failed,
                                accumulated_text,
                                usage: None,
                                effective_model: model,
                                error_code: Some(code),
                                provider_response_id: None,
                                provider_partial_usage: has_partial,
                            };
                        }
                        None => {
                            // Stream ended — terminal captured by ProviderStream
                            break;
                        }
                    }
                }
            }
        }

        if cancelled {
            let elapsed = stream_start.elapsed();
            info!(
                terminal = "cancelled",
                duration_ms = elapsed.as_millis() as u64,
                "stream cancelled"
            );

            // Finalize cancelled turn — no SSE emission (stream already disconnected) (D3)
            if let Some(ref fctx) = fin_ctx {
                let input = fctx.to_finalization_input(
                    TurnState::Cancelled,
                    &accumulated_text,
                    None,
                    None,
                    None,
                    None,
                    web_search_completed_count,
                    code_interpreter_completed_count,
                    knowledge_call_count,
                    first_token_time.map(|d| d.as_millis() as u64),
                    Some(elapsed.as_millis() as u64),
                );
                if let Err(e) = fctx.finalization_svc.finalize_turn_cas(input).await {
                    warn!(error = %e, "finalization failed on cancelled stream");
                }

                // Metrics: cancelled stream
                let ms = elapsed.as_secs_f64() * 1000.0;
                fctx.metrics.record_cancel_effective(trigger::DISCONNECT);
                fctx.metrics.record_time_to_abort_ms(trigger::DISCONNECT, ms);
                fctx.metrics.record_stream_total_latency_ms(&fctx.provider_id, &fctx.effective_model, ms);
            }

            return StreamOutcome {
                terminal: StreamTerminal::Cancelled,
                accumulated_text,
                usage: None,
                effective_model: model,
                error_code: None,
                provider_response_id: None,
                provider_partial_usage: false,
            };
        }

        // Extract the terminal outcome from the provider stream
        let terminal = provider_stream.into_outcome().await;

        match terminal {
            TerminalOutcome::Completed {
                usage,
                content: _,
                citations,
                response_id,
                ..
            } => {
                let elapsed = stream_start.elapsed();
                info!(
                    terminal = "completed",
                    input_tokens = usage.input_tokens,
                    output_tokens = usage.output_tokens,
                    duration_ms = elapsed.as_millis() as u64,
                    "stream completed"
                );

                // Finalize first, then emit Done only if CAS winner (D3)
                if let Some(ref fctx) = fin_ctx {
                    let input = fctx.to_finalization_input(
                        TurnState::Completed,
                        &accumulated_text,
                        Some(usage),
                        None,
                        None,
                        Some(response_id.clone()),
                        web_search_completed_count,
                        code_interpreter_completed_count,
                        knowledge_call_count,
                        first_token_time.map(|d| d.as_millis() as u64),
                        Some(elapsed.as_millis() as u64),
                    );
                    match fctx.finalization_svc.finalize_turn_cas(input).await {
                        Ok(outcome) if outcome.won_cas => {
                            // P4-2: Map provider file_ids to internal UUIDs
                            let mapped = crate::domain::citation_mapping::map_citation_ids(
                                citations,
                                &provider_file_id_map,
                            );
                            if !mapped.is_empty() {
                                let _ = tx
                                    .send(StreamEvent::Citations(
                                        crate::domain::stream_events::CitationsData {
                                            items: mapped,
                                        },
                                    ))
                                    .await;
                            }
                            // Compute quota warnings post-commit (advisory, best-effort)
                            let quota_warnings = match fctx
                                .quota_warnings_provider
                                .get_quota_warnings(&fctx.scope, fctx.tenant_id, fctx.user_id)
                                .await
                            {
                                Ok(w) => Some(w),
                                Err(e) => {
                                    warn!(error = %e, "failed to compute quota_warnings");
                                    None
                                }
                            };
                            let _ = tx
                                .send(StreamEvent::Done(Box::new(DoneData {
                                    usage: Some(usage),
                                    effective_model: fctx.effective_model.clone(),
                                    selected_model: fctx.selected_model.clone(),
                                    quota_decision: fctx.quota_decision.clone(),
                                    downgrade_from: fctx.downgrade_from.clone(),
                                    downgrade_reason: fctx.downgrade_reason.clone(),
                                    quota_warnings,
                                })))
                                .await;
                        }
                        Ok(_) => { /* CAS loser — no SSE emission */ }
                        Err(fe) => {
                            warn!(error = %fe, "finalization failed on completed stream");
                            // Emit Done anyway so client isn't left hanging
                            let _ = tx
                                .send(StreamEvent::Done(Box::new(DoneData {
                                    usage: Some(usage),
                                    effective_model: fctx.effective_model.clone(),
                                    selected_model: fctx.selected_model.clone(),
                                    quota_decision: fctx.quota_decision.clone(),
                                    downgrade_from: fctx.downgrade_from.clone(),
                                    downgrade_reason: fctx.downgrade_reason.clone(),
                                    quota_warnings: None,
                                })))
                                .await;
                        }
                    }
                } else {
                    // No finalization context (unit tests) — emit directly
                    let mapped = crate::domain::citation_mapping::map_citation_ids(
                        citations,
                        &provider_file_id_map,
                    );
                    if !mapped.is_empty() {
                        let _ = tx
                            .send(StreamEvent::Citations(
                                crate::domain::stream_events::CitationsData { items: mapped },
                            ))
                            .await;
                    }
                    let _ = tx
                        .send(StreamEvent::Done(Box::new(DoneData {
                            usage: Some(usage),
                            effective_model: model.clone(),
                            selected_model: model.clone(),
                            quota_decision: "allow".into(),
                            downgrade_from: None,
                            downgrade_reason: None,
                            quota_warnings: None,
                        })))
                        .await;
                }

                // Metrics: completed stream
                if let Some(ref fctx) = fin_ctx {
                    let ms = stream_start.elapsed().as_secs_f64() * 1000.0;
                    fctx.metrics.record_stream_completed(&fctx.provider_id, &fctx.effective_model);
                    fctx.metrics.record_stream_total_latency_ms(&fctx.provider_id, &fctx.effective_model, ms);
                }

                return StreamOutcome {
                    terminal: StreamTerminal::Completed,
                    accumulated_text,
                    usage: Some(usage),
                    effective_model: model,
                    error_code: None,
                    provider_response_id: Some(response_id),
                    provider_partial_usage: false,
                };
            }
            TerminalOutcome::Incomplete { usage, reason, .. } => {
                let elapsed = stream_start.elapsed();
                warn!(
                    terminal = "incomplete",
                    reason = %reason,
                    duration_ms = elapsed.as_millis() as u64,
                    "stream incomplete"
                );

                // Incomplete maps to Completed in DB — provider finished but hit
                // max_output_tokens. From billing/persistence perspective this is
                // a completed turn with truncated content (see design D10).
                if let Some(ref fctx) = fin_ctx {
                    let input = fctx.to_finalization_input(
                        TurnState::Completed,
                        &accumulated_text,
                        Some(usage),
                        None,
                        None,
                        None,
                        web_search_completed_count,
                        code_interpreter_completed_count,
                        knowledge_call_count,
                        first_token_time.map(|d| d.as_millis() as u64),
                        Some(elapsed.as_millis() as u64),
                    );
                    match fctx.finalization_svc.finalize_turn_cas(input).await {
                        Ok(outcome) if outcome.won_cas => {
                            let quota_warnings = match fctx
                                .quota_warnings_provider
                                .get_quota_warnings(&fctx.scope, fctx.tenant_id, fctx.user_id)
                                .await
                            {
                                Ok(w) => Some(w),
                                Err(e) => {
                                    warn!(error = %e, "failed to compute quota_warnings");
                                    None
                                }
                            };
                            let _ = tx
                                .send(StreamEvent::Done(Box::new(DoneData {
                                    usage: Some(usage),
                                    effective_model: fctx.effective_model.clone(),
                                    selected_model: fctx.selected_model.clone(),
                                    quota_decision: fctx.quota_decision.clone(),
                                    downgrade_from: fctx.downgrade_from.clone(),
                                    downgrade_reason: fctx.downgrade_reason.clone(),
                                    quota_warnings,
                                })))
                                .await;
                        }
                        Ok(_) => {}
                        Err(fe) => {
                            warn!(error = %fe, "finalization failed on incomplete stream");
                            let _ = tx
                                .send(StreamEvent::Done(Box::new(DoneData {
                                    usage: Some(usage),
                                    effective_model: fctx.effective_model.clone(),
                                    selected_model: fctx.selected_model.clone(),
                                    quota_decision: fctx.quota_decision.clone(),
                                    downgrade_from: fctx.downgrade_from.clone(),
                                    downgrade_reason: fctx.downgrade_reason.clone(),
                                    quota_warnings: None,
                                })))
                                .await;
                        }
                    }
                } else {
                    let _ = tx
                        .send(StreamEvent::Done(Box::new(DoneData {
                            usage: Some(usage),
                            effective_model: model.clone(),
                            selected_model: model.clone(),
                            quota_decision: "allow".into(),
                            downgrade_from: None,
                            downgrade_reason: None,
                            quota_warnings: None,
                        })))
                        .await;
                }

                // Metrics: incomplete stream
                if let Some(ref fctx) = fin_ctx {
                    let ms = stream_start.elapsed().as_secs_f64() * 1000.0;
                    fctx.metrics.record_stream_incomplete(&fctx.provider_id, &fctx.effective_model, &reason);
                    fctx.metrics.record_stream_completed(&fctx.provider_id, &fctx.effective_model);
                    fctx.metrics.record_stream_total_latency_ms(&fctx.provider_id, &fctx.effective_model, ms);
                }

                return StreamOutcome {
                    terminal: StreamTerminal::Incomplete,
                    accumulated_text,
                    usage: Some(usage),
                    effective_model: model,
                    error_code: Some(format!("incomplete:{reason}")),
                    provider_response_id: None,
                    provider_partial_usage: false,
                };
            }
            TerminalOutcome::Failed { error, usage, .. } => {
                let raw_detail = error.raw_detail().map(ToOwned::to_owned);
                let (code, message) = normalize_error(&error);
                let elapsed = stream_start.elapsed();
                warn!(
                    terminal = "failed",
                    error_code = %code,
                    raw_detail = raw_detail.as_deref().unwrap_or(""),
                    duration_ms = elapsed.as_millis() as u64,
                    "stream failed"
                );

                // Finalize first, emit error only if CAS winner (D3)
                if let Some(ref fctx) = fin_ctx {
                    let input = fctx.to_finalization_input(
                        TurnState::Failed,
                        &accumulated_text,
                        usage,
                        Some(code.clone()),
                        None,
                        None,
                        web_search_completed_count,
                        code_interpreter_completed_count,
                        knowledge_call_count,
                        first_token_time.map(|d| d.as_millis() as u64),
                        Some(elapsed.as_millis() as u64),
                    );
                    match fctx.finalization_svc.finalize_turn_cas(input).await {
                        Ok(outcome) if outcome.won_cas => {
                            let _ = tx
                                .send(StreamEvent::Error(ErrorData {
                                    code: code.clone(),
                                    message,
                                }))
                                .await;
                        }
                        Ok(_) => {}
                        Err(fe) => {
                            warn!(error = %fe, "finalization failed on failed stream");
                            let _ = tx
                                .send(StreamEvent::Error(ErrorData {
                                    code: code.clone(),
                                    message,
                                }))
                                .await;
                        }
                    }
                } else {
                    let _ = tx
                        .send(StreamEvent::Error(ErrorData {
                            code: code.clone(),
                            message,
                        }))
                        .await;
                }

                // Metrics: failed stream (post-provider)
                if let Some(ref fctx) = fin_ctx {
                    let ms = stream_start.elapsed().as_secs_f64() * 1000.0;
                    fctx.metrics.record_stream_failed(&fctx.provider_id, &fctx.effective_model, &code);
                    fctx.metrics.record_stream_total_latency_ms(&fctx.provider_id, &fctx.effective_model, ms);
                }

                return StreamOutcome {
                    terminal: StreamTerminal::Failed,
                    accumulated_text,
                    usage,
                    effective_model: model,
                    error_code: Some(code),
                    provider_response_id: None,
                    provider_partial_usage: usage.is_some(),
                };
            }
            TerminalOutcome::ToolUse {
                tool_use_id,
                name,
                input,
            } => {
                if name == "search_knowledge"
                    && let Some(ref ks) = knowledge_search
                {
                        // Enforce per-message call limit — graceful degradation.
                        // Instead of failing the turn, inject a soft limit notice as a
                        // function_call_output so the model can still answer from whatever
                        // it has already retrieved.
                        if knowledge_call_count >= ks.max_calls {
                            warn!(
                                knowledge_call_count,
                                limit = ks.max_calls,
                                "knowledge search per-message limit reached, injecting soft limit response"
                            );
                            let raw_arguments =
                                serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_owned());
                            raw_input_items.push(serde_json::json!({
                                "type": "function_call",
                                "call_id": tool_use_id,
                                "name": "search_knowledge",
                                "arguments": raw_arguments,
                            }));
                            raw_input_items.push(serde_json::json!({
                                "type": "function_call_output",
                                "call_id": tool_use_id,
                                "output": "Search limit reached for this message. \
                                           Please answer based on the information already retrieved.",
                            }));
                            continue 'agentic;
                        }

                        knowledge_call_count += 1;

                        // Extract arguments. top_k from the model is capped at
                        // ks.top_k so the model cannot inflate retrieval cost.
                        let query = input
                            .get("query")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_owned();
                        let top_k = input
                            .get("top_k")
                            .and_then(|v| v.as_u64())
                            .map(|v| (v as usize).min(ks.top_k))
                            .unwrap_or(ks.top_k);
                        let raw_arguments =
                            serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_owned());

                        // Append the model's function_call item to replay history.
                        raw_input_items.push(serde_json::json!({
                            "type": "function_call",
                            "call_id": tool_use_id,
                            "name": "search_knowledge",
                            "arguments": raw_arguments,
                        }));

                        // Call the retriever.
                        let retrieval_start = std::time::Instant::now();
                        let retrieval_result = ks
                            .retriever
                            .retrieve(
                                ctx.clone(),
                                RetrievalRequest {
                                    query,
                                    top_k,
                                    chat_id: fin_ctx
                                        .as_ref()
                                        .map_or_else(String::new, |f| f.chat_id.to_string()),
                                    vector_store_id: ks.vector_store_id.clone(),
                                    upstream_alias: ks.upstream_alias.clone(),
                                    api_version: ks.api_version.clone(),
                                },
                            )
                            .await;
                        let retrieval_ms =
                            retrieval_start.elapsed().as_secs_f64() * 1000.0;

                        let output_text = match retrieval_result {
                            Ok(raw_chunks) => {
                                let chunks =
                                    post_process_chunks(raw_chunks, ks.max_chunk_chars);
                                if let Some(ref fctx) = fin_ctx {
                                    fctx.metrics.record_knowledge_search("ok");
                                    fctx.metrics
                                        .record_knowledge_search_latency_ms(retrieval_ms);
                                    fctx.metrics
                                        .record_knowledge_search_chunks(chunks.len() as f64);

                                    // Persist increment to chat_turns so the
                                    // orphan watchdog can recover the count if
                                    // the pod dies before stream finalization.
                                    // Same pattern as web_search / code_interpreter.
                                    if let Ok(conn) = fctx.db.conn() {
                                        if let Err(e) = fctx.turn_repo.increment_tool_calls(
                                            &conn,
                                            &fctx.scope,
                                            fctx.turn_id,
                                            ToolCallType::FileSearch,
                                        ).await {
                                            warn!(
                                                turn_id = %fctx.turn_id,
                                                error = %e,
                                                "failed to persist file_search_completed_count"
                                            );
                                        }
                                    } else {
                                        warn!(
                                            turn_id = %fctx.turn_id,
                                            "failed to acquire DB conn for file_search_completed_count"
                                        );
                                    }
                                }
                                if ks.use_search_result_blocks {
                                    format_chunks_as_search_result_json(&chunks)
                                } else {
                                    format_chunks_as_text(&chunks)
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "knowledge retrieval failed");
                                if let Some(ref fctx) = fin_ctx {
                                    fctx.metrics.record_knowledge_search("error");
                                    fctx.metrics
                                        .record_knowledge_search_latency_ms(retrieval_ms);
                                }
                                // Distinct from the legitimate "empty result"
                                // message so the model can tell a retriever
                                // failure from a zero-hit query and adjust.
                                "Knowledge search failed; answer without retrieved context."
                                    .to_owned()
                            }
                        };

                        // Append the function_call_output item to replay history.
                        raw_input_items.push(serde_json::json!({
                            "type": "function_call_output",
                            "call_id": tool_use_id,
                            "output": output_text,
                        }));

                        continue 'agentic;
                }

                if name == "timer"
                    && let Some(ref tp) = timer
                {
                    // Timers are scoped per-chat. When there is no finalization
                    // context (unit tests) the chat scope is the empty string.
                    let chat_id = fin_ctx
                        .as_ref()
                        .map_or_else(String::new, |f| f.chat_id.to_string());
                    let raw_arguments =
                        serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_owned());

                    // Always replay the model's function_call into history.
                    raw_input_items.push(serde_json::json!({
                        "type": "function_call",
                        "call_id": tool_use_id,
                        "name": "timer",
                        "arguments": raw_arguments,
                    }));

                    // Soft per-message cap — degrade gracefully instead of failing.
                    if timer_call_count >= tp.max_calls {
                        warn!(
                            timer_call_count,
                            limit = tp.max_calls,
                            "timer per-message limit reached, injecting soft limit response"
                        );
                        raw_input_items.push(serde_json::json!({
                            "type": "function_call_output",
                            "call_id": tool_use_id,
                            "output": "Timer call limit reached for this message. \
                                       Please answer based on the information already gathered.",
                        }));
                        continue 'agentic;
                    }
                    timer_call_count += 1;

                    let action = input
                        .get("action")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let timer_name = input
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("default");

                    let output = match action {
                        "start" => {
                            tp.store.start(&chat_id, timer_name);
                            format!("Timer '{timer_name}' started.")
                        }
                        "elapsed" => match tp.store.elapsed(&chat_id, timer_name) {
                            Some(d) => {
                                format!("Timer '{timer_name}': {} elapsed.", format_duration(d))
                            }
                            None => format!("No timer named '{timer_name}' is running."),
                        },
                        "reset" => {
                            if tp.store.reset(&chat_id, timer_name) {
                                format!("Timer '{timer_name}' reset.")
                            } else {
                                format!("No timer named '{timer_name}' to reset.")
                            }
                        }
                        "list"
                        | "show current timers"
                        | "show active timers"
                        | "show timers" => {
                            let timers = tp.store.list(&chat_id);
                            if timers.is_empty() {
                                "No active timers.".to_owned()
                            } else {
                                let body = timers
                                    .iter()
                                    .map(|(n, d)| format!("{n} ({})", format_duration(*d)))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                format!("Active timers: {body}.")
                            }
                        }
                        other => format!(
                            "Unknown timer action '{other}'. \
                             Valid actions: start, elapsed, reset, list."
                        ),
                    };

                    raw_input_items.push(serde_json::json!({
                        "type": "function_call_output",
                        "call_id": tool_use_id,
                        "output": output,
                    }));
                    continue 'agentic;
                }

                // REST connector tools. Dispatched after the built-in branches
                // so connectors can never shadow `timer` / `search_knowledge`.
                if let Some(ref rp) = rest
                    && rp.registry.contains(&name)
                {
                    let raw_arguments =
                        serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_owned());

                    // Always replay the model's function_call into history.
                    raw_input_items.push(serde_json::json!({
                        "type": "function_call",
                        "call_id": tool_use_id,
                        "name": name,
                        "arguments": raw_arguments,
                    }));

                    // Soft per-message cap — degrade gracefully instead of failing.
                    if rest_call_count >= rp.max_calls {
                        warn!(
                            rest_call_count,
                            limit = rp.max_calls,
                            tool = %name,
                            "rest connector per-message limit reached, injecting soft limit response"
                        );
                        raw_input_items.push(serde_json::json!({
                            "type": "function_call_output",
                            "call_id": tool_use_id,
                            "output": "REST connector call limit reached for this message. \
                                       Please answer based on the information already gathered.",
                        }));
                        continue 'agentic;
                    }
                    rest_call_count += 1;

                    let output = match rp.registry.build_request(&name, &input) {
                        Ok(req) => match rp.client.call(ctx.clone(), req).await {
                            Ok(resp) => format_rest_output(&resp),
                            Err(e) => {
                                warn!(tool = %name, error = %e, "rest connector call failed");
                                try_hardcoded_fallback(&name)
                                    .unwrap_or_else(|| format_rest_error(&e))
                            }
                        },
                        Err(e) => {
                            warn!(tool = %name, error = %e, "rest connector request build failed");
                            format!(
                                "The {name} tool could not be called with those arguments: {e}. \
                                 Check the required parameters and try again."
                            )
                        }
                    };

                    raw_input_items.push(serde_json::json!({
                        "type": "function_call_output",
                        "call_id": tool_use_id,
                        "output": output,
                    }));
                    continue 'agentic;
                }

                // Unrecognised tool or feature disabled — treat as a provider failure.
                warn!(tool = %name, "unexpected ToolUse outcome; finalizing as failed");
                let code = "unexpected_tool_use".to_owned();
                let message = "Provider requested an unsupported function tool".to_owned();
                if let Some(ref fctx) = fin_ctx {
                    let elapsed = stream_start.elapsed();
                    let finput = fctx.to_finalization_input(
                        TurnState::Failed,
                        &accumulated_text,
                        None,
                        Some(code.clone()),
                        None,
                        None,
                        web_search_completed_count,
                        code_interpreter_completed_count,
                        knowledge_call_count,
                        first_token_time.map(|d| d.as_millis() as u64),
                        Some(elapsed.as_millis() as u64),
                    );
                    match fctx.finalization_svc.finalize_turn_cas(finput).await {
                        Ok(outcome) if outcome.won_cas => {
                            let _ = tx
                                .send(StreamEvent::Error(ErrorData {
                                    code: code.clone(),
                                    message,
                                }))
                                .await;
                        }
                        Ok(_) => {}
                        Err(fe) => {
                            warn!(error = %fe, "finalization failed on unexpected tool use");
                            let _ = tx
                                .send(StreamEvent::Error(ErrorData {
                                    code: code.clone(),
                                    message,
                                }))
                                .await;
                        }
                    }
                    let ms = stream_start.elapsed().as_secs_f64() * 1000.0;
                    fctx.metrics
                        .record_stream_failed(&fctx.provider_id, &fctx.effective_model, &code);
                    fctx.metrics.record_stream_total_latency_ms(
                        &fctx.provider_id,
                        &fctx.effective_model,
                        ms,
                    );
                } else {
                    let _ = tx
                        .send(StreamEvent::Error(ErrorData {
                            code: code.clone(),
                            message,
                        }))
                        .await;
                }
                let has_partial = !accumulated_text.is_empty();
                return StreamOutcome {
                    terminal: StreamTerminal::Failed,
                    accumulated_text,
                    usage: None,
                    effective_model: model,
                    error_code: Some(code),
                    provider_response_id: None,
                    provider_partial_usage: has_partial,
                };
            }
        }

        } // end 'agentic loop
    }.instrument(span))
}

/// Format a [`std::time::Duration`] as a compact human-readable string for the
/// `timer` tool output, e.g. `5s`, `3m 12s`, `1h 2m 3s`. A zero duration renders
/// as `0s`.
#[allow(clippy::integer_division)]
fn format_duration(d: std::time::Duration) -> String {
    let total = d.as_secs();
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;

    let mut parts = Vec::new();
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{seconds}s"));
    }
    parts.join(" ")
}

/// Format a REST connector [`RestResponse`] as the `function_call_output` text
/// fed back to the model: a status/content-type header line followed by the
/// (possibly truncated) body.
fn format_rest_output(resp: &RestResponse) -> String {
    let ct = resp.content_type.as_deref().unwrap_or("unknown");
    let mut out = format!("HTTP {} ({ct})\n{}", resp.status, resp.body_text);
    if resp.truncated {
        out.push_str("\n\n[response truncated at byte cap]");
    }
    out
}

/// Format a [`RestError`] as a graceful `function_call_output` string so the
/// model can recover instead of failing the turn.
fn format_rest_error(e: &RestError) -> String {
    format!("The REST connector call did not succeed: {e}. Answer without that data if possible.")
}

/// Hardcoded fallback content for `search_confluence` when the remote
/// Confluence instance is unreachable. Returned to the model so it can still
/// answer from cached data instead of giving a generic "service unavailable".
const SEARCH_CONFLUENCE_FALLBACK: &str = "\
Design Summary
JIRA


Business requirements document link
Event Manager
PoC / mockups / research


Problem Overview
Acronis Cyber Cloud currently has no simple, reliable mechanism to enable event-responsive behavior that is accessible via standard Acronis domain model semantics (i.e. Acronis JWT, roles, etc...)
Some small subset of applications use amqp, but there's a variety of practical and architectural problems that prevent more widespread usage/adoption
Our existing usage of amqp does not have any form of archive allowing event playback, so missed messages are unrecoverable
Many applications rely upon polling to receive updates, which causes unnecessary load and causes direct coupling of applications, i.e. one application being down will directly cause many others to fail.
Task manager in particular is used/abused as a long-running event manager, with heavy polling load.
Many application designs can be simplified with a common event platform providing push delivery, smart polling support and full event playback.
New Components
Event Producer Library
Event Ingest Manager
NATS (3rd Party)
Event Delivery Manager
Event Consumer Library
Relevant Existing Components
Event Archive
Requirements, Design And Test Strategy Outline
 #
Requirement
Design Details
1\tFunctional requirements\t
1.1\tAt least once delivery guarantee option\tTopics with configurable durability can provide guarantees about message delivery due to persistence to durable media, in this case, PostgreSQL.
1.2\tBest-effort delivery option\t
Topics which do not require strict ordering or delivery guarantees may be delivered in non-persisted best-effort mode.
Producers and consumers should expect the possibility of out of order and/or lost messages.
1.3\tMultiple independent, configurable event topics\t
Different topics will require different configuration parameters.
Topics and sharding will be configured via JSON in a repository.
1.4\tReliable, global ordering of events within a persisted topic\tSo that consumers may rely on the causal relationship preserved in time ordering of events, topics will guarantee causal ordering (may implement stricter ordering)
1.5\tEvent durability at the earliest possible opportunity\t
Producers with databases will persist events in the same database transaction where possible to prevent lost events.
Producers without databases may make synchronous calls to Event Ingest Manager's API to POST events, and fail their own business transaction if the event cannot be accepted.
1.6\tEnable consumers to use event collaboration\tBecause causal relationship is preserved, consumers may rely upon events to form accurate local views of information as required, or update their corresponding state as required reliably.
1.7\tProvide in-order delivery of events\t
Event Delivery Manager may redeliver previous batches, but it will never deliver newer batches until previous batches have been accepted.
Consumers do not need to handle the case of buffering or deciphering sparse events: either the event is below the last delivered counter and therefore a redelivery, or it is new and in order.
1.8\t
Provide interface to publish events
Event Ingest Manager provides a REST API for producers to publish events.
1.9\tEvent Short Polling\tEvent Delivery Manager provides a REST API for consumers to frequently poll for new events, with a server-side cursor tracking the consumer's confirmed deliveries (delivered to complete connection termination or optional last-received parameter).
1.10\tEvent Long Polling\tEvent Delivery Manager provides a REST API for consumers to open a connection waiting for the next message(s) matching their subscription.
1.11\tEvent Push Delivery\tEvent Delivery Manager provides a REST API for consumers to register a web endpoint for EDM to push events to in batches (as small as one).
1.12\tEvent Replay\t
Event Delivery Manager ensures that Event Archive receives all messages as a special subscriber, and the event archive API allows both simple and complex filtering event playback.
Event Archive is also used internally, i.e. for Event Delivery Manager pod start/restart.
1.13\tEvent Archive\tEvent Archive component provides full event archive functionality using existing API.
1.14\tSupport Cloud Events Spec\tEvent Manager follows the Cloud Events spec
2\tPerformance\t
2.1\tPlanned Throughput\t
For the prototype release, we expect trivial load from a single test topic, occasional events for testing with no continuous or heavy load.
2.2\tDesign Throughput\t
The system is currently designed to support Max 10'000 events/sec, Avg: 1'000/sec, Min 1'000/sec for a big message of 5 user-defined fields size of the event is close to 1024B. In this way amount of traffic shall be around 10MB/sec.

2.3\t
Minimize Delivery Latency
The design goal is to minimize delivery latency for short-duration pollers and push recipients without sacrificing any guarantees.
2.3\t
Sharding
The overall architecture and guarantees are intended to allow sharding by topic.
Event Delivery Manager implements static, topic-based sharding.
2.4\tHorizontal Scaling\t
Event Ingest Manager and Event Delivery Manager are both designed for horizontal scaling beyond database performance limits.
NATS uses a highly scalable architecture, and because there's database transactions involved, NATS throughput is not expected to be a limiting factor.
3\tLongHaul\t
3.1\tTested as Platform\tAs different real workflows are added, existing long haul tests will test Event Manager, or new tests should be created as required for those features as normal
4\tSecurity\t
4.1\tProducer Authentication & Authorization\t
oauth2
scope \"urn:acronis.com:event-ingest-manager:event-ingest-manager:topics:<topic>:publisher|push \".
4.2\tConsumer Authentication & Authorization\t
oauth2
scope \"urn:acronis.com:event-delivery-manager:event-delivery-manager:topics:<topic>:subscriber\".
4.3\tWebhook Authentication & Authorization\t
Consumer endpoints
oauth2
scope \"urn:acronis.com:event-delivery-manager:event-delivery-manager:topics:<topic>:delivery\".
4.4\tNew 3rd Party - NATS\t
NATS is a well regarded, distributed, fault tolerant messaging platform.
We will utilize it in ephemeral, at most once mode, and implement our own durability mechanism integrated into our service framework and platform.
4.5\tNATS Authentication\t
Username/Password stored in Kubernetes Secrets in prod, no auth on dev stands
4.6\tNATS Allowed Usage\t
Currently, NATS will only be available to event-ingest-manager and event-delivery-manager.
NATS Streaming was evaluated and rejected explicitly, so it should not be used.
NATS is only intended to be used between two closely related functions within one overall service domain for the purposes of scalability.  It shall not be used as a general API for services, instead, Event Manager itself must be used in such cases.
4.7\tPersonal Data/Privacy\t
Currently, only a test topic will be included in event manager.
Personal data and privacy considerations should be made on a topic-by-topic basis with specific use cases subject to security review.
As a starting policy, each new topic or type would require architectural and security review & approval.  This may be reviewed later if clearer procedures can be drafted from experience.
5\tDatabase requirements\t
5.1\tPostgres/Patroni Used for All State\t
Both event-ingest-manager and event-delivery-manager use PostgreSQL for storing state.
5.2\tStandard Patroni Instance\tThe standard cloud patroni cluster will be used in production.
5.3\tNo current migrations\t
The database schemas are currently simple and only column additions and other simple operations are currently planned.
5.4\tDatabase Performance\tA dedicated testing suite was used to evaluate various options, including database tuning parameters.  We have good understanding of parameters necessary for tuning, and a plan for applied testing.
6\tOperational requirements\t
6.1\tDeployment Requirements\t
All components deployed to kubernetes via standard mechanisms.
6.2\t
Cloud Requirements
Review Tickets

Acronis Event Ingest Manger
Event Ingest Manager Scaling Guide

Event Delivery Manager SLI
Event Delivery Manager Scaling Guide
Platform Event Delivery Manager Troubleshooting
DCO Training (EDM)
6.3\tState\t
Event Ingest Manager: Stateless 
Event Delivery Manager: Stateful. The deployment is done via a StatefulSet, each pod is responsible for storing in-memory events for a subset of subscribers. On startup, the service retrieves missing subscriber events from Event Archive and NATS subscription to Event Ingest Manager.
NATS: Stateless
6.4\tSharding\t
Event Ingest Manager: None 
Event Delivery Manager: Static sharding by topic.  Horizontally scalable within a shard.
NATS: None
6.5\tHigh Availability\t
Event Ingest Manager: Stateless HA Application
Event Delivery Manager: Graceful failover and restart of stateful aspects and horizontal scalability with hot spare
NATS: Core NATS supports full mesh clustering with self-healing features to provide high availability to clients.
6.6\tZero-downtime update\t
All: Supported by design due to k8s deployment with stable database schema
6.7\tKubernetes ready\tAll
6.10\tNetwork\tPrivate for prototype and initial phase until public API epics
6.11\tMonitoring & Metrics\t
Container monitoring comes for free with k8s deployment.
We will also export metrics via Prometheus at /metrics endpoint.
Specific metrics to be evaluated by implementation review
6.12\tLogging\t
Kibana Logging
All services will expose logs to Kibana via ELK
Logs will be in JSON formal so searching through Kibana is easier
Mapping
Glossary
EIM: Event Ingest Manager
EDM: Event Delivery Manager
NATS: Neural Autonomic Transport System, an open source application
Logical And Deployment Diagram

Workflow Diagrams
@startuml
boundary \"Producer Service\" as prod
database \"Producer DB\" as proddb
participant \"Event Ingest Manager\" as eim
queue \"NATS\" as nats
participant \"Event Delivery Manager\" as edm
participant \"Event Archive\" as ea
database \"Event Archive DB\" as eadb
boundary \"Consumer Service\" as cons
autonumber
prod -> proddb: Producer persists event to database in original tx
prod -> eim: Publish the event
eim -> nats: Publish the event
nats -> edm: Receive the event (fanout)
alt Happens asynchronously
\tedm -> ea: Push the event to special archive subscriber
\tea -> eadb: Persist the event
\tedm -> nats: Ack the event
\tnats -> eim: Propagate the ack
else EDM unable to ack
\tloop Until acks begin again
\t\teim -> nats: Resend events intelligently
\tend
end
Group Push Delivery
\tedm -> cons: Push the event
end
...
autonumber stop
Group Pull Consumers
\tcons -> edm: Poll for events
\tcons -> ea: Replay or query archive
end
@enduml

@startuml
boundary \"Producer Service\" as prod
participant \"Event Ingest Manager\" as eim
database \"Event Ingest Manager DB\" as eimdb
queue \"NATS\" as nats
participant \"Event Delivery Manager\" as edm
participant \"Event Archive\" as ea
database \"Event Archive DB\" as eadb
boundary \"Consumer Service\" as cons
autonumber
prod -> eim: Publish the event synchronously
eim -> eimdb: Persist the event
eim -> nats: Publish the event
nats -> edm: Receive the event (fanout)
alt Happens asynchronously
\tedm -> ea: Push the event to special archive subscriber
\tea -> eadb: Persist the event
\tedm -> nats: Ack the event
\tnats -> eim: Propagate the ack
else EDM unable to ack
\tloop Until acks begin again
\t\teim -> nats: Resend events intelligently
\tend
end
Group Push Delivery
\tedm -> cons: Push the event
end
...
autonumber stop
Group Pull Consumers
\tcons -> edm: Poll for events
\tcons -> ea: Replay or query archive
end
@enduml

@startuml
boundary \"Producer Service\" as prod
participant \"Event Ingest Manager\" as eim
database \"Event Ingest Manager DB\" as eimdb
queue \"NATS\" as nats
participant \"Event Delivery Manager\" as edm
participant \"Event Archive\" as ea
database \"Event Archive DB\" as eadb
boundary \"Consumer Service\" as cons
autonumber
prod -> eim: Publish the event
eim -> nats: Publish the event
nats -> edm: Receive the event (fanout)
Group Push Delivery
\tedm -> cons: Push the event
end
...
autonumber stop
Group Pull Consumers
\tcons -> edm: Poll for events
\tcons -> ea: Replay or query archive
end
@enduml
Technologies Considered
Scalability Fanout
NATS was chosen because it is the most resilient technology available.  From our research and testing, NATS gives the most reliable performance with the least operational intervention.
Rabbitmq was considered and rejected because of past negative experience and inferior scaling and resiliency.
Raw HTTP communication between ingest and delivery was considered, using either some shared configuration or intermediate proxy.  However, this is a dramatically more complex solution with no real benefit beyond avoidance of new technology.
Message Durability
PostgreSQL was chosen because the performance was similar to or beyond other options, and Acronis has good experience with PostgreSQL in terms of reliability and operational performance.
NATS Streaming was considered, but offered no performance improvements but introduced a new and unfamiliar data persistence layer that provided no benefit, because consumers would not be able to directly use it because it does not support the various Acronis authorization and tenant filtering behaviors.
";

/// If the tool has a hardcoded fallback and the content is non-empty, return it
/// prefixed with a notice. Otherwise return `None` so the caller falls through
/// to the generic error message.
fn try_hardcoded_fallback(tool_name: &str) -> Option<String> {
    let content = match tool_name {
        "search_confluence" => SEARCH_CONFLUENCE_FALLBACK,
        _ => return None,
    };
    if content.trim().is_empty() {
        return None;
    }
    info!(tool = %tool_name, "REST call failed; serving hardcoded fallback content");
    Some(format!(
        "[Fallback — live service was unreachable, showing cached data]\n\n{content}"
    ))
}

/// Post-process raw retrieval results before injecting them into the model context.
///
/// Steps applied in order:
/// 1. **Sort** by relevance score descending (highest score first).
/// 2. **Deduplicate** — remove chunks whose text is identical to an earlier chunk.
///    Prevents wasting tokens on overlapping windows from the same document.
/// 3. **Assign stable chunk indices** — appends `#chunk/{i}` to each `source_uri`
///    so citations are traceable back to a specific chunk position.
/// 4. **Truncate** each chunk's text to `max_chars` to bound context token cost.
fn post_process_chunks(mut chunks: Vec<RetrievedChunk>, max_chars: usize) -> Vec<RetrievedChunk> {
    // 1. Sort by score descending.
    chunks.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // 2. Deduplicate by exact text content.
    let mut seen = std::collections::HashSet::new();
    chunks.retain(|c| seen.insert(c.text.clone()));

    // 3. Assign stable chunk index to source_uri.
    for (i, chunk) in chunks.iter_mut().enumerate() {
        // Strip any existing fragment before appending so re-runs are idempotent.
        if let Some(base) = chunk.source_uri.split_once('#') {
            chunk.source_uri = format!("{}#chunk/{i}", base.0);
        } else {
            chunk.source_uri = format!("{}#chunk/{i}", chunk.source_uri);
        }
    }

    // 4. Truncate text at a valid UTF-8 char boundary.
    for chunk in &mut chunks {
        if chunk.text.len() > max_chars {
            let mut boundary = max_chars;
            while !chunk.text.is_char_boundary(boundary) {
                boundary -= 1;
            }
            chunk.text.truncate(boundary);
        }
    }

    chunks
}

/// Format retrieved knowledge chunks as Anthropic `search_result` JSON blocks.
///
/// Produces a JSON array of `search_result` objects. When this string is set as
/// `function_call_output.output`, the Anthropic adapter's `parse_tool_result_content`
/// recognises the typed-block array and forwards it verbatim as `tool_result` content,
/// enabling Anthropic's native citation machinery.
fn format_chunks_as_search_result_json(chunks: &[RetrievedChunk]) -> String {
    if chunks.is_empty() {
        return serde_json::json!([{
            "type": "text",
            "text": "No relevant content found."
        }])
        .to_string();
    }
    let blocks: Vec<serde_json::Value> = chunks
        .iter()
        .map(|chunk| {
            serde_json::json!({
                "type": "search_result",
                "source": chunk.source_uri,
                "title": chunk.title,
                "content": [{"type": "text", "text": chunk.text}]
            })
        })
        .collect();
    serde_json::Value::Array(blocks).to_string()
}

/// Format retrieved knowledge chunks as a text block for the LLM.
///
/// Uses `[SOURCE_N]` labels so the model can inline-cite them naturally.
/// The Responses API does not support Anthropic-style `search_result` content
/// blocks, so plain text with explicit source labels is the correct approach
/// for OpenAI/Azure providers.
fn format_chunks_as_text(chunks: &[RetrievedChunk]) -> String {
    use std::fmt::Write as _;
    if chunks.is_empty() {
        return "No relevant content found.".to_owned();
    }
    chunks
        .iter()
        .enumerate()
        .fold(String::new(), |mut out, (i, chunk)| {
            write!(
                out,
                "[SOURCE_{}] \"{}\"\n{}\n\n",
                i + 1,
                chunk.title,
                chunk.text,
            )
            .ok();
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(source_uri: &str, title: &str, text: &str) -> RetrievedChunk {
        RetrievedChunk {
            source_uri: source_uri.to_owned(),
            title: title.to_owned(),
            text: text.to_owned(),
            score: 1.0,
        }
    }

    #[test]
    fn format_rest_output_renders_status_content_type_and_body() {
        let resp = RestResponse {
            status: 200,
            content_type: Some("application/json".to_owned()),
            body_text: "{\"ok\":true}".to_owned(),
            truncated: false,
        };
        let out = format_rest_output(&resp);
        assert!(out.starts_with("HTTP 200 (application/json)\n"));
        assert!(out.contains("{\"ok\":true}"));
        assert!(!out.contains("truncated"));
    }

    #[test]
    fn format_rest_output_notes_truncation_and_unknown_content_type() {
        let resp = RestResponse {
            status: 200,
            content_type: None,
            body_text: "partial".to_owned(),
            truncated: true,
        };
        let out = format_rest_output(&resp);
        assert!(out.starts_with("HTTP 200 (unknown)\n"));
        assert!(out.contains("[response truncated at byte cap]"));
    }

    #[test]
    fn format_search_result_empty_returns_text_block_with_no_content_message() {
        let json = format_chunks_as_search_result_json(&[]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array());
        assert_eq!(v[0]["type"], "text");
        assert_eq!(v[0]["text"], "No relevant content found.");
    }

    #[test]
    fn format_search_result_single_chunk_has_correct_fields() {
        let chunks = [chunk("kb://doc/1#chunk/0", "Doc 1", "Some text")];
        let json = format_chunks_as_search_result_json(&chunks);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["type"], "search_result");
        assert_eq!(v[0]["source"], "kb://doc/1#chunk/0");
        assert_eq!(v[0]["title"], "Doc 1");
        assert_eq!(v[0]["content"][0]["type"], "text");
        assert_eq!(v[0]["content"][0]["text"], "Some text");
    }

    #[test]
    fn format_search_result_multiple_chunks_all_present() {
        let chunks = [
            chunk("kb://doc/1#chunk/0", "Doc 1", "Text one"),
            chunk("kb://doc/2#chunk/1", "Doc 2", "Text two"),
        ];
        let json = format_chunks_as_search_result_json(&chunks);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert_eq!(v[0]["type"], "search_result");
        assert_eq!(v[1]["source"], "kb://doc/2#chunk/1");
        assert_eq!(v[1]["title"], "Doc 2");
    }

    #[test]
    fn format_search_result_all_blocks_have_type_field_for_passthrough() {
        // parse_tool_result_content in anthropic_messages forwards a JSON array
        // verbatim only when every element has a "type" field.
        let chunks = [
            chunk("kb://doc/1#chunk/0", "Doc 1", "Hello"),
            chunk("kb://doc/2#chunk/1", "Doc 2", "World"),
        ];
        let json = format_chunks_as_search_result_json(&chunks);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = v.as_array().unwrap();
        assert!(arr.iter().all(|block| block.get("type").is_some()));
    }

    // ── format_chunks_as_text ──

    fn chunk_with_score(source_uri: &str, title: &str, text: &str, score: f32) -> RetrievedChunk {
        RetrievedChunk {
            source_uri: source_uri.to_owned(),
            title: title.to_owned(),
            text: text.to_owned(),
            score,
        }
    }

    #[test]
    fn format_text_empty_returns_no_content_message() {
        let out = format_chunks_as_text(&[]);
        assert_eq!(out, "No relevant content found.");
    }

    #[test]
    fn format_text_single_chunk_uses_source_1_label() {
        let chunks = [chunk("kb://doc/1", "Title", "Body text")];
        let out = format_chunks_as_text(&chunks);
        assert!(out.contains("[SOURCE_1]"));
        assert!(out.contains("\"Title\""));
        assert!(out.contains("Body text"));
    }

    #[test]
    fn format_text_multiple_chunks_numbered_sequentially() {
        let chunks = [
            chunk("kb://doc/1", "First", "aaa"),
            chunk("kb://doc/2", "Second", "bbb"),
            chunk("kb://doc/3", "Third", "ccc"),
        ];
        let out = format_chunks_as_text(&chunks);
        assert!(out.contains("[SOURCE_1]"));
        assert!(out.contains("[SOURCE_2]"));
        assert!(out.contains("[SOURCE_3]"));
        // Labels must appear in order.
        let p1 = out.find("[SOURCE_1]").unwrap();
        let p2 = out.find("[SOURCE_2]").unwrap();
        let p3 = out.find("[SOURCE_3]").unwrap();
        assert!(p1 < p2 && p2 < p3);
    }

    // ── post_process_chunks ──

    #[test]
    fn post_process_sorts_by_score_descending() {
        let chunks = vec![
            chunk_with_score("kb://a", "A", "text-a", 0.1),
            chunk_with_score("kb://b", "B", "text-b", 0.9),
            chunk_with_score("kb://c", "C", "text-c", 0.5),
        ];
        let out = post_process_chunks(chunks, 1000);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].text, "text-b");
        assert_eq!(out[1].text, "text-c");
        assert_eq!(out[2].text, "text-a");
    }

    #[test]
    fn post_process_deduplicates_identical_text() {
        let chunks = vec![
            chunk_with_score("kb://a", "A", "same", 0.9),
            chunk_with_score("kb://b", "B", "same", 0.8),
            chunk_with_score("kb://c", "C", "different", 0.5),
        ];
        let out = post_process_chunks(chunks, 1000);
        assert_eq!(out.len(), 2);
        // Sort happens first → dedup keeps the highest-scoring duplicate.
        assert_eq!(out[0].text, "same");
        assert_eq!(out[0].source_uri, "kb://a#chunk/0");
        assert_eq!(out[1].text, "different");
    }

    #[test]
    fn post_process_assigns_stable_chunk_index_to_source_uri() {
        let chunks = vec![
            chunk_with_score("kb://doc/x", "X", "first", 0.9),
            chunk_with_score("kb://doc/y", "Y", "second", 0.5),
        ];
        let out = post_process_chunks(chunks, 1000);
        assert_eq!(out[0].source_uri, "kb://doc/x#chunk/0");
        assert_eq!(out[1].source_uri, "kb://doc/y#chunk/1");
    }

    #[test]
    fn post_process_replaces_existing_fragment_when_reassigning_index() {
        // Idempotence: if post_process_chunks runs twice, the existing
        // `#chunk/{i}` fragment is stripped and re-assigned instead of
        // doubling up (e.g., `#chunk/0#chunk/0`).
        let chunks = vec![chunk_with_score("kb://doc/x#chunk/9", "X", "once", 0.9)];
        let out = post_process_chunks(chunks, 1000);
        assert_eq!(out[0].source_uri, "kb://doc/x#chunk/0");
    }

    #[test]
    fn post_process_truncates_text_to_max_chars() {
        let chunks = vec![chunk_with_score("kb://doc/x", "X", "abcdefghij", 0.9)];
        let out = post_process_chunks(chunks, 5);
        assert_eq!(out[0].text, "abcde");
    }

    #[test]
    fn post_process_truncates_at_utf8_char_boundary() {
        // "héllo" — 'é' is two bytes (0xc3 0xa9) at positions 1..3.
        // A naive truncate(2) would split inside 'é'. post_process_chunks
        // must find a char boundary and truncate to a valid UTF-8 string.
        let chunks = vec![chunk_with_score("kb://doc/x", "X", "héllo", 0.9)];
        let out = post_process_chunks(chunks, 2);
        // Must not panic and must be valid UTF-8. Boundary-safe truncation
        // yields either 1 byte ("h") or stays at 2 if it lands on a boundary;
        // the actual result here is "h" since byte 2 is inside 'é'.
        assert!(out[0].text.is_char_boundary(out[0].text.len()));
        assert_eq!(out[0].text, "h");
    }

    #[test]
    fn post_process_empty_input_returns_empty() {
        let out = post_process_chunks(vec![], 1000);
        assert!(out.is_empty());
    }

    #[test]
    #[allow(clippy::duration_suboptimal_units)]
    fn format_duration_renders_compact_units() {
        use std::time::Duration;
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(5)), "5s");
        assert_eq!(format_duration(Duration::from_secs(72)), "1m 12s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(3723)), "1h 2m 3s");
        // Sub-second durations round down to 0s.
        assert_eq!(format_duration(Duration::from_millis(900)), "0s");
        // Whole minutes omit the seconds component.
        assert_eq!(format_duration(Duration::from_secs(120)), "2m");
    }
}
