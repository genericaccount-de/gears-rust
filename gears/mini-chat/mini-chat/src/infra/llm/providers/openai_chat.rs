//! `OpenAI` Chat Completions API adapter (`/v1/chat/completions`).
//!
//! Implements [`LlmProvider`] by converting [`LlmRequest`] to the Chat
//! Completions API format, proxying through OAGW, parsing SSE events, and
//! translating them to the shared `TranslatedEvent` contract.

use std::sync::Arc;

use bytes::Bytes;
use futures::StreamExt;
use oagw_sdk::error::StreamingError;
use oagw_sdk::sse::{FromServerEvent, ServerEvent, ServerEventsResponse, ServerEventsStream};
use oagw_sdk::{Body, ServiceGatewayClientV1};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use toolkit_security::SecurityContext;
use tracing::debug;

use crate::infra::llm::request::{ContentPart as MessageContentPart, LlmTool, Role};
use crate::infra::llm::{
    ClientSseEvent, LlmProviderError, LlmRequest, NonStreaming, ProviderStream, RawDetail,
    ResponseResult, Streaming, TerminalOutcome, ToolPhase, TranslatedEvent, Usage,
};

// ════════════════════════════════════════════════════════════════════════════
// Chat Completions SSE event types
// ════════════════════════════════════════════════════════════════════════════

#[derive(Debug)]
enum ChatCompletionEvent {
    /// Text content delta.
    Delta {
        content: String,
        chunk_id: Option<String>,
    },
    /// Tool call delta (streamed incrementally).
    ToolCallDelta {
        index: usize,
        id: Option<String>,
        name: Option<String>,
        arguments: Option<String>,
        /// Additional tool-call deltas from the same chunk.
        extra: Vec<ToolCallPiece>,
        /// `finish_reason` from the same chunk (some providers embed the
        /// last argument fragment in the same chunk as `finish_reason`).
        finish_reason: Option<String>,
    },
    /// Chunk with `finish_reason` set (but usage may arrive in a later chunk).
    FinishReason { finish_reason: String },
    /// Final usage-only chunk (empty choices, populated usage).
    Usage { usage: ChatUsage },
    /// Combined finish + usage in a single chunk.
    Done {
        usage: ChatUsage,
        finish_reason: String,
    },
    /// `data: [DONE]` sentinel.
    StreamEnd,
    /// Unrecognized chunk (ignored).
    Unknown,
}

/// A single tool-call delta extracted from the chunk.
#[derive(Debug)]
struct ToolCallPiece {
    index: usize,
    id: Option<String>,
    name: Option<String>,
    arguments: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct PromptTokensDetails {
    #[serde(default)]
    cached_tokens: i64,
}

#[derive(Debug, Deserialize, Default)]
struct CompletionTokensDetails {
    #[serde(default)]
    reasoning_tokens: i64,
}

#[derive(Debug, Deserialize)]
struct ChatUsage {
    prompt_tokens: i64,
    completion_tokens: i64,
    #[serde(default)]
    prompt_tokens_details: Option<PromptTokensDetails>,
    #[serde(default)]
    completion_tokens_details: Option<CompletionTokensDetails>,
}

// ════════════════════════════════════════════════════════════════════════════
// SSE deserialization helpers
// ════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct ChatChunk {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    choices: Vec<ChatChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
}

#[derive(Deserialize)]
struct ChatChoice {
    #[serde(default)]
    delta: Option<ChatDelta>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChatDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<ChatDeltaToolCall>>,
}

#[derive(Deserialize)]
struct ChatDeltaToolCall {
    index: usize,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<ChatDeltaFunction>,
}

#[derive(Deserialize)]
struct ChatDeltaFunction {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

// ════════════════════════════════════════════════════════════════════════════
// FromServerEvent
// ════════════════════════════════════════════════════════════════════════════

impl FromServerEvent for ChatCompletionEvent {
    fn from_server_event(event: ServerEvent) -> Result<Self, StreamingError> {
        let data = event.data.trim();

        // [DONE] sentinel
        if data == "[DONE]" {
            return Ok(ChatCompletionEvent::StreamEnd);
        }

        let chunk: ChatChunk =
            serde_json::from_str(data).map_err(|e| StreamingError::ServerEventsParse {
                detail: format!("failed to parse chat completion chunk: {e}"),
            })?;

        let finish_reason = chunk.choices.first().and_then(|c| c.finish_reason.clone());

        // Usage-only chunk: empty choices with populated usage (final chunk
        // when stream_options.include_usage = true).
        if chunk.choices.is_empty() {
            if let Some(usage) = chunk.usage {
                return Ok(ChatCompletionEvent::Usage { usage });
            }
            return Ok(ChatCompletionEvent::Unknown);
        }

        // Tool call deltas — check BEFORE finish_reason so the last
        // argument fragment is not lost when a provider (e.g. vLLM) embeds
        // it in the same chunk as `finish_reason`. The finish_reason is
        // carried on the event and stashed by `translate_chat_event`.
        if let Some(tool_calls) = chunk
            .choices
            .first()
            .and_then(|c| c.delta.as_ref())
            .and_then(|d| d.tool_calls.as_ref())
            && let Some(tc) = tool_calls.first()
        {
            return Ok(ChatCompletionEvent::ToolCallDelta {
                index: tc.index,
                id: tc.id.clone(),
                name: tc.function.as_ref().and_then(|f| f.name.clone()),
                arguments: tc.function.as_ref().and_then(|f| f.arguments.clone()),
                extra: tool_calls
                    .iter()
                    .skip(1)
                    .map(|tc| ToolCallPiece {
                        index: tc.index,
                        id: tc.id.clone(),
                        name: tc.function.as_ref().and_then(|f| f.name.clone()),
                        arguments: tc.function.as_ref().and_then(|f| f.arguments.clone()),
                    })
                    .collect(),
                finish_reason: finish_reason.clone(),
            });
        }

        // Combined finish + usage in a single chunk.
        if let (Some(reason), Some(usage)) = (finish_reason.clone(), chunk.usage) {
            return Ok(ChatCompletionEvent::Done {
                usage,
                finish_reason: reason,
            });
        }

        // Finish reason without usage — usage arrives in a later chunk.
        if let Some(reason) = finish_reason {
            return Ok(ChatCompletionEvent::FinishReason {
                finish_reason: reason,
            });
        }

        // Delta content.
        let content = chunk
            .choices
            .first()
            .and_then(|c| c.delta.as_ref())
            .and_then(|d| d.content.clone())
            .unwrap_or_default();

        if content.is_empty() {
            return Ok(ChatCompletionEvent::Unknown);
        }

        Ok(ChatCompletionEvent::Delta {
            content,
            chunk_id: chunk.id,
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Scan state + translation
// ════════════════════════════════════════════════════════════════════════════

struct AccumulatedToolCall {
    id: String,
    name: String,
    arguments: String,
}

struct ChatCompletionsState {
    accumulated_text: String,
    finish_reason: Option<String>,
    tool_calls: Vec<AccumulatedToolCall>,
    response_id: String,
}

impl ChatCompletionsState {
    fn new() -> Self {
        Self {
            accumulated_text: String::new(),
            finish_reason: None,
            tool_calls: Vec::new(),
            response_id: String::new(),
        }
    }

    /// Emit `Tool(Done)` events for all accumulated tool calls.
    fn tool_call_done_events(&self) -> Vec<TranslatedEvent> {
        self.tool_calls
            .iter()
            .map(|tc| {
                TranslatedEvent::Sse(ClientSseEvent::Tool {
                    phase: ToolPhase::Done,
                    name: "function_call",
                    details: serde_json::json!({
                        "call_id": tc.id,
                        "name": tc.name,
                        "arguments": tc.arguments,
                    }),
                })
            })
            .collect()
    }

    fn make_terminal(&self, usage: &ChatUsage, finish_reason: &str) -> TranslatedEvent {
        let mapped_usage = Usage {
            input_tokens: usage.prompt_tokens,
            output_tokens: usage.completion_tokens,
            cache_read_input_tokens: usage
                .prompt_tokens_details
                .as_ref()
                .map_or(0, |d| d.cached_tokens),
            cache_write_input_tokens: 0,
            reasoning_tokens: usage
                .completion_tokens_details
                .as_ref()
                .map_or(0, |d| d.reasoning_tokens),
        };

        match finish_reason {
            "length" => TranslatedEvent::Terminal(TerminalOutcome::Incomplete {
                reason: "max_tokens".to_owned(),
                usage: mapped_usage,
                partial_content: self.accumulated_text.clone(),
            }),
            // Agentic loop: surface the first accumulated tool call as a
            // `ToolUse` terminal so the provider task can dispatch it and feed
            // the result back. Mirrors the Responses / Anthropic adapters.
            // Chat Completions can return multiple tool calls per turn, but the
            // agentic loop processes one per iteration (the remaining calls are
            // re-requested on the next round).
            //
            // vLLM quirk: some models/versions emit a phantom entry at index 0
            // (empty name + id) with the real tool call at a higher index. Skip
            // phantom entries and pick the first entry with a non-empty `name`.
            "tool_calls" => {
                let primary = self
                    .tool_calls
                    .iter()
                    .find(|tc| !tc.name.is_empty());
                match primary {
                    Some(tc) => {
                        // Merge arguments: some providers (e.g. vLLM) split a
                        // single tool call's arguments across multiple indices in
                        // the streamed `tool_calls` array, creating continuation
                        // entries with empty `name`. Concatenate those fragments
                        // so the JSON is complete before parsing.
                        let mut combined = tc.arguments.clone();
                        for cont in &self.tool_calls {
                            if cont.name.is_empty() {
                                combined.push_str(&cont.arguments);
                            }
                        }
                        let raw_args = if combined.is_empty() {
                            "{}".to_owned()
                        } else {
                            combined
                        };
                        // Surface malformed arguments as a provider protocol error
                        // rather than silently coercing to `{}` — that would route
                        // the tool call to the wrong inputs instead of failing.
                        match serde_json::from_str::<serde_json::Value>(&raw_args) {
                            Ok(input) => TranslatedEvent::Terminal(TerminalOutcome::ToolUse {
                                tool_use_id: tc.id.clone(),
                                name: tc.name.clone(),
                                input,
                            }),
                            Err(e) => TranslatedEvent::Terminal(TerminalOutcome::Failed {
                                error: LlmProviderError::InvalidResponse {
                                    detail: format!(
                                        "function_call arguments were not valid JSON: {e}"
                                    ),
                                },
                                usage: Some(mapped_usage),
                                partial_content: self.accumulated_text.clone(),
                            }),
                        }
                    }
                    // finish_reason was "tool_calls" but no real tool call
                    // accumulated — treat as a normal completion rather than
                    // stalling the stream.
                    None => TranslatedEvent::Terminal(TerminalOutcome::Completed {
                        usage: mapped_usage,
                        response_id: self.response_id.clone(),
                        content: self.accumulated_text.clone(),
                        citations: vec![],
                        raw_response: serde_json::Value::Null,
                    }),
                }
            }
            _ => TranslatedEvent::Terminal(TerminalOutcome::Completed {
                usage: mapped_usage,
                response_id: self.response_id.clone(),
                content: self.accumulated_text.clone(),
                citations: vec![],
                raw_response: serde_json::Value::Null,
            }),
        }
    }
}

/// Accumulate a single tool-call delta into state, returning a `Start` event
/// on the first delta for an index or `Skip` for continuations.
fn accumulate_tool_call(
    state: &mut ChatCompletionsState,
    index: usize,
    id: Option<&String>,
    name: Option<&String>,
    arguments: Option<&String>,
) -> Vec<TranslatedEvent> {
    while state.tool_calls.len() <= index {
        state.tool_calls.push(AccumulatedToolCall {
            id: String::new(),
            name: String::new(),
            arguments: String::new(),
        });
    }
    let tc = &mut state.tool_calls[index];
    if let Some(id) = id {
        tc.id.clone_from(id);
    }
    if let Some(name) = name {
        tc.name.clone_from(name);
    }
    if let Some(args) = arguments {
        tc.arguments.push_str(args);
    }
    if id.is_some() {
        vec![TranslatedEvent::Sse(ClientSseEvent::Tool {
            phase: ToolPhase::Start,
            name: "function_call",
            details: serde_json::json!({
                "index": index,
                "call_id": tc.id,
                "name": tc.name,
            }),
        })]
    } else {
        vec![TranslatedEvent::Skip]
    }
}

fn translate_chat_event(
    event: &ChatCompletionEvent,
    state: &mut ChatCompletionsState,
) -> Vec<TranslatedEvent> {
    match event {
        ChatCompletionEvent::Delta { content, chunk_id } => {
            if let Some(id) = chunk_id
                && state.response_id.is_empty()
            {
                state.response_id.clone_from(id);
            }
            state.accumulated_text.push_str(content);
            vec![TranslatedEvent::Sse(ClientSseEvent::Delta {
                r#type: "text",
                content: content.clone(),
            })]
        }

        ChatCompletionEvent::ToolCallDelta {
            index,
            id,
            name,
            arguments,
            extra,
            finish_reason,
        } => {
            let mut events = accumulate_tool_call(
                state,
                *index,
                id.as_ref(),
                name.as_ref(),
                arguments.as_ref(),
            );
            for piece in extra {
                events.extend(accumulate_tool_call(
                    state,
                    piece.index,
                    piece.id.as_ref(),
                    piece.name.as_ref(),
                    piece.arguments.as_ref(),
                ));
            }
            // If finish_reason was in the same chunk as the tool-call delta,
            // stash it and emit Done events just like the FinishReason path.
            if let Some(reason) = finish_reason {
                state.finish_reason = Some(reason.clone());
                if reason == "tool_calls" {
                    events.extend(state.tool_call_done_events());
                }
            }
            events
        }

        // finish_reason arrived without usage — stash it for the usage chunk.
        ChatCompletionEvent::FinishReason { finish_reason } => {
            state.finish_reason = Some(finish_reason.clone());
            // Emit Done for accumulated tool calls when finish_reason is "tool_calls".
            if finish_reason == "tool_calls" {
                state.tool_call_done_events()
            } else {
                vec![TranslatedEvent::Skip]
            }
        }

        // Usage-only chunk (after finish_reason chunk).
        ChatCompletionEvent::Usage { usage } => {
            let reason = state.finish_reason.as_deref().unwrap_or("stop");
            vec![state.make_terminal(usage, reason)]
        }

        // Combined finish + usage in one chunk.
        ChatCompletionEvent::Done {
            usage,
            finish_reason,
        } => {
            let mut events = Vec::new();
            if finish_reason == "tool_calls" {
                events.extend(state.tool_call_done_events());
            }
            events.push(state.make_terminal(usage, finish_reason));
            events
        }

        // [DONE] sentinel — if we have a stashed finish_reason but never got
        // usage, emit terminal with zero usage as fallback.
        ChatCompletionEvent::StreamEnd => {
            if let Some(reason) = state.finish_reason.take() {
                let zero = ChatUsage {
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    prompt_tokens_details: None,
                    completion_tokens_details: None,
                };
                return vec![state.make_terminal(&zero, &reason)];
            }
            vec![TranslatedEvent::Skip]
        }

        ChatCompletionEvent::Unknown => vec![TranslatedEvent::Skip],
    }
}

// ════════════════════════════════════════════════════════════════════════════
// LlmRequest → Chat Completions conversion
// ════════════════════════════════════════════════════════════════════════════

#[allow(clippy::cognitive_complexity)]
fn build_request_body<M>(request: &LlmRequest<M>, stream: bool) -> serde_json::Value {
    let mut body = serde_json::json!({});

    body["model"] = serde_json::json!(&request.model);

    if stream {
        body["stream"] = serde_json::json!(true);
        body["stream_options"] = serde_json::json!({ "include_usage": true });
    }

    // Build messages array: system instruction as first system message
    let mut messages: Vec<serde_json::Value> = Vec::new();

    if let Some(ref instructions) = request.system_instructions {
        messages.push(serde_json::json!({
            "role": "system",
            "content": instructions
        }));
    }

    for msg in &request.messages {
        let role = match msg.role {
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::System => "system",
        };

        // Simple text messages use string content
        if msg.content.len() == 1
            && let MessageContentPart::Text { text } = &msg.content[0]
        {
            messages.push(serde_json::json!({
                "role": role,
                "content": text
            }));
            continue;
        }

        let content: Vec<serde_json::Value> = msg
            .content
            .iter()
            .map(|part| match part {
                MessageContentPart::Text { text } => serde_json::json!({
                    "type": "text",
                    "text": text
                }),
                MessageContentPart::Image { file_id } => serde_json::json!({
                    "type": "image_url",
                    "image_url": { "url": file_id }
                }),
            })
            .collect();

        messages.push(serde_json::json!({
            "role": role,
            "content": content
        }));
    }
    // Append raw input items (function_call + function_call_output from the
    // agentic loop) converted to Chat Completions format (assistant message
    // with `tool_calls` + tool-role messages).
    if !request.raw_input_items.is_empty() {
        messages.extend(convert_raw_input_items_to_chat_messages(
            &request.raw_input_items,
        ));
    }
    body["messages"] = serde_json::Value::Array(messages);

    if let Some(max_tokens) = request.max_output_tokens {
        body["max_completion_tokens"] = serde_json::json!(max_tokens);
    }

    // User field: "{tenant_id}:{user_id}"
    if let Some(ref identity) = request.user_identity {
        body["user"] = serde_json::json!(format!("{}:{}", identity.tenant_id, identity.user_id));
    }

    // Map tools: Function → Chat Completions function format, others dropped
    let tools: Vec<serde_json::Value> = request
        .tools
        .iter()
        .filter_map(|tool| match tool {
            LlmTool::Function {
                name,
                description,
                parameters,
            } => Some(serde_json::json!({
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": parameters
                }
            })),
            LlmTool::FileSearch { .. } => {
                debug!("FileSearch tool not supported by Chat Completions, dropping");
                None
            }
            LlmTool::WebSearch { .. } => {
                debug!("WebSearch tool not supported by Chat Completions, dropping");
                None
            }
            LlmTool::CodeInterpreter { .. } => {
                debug!("CodeInterpreter tool not supported by Chat Completions, dropping");
                None
            }
        })
        .collect();
    if !tools.is_empty() {
        body["tools"] = serde_json::Value::Array(tools);
    }

    // Inference params from the typed model-policy channel. The Chat
    // Completions API uses a top-level `reasoning_effort`, in contrast to
    // the Responses API which nests it under `reasoning: { effort }`.
    if let Some(p) = request.api_params.as_ref() {
        body["temperature"] = serde_json::json!(p.temperature);
        body["top_p"] = serde_json::json!(p.top_p);
        body["frequency_penalty"] = serde_json::json!(p.frequency_penalty);
        body["presence_penalty"] = serde_json::json!(p.presence_penalty);
        if !p.stop.is_empty() {
            body["stop"] = serde_json::json!(&p.stop);
        }
        if let Some(ref effort) = p.reasoning_effort {
            body["reasoning_effort"] = serde_json::json!(effort);
        }
        // `extra_body` is merged at the top level; policy author's escape
        // hatch for fields not covered by `ModelApiParams`.
        if let Some(ref extra) = p.extra_body
            && let (Some(body_obj), Some(extra_obj)) = (body.as_object_mut(), extra.as_object())
        {
            for (k, v) in extra_obj {
                body_obj.insert(k.clone(), v.clone());
            }
        }
    }

    body
}

/// Convert OpenAI Responses API `raw_input_items` to Chat Completions messages.
///
/// Groups consecutive `function_call` items into a single assistant message
/// with `tool_calls`, and converts `function_call_output` items into `tool`
/// role messages. This mirrors the conversion in the Anthropic adapter but
/// targets the Chat Completions message schema.
fn convert_raw_input_items_to_chat_messages(
    items: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut messages = Vec::new();
    let mut pending_tool_calls: Vec<serde_json::Value> = Vec::new();

    for item in items {
        let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match item_type {
            "function_call" => {
                let call_id = item.get("call_id").and_then(|v| v.as_str()).unwrap_or("");
                let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = item
                    .get("arguments")
                    .and_then(|v| v.as_str())
                    .unwrap_or("{}");
                pending_tool_calls.push(serde_json::json!({
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": arguments,
                    }
                }));
            }
            "function_call_output" => {
                // Flush pending tool_calls as an assistant message before
                // emitting the corresponding tool result.
                if !pending_tool_calls.is_empty() {
                    messages.push(serde_json::json!({
                        "role": "assistant",
                        "content": serde_json::Value::Null,
                        "tool_calls": serde_json::Value::Array(pending_tool_calls.drain(..).collect()),
                    }));
                }
                let call_id = item.get("call_id").and_then(|v| v.as_str()).unwrap_or("");
                let output = item.get("output").and_then(|v| v.as_str()).unwrap_or("");
                messages.push(serde_json::json!({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": output,
                }));
            }
            _ => {}
        }
    }

    // Flush any remaining pending tool_calls (edge case: trailing
    // function_call with no matching output yet).
    if !pending_tool_calls.is_empty() {
        messages.push(serde_json::json!({
            "role": "assistant",
            "content": serde_json::Value::Null,
            "tool_calls": serde_json::Value::Array(pending_tool_calls),
        }));
    }

    messages
}

fn body_to_bytes(body: &serde_json::Value) -> Body {
    #[allow(clippy::expect_used)]
    let json = serde_json::to_vec(body).expect("serde_json::Value always serializes");
    Body::Bytes(Bytes::from(json))
}

// ════════════════════════════════════════════════════════════════════════════
// OpenAiChatProvider
// ════════════════════════════════════════════════════════════════════════════

/// `OpenAI` Chat Completions API adapter. Routes all calls through OAGW.
///
/// The upstream alias is not stored — it is passed per-request to allow
/// different tenants to route to different OAGW upstreams.
#[derive(Clone)]
pub struct OpenAiChatProvider {
    gateway: Arc<dyn ServiceGatewayClientV1>,
}

impl OpenAiChatProvider {
    #[must_use]
    pub fn new(gateway: Arc<dyn ServiceGatewayClientV1>) -> Self {
        Self { gateway }
    }
}

/// Chat Completions error response payload.
#[derive(Deserialize)]
struct ChatErrorPayload {
    error: ChatErrorDetail,
}

#[derive(Deserialize)]
struct ChatErrorDetail {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: String,
}

/// Chat Completions non-streaming response.
#[derive(Deserialize)]
struct ChatResponse {
    id: String,
    choices: Vec<ChatResponseChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
}

#[derive(Deserialize)]
struct ChatResponseChoice {
    #[serde(default)]
    message: Option<ChatResponseMessage>,
    #[serde(default)]
    #[allow(dead_code)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChatResponseMessage {
    #[serde(default)]
    content: Option<String>,
}

#[async_trait::async_trait]
impl crate::infra::llm::LlmProvider for OpenAiChatProvider {
    #[tracing::instrument(
        skip(self, ctx, request, upstream_alias, cancel),
        fields(model = %request.model(), upstream = %upstream_alias)
    )]
    async fn stream(
        &self,
        ctx: SecurityContext,
        request: LlmRequest<Streaming>,
        upstream_alias: &str,
        cancel: CancellationToken,
    ) -> Result<ProviderStream, LlmProviderError> {
        let body = build_request_body(&request, true);
        let uri = format!("/{upstream_alias}");

        let http_request = http::Request::builder()
            .method(http::Method::POST)
            .uri(&uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::ACCEPT, "text/event-stream")
            .body(body_to_bytes(&body))
            .map_err(|e| LlmProviderError::InvalidResponse {
                detail: format!("failed to build HTTP request: {e}"),
            })?;

        let response = self.gateway.proxy_request(ctx, http_request).await?;

        match ServerEventsStream::from_response::<ChatCompletionEvent>(response) {
            ServerEventsResponse::Events(event_stream) => {
                let translated = event_stream
                    .scan(ChatCompletionsState::new(), |state, result| {
                        let outputs: Vec<Result<TranslatedEvent, StreamingError>> = match result {
                            Ok(event) => translate_chat_event(&event, state)
                                .into_iter()
                                .map(Ok)
                                .collect(),
                            Err(e) => vec![Err(e)],
                        };
                        async move { Some(futures::stream::iter(outputs)) }
                    })
                    .flatten();

                Ok(ProviderStream::new(translated, cancel))
            }
            ServerEventsResponse::Response(resp) => {
                let (_parts, body) = resp.into_parts();
                match body.into_bytes().await {
                    Ok(bytes) => {
                        if let Ok(error_payload) =
                            serde_json::from_slice::<ChatErrorPayload>(&bytes)
                        {
                            let raw = error_payload.error.message.clone();
                            Err(LlmProviderError::ProviderError {
                                code: error_payload.error.code.unwrap_or_default(),
                                message: crate::infra::llm::sanitize_provider_message(&raw),
                                raw_detail: Some(RawDetail(raw)),
                            })
                        } else {
                            let body_str = String::from_utf8_lossy(&bytes);
                            let snippet = crate::infra::llm::sanitize_provider_message(
                                &body_str.chars().take(200).collect::<String>(),
                            );
                            Err(LlmProviderError::InvalidResponse {
                                detail: format!(
                                    "non-SSE response with unparseable body: {snippet}"
                                ),
                            })
                        }
                    }
                    Err(e) => Err(LlmProviderError::InvalidResponse {
                        detail: format!("failed to read response body: {e}"),
                    }),
                }
            }
        }
    }

    #[tracing::instrument(
        skip(self, ctx, request, upstream_alias),
        fields(model = %request.model(), upstream = %upstream_alias)
    )]
    async fn complete(
        &self,
        ctx: SecurityContext,
        request: LlmRequest<NonStreaming>,
        upstream_alias: &str,
    ) -> Result<ResponseResult, LlmProviderError> {
        let body = build_request_body(&request, false);
        let uri = format!("/{upstream_alias}");

        let http_request = http::Request::builder()
            .method(http::Method::POST)
            .uri(&uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(http::header::ACCEPT, "application/json")
            .body(body_to_bytes(&body))
            .map_err(|e| LlmProviderError::InvalidResponse {
                detail: format!("failed to build HTTP request: {e}"),
            })?;

        let response = self.gateway.proxy_request(ctx, http_request).await?;

        let (parts, resp_body) = response.into_parts();
        let bytes =
            resp_body
                .into_bytes()
                .await
                .map_err(|e| LlmProviderError::InvalidResponse {
                    detail: format!("failed to read response body: {e}"),
                })?;

        if !parts.status.is_success() {
            if let Ok(error_payload) = serde_json::from_slice::<ChatErrorPayload>(&bytes) {
                let raw = error_payload.error.message.clone();
                return Err(LlmProviderError::ProviderError {
                    code: error_payload.error.code.unwrap_or_default(),
                    message: crate::infra::llm::sanitize_provider_message(&raw),
                    raw_detail: Some(RawDetail(raw)),
                });
            }
            let body_str = String::from_utf8_lossy(&bytes);
            let snippet = crate::infra::llm::sanitize_provider_message(
                &body_str.chars().take(200).collect::<String>(),
            );
            return Err(LlmProviderError::InvalidResponse {
                detail: format!("HTTP {}: {snippet}", parts.status),
            });
        }

        let resp: ChatResponse =
            serde_json::from_slice(&bytes).map_err(|e| LlmProviderError::InvalidResponse {
                detail: format!("failed to parse response: {e}"),
            })?;

        let content = resp
            .choices
            .first()
            .and_then(|c| c.message.as_ref())
            .and_then(|m| m.content.clone())
            .unwrap_or_default();

        let usage = resp.usage.map_or(
            Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_read_input_tokens: 0,
                cache_write_input_tokens: 0,
                reasoning_tokens: 0,
            },
            |u| Usage {
                input_tokens: u.prompt_tokens,
                output_tokens: u.completion_tokens,
                cache_read_input_tokens: u
                    .prompt_tokens_details
                    .as_ref()
                    .map_or(0, |d| d.cached_tokens),
                cache_write_input_tokens: 0,
                reasoning_tokens: u
                    .completion_tokens_details
                    .as_ref()
                    .map_or(0, |d| d.reasoning_tokens),
            },
        );

        Ok(ResponseResult {
            content,
            usage,
            response_id: resp.id,
            citations: vec![],
            raw_response: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        })
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::llm::{LlmMessage, llm_request};
    use oagw_sdk::sse::ServerEvent;

    // ── FromServerEvent tests ─────────────────────────────────────────────

    #[test]
    fn parse_text_delta() {
        let event = ServerEvent {
            event: None,
            data: r#"{"choices":[{"delta":{"content":"Hello"}}]}"#.into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event).unwrap();
        assert!(matches!(result, ChatCompletionEvent::Delta { content, .. } if content == "Hello"));
    }

    #[test]
    fn parse_done_with_usage() {
        let event = ServerEvent {
            event: None,
            data: r#"{"usage":{"prompt_tokens":500,"completion_tokens":120},"choices":[{"finish_reason":"stop"}]}"#.into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event).unwrap();
        match result {
            ChatCompletionEvent::Done {
                usage,
                finish_reason,
            } => {
                assert_eq!(usage.prompt_tokens, 500);
                assert_eq!(usage.completion_tokens, 120);
                assert_eq!(finish_reason, "stop");
            }
            _ => panic!("expected Done"),
        }
    }

    #[test]
    fn parse_done_with_token_details() {
        let event = ServerEvent {
            event: None,
            data: r#"{"usage":{"prompt_tokens":500,"completion_tokens":120,"prompt_tokens_details":{"cached_tokens":200},"completion_tokens_details":{"reasoning_tokens":40}},"choices":[{"finish_reason":"stop"}]}"#.into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event).unwrap();
        match result {
            ChatCompletionEvent::Done { usage, .. } => {
                assert_eq!(
                    usage.prompt_tokens_details.as_ref().unwrap().cached_tokens,
                    200
                );
                assert_eq!(
                    usage
                        .completion_tokens_details
                        .as_ref()
                        .unwrap()
                        .reasoning_tokens,
                    40
                );
            }
            _ => panic!("expected Done"),
        }
    }

    #[test]
    fn parse_finish_reason_without_usage() {
        let event = ServerEvent {
            event: None,
            data: r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#.into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event).unwrap();
        assert!(matches!(
            result,
            ChatCompletionEvent::FinishReason { finish_reason } if finish_reason == "stop"
        ));
    }

    #[test]
    fn parse_usage_only_chunk() {
        let event = ServerEvent {
            event: None,
            data: r#"{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":50}}"#.into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event).unwrap();
        match result {
            ChatCompletionEvent::Usage { usage } => {
                assert_eq!(usage.prompt_tokens, 100);
                assert_eq!(usage.completion_tokens, 50);
            }
            _ => panic!("expected Usage"),
        }
    }

    #[test]
    fn parse_done_sentinel() {
        let event = ServerEvent {
            event: None,
            data: "[DONE]".into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event).unwrap();
        assert!(matches!(result, ChatCompletionEvent::StreamEnd));
    }

    #[test]
    fn parse_malformed_json_returns_error() {
        let event = ServerEvent {
            event: None,
            data: "not json at all".into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event);
        assert!(matches!(
            result.unwrap_err(),
            StreamingError::ServerEventsParse { .. }
        ));
    }

    #[test]
    fn parse_empty_delta_is_unknown() {
        let event = ServerEvent {
            event: None,
            data: r#"{"choices":[{"delta":{}}]}"#.into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event).unwrap();
        assert!(matches!(result, ChatCompletionEvent::Unknown));
    }

    // ── Translation tests ─────────────────────────────────────────────────

    /// Helper: unwrap a single-event translation result.
    fn translate_one(
        event: &ChatCompletionEvent,
        state: &mut ChatCompletionsState,
    ) -> TranslatedEvent {
        let mut events = translate_chat_event(event, state);
        assert_eq!(events.len(), 1, "expected 1 event, got {}", events.len());
        events.remove(0)
    }

    #[test]
    fn translate_delta_to_sse() {
        let event = ChatCompletionEvent::Delta {
            content: "Hi".into(),
            chunk_id: Some("chatcmpl-abc".into()),
        };
        let mut state = ChatCompletionsState::new();
        let translated = translate_one(&event, &mut state);
        match translated {
            TranslatedEvent::Sse(ClientSseEvent::Delta { r#type, content }) => {
                assert_eq!(r#type, "text");
                assert_eq!(content, "Hi");
            }
            _ => panic!("expected Sse(Delta)"),
        }
    }

    #[test]
    fn translate_delta_captures_response_id() {
        let mut state = ChatCompletionsState::new();
        let delta = ChatCompletionEvent::Delta {
            content: "Hi".into(),
            chunk_id: Some("chatcmpl-abc123".into()),
        };
        translate_one(&delta, &mut state);
        assert_eq!(state.response_id, "chatcmpl-abc123");

        // Terminal should carry the response_id.
        let done = ChatCompletionEvent::Done {
            usage: ChatUsage {
                prompt_tokens: 10,
                completion_tokens: 5,
                prompt_tokens_details: None,
                completion_tokens_details: None,
            },
            finish_reason: "stop".into(),
        };
        let translated = translate_one(&done, &mut state);
        match translated {
            TranslatedEvent::Terminal(TerminalOutcome::Completed { response_id, .. }) => {
                assert_eq!(response_id, "chatcmpl-abc123");
            }
            _ => panic!("expected Terminal(Completed)"),
        }
    }

    #[test]
    fn translate_done_stop_to_completed() {
        let event = ChatCompletionEvent::Done {
            usage: ChatUsage {
                prompt_tokens: 500,
                completion_tokens: 120,
                prompt_tokens_details: None,
                completion_tokens_details: None,
            },
            finish_reason: "stop".into(),
        };
        let mut state = ChatCompletionsState::new();
        state.accumulated_text = "Hello world".into();
        let translated = translate_one(&event, &mut state);
        match translated {
            TranslatedEvent::Terminal(TerminalOutcome::Completed { usage, content, .. }) => {
                assert_eq!(usage.input_tokens, 500);
                assert_eq!(usage.output_tokens, 120);
                assert_eq!(content, "Hello world");
            }
            _ => panic!("expected Terminal(Completed)"),
        }
    }

    #[test]
    fn translate_done_propagates_token_details() {
        let event = ChatCompletionEvent::Done {
            usage: ChatUsage {
                prompt_tokens: 500,
                completion_tokens: 120,
                prompt_tokens_details: Some(PromptTokensDetails { cached_tokens: 200 }),
                completion_tokens_details: Some(CompletionTokensDetails {
                    reasoning_tokens: 40,
                }),
            },
            finish_reason: "stop".into(),
        };
        let mut state = ChatCompletionsState::new();
        let translated = translate_one(&event, &mut state);
        match translated {
            TranslatedEvent::Terminal(TerminalOutcome::Completed { usage, .. }) => {
                assert_eq!(usage.cache_read_input_tokens, 200);
                assert_eq!(usage.reasoning_tokens, 40);
                assert_eq!(usage.cache_write_input_tokens, 0);
            }
            _ => panic!("expected Terminal(Completed)"),
        }
    }

    #[test]
    fn translate_done_length_to_incomplete() {
        let event = ChatCompletionEvent::Done {
            usage: ChatUsage {
                prompt_tokens: 0,
                completion_tokens: 0,
                prompt_tokens_details: None,
                completion_tokens_details: None,
            },
            finish_reason: "length".into(),
        };
        let mut state = ChatCompletionsState::new();
        state.accumulated_text = "partial".into();
        let translated = translate_one(&event, &mut state);
        match translated {
            TranslatedEvent::Terminal(TerminalOutcome::Incomplete {
                reason,
                partial_content,
                ..
            }) => {
                assert_eq!(reason, "max_tokens");
                assert_eq!(partial_content, "partial");
            }
            _ => panic!("expected Terminal(Incomplete)"),
        }
    }

    #[test]
    fn translate_stream_end_without_finish_is_skip() {
        let event = ChatCompletionEvent::StreamEnd;
        let mut state = ChatCompletionsState::new();
        let translated = translate_one(&event, &mut state);
        assert!(matches!(translated, TranslatedEvent::Skip));
    }

    #[test]
    fn translate_finish_then_usage_produces_completed() {
        let mut state = ChatCompletionsState::new();
        state.accumulated_text = "Hello".into();

        // Step 1: finish_reason arrives without usage — stashed, skip
        let finish = ChatCompletionEvent::FinishReason {
            finish_reason: "stop".into(),
        };
        let translated = translate_one(&finish, &mut state);
        assert!(matches!(translated, TranslatedEvent::Skip));
        assert_eq!(state.finish_reason.as_deref(), Some("stop"));

        // Step 2: usage-only chunk arrives — terminal with correct usage
        let usage = ChatCompletionEvent::Usage {
            usage: ChatUsage {
                prompt_tokens: 100,
                completion_tokens: 50,
                prompt_tokens_details: None,
                completion_tokens_details: None,
            },
        };
        let translated = translate_one(&usage, &mut state);
        match translated {
            TranslatedEvent::Terminal(TerminalOutcome::Completed { usage, content, .. }) => {
                assert_eq!(usage.input_tokens, 100);
                assert_eq!(usage.output_tokens, 50);
                assert_eq!(content, "Hello");
            }
            _ => panic!("expected Terminal(Completed)"),
        }
    }

    #[test]
    fn translate_finish_length_then_usage_produces_incomplete() {
        let mut state = ChatCompletionsState::new();
        state.accumulated_text = "partial".into();

        let finish = ChatCompletionEvent::FinishReason {
            finish_reason: "length".into(),
        };
        translate_chat_event(&finish, &mut state);

        let usage = ChatCompletionEvent::Usage {
            usage: ChatUsage {
                prompt_tokens: 200,
                completion_tokens: 100,
                prompt_tokens_details: None,
                completion_tokens_details: None,
            },
        };
        let translated = translate_one(&usage, &mut state);
        match translated {
            TranslatedEvent::Terminal(TerminalOutcome::Incomplete {
                reason,
                usage,
                partial_content,
            }) => {
                assert_eq!(reason, "max_tokens");
                assert_eq!(usage.input_tokens, 200);
                assert_eq!(usage.output_tokens, 100);
                assert_eq!(partial_content, "partial");
            }
            _ => panic!("expected Terminal(Incomplete)"),
        }
    }

    #[test]
    fn translate_stream_end_with_stashed_finish_emits_terminal() {
        let mut state = ChatCompletionsState::new();
        state.accumulated_text = "text".into();
        state.finish_reason = Some("stop".into());

        let translated = translate_one(&ChatCompletionEvent::StreamEnd, &mut state);
        assert!(matches!(
            translated,
            TranslatedEvent::Terminal(TerminalOutcome::Completed { .. })
        ));
    }

    // ── Tool call translation tests ──────────────────────────────────────

    #[test]
    fn parse_tool_call_delta() {
        let event = ServerEvent {
            event: None,
            data: r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_abc","function":{"name":"get_weather","arguments":""}}]}}]}"#.into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event).unwrap();
        match result {
            ChatCompletionEvent::ToolCallDelta {
                index,
                id,
                name,
                arguments,
                ..
            } => {
                assert_eq!(index, 0);
                assert_eq!(id.as_deref(), Some("call_abc"));
                assert_eq!(name.as_deref(), Some("get_weather"));
                assert_eq!(arguments.as_deref(), Some(""));
            }
            _ => panic!("expected ToolCallDelta"),
        }
    }

    #[test]
    fn translate_tool_call_start_emitted_on_first_delta() {
        let event = ChatCompletionEvent::ToolCallDelta {
            index: 0,
            id: Some("call_abc".into()),
            name: Some("get_weather".into()),
            arguments: Some(String::new()),
            extra: vec![],
            finish_reason: None,
        };
        let mut state = ChatCompletionsState::new();
        let translated = translate_one(&event, &mut state);
        match translated {
            TranslatedEvent::Sse(ClientSseEvent::Tool {
                phase,
                name,
                details,
            }) => {
                assert!(matches!(phase, ToolPhase::Start));
                assert_eq!(name, "function_call");
                assert_eq!(details["name"], "get_weather");
                assert_eq!(details["call_id"], "call_abc");
            }
            _ => panic!("expected Sse(Tool)"),
        }
    }

    #[test]
    fn translate_tool_call_argument_deltas_are_skip() {
        let mut state = ChatCompletionsState::new();

        // First delta: Start event
        let first = ChatCompletionEvent::ToolCallDelta {
            index: 0,
            id: Some("call_abc".into()),
            name: Some("get_weather".into()),
            arguments: Some("{\"lo".into()),
            extra: vec![],
            finish_reason: None,
        };
        translate_one(&first, &mut state);

        // Subsequent delta: Skip (arguments accumulated)
        let cont = ChatCompletionEvent::ToolCallDelta {
            index: 0,
            id: None,
            name: None,
            arguments: Some("cation\":\"SF\"}".into()),
            extra: vec![],
            finish_reason: None,
        };
        let translated = translate_one(&cont, &mut state);
        assert!(matches!(translated, TranslatedEvent::Skip));

        // Verify arguments were accumulated
        assert_eq!(state.tool_calls[0].arguments, "{\"location\":\"SF\"}");
    }

    #[test]
    fn translate_finish_tool_calls_emits_done_events() {
        let mut state = ChatCompletionsState::new();

        // Simulate accumulated tool call
        state.tool_calls.push(AccumulatedToolCall {
            id: "call_abc".into(),
            name: "get_weather".into(),
            arguments: r#"{"location":"SF"}"#.into(),
        });

        let finish = ChatCompletionEvent::FinishReason {
            finish_reason: "tool_calls".into(),
        };
        let events = translate_chat_event(&finish, &mut state);

        // Should emit 1 Done event for the tool call
        assert_eq!(events.len(), 1);
        match &events[0] {
            TranslatedEvent::Sse(ClientSseEvent::Tool {
                phase,
                name,
                details,
            }) => {
                assert!(matches!(phase, ToolPhase::Done));
                assert_eq!(*name, "function_call");
                assert_eq!(details["name"], "get_weather");
                assert_eq!(details["arguments"], r#"{"location":"SF"}"#);
            }
            _ => panic!("expected Sse(Tool)"),
        }
    }

    // ── Request serialization tests ───────────────────────────────────────

    #[test]
    fn request_basic_text() {
        let request = llm_request("gpt-4o")
            .message(LlmMessage::user("Hello"))
            .system_instructions("Be helpful")
            .max_output_tokens(4096)
            .build_streaming();

        let body = build_request_body(&request, true);

        assert_eq!(body["model"], "gpt-4o");
        assert_eq!(body["max_completion_tokens"], 4096);
        assert_eq!(body["stream"], true);
        assert_eq!(body["stream_options"]["include_usage"], true);

        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "Be helpful");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "Hello");
    }

    #[test]
    fn request_multi_turn() {
        let request = llm_request("gpt-4o")
            .message(LlmMessage::user("Hi"))
            .message(LlmMessage::assistant("Hello!"))
            .message(LlmMessage::user("How are you?"))
            .build_streaming();

        let body = build_request_body(&request, true);

        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[2]["role"], "user");
    }

    #[test]
    fn request_user_identity_mapped() {
        let request = llm_request("gpt-4o")
            .user_identity("abc", "def")
            .message(LlmMessage::user("Hi"))
            .build_streaming();

        let body = build_request_body(&request, true);

        assert_eq!(body["user"], "abc:def");
    }

    #[test]
    fn request_function_tool_mapped() {
        let request = llm_request("gpt-4o")
            .tool(LlmTool::Function {
                name: "get_weather".into(),
                description: "Get weather".into(),
                parameters: serde_json::json!({"type": "object"}),
            })
            .message(LlmMessage::user("Hi"))
            .build_streaming();

        let body = build_request_body(&request, true);

        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["tools"][0]["function"]["name"], "get_weather");
        assert_eq!(body["tools"][0]["function"]["description"], "Get weather");
    }

    #[test]
    fn request_file_search_dropped() {
        let request = llm_request("gpt-4o")
            .tool(LlmTool::FileSearch {
                vector_store_ids: vec!["vs-1".into()],
                filters: None,
                max_num_results: None,
            })
            .message(LlmMessage::user("Hi"))
            .build_streaming();

        let body = build_request_body(&request, true);

        assert!(body.get("tools").is_none());
    }

    #[test]
    fn request_code_interpreter_dropped() {
        let request = llm_request("gpt-4o")
            .tool(LlmTool::CodeInterpreter {
                file_ids: vec!["file-1".into()],
            })
            .message(LlmMessage::user("Run analysis"))
            .build_streaming();

        let body = build_request_body(&request, true);

        assert!(body.get("tools").is_none());
    }

    // ── Split argument merging ───────────────────────────────────────────

    #[test]
    fn make_terminal_merges_split_tool_call_arguments() {
        let mut state = ChatCompletionsState::new();
        state.tool_calls.push(AccumulatedToolCall {
            id: "call_1".into(),
            name: "timer".into(),
            arguments: r#"{"action": "start", "name"#.into(),
        });
        state.tool_calls.push(AccumulatedToolCall {
            id: String::new(),
            name: String::new(),
            arguments: r#"": "test1"}"#.into(),
        });

        let usage = ChatUsage {
            prompt_tokens: 10,
            completion_tokens: 5,
            prompt_tokens_details: None,
            completion_tokens_details: None,
        };
        let terminal = state.make_terminal(&usage, "tool_calls");
        match terminal {
            TranslatedEvent::Terminal(TerminalOutcome::ToolUse {
                tool_use_id,
                name,
                input,
            }) => {
                assert_eq!(tool_use_id, "call_1");
                assert_eq!(name, "timer");
                assert_eq!(input["action"], "start");
                assert_eq!(input["name"], "test1");
            }
            _ => panic!("expected Terminal(ToolUse), got {terminal:?}"),
        }
    }

    #[test]
    fn make_terminal_single_entry_tool_call_works() {
        let mut state = ChatCompletionsState::new();
        state.tool_calls.push(AccumulatedToolCall {
            id: "call_1".into(),
            name: "timer".into(),
            arguments: r#"{"action":"start"}"#.into(),
        });

        let usage = ChatUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            prompt_tokens_details: None,
            completion_tokens_details: None,
        };
        let terminal = state.make_terminal(&usage, "tool_calls");
        assert!(matches!(
            terminal,
            TranslatedEvent::Terminal(TerminalOutcome::ToolUse { .. })
        ));
    }

    #[test]
    fn make_terminal_skips_phantom_entry_at_index_zero() {
        // vLLM quirk: a phantom entry (empty name/id) at index 0 with the
        // real tool call at index 1. The adapter must skip the phantom and
        // dispatch the real call.
        let mut state = ChatCompletionsState::new();
        state.tool_calls.push(AccumulatedToolCall {
            id: String::new(),
            name: String::new(),
            arguments: String::new(),
        });
        state.tool_calls.push(AccumulatedToolCall {
            id: "call_1".into(),
            name: "search_confluence".into(),
            arguments: r#"{"query": "Bytebase"}"#.into(),
        });

        let usage = ChatUsage {
            prompt_tokens: 10,
            completion_tokens: 5,
            prompt_tokens_details: None,
            completion_tokens_details: None,
        };
        let terminal = state.make_terminal(&usage, "tool_calls");
        match terminal {
            TranslatedEvent::Terminal(TerminalOutcome::ToolUse {
                tool_use_id,
                name,
                input,
            }) => {
                assert_eq!(tool_use_id, "call_1");
                assert_eq!(name, "search_confluence");
                assert_eq!(input["query"], "Bytebase");
            }
            _ => panic!("expected Terminal(ToolUse), got {terminal:?}"),
        }
    }

    // ── finish_reason in same chunk as tool_call delta ───────────────────

    #[test]
    fn tool_call_delta_with_finish_reason_accumulates_and_stashes() {
        let mut state = ChatCompletionsState::new();

        // First delta without finish_reason.
        let first = ChatCompletionEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".into()),
            name: Some("timer".into()),
            arguments: Some(r#"{"action":"#.into()),
            extra: vec![],
            finish_reason: None,
        };
        translate_chat_event(&first, &mut state);

        // Second delta WITH finish_reason in the same chunk.
        let last = ChatCompletionEvent::ToolCallDelta {
            index: 0,
            id: None,
            name: None,
            arguments: Some(r#""start"}"#.into()),
            extra: vec![],
            finish_reason: Some("tool_calls".into()),
        };
        let events = translate_chat_event(&last, &mut state);

        // Should stash finish_reason.
        assert_eq!(state.finish_reason.as_deref(), Some("tool_calls"));
        // Should emit tool_call Done event(s).
        assert!(events.iter().any(|e| matches!(
            e,
            TranslatedEvent::Sse(ClientSseEvent::Tool {
                phase: ToolPhase::Done,
                ..
            })
        )));
        // Arguments should be fully accumulated.
        assert_eq!(state.tool_calls[0].arguments, r#"{"action":"start"}"#);
    }

    #[test]
    fn parse_tool_call_delta_with_finish_reason_in_same_chunk() {
        let event = ServerEvent {
            event: None,
            data: r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"end\"}"}}]},"finish_reason":"tool_calls"}]}"#.into(),
            id: None,
            retry: None,
        };
        let result = ChatCompletionEvent::from_server_event(event).unwrap();
        match result {
            ChatCompletionEvent::ToolCallDelta {
                arguments,
                finish_reason,
                ..
            } => {
                assert_eq!(arguments.as_deref(), Some("\"end\"}"));
                assert_eq!(finish_reason.as_deref(), Some("tool_calls"));
            }
            _ => panic!("expected ToolCallDelta, got {result:?}"),
        }
    }

    // ── raw_input_items conversion ───────────────────────────────────────

    #[test]
    fn convert_raw_input_items_produces_chat_messages() {
        let items = vec![
            serde_json::json!({
                "type": "function_call",
                "call_id": "call_1",
                "name": "timer",
                "arguments": r#"{"action":"start"}"#,
            }),
            serde_json::json!({
                "type": "function_call_output",
                "call_id": "call_1",
                "output": "Timer 'default' started.",
            }),
        ];
        let messages = convert_raw_input_items_to_chat_messages(&items);
        assert_eq!(messages.len(), 2);

        // Assistant message with tool_calls.
        assert_eq!(messages[0]["role"], "assistant");
        assert!(messages[0]["content"].is_null());
        let tool_calls = messages[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0]["id"], "call_1");
        assert_eq!(tool_calls[0]["type"], "function");
        assert_eq!(tool_calls[0]["function"]["name"], "timer");

        // Tool message with result.
        assert_eq!(messages[1]["role"], "tool");
        assert_eq!(messages[1]["tool_call_id"], "call_1");
        assert_eq!(messages[1]["content"], "Timer 'default' started.");
    }

    #[test]
    fn convert_raw_input_items_empty_returns_empty() {
        assert!(convert_raw_input_items_to_chat_messages(&[]).is_empty());
    }

    #[test]
    fn convert_raw_input_items_trailing_function_call_flushed() {
        let items = vec![serde_json::json!({
            "type": "function_call",
            "call_id": "call_1",
            "name": "timer",
            "arguments": "{}",
        })];
        let messages = convert_raw_input_items_to_chat_messages(&items);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "assistant");
        assert_eq!(messages[0]["tool_calls"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn convert_raw_input_items_multiple_calls_grouped() {
        let items = vec![
            serde_json::json!({"type":"function_call","call_id":"c1","name":"timer","arguments":"{}"}),
            serde_json::json!({"type":"function_call","call_id":"c2","name":"timer","arguments":"{}"}),
            serde_json::json!({"type":"function_call_output","call_id":"c1","output":"r1"}),
            serde_json::json!({"type":"function_call_output","call_id":"c2","output":"r2"}),
        ];
        let messages = convert_raw_input_items_to_chat_messages(&items);
        // 2 function_calls → 1 assistant with 2 tool_calls
        // 2 function_call_outputs → 2 tool messages
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "assistant");
        assert_eq!(messages[0]["tool_calls"].as_array().unwrap().len(), 2);
        assert_eq!(messages[1]["role"], "tool");
        assert_eq!(messages[2]["role"], "tool");
    }

    #[test]
    fn request_raw_input_items_appended_as_chat_messages() {
        let request = llm_request("gpt-4o")
            .message(LlmMessage::user("start timer"))
            .raw_input_items(vec![
                serde_json::json!({
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "timer",
                    "arguments": r#"{"action":"start"}"#,
                }),
                serde_json::json!({
                    "type": "function_call_output",
                    "call_id": "call_1",
                    "output": "Timer started.",
                }),
            ])
            .build_streaming();

        let body = build_request_body(&request, true);
        let messages = body["messages"].as_array().unwrap();

        // user message + assistant (tool_calls) + tool (result)
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["tool_calls"][0]["function"]["name"], "timer");
        assert_eq!(messages[2]["role"], "tool");
        assert_eq!(messages[2]["content"], "Timer started.");
    }
}
