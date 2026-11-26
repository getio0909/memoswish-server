//! MCP 请求分发（与传输无关）。

#[cfg(test)]
use std::sync::Arc;

use memoswish_core::Principal;
use serde_json::{Value, json};

use crate::protocol::codes;
use crate::tools::{self, CallError};

pub use memoswish_application::Services;

/// 给 AI Agent 的使用说明（`initialize.instructions`）。
pub const INSTRUCTIONS: &str = concat!(
    env!("BRAND_EN_PRODUCT"),
    " (",
    env!("BRAND_ZH_PRODUCT"),
    ") turns learning material from any discipline into a TikTok-style feed of micro cards. \
Typical workflow: 1) deck_create (or deck_list); 2) card_upsert with structured cards — keep each card bite-sized: \
a short front title, optional subtitle (phonetics/year/formula label), and ContentBlock items (text, code, math, quote, list, table, image, link) \
on front/back, plus free-form template and attributes; TTS with word-level timestamps is generated automatically; \
3) bgm_match by mood (calm/focus/upbeat/epic) then bgm_assign to the deck; \
4) feed_preview to verify what the learner will see; learning_stats to monitor FSRS-6 progress. \
Use material_slice for quick deterministic slicing of 'term :: definition' lists, Q:/A: pairs, or Markdown notes. For draft-by-default generation, set content_lifecycle=true on card_upsert/material_slice, inspect with card_get, then explicitly card_publish with the observed revision. Strict card_save supports atomic save-and-publish; media uses separate commands."
);

/// MCP 服务端。
#[derive(Clone)]
pub struct McpServer {
    pub services: Services,
    pub(crate) active_calls: crate::control::ActiveCalls,
    pub server_name: String,
    pub server_version: String,
}

impl McpServer {
    pub fn new(services: Services) -> Self {
        Self {
            services,
            active_calls: Default::default(),
            server_name: "memoswishd".into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    async fn dispatch(
        &self,
        principal: &Principal,
        method: &str,
        params: Value,
        token_hash: Option<memoswish_core::imports::ImportCredential>,
    ) -> Result<Value, (i64, String)> {
        if matches!(method, "resources/list" | "resources/read") {
            self.services
                .auth
                .require_privacy_collection(principal)
                .await
                .map_err(|e| (codes::INVALID_PARAMS, e.public_message().into_owned()))?;
        }
        match method {
            "tools/list" => Ok(tools::list_tools_json()),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or((codes::INVALID_PARAMS, "missing tool name".to_string()))?;
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);
                match tools::call_with_credential(&self.services, principal, name, args, token_hash).await {
                    Ok(v) => {
                        let text = if name == "deck_export_portable" {
                            "Portable DeckPack with embedded media.".into()
                        } else {
                            serde_json::to_string_pretty(&v).unwrap_or_default()
                        };
                        // structuredContent 必须是对象，数组结果包一层。
                        let structured = if v.is_object() { v } else { json!({ "result": v }) };
                        Ok(json!({
                            "content": [{ "type": "text", "text": text }],
                            "structuredContent": structured,
                            "isError": false
                        }))
                    }
                    Err(CallError::UnknownTool(_)) => Err((codes::INVALID_PARAMS, "unknown tool".into())),
                    Err(CallError::InvalidArgs(_)) => Err((codes::INVALID_PARAMS, "invalid tool arguments".into())),
                    Err(CallError::Domain(e)) => {
                        // 业务错误按 MCP 规范放在结果里（isError=true），便于模型自我纠正。
                        tracing::info!(target: "memoswish::mcp::server", code = e.code(), "mcp tool error");
                        Ok(json!({
                            "content": [{ "type": "text", "text": format!("[{}] {}", e.code(), e.public_message()) }],
                            "isError": true
                        }))
                    }
                }
            }
            "resources/list" => self.list_resources(principal).await,
            "resources/read" => self.read_resource(principal, &params).await,
            "resources/templates/list" => Ok(json!({
                "resourceTemplates": [{
                    "uriTemplate": "memoswish://decks/{deck_id}",
                    "name": "Deck Pack Export",
                    "description": concat!("Export a ", env!("BRAND_EN_PRODUCT"), " deck and all of its micro cards as a portable DeckPack JSON document."),
                    "mimeType": "application/json"
                }]
            })),
            "prompts/list" => Ok(Self::list_prompts()),
            "prompts/get" => Self::get_prompt(&params),
            _ => Err((codes::METHOD_NOT_FOUND, "method not found".into())),
        }
    }

    /// 列出当前租户可读的 MCP 资源（全局统计 + 每个卡组的内容包 URI）。
    async fn list_resources(&self, principal: &Principal) -> Result<Value, (i64, String)> {
        let mut resources = vec![json!({
            "uri": "memoswish://stats",
            "name": "Learning Statistics",
            "description": "Global FSRS-6 learning statistics (total, seen, due, starred, average retrievability, exposures).",
            "mimeType": "application/json"
        })];
        let decks = self
            .services
            .list_decks(principal)
            .await
            .map_err(|e| (codes::INVALID_PARAMS, format!("[{}] {}", e.code(), e.public_message())))?;
        for deck in decks {
            resources.push(json!({
                "uri": format!("memoswish://decks/{}", deck.id),
                "name": deck.title,
                "description": format!("Portable DeckPack JSON for deck `{}` ({} cards, {})", deck.id, deck.card_count, deck.language),
                "mimeType": "application/json"
            }));
        }
        Ok(json!({ "resources": resources }))
    }

    /// 读取指定 URI 的 MCP 资源内容。
    async fn read_resource(&self, principal: &Principal, params: &Value) -> Result<Value, (i64, String)> {
        let uri = params
            .get("uri")
            .and_then(Value::as_str)
            .ok_or((codes::INVALID_PARAMS, "missing resource uri".to_string()))?;
        let text = if uri == "memoswish://stats" {
            let stats = self
                .services
                .stats(principal)
                .await
                .map_err(|e| (codes::INVALID_PARAMS, format!("[{}] {}", e.code(), e.public_message())))?;
            serde_json::to_string_pretty(&stats).unwrap_or_default()
        } else if let Some(deck_id) = uri.strip_prefix("memoswish://decks/") {
            if deck_id.is_empty() {
                return Err((codes::INVALID_PARAMS, "missing deck_id in resource uri".to_string()));
            }
            let pack = self
                .services
                .export_deck(principal, deck_id)
                .await
                .map_err(|e| (codes::INVALID_PARAMS, format!("[{}] {}", e.code(), e.public_message())))?;
            serde_json::to_string_pretty(&pack).unwrap_or_default()
        } else {
            return Err((codes::INVALID_PARAMS, "unknown resource uri".into()));
        };
        Ok(json!({
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": text
            }]
        }))
    }

    /// 返回内置 MCP 提示词模板列表。
    fn list_prompts() -> Value {
        json!({
            "prompts": [
                {
                    "name": "slice_article_to_cards",
                    "description": concat!("Slice an article or study note into bite-sized ", env!("BRAND_EN_PRODUCT"), " micro cards with TTS and mood-matched BGM."),
                    "arguments": [
                        { "name": "topic", "description": "Deck title or subject area.", "required": true },
                        { "name": "material", "description": "Raw article, notes, or study material to slice.", "required": true }
                    ]
                },
                {
                    "name": "create_exam_prep_deck",
                    "description": "Create a structured exam preparation deck covering core concepts, formulas/code, and pitfalls.",
                    "arguments": [
                        { "name": "subject", "description": "Exam subject or course name.", "required": true },
                        { "name": "level", "description": "Difficulty or target level (e.g. beginner, advanced, AP, JLPT-N1).", "required": false }
                    ]
                },
                {
                    "name": "explain_difficult_concept",
                    "description": "Break down a difficult concept using analogies and turn the explanation into a micro-card sequence.",
                    "arguments": [
                        { "name": "concept", "description": "The concept, theorem, or term to explain.", "required": true },
                        { "name": "audience", "description": "Target learner profile or background.", "required": false }
                    ]
                }
            ]
        })
    }

    /// 渲染指定的 MCP 提示词模板。
    fn get_prompt(params: &Value) -> Result<Value, (i64, String)> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((codes::INVALID_PARAMS, "missing prompt name".to_string()))?;
        let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
        let product = env!("BRAND_EN_PRODUCT");
        let (description, prompt_text) = match name {
            "slice_article_to_cards" => {
                let topic = args
                    .get("topic")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .ok_or((codes::INVALID_PARAMS, "missing required argument `topic`".to_string()))?;
                let material = args
                    .get("material")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .ok_or((codes::INVALID_PARAMS, "missing required argument `material`".to_string()))?;
                (
                    format!("Slice material on `{topic}` into {product} micro cards"),
                    format!(
                        "Please turn the following study material on \"{topic}\" into a {product} micro-card deck:\n\n\
                        1. Call `deck_create` to create a deck titled \"{topic}\".\n\
                        2. Break the material into atomic micro cards (15-40 words on the front, structured ContentBlocks on the back) and call `card_upsert` with `auto_tts: true`.\n\
                        3. Call `bgm_match` and `bgm_assign` to bind a fitting background track with `policy: \"switch_on_theme\"`.\n\n\
                        --- MATERIAL ---\n{material}"
                    ),
                )
            }
            "create_exam_prep_deck" => {
                let subject = args
                    .get("subject")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .ok_or((codes::INVALID_PARAMS, "missing required argument `subject`".to_string()))?;
                let level = args.get("level").and_then(Value::as_str).unwrap_or("intermediate");
                (
                    format!("Create a {level} exam prep deck for `{subject}`"),
                    format!(
                        "Create a high-yield {product} exam preparation deck for \"{subject}\" (target level: {level}):\n\n\
                        1. Use `deck_create` to create the deck.\n\
                        2. Use `card_upsert` to add 8-12 micro cards covering core definitions, key formulas/code snippets, and common exam traps.\n\
                        3. Match a `focus` mood BGM via `bgm_match` and bind it with `bgm_assign`.\n\
                        4. Verify the learning sequence using `feed_preview`."
                    ),
                )
            }
            "explain_difficult_concept" => {
                let concept = args
                    .get("concept")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .ok_or((codes::INVALID_PARAMS, "missing required argument `concept`".to_string()))?;
                let audience = args.get("audience").and_then(Value::as_str).unwrap_or("curious self-learner");
                (
                    format!("Explain `{concept}` for {audience}"),
                    format!(
                        "Explain the concept \"{concept}\" for a {audience}, then persist it as a 3-card progression in {product}:\n\n\
                        - Card 1 (Intuition): One-sentence core intuition and everyday analogy.\n\
                        - Card 2 (Mechanism): Key structural points, formula, or minimal code example.\n\
                        - Card 3 (Self-Check): A quick active-recall question testing edge cases."
                    ),
                )
            }
            _ => return Err((codes::INVALID_PARAMS, "unknown prompt".into())),
        };
        Ok(json!({
            "description": description,
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": prompt_text
                }
            }]
        }))
    }
}

/// SDK handler 只携带服务；HTTP 主体必须来自本次认证的 request parts。
#[derive(Clone)]
pub(crate) struct Handler {
    pub server: McpServer,
    pub stdio_principal: Option<Principal>,
    pub stdio_authority: Option<String>,
}

impl Handler {
    async fn controlled_dispatch(
        &self,
        principal: &Principal,
        params: Value,
        credential: Option<memoswish_core::imports::ImportCredential>,
        context: &rmcp::service::RequestContext<rmcp::RoleServer>,
        bearer: Option<&str>,
    ) -> Result<Value, rmcp::ErrorData> {
        let authority =
            self.stdio_authority.clone().unwrap_or_else(|| crate::control::http_authority(principal, bearer));
        // stdio 的守卫由输入帧同步创建；HTTP 仍在本次认证后登记。
        let active = match context.extensions.get::<std::sync::Arc<crate::control::ActiveCall>>() {
            Some(active) => active.clone(),
            None => std::sync::Arc::new(self.server.active_calls.register(authority, context.id.clone())?),
        };
        let control = &active.control;
        let mut phases = control.subscribe();
        phases.mark_changed();
        let token = context.meta.get_progress_token();
        let mut sequence = 0_u32;
        let operation = control.scope(self.server.dispatch(principal, "tools/call", params, credential));
        tokio::pin!(operation);
        let mut cancelled = false;
        loop {
            if cancelled && *phases.borrow() == "accepted" {
                return Ok(
                    json!({"content":[{"type":"text","text":"[unavailable] cancellation requested after acceptance; reconcile original business identity"}],"isError":true}),
                );
            }
            tokio::select! {
                biased;
                _ = context.ct.cancelled(), if !cancelled => {
                    cancelled = true;
                }
                _ = control.cancelled(), if !cancelled => {
                    cancelled = true;
                }
                result = &mut operation => return result.map_err(|(code, message)| crate::protocol::rpc_error(code, message)),
                changed = phases.changed() => {
                    if changed.is_ok() {
                        let phase = *phases.borrow_and_update();
                        if token.is_none() || cancelled { continue; }
                        sequence += 1;
                        let progress = rmcp::model::ProgressNotificationParam::new(token.clone().unwrap(), f64::from(sequence)).with_message(phase);
                        // 传输背压不会增加队列，关闭或取消即停止通知；业务拥有者继续解析事务。
                        tokio::select! {
                            _ = context.ct.cancelled() => { cancelled = true; }
                            _ = control.cancelled() => { cancelled = true; }
                            _ = context.peer.notify_progress(progress) => {}
                        }
                    }
                }
            }
        }
    }

    async fn invoke<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<T, rmcp::ErrorData> {
        let principal = context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Principal>())
            .or(self.stdio_principal.as_ref())
            .ok_or_else(|| rmcp::ErrorData::invalid_request("authentication required", None))?;
        let bearer = context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.headers.get(axum::http::header::AUTHORIZATION))
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")));
        let token_hash =
            if method == "tools/call"
                && matches!(
                    params.get("name").and_then(Value::as_str),
                    Some(
                        "deck_import"
                            | "deck_import_apkg"
                            | "deck_export_portable"
                            | "deck_import_portable"
                            | "deck_import_status"
                    )
                )
                && matches!(principal.via.as_str(), "jwt" | "api_token" | "mcp_oauth")
            {
                Some(
                    self.server.services.auth.import_credential(principal, bearer).map_err(|_| {
                        rmcp::ErrorData::invalid_request("original credential evidence is missing", None)
                    })?,
                )
            } else {
                None
            };
        let portable_export =
            method == "tools/call" && params.get("name").and_then(Value::as_str) == Some("deck_export_portable");
        let result = if method == "tools/call" {
            self.controlled_dispatch(principal, params, token_hash, &context, bearer).await
        } else {
            self.server
                .dispatch(principal, method, params, token_hash)
                .await
                .map_err(|(code, message)| crate::protocol::rpc_error(code, message))
        }?;
        // 活动调用表不缓存授权，释放业务结果前仍观察已提交的撤销。
        if matches!(method, "tools/call" | "resources/list" | "resources/read") {
            self.server
                .services
                .auth
                .require_privacy_collection(principal)
                .await
                .map_err(|_| rmcp::ErrorData::invalid_request("credential was revoked or expired", None))?;
        }
        if portable_export {
            memoswish_content::deckpack::bounded_json(
                &json!({"jsonrpc":"2.0","id":context.id,"result":result}),
                crate::protocol::MAX_MESSAGE_BYTES,
            )
            .map_err(|_| rmcp::ErrorData::internal_error("portable response exceeds message budget", None))?;
        }
        serde_json::from_value(result).map_err(|_| rmcp::ErrorData::internal_error("internal server error", None))
    }
}

impl rmcp::ServerHandler for Handler {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        serde_json::from_value(json!({
            "protocolVersion": crate::protocol::SUPPORTED_VERSIONS[0],
            "capabilities": {
                "tools": {"listChanged": false},
                "resources": {"listChanged": false},
                "prompts": {"listChanged": false}
            },
            "serverInfo": {"name": self.server.server_name, "title": concat!(env!("BRAND_EN_PRODUCT"), " MCP"), "version": self.server.server_version},
            "instructions": INSTRUCTIONS
        })).expect("static MCP server metadata")
    }

    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [rmcp::model::ProtocolVersion]> {
        std::borrow::Cow::Owned(vec![
            rmcp::model::ProtocolVersion::V_2025_11_25,
            rmcp::model::ProtocolVersion::V_2025_06_18,
        ])
    }

    async fn discover(
        &self,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::DiscoverResult, rmcp::ErrorData> {
        Err(rmcp::ErrorData::new(rmcp::model::ErrorCode::METHOD_NOT_FOUND, "method not found", None))
    }

    async fn complete(
        &self,
        _: rmcp::model::CompleteRequestParams,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CompleteResult, rmcp::ErrorData> {
        Err(rmcp::ErrorData::new(rmcp::model::ErrorCode::METHOD_NOT_FOUND, "method not found", None))
    }

    #[allow(deprecated)]
    async fn set_level(
        &self,
        _: rmcp::model::SetLevelRequestParams,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<(), rmcp::ErrorData> {
        Err(rmcp::ErrorData::new(rmcp::model::ErrorCode::METHOD_NOT_FOUND, "method not found", None))
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        self.invoke::<rmcp::model::CallToolResult>(
            "tools/call",
            serde_json::to_value(request).expect("MCP parameters"),
            context,
        )
        .await
        .map(Into::into)
    }

    async fn list_tools(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        self.invoke("tools/list", json!({}), context).await
    }

    async fn list_resources(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, rmcp::ErrorData> {
        self.invoke("resources/list", json!({}), context).await
    }

    async fn list_resource_templates(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListResourceTemplatesResult, rmcp::ErrorData> {
        self.invoke("resources/templates/list", json!({}), context).await
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, rmcp::ErrorData> {
        self.invoke::<rmcp::model::ReadResourceResult>(
            "resources/read",
            serde_json::to_value(request).expect("MCP parameters"),
            context,
        )
        .await
        .map(Into::into)
    }

    async fn list_prompts(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListPromptsResult, rmcp::ErrorData> {
        self.invoke("prompts/list", json!({}), context).await
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::GetPromptResponse, rmcp::ErrorData> {
        self.invoke::<rmcp::model::GetPromptResult>(
            "prompts/get",
            serde_json::to_value(request).expect("MCP parameters"),
            context,
        )
        .await
        .map(Into::into)
    }

    async fn on_custom_request(
        &self,
        _: rmcp::model::CustomRequest,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CustomResult, rmcp::ErrorData> {
        Err(rmcp::ErrorData::new(rmcp::model::ErrorCode::METHOD_NOT_FOUND, "method not found", None))
    }
}

// 单元测试通过 SDK 的单消息传输运行，与生产 handler 共用同一分发路径。
#[cfg(test)]
impl McpServer {
    pub async fn handle_value(&self, principal: &Principal, value: Value) -> Option<Value> {
        let message = match crate::protocol::validate(value.clone()) {
            Ok(message) => message,
            Err(error) => {
                return Some(crate::protocol::failure(
                    value.get("id").cloned().unwrap_or(Value::Null),
                    i64::from(error.code.0),
                    error.message,
                ));
            }
        };
        if !matches!(message, rmcp::model::ClientJsonRpcMessage::Request(_)) {
            return None;
        }
        let (transport, mut receiver) = rmcp::transport::OneshotTransport::<rmcp::RoleServer>::new(message);
        let service = rmcp::service::serve_directly(
            Handler {
                server: self.clone(),
                stdio_principal: Some(principal.clone()),
                stdio_authority: Some(format!("stdio:{}", memoswish_core::ids::new_id())),
            },
            transport,
            None,
        );
        let response = receiver.recv().await.map(|response| serde_json::to_value(response).unwrap());
        service.cancel().await.unwrap();
        response
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use memoswish_auth::{AuthConfig, AuthService, QuotaPolicy, RateLimiter, Unlimited};
    use memoswish_content::ContentService;
    use memoswish_core::repo::Repository;
    use memoswish_core::store::ObjectStore;
    use memoswish_feed::FeedConfig;
    use memoswish_feed::FeedService;
    use memoswish_media::MediaService;
    use memoswish_media::tts::placeholder::PlaceholderTts;
    use memoswish_protocol::DeploymentMode;
    use memoswish_storage::LocalDiskStore;
    use memoswish_storage::sqlite::SqliteRepository;

    pub async fn test_server() -> McpServer {
        test_server_with_repo(DeploymentMode::SingleUser).await.0
    }

    #[tokio::test]
    async fn raw_legacy_import_budget_survives_mcp_dispatch() {
        let s = test_server().await;
        for tool in ["deck_import", "deck_import_portable"] {
            let mut pack: Value = serde_json::from_str(include_str!(
                "../../../../compatibility/history/2.13.0/protocol/fixtures/deck-pack.json"
            ))
            .unwrap();
            assert!(pack["deck"].get("revision").is_none());
            pack["cards"] = json!([]);
            pack["deck"]["card_count"] = json!(0);
            pack["deck"]["description"] = json!("");
            let base = serde_json::to_vec(&pack).unwrap().len();
            pack["deck"]["description"] = json!("x".repeat(memoswish_core::imports::IMPORT_CONTENT_BYTES - base));
            for excess in [false, true] {
                if excess {
                    pack["deck"]["description"] = json!(format!("{}x", pack["deck"]["description"].as_str().unwrap()));
                }
                let input = if tool == "deck_import" {
                    json!({"pack":pack,"auto_tts":false})
                } else {
                    json!({"pack":{"version":"2.0","content":pack,"media":[]}})
                };
                let response = call(&s, 1, "tools/call", json!({"name":tool,"arguments":input})).await;
                assert_eq!(response["result"]["isError"], excess, "{tool}: {response}");
            }
        }
        s.services.operations.close();
        s.services.operations.wait().await;
    }

    pub async fn test_server_with_repo(mode: DeploymentMode) -> (McpServer, Arc<dyn Repository>) {
        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
        let dir = std::env::temp_dir().join(format!("memoswish-mcp-{}", memoswish_core::ids::new_id()));
        let store: Arc<dyn ObjectStore> = Arc::new(LocalDiskStore::new(dir, "/assets"));
        let quota: Arc<dyn QuotaPolicy> = Arc::new(Unlimited::new());
        let auth = AuthService::new(
            repo.clone(),
            AuthConfig {
                mode,
                jwt_secret: "k".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: true,
                default_plan: "self_hosted".into(),
            },
        )
        .unwrap();
        auth.bootstrap_local().await.unwrap();
        let media = MediaService::new(
            repo.clone(),
            store.clone(),
            quota.clone(),
            vec![Arc::new(PlaceholderTts)],
            "placeholder",
        )
        .unwrap();
        media.ensure_builtin_bgm().await.unwrap();
        let server = McpServer::new(Services {
            operations: Default::default(),
            auth,
            content: ContentService::new(repo.clone()).with_import_store(store),
            media,
            feed: FeedService::new(
                repo.clone(),
                FeedConfig::default(),
                std::sync::Arc::new(|| memoswish_protocol::examples::sample_feed_page().generated_at),
            )
            .unwrap(),
            quota,
            limiter: Arc::new(RateLimiter::new(1000, 100.0)),
        });
        (server, repo)
    }

    pub(super) async fn call(s: &McpServer, id: i64, method: &str, params: Value) -> Value {
        let p = Principal::local_owner("stdio");
        s.handle_value(&p, json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})).await.unwrap()
    }

    #[tokio::test]
    async fn handshake_and_tool_listing() {
        let s = test_server().await;
        use rmcp::ServerHandler;
        let handler = Handler { server: s.clone(), stdio_principal: None, stdio_authority: None };
        let supported = handler.supported_protocol_versions();
        assert_eq!(
            supported.iter().map(rmcp::model::ProtocolVersion::as_str).collect::<Vec<_>>(),
            crate::protocol::SUPPORTED_VERSIONS
        );
        let init = call(
            &s,
            1,
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        )
        .await;
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert!(init["result"]["capabilities"]["tools"].is_object());
        assert!(init["result"]["capabilities"]["resources"].is_object());
        assert!(init["result"]["capabilities"]["prompts"].is_object());
        let p = Principal::local_owner("stdio");
        assert!(s.handle_value(&p, json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await.is_none());
        let list = call(&s, 2, "tools/list", json!({})).await;
        let tools = list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), tools::catalog().len());
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object", "tool {} schema must be an object", t["name"]);
        }
        let unknown = call(&s, 3, "nope", json!({})).await;
        assert_eq!(unknown["error"]["code"], codes::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn end_to_end_agent_workflow() {
        let s = test_server().await;
        let deck = call(
            &s,
            1,
            "tools/call",
            json!({"name": "deck_create", "arguments": {"title": "Rust 60s", "language": "en-US"}}),
        )
        .await;
        let deck_id = deck["result"]["structuredContent"]["id"].as_str().unwrap().to_string();

        let upsert = call(&s, 2, "tools/call", json!({"name": "card_upsert", "arguments": {
            "cards": [{"deck_id": deck_id, "template": "concept", "front": {"title": "Borrowing", "blocks": [{"type": "text", "text": "Use without owning"}]}, "back": {"title": "&T / &mut T"}}],
            "bgm": {"track_id": "bgm_focus_pad"}
        }})).await;
        let cards = &upsert["result"]["structuredContent"]["result"];
        assert_eq!(upsert["result"]["isError"], false, "{upsert}");
        assert_eq!(cards[0]["tts"]["words"].as_array().unwrap().len(), 4);
        assert_eq!(cards[0]["bgm"]["track"]["id"], "bgm_focus_pad");

        let sliced = call(&s, 3, "tools/call", json!({"name": "material_slice", "arguments": {"deck_id": deck_id, "text": "a :: b\nc :: d", "commit": true, "auto_tts": false}})).await;
        assert_eq!(sliced["result"]["structuredContent"]["cards"].as_array().unwrap().len(), 2);

        let feed = call(&s, 4, "tools/call", json!({"name": "feed_preview", "arguments": {"limit": 3}})).await;
        assert_eq!(feed["result"]["structuredContent"]["items"].as_array().unwrap().len(), 3);

        let card_id = cards[0]["id"].as_str().unwrap().to_string();
        let explained = call(
            &s,
            8,
            "tools/call",
            json!({"name": "card_explain", "arguments": {"card_id": card_id, "question": "Why borrow?"}}),
        )
        .await;
        assert_eq!(explained["result"]["isError"], false);
        assert!(explained["result"]["structuredContent"]["summary"].as_str().unwrap().contains("Borrowing"));

        let exported =
            call(&s, 9, "tools/call", json!({"name": "deck_export", "arguments": {"deck_id": deck_id}})).await;
        assert_eq!(exported["result"]["isError"], false);
        let pack = exported["result"]["structuredContent"].clone();
        assert_eq!(pack["cards"].as_array().unwrap().len(), 3);

        let imported =
            call(&s, 10, "tools/call", json!({"name": "deck_import", "arguments": {"pack": pack, "auto_tts": true}}))
                .await;
        assert_eq!(imported["result"]["isError"], false);
        assert_eq!(imported["result"]["structuredContent"]["card_count"], 3);

        let bad = call(&s, 5, "tools/call", json!({"name": "card_get", "arguments": {"card_id": "missing"}})).await;
        assert_eq!(bad["result"]["isError"], true);
        let invalid = call(&s, 6, "tools/call", json!({"name": "card_get", "arguments": {}})).await;
        assert_eq!(invalid["error"]["code"], codes::INVALID_PARAMS);
        let unknown = call(&s, 7, "tools/call", json!({"name": "rm_rf", "arguments": {}})).await;
        assert_eq!(unknown["error"]["code"], codes::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn conditional_content_tools_preserve_conflict_and_atomic_batch_results() {
        let s = test_server().await;
        let p = Principal::local_owner("test");
        let deck = s
            .services
            .create_deck(
                &p,
                memoswish_content::NewDeck {
                    title: "CAS".into(),
                    description: String::new(),
                    language: "en".into(),
                    tags: vec![],
                },
            )
            .await
            .unwrap();
        let drafts = memoswish_content::slice_material(&deck.id, "One :: 1\nTwo :: 2", 2);
        let cards = s.services.content.upsert_cards(&p, drafts.clone()).await.unwrap();
        let mut edit = drafts[0].clone();
        edit.id = Some(cards[0].id.clone());
        edit.expected_revision = Some(1);
        edit.front.title = "Updated".into();
        let response =
            call(&s, 1, "tools/call", json!({"name":"card_upsert", "arguments":{"cards":[edit], "auto_tts":false}}))
                .await;
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["structuredContent"]["result"][0]["revision"], 2);
        let failed = call(
            &s,
            2,
            "tools/call",
            json!({"name":"card_upsert", "arguments":{"cards":[drafts[1],edit], "auto_tts":false}}),
        )
        .await;
        assert_eq!(failed["result"]["isError"], true);
        assert!(failed["result"]["content"][0]["text"].as_str().unwrap().contains("current revision 2"));
        assert_eq!(s.services.list_cards(&p, Some(&deck.id), 10, 0).await.unwrap().len(), 2);
        let missing = call(&s, 3, "tools/call", json!({"name":"bgm_assign", "arguments":{"card_ids":[cards[0].id, "missing"], "assignment":{"track_id":"bgm_focus_pad"}}})).await;
        assert_eq!(missing["result"]["isError"], true);
        assert!(s.services.get_card(&p, &cards[0].id).await.unwrap().bgm.is_none());
        let generated =
            call(&s, 4, "tools/call", json!({"name":"bgm_generate", "arguments":{"title":"CAS", "moods":["focus"]}}))
                .await;
        assert_eq!(generated["result"]["structuredContent"]["revision"], 1);
        let updated = call(
            &s,
            5,
            "tools/call",
            json!({"name":"bgm_generate", "arguments":{"title":"CAS", "moods":["calm"], "expected_revision":1}}),
        )
        .await;
        assert_eq!(updated["result"]["structuredContent"]["revision"], 2);
        let conflict = call(
            &s,
            6,
            "tools/call",
            json!({"name":"bgm_generate", "arguments":{"title":"CAS", "moods":["focus"], "expected_revision":1}}),
        )
        .await;
        assert_eq!(conflict["result"]["isError"], true);
        assert!(conflict["result"]["content"][0]["text"].as_str().unwrap().contains("current revision 2"));
        let removed = call(
            &s,
            7,
            "tools/call",
            json!({"name":"card_delete", "arguments":{"card_id":cards[0].id,"expected_revision":2}}),
        )
        .await;
        assert_eq!(removed["result"]["isError"], false);
        edit.expected_revision = None;
        let replay =
            call(&s, 8, "tools/call", json!({"name":"card_upsert", "arguments":{"cards":[edit],"auto_tts":false}}))
                .await;
        assert_eq!(replay["result"]["isError"], true);
        assert!(replay["result"]["content"][0]["text"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn bgm_assign_api_token_requires_read_before_mutation_or_disclosure() {
        let s = test_server().await;
        let owner = Principal::local_owner("test");
        let deck = s
            .services
            .create_deck(
                &owner,
                memoswish_content::NewDeck {
                    title: "Scopes".into(),
                    description: String::new(),
                    language: "en".into(),
                    tags: vec![],
                },
            )
            .await
            .unwrap();
        let drafts = memoswish_content::slice_material(&deck.id, "Private card sentinel :: Private answer sentinel", 1);
        let card = s.services.content.upsert_cards(&owner, drafts).await.unwrap().remove(0);
        // 准入会复核原始凭据，范围测试也必须使用真实持久化 Token。
        let authenticated_owner = s.services.auth.authenticate(None).await.unwrap();
        let created = s
            .services
            .auth
            .create_api_token(&authenticated_owner, "write-only", vec!["content:write".into()], None)
            .await
            .unwrap();
        let mut token = s.services.auth.authenticate(Some(&created.plaintext)).await.unwrap();
        token.role = memoswish_core::Role::Editor;
        let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
            "name":"bgm_assign", "arguments":{"card_ids":[card.id], "assignment":{"track_id":"bgm_focus_pad"}}
        }});
        let rejected = s.handle_value(&token, request.clone()).await.unwrap();
        assert_eq!(rejected["result"]["isError"], true);
        assert_eq!(rejected["result"]["content"][0]["text"], "[forbidden] forbidden");
        assert!(rejected["result"].get("structuredContent").is_none());
        assert!(!rejected.to_string().contains("Private card sentinel"));
        assert!(!rejected.to_string().contains("Private answer sentinel"));
        assert_eq!(s.services.get_card(&owner, &card.id).await.unwrap(), card);
        let created = s
            .services
            .auth
            .create_api_token(
                &authenticated_owner,
                "read-write",
                vec!["content:write".into(), "content:read".into()],
                None,
            )
            .await
            .unwrap();
        let mut token = s.services.auth.authenticate(Some(&created.plaintext)).await.unwrap();
        token.role = memoswish_core::Role::Editor;
        let accepted = s.handle_value(&token, request).await.unwrap();
        assert_eq!(accepted["result"]["isError"], false);
        let returned = &accepted["result"]["structuredContent"]["cards"][0];
        assert_eq!(returned["front"]["title"], card.front.title);
        assert_eq!(returned["revision"], card.revision + 1);
        assert_eq!(returned["bgm"]["track"]["id"], "bgm_focus_pad");
        assert_eq!(serde_json::to_value(s.services.get_card(&owner, &card.id).await.unwrap()).unwrap(), *returned);
    }

    #[tokio::test]
    async fn learner_cannot_write_via_mcp() {
        let s = test_server().await;
        let owner = s.services.auth.authenticate(None).await.unwrap();
        let created = s.services.auth.create_api_token(&owner, "role-check", vec!["*".into()], None).await.unwrap();
        let mut learner = s.services.auth.authenticate(Some(&created.plaintext)).await.unwrap();
        learner.role = memoswish_core::Role::Learner;
        let r = s
            .handle_value(&learner, json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "deck_create", "arguments": {"title": "x", "language": "en"}}}))
            .await
            .unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("forbidden"));
    }

    #[tokio::test]
    async fn resources_and_prompts_endpoints() {
        let s = test_server().await;
        let deck = call(
            &s,
            1,
            "tools/call",
            json!({"name": "deck_create", "arguments": {"title": "Distributed Systems", "language": "en-US"}}),
        )
        .await;
        let deck_id = deck["result"]["structuredContent"]["id"].as_str().unwrap().to_string();

        // 验证 resources/list 包含全局统计与新建卡组。
        let res_list = call(&s, 2, "resources/list", json!({})).await;
        let resources = res_list["result"]["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0]["uri"], "memoswish://stats");
        assert_eq!(resources[1]["uri"], format!("memoswish://decks/{deck_id}"));

        // 验证 resources/read 读取学习统计与卡组导出包。
        let stats_res = call(&s, 3, "resources/read", json!({"uri": "memoswish://stats"})).await;
        let stats_text = stats_res["result"]["contents"][0]["text"].as_str().unwrap();
        let stats_val: Value = serde_json::from_str(stats_text).unwrap();
        assert_eq!(stats_val["total_cards"], 0);

        let deck_res = call(&s, 4, "resources/read", json!({"uri": format!("memoswish://decks/{deck_id}")})).await;
        let deck_text = deck_res["result"]["contents"][0]["text"].as_str().unwrap();
        let pack_val: Value = serde_json::from_str(deck_text).unwrap();
        assert_eq!(pack_val["deck"]["title"], "Distributed Systems");

        let bad_res = call(&s, 5, "resources/read", json!({"uri": "memoswish://unknown"})).await;
        assert_eq!(bad_res["error"]["code"], codes::INVALID_PARAMS);

        for uri in ["learntok://stats", "memoswish://stats/", "memoswish://stats?tenant_id=other"] {
            let response = call(&s, 50, "resources/read", json!({"uri": uri})).await;
            assert_eq!(response["error"]["code"], codes::INVALID_PARAMS);
        }

        // 验证 prompts/list 与 prompts/get。
        let prompts_list = call(&s, 6, "prompts/list", json!({})).await;
        let prompts = prompts_list["result"]["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 3);

        let p1 = call(
            &s,
            7,
            "prompts/get",
            json!({"name": "slice_article_to_cards", "arguments": {"topic": "Raft", "material": "Leader election :: term numbers"}}),
        )
        .await;
        let msg1 = p1["result"]["messages"][0]["content"]["text"].as_str().unwrap();
        assert!(msg1.contains("Raft"));
        assert!(msg1.contains("Leader election"));

        let p2 = call(
            &s,
            8,
            "prompts/get",
            json!({"name": "create_exam_prep_deck", "arguments": {"subject": "Operating Systems", "level": "graduate"}}),
        )
        .await;
        let msg2 = p2["result"]["messages"][0]["content"]["text"].as_str().unwrap();
        assert!(msg2.contains("Operating Systems"));
        assert!(msg2.contains("graduate"));

        let p3 = call(
            &s,
            9,
            "prompts/get",
            json!({"name": "explain_difficult_concept", "arguments": {"concept": "Linearizability", "audience": "backend engineers"}}),
        )
        .await;
        let msg3 = p3["result"]["messages"][0]["content"]["text"].as_str().unwrap();
        assert!(msg3.contains("Linearizability"));
        assert!(msg3.contains("backend engineers"));

        let bad_prompt = call(&s, 10, "prompts/get", json!({"name": "nonexistent"})).await;
        assert_eq!(bad_prompt["error"]["code"], codes::INVALID_PARAMS);
    }
}

#[cfg(test)]
#[path = "../../memoswish-content/tests/support/mod.rs"]
pub(crate) mod apkg_support;

#[cfg(test)]
mod apkg_tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use memoswish_auth::{Metric, Unlimited};
    use memoswish_content::apkg::ApkgLimits;
    use memoswish_core::Role;

    async fn import(server: &McpServer, p: &Principal, args: Value) -> Value {
        server
            .handle_value(
                p,
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"deck_import_apkg","arguments":args}}),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn apkg_tool_schema_dispatch_validation_and_metering() {
        let _guard = crate::APKG_TEST.lock().await;
        let mut server = tests::test_server().await;
        let repo = server.services.content.import_repository();
        server.services.quota = Arc::new(Unlimited::metered(repo));
        let p = Principal::local_owner("stdio");
        let list = tools::list_tools_json();
        let tools = list["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 32);
        let tool = tools.iter().find(|t| t["name"] == "deck_import_apkg").unwrap();
        assert_eq!(tool["inputSchema"]["properties"]["apkg_base64"]["type"], "string");
        let args = json!({"apkg_base64":STANDARD.encode(apkg_support::basic().await),"title":"MCP import"});
        let response = import(&server, &p, args.clone()).await;
        assert_eq!(response["result"]["isError"], false, "{response}");
        assert_eq!(response["result"]["structuredContent"]["cards_imported"], 1);
        let snap = server.services.quota.snapshot(&p).await.unwrap();
        assert_eq!(snap.metrics.iter().find(|m| m.metric == Metric::CardWrites.as_str()).unwrap().used, 1);
        let response = import(&server, &p, json!({"apkg_base64":"@@@"})).await;
        assert_eq!(response["error"]["code"], -32602);
        let response =
            import(&server, &p, json!({"apkg_base64":"A".repeat(ApkgLimits::ARCHIVE.div_ceil(3)*4+1)})).await;
        assert_eq!(response["error"]["code"], -32602);
        let response =
            import(&server, &p, json!({"apkg_base64":STANDARD.encode(vec![0; ApkgLimits::ARCHIVE + 1])})).await;
        assert_eq!(response["error"]["code"], -32602);
        let response = import(&server, &p, json!({"apkg_base64":STANDARD.encode(b"not a zip")})).await;
        assert_eq!(response["result"]["isError"], true);
        let reversed = apkg_support::zip(vec![
            ("collection.anki2", apkg_support::database("reversed", "Front\x1fBack", &[0, 1]).await),
            ("media", b"{}".to_vec()),
        ]);
        let response = import(&server, &p, json!({"apkg_base64":STANDARD.encode(reversed)})).await;
        assert_eq!(response["result"]["structuredContent"]["cards_imported"], 2);
        let mut learner = p.clone();
        learner.role = Role::Learner;
        let response = import(&server, &learner, args).await;
        assert_eq!(response["result"]["isError"], true);
        let snap = server.services.quota.snapshot(&p).await.unwrap();
        assert_eq!(snap.metrics.iter().find(|m| m.metric == Metric::CardWrites.as_str()).unwrap().used, 3);
        assert_eq!(snap.metrics.iter().find(|m| m.metric == Metric::McpCalls.as_str()).unwrap().used, 7);
    }
}

#[cfg(test)]
mod admission_tests {
    use super::tests::call;
    use super::*;
    use memoswish_auth::{Metric, Unlimited};

    #[tokio::test]
    async fn unknown_tool_precedes_admission_but_malformed_known_tool_is_metered() {
        let mut server = tests::test_server().await;
        let repo = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
        server.services.quota = Arc::new(Unlimited::metered(repo));
        let p = Principal::local_owner("test");
        for (name, expected) in [("unknown", 0), ("card_upsert", 1)] {
            let response = server
                .handle_value(
                    &p,
                    json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":name,"arguments":{}}}),
                )
                .await
                .unwrap();
            assert_eq!(response["error"]["code"], codes::INVALID_PARAMS);
            let snapshot = server.services.usage(&p).await.unwrap();
            assert_eq!(
                snapshot.metrics.iter().find(|metric| metric.metric == Metric::McpCalls.as_str()).unwrap().used,
                expected
            );
            assert_eq!(
                snapshot.metrics.iter().find(|metric| metric.metric == Metric::CardWrites.as_str()).unwrap().used,
                0
            );
        }
    }
    #[tokio::test]
    async fn durable_submission_tools_replay_original_facts_and_enforce_owner() {
        async fn request(s: &McpServer, id: i64, method: &str, params: Value) -> Value {
            s.handle_value(
                &Principal::local_owner("stdio"),
                json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
            )
            .await
            .unwrap()
        }
        let (s, repo) = tests::test_server_with_repo(memoswish_protocol::DeploymentMode::SingleUser).await;
        let p = Principal::local_owner("stdio");
        let deck = memoswish_protocol::examples::sample_deck();
        let mut card = memoswish_protocol::examples::sample_card();
        card.tts = None;
        repo.insert_deck_with_cards(&p.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
        let args = json!({"request_id":"mcp-replay","card_ids":[card.id]});
        let submit = request(&s, 1, "tools/call", json!({"name":"tts_submit","arguments":args})).await;
        assert_eq!(submit["result"]["isError"], false);
        let item = submit["result"]["structuredContent"]["items"][0]["item_id"].as_str().unwrap().to_owned();
        s.services.operations.close();
        s.services.operations.wait().await;
        let mut s = s;
        s.services.operations = Default::default();
        s.services.recover_speech().unwrap().await.unwrap().unwrap();
        let terminal = request(
            &s,
            2,
            "tools/call",
            json!({"name":"tts_submission_status","arguments":{"request_id":"mcp-replay"}}),
        )
        .await;
        assert_eq!(terminal["result"]["structuredContent"]["complete"], true);
        assert_eq!(terminal["result"]["structuredContent"]["items"][0]["receipt"]["disposition"], "attached");
        repo.delete_card(&p.tenant_id, &card.id).await.unwrap();
        let replay = request(&s, 3, "tools/call", json!({"name":"tts_submit","arguments":args})).await;
        assert_eq!(replay["result"]["structuredContent"], terminal["result"]["structuredContent"]);
        repo.resolve_speech_attachment(&p.tenant_id, &item).await.unwrap();
        let changed=request(&s,4,"tools/call",json!({"name":"tts_submit","arguments":{"request_id":"mcp-replay","card_ids":[card.id],"options":{"voice":"changed"}}})).await;
        assert_eq!(changed["result"]["isError"], true);
        for ids in [json!([]), json!(["duplicate", "duplicate"]), json!(vec!["x"; 101])] {
            let bad = request(
                &s,
                5,
                "tools/call",
                json!({"name":"tts_submit","arguments":{"request_id":"bad","card_ids":ids}}),
            )
            .await;
            assert_eq!(bad["result"]["isError"], true);
        }
        let mut denied = p.clone();
        denied.scopes = Some(vec!["content:read".into()]);
        let result=s.handle_value(&denied,json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"tts_submission_status","arguments":{"request_id":"mcp-replay"}}})).await.unwrap();
        assert_eq!(result["result"]["isError"], true);
        s.services.operations.close();
        s.services.operations.wait().await;
    }
    #[tokio::test]
    async fn portable_tools_roundtrip_one_structured_copy_and_builtin_bgm() {
        async fn call(s: &McpServer, id: i64, method: &str, params: Value) -> Value {
            s.handle_value(
                &Principal::local_owner("stdio"),
                json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
            )
            .await
            .unwrap()
        }
        let s = tests::test_server().await;
        let pack = memoswish_protocol::examples::sample_portable_deck_pack();
        let imported = call(
            &s,
            1,
            "tools/call",
            json!({"name":"deck_import_portable","arguments":{"pack":pack,"request_id":"portable-mcp"}}),
        )
        .await;
        assert_eq!(imported["result"]["isError"], false, "{imported}");
        let deck = imported["result"]["structuredContent"]["id"].as_str().unwrap();
        let exported =
            call(&s, 2, "tools/call", json!({"name":"deck_export_portable","arguments":{"deck_id":deck}})).await;
        assert_eq!(exported["result"]["isError"], false, "{exported}");
        assert_eq!(exported["result"]["structuredContent"]["media"].as_array().unwrap().len(), 2);
        assert_eq!(exported["result"]["content"][0]["text"], "Portable DeckPack with embedded media.");
        memoswish_content::deckpack::bounded_json(&exported, crate::protocol::MAX_MESSAGE_BYTES).unwrap();
        let p = Principal::local_owner("stdio");
        let card = s.services.list_cards(&p, Some(deck), 1, 0).await.unwrap().remove(0);
        assert_eq!(card.tts.as_ref().unwrap().words, pack.content.cards[0].tts.as_ref().unwrap().words);
        let builtin = s.services.media.list_bgm(&p).await.unwrap().remove(0);
        let mut card = s.services.content.get_card(&p, &card.id).await.unwrap();
        card.bgm.as_mut().unwrap().track = builtin;
        s.services
            .content
            .import_repository()
            .mutate_cards(
                &p.tenant_id,
                &[memoswish_core::content::CardMutation::Bgm {
                    id: card.id.clone(),
                    expected_revision: Some(card.revision),
                    binding: card.bgm.clone(),
                }],
            )
            .await
            .unwrap();
        let builtin_pack = s.services.export_portable_deck(&p, deck, None).await.unwrap();
        assert!(builtin_pack.media.iter().any(|m| m.bytes > 204));
        assert!(
            builtin_pack
                .content
                .cards
                .iter()
                .flat_map(memoswish_core::assets::card_assets)
                .all(|a| !a.key.starts_with("shared/") && a.url.is_empty())
        );
    }

    #[tokio::test]
    async fn explanation_lookup_replay_and_reconcile_keep_mcp_envelope() {
        let (s, repo) = tests::test_server_with_repo(memoswish_protocol::DeploymentMode::SingleUser).await;
        let deck = memoswish_protocol::examples::sample_deck();
        let card = memoswish_protocol::examples::sample_card();
        repo.insert_deck_with_cards("local", &deck, std::slice::from_ref(&card)).await.unwrap();
        let args = json!({"card_id":card.id,"request_id":"mcp-explain"});
        let result = call(&s, 1, "tools/call", json!({"name":"card_explain","arguments":args})).await;
        assert_eq!(result["result"]["isError"], false);
        assert_eq!(result["result"]["structuredContent"]["operation"]["disposition"], "local");
        let result =
            call(&s, 2, "tools/call", json!({"name":"explanation_lookup","arguments":{"request_id":"mcp-explain"}}))
                .await;
        assert_eq!(result["result"]["isError"], false);
        let result=call(&s,3,"tools/call",json!({"name":"card_explain","arguments":{"card_id":card.id,"request_id":"mcp-explain","question":"changed"}})).await;
        assert_eq!(result["result"]["isError"], true);
        let result =
            call(&s, 4, "tools/call", json!({"name":"explanation_lookup","arguments":{"request_id":"absent"}})).await;
        assert_eq!(result["result"]["isError"], true);
        let result=call(&s,5,"tools/call",json!({"name":"explanation_reconcile","arguments":{"request_id":"mcp-explain","evidence":{"input_tokens":1,"output_tokens":1}}})).await;
        assert_eq!(result["result"]["isError"], true);
        let mut p = Principal::local_owner("stdio");
        p.scopes = Some(vec!["content:read".into()]);
        let result=s.handle_value(&p,json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"explanation_reconcile","arguments":{"request_id":"mcp-explain","evidence":{"input_tokens":1,"output_tokens":1}}}})).await.unwrap();
        assert_eq!(result["result"]["isError"], true);
    }
}

#[cfg(test)]
mod speech_bgm_tests {
    use super::*;
    #[tokio::test]
    async fn typed_diagnostics_and_frame_clip_reach_application_boundary() {
        let server = tests::test_server().await;
        let response = tests::call(&server, 1, "tools/call", json!({"name":"tts_engines","arguments":{}})).await;
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(response["result"]["structuredContent"]["diagnostics"][0]["state"], "demo");
        let args = json!({"request_id":"mcp-clip","track_id":"bgm_focus_pad","start_frame":1,"end_frame":100});
        let first = tests::call(&server, 2, "tools/call", json!({"name":"bgm_clip","arguments":args})).await;
        assert_eq!(first["result"]["isError"], false, "{first}");
        assert_eq!(first["result"]["structuredContent"]["pcm"]["frames"], 99);
        let again = tests::call(&server, 3, "tools/call", json!({"name":"bgm_clip","arguments":args})).await;
        assert_eq!(first["result"], again["result"]);
        let invalid=tests::call(&server,4,"tools/call",json!({"name":"bgm_clip","arguments":{"request_id":"bad-range","track_id":"bgm_focus_pad","start_frame":100,"end_frame":100}})).await;
        assert_eq!(invalid["result"]["isError"], true);
    }
}
