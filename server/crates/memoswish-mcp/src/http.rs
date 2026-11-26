//! rmcp Streamable HTTP 与逐请求认证、OAuth 预检。

use std::sync::Arc;

use crate::protocol::{MAX_MESSAGE_BYTES, SUPPORTED_VERSIONS, request_id, validate};
use crate::server::Handler;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
};

use crate::protocol::{codes, failure};
use crate::server::McpServer;

/// 会话 ID 响应头。
pub const SESSION_HEADER: &str = "mcp-session-id";

/// HTTP 传输状态。
#[derive(Clone)]
pub struct HttpState {
    pub server: Arc<McpServer>,
    #[cfg(feature = "mcp-oauth")]
    pub oauth: Option<Arc<memoswish_auth::oauth::OAuthService>>,
    /// 允许的 Origin 列表；为空时只允许无 Origin 或本机 Origin。
    pub allowed_origins: Arc<Vec<String>>,
    /// 可信 Host 来自部署配置，不读取 Forwarded。
    pub allowed_hosts: Arc<Vec<String>>,
}

/// 挂载在 `/mcp` 的路由。
/// 参考条件：mcp.http_enabled = true。
pub fn router(state: HttpState) -> Router {
    Router::new().route("/mcp", post(handle).get(handle).delete(handle)).with_state(state)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
}

fn json_error(status: StatusCode, code: i64, msg: &str) -> Response {
    (status, axum::Json(failure(serde_json::Value::Null, code, msg))).into_response()
}

fn challenge(st: &HttpState, status: StatusCode, scopes: Option<&str>) -> Response {
    let mut value = "Bearer realm=\"learntok\"".to_string();
    #[cfg(feature = "mcp-oauth")]
    if let Some(oauth) = &st.oauth {
        value.push_str(&format!(", resource_metadata=\"{}\"", oauth.config.metadata_url()));
    }
    let _ = st;
    if let Some(scopes) = scopes {
        value.push_str(&format!(", error=\"insufficient_scope\", scope=\"{scopes}\""));
    }
    let mut response = json_error(
        status,
        codes::INVALID_REQUEST,
        if scopes.is_some() { "insufficient scope" } else { "authentication required" },
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, value);
    }
    response
}
async fn authenticate(st: &HttpState, headers: &HeaderMap) -> memoswish_core::CoreResult<memoswish_core::Principal> {
    #[cfg(feature = "mcp-oauth")]
    if let Some(token) = bearer(headers).filter(|t| t.starts_with("lto_")) {
        let oauth =
            st.oauth.as_ref().ok_or_else(|| memoswish_core::CoreError::Unauthorized("OAuth is disabled".into()))?;
        return oauth.authenticate(token, &oauth.config.mcp_resource).await;
    }
    st.server.services.auth.authenticate(bearer(headers)).await
}

/// OAuth 在任何副作用前检查整批请求以及自动 TTS 等隐含权限。
/// 返回 OAuth 预检权限，供请求处理与离线参考生成共用。
#[doc(hidden)]
pub fn required_permissions(value: &serde_json::Value) -> Vec<memoswish_core::Permission> {
    use memoswish_core::Permission::*;
    if let Some(batch) = value.as_array() {
        let mut result = Vec::new();
        for msg in batch {
            for p in required_permissions(msg) {
                if !result.contains(&p) {
                    result.push(p);
                }
            }
        }
        return result;
    }
    let params = &value["params"];
    let args = &params["arguments"];
    let mut required = match value["method"].as_str().unwrap_or("") {
        "resources/list" => vec![ContentRead],
        "resources/read" if params["uri"] == "memoswish://stats" => vec![FeedRead],
        "resources/read" => vec![ContentRead],
        "tools/call" => match params["name"].as_str().unwrap_or("") {
            "explanation_reconcile" => vec![ContentRead, BillingManage],
            "deck_list"
            | "card_list"
            | "card_get"
            | "card_explain"
            | "explanation_lookup"
            | "deck_export"
            | "deck_export_portable" => {
                vec![ContentRead]
            }
            "deck_create" | "deck_delete" | "card_delete" | "card_save" | "card_publish" | "deck_import_status" => {
                vec![ContentWrite]
            }
            "card_report" => vec![ContentRead, FeedbackWrite],
            "deck_import_portable" => {
                if args["pack"]["media"].as_array().is_some_and(|m| !m.is_empty()) {
                    vec![ContentWrite, MediaWrite]
                } else {
                    vec![ContentWrite]
                }
            }
            "deck_import_apkg" => vec![ContentWrite, MediaWrite],
            "card_upsert" | "deck_import" => vec![ContentWrite],
            "material_slice" => {
                if args["commit"] == true {
                    vec![ContentRead, ContentWrite]
                } else {
                    vec![ContentRead]
                }
            }
            "tts_synthesize" | "tts_submit" | "tts_submission_status" => vec![TtsGenerate, ContentRead, ContentWrite],
            "tts_engines" | "bgm_list" | "bgm_match" => vec![MediaRead],
            "bgm_assign" => vec![ContentRead, ContentWrite],
            "bgm_generate" | "bgm_upload" => vec![MediaWrite],
            "bgm_clip" => vec![MediaRead, MediaWrite],
            "feed_preview" | "learning_stats" => vec![FeedRead],
            _ => vec![],
        },
        _ => vec![],
    };
    if value["method"] == "tools/call"
        && matches!(params["name"].as_str(), Some("card_upsert" | "deck_import" | "material_slice"))
        && (params["name"] != "material_slice" || args["commit"] == true)
        && args["content_lifecycle"] != true
        && args["auto_tts"].as_bool().unwrap_or(true)
    {
        for p in [TtsGenerate, ContentRead, ContentWrite] {
            if !required.contains(&p) {
                required.push(p);
            }
        }
    }
    if value["method"] == "tools/call"
        && params["name"] == "card_upsert"
        && !args["bgm"].is_null()
        && !required.contains(&ContentRead)
    {
        required.push(ContentRead);
    }
    required
}

/// 保留 JSON-only、SSE-only 及无 Accept 的旧客户端入口，SDK 收到规范双类型。
fn response_format(headers: &HeaderMap) -> Option<bool> {
    if !headers.contains_key(header::ACCEPT) {
        return Some(true);
    }
    let mut json = false;
    let mut sse = false;
    for value in headers.get_all(header::ACCEPT) {
        for media in value.to_str().ok()?.split(',') {
            let mut parameters = media.split(';');
            let essence = parameters.next()?.trim();
            let mut quality = 1.0_f32;
            for parameter in parameters {
                if let Some((name, value)) = parameter.trim().split_once('=')
                    && name.eq_ignore_ascii_case("q")
                {
                    quality = value.parse().ok()?;
                    if !(0.0..=1.0).contains(&quality) {
                        return None;
                    }
                }
            }
            if quality > 0.0 {
                json |= essence.eq_ignore_ascii_case("application/json") || essence == "*/*";
                sse |= essence.eq_ignore_ascii_case("text/event-stream") || essence == "*/*";
            }
        }
    }
    (json || sse).then_some(json)
}

async fn handle(State(st): State<HttpState>, request: Request) -> Response {
    // 凭据不保存在 handler 或会话中，每次请求都重新读取当前授权。
    let principal = match authenticate(&st, request.headers()).await {
        Ok(principal) => principal,
        Err(_) => return challenge(&st, StatusCode::UNAUTHORIZED, None),
    };
    let (mut parts, body) = request.into_parts();
    if let Some(origin) = parts.headers.get(header::ORIGIN) {
        let valid = origin.to_str().ok().is_some_and(|origin| {
            origin == "null"
                || origin.split_once("://").is_some_and(|(scheme, authority)| {
                    matches!(scheme, "http" | "https")
                        && !authority.contains('@')
                        && authority.parse::<axum::http::uri::Authority>().is_ok_and(|authority| {
                            authority.port_u16().is_some() || authority.as_str() == authority.host()
                        })
                })
        });
        if !valid {
            return json_error(StatusCode::FORBIDDEN, codes::INVALID_REQUEST, "invalid Origin header");
        }
    }
    parts.headers.remove(SESSION_HEADER);
    let origins = if st.allowed_origins.iter().any(|origin| origin == "*") {
        // 交给 SDK 校验 Origin 语法，同时保留显式 wildcard 配置的既有含义。
        parts
            .headers
            .get(header::ORIGIN)
            .and_then(|origin| origin.to_str().ok())
            .map(|origin| vec![origin.to_owned()])
            .unwrap_or_default()
    } else {
        let mut origins = st.allowed_origins.as_ref().clone();
        origins.extend(
            [
                "http://localhost:*",
                "https://localhost:*",
                "http://127.0.0.1:*",
                "https://127.0.0.1:*",
                "http://[::1]:*",
                "https://[::1]:*",
            ]
            .map(String::from),
        );
        origins
    };
    let mut config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_allowed_origins(origins)
        .enforce_origin_validation()
        .with_max_request_body_bytes(MAX_MESSAGE_BYTES)
        .with_sse_keep_alive(None)
        .with_sse_retry(None);
    // SDK 的空 Host 列表会关闭保护，空配置沿用其 loopback 默认值。
    if !st.allowed_hosts.is_empty() {
        config = config.with_allowed_hosts(st.allowed_hosts.as_ref().clone());
    }
    if parts.method == Method::POST {
        let Some(json_response) = response_format(&parts.headers) else {
            return json_error(StatusCode::NOT_ACCEPTABLE, codes::INVALID_REQUEST, "unsupported Accept header");
        };
        config = config.with_json_response(json_response);
        if !parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json"))
        {
            return json_error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                codes::INVALID_REQUEST,
                "Content-Type must be application/json",
            );
        }
        let bytes = match to_bytes(body, MAX_MESSAGE_BYTES).await {
            Ok(bytes) => bytes,
            Err(error) => {
                use std::error::Error;
                let status = if error.source().is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                };
                return json_error(status, codes::INVALID_REQUEST, "request body rejected");
            }
        };
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => return json_error(StatusCode::BAD_REQUEST, codes::PARSE_ERROR, "invalid JSON"),
        };
        // 即使不支持数组，也在拒绝前保留全负载 OAuth 权限预检及 challenge。
        #[cfg(feature = "mcp-oauth")]
        if principal.via == "mcp_oauth" {
            let required = required_permissions(&value);
            if required.iter().any(|permission| !principal.can(*permission)) {
                let scopes = required.iter().map(|permission| permission.as_scope()).collect::<Vec<_>>().join(" ");
                return challenge(&st, StatusCode::FORBIDDEN, Some(&scopes));
            }
        }
        if let Err(error) = validate(value.clone()) {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(failure(
                    request_id(&value).map(|id| id.into_json_value()).unwrap_or(serde_json::Value::Null),
                    i64::from(error.code.0),
                    error.message,
                )),
            )
                .into_response();
        }
        if let Some(version) = parts.headers.get("mcp-protocol-version") {
            let Ok(version) = version.to_str() else {
                return json_error(StatusCode::BAD_REQUEST, codes::INVALID_REQUEST, "unsupported protocol version");
            };
            if !SUPPORTED_VERSIONS.contains(&version) {
                return json_error(StatusCode::BAD_REQUEST, codes::INVALID_REQUEST, "unsupported protocol version");
            }
        } else if value["method"] != "initialize" {
            // 无头旧客户端采用最早受支持版本，不暗中降到已退役的批量协议。
            parts.headers.insert("mcp-protocol-version", HeaderValue::from_static("2025-06-18"));
        }
        if let Some(version) = value["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str()
            && !SUPPORTED_VERSIONS.contains(&version)
        {
            return json_error(StatusCode::BAD_REQUEST, codes::INVALID_REQUEST, "unsupported protocol version");
        }
        let cancellation =
            if value["method"] == "notifications/cancelled" { crate::protocol::cancellation_id(&value) } else { None };
        let authority = crate::control::http_authority(&principal, bearer(&parts.headers));
        parts.headers.insert(header::ACCEPT, HeaderValue::from_static("application/json, text/event-stream"));
        parts.extensions.insert(principal);
        let response = sdk_response(&st, config, Request::from_parts(parts, Body::from(bytes))).await;
        // 必须先通过 SDK 的 Host、Origin 与协议校验，才允许跨 POST 控制。
        if response.status() == StatusCode::ACCEPTED
            && let Some(id) = cancellation
        {
            st.server.active_calls.cancel(authority, id);
        }
        return response;
    }
    parts.extensions.insert(principal);
    sdk_response(&st, config, Request::from_parts(parts, Body::empty())).await
}

async fn sdk_response(st: &HttpState, config: StreamableHttpServerConfig, request: Request) -> Response {
    let server = st.server.clone();
    let service = StreamableHttpService::new(
        move || Ok(Handler { server: server.as_ref().clone(), stdio_principal: None, stdio_authority: None }),
        Arc::new(NeverSessionManager::default()),
        config,
    );
    let response = service.handle(request).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        // SDK 内部错误可能携带 serde/body/provider 细节，统一受控英文消息。
        let status = response.status();
        let mut safe = json_error(status, codes::INVALID_REQUEST, "MCP transport request rejected");
        if let Some(allow) = response.headers().get(header::ALLOW) {
            safe.headers_mut().insert(header::ALLOW, allow.clone());
        }
        return safe;
    }
    response.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::tests::test_server;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn app() -> Router {
        router(HttpState {
            server: Arc::new(test_server().await),
            allowed_origins: Arc::new(vec![]),
            allowed_hosts: Arc::new(vec!["localhost".into(), "127.0.0.1".into(), "::1".into()]),
            #[cfg(feature = "mcp-oauth")]
            oauth: None,
        })
    }

    fn post_req(body: &str, accept: &str, origin: Option<&str>) -> Request<Body> {
        let mut b = Request::post("/mcp")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("accept", accept);
        if let Some(o) = origin {
            b = b.header("origin", o);
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn http_json_and_sse() {
        let app = app().await;
        let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#;
        let resp = app.clone().oneshot(post_req(init, "application/json, text/event-stream", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key(SESSION_HEADER));
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["result"]["protocolVersion"], "2025-06-18");

        let ping = r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;
        let resp = app.clone().oneshot(post_req(ping, "text/event-stream", None)).await.unwrap();
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");
        let body = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        let event = body.lines().find_map(|line| line.strip_prefix("data:")).expect("SSE data event");
        let event: serde_json::Value = serde_json::from_str(event.trim()).unwrap();
        assert_eq!(body.lines().filter(|line| line.starts_with("data:")).count(), 1);
        assert!(!body.lines().any(|line| line.starts_with("id:")));
        assert_eq!(event["id"], 2);
        assert_eq!(event["result"], serde_json::json!({}));

        let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let resp = app.clone().oneshot(post_req(note, "application/json", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let resp = app.clone().oneshot(post_req(ping, "application/json", Some("https://evil.example"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp =
            app.clone().oneshot(post_req(ping, "application/json", Some("http://localhost:3000"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp =
            app.oneshot(Request::get("/mcp").header("host", "localhost").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod boundary_tests;

#[cfg(test)]
mod submission_scope_tests {
    #[test]
    fn durable_tools_preflight_requires_all_mutation_permissions() {
        use memoswish_core::Permission::{ContentRead, ContentWrite, TtsGenerate};
        for name in ["tts_submit", "tts_submission_status"] {
            assert_eq!(
                super::required_permissions(&serde_json::json!({"method":"tools/call","params":{"name":name}})),
                vec![TtsGenerate, ContentRead, ContentWrite]
            );
        }
    }
}

#[cfg(test)]
mod portable_scope_tests {
    use super::*;
    use serde_json::{Value, json};
    #[test]
    fn renamed_resources_preflight_keeps_statistics_and_content_permissions_distinct() {
        use memoswish_core::Permission::{ContentRead, FeedRead};
        for (uri, permissions) in
            [("memoswish://stats", vec![FeedRead]), ("memoswish://decks/private-deck", vec![ContentRead])]
        {
            assert_eq!(required_permissions(&json!({"method":"resources/read","params":{"uri":uri}})), permissions);
        }
    }

    #[test]
    fn portable_scopes_do_not_request_tts_or_media_for_empty_packages() {
        use memoswish_core::Permission::*;
        let call = |name: &str, media: Value| json!({"method":"tools/call","params":{"name":name,"arguments":{"pack":{"media":media}}}});
        assert_eq!(required_permissions(&call("deck_export_portable", json!([]))), vec![ContentRead]);
        assert_eq!(required_permissions(&call("deck_import_portable", json!([]))), vec![ContentWrite]);
        assert_eq!(required_permissions(&call("deck_import_portable", json!([{}]))), vec![ContentWrite, MediaWrite]);
    }
}
