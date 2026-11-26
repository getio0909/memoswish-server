//! MCP 版本策略及进入 SDK 前的安全边界。

use rmcp::model::{ClientJsonRpcMessage, ErrorCode, ErrorData, RequestId};
use serde_json::{Value, json};

/// 仅宣告完整支持的初始化时代版本，不包含要求批量接收的旧版。
pub const SUPPORTED_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18"];

/// 两种传输共用的输入预算。
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// JSON-RPC 错误码。
pub mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// 保留 HTTP 认证预检使用的 JSON-RPC envelope。
pub fn failure(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message.into()}})
}

/// SDK 接受部分宽松 envelope；先拒绝可能被误判为业务请求的混合形状。
/// 参数内容仍在已知工具准入和计量后由原领域适配器解析。
pub(crate) fn validate(value: Value) -> Result<ClientJsonRpcMessage, ErrorData> {
    let invalid = || ErrorData::invalid_request("invalid request", None);
    let object = value.as_object().ok_or_else(invalid)?;
    if object.get("jsonrpc") != Some(&json!("2.0")) {
        return Err(invalid());
    }
    if let Some(id) = object.get("id")
        && !(id.is_string() || id.as_i64().is_some())
    {
        return Err(invalid());
    }
    let method = object.get("method").and_then(Value::as_str);
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    if method.is_some() {
        if has_result || has_error {
            return Err(invalid());
        }
        if !object.contains_key("id") && !method.is_some_and(|m| m.starts_with("notifications/")) {
            return Err(invalid());
        }
        if object.contains_key("id") && method.is_some_and(|m| m.starts_with("notifications/")) {
            return Err(invalid());
        }
        if let Some(params) = object.get("params")
            && !params.is_object()
        {
            return Err(ErrorData::invalid_params("invalid parameters", None));
        }
    } else if object.contains_key("method")
        || object.contains_key("params")
        || has_result == has_error
        || !object.contains_key("id")
    {
        return Err(invalid());
    }
    if let Some(token) = value.get("params").and_then(|p| p.get("_meta")).and_then(|m| m.get("progressToken"))
        && !(token.as_i64().is_some() || token.as_str().is_some_and(|s| s.len() <= 128))
    {
        return Err(ErrorData::invalid_params("invalid progress token", None));
    }
    let message: ClientJsonRpcMessage =
        serde_json::from_value(value).map_err(|_| ErrorData::invalid_params("invalid parameters", None))?;
    // SDK 将部分已知方法的畸形参数解析为 CustomRequest，必须在准入前拒绝。
    if let ClientJsonRpcMessage::Request(request) = &message
        && let rmcp::model::ClientRequest::CustomRequest(custom) = &request.request
        && [
            "initialize",
            "ping",
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/read",
            "resources/templates/list",
            "prompts/list",
            "prompts/get",
            "logging/setLevel",
        ]
        .contains(&custom.method.as_str())
    {
        return Err(ErrorData::invalid_params("invalid parameters", None));
    }
    Ok(message)
}

/// 取消仅使用类型正确的原请求 ID，忽略不可信原因。
pub(crate) fn cancellation_id(value: &Value) -> Option<RequestId> {
    if value["method"] != "notifications/cancelled"
        || value.get("id").is_some()
        || value["params"].get("reason").is_some_and(|v| !v.is_string())
    {
        return None;
    }
    let id = value["params"].get("requestId")?;
    if !(id.is_string() || id.as_i64().is_some()) {
        return None;
    }
    serde_json::from_value(id.clone()).ok()
}

/// 只有合法 ID 才能回显，避免把畸形对象作为响应 ID。
pub(crate) fn request_id(value: &Value) -> Option<RequestId> {
    value
        .get("id")
        .filter(|id| id.is_string() || id.as_i64().is_some())
        .cloned()
        .and_then(|id| serde_json::from_value(id).ok())
}

pub(crate) fn rpc_error(code: i64, message: String) -> ErrorData {
    ErrorData::new(ErrorCode(code as i32), message, None)
}

/// rmcp 的 verbose 诊断含原始负载；嵌入方须在所有级别过滤 SDK target。
pub fn diagnostic_target_allowed(target: &str) -> bool {
    target != "rmcp" && !target.starts_with("rmcp::")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::{Layer, layer::SubscriberExt};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn diagnostics_filter_excludes_payloads_at_every_level() {
        use tokio_util::codec::Decoder;
        for level in ["info", "debug", "trace,rmcp=trace"] {
            let capture = Capture(Arc::new(Mutex::new(Vec::new())));
            let output = capture.clone();
            let subscriber = tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::new(level)).with(
                tracing_subscriber::fmt::layer().with_ansi(false).with_writer(move || output.clone()).with_filter(
                    tracing_subscriber::filter::filter_fn(|metadata| diagnostic_target_allowed(metadata.target())),
                ),
            );
            tracing::subscriber::with_default(subscriber, || {
                let error = memoswish_core::CoreError::internal("S28_SECRET_SENTINEL");
                tracing::error!(target: "rmcp::service", display = %error, debug = ?error, chain = %format!("{error:#}"), "SDK error");
                let mut codec = rmcp::transport::async_rw::JsonRpcMessageCodec::<Value>::new();
                let mut bytes = tokio_util::bytes::BytesMut::from(&b"{\"S28_SECRET_SENTINEL\":bad}\n"[..]);
                assert!(codec.decode(&mut bytes).is_err());
                tracing::info!(target: "memoswish::mcp::protocol", code = error.code(), "safe MCP failure");
            });
            let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            assert!(logs.contains("safe MCP failure"));
            assert!(!logs.contains("S28_SECRET_SENTINEL"), "{level}: {logs}");
        }
    }
}
