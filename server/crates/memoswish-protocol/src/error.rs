//! 统一错误响应体。

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 所有非 2xx HTTP 响应的 JSON 结构。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApiError {
    /// 机器可读错误码，例如 `not_found`、`unauthorized`、`quota_exceeded`。
    pub code: String,
    /// 人类可读的英文描述。
    pub message: String,
}
