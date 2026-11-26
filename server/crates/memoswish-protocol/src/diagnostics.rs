//! 诊断只携带有限分类，不接收异常文本、路径、地址或任意上下文。
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticReport {
    pub report_id: String,
    pub privacy_revision: i64,
    pub captured_at_ms: i64,
    pub purpose_version: String,
    pub build: String,
    pub platform: String,
    pub category: String,
    pub code: String,
    pub frames: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosticReceipt {
    pub report_id: String,
    pub duplicate: bool,
}
