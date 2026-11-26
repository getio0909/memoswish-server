//! 持久提交回执只保存原操作事实，不携带历史卡片或交付地址。
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TtsDisposition {
    Attached,
    Conflict,
    NotFound,
    RequesterRevoked,
    Failed,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TtsAttachmentReceipt {
    pub item_id: String,
    pub card_id: String,
    pub expected_revision: u32,
    pub disposition: TtsDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_revision: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TtsSubmissionItem {
    pub item_id: String,
    pub card_id: String,
    pub expected_revision: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<TtsAttachmentReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TtsSubmission {
    pub request_id: String,
    /// 仅当每项都有已提交终态回执时为 true；不表示每项都成功。
    pub complete: bool,
    pub items: Vec<TtsSubmissionItem>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipts_roundtrip_and_tolerate_future_fields() {
        let example = crate::examples::sample_tts_submission();
        assert_eq!(serde_json::from_value::<TtsSubmission>(serde_json::to_value(&example).unwrap()).unwrap(), example);
        let mut receipt = serde_json::to_value(example.items[0].receipt.as_ref().unwrap()).unwrap();
        receipt["future"] = serde_json::json!(true);
        receipt["disposition"] = serde_json::json!("future");
        receipt.as_object_mut().unwrap().remove("resulting_revision");
        receipt.as_object_mut().unwrap().remove("asset_id");
        let decoded: TtsAttachmentReceipt = serde_json::from_value(receipt).unwrap();
        assert_eq!(decoded.disposition, TtsDisposition::Unknown);
        assert!(decoded.resulting_revision.is_none());
        assert!(decoded.asset_id.is_none());
        assert!(serde_json::to_value(decoded).unwrap().get("asset_id").is_none());
    }
}

/// 公共诊断只返回已分类状态，不包含程序、模型路径、URL 或原始输出。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SpeechDiagnostic {
    pub engine: String,
    pub configured: bool,
    pub state: SpeechDiagnosticState,
    pub voices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SpeechDiagnosticState {
    Unconfigured,
    Unchecked,
    Available,
    Unavailable,
    Demo,
    #[serde(other)]
    Unknown,
}

/// 完整物化源帧范围，不支持独立 intro/outro 或子循环。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BgmClip {
    pub request_id: String,
    pub track_id: String,
    pub start_frame: u32,
    pub end_frame: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}
