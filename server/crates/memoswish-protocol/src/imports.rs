//! 导入请求的可选重试身份；REST 使用同一语义的 Idempotency-Key 头。
use crate::DeckPack;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeckImportRequest {
    pub pack: DeckPack,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_tts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApkgImportRequest {
    pub apkg_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// 嵌入媒体的独立封套；不具有旧 DeckPack 的顶层 deck/cards。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PortableDeckPack {
    pub version: String,
    pub content: DeckPack,
    pub media: Vec<PortableMedia>,
}

/// 包内标识仅参与内容映射，不能提供存储授权。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PortableMedia {
    pub id: String,
    pub mime: String,
    pub bytes: u64,
    pub sha256: String,
    pub data_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortableImportRequest {
    pub pack: PortableDeckPack,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}
