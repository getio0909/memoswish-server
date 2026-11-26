//! 租户私有编辑、发布与修订报告的增量契约。
use crate::{Card, CardDraft};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 来源字段均为调用方声明，不表示服务端核实。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ContentProvenance {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub attribution: String,
    #[serde(default)]
    pub rights: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// true 表示 source_id 为原始 UTF-8 身份的 sha256:hex 摘要；缺省为原文。
    #[serde(default, skip_serializing_if = "is_false")]
    pub source_id_is_digest: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_generation_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_publication_claim: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// 未知状态保留原文；只有精确 published 可进入学习。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ContentMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<String>,
    pub publication: String,
    #[serde(default)]
    pub provenance: ContentProvenance,
}

/// 更新必须携带 card.expected_revision；新建不接受已有 ID。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CardSave {
    pub card: CardDraft,
    #[serde(default)]
    pub publish: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ContentProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublicationCommand {
    pub expected_revision: u32,
    pub publish: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DeckEdit {
    pub expected_revision: u32,
    pub title: String,
    pub description: String,
    pub language: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReportCreate {
    pub observed_revision: u32,
    pub text: String,
    #[serde(default)]
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ContentReport {
    pub id: String,
    pub card_id: String,
    pub user_id: String,
    pub observed_revision: u32,
    pub evidence_available: bool,
    pub text: String,
    pub sources: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corrected_revision: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CardRevision {
    pub revision: u32,
    pub card: Card,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StarterDeck {
    pub id: String,
    pub title: String,
    pub description: String,
    pub attribution: String,
    pub rights: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StarterInstall {
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ContentImport {
    pub pack: crate::PortableDeckPack,
    pub idempotency_key: String,
    #[serde(default)]
    pub publish: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContentApkgImport {
    pub apkg: crate::ApkgImportRequest,
    #[serde(default)]
    pub publish: bool,
}
