//! 个人资料库、显式收藏及真实接受历史。
use crate::{Card, LearnerCardControl};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FavoriteCommand {
    pub operation_id: String,
    pub desired_state: bool,
    pub expected_revision: u32,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FavoriteState {
    pub card_id: String,
    pub starred: bool,
    pub revision: u32,
}
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LibraryQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starred: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LibraryEntry {
    pub card: Card,
    pub favorite: FavoriteState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<LearnerCardControl>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LibraryPage {
    pub items: Vec<LibraryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReviewHistoryEntry {
    pub event_id: String,
    pub card_id: String,
    pub received_at: DateTime<Utc>,
    // 未知旧记录保持未知，不从评分推断已调度。
    pub disposition: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rating: Option<u8>,
    pub archived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<LearnerCardControl>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReviewHistoryPage {
    pub items: Vec<ReviewHistoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedbackReceipt {
    pub event_id: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
}
