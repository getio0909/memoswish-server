//! 学习者控制命令使用显式修订，不提供反转或自动重放。
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LearnerPreferences {
    pub revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_retention: Option<f64>,
    pub effective_retention: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetentionCommand {
    pub expected_revision: i64,
    // 省略不修改，显式 null 重置，数值设置覆盖值。
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "retention_change")]
    #[schemars(with = "Option<f64>")]
    pub desired_retention: Option<Option<f64>>,
}

fn retention_change<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Option<f64>>, D::Error> {
    Option::<f64>::deserialize(deserializer).map(Some)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CardControlAction {
    Suspend,
    Bury,
    Resume,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CardControlCommand {
    pub expected_revision: i64,
    pub action: CardControlAction,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LearnerCardControl {
    pub card_id: String,
    pub revision: i64,
    pub suspended: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buried_until: Option<DateTime<Utc>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HiddenCardsPage {
    pub items: Vec<LearnerCardControl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after: Option<String>,
}
