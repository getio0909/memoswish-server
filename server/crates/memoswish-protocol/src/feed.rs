//! 无限信息流分页与预加载清单。

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::card::{AssetRef, Card};

/// 某张卡进入信息流的原因（可变奖赏机制的可观测性）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedReason {
    /// FSRS 判定到期需要复习。
    Due,
    /// 从未学习过的新卡。
    New,
    /// 用户标记的重点卡（双击 / 多次循环）强化。
    Reinforce,
    /// 可变奖赏：随机插入的“惊喜”卡（高把握的快速胜利或久违的收藏）。
    Surprise,
}

/// 信息流中的一项。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    /// 会话内全局递增的位置序号，客户端埋点必须回传。
    pub slot: u64,
    pub reason: FeedReason,
    pub card: Card,
    /// 用户对此卡当前的记忆可提取率估计（0~1），新卡为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrievability: Option<f32>,
}

/// 预加载条目：客户端应提前下载并解码的资产。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PrefetchEntry {
    pub slot: u64,
    pub card_id: String,
    /// 0 为最高优先级（紧邻当前卡）。
    pub priority: u8,
    pub assets: Vec<AssetRef>,
}

/// 预加载清单（Pre-fetch Manifest）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PrefetchManifest {
    /// 建议在内存中保留的“当前卡之前”的卡片数。
    pub window_before: u8,
    /// 建议提前加载的“当前卡之后”的卡片数。
    pub window_after: u8,
    pub entries: Vec<PrefetchEntry>,
    /// 资产 URL 的有效期（签名 URL 场景）；本地存储时为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// `GET /v1/feed` 返回的一页信息流。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    pub session_id: String,
    pub items: Vec<FeedItem>,
    /// 下一页游标（不透明字符串）。
    pub next_cursor: String,
    pub prefetch: PrefetchManifest,
    pub generated_at: DateTime<Utc>,
}

/// `GET /v1/feed` 查询参数。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct FeedQuery {
    /// preview 返回不可学习的预览页，缺省为普通学习页。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// 客户端会话 ID；为空时服务端新建会话。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// 首次请求的客户端身份；重试保持原值，与 session_id/cursor 互斥。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// 上一页返回的 `next_cursor`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// 每页数量，默认 10，最大 50。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// 仅从指定卡组取卡。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deck_id: Option<String>,
}

/// 学习统计（`GET /v1/stats` 与 MCP `learning_stats`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LearningStats {
    pub total_cards: u32,
    pub seen_cards: u32,
    pub due_cards: u32,
    pub starred_cards: u32,
    /// 已学卡片的平均当前可提取率（0~1）。
    pub average_retrievability: f32,
    pub total_exposures: u64,
}
