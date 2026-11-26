//! 无感行为埋点（Implicit Feedback）批量上报。

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 离开卡片时的滑动方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum SwipeDirection {
    /// 上滑到下一张。
    #[default]
    Next,
    /// 下滑回到上一张。
    Previous,
    /// 未滑动离开（App 切后台、会话结束等）。
    None,
}

/// 单张卡片一次曝光的微交互指标。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ImplicitFeedback {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    /// 客户端生成的 UUID，用于幂等去重。
    pub event_id: String,
    pub card_id: String,
    /// 对应 `FeedItem.slot`。
    pub slot: u64,
    /// 卡片完全进入视口的时间。
    pub shown_at: DateTime<Utc>,
    /// 停留时长（毫秒）。
    pub dwell_time_ms: u32,
    /// TTS 完整播放（含自动循环）次数。
    pub loop_count: u32,
    /// 离开时的划走速度（视口高度 / 秒，非负）。
    pub swipe_velocity: f32,
    #[serde(default)]
    pub swipe_direction: SwipeDirection,
    /// 是否翻转查看背面。
    #[serde(default)]
    pub flipped: bool,
    /// 是否双击（点赞 / 加入重点记忆库）。
    #[serde(default)]
    pub double_tapped: bool,
    /// 是否长按呼出 AI 解析抽屉。
    #[serde(default)]
    pub long_pressed: bool,
    /// 曝光时客户端是否处于静音状态（静音时 loop_count 不可信）。
    #[serde(default)]
    pub muted: bool,
}

/// `POST /v1/feedback` 请求体。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FeedbackBatch {
    pub session_id: String,
    /// 客户端安装实例 ID。
    pub client_id: String,
    /// 客户端发送时间，用于时钟偏移校正。
    pub sent_at: DateTime<Utc>,
    /// 单批最多 200 条。
    pub events: Vec<ImplicitFeedback>,
}

/// 单批事件上限。
pub const MAX_FEEDBACK_BATCH: usize = 200;

/// 被拒绝的单条事件。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RejectedEvent {
    pub event_id: String,
    pub reason: String,
}

/// `POST /v1/feedback` 响应体。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct FeedbackAck {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipts: Option<Vec<crate::FeedbackReceipt>>,
    /// 新接收并已更新记忆模型的事件数。
    pub accepted: u32,
    /// 因重复 `event_id` 被忽略的事件数（客户端可视为成功）。
    pub duplicates: u32,
    #[serde(default)]
    pub rejected: Vec<RejectedEvent>,
}
