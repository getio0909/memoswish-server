//! 学习微卡片（Micro Card）及其视听挂载数据。
//!
//! 设计原则：**领域无关**。卡片不预设学科（语言、编程、历史、化学、音乐……都适用）：
//! - 每一面由任意数量的 [`ContentBlock`] 组成（文本 / 代码 / 公式 / 图片 / 引用 / 列表 / 表格 / 链接）；
//! - `template` 只是渲染提示（自由字符串），客户端不认识时回退到通用布局；
//! - `attributes` 承载领域特有的结构化元数据（例如 `{"year": 618, "dynasty": "唐"}`）。

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// 默认渲染模板。
pub const DEFAULT_TEMPLATE: &str = "basic";

fn default_template() -> String {
    DEFAULT_TEMPLATE.to_string()
}

/// 二进制资产引用（音频、图片等）。`sha256` 同时作为客户端磁盘缓存键。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AssetRef {
    /// 对象存储内部键，例如 `tenants/<tid>/tts/<sha>.wav`。
    pub key: String,
    /// 可直接下载的 URL；以 `/` 开头时表示相对于服务端 base URL。
    pub url: String,
    /// MIME 类型，例如 `audio/wav`。
    pub mime: String,
    /// 字节数。
    pub bytes: u64,
    /// 内容 SHA-256（小写十六进制）。
    pub sha256: String,
}

/// 卡面内容块。以 `type` 字段区分；客户端必须容忍未知的 `type`（跳过或降级为纯文本）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// 文本，支持轻量 Markdown（粗体、斜体、行内代码、链接）。
    Text { text: String },
    /// 代码片段。
    Code {
        /// 语言标识，例如 `rust`、`python`、`sql`。
        language: String,
        source: String,
        /// 需要高亮的行号（从 1 开始）。
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        highlight_lines: Vec<u32>,
    },
    /// 数学 / 化学公式（LaTeX）。
    Math {
        latex: String,
        /// 是否独立成行展示。
        #[serde(default)]
        display: bool,
    },
    /// 图片。
    Image {
        asset: AssetRef,
        /// 替代文本（无障碍 + 图片加载失败时显示）。
        #[serde(default)]
        alt: String,
    },
    /// 引用 / 名言。
    Quote {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
    /// 列表。
    List {
        items: Vec<String>,
        #[serde(default)]
        ordered: bool,
    },
    /// 表格。
    Table {
        #[serde(default)]
        header: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// 外部链接。
    Link {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
}

impl ContentBlock {
    /// 便捷构造：文本块。
    pub fn text(s: impl Into<String>) -> Self {
        ContentBlock::Text { text: s.into() }
    }

    /// 该块中适合朗读的纯文本（代码、公式、图片、表格、链接不朗读）。
    pub fn speakable_text(&self) -> Option<&str> {
        match self {
            ContentBlock::Text { text } | ContentBlock::Quote { text, .. } => Some(text),
            _ => None,
        }
    }

    /// 块内引用的资产（用于预加载清单）。
    pub fn asset(&self) -> Option<&AssetRef> {
        match self {
            ContentBlock::Image { asset, .. } => Some(asset),
            _ => None,
        }
    }
}

/// 卡片的某一面。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct CardFace {
    /// 主标题（正面通常是要记住的对象或问题；背面可为空）。
    #[serde(default)]
    pub title: String,
    /// 副标题：发音 / 拼音 / 年代 / 化学式 / 作者等任意短注释。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    /// 内容块，按顺序渲染。
    #[serde(default)]
    pub blocks: Vec<ContentBlock>,
}

impl CardFace {
    /// 便捷构造：标题 + 可选文本块。
    pub fn simple(title: impl Into<String>, text: impl Into<String>) -> Self {
        let text = text.into();
        Self {
            title: title.into(),
            subtitle: None,
            blocks: if text.is_empty() { vec![] } else { vec![ContentBlock::Text { text }] },
        }
    }

    /// 第一个可朗读内容块的文本（若不存在则返回空字符串）。
    pub fn primary_text(&self) -> &str {
        self.blocks.iter().find_map(ContentBlock::speakable_text).unwrap_or("")
    }
}

/// 逐字（逐词）时间戳，驱动卡拉 OK 高亮。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WordTimestamp {
    /// 该词的展示文本。
    pub text: String,
    /// 起始时间（毫秒，相对音频起点）。
    pub start_ms: u32,
    /// 结束时间（毫秒，`end_ms >= start_ms`）。
    pub end_ms: u32,
    /// 在 `TtsTrack.text` 中的起始位置（Unicode 标量下标，含）。
    pub char_start: u32,
    /// 在 `TtsTrack.text` 中的结束位置（Unicode 标量下标，不含）。
    pub char_end: u32,
}

/// TTS 发音音轨。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TtsTrack {
    /// 缺省表示未知，不从引擎或时间戳推断质量。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment_quality: Option<AlignmentQuality>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_kind: Option<AudioKind>,
    /// 沿用内容来源词汇；仅为来源声明，不表示权利核验。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::ContentProvenance>,
    /// 音频资产。
    pub audio: AssetRef,
    /// 被朗读的原文。
    pub text: String,
    /// BCP-47 语言标签，例如 `en-US`、`zh-CN`。
    pub language: String,
    /// 音色 / 发音人标识。
    pub voice: String,
    /// 生成该音轨的引擎标识，例如 `placeholder`、`espeak-ng`。
    pub engine: String,
    /// 音频总时长（毫秒）。
    pub duration_ms: u32,
    /// 逐词时间戳，按 `start_ms` 升序且互不重叠。
    pub words: Vec<WordTimestamp>,
}

/// 背景音乐曲目。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BgmTrack {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::ContentProvenance>,
    /// 输出完整循环及源范围；所有帧坐标均为半开区间。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcm: Option<PcmLoop>,
    pub id: String,
    /// 曲库版本；历史 JSON 缺省为 1，嵌入卡片的曲目保留其挂载时快照。
    #[serde(default = "initial_revision")]
    pub revision: u32,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artist: Option<String>,
    pub asset: AssetRef,
    pub duration_ms: u32,
    /// 每分钟节拍数。
    pub bpm: u16,
    /// 情绪标签，例如 `calm`、`focus`、`upbeat`、`epic`。
    #[serde(default)]
    pub moods: Vec<String>,
    /// 能量值 0.0 ~ 1.0。
    pub energy: f32,
    /// 无缝循环起点（毫秒）。
    #[serde(default)]
    pub loop_start_ms: u32,
    /// 无缝循环终点（毫秒，0 表示曲目结尾）。
    #[serde(default)]
    pub loop_end_ms: u32,
    /// 授权说明，例如 `CC0`、`generated`。
    pub license: String,
}

fn initial_revision() -> u32 {
    1
}

/// 卡片切换时 BGM 的处理策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum BgmPolicy {
    /// 与上一张卡相同主题时连续播放，不重新开始。
    #[default]
    Continue,
    /// 主题（`theme_key`）变化时交叉淡入淡出切换曲目。
    SwitchOnTheme,
    /// 本卡静音 BGM。
    Silence,
}

/// 卡片上挂载的 BGM。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BgmBinding {
    pub track: BgmTrack,
    #[serde(default)]
    pub policy: BgmPolicy,
    /// 主题键：相同主题键的连续卡片共享同一条 BGM 而不重启。
    pub theme_key: String,
    /// BGM 基础音量 0.0 ~ 1.0（闪避前）。
    pub base_volume: f32,
}

/// 闪避包络曲线形状。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum DuckCurve {
    Linear,
    #[default]
    EaseOut,
    Exponential,
}

/// 音频闪避（Audio Ducking）参数：TTS 发声时压低 BGM。
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DuckingParams {
    /// 闪避后 BGM 音量占基础音量的比例，推荐 0.2 ~ 0.3。
    pub duck_ratio: f32,
    /// 压低所用时间（毫秒），规范要求 <= 150。
    pub attack_ms: u32,
    /// TTS 结束后保持压低的时间（毫秒），避免词间呼吸导致音量抖动。
    pub hold_ms: u32,
    /// 恢复所用时间（毫秒）。
    pub release_ms: u32,
    #[serde(default)]
    pub curve: DuckCurve,
}

impl Default for DuckingParams {
    fn default() -> Self {
        Self { duck_ratio: 0.25, attack_ms: 150, hold_ms: 120, release_ms: 400, curve: DuckCurve::EaseOut }
    }
}

impl DuckingParams {
    /// 校验参数是否落在规范允许的范围内。
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.duck_ratio) {
            return Err("duck_ratio must be within [0, 1]".into());
        }
        if self.attack_ms > 1000 || self.release_ms > 5000 || self.hold_ms > 5000 {
            return Err("ducking timings out of range".into());
        }
        Ok(())
    }
}

/// 卡片视觉主题。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CardVisual {
    /// 背景色 `#RRGGBB`。
    pub background: String,
    /// 强调色（卡拉 OK 高亮色）`#RRGGBB`。
    pub accent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<AssetRef>,
}

impl Default for CardVisual {
    fn default() -> Self {
        Self { background: "#101018".into(), accent: "#FE2C55".into(), image: None }
    }
}

/// 学习微卡片。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Card {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<crate::ContentMetadata>,
    pub id: String,
    pub deck_id: String,
    /// 渲染模板提示（自由字符串），例如 `basic`、`term`、`qa`、`cloze`、`code`、`formula`、`timeline`。
    /// 客户端不认识的模板必须回退到通用布局。
    #[serde(default = "default_template")]
    pub template: String,
    /// 卡片主语言（BCP-47），决定 TTS 发音语言。
    pub language: String,
    pub front: CardFace,
    pub back: CardFace,
    #[serde(default)]
    pub tags: Vec<String>,
    /// 领域特有的结构化元数据（任意 JSON 对象）。客户端可渲染为键值标签。
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub attributes: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tts: Option<TtsTrack>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bgm: Option<BgmBinding>,
    #[serde(default)]
    pub ducking: DuckingParams,
    #[serde(default)]
    pub visual: CardVisual,
    /// 每次内容变化递增，客户端据此失效缓存。
    pub revision: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 卡组。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Deck {
    // 旧包缺失或显式 null 时不补出版本，保留原始指纹与字节预算。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u32>,
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub language: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub card_count: u32,
    pub created_at: DateTime<Utc>,
}

/// 卡组内容包（Deck Pack）：用于一键导出与跨实例导入卡组及卡片元数据。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DeckPack {
    /// 内容包格式版本（默认 `"1.0"`）。
    pub version: String,
    /// 卡组定义。
    pub deck: Deck,
    /// 卡组内的卡片列表。
    pub cards: Vec<Card>,
    /// 导出时间（UTC）。
    pub exported_at: DateTime<Utc>,
}

/// `POST /v1/cards/{card_id}/explain` 请求参数。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ExplainRequest {
    /// 外部执行必需的持久调用身份；缺省只使用本地解析。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// 用户追问的问题；为空时生成该卡片的默认深度解析与类比。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question: Option<String>,
    /// 期望输出语言（BCP-47，如 `zh-CN` 或 `en-US`）；缺省跟随卡片或客户端。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

/// 卡片 AI 深度解析响应（长按抽屉展示）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CardExplanation {
    /// 可选持久处置，不包含内部预算和提供者证据。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<ExplainOperation>,
    /// 关联卡片 ID。
    pub card_id: String,
    /// 一句话核心直觉总结。
    pub summary: String,
    /// 结构化拆解要点。
    pub key_points: Vec<String>,
    /// 帮助记忆的生活化类比 / 助记法。
    pub analogy: String,
    /// 推荐追问问题。
    #[serde(default)]
    pub follow_up_questions: Vec<String>,
    /// 解析来源（如 `"builtin-heuristic"` 或 `"openai:gpt-4o-mini"`）。
    pub provider: String,
    /// 生成时间（UTC）。
    pub generated_at: DateTime<Utc>,
}

/// 卡片草稿：AI Agent / 导入工具提交的结构化卡片。`id` 为空表示新建，否则更新。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CardDraft {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// 更新时可选的前置版本；缺省保留 2.x 的最后写入语义。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u32>,
    pub deck_id: String,
    /// 开放模板标识（如 `"basic"`、`"term"`、`"code"`、`"formula"`、`"qa"`），缺省时使用 `"basic"`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// 缺省时继承卡组语言。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    pub front: CardFace,
    #[serde(default)]
    pub back: CardFace,
    #[serde(default)]
    pub tags: Vec<String>,
    /// 领域自由扩展键值。
    #[serde(default)]
    pub attributes: serde_json::Map<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ducking: Option<DuckingParams>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visual: Option<CardVisual>,
}

/// 内容删除的可选版本前提，也用于 HTTP 查询参数。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RevisionPrecondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u32>,
}

/// 解释操作的最小回执；文本过期不会再次支付。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExplainOperation {
    /// 原账期账本投影；未决费用体现在 held 中。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounting: Option<ExplainAccounting>,
    pub request_id: String,
    pub disposition: ExplainDisposition,
}

/// 调用处置与财务不确定性独立于返回的本地回退文本。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExplainDisposition {
    Local,
    Pending,
    Unresolved,
    Settled,
    Suppressed,
    Expired,
    Cancelled,
}

/// 管理员核账只能提供一类已核验的数字或未收费证明摘要。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ExplainReconcileRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_charged_reference_sha256: Option<String>,
}

/// 请求、token 和整数金额保持独立维度，不披露提供者凭据或原文。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExplainAccounting {
    pub requests: u32,
    pub attempts: u32,
    pub period: String,
    pub currency: String,
    pub held_microcurrency: i64,
    pub committed_microcurrency: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<i64>,
}

/// native 仅说明边界由提供者返回，不构成精度认证。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentQuality {
    Native,
    Estimated,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AudioKind {
    Speech,
    Demo,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PcmLoop {
    pub sample_rate: u32,
    pub channels: u16,
    pub bits_per_sample: u16,
    pub frames: u32,
    pub source_sha256: String,
    pub source_start_frame: u32,
    pub source_end_frame: u32,
}
