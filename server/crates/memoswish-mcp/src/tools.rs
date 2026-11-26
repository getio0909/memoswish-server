//! MCP 工具定义与分发。新增工具的步骤：
//! 1. 定义参数结构体（`#[derive(Deserialize, JsonSchema)]`，字段文档注释即为参数描述）；
//! 2. 在 [`catalog`] 中登记名称、描述、注解；
//! 3. 在 [`call`] 中实现分发；
//! 4. 补充工具目录和调用测试。

use base64::Engine;
use memoswish_application::{BgmUpload, MaterialSlice, MaterialSliceResult};
use memoswish_content::apkg::{ApkgLimits, ApkgOptions};
use memoswish_content::{CardDraft, NewDeck};
use memoswish_core::{CoreError, Principal};
use memoswish_media::{BgmAssignment, BgmQuery, SynthesizeOptions};
use memoswish_protocol::ExplainRequest;
use schemars::{JsonSchema, Schema};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::server::Services;

/// 无参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct NoArgs {}

/// 按 ID 引用卡组。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeckRef {
    /// 卡组 ID。
    pub deck_id: String,
}

/// 按 ID 引用卡片。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CardRef {
    /// 删除时可选的前置版本。
    #[serde(default)]
    pub expected_revision: Option<u32>,
    /// 卡片 ID。
    pub card_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PublicationArgs {
    pub card_id: String,
    #[serde(flatten)]
    pub command: memoswish_protocol::PublicationCommand,
}
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReportArgs {
    pub card_id: String,
    #[serde(flatten)]
    pub report: memoswish_protocol::ReportCreate,
}

/// `card_list` 参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CardListArgs {
    /// 仅列出该卡组的卡片。
    #[serde(default)]
    pub deck_id: Option<String>,
    /// 返回数量（1~500，默认 50）。
    #[serde(default)]
    pub limit: Option<u32>,
    /// 偏移量。
    #[serde(default)]
    pub offset: Option<u32>,
}

/// `card_upsert` 参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CardUpsertArgs {
    /// 启用严格草稿命令；媒体使用独立工具，新路径不自动合成。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_lifecycle: Option<bool>,
    /// 严格路径中显式发布，缺省保存草稿。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish: Option<bool>,
    /// 卡片草稿（最多 200 张）；`id` 为空表示新建。
    pub cards: Vec<CardDraft>,
    /// 写入后自动合成 TTS 发音（含逐词时间戳），默认 true。
    #[serde(default)]
    pub auto_tts: Option<bool>,
    /// TTS 选项。
    #[serde(default)]
    pub tts: Option<SynthesizeOptions>,
    /// 可选：同时挂载 BGM。
    #[serde(default)]
    pub bgm: Option<BgmAssignment>,
}

/// `material_slice` 参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MaterialSliceArgs {
    /// 启用严格草稿命令；媒体使用独立工具，新路径不自动合成。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_lifecycle: Option<bool>,
    /// 严格路径中显式发布，缺省保存草稿。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish: Option<bool>,
    /// 目标卡组 ID。
    pub deck_id: String,
    /// 原始资料文本。支持 `term :: definition`、`Q:/A:`、Markdown `##` 小节与代码块。
    pub text: String,
    /// 最多切出的卡片数（默认 50，最大 200）。
    #[serde(default)]
    pub max_cards: Option<usize>,
    /// 为 true 时直接入库（并按 auto_tts 合成发音），否则只返回草稿预览。
    #[serde(default)]
    pub commit: bool,
    /// 入库后自动合成 TTS，默认 true。
    #[serde(default)]
    pub auto_tts: Option<bool>,
}

/// `tts_synthesize` 参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TtsSynthesizeArgs {
    /// 需要（重新）合成发音的卡片 ID 列表（最多 100）。
    pub card_ids: Vec<String>,
    /// 合成选项。
    #[serde(default)]
    pub options: SynthesizeOptions,
}

/// 持久 TTS 提交参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TtsSubmitArgs {
    pub request_id: String,
    pub card_ids: Vec<String>,
    #[serde(default)]
    pub options: SynthesizeOptions,
}
/// 仅在当前调用者范围读取回执。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TtsStatusArgs {
    pub request_id: String,
}

/// `bgm_assign` 参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BgmAssignArgs {
    /// 目标卡片 ID 列表；与 deck_id 二选一。
    #[serde(default)]
    pub card_ids: Vec<String>,
    /// 挂载到整个卡组的所有卡片。
    #[serde(default)]
    pub deck_id: Option<String>,
    /// 挂载参数。
    pub assignment: BgmAssignment,
}

/// `bgm_generate` 参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BgmGenerateArgs {
    /// 已有曲目元数据的可选前置版本。
    #[serde(default)]
    pub expected_revision: Option<u32>,
    /// 曲目标题。
    pub title: String,
    /// 情绪标签，例如 `["focus"]`。
    #[serde(default)]
    pub moods: Vec<String>,
    /// 能量 0~1（默认 0.4）。
    #[serde(default)]
    pub energy: Option<f32>,
    /// BPM 50~180（默认 90）。
    #[serde(default)]
    pub bpm: Option<u16>,
}

/// `bgm_upload` 参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BgmUploadArgs {
    #[serde(default)]
    pub provenance: Option<memoswish_protocol::ContentProvenance>,
    /// 同摘要曲目元数据的可选前置版本。
    #[serde(default)]
    pub expected_revision: Option<u32>,
    /// 曲目标题。
    pub title: String,
    /// 情绪标签。
    #[serde(default)]
    pub moods: Vec<String>,
    /// 能量 0~1。
    pub energy: f32,
    /// BPM。
    pub bpm: u16,
    /// base64 编码的 PCM WAV（≤ 10 MiB）。
    pub audio_base64: String,
    /// 授权声明，例如 `CC0`、`CC-BY-4.0 by Alice`。
    pub license: String,
}

/// `feed_preview` 参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FeedPreviewArgs {
    /// 预览条数（默认 10）。
    #[serde(default)]
    pub limit: Option<u32>,
    /// 仅预览指定卡组。
    #[serde(default)]
    pub deck_id: Option<String>,
}

/// `card_explain` 参数。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CardExplainArgs {
    /// 付费执行的持久身份，缺省只返回本地解析。
    #[serde(default)]
    pub request_id: Option<String>,
    /// 卡片 ID。
    pub card_id: String,
    /// 可选追问问题；为空时生成卡片的默认深度解析与类比。
    #[serde(default)]
    pub question: Option<String>,
    /// 期望输出语言（BCP-47，如 `zh-CN` 或 `en-US`）。
    #[serde(default)]
    pub locale: Option<String>,
}

pub use memoswish_protocol::{ApkgImportRequest as ApkgImportArgs, DeckImportRequest as DeckImportArgs};

/// 工具描述。
pub struct ToolDef {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub schema: Schema,
    pub read_only: bool,
    pub destructive: bool,
}

fn def<T: JsonSchema>(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    read_only: bool,
    destructive: bool,
) -> ToolDef {
    ToolDef { name, title, description, schema: schemars::schema_for!(T), read_only, destructive }
}

/// 工具目录（唯一登记处）。
pub fn catalog() -> Vec<ToolDef> {
    vec![
        def::<memoswish_protocol::CardSave>(
            "card_save",
            "Save private card",
            "Strict CAS save. Defaults to draft; publish=true atomically saves and publishes. Provenance is an unverified caller claim. No automatic TTS.",
            false,
            false,
        ),
        def::<PublicationArgs>(
            "card_publish",
            "Publish or withdraw private card",
            "Require observed expected_revision. Publishing only enables learning inside the tenant.",
            false,
            false,
        ),
        def::<ReportArgs>(
            "card_report",
            "Report a revision",
            "Report the observed revision; references are unverified claims.",
            false,
            false,
        ),
        def::<NoArgs>("deck_list", "List decks", "List all decks of the current tenant with card counts.", true, false),
        def::<NewDeck>(
            "deck_create",
            "Create deck",
            "Create a new deck (a themed collection of micro cards).",
            false,
            false,
        ),
        def::<DeckRef>("deck_delete", "Delete deck", "Delete a deck and all of its cards. Irreversible.", false, true),
        def::<CardListArgs>(
            "card_list",
            "List cards",
            "List cards, optionally filtered by deck, with pagination.",
            true,
            false,
        ),
        def::<CardRef>(
            "card_get",
            "Get card",
            "Fetch a single card including TTS track, word timestamps and BGM binding.",
            true,
            false,
        ),
        def::<CardUpsertArgs>(
            "card_upsert",
            "Create or update cards",
            "Create or update up to 200 structured micro cards (front/back faces, code snippets, tags). By default synthesizes TTS with word-level timestamps for karaoke subtitles, and can attach BGM in the same call.",
            false,
            false,
        ),
        def::<CardRef>("card_delete", "Delete card", "Delete a single card. Irreversible.", false, true),
        def::<MaterialSliceArgs>(
            "material_slice",
            "Slice learning material",
            "Deterministically slice semi-structured text (term :: definition lines, Q:/A: pairs, Markdown sections with code blocks) into card drafts. Preview by default; set commit=true to save. For complex material, slice it yourself and call card_upsert.",
            false,
            false,
        ),
        def::<NoArgs>(
            "tts_engines",
            "List TTS engines",
            "List available TTS engines and voices, plus the default engine.",
            true,
            false,
        ),
        def::<TtsSubmitArgs>(
            "tts_submit",
            "Submit durable pronunciation",
            "Atomically accept 1..=100 targets under a caller request_id. Replay the same command to recover the original mapping; altered commands conflict. Attachments recover after disconnect or restart.",
            false,
            false,
        ),
        def::<TtsStatusArgs>(
            "tts_submission_status",
            "Read pronunciation receipts",
            "Read ordered immutable per-target receipts owned by the current caller. Complete means every item has a terminal receipt, including failures.",
            true,
            false,
        ),
        def::<TtsSynthesizeArgs>(
            "tts_synthesize",
            "Synthesize pronunciation",
            "(Re)generate TTS audio with word-level timestamps for the given cards and attach it. Consumes TTS quota (cached by content hash).",
            false,
            false,
        ),
        def::<NoArgs>(
            "bgm_list",
            "List BGM",
            "List background music tracks available to the tenant (shared + private).",
            true,
            false,
        ),
        def::<BgmQuery>("bgm_match", "Match BGM", "Rank BGM tracks by mood tags, energy (0-1) and BPM.", true, false),
        def::<BgmAssignArgs>(
            "bgm_assign",
            "Assign BGM",
            "Attach a BGM track to cards or a whole deck, with switching policy (continue | switch_on_theme | silence), theme key and base volume. Ducking under TTS is handled by the app.",
            false,
            false,
        ),
        def::<BgmGenerateArgs>(
            "bgm_generate",
            "Generate BGM",
            "Generate a royalty-free seamless 30s synth pad and add it to the tenant library.",
            false,
            false,
        ),
        def::<memoswish_protocol::BgmClip>(
            "bgm_clip",
            "Clip BGM frames",
            "Materialize one integer PCM frame range as the complete loop; inherit source rights.",
            false,
            false,
        ),
        def::<BgmUploadArgs>(
            "bgm_upload",
            "Upload BGM",
            "Upload a licensed PCM WAV track (base64, <= 10 MiB) to the tenant library.",
            false,
            false,
        ),
        def::<FeedPreviewArgs>(
            "feed_preview",
            "Preview feed",
            "Preview what the learner's infinite feed would serve next, including reasons (due/new/reinforce/surprise) and the prefetch manifest.",
            true,
            false,
        ),
        def::<NoArgs>(
            "learning_stats",
            "Learning stats",
            "Aggregate learning statistics: total/seen/due/starred cards and average retrievability.",
            true,
            false,
        ),
        def::<ExplanationReconcileArgs>(
            "explanation_reconcile",
            "Reconcile explanation",
            "Settle original explanation accounting against verified usage or affirmative no-charge evidence. Requires billing:manage.",
            false,
            false,
        ),
        def::<ExplanationLookupArgs>(
            "explanation_lookup",
            "Explanation disposition",
            "Look up a durable explanation request without executing the provider.",
            true,
            false,
        ),
        def::<CardExplainArgs>(
            "card_explain",
            "Explain card",
            "Generate a deep explanation (summary, key points, analogy, and follow-up questions) for a card, optionally answering a specific learner question.",
            false,
            false,
        ),
        def::<DeckRef>(
            "deck_export_portable",
            "Export portable deck",
            "Export bounded self-contained DeckPack 2.0 including media.",
            true,
            false,
        ),
        def::<memoswish_protocol::PortableImportRequest>(
            "deck_import_portable",
            "Import portable deck",
            "Import embedded media atomically without TTS generation.",
            false,
            false,
        ),
        def::<DeckRef>(
            "deck_export",
            "Export deck pack",
            "Export legacy DeckPack 1.0 content references; use deck_export_portable for self-contained media.",
            true,
            false,
        ),
        def::<ApkgImportArgs>(
            "deck_import_apkg",
            "Import legacy Anki package",
            "Import a legacy .apkg (base64, <= 10 MiB) into a fresh deck. Requires content:write and media:write for retained images. Audio is omitted with warnings. Re-export modern packages with Support older Anki versions enabled.",
            false,
            false,
        ),
        def::<ExplanationLookupArgs>(
            "deck_import_status",
            "Import disposition",
            "Read the original credential-owned import disposition without executing work.",
            true,
            false,
        ),
        def::<DeckImportArgs>(
            "deck_import",
            "Import deck pack",
            "Import a DeckPack JSON bundle into a new deck and optionally synthesize TTS for all imported cards.",
            false,
            false,
        ),
    ]
}

/// `tools/list` 的结果。
pub fn list_tools_json() -> Value {
    let tools: Vec<Value> = catalog()
        .into_iter()
        .map(|t| {
            let mut schema = serde_json::to_value(&t.schema).unwrap_or_else(|_| json!({"type": "object"}));
            if let Some(obj) = schema.as_object_mut() {
                obj.remove("$schema");
                obj.remove("title");
                obj.entry("type").or_insert(json!("object"));
            }
            json!({
                "name": t.name,
                "title": t.title,
                "description": t.description,
                "inputSchema": schema,
                "annotations": {
                    "title": t.title,
                    "readOnlyHint": t.read_only,
                    "destructiveHint": t.destructive,
                    "openWorldHint": false
                }
            })
        })
        .collect();
    json!({ "tools": tools })
}

/// 工具参数解析失败（映射为 JSON-RPC -32602）。
#[derive(Debug)]
pub enum CallError {
    UnknownTool(String),
    InvalidArgs(String),
    Domain(CoreError),
}

impl From<CoreError> for CallError {
    fn from(e: CoreError) -> Self {
        CallError::Domain(e)
    }
}

fn parse<T: DeserializeOwned>(args: Value) -> Result<T, CallError> {
    let args = if args.is_null() { json!({}) } else { args };
    memoswish_core::imports::decode_input(args, crate::protocol::MAX_MESSAGE_BYTES)
        .map_err(|e| CallError::InvalidArgs(e.to_string()))
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, CallError> {
    serde_json::to_value(v).map_err(|e| CallError::Domain(CoreError::internal(e)))
}

/// 执行工具。
pub async fn call(s: &Services, p: &Principal, name: &str, args: Value) -> Result<Value, CallError> {
    call_with_credential(s, p, name, args, None).await
}

/// 凭据摘要只来自已认证传输，不接受工具参数提供的授权证据。
pub async fn call_with_credential(
    s: &Services,
    p: &Principal,
    name: &str,
    args: Value,
    token_hash: Option<memoswish_core::imports::ImportCredential>,
) -> Result<Value, CallError> {
    if !catalog().iter().any(|t| t.name == name) {
        return Err(CallError::UnknownTool(name.into()));
    }
    s.admit_mcp_call(p).await?;
    memoswish_application::OperationControl::current().checkpoint()?;
    match name {
        "deck_import_status" => {
            let a: ExplanationLookupArgs = parse(args)?;
            to_value(s.import_status(p, &a.request_id, token_hash).await?)
        }
        "deck_import_apkg" => {
            let a: ApkgImportArgs = parse(args)?;
            p.require(memoswish_core::Permission::ContentWrite)?;
            if a.apkg_base64.len() > ApkgLimits::ARCHIVE.div_ceil(3) * 4 {
                return Err(CallError::InvalidArgs("APKG base64 exceeds 10 MiB decoded limit".into()));
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&a.apkg_base64)
                .map_err(|e| CallError::InvalidArgs(format!("invalid APKG base64: {e}")))?;
            if bytes.len() > ApkgLimits::ARCHIVE {
                return Err(CallError::InvalidArgs("APKG upload exceeds 10 MiB".into()));
            }
            to_value(
                s.import_apkg_with_identity(
                    p,
                    bytes,
                    ApkgOptions { title: a.title, language: a.language },
                    a.request_id,
                    token_hash,
                )
                .await?,
            )
        }
        "card_save" => to_value(s.save_card(p, parse(args)?).await?),
        "card_publish" => {
            let a: PublicationArgs = parse(args)?;
            to_value(s.publish_card(p, &a.card_id, a.command).await?)
        }
        "card_report" => {
            let a: ReportArgs = parse(args)?;
            to_value(s.report_content(p, &a.card_id, &a.report).await?)
        }
        "deck_list" => to_value(s.list_decks(p).await?),
        "deck_create" => to_value(s.create_deck(p, parse::<NewDeck>(args)?).await?),
        "deck_delete" => {
            let a: DeckRef = parse(args)?;
            s.delete_deck(p, &a.deck_id).await?;
            Ok(json!({ "deleted": a.deck_id }))
        }
        "card_list" => {
            let a: CardListArgs = parse(args)?;
            to_value(s.list_cards(p, a.deck_id.as_deref(), a.limit.unwrap_or(50), a.offset.unwrap_or(0)).await?)
        }
        "card_get" => to_value(s.get_card(p, &parse::<CardRef>(args)?.card_id).await?),
        "card_upsert" => {
            let a: CardUpsertArgs = parse(args)?;
            if a.content_lifecycle.unwrap_or(false) {
                if a.auto_tts == Some(true) || a.tts.is_some() || a.bgm.is_some() {
                    return Err(CoreError::invalid("strict content_lifecycle uses separate media commands").into());
                }
                return Ok(generated(s, p, a.cards, a.publish.unwrap_or(false), "agent").await?);
            }
            to_value(
                s.upsert_cards(p, a.cards, a.auto_tts.unwrap_or(true), &a.tts.unwrap_or_default(), a.bgm.as_ref())
                    .await?,
            )
        }
        "card_delete" => {
            let a: CardRef = parse(args)?;
            s.delete_card_if_revision(p, &a.card_id, a.expected_revision).await?;
            Ok(json!({ "deleted": a.card_id }))
        }
        "material_slice" => {
            let a: MaterialSliceArgs = parse(args)?;
            if a.content_lifecycle.unwrap_or(false) && a.commit {
                if a.auto_tts == Some(true) {
                    return Err(CoreError::invalid("strict content_lifecycle uses separate media commands").into());
                }
                let drafts =
                    memoswish_content::slice_material(&a.deck_id, &a.text, a.max_cards.unwrap_or(50).clamp(1, 200));
                return Ok(
                    json!({"committed":true,"cards":generated(s,p,drafts,a.publish.unwrap_or(false),"heuristic").await?}),
                );
            }
            let result = s
                .slice_material(
                    p,
                    MaterialSlice {
                        deck_id: &a.deck_id,
                        text: &a.text,
                        max_cards: a.max_cards.unwrap_or(50),
                        commit: a.commit,
                        auto_tts: a.auto_tts.unwrap_or(true),
                    },
                )
                .await?;
            Ok(match result {
                MaterialSliceResult::Preview(drafts) => json!({ "committed": false, "drafts": drafts }),
                MaterialSliceResult::Empty => {
                    json!({ "committed": false, "drafts": [], "message": "no recognizable cards in text" })
                }
                MaterialSliceResult::Committed(cards) => json!({ "committed": true, "cards": cards }),
            })
        }
        "tts_engines" => {
            let engines: Vec<Value> =
                s.tts_engines(p).into_iter().map(|(id, voices)| json!({ "id": id, "voices": voices })).collect();
            Ok(
                json!({ "default": s.default_tts_engine(p), "engines": engines, "diagnostics": s.speech_diagnostics(p).await? }),
            )
        }
        "tts_submit" => {
            let a: TtsSubmitArgs = parse(args)?;
            Ok(serde_json::to_value(s.submit_tts(p, &a.request_id, &a.card_ids, &a.options).await?)
                .map_err(|_| memoswish_core::CoreError::internal("invalid submission response"))?)
        }
        "tts_submission_status" => {
            let a: TtsStatusArgs = parse(args)?;
            Ok(serde_json::to_value(s.tts_submission_status(p, &a.request_id).await?)
                .map_err(|_| memoswish_core::CoreError::internal("invalid submission response"))?)
        }
        "tts_synthesize" => {
            let a: TtsSynthesizeArgs = parse(args)?;
            if a.card_ids.is_empty() || a.card_ids.len() > 100 {
                return Err(CallError::InvalidArgs("card_ids must contain 1..=100 ids".into()));
            }
            to_value(s.synthesize_cards(p, &a.card_ids, &a.options).await?)
        }
        "bgm_clip" => to_value(s.clip_bgm(p, &parse::<memoswish_protocol::BgmClip>(args)?).await?),
        "bgm_list" => to_value(s.list_bgm(p).await?),
        "bgm_match" => to_value(s.match_bgm(p, &parse::<BgmQuery>(args)?).await?),
        "bgm_assign" => {
            let a: BgmAssignArgs = parse(args)?;
            if a.deck_id.is_none() && a.card_ids.is_empty() {
                return Err(CallError::InvalidArgs("provide card_ids or deck_id".into()));
            }
            let cards = s.assign_bgm(p, a.deck_id.as_deref(), a.card_ids, &a.assignment).await?;
            Ok(
                json!({ "updated": cards.len(), "card_ids": cards.iter().map(|c| &c.id).collect::<Vec<_>>(), "cards": cards }),
            )
        }
        "bgm_generate" => {
            let a: BgmGenerateArgs = parse(args)?;
            to_value(
                s.generate_bgm_if_revision(
                    p,
                    &a.title,
                    a.moods,
                    a.energy.unwrap_or(0.4),
                    a.bpm.unwrap_or(90),
                    a.expected_revision,
                )
                .await?,
            )
        }
        "bgm_upload" => {
            let a: BgmUploadArgs = parse(args)?;
            to_value(
                s.upload_bgm(
                    p,
                    BgmUpload {
                        provenance: a.provenance,
                        expected_revision: a.expected_revision,
                        title: &a.title,
                        moods: a.moods,
                        energy: a.energy,
                        bpm: a.bpm,
                        audio_base64: &a.audio_base64,
                        license: &a.license,
                    },
                )
                .await?,
            )
        }
        "feed_preview" => {
            let a: FeedPreviewArgs = parse(args)?;
            to_value(s.preview_feed(p, a.limit, a.deck_id).await?)
        }
        "learning_stats" => to_value(s.stats(p).await?),
        "explanation_reconcile" => {
            let a: ExplanationReconcileArgs = parse(args)?;
            to_value(s.reconcile_explanation_request(p, &a.request_id, &a.evidence).await?)
        }
        "explanation_lookup" => {
            let a: ExplanationLookupArgs = parse(args)?;
            to_value(s.explanation_operation(p, &a.request_id).await?)
        }
        "card_explain" => {
            let a: CardExplainArgs = parse(args)?;
            let req = ExplainRequest { request_id: a.request_id, question: a.question, locale: a.locale };
            to_value(s.explain_card(p, &a.card_id, &req).await?)
        }
        "deck_export_portable" => {
            let a: DeckRef = parse(args)?;
            to_value(s.export_portable_deck(p, &a.deck_id, token_hash).await?)
        }
        "deck_import_portable" => {
            let pack = args["pack"].clone();
            let a: memoswish_protocol::PortableImportRequest = parse(args)?;
            to_value(s.import_portable_deck_input(p, pack, a.request_id, token_hash).await?)
        }
        "deck_export" => {
            let a: DeckRef = parse(args)?;
            to_value(s.export_deck(p, &a.deck_id).await?)
        }
        "deck_import" => {
            let pack = args["pack"].clone();
            let a: DeckImportArgs = parse(args)?;
            to_value(s.import_deck_pack_input(p, pack, a.auto_tts.unwrap_or(true), a.request_id, token_hash).await?)
        }
        other => Err(CallError::UnknownTool(other.into())),
    }
}

/// 解释回执只查当前主体的原始身份。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExplanationLookupArgs {
    pub request_id: String,
}

/// 核账只接受明确的结构化证据，不保存任意提供者原文。
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExplanationReconcileArgs {
    pub request_id: String,
    pub evidence: memoswish_protocol::ExplainReconcileRequest,
}

async fn generated(
    s: &Services,
    p: &Principal,
    drafts: Vec<CardDraft>,
    publish: bool,
    method: &str,
) -> Result<Value, CoreError> {
    serde_json::to_value(s.save_generated_cards(p, drafts, publish, method).await?).map_err(CoreError::internal)
}

#[cfg(test)]
mod optional_lifecycle_tests {
    use super::*;

    #[test]
    fn lifecycle_flags_preserve_missing_null_and_explicit_values() {
        for (base, schema, card_upsert) in [
            (json!({"cards": []}), serde_json::to_value(schemars::schema_for!(CardUpsertArgs)).unwrap(), true),
            (
                json!({"deck_id": "deck", "text": "Term :: Definition"}),
                serde_json::to_value(schemars::schema_for!(MaterialSliceArgs)).unwrap(),
                false,
            ),
        ] {
            for field in ["content_lifecycle", "publish"] {
                assert_eq!(schema["properties"][field]["type"], json!(["boolean", "null"]));
                assert!(!schema["required"].as_array().unwrap().contains(&json!(field)));
            }
            for lifecycle in [None, Some(Value::Null), Some(json!(false)), Some(json!(true))] {
                for publish in [None, Some(Value::Null), Some(json!(false)), Some(json!(true))] {
                    let mut input = base.clone();
                    if let Some(value) = &lifecycle {
                        input["content_lifecycle"] = value.clone();
                    }
                    if let Some(value) = &publish {
                        input["publish"] = value.clone();
                    }
                    let flags = if card_upsert {
                        let args: CardUpsertArgs = parse(input).unwrap();
                        (args.content_lifecycle, args.publish)
                    } else {
                        let args: MaterialSliceArgs = parse(input).unwrap();
                        (args.content_lifecycle, args.publish)
                    };
                    assert_eq!(
                        flags,
                        (lifecycle.as_ref().and_then(Value::as_bool), publish.as_ref().and_then(Value::as_bool))
                    );
                }
            }
        }
    }
}
