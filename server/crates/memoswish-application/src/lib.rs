//! 与传输无关的应用命令、查询与副作用。

use std::sync::Arc;

pub mod asset_delivery;
pub mod asset_uploads;
pub mod privacy;
use asset_delivery::{render_bgm, render_card, render_cards, render_page};
mod content_lifecycle;
mod explanations;
mod imports;
mod lifecycle;
mod operations;
pub use operations::{OperationControl, OperationTracker};

use memoswish_auth::{AuthService, Metric, QuotaPolicy, UsageSnapshot};
use memoswish_content::{CardDraft, ContentService, NewDeck, slice_material};
use memoswish_core::{CoreError, CoreResult, Principal};
use memoswish_feed::FeedService;
use memoswish_media::{BgmAssignment, BgmMatch, BgmQuery, MediaService, SynthesizeOptions};
use memoswish_protocol::{
    Card, CardExplanation, Deck, DeckPack, ExplainRequest, FeedPage, FeedQuery, FeedbackAck, FeedbackBatch,
    LearningStats,
};

/// 由 daemon 组装、供传输适配器共享的应用服务。
#[derive(Clone)]
pub struct Services {
    pub operations: OperationTracker,
    pub auth: AuthService,
    pub content: ContentService,
    pub media: MediaService,
    pub feed: FeedService,
    pub quota: Arc<dyn QuotaPolicy>,
    pub limiter: Arc<dyn memoswish_core::rate_limit::RateLimiter>,
}

impl Services {
    fn require_import_executor(&self) -> CoreResult<()> {
        if !self.media.executes_work() {
            return Err(memoswish_core::CoreError::Unavailable(
                "durable import execution is not available in this role".into(),
            ));
        }
        Ok(())
    }

    /// REST 与 MCP 共用的导入流程，解析与权限失败不会消耗卡片额度。
    pub async fn import_apkg(
        &self,
        principal: &Principal,
        bytes: Vec<u8>,
        options: memoswish_content::apkg::ApkgOptions,
    ) -> memoswish_core::CoreResult<memoswish_content::apkg::ApkgReport> {
        self.import_apkg_with_identity(principal, bytes, options, None, None).await
    }
}

/// 资料切片的类型化结果，传输层负责保持各分支的响应形状。
pub enum MaterialSliceResult {
    Preview(Vec<CardDraft>),
    Empty,
    Committed(Vec<Card>),
}

/// 资料切片与可选提交参数。
pub struct MaterialSlice<'a> {
    pub deck_id: &'a str,
    pub text: &'a str,
    pub max_cards: usize,
    pub commit: bool,
    pub auto_tts: bool,
}

/// 已由适配器解码的 BGM 上传参数。
pub struct BgmUpload<'a> {
    pub provenance: Option<memoswish_protocol::ContentProvenance>,
    pub expected_revision: Option<u32>,
    pub title: &'a str,
    pub moods: Vec<String>,
    pub energy: f32,
    pub bpm: u16,
    pub audio_base64: &'a str,
    pub license: &'a str,
}

impl Services {
    /// 工具名称确认后、参数解码前执行现有 MCP 准入与计量。
    pub async fn admit_mcp_call(&self, p: &Principal) -> CoreResult<()> {
        self.auth.require_privacy_collection(p).await?;
        self.limiter.check(&p.tenant_id, 1.0).await?;
        // 异步准入等待期间可能撤销凭据，计量和业务分发前重新核验。
        self.auth.require_privacy_collection(p).await?;
        self.quota.consume(p, Metric::McpCalls, 1).await?;
        self.auth.require_privacy_collection(p).await
    }

    pub async fn usage(&self, p: &Principal) -> CoreResult<UsageSnapshot> {
        self.quota.snapshot(p).await
    }

    pub async fn list_decks(&self, p: &Principal) -> CoreResult<Vec<Deck>> {
        self.content.list_decks(p).await
    }

    pub async fn create_deck(&self, p: &Principal, deck: NewDeck) -> CoreResult<Deck> {
        self.content.create_deck(p, deck).await
    }

    pub async fn get_deck(&self, p: &Principal, deck_id: &str) -> CoreResult<Deck> {
        self.content.get_deck(p, deck_id).await
    }

    pub async fn delete_deck(&self, p: &Principal, deck_id: &str) -> CoreResult<()> {
        self.content.delete_deck(p, deck_id).await
    }

    pub async fn list_cards(
        &self,
        p: &Principal,
        deck_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> CoreResult<Vec<Card>> {
        self.content.list_cards(p, deck_id, limit, offset).await.map(|cards| render_cards(cards, "content"))
    }

    pub async fn get_card(&self, p: &Principal, card_id: &str) -> CoreResult<Card> {
        self.content.get_card(p, card_id).await.map(|card| render_card(card, "content"))
    }

    /// 保留先扣额、写卡、逐项合成、最后挂载 BGM 的顺序与部分失败语义。
    pub async fn upsert_cards(
        &self,
        p: &Principal,
        drafts: Vec<CardDraft>,
        auto_tts: bool,
        tts: &SynthesizeOptions,
        bgm: Option<&BgmAssignment>,
    ) -> CoreResult<Vec<Card>> {
        self.quota.consume(p, Metric::CardWrites, drafts.len() as u64).await?;
        let mut cards = self.content.upsert_cards(p, drafts).await?;
        if auto_tts {
            cards = self.synthesize_many(p, cards, tts).await?;
        }
        if let Some(bgm) = bgm {
            let ids: Vec<String> = cards.iter().map(|c| c.id.clone()).collect();
            let mut assignment = bgm.clone();
            for card in &cards {
                assignment.expected_revisions.entry(card.id.clone()).or_insert(card.revision);
            }
            cards = self.media.assign_bgm(p, &ids, &assignment).await?;
        }
        Ok(render_cards(cards, "content"))
    }

    pub async fn delete_card(&self, p: &Principal, card_id: &str) -> CoreResult<()> {
        self.delete_card_if_revision(p, card_id, None).await
    }

    pub async fn delete_card_if_revision(
        &self,
        p: &Principal,
        card_id: &str,
        expected_revision: Option<u32>,
    ) -> CoreResult<()> {
        self.content.delete_card_if_revision(p, card_id, expected_revision).await
    }

    pub async fn slice_material(&self, p: &Principal, request: MaterialSlice<'_>) -> CoreResult<MaterialSliceResult> {
        self.content.get_deck(p, request.deck_id).await?;
        let drafts = slice_material(request.deck_id, request.text, request.max_cards.clamp(1, 200));
        if !request.commit {
            return Ok(MaterialSliceResult::Preview(drafts));
        }
        if drafts.is_empty() {
            return Ok(MaterialSliceResult::Empty);
        }
        self.quota.consume(p, Metric::CardWrites, drafts.len() as u64).await?;
        let mut cards = self.content.upsert_cards(p, drafts).await?;
        if request.auto_tts {
            cards = self.synthesize_many(p, cards, &SynthesizeOptions::default()).await?;
        }
        Ok(MaterialSliceResult::Committed(render_cards(cards, "content")))
    }

    pub fn tts_engines(&self, _p: &Principal) -> Vec<(String, Vec<memoswish_core::tts::VoiceInfo>)> {
        self.media.engines()
    }

    pub fn default_tts_engine(&self, _p: &Principal) -> &str {
        self.media.default_engine()
    }

    pub async fn synthesize_cards(
        &self,
        p: &Principal,
        card_ids: &[String],
        options: &SynthesizeOptions,
    ) -> CoreResult<Vec<Card>> {
        let unique: std::collections::HashSet<_> = card_ids.iter().collect();
        if card_ids.is_empty()
            || card_ids.len() > 100
            || unique.len() != card_ids.len()
            || options.expected_revisions.keys().any(|id| !unique.contains(id))
        {
            return Err(memoswish_core::CoreError::invalid(
                "provide 1..=100 unique card targets and matching expected_revisions",
            ));
        }
        let mut out = Vec::with_capacity(card_ids.len());
        for id in card_ids {
            out.push(self.synthesize_owned_card(p, id, options).await?);
        }
        Ok(render_cards(out, "content"))
    }

    async fn synthesize_many(
        &self,
        p: &Principal,
        cards: Vec<Card>,
        options: &SynthesizeOptions,
    ) -> CoreResult<Vec<Card>> {
        if options.expected_revisions.keys().any(|id| !cards.iter().any(|card| &card.id == id)) {
            return Err(memoswish_core::CoreError::invalid("expected_revisions contains an unknown card target"));
        }
        let mut out = Vec::with_capacity(cards.len());
        for card in cards {
            let mut snapshot_options = options.clone();
            snapshot_options.expected_revisions.entry(card.id.clone()).or_insert(card.revision);
            out.push(self.synthesize_owned_card(p, &card.id, &snapshot_options).await?);
        }
        Ok(render_cards(out, "content"))
    }

    pub async fn speech_diagnostics(&self, p: &Principal) -> CoreResult<Vec<memoswish_protocol::SpeechDiagnostic>> {
        self.media.speech_diagnostics(p).await
    }

    pub async fn list_bgm(&self, p: &Principal) -> CoreResult<Vec<memoswish_protocol::BgmTrack>> {
        self.media.list_bgm(p).await.map(|tracks| tracks.into_iter().map(render_bgm).collect())
    }

    pub async fn match_bgm(&self, p: &Principal, query: &BgmQuery) -> CoreResult<Vec<BgmMatch>> {
        self.media.match_bgm(p, query).await.map(|mut matches| {
            for m in &mut matches {
                m.track = render_bgm(m.track.clone());
            }
            matches
        })
    }

    /// 整组挂载使用有界目标快照，超过支持上限明确失败。
    pub async fn assign_bgm(
        &self,
        p: &Principal,
        deck_id: Option<&str>,
        card_ids: Vec<String>,
        assignment: &BgmAssignment,
    ) -> CoreResult<Vec<Card>> {
        let ids = match deck_id {
            Some(deck) => self.content.bgm_target_snapshot(p, deck).await?,
            None => card_ids,
        };
        self.media.assign_bgm(p, &ids, assignment).await.map(|cards| render_cards(cards, "content"))
    }

    pub async fn generate_bgm(
        &self,
        p: &Principal,
        title: &str,
        moods: Vec<String>,
        energy: f32,
        bpm: u16,
    ) -> CoreResult<memoswish_protocol::BgmTrack> {
        self.generate_bgm_if_revision(p, title, moods, energy, bpm, None).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn generate_bgm_if_revision(
        &self,
        p: &Principal,
        title: &str,
        moods: Vec<String>,
        energy: f32,
        bpm: u16,
        expected_revision: Option<u32>,
    ) -> CoreResult<memoswish_protocol::BgmTrack> {
        let media = self.media.clone();
        let p = p.clone();
        let title = title.to_owned();
        self.operations
            .spawn(async move {
                let control = crate::OperationControl::current();
                control.checkpoint()?;
                media
                    .generate_bgm_if_revision_controlled(
                        &p,
                        &title,
                        moods,
                        energy,
                        bpm,
                        expected_revision,
                        |accepted| {
                            if accepted {
                                control.accepted();
                                Ok(())
                            } else {
                                control.begin_acceptance()
                            }
                        },
                    )
                    .await
            })?
            .await
            .map_err(|_| CoreError::Unavailable("BGM work interrupted; durable responsibility retained".into()))?
            .map(render_bgm)
    }

    pub async fn upload_bgm(&self, p: &Principal, upload: BgmUpload<'_>) -> CoreResult<memoswish_protocol::BgmTrack> {
        let media = self.media.clone();
        let p = p.clone();
        let title = upload.title.to_owned();
        let audio = upload.audio_base64.to_owned();
        let license = upload.license.to_owned();
        self.operations
            .spawn(async move {
                let control = crate::OperationControl::current();
                control.checkpoint()?;
                media
                    .upload_bgm_with_provenance_controlled(
                        &p,
                        &title,
                        upload.moods,
                        upload.energy,
                        upload.bpm,
                        &audio,
                        &license,
                        upload.expected_revision,
                        upload.provenance,
                        |accepted| {
                            if accepted {
                                control.accepted();
                                Ok(())
                            } else {
                                control.begin_acceptance()
                            }
                        },
                    )
                    .await
            })?
            .await
            .map_err(|_| CoreError::Unavailable("BGM work interrupted; durable responsibility retained".into()))?
            .map(render_bgm)
    }

    pub async fn clip_bgm(
        &self,
        p: &Principal,
        command: &memoswish_protocol::BgmClip,
    ) -> CoreResult<memoswish_protocol::BgmTrack> {
        let media = self.media.clone();
        let p = p.clone();
        let command = command.clone();
        self.operations
            .spawn(async move {
                let control = crate::OperationControl::current();
                control.checkpoint()?;
                media
                    .clip_bgm_controlled(&p, &command, |accepted| {
                        if accepted {
                            control.accepted();
                            Ok(())
                        } else {
                            control.begin_acceptance()
                        }
                    })
                    .await
            })?
            .await
            .map_err(|_| CoreError::Unavailable("BGM clipping interrupted; retry the same request ID".into()))?
            .map(render_bgm)
    }

    /// 预览不创建学习会话、回执、投递或曝光。
    pub async fn preview_feed(
        &self,
        p: &Principal,
        limit: Option<u32>,
        deck_id: Option<String>,
    ) -> CoreResult<FeedPage> {
        let query = FeedQuery { mode: None, session_id: None, cursor: None, request_id: None, limit, deck_id };
        self.feed.preview(p, &query).await.map(render_page)
    }

    pub async fn next_page(&self, p: &Principal, query: &FeedQuery) -> CoreResult<FeedPage> {
        self.feed.next_page(p, query).await.map(render_page)
    }

    pub async fn record_feedback(&self, p: &Principal, batch: &FeedbackBatch) -> CoreResult<FeedbackAck> {
        let mut ack = self.feed.record_feedback(p, batch).await?;
        let ids: Vec<_> = batch
            .events
            .iter()
            .filter(|e| !ack.rejected.iter().any(|r| r.event_id == e.event_id))
            .map(|e| e.event_id.clone())
            .collect();
        ack.receipts = Some(self.content.explanation_repository().feedback_receipts(p, &ids).await?);
        Ok(ack)
    }

    pub async fn stats(&self, p: &Principal) -> CoreResult<LearningStats> {
        self.feed.stats(p).await
    }

    pub async fn stats_for_deck(&self, p: &Principal, deck_id: Option<&str>) -> CoreResult<LearningStats> {
        self.feed.stats_for_deck(p, deck_id).await
    }

    pub async fn list_starred_cards(&self, p: &Principal, deck_id: Option<&str>) -> CoreResult<Vec<Card>> {
        self.feed.list_starred_cards(p, deck_id).await.map(|cards| render_cards(cards, "feed"))
    }

    pub async fn explain_card(
        &self,
        p: &Principal,
        card_id: &str,
        request: &ExplainRequest,
    ) -> CoreResult<CardExplanation> {
        // 只记录已捕获本人授权的固定操作分类，失败不改变原业务结果。
        let revision = self.auth.admit_privacy_purpose(p, "diagnostics", None).await.ok();
        let result = self.explain_request(p, card_id, request).await;
        if result.is_err()
            && let Some(revision) = revision
        {
            let report = memoswish_protocol::DiagnosticReport {
                report_id: memoswish_core::ids::new_id().replace('-', ""),
                privacy_revision: revision,
                captured_at_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64 * 1000)
                    .unwrap_or(0),
                purpose_version: self
                    .auth
                    .privacy_policy()
                    .purpose_versions
                    .get("diagnostics")
                    .cloned()
                    .unwrap_or_default(),
                build: env!("CARGO_PKG_VERSION").into(),
                platform: "server".into(),
                category: "operation".into(),
                code: "operation_failed".into(),
                frames: vec![],
            };
            let _ = self.report_diagnostic(p, &report).await;
        }
        result
    }

    pub async fn export_deck(&self, p: &Principal, deck_id: &str) -> CoreResult<DeckPack> {
        self.content.export_deck(p, deck_id).await.map(|mut pack| {
            pack.cards = render_cards(pack.cards, "content");
            pack
        })
    }

    /// REST 导入与 MCP 共用计量，保留无自动语音的默认值。
    pub async fn import_deck_pack(&self, p: &Principal, pack: DeckPack) -> CoreResult<Deck> {
        self.import_deck_pack_with_identity(p, pack, false, None, None).await
    }
    /// MCP 默认策略由适配器提供，语音失败与内容回执分开保存。
    pub async fn import_deck_pack_with_media(&self, p: &Principal, pack: DeckPack, auto_tts: bool) -> CoreResult<Deck> {
        self.import_deck_pack_with_identity(p, pack, auto_tts, None, None).await
    }
}

#[cfg(test)]
mod tests;

pub mod erasure;

mod portable;

mod access;
mod learning_controls;
mod library;
mod maintenance;
