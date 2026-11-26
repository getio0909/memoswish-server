//! 媒体服务：TTS 合成（带缓存与配额）、BGM 曲库管理、匹配与挂载。

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use memoswish_auth::QuotaPolicy;
use memoswish_content::ContentService;
use memoswish_core::ids::sha256_hex;
use memoswish_core::repo::Repository;
use memoswish_core::store::ObjectStore;
use memoswish_core::tts::{TtsEngine, VoiceInfo};
use memoswish_core::{CoreError, CoreResult, Permission, Principal};
use memoswish_protocol::{AssetRef, BgmBinding, BgmPolicy, BgmTrack, Card, TtsTrack, WordTimestamp};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bgm::{PRESETS, score, synth_pad};
use crate::segment::strip_markdown;

#[path = "bgm_jobs.rs"]
mod bgm_jobs;
#[path = "jobs.rs"]
mod jobs;

/// TTS 合成选项。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SynthesizeOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<memoswish_protocol::ContentProvenance>,
    /// 按卡片 ID 指定合成前版本；未提供时在合成开始读取当前版本。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub expected_revisions: BTreeMap<String, u32>,
    /// 引擎 ID，缺省使用服务端默认引擎。
    #[serde(default)]
    pub engine: Option<String>,
    /// 音色，缺省 `default`。
    #[serde(default)]
    pub voice: Option<String>,
    /// 覆盖朗读文本；缺省由卡片正面推导。
    #[serde(default)]
    pub text: Option<String>,
    /// 语速倍率 0.5~2.0，缺省 1.0。
    #[serde(default)]
    pub speed: Option<f32>,
}

/// BGM 匹配需求。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BgmQuery {
    /// 期望情绪标签，例如 `["focus", "calm"]`。
    #[serde(default)]
    pub moods: Vec<String>,
    /// 期望能量 0~1。
    #[serde(default)]
    pub energy: Option<f32>,
    /// 期望 BPM。
    #[serde(default)]
    pub bpm: Option<u16>,
    /// 返回数量，缺省 5。
    #[serde(default)]
    pub limit: Option<usize>,
}

/// 匹配结果。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BgmMatch {
    pub track: BgmTrack,
    pub score: f32,
}

/// BGM 挂载参数。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BgmAssignment {
    /// 按目标卡片 ID 指定可选前置版本。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub expected_revisions: BTreeMap<String, u32>,
    pub track_id: String,
    #[serde(default)]
    pub policy: BgmPolicy,
    /// 主题键；缺省为 `track_id`。
    #[serde(default)]
    pub theme_key: Option<String>,
    /// 基础音量 0~1，缺省 0.6。
    #[serde(default)]
    pub base_volume: Option<f32>,
}

/// TTS 缓存旁路文件。
#[derive(Debug, Serialize, Deserialize)]
struct TtsSidecar {
    #[serde(default)]
    alignment_quality: Option<memoswish_protocol::AlignmentQuality>,
    #[serde(default)]
    audio_kind: Option<memoswish_protocol::AudioKind>,
    #[serde(default)]
    provenance: Option<memoswish_protocol::ContentProvenance>,
    #[serde(default)]
    sha256: Option<String>,
    duration_ms: u32,
    words: Vec<WordTimestamp>,
}

/// 媒体服务。
#[derive(Clone)]
pub struct MediaService {
    privacy: memoswish_protocol::PrivacyPolicy,
    repo: Arc<dyn Repository>,
    store: Arc<dyn ObjectStore>,
    content: ContentService,
    quota: Arc<dyn QuotaPolicy>,
    engines: BTreeMap<String, Arc<dyn TtsEngine>>,
    default_engine: String,
    execute_work: bool,
}

/// 上传 BGM 的最大字节数（10 MiB）。
pub const MAX_BGM_UPLOAD: usize = 10 * 1024 * 1024;

impl MediaService {
    /// API 只接受并等待 SQL 结果；worker 与 embedded 保留执行权。
    pub fn with_execution(mut self, execute: bool) -> Self {
        self.execute_work = execute;
        self
    }

    pub fn executes_work(&self) -> bool {
        self.execute_work
    }

    pub fn new(
        repo: Arc<dyn Repository>,
        store: Arc<dyn ObjectStore>,
        quota: Arc<dyn QuotaPolicy>,
        engines: Vec<Arc<dyn TtsEngine>>,
        default_engine: &str,
    ) -> CoreResult<Self> {
        let engines: BTreeMap<_, _> = engines.into_iter().map(|e| (e.id().to_string(), e)).collect();
        for id in engines.keys() {
            memoswish_core::assets::validate_asset_id(id)?;
        }
        if !engines.contains_key(default_engine) {
            return Err(CoreError::invalid(format!("default tts engine `{default_engine}` is not registered")));
        }
        Ok(Self {
            content: ContentService::new(repo.clone()),
            repo,
            store,
            quota,
            engines,
            privacy: Default::default(),
            default_engine: default_engine.into(),
            execute_work: true,
        })
    }

    pub fn store(&self) -> &Arc<dyn ObjectStore> {
        &self.store
    }

    pub fn with_privacy_policy(mut self, policy: memoswish_protocol::PrivacyPolicy) -> Self {
        self.privacy = policy;
        self
    }
    pub fn engine_ids(&self) -> Vec<String> {
        self.engines.keys().cloned().collect()
    }

    pub async fn speech_diagnostics(&self, p: &Principal) -> CoreResult<Vec<memoswish_protocol::SpeechDiagnostic>> {
        p.require(Permission::MediaRead)?;
        let mut result = Vec::new();
        for engine in self.engines.values() {
            result.push(engine.diagnostics().await);
        }
        Ok(result)
    }

    pub fn speech_configured(&self) -> bool {
        self.default_engine != "unconfigured"
    }

    pub fn default_engine(&self) -> &str {
        &self.default_engine
    }

    /// 导入自动语音在受理内容前检查用途，恢复执行仍由持久语音屏障复核。
    pub async fn default_tts_privacy(
        &self,
        p: &Principal,
    ) -> CoreResult<Option<memoswish_core::imports::ImportPrivacy>> {
        if self.engines[&self.default_engine].external_transfer() {
            let revision = self.repo.privacy_admit(&p.tenant_id, p, &self.privacy, Some("external_tts"), None).await?;
            return Ok(Some(memoswish_core::imports::ImportPrivacy { policy: self.privacy.clone(), revision }));
        }
        Ok(None)
    }

    /// 列出引擎及其音色。
    pub fn engines(&self) -> Vec<(String, Vec<VoiceInfo>)> {
        self.engines.iter().map(|(k, e)| (k.clone(), e.voices())).collect()
    }

    /// 由卡片推导默认朗读文本：提取正面标题与可朗读内容块（文本、引语）。
    pub fn default_tts_text(card: &Card) -> String {
        let title = strip_markdown(&card.front.title);
        let blocks_text: Vec<String> = card
            .front
            .blocks
            .iter()
            .filter_map(|b| b.speakable_text().map(strip_markdown))
            .filter(|s| !s.is_empty())
            .collect();
        if blocks_text.is_empty() || matches!(card.template.as_str(), "quote" | "qa") {
            title
        } else {
            format!("{title}. {}", blocks_text.join(". "))
        }
    }

    /// 为卡片合成发音并挂载，返回更新后的卡片。
    pub async fn synthesize_card(&self, p: &Principal, card_id: &str, opts: &SynthesizeOptions) -> CoreResult<Card> {
        p.require(Permission::TtsGenerate)?;
        let card = self.content.get_card(p, card_id).await?;
        memoswish_core::content::check_revision(opts.expected_revisions.get(card_id).copied(), card.revision)?;
        let text = opts.text.clone().unwrap_or_else(|| Self::default_tts_text(&card));
        let (request, _) =
            self.durable_synthesis(p, &text, &card.language, opts, Some((card_id, card.revision))).await?;
        let mut attached = self.repo.attach_speech(&p.tenant_id, &request.id).await?;
        if let Some(tts) = &mut attached.tts {
            tts.audio.url = self.store.url_for(&tts.audio.key);
        }
        Ok(attached)
    }

    /// 合成任意文本为 `TtsTrack`（内容寻址缓存：相同参数不重复合成、不重复计费）。
    pub async fn synthesize(
        &self,
        p: &Principal,
        text: &str,
        language: &str,
        opts: &SynthesizeOptions,
    ) -> CoreResult<TtsTrack> {
        self.durable_synthesis(p, text, language, opts, None).await.map(|(_, track)| track)
    }

    /// 确保内置共享 BGM 存在（幂等，启动时调用）。
    pub async fn ensure_builtin_bgm(&self) -> CoreResult<usize> {
        let mut created = 0;
        for (id, title, moods, energy, bpm, chord) in PRESETS {
            let key = format!("shared/bgm/{id}.wav");
            let exists = self.store.exists(&key).await?;
            let asset = if exists {
                let obj = self.store.get(&key).await?.ok_or_else(|| CoreError::internal("bgm vanished"))?;
                AssetRef {
                    key: key.clone(),
                    url: self.store.url_for(&key),
                    mime: obj.mime,
                    bytes: obj.bytes.len() as u64,
                    sha256: sha256_hex(&obj.bytes),
                }
            } else {
                created += 1;
                self.store.put(&key, synth_pad(chord, *bpm, *energy, 30), "audio/wav").await?
            };
            let track = BgmTrack {
                provenance: None,
                pcm: None,
                revision: 1,
                id: (*id).into(),
                title: (*title).into(),
                artist: Some("Memoswish Synth".into()),
                asset,
                duration_ms: 30_000,
                bpm: *bpm,
                moods: moods.iter().map(|m| (*m).to_string()).collect(),
                energy: *energy,
                loop_start_ms: 0,
                loop_end_ms: 30_000,
                license: "generated".into(),
            };
            if self.repo.get_bgm("", &track.id).await?.is_none() {
                self.repo.save_bgm(None, &track, None).await?;
            }
        }
        Ok(created)
    }

    pub async fn list_bgm(&self, p: &Principal) -> CoreResult<Vec<BgmTrack>> {
        p.require(Permission::MediaRead)?;
        self.repo.list_bgm(&p.tenant_id).await
    }

    /// 按情绪 / 能量 / BPM 匹配曲目。
    pub async fn match_bgm(&self, p: &Principal, q: &BgmQuery) -> CoreResult<Vec<BgmMatch>> {
        let mut scored: Vec<BgmMatch> = self
            .list_bgm(p)
            .await?
            .into_iter()
            .map(|t| BgmMatch { score: score(&t, &q.moods, q.energy, q.bpm), track: t })
            .collect();
        scored.sort_by(|a, b| b.score.total_cmp(&a.score));
        scored.truncate(q.limit.unwrap_or(5).clamp(1, 50));
        Ok(scored)
    }

    /// 把曲目挂载到多张卡片。
    pub async fn assign_bgm(&self, p: &Principal, card_ids: &[String], a: &BgmAssignment) -> CoreResult<Vec<Card>> {
        p.require(Permission::ContentWrite)?;
        let track = self
            .repo
            .get_bgm(&p.tenant_id, &a.track_id)
            .await?
            .ok_or_else(|| CoreError::NotFound(format!("bgm `{}`", a.track_id)))?;
        let binding = BgmBinding {
            policy: a.policy,
            theme_key: a.theme_key.clone().unwrap_or_else(|| track.id.clone()),
            base_volume: a.base_volume.unwrap_or(0.6),
            track,
        };
        if a.expected_revisions.keys().any(|id| !card_ids.contains(id)) {
            return Err(CoreError::invalid("expected_revisions contains an unknown card target"));
        }
        let targets: Vec<_> = card_ids.iter().map(|id| (id.clone(), a.expected_revisions.get(id).copied())).collect();
        self.content.attach_bgm_batch(p, &targets, Some(binding)).await
    }

    /// 生成一条合成 Pad 并加入租户曲库。
    pub async fn generate_bgm(
        &self,
        p: &Principal,
        title: &str,
        moods: Vec<String>,
        energy: f32,
        bpm: u16,
    ) -> CoreResult<BgmTrack> {
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
    ) -> CoreResult<BgmTrack> {
        self.generate_bgm_if_revision_controlled(p, title, moods, energy, bpm, expected_revision, |_| Ok(())).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn generate_bgm_if_revision_controlled(
        &self,
        p: &Principal,
        title: &str,
        moods: Vec<String>,
        energy: f32,
        bpm: u16,
        expected_revision: Option<u32>,
        control: impl Fn(bool) -> CoreResult<()> + Send + Sync,
    ) -> CoreResult<BgmTrack> {
        p.require(Permission::MediaWrite)?;
        let energy = energy.clamp(0.0, 1.0);
        let bpm = bpm.clamp(50, 180);
        // 根据能量选择和弦预设作为音色基础。
        let preset = PRESETS
            .iter()
            .min_by(|a, b| (a.3 - energy).abs().total_cmp(&(b.3 - energy).abs()))
            .ok_or_else(|| CoreError::internal("no presets"))?;
        let permit = crate::wav::PROCESSING
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("PCM processing capacity exhausted".into()))?;
        let chord = preset.5.to_vec();
        let bytes = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            synth_pad(&chord, bpm, energy, 30)
        })
        .await
        .map_err(|_| CoreError::Unavailable("BGM synthesis interrupted".into()))?;
        let id = format!("bgm_{}", &sha256_hex(format!("{title}|{energy}|{bpm}|{}", p.tenant_id).as_bytes())[..16]);
        self.register_bytes(
            p,
            &id,
            title,
            moods,
            energy,
            bpm,
            bytes,
            "generated",
            expected_revision,
            Some(memoswish_protocol::ContentProvenance {
                method: "heuristic".into(),
                rights: "generated".into(),
                attribution: "Memoswish Synth".into(),
                ..Default::default()
            }),
            control,
        )
        .await
    }

    /// 上传自有 BGM（base64 编码的 WAV）。
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_bgm(
        &self,
        p: &Principal,
        title: &str,
        moods: Vec<String>,
        energy: f32,
        bpm: u16,
        audio_base64: &str,
        license: &str,
    ) -> CoreResult<BgmTrack> {
        self.upload_bgm_if_revision(p, title, moods, energy, bpm, audio_base64, license, None).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upload_bgm_if_revision(
        &self,
        p: &Principal,
        title: &str,
        moods: Vec<String>,
        energy: f32,
        bpm: u16,
        audio_base64: &str,
        license: &str,
        expected_revision: Option<u32>,
    ) -> CoreResult<BgmTrack> {
        self.upload_bgm_with_provenance(p, title, moods, energy, bpm, audio_base64, license, expected_revision, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upload_bgm_with_provenance(
        &self,
        p: &Principal,
        title: &str,
        moods: Vec<String>,
        energy: f32,
        bpm: u16,
        audio_base64: &str,
        license: &str,
        expected_revision: Option<u32>,
        provenance: Option<memoswish_protocol::ContentProvenance>,
    ) -> CoreResult<BgmTrack> {
        self.upload_bgm_with_provenance_controlled(
            p,
            title,
            moods,
            energy,
            bpm,
            audio_base64,
            license,
            expected_revision,
            provenance,
            |_| Ok(()),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upload_bgm_with_provenance_controlled(
        &self,
        p: &Principal,
        title: &str,
        moods: Vec<String>,
        energy: f32,
        bpm: u16,
        audio_base64: &str,
        license: &str,
        expected_revision: Option<u32>,
        provenance: Option<memoswish_protocol::ContentProvenance>,
        control: impl Fn(bool) -> CoreResult<()> + Send + Sync,
    ) -> CoreResult<BgmTrack> {
        p.require(Permission::MediaWrite)?;
        if audio_base64.len() > MAX_BGM_UPLOAD.div_ceil(3) * 4 {
            return Err(CoreError::invalid("bgm upload exceeds 10 MiB"));
        }
        let permit = crate::wav::PROCESSING
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("PCM processing capacity exhausted".into()))?;
        let encoded = audio_base64.to_owned();
        let bytes = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|_| CoreError::invalid("invalid BGM base64"))
        })
        .await
        .map_err(|_| CoreError::Unavailable("BGM decoder interrupted".into()))??;
        if bytes.len() > MAX_BGM_UPLOAD {
            return Err(CoreError::invalid("bgm upload exceeds 10 MiB"));
        }
        if license.trim().is_empty() {
            return Err(CoreError::invalid("license is required for uploaded music"));
        }
        let id = format!("bgm_{}", &sha256_hex(&bytes)[..16]);
        self.register_bytes(
            p,
            &id,
            title,
            moods,
            energy.clamp(0.0, 1.0),
            bpm,
            bytes,
            license,
            expected_revision,
            provenance,
            control,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn register_bytes(
        &self,
        p: &Principal,
        id: &str,
        title: &str,
        moods: Vec<String>,
        energy: f32,
        bpm: u16,
        bytes: Vec<u8>,
        license: &str,
        expected_revision: Option<u32>,
        provenance: Option<memoswish_protocol::ContentProvenance>,
        control: impl Fn(bool) -> CoreResult<()> + Send + Sync,
    ) -> CoreResult<BgmTrack> {
        let permit = crate::wav::PROCESSING
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("PCM processing capacity exhausted".into()))?;
        let (bytes, pcm) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let pcm = crate::wav::pcm_info(&bytes)?;
            Ok::<_, CoreError>((bytes, pcm))
        })
        .await
        .map_err(|_| CoreError::Unavailable("PCM processor interrupted".into()))??;
        let duration_ms = (u64::from(pcm.frames) * 1000 / u64::from(pcm.sample_rate)) as u32;
        let track = BgmTrack {
            provenance: provenance.or_else(|| {
                Some(memoswish_protocol::ContentProvenance {
                    method: "manual".into(),
                    rights: license.into(),
                    attribution: String::new(),
                    ..Default::default()
                })
            }),
            pcm: Some(pcm),
            revision: 1,
            id: id.into(),
            title: if title.trim().is_empty() { id.into() } else { title.trim().into() },
            artist: None,
            asset: AssetRef {
                key: format!("{}bgm/{id}.wav", p.asset_prefix()),
                url: String::new(),
                mime: "audio/wav".into(),
                bytes: bytes.len() as u64,
                sha256: sha256_hex(&bytes),
            },
            duration_ms,
            bpm,
            moods,
            energy,
            loop_start_ms: 0,
            loop_end_ms: duration_ms,
            license: license.into(),
        };
        let command = sha256_hex(&serde_json::to_vec(&(&track, expected_revision)).map_err(CoreError::internal)?);
        // 上传和生成没有显式请求身份，每次独立接受并在发布时检查当前目录版本。
        let request = memoswish_core::ids::new_id();
        self.publish_bgm_bytes(p, &request, track, bytes, expected_revision, &command, false, control).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memoswish_core::tts::TtsRequest;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::tts::placeholder::PlaceholderTts;
    use async_trait::async_trait;
    use memoswish_auth::Unlimited;
    use memoswish_content::{CardDraft, NewDeck};
    use memoswish_core::tts::TtsOutput;
    use memoswish_protocol::CardFace;
    use memoswish_storage::LocalDiskStore;
    use memoswish_storage::sqlite::SqliteRepository;

    #[derive(Default)]
    pub(super) struct CountingTts {
        pub(super) calls: AtomicUsize,
    }

    #[async_trait]
    impl TtsEngine for CountingTts {
        fn id(&self) -> &str {
            PlaceholderTts.id()
        }

        fn voices(&self) -> Vec<VoiceInfo> {
            PlaceholderTts.voices()
        }

        async fn synthesize(&self, req: &TtsRequest) -> CoreResult<TtsOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            PlaceholderTts.synthesize(req).await
        }
    }

    pub(super) async fn setup() -> (MediaService, ContentService, Principal, std::path::PathBuf, Arc<CountingTts>) {
        let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
        memoswish_auth::AuthService::new(
            repo.clone(),
            memoswish_auth::AuthConfig {
                mode: memoswish_protocol::DeploymentMode::SingleUser,
                jwt_secret: "k".repeat(32),
                jwt_ttl_secs: 3600,
                registration_open: false,
                default_plan: "self_hosted".into(),
            },
        )
        .unwrap()
        .bootstrap_local()
        .await
        .unwrap();
        let dir = std::env::temp_dir().join(format!("memoswish-media-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(LocalDiskStore::new(&dir, "/assets"));
        let engine = Arc::new(CountingTts::default());
        let media =
            MediaService::new(repo.clone(), store, Arc::new(Unlimited::new()), vec![engine.clone()], "placeholder")
                .unwrap();
        (media, ContentService::new(repo), Principal::local_owner("test"), dir, engine)
    }

    #[tokio::test]
    async fn synthesize_attach_and_cache() {
        let (media, content, p, dir, engine) = setup().await;
        let deck = content
            .create_deck(
                &p,
                NewDeck { title: "D".into(), description: String::new(), language: "en-US".into(), tags: vec![] },
            )
            .await
            .unwrap();
        let card = content
            .upsert_cards(
                &p,
                vec![CardDraft {
                    id: None,
                    expected_revision: None,
                    deck_id: deck.id,
                    template: Some("term".into()),
                    language: None,
                    front: CardFace::simple("ubiquitous", "found everywhere"),
                    back: CardFace::default(),
                    tags: vec![],
                    attributes: serde_json::Map::new(),
                    ducking: None,
                    visual: None,
                }],
            )
            .await
            .unwrap()
            .remove(0);
        assert_eq!(engine.calls.load(Ordering::SeqCst), 0);
        let updated = media.synthesize_card(&p, &card.id, &SynthesizeOptions::default()).await.unwrap();
        assert_eq!(engine.calls.load(Ordering::SeqCst), 1, "initial cache miss invokes the engine");
        let tts = updated.tts.unwrap();
        assert_eq!(tts.text, "ubiquitous. found everywhere");
        assert_eq!(tts.words.len(), 3);
        assert_eq!(updated.revision, card.revision + 1);
        let again = media.synthesize(&p, &tts.text, "en-US", &SynthesizeOptions::default()).await.unwrap();
        assert_eq!(again.audio.sha256, tts.audio.sha256, "served from cache");
        assert_eq!(engine.calls.load(Ordering::SeqCst), 1, "cache hit must not invoke the engine again");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn builtin_bgm_match_and_assign() {
        let (media, _content, p, dir, _engine) = setup().await;
        assert_eq!(media.ensure_builtin_bgm().await.unwrap(), PRESETS.len());
        assert_eq!(media.ensure_builtin_bgm().await.unwrap(), 0, "idempotent");
        let m = media.match_bgm(&p, &BgmQuery { moods: vec!["upbeat".into()], ..Default::default() }).await.unwrap();
        assert_eq!(m[0].track.id, "bgm_upbeat_pulse");
        let generated = media.generate_bgm(&p, "My Loop", vec!["focus".into()], 0.4, 95).await.unwrap();
        assert_eq!(generated.duration_ms, 30_000);
        assert_eq!(media.list_bgm(&p).await.unwrap().len(), PRESETS.len() + 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
#[path = "p35_regressions.rs"]
mod p35_regressions;

#[cfg(test)]
mod p35_tests {
    use super::*;
    use memoswish_protocol::{AlignmentQuality, AudioKind, BgmClip, ContentProvenance};
    #[tokio::test]
    async fn clipping_preserves_rights_materializes_loop_and_replays_after_source_removal() {
        let (media, _, p, dir, _) = super::tests::setup().await;
        let bytes = crate::wav::encode_wav(&vec![0.25; 8000], 8000);
        let source = media
            .upload_bgm_with_provenance(
                &p,
                "Source",
                vec![],
                0.3,
                90,
                &base64::engine::general_purpose::STANDARD.encode(&bytes),
                "CC-BY-4.0",
                None,
                Some(ContentProvenance {
                    method: "manual".into(),
                    sources: vec!["https://example.org/music".into()],
                    rights: "CC-BY-4.0".into(),
                    attribution: "Original artist".into(),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
        let command = BgmClip {
            request_id: "clip".into(),
            track_id: source.id.clone(),
            start_frame: 1,
            end_frame: 7999,
            title: Some("Clip".into()),
        };
        let clipped = media.clip_bgm(&p, &command).await.unwrap();
        assert_eq!(clipped.provenance, source.provenance);
        assert_eq!(clipped.license, source.license);
        assert_eq!(clipped.pcm.as_ref().unwrap().frames, 7998);
        assert_eq!(clipped.loop_start_ms, 0);
        for track in [&source, &clipped] {
            let manifest = media.repo.asset_read_manifest(&p.tenant_id, &track.asset.key).await.unwrap().unwrap();
            assert!(manifest.verified, "BGM must publish with verified read metadata");
            assert_eq!(manifest.sha256, track.asset.sha256);
            assert_eq!(manifest.size, track.asset.bytes);
            let bytes = media.store.get(&track.asset.key).await.unwrap().unwrap().bytes;
            for (index, block) in bytes.chunks(memoswish_core::asset_read::BLOCK_BYTES).enumerate() {
                manifest.verify_block(index, block).unwrap();
            }
        }
        let object = media.store.get(&clipped.asset.key).await.unwrap().unwrap();
        assert_eq!(crate::wav::pcm_info(&object.bytes).unwrap().frames, 7998);
        media.store.delete(&source.asset.key).await.unwrap();
        assert_eq!(media.clip_bgm(&p, &command).await.unwrap(), clipped);
        let changed = BgmClip { end_frame: 7998, ..command };
        assert!(media.clip_bgm(&p, &changed).await.is_err());
        let mut foreign = p.clone();
        foreign.tenant_id = "other-tenant".into();
        assert!(media.clip_bgm(&foreign, &changed).await.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
    #[tokio::test]
    async fn bgm_capacity_rejection_precedes_processing_and_publication() {
        let (media, _, p, dir, _) = super::tests::setup().await;
        let bytes = crate::wav::encode_wav(&vec![0.25; 8000], 8000);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let source = media.upload_bgm(&p, "Source", vec![], 0.3, 90, &encoded, "CC0").await.unwrap();
        let before = media.repo.list_bgm(&p.tenant_id).await.unwrap();
        let held = crate::wav::PROCESSING.acquire_many(2).await.unwrap();
        let generated = media.generate_bgm(&p, "Blocked", vec![], 0.3, 90).await;
        let uploaded = media.upload_bgm(&p, "Blocked", vec![], 0.3, 90, &encoded, "CC0").await;
        let clipped = media
            .clip_bgm(
                &p,
                &BgmClip {
                    request_id: "blocked".into(),
                    track_id: source.id,
                    start_frame: 0,
                    end_frame: 4000,
                    title: None,
                },
            )
            .await;
        for result in [generated, uploaded, clipped] {
            assert!(
                matches!(result, Err(CoreError::Unavailable(message)) if message == "PCM processing capacity exhausted")
            );
        }
        assert_eq!(media.repo.list_bgm(&p.tenant_id).await.unwrap(), before);
        assert!(media.repo.pending_bgm(None, 100).await.unwrap().is_empty());
        drop(held);
        media.generate_bgm(&p, "Retry", vec![], 0.3, 90).await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn stored_timing_quality_and_rights_survive_cache_reload() {
        let (media, _, p, dir, engine) = super::tests::setup().await;
        let opts = SynthesizeOptions {
            provenance: Some(ContentProvenance {
                method: "manual".into(),
                rights: "Own recording declaration".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let first = media.synthesize(&p, "Hello world", "en-US", &opts).await.unwrap();
        assert_eq!(first.alignment_quality, Some(AlignmentQuality::Native));
        assert_eq!(first.audio_kind, Some(AudioKind::Demo));
        assert_eq!(first.provenance, opts.provenance);
        let again = media.clone().synthesize(&p, "Hello world", "en-US", &opts).await.unwrap();
        assert_eq!(again, first);
        assert_eq!(engine.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
    #[tokio::test]
    async fn unconfigured_speech_does_not_generate_demo_or_durable_jobs() {
        let (media, _, p, dir, _) = super::tests::setup().await;
        let media = MediaService::new(
            media.repo,
            media.store,
            media.quota,
            vec![Arc::new(crate::tts::disabled::DisabledTts)],
            "unconfigured",
        )
        .unwrap();
        assert!(!media.speech_configured());
        assert!(matches!(
            media.synthesize(&p, "hello", "en-US", &SynthesizeOptions::default()).await,
            Err(CoreError::SpeechUnconfigured)
        ));
        assert_eq!(media.repo.pending_speech(None, 100).await.unwrap(), vec![]);
        assert_eq!(
            media.speech_diagnostics(&p).await.unwrap()[0].state,
            memoswish_protocol::SpeechDiagnosticState::Unconfigured
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
