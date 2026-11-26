//! TTS 引擎抽象：必须返回逐词时间戳，驱动客户端卡拉 OK 字幕。

use async_trait::async_trait;
use memoswish_protocol::WordTimestamp;
use serde::{Deserialize, Serialize};

use crate::error::CoreResult;

/// 尚未开始执行的合成；持有准入资源，丢弃即释放，轮询后由实际执行所有者接管。
pub type PreparedSpeech<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = CoreResult<TtsOutput>> + Send + 'a>>;

/// 合成请求。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TtsRequest {
    pub text: String,
    /// BCP-47 语言标签。
    pub language: String,
    pub voice: String,
    /// 语速倍率，1.0 为正常。
    pub speed: f32,
}

impl TtsRequest {
    pub fn validate(&self) -> crate::CoreResult<()> {
        if self.text.len() > 8000
            || self.text.trim().is_empty()
            || self.text.chars().count() > 2000
            || self.language.len() > 128
            || self.voice.len() > 256
            || !self.speed.is_finite()
            || !(0.5..=2.0).contains(&self.speed)
        {
            return Err(crate::CoreError::invalid("invalid speech request envelope"));
        }
        Ok(())
    }
}

/// 合成结果。
#[derive(Debug, Clone, PartialEq)]
pub struct TtsOutput {
    pub alignment_quality: Option<memoswish_protocol::AlignmentQuality>,

    pub audio_kind: Option<memoswish_protocol::AudioKind>,

    pub provenance: Option<memoswish_protocol::ContentProvenance>,
    pub audio: Vec<u8>,
    pub mime: String,
    /// 文件扩展名，例如 `wav`。
    pub extension: String,
    pub duration_ms: u32,
    pub words: Vec<WordTimestamp>,
}

/// 引擎可用音色描述。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoiceInfo {
    pub id: String,
    pub language: String,
    pub description: String,
}

/// TTS 引擎。
#[async_trait]
pub trait TtsEngine: Send + Sync {
    /// 引擎唯一标识，例如 `placeholder`、`command`、`azure`。
    fn id(&self) -> &str;
    fn external_transfer(&self) -> bool {
        false
    }
    /// 影响输出的配置摘要，不返回原始端点或凭据。
    fn cache_namespace(&self) -> String {
        crate::ids::sha256_hex(self.id().as_bytes())
    }
    /// 计费单位倍率（每字符消耗的算力单位），本地引擎为 0。
    fn cost_per_char(&self) -> u32 {
        0
    }
    fn voices(&self) -> Vec<VoiceInfo>;
    async fn diagnostics(&self) -> memoswish_protocol::SpeechDiagnostic {
        memoswish_protocol::SpeechDiagnostic {
            engine: self.id().into(),
            configured: true,
            state: memoswish_protocol::SpeechDiagnosticState::Unchecked,
            voices: vec![],
        }
    }
    /// 已知本地配置错误在 provider 尝试记账前返回，不合成用户文本。
    async fn validate_request(&self, _req: &TtsRequest) -> CoreResult<()> {
        Ok(())
    }
    /// 在记录 provider 责任之前预留容量；此步骤不得发送用户文本或启动合成。
    async fn prepare_execution<'a>(&'a self, req: &'a TtsRequest) -> CoreResult<PreparedSpeech<'a>> {
        Ok(Box::pin(self.synthesize(req)))
    }
    async fn synthesize(&self, req: &TtsRequest) -> CoreResult<TtsOutput>;
}

/// 不含凭据或交付地址的可重放合成输入。
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SpeechWork {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<memoswish_protocol::ContentProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<crate::privacy::PrivacyFence>,
    pub engine: String,
    pub namespace: String,
    pub request: TtsRequest,
    pub amount: i64,
    /// 已在读取边界验证摘要的 legacy 字节，与首次准入一起持久化。
    #[serde(skip)]
    pub legacy_output: Option<TtsOutput>,
}

impl SpeechWork {
    pub fn validate(&self) -> crate::CoreResult<()> {
        if let Some(p) = &self.provenance {
            crate::content_lifecycle::validate_provenance(p)?;
        }
        crate::assets::validate_asset_id(&self.engine)?;
        crate::assets::validate_asset_id(&self.namespace)?;
        if self.request.text.trim().is_empty()
            || self.request.text.chars().count() > 2000
            || self.request.language.len() > 128
            || self.request.voice.len() > 256
            || !self.request.speed.is_finite()
            || !(0.5..=2.0).contains(&self.request.speed)
            || !(0..=2000_i64 * u32::MAX as i64).contains(&self.amount)
        {
            return Err(crate::CoreError::invalid("invalid synthesis work"));
        }
        Ok(())
    }

    pub fn identity(&self) -> crate::CoreResult<String> {
        self.validate()?;
        let bytes = if self.provenance.is_some() {
            serde_json::to_vec(&(&self.engine, &self.namespace, &self.request, &self.privacy, &self.provenance))
        } else if self.privacy.is_some() {
            serde_json::to_vec(&(&self.engine, &self.namespace, &self.request, &self.privacy))
        } else {
            serde_json::to_vec(&(&self.engine, &self.namespace, &self.request))
        };
        Ok(crate::ids::sha256_hex(&bytes.map_err(|_| crate::CoreError::internal("invalid synthesis work"))?))
    }
}

/// 合成结果仅保留资产身份和有界时序；URL 在授权响应时渲染。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpeechMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment_quality: Option<memoswish_protocol::AlignmentQuality>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_kind: Option<memoswish_protocol::AudioKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<memoswish_protocol::ContentProvenance>,
    pub extension: String,
    pub duration_ms: u32,
    pub words: Vec<WordTimestamp>,
}

impl SpeechMetadata {
    pub fn validate(&self) -> crate::CoreResult<()> {
        if let Some(p) = &self.provenance {
            crate::content_lifecycle::validate_provenance(p)?;
        }
        if self.extension.is_empty()
            || self.extension.len() > 12
            || !self.extension.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || self.duration_ms == 0
            || self.words.len() > 8000
            || self.words.iter().any(|w| {
                w.text.len() > 8192 || w.start_ms > w.end_ms || w.end_ms > self.duration_ms || w.char_start > w.char_end
            })
            || self.words.windows(2).any(|w| w[0].end_ms > w[1].start_ms || w[0].char_end > w[1].char_start)
            || serde_json::to_vec(self).map_or(true, |b| b.len() > 1024 * 1024)
        {
            return Err(crate::CoreError::invalid("invalid synthesis output metadata"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeechRequest {
    pub id: String,
    pub synthesis_id: String,
    pub outcome: String,
    pub failure: Option<SpeechFailure>,
}

/// 仅持久化允许公开的固定分类，不保留提供者诊断或配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeechFailure {
    EngineUnavailable,
    VoiceUnavailable,
}

impl SpeechFailure {
    pub fn from_error(error: &crate::CoreError) -> Option<Self> {
        Self::from_code(error.code())
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "speech_engine_unavailable" => Some(Self::EngineUnavailable),
            "speech_voice_unavailable" => Some(Self::VoiceUnavailable),
            _ => None,
        }
    }

    pub fn error(self) -> crate::CoreError {
        match self {
            Self::EngineUnavailable => crate::CoreError::SpeechEngineUnavailable,
            Self::VoiceUnavailable => crate::CoreError::SpeechVoiceUnavailable,
        }
    }
}

/// 准入前解析的执行数据；仓储在同一事务内复核卡片版本。
pub struct SpeechSubmissionTarget {
    pub card_id: String,
    pub revision: u32,
    pub work: SpeechWork,
}

pub fn validate_submission_id(id: &str) -> CoreResult<()> {
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(crate::CoreError::invalid("invalid submission request ID"));
    }
    Ok(())
}

/// 合成和上传共享 background_jobs；每个阶段只有该表的一个租约。
#[async_trait]
pub trait SpeechRepo: Send + Sync {
    /// 先按原命令哈希重放，不能重新解析当前卡片或缺省配置。
    async fn speech_submission(
        &self,
        p: &crate::Principal,
        request_id: &str,
        command_hash: Option<&str>,
    ) -> CoreResult<Option<memoswish_protocol::tts::TtsSubmission>>;
    async fn submit_speech(
        &self,
        p: &crate::Principal,
        request_id: &str,
        command_hash: &str,
        targets: &[SpeechSubmissionTarget],
        limit: Option<i64>,
    ) -> CoreResult<memoswish_protocol::tts::TtsSubmission>;
    /// 窄维护入口；SQL-only 挂载与回执原子完成，不领取新租约。
    async fn resolve_speech_attachment(&self, tenant: &str, item: &str) -> CoreResult<()>;
    async fn pending_speech_attachments(
        &self,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> CoreResult<Vec<(String, String)>>;
    async fn accept_speech(
        &self,
        p: &crate::Principal,
        work: &SpeechWork,
        target: Option<(&str, u32)>,
        limit: Option<i64>,
    ) -> crate::CoreResult<SpeechRequest>;
    async fn speech_request(&self, tenant: &str, id: &str) -> crate::CoreResult<SpeechRequest>;
    async fn speech_work(&self, tenant: &str, id: &str) -> crate::CoreResult<SpeechWork>;
    /// 窄维护入口；不可恢复的隐私失效在同一事务终结请求、释放未发送预留并写稳定回执。
    async fn retire_invalid_speech(
        &self,
        tenant: &str,
        id: &str,
        policy: &memoswish_protocol::PrivacyPolicy,
        external: bool,
    ) -> CoreResult<bool>;
    async fn claim_speech(
        &self,
        tenant: &str,
        id: &str,
        lease_ms: i64,
    ) -> crate::CoreResult<Option<crate::jobs::JobClaim>>;
    async fn heartbeat_speech(
        &self,
        tenant: &str,
        claim: &crate::jobs::JobClaim,
        lease_ms: i64,
    ) -> crate::CoreResult<()>;
    async fn begin_provider(&self, tenant: &str, claim: &crate::jobs::JobClaim) -> crate::CoreResult<()>;
    async fn fail_speech(
        &self,
        tenant: &str,
        claim: &crate::jobs::JobClaim,
        failure: Option<SpeechFailure>,
    ) -> crate::CoreResult<()>;
    /// 记录输出和创建 S15 上传任务在同一个事务内完成。
    async fn materialize_speech(
        &self,
        tenant: &str,
        claim: &crate::jobs::JobClaim,
        bytes: &[u8],
        spec: &crate::assets::AssetSpec,
        metadata: &SpeechMetadata,
        legacy: bool,
    ) -> crate::CoreResult<()>;
    async fn legacy_speech_output(&self, tenant: &str, id: &str) -> crate::CoreResult<Option<TtsOutput>>;
    async fn speech_upload(&self, tenant: &str, id: &str) -> crate::CoreResult<Option<(String, Vec<u8>)>>;
    /// 只发布当前上传 claim 的精确回执，结算原始周期并写请求者终态。
    async fn publish_speech(&self, tenant: &str, claim: &crate::jobs::JobClaim, attempt: &str)
    -> crate::CoreResult<()>;
    async fn speech_track(&self, tenant: &str, id: &str) -> crate::CoreResult<Option<memoswish_protocol::TtsTrack>>;
    async fn attach_speech(&self, tenant: &str, request: &str) -> crate::CoreResult<memoswish_protocol::Card>;
    /// 窄维护分页包含 dead/uncertain；不依赖业务父对象存活。
    async fn pending_speech(&self, after: Option<(&str, &str)>, limit: i64)
    -> crate::CoreResult<Vec<(String, String)>>;
    async fn held_speech_usage(&self, tenant: &str, period: &str) -> crate::CoreResult<(i64, i64)>;
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    fn work() -> SpeechWork {
        SpeechWork {
            provenance: None,
            privacy: None,
            engine: "test".into(),
            namespace: "configuration".into(),
            request: TtsRequest {
                text: "hello|世界".into(),
                language: "en-US".into(),
                voice: "default".into(),
                speed: 1.0,
            },
            amount: 8,
            legacy_output: None,
        }
    }
    #[test]
    fn structured_identity_preserves_exact_effective_parameters() {
        let original = work();
        let identity = original.identity().unwrap();
        for changed in ["text", "language", "voice", "speed", "namespace", "engine"] {
            let mut w = original.clone();
            match changed {
                "text" => w.request.text.push('|'),
                "language" => w.request.language.push('x'),
                "voice" => w.request.voice.push('x'),
                "speed" => w.request.speed = 1.001,
                "namespace" => w.namespace.push('x'),
                _ => w.engine.push('x'),
            }
            assert_ne!(identity, w.identity().unwrap());
        }
        let mut w = original;
        w.amount = 0;
        assert_eq!(identity, w.identity().unwrap());
    }
    #[test]
    fn invalid_input_and_bounded_output_are_rejected() {
        for speed in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 0.0] {
            let mut w = work();
            w.request.speed = speed;
            assert!(w.identity().is_err());
        }
        let mut w = work();
        w.request.text = "中".repeat(2000);
        assert!(w.validate().is_ok());
        w.request.text.push('中');
        assert!(w.validate().is_err());
        let mut m = SpeechMetadata {
            alignment_quality: None,
            audio_kind: None,
            provenance: None,
            extension: "wav".into(),
            duration_ms: 100,
            words: vec![],
        };
        assert!(m.validate().is_ok());
        m.extension = "../SECRET_SENTINEL".into();
        let e = m.validate().unwrap_err();
        assert!(!format!("{e:?}").contains("SECRET_SENTINEL"));
        m.extension = "wav".into();
        m.words = vec![WordTimestamp { text: "x".repeat(8193), start_ms: 0, end_ms: 1, char_start: 0, char_end: 1 }];
        assert!(m.validate().is_err());
    }
}

#[cfg(test)]
mod request_budget_tests {
    use super::*;
    #[test]
    fn speech_request_exact_numeric_boundaries_and_plus_one() {
        let valid = TtsRequest {
            text: "\u{1f600}".repeat(2000),
            language: "x".repeat(128),
            voice: "v".repeat(256),
            speed: 2.0,
        };
        assert!(valid.validate().is_ok());
        let mut invalid = valid.clone();
        invalid.text.push('x');
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.language.push('x');
        assert!(invalid.validate().is_err());
        let mut invalid = valid.clone();
        invalid.voice.push('v');
        assert!(invalid.validate().is_err());
        for speed in [f32::NAN, f32::INFINITY, 2.01, 0.49] {
            let mut invalid = valid.clone();
            invalid.speed = speed;
            assert!(invalid.validate().is_err());
        }
    }
}
