//! BGM 与既有资产上传共用一条任务租约；不新增计费指标。
use crate::{CoreError, CoreResult, Principal, jobs::JobClaim};
use async_trait::async_trait;
use memoswish_protocol::BgmTrack;

pub fn validate_track(track: &BgmTrack) -> CoreResult<()> {
    crate::assets::validate_asset_id(&track.id)?;
    crate::assets::validate_asset_ref(&track.asset)?;
    validate_track_metadata(track)
}

/// 便携包可使用紧凑空身份；元数据校验不承担目录身份校验。
pub fn validate_track_metadata(track: &BgmTrack) -> CoreResult<()> {
    if track.title.trim().is_empty()
        || track.title.chars().count() > 200
        || track.license.trim().is_empty()
        || track.license.len() > 4096
        || track.artist.as_ref().is_some_and(|s| s.len() > 1024)
        || track.moods.len() > 32
        || track.moods.iter().any(|m| m.len() > 128)
        || !track.energy.is_finite()
        || !(0.0..=1.0).contains(&track.energy)
        || track.duration_ms > 300_000
        || track.loop_start_ms != 0
        || track.loop_end_ms != track.duration_ms
    {
        return Err(CoreError::invalid("invalid BGM metadata"));
    }
    if let Some(p) = &track.provenance {
        crate::content_lifecycle::validate_provenance(p)?;
    }
    if let Some(pcm) = &track.pcm
        && (!(8000..=96000).contains(&pcm.sample_rate)
            || !(1..=2).contains(&pcm.channels)
            || ![8, 16, 24, 32].contains(&pcm.bits_per_sample)
            || pcm.frames == 0
            || pcm.frames > pcm.sample_rate * 300
            || pcm.source_end_frame.checked_sub(pcm.source_start_frame) != Some(pcm.frames)
            || pcm.source_sha256.len() != 64
            || !pcm.source_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || u64::from(pcm.frames) * 1000 / u64::from(pcm.sample_rate) != u64::from(track.duration_ms))
    {
        return Err(CoreError::invalid("invalid BGM PCM loop metadata"));
    }
    Ok(())
}

/// 源读取权限随原始授权持久保存，不借后继凭据续做裁切。
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BgmAuthority {
    pub original: crate::imports::ImportAuthority,
    pub read_source: bool,
}

#[async_trait]
pub trait BgmPublicationRepo: Send + Sync {
    async fn bgm_request(&self, p: &Principal, request: &str, command: &str) -> CoreResult<Option<String>>;
    #[allow(clippy::too_many_arguments)]
    async fn accept_bgm(
        &self,
        p: &Principal,
        request: &str,
        track: &BgmTrack,
        bytes: &[u8],
        expected: Option<u32>,
        command: &str,
        read_source: bool,
    ) -> CoreResult<String>;
    async fn bgm_result(&self, tenant: &str, id: &str) -> CoreResult<Option<BgmTrack>>;
    async fn bgm_stage(&self, tenant: &str, id: &str) -> CoreResult<Option<Vec<u8>>>;
    async fn claim_bgm(&self, tenant: &str, id: &str, lease_ms: i64) -> CoreResult<Option<JobClaim>>;
    async fn publish_bgm(&self, tenant: &str, claim: &JobClaim, attempt: &str) -> CoreResult<()>;
    async fn pending_bgm(&self, after: Option<(&str, &str)>, limit: i64) -> CoreResult<Vec<(String, String)>>;
}

/// 旧包读取器会丢失这些时序、权利和播放语义，导出必须提升包版本。
pub fn has_media_metadata(card: &memoswish_protocol::Card) -> bool {
    card.tts.as_ref().is_some_and(|t| t.alignment_quality.is_some() || t.audio_kind.is_some() || t.provenance.is_some())
        || card.bgm.as_ref().is_some_and(|b| b.track.pcm.is_some() || b.track.provenance.is_some())
}

/// 终态失败保留原始 CAS 事实，重放不从当前目录重新推断。
#[derive(serde::Serialize, serde::Deserialize)]
pub enum BgmFailure {
    Revision(u32),
    NotFound,
    RequesterRevoked,
    Exhausted,
}
impl BgmFailure {
    pub fn error(&self) -> CoreError {
        match self {
            Self::Revision(current) => CoreError::Conflict(format!("revision mismatch; current revision {current}")),
            Self::NotFound => CoreError::NotFound("bgm".into()),
            Self::RequesterRevoked => CoreError::Forbidden("BGM original requester is no longer authorized".into()),
            Self::Exhausted => CoreError::Unavailable("BGM publication attempts exhausted; use a new request".into()),
        }
    }
}
