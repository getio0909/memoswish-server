//! BGM 暂存复用 S15 PUT 与 S16 工作预算，不引入后台循环或新租约。
use super::{MAX_BGM_UPLOAD, MediaService};
use crate::wav::pcm_info;
use memoswish_core::{CoreError, CoreResult, Permission, Principal, ids::sha256_hex};
use memoswish_protocol::{AssetRef, BgmTrack};

impl MediaService {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn publish_bgm_bytes(
        &self,
        p: &Principal,
        request: &str,
        track: BgmTrack,
        bytes: Vec<u8>,
        expected: Option<u32>,
        command: &str,
        read_source: bool,
        control: impl Fn(bool) -> CoreResult<()> + Send + Sync,
    ) -> CoreResult<BgmTrack> {
        control(false)?;
        let id = self.repo.accept_bgm(p, request, &track, &bytes, expected, command, read_source).await?;
        control(true)?;
        self.wait_bgm(p, &id).await
    }

    async fn wait_bgm(&self, p: &Principal, id: &str) -> CoreResult<BgmTrack> {
        let wait = async {
            loop {
                if let Some(mut result) = self.repo.bgm_result(&p.tenant_id, id).await? {
                    result.asset.url = self.store.url_for(&result.asset.key);
                    return Ok(result);
                }
                if self.execute_work {
                    self.recover_bgm_job(&p.tenant_id, id).await?;
                }
                tokio::time::sleep(std::time::Duration::from_millis(super::jobs::POLL_MS)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_millis(super::jobs::LEASE_MS as u64), wait)
            .await
            .map_err(|_| CoreError::Unavailable("BGM pending; retry the same request ID".into()))?
    }

    pub(super) async fn recover_bgm_job(&self, tenant: &str, id: &str) -> CoreResult<()> {
        if !self.execute_work {
            return Err(CoreError::Unavailable("this role cannot execute BGM work".into()));
        }
        if let Some(bytes) = self.repo.bgm_stage(tenant, id).await?
            && let Some(claim) = self.repo.claim_bgm(tenant, id, super::jobs::LEASE_MS).await?
        {
            let claim = &claim;
            let result = Self::under_speech_lease(
                self.upload_materialized(tenant, claim, bytes),
                self.maintain_speech_lease(tenant, claim),
                |attempt| async move { self.repo.publish_bgm(tenant, claim, &attempt).await },
            )
            .await;
            if result.is_err() {
                let _ = self.repo.retry_asset_job(tenant, claim, 0).await;
            }
            return result;
        }
        Ok(())
    }

    /// 一个源帧范围成为整个循环资产；保留原始权利声明和作者。
    pub async fn clip_bgm(&self, p: &Principal, command: &memoswish_protocol::BgmClip) -> CoreResult<BgmTrack> {
        self.clip_bgm_controlled(p, command, |_| Ok(())).await
    }

    pub async fn clip_bgm_controlled(
        &self,
        p: &Principal,
        command: &memoswish_protocol::BgmClip,
        control: impl Fn(bool) -> CoreResult<()> + Send + Sync,
    ) -> CoreResult<BgmTrack> {
        p.require(Permission::MediaRead)?;
        p.require(Permission::MediaWrite)?;
        memoswish_core::assets::validate_asset_id(&command.request_id)?;
        let command_hash = sha256_hex(&serde_json::to_vec(command).map_err(CoreError::internal)?);
        if let Some(id) = self.repo.bgm_request(p, &command.request_id, &command_hash).await? {
            control(true)?;
            return self.wait_bgm(p, &id).await;
        }
        let source = self
            .repo
            .get_bgm(&p.tenant_id, &command.track_id)
            .await?
            .ok_or_else(|| CoreError::NotFound("source BGM".into()))?;
        let key = &source.asset.key;
        if !key.starts_with(&p.asset_prefix()) && !key.starts_with("shared/bgm/") {
            return Err(CoreError::Forbidden("BGM source is outside tenant ownership".into()));
        }
        let delivery = self.repo.asset_delivery(p, key, Permission::MediaRead).await?;
        let object = if let Some(delivery) = &delivery {
            if delivery.store_id != self.store.namespace()? {
                return Err(CoreError::Unavailable("BGM source store mismatch".into()));
            }
            self.store.read_delivery(key, &delivery.version, MAX_BGM_UPLOAD as u64).await?
        } else {
            if key.starts_with(&format!("{}uploads/", p.asset_prefix())) {
                return Err(CoreError::NotFound("published BGM source".into()));
            }
            self.store.read_legacy(key, MAX_BGM_UPLOAD as u64).await?
        }
        .ok_or_else(|| CoreError::NotFound("BGM source bytes".into()))?;
        if source.asset.bytes != object.bytes.len() as u64 || source.asset.sha256 != sha256_hex(&object.bytes) {
            return Err(CoreError::Unavailable("BGM source integrity mismatch".into()));
        }
        let permit = crate::wav::PROCESSING
            .try_acquire()
            .map_err(|_| CoreError::Unavailable("PCM processing capacity exhausted".into()))?;
        let (start, end) = (command.start_frame, command.end_frame);
        let (bytes, pcm) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            crate::wav::clip_pcm(&object.bytes, start, end)
        })
        .await
        .map_err(|_| CoreError::Unavailable("PCM processor interrupted".into()))??;
        // 读取后重查源目录快照和当前读者权限；暂存后只依赖捕获的输出。
        self.repo.asset_delivery(p, key, Permission::MediaRead).await?;
        if self.repo.get_bgm(&p.tenant_id, &command.track_id).await?.as_ref() != Some(&source) {
            return Err(CoreError::Conflict("BGM source changed during clipping".into()));
        }
        let mut track = source;
        let identity = sha256_hex(
            &serde_json::to_vec(&(p.tenant_id.as_str(), &command, &track.asset.sha256, &track.provenance))
                .map_err(CoreError::internal)?,
        );
        track.id = format!("bgm_{}", &identity[..32]);
        if let Some(title) = &command.title {
            track.title = title.clone();
        }
        track.revision = 1;
        track.duration_ms = (u64::from(pcm.frames) * 1000 / u64::from(pcm.sample_rate)) as u32;
        track.loop_start_ms = 0;
        track.loop_end_ms = track.duration_ms;
        track.asset = AssetRef {
            key: format!("{}bgm/{}.wav", p.asset_prefix(), track.id),
            url: String::new(),
            mime: "audio/wav".into(),
            bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        };
        track.pcm = Some(pcm);
        pcm_info(&bytes)?;
        self.publish_bgm_bytes(p, &command.request_id, track, bytes, None, &command_hash, true, control).await
    }
}
