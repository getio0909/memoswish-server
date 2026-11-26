//! 持久合成与 S15 上传交接；仅使用 jobs 租约，不引入第二调度器。
use super::{MediaService, SynthesizeOptions, TtsSidecar};
use memoswish_core::assets::{AssetSpec, ObjectVersion};
use memoswish_core::jobs::JobClaim;
use memoswish_core::tts::{SpeechFailure, SpeechMetadata, SpeechRequest, SpeechWork, TtsOutput, TtsRequest};
use memoswish_core::{CoreError, CoreResult, Permission, Principal, ids::sha256_hex};
use memoswish_protocol::TtsTrack;
use std::time::Duration;

// 心跳和同步等待预算由同一个租约推导；轮询只影响延迟，不提供完成证明。
pub(super) const LEASE_MS: i64 = 120_000;
pub(super) const POLL_MS: u64 = 25;

impl MediaService {
    async fn prepare_speech_work(
        &self,
        p: &Principal,
        text: &str,
        language: &str,
        opts: &SynthesizeOptions,
        import_privacy: Option<Option<&memoswish_core::imports::ImportPrivacy>>,
    ) -> CoreResult<SpeechWork> {
        let id = opts.engine.as_deref().unwrap_or(&self.default_engine);
        if id == "unconfigured" {
            return Err(CoreError::SpeechUnconfigured);
        }
        let engine = self.engines.get(id).ok_or_else(|| CoreError::invalid("unknown tts engine"))?;
        let speed = opts.speed.unwrap_or(1.0);
        if !speed.is_finite() {
            return Err(CoreError::invalid("tts speed must be finite"));
        }
        let privacy = if engine.external_transfer() {
            let admitted_revision = match import_privacy {
                Some(Some(fence)) if fence.policy == self.privacy => Some(fence.revision),
                Some(_) => return Err(CoreError::Forbidden("import privacy evidence is missing or changed".into())),
                None => None,
            };
            let revision = self
                .repo
                .privacy_admit(&p.tenant_id, p, &self.privacy, Some("external_tts"), admitted_revision)
                .await?;
            Some(memoswish_core::privacy::PrivacyFence {
                principal: p.clone(),
                credential_hash: p.session_access_hash.clone(),
                policy: self.privacy.clone(),
                revision,
            })
        } else {
            None
        };
        let mut work = SpeechWork {
            provenance: opts.provenance.clone(),
            privacy,
            engine: id.into(),
            namespace: engine.cache_namespace(),
            request: TtsRequest {
                text: text.trim().into(),
                language: language.into(),
                voice: opts.voice.clone().unwrap_or_else(|| "default".into()),
                speed: speed.clamp(0.5, 2.0),
            },
            legacy_output: None,
            amount: text.trim().chars().count() as i64 * i64::from(engine.cost_per_char().max(1)),
        };
        work.validate()?;
        let legacy = self.legacy_speech(&p.tenant_id, &work).await?;
        if legacy.is_some() {
            work.amount = 0;
            work.legacy_output = legacy;
        }
        Ok(work)
    }
    /// 提交命令先重放，再解析当前内容和配置；接受后不依赖调用连接。
    pub async fn submit_tts(
        &self,
        p: &Principal,
        request_id: &str,
        card_ids: &[String],
        opts: &SynthesizeOptions,
    ) -> CoreResult<memoswish_protocol::tts::TtsSubmission> {
        self.submit_tts_inner(p, request_id, card_ids, opts, None, || Ok(())).await
    }

    /// 导入恢复必须沿用受理时的用途证据，旧导入缺少外传授权时关闭失败。
    pub async fn submit_import_tts(
        &self,
        p: &Principal,
        request_id: &str,
        card_ids: &[String],
        opts: &SynthesizeOptions,
        privacy: Option<&memoswish_core::imports::ImportPrivacy>,
    ) -> CoreResult<memoswish_protocol::tts::TtsSubmission> {
        self.submit_tts_inner(p, request_id, card_ids, opts, Some(privacy), || Ok(())).await
    }

    /// 应用适配器在准备完成、进入接收事务前检查显式取消。
    pub async fn submit_tts_controlled(
        &self,
        p: &Principal,
        request_id: &str,
        card_ids: &[String],
        opts: &SynthesizeOptions,
        before_accept: impl FnOnce() -> CoreResult<()>,
    ) -> CoreResult<memoswish_protocol::tts::TtsSubmission> {
        self.submit_tts_inner(p, request_id, card_ids, opts, None, before_accept).await
    }

    async fn submit_tts_inner(
        &self,
        p: &Principal,
        request_id: &str,
        card_ids: &[String],
        opts: &SynthesizeOptions,
        import_privacy: Option<Option<&memoswish_core::imports::ImportPrivacy>>,
        before_accept: impl FnOnce() -> CoreResult<()>,
    ) -> CoreResult<memoswish_protocol::tts::TtsSubmission> {
        use memoswish_core::tts::{SpeechSubmissionTarget, validate_submission_id};
        p.require(Permission::TtsGenerate)?;
        p.require(Permission::ContentRead)?;
        p.require(Permission::ContentWrite)?;
        validate_submission_id(request_id)?;
        let unique: std::collections::HashSet<_> = card_ids.iter().collect();
        if card_ids.is_empty()
            || card_ids.len() > 100
            || unique.len() != card_ids.len()
            || opts.expected_revisions.iter().any(|(id, r)| !unique.contains(id) || *r == 0)
            || opts.speed.is_some_and(|s| !s.is_finite() || !(0.5..=2.0).contains(&s))
        {
            return Err(CoreError::invalid("provide 1..=100 unique card targets and valid synthesis options"));
        }
        let command = sha256_hex(
            &serde_json::to_vec(&(card_ids, opts)).map_err(|_| CoreError::invalid("invalid synthesis command"))?,
        );
        if let Some(replay) = self.repo.speech_submission(p, request_id, Some(&command)).await? {
            return Ok(replay);
        }
        let mut targets = Vec::with_capacity(card_ids.len());
        for id in card_ids {
            let card = self.content.get_card(p, id).await?;
            memoswish_core::content::check_revision(opts.expected_revisions.get(id).copied(), card.revision)?;
            let text = opts.text.clone().unwrap_or_else(|| Self::default_tts_text(&card));
            let work = self.prepare_speech_work(p, &text, &card.language, opts, import_privacy).await?;
            targets.push(SpeechSubmissionTarget { card_id: id.clone(), revision: card.revision, work });
        }
        let limit = self.quota.tts_limit(&p.tenant_id).await?;
        before_accept()?;
        self.repo.submit_speech(p, request_id, &command, &targets, limit).await
    }

    pub async fn tts_submission_status(
        &self,
        p: &Principal,
        request_id: &str,
    ) -> CoreResult<memoswish_protocol::tts::TtsSubmission> {
        self.repo
            .speech_submission(p, request_id, None)
            .await?
            .ok_or_else(|| CoreError::NotFound("tts submission".into()))
    }
    pub async fn pending_attachment_page(&self, after: Option<(&str, &str)>) -> CoreResult<Vec<(String, String)>> {
        self.repo.pending_speech_attachments(after, 100).await
    }
    /// 直接受理命令的有限单项交接；不执行全局发现。
    pub async fn recover_submission_item(&self, tenant: &str, item: &str) -> CoreResult<()> {
        if !self.execute_work {
            return Err(CoreError::Unavailable("this role cannot execute speech work".into()));
        }
        let request = self.repo.speech_request(tenant, item).await?;
        self.recover_speech_job(tenant, &request.synthesis_id).await?;
        self.recover_attachment(tenant, item).await
    }
    pub async fn recover_attachment(&self, tenant: &str, item: &str) -> CoreResult<()> {
        self.repo.resolve_speech_attachment(tenant, item).await
    }

    async fn legacy_speech(&self, tenant: &str, work: &SpeechWork) -> CoreResult<Option<TtsOutput>> {
        let r = &work.request;
        let cache =
            sha256_hex(format!("{}|{}|{}|{:.2}|{}", work.engine, r.voice, r.language, r.speed, r.text).as_bytes());
        let base = format!("tenants/{tenant}/tts/{}", &cache[..32]);
        let key = format!("{base}.wav");
        let Some(meta) = self.store.read_legacy(&format!("{base}.json"), 1024 * 1024).await? else { return Ok(None) };
        let Ok(side) = serde_json::from_slice::<TtsSidecar>(&meta.bytes) else { return Ok(None) };
        let Some(obj) = self.store.read_legacy(&key, 64 * 1024 * 1024).await? else { return Ok(None) };
        let digest = sha256_hex(&obj.bytes);
        // 旧 sidecar 没有摘要时，只能使用已持久卡片的独立摘要，绝不把现读摘要当历史证据。
        let recorded = side.sha256.as_ref() == Some(&digest)
            || self.repo.legacy_asset_cards(tenant, &key).await?.iter().any(|c| {
                c.tts.as_ref().is_some_and(|t| {
                    t.audio.key == key
                        && t.audio.sha256 == digest
                        && t.audio.bytes == obj.bytes.len() as u64
                        && t.text == r.text
                        && t.language == r.language
                        && t.voice == r.voice
                        && t.engine == work.engine
                })
            });
        if !recorded {
            return Ok(None);
        }
        let out = TtsOutput {
            alignment_quality: side.alignment_quality,
            audio_kind: side.audio_kind,
            provenance: side.provenance,
            audio: obj.bytes,
            mime: obj.mime,
            extension: "wav".into(),
            duration_ms: side.duration_ms,
            words: side.words,
        };
        if Self::validate_speech_output(&out).is_err() {
            return Ok(None);
        }
        Ok(Some(out))
    }

    pub(super) async fn durable_synthesis(
        &self,
        p: &Principal,
        text: &str,
        language: &str,
        opts: &SynthesizeOptions,
        target: Option<(&str, u32)>,
    ) -> CoreResult<(SpeechRequest, TtsTrack)> {
        p.require(Permission::TtsGenerate)?;
        if target.is_some() {
            p.require(Permission::ContentRead)?;
            p.require(Permission::ContentWrite)?;
        }
        let work = self.prepare_speech_work(p, text, language, opts, None).await?;
        let request = self.repo.accept_speech(p, &work, target, self.quota.tts_limit(&p.tenant_id).await?).await?;
        // 同步调用保留既有响应；超时/取消后由持久任务和后台恢复继续负责。
        let wait = async {
            loop {
                let current = self.repo.speech_request(&p.tenant_id, &request.id).await?;
                match current.outcome.as_str() {
                    "requester_revoked" => {
                        return Err(CoreError::Forbidden("synthesis requester is no longer authorized".into()));
                    }
                    "failed" => {
                        return Err(current.failure.map(SpeechFailure::error).unwrap_or_else(|| {
                            CoreError::Unavailable("synthesis failed; durable responsibility retained".into())
                        }));
                    }
                    _ => {}
                }
                if let Some(mut track) = self.repo.speech_track(&p.tenant_id, &request.synthesis_id).await? {
                    track.audio.url = self.store.url_for(&track.audio.key);
                    return Ok((request.clone(), track));
                }
                if self.execute_work {
                    self.advance_speech(&p.tenant_id, &request.synthesis_id).await?;
                }
                tokio::time::sleep(Duration::from_millis(POLL_MS)).await;
            }
        };
        tokio::time::timeout(Duration::from_millis(LEASE_MS as u64), wait)
            .await
            .map_err(|_| CoreError::Unavailable("synthesis pending; retry the same request".into()))?
    }

    fn validate_speech_output(out: &TtsOutput) -> CoreResult<(AssetSpec, SpeechMetadata)> {
        let spec = AssetSpec { mime: out.mime.clone(), size: out.audio.len() as i64, sha256: sha256_hex(&out.audio) };
        spec.validate()?;
        let meta = SpeechMetadata {
            alignment_quality: out.alignment_quality,
            audio_kind: out.audio_kind,
            provenance: out.provenance.clone(),
            extension: out.extension.clone(),
            duration_ms: out.duration_ms,
            words: out.words.clone(),
        };
        meta.validate()?;
        if out.audio.is_empty() || !out.mime.starts_with("audio/") {
            return Err(CoreError::invalid("invalid synthesis output"));
        }
        Ok((spec, meta))
    }

    pub(super) async fn under_speech_lease<F, H, T, C, R>(
        operation: F,
        heartbeat: H,
        complete: impl FnOnce(T) -> C,
    ) -> CoreResult<R>
    where
        F: Future<Output = CoreResult<T>>,
        H: Future<Output = CoreResult<T>>,
        C: Future<Output = CoreResult<R>>,
    {
        // 心跳 SQL 等待连接时仍轮询主操作，避免单连接 SQLite 的互相等待。
        let prepared = tokio::select! {
            biased;
            result=operation=>result,
            result=heartbeat=>result,
        }?;
        // select 退出即丢弃心跳；完成事务仍复核 token 和租约，不能被自己的续约取消。
        complete(prepared).await
    }

    pub(super) async fn maintain_speech_lease<T>(&self, tenant: &str, claim: &JobClaim) -> CoreResult<T> {
        let mut interval = tokio::time::interval(Duration::from_millis(LEASE_MS as u64 / 3));
        loop {
            interval.tick().await;
            self.repo.heartbeat_speech(tenant, claim, LEASE_MS).await?;
        }
    }

    async fn advance_speech(&self, tenant: &str, id: &str) -> CoreResult<()> {
        if !self.execute_work {
            return Err(CoreError::Unavailable("this role cannot execute speech work".into()));
        }
        let work = self.repo.speech_work(tenant, id).await?;
        let engine = self.engines.get(&work.engine);
        let external = engine.is_some_and(|engine| engine.external_transfer());
        if self.repo.retire_invalid_speech(tenant, id, &self.privacy, external).await? {
            return Ok(());
        }
        if self.repo.speech_track(tenant, id).await?.is_some() {
            return Ok(());
        }
        if let Some((upload, bytes)) = self.repo.speech_upload(tenant, id).await? {
            // 暂存输出仍须识别原引擎的外传属性，防止绕过既有隐私屏障。
            engine.ok_or(CoreError::SpeechEngineUnavailable)?;
            if let Some(claim) = self.repo.claim_speech(tenant, &upload, LEASE_MS).await? {
                let claim = &claim;
                let result = Self::under_speech_lease(
                    self.upload_materialized(tenant, claim, bytes),
                    self.maintain_speech_lease(tenant, claim),
                    |attempt| async move { self.repo.publish_speech(tenant, claim, &attempt).await },
                )
                .await;
                if result.is_err() {
                    self.repo.retire_invalid_speech(tenant, id, &self.privacy, external).await?;
                    let _ = self
                        .repo
                        .fail_speech(tenant, claim, result.as_ref().err().and_then(SpeechFailure::from_error))
                        .await;
                }
                return result;
            }
        } else if let Some(claim) = self.repo.claim_speech(tenant, id, LEASE_MS).await? {
            let claim = &claim;
            let result = Self::under_speech_lease(
                async {
                    let work = self.repo.speech_work(tenant, id).await?;
                    let engine = self.engines.get(&work.engine).ok_or(CoreError::SpeechEngineUnavailable)?;
                    if engine.cache_namespace() != work.namespace {
                        return Err(CoreError::Unavailable("synthesis engine configuration changed".into()));
                    }
                    let legacy = self.repo.legacy_speech_output(tenant, id).await?;
                    let adopted = legacy.is_some();
                    let mut out = if let Some(out) = legacy {
                        out
                    } else {
                        // 零额度只允许有摘要证据的 legacy；崩溃丢失该证据时不调用 provider。
                        if work.amount == 0 {
                            return Err(CoreError::Unavailable("legacy adoption requires recorded bytes".into()));
                        }
                        engine.validate_request(&work.request).await?;
                        let execution = engine.prepare_execution(&work.request).await?;
                        self.repo.begin_provider(tenant, claim).await?;
                        execution
                            .await
                            .map_err(|_| CoreError::Unavailable("synthesis provider outcome is uncertain".into()))?
                    };
                    if let Some(declared) = &work.provenance {
                        out.provenance = Some(declared.clone());
                    } else if !adopted && out.provenance.is_none() {
                        out.provenance = Some(memoswish_protocol::ContentProvenance {
                            method: if work.engine == "placeholder" { "heuristic" } else { "provider" }.into(),
                            provider_claim: Some(work.engine.clone()),
                            ..Default::default()
                        });
                    }
                    if out.words.iter().any(|w| w.char_end > work.request.text.chars().count() as u32) {
                        return Err(CoreError::invalid("synthesis timing exceeds text"));
                    }
                    let (spec, meta) = Self::validate_speech_output(&out)?;
                    Ok((out, spec, meta, adopted))
                },
                self.maintain_speech_lease(tenant, claim),
                |(out, spec, meta, adopted)| async move {
                    self.repo.materialize_speech(tenant, claim, &out.audio, &spec, &meta, adopted).await
                },
            )
            .await;
            if result.is_err() {
                self.repo.retire_invalid_speech(tenant, id, &self.privacy, external).await?;
                let _ = self
                    .repo
                    .fail_speech(tenant, claim, result.as_ref().err().and_then(SpeechFailure::from_error))
                    .await;
            }
            return result;
        }
        Ok(())
    }

    pub(super) async fn upload_materialized(
        &self,
        tenant: &str,
        claim: &JobClaim,
        bytes: Vec<u8>,
    ) -> CoreResult<String> {
        let intent = self
            .repo
            .asset_intent(tenant, &claim.job_id)
            .await?
            .ok_or_else(|| CoreError::NotFound("synthesis asset intent".into()))?;
        if intent.spec.size != bytes.len() as i64 || intent.spec.sha256 != sha256_hex(&bytes) {
            return Err(CoreError::invalid("synthesis upload identity mismatch"));
        }
        let attempt = self.repo.begin_upload(tenant, claim, &self.store.namespace()?).await?;
        let read_blocks = bytes.chunks(memoswish_core::asset_read::BLOCK_BYTES).map(sha256_hex).collect();
        let write = match self.store.put_versioned(&attempt.key, bytes, &intent.spec.mime).await {
            Ok(write) => write,
            Err(_) => {
                self.repo.mark_upload_uncertain(tenant, &attempt).await?;
                return Err(CoreError::Unavailable("synthesis upload outcome is uncertain".into()));
            }
        };
        if write.asset.key != attempt.key
            || write.asset.mime != intent.spec.mime
            || write.asset.bytes != intent.spec.size as u64
            || write.asset.sha256 != intent.spec.sha256
        {
            self.repo.mark_upload_uncertain(tenant, &attempt).await?;
            return Err(CoreError::Unavailable("synthesis upload receipt mismatch".into()));
        }
        let version = write.version.map_or(ObjectVersion::Unversioned, ObjectVersion::VersionId);
        if self.repo.record_upload(tenant, &attempt, &version).await.is_err() {
            let _ = self.repo.mark_upload_uncertain(tenant, &attempt).await;
            return Err(CoreError::Unavailable("synthesis upload receipt persistence is uncertain".into()));
        }
        memoswish_core::asset_read::register_blocks(
            self.repo.as_ref(),
            self.store.as_ref(),
            tenant,
            &attempt.key,
            &version,
            &intent.spec,
            read_blocks,
        )
        .await?;
        Ok(attempt.id)
    }

    /// 维护只发现责任，领取仍经过应用准入。
    pub async fn pending_speech_page(&self, after: Option<(&str, &str)>) -> CoreResult<Vec<(String, String)>> {
        let mut page = self.repo.pending_speech(after, 100).await?;
        page.extend(self.repo.pending_bgm(after, 100).await?);
        page.sort();
        page.truncate(100);
        Ok(page)
    }
    pub async fn recover_speech_job(&self, tenant: &str, id: &str) -> CoreResult<()> {
        if self.repo.bgm_stage(tenant, id).await?.is_some() {
            return self.recover_bgm_job(tenant, id).await;
        }
        self.advance_speech(tenant, id).await?;
        if self.repo.speech_upload(tenant, id).await?.is_some() {
            self.advance_speech(tenant, id).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "jobs_tests.rs"]
mod tests;
