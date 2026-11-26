//! 导入持久执行与补偿；调度时机由应用层现有维护入口提供。
use crate::{ContentService, apkg::ApkgLimits};
use memoswish_core::{
    CoreError, CoreResult,
    assets::{ObjectVersion, UploadOutcome},
    imports::*,
    jobs::JobClaim,
};
use memoswish_protocol::DeckPack;
use std::time::Duration;

// 心跳、同步等待均由同一个任务租约推导；轮询只影响响应延迟。
const LEASE_MS: i64 = 120_000;
const POLL_MS: u64 = 25;

impl ContentService {
    /// API 只受理并等待持久回执，worker 与嵌入式安装才领取、发布和补偿。
    pub fn with_import_execution(mut self, enabled: bool) -> Self {
        self.execute_imports = enabled;
        self
    }

    pub fn import_repository(&self) -> std::sync::Arc<dyn memoswish_core::repo::Repository> {
        self.repo.clone()
    }
    pub fn import_staging_limit(&self) -> i64 {
        self.import_staging_limit
    }
    pub fn with_import_staging_limit(mut self, limit: i64) -> CoreResult<Self> {
        if !(1..=100).contains(&limit) {
            return Err(CoreError::invalid("import staging limit must be 1..=100"));
        }
        self.import_staging_limit = limit;
        Ok(self)
    }
    /// 整包校验、全新身份和聚合预算先于任何写入。
    pub fn prepare_deck_pack(
        &self,
        p: &memoswish_core::Principal,
        pack: impl serde::Serialize,
        auto_tts: bool,
    ) -> CoreResult<ImportWork> {
        p.require(memoswish_core::Permission::ContentWrite)?;
        let wire = input_value(&pack)?;
        let pack: DeckPack = decode_input(wire, ApkgLimits::NORMALIZED)?;
        if pack.version != "1.2" && pack.cards.iter().any(memoswish_core::bgm::has_media_metadata) {
            return Err(CoreError::Unsupported("media metadata requires DeckPack 1.2".into()));
        }
        if pack.version != "1.0" && pack.version != "1.1" && pack.version != "1.2" {
            return Err(CoreError::Unsupported("unsupported DeckPack version".into()));
        }
        if pack.cards.len() > ApkgLimits::CARDS {
            return Err(CoreError::invalid("DeckPack exceeds 500 cards or 8 MiB"));
        }
        let mut deck = pack.deck;
        deck.id = memoswish_core::ids::new_id();
        deck.revision = Some(1);
        deck.card_count = pack.cards.len() as u32;
        deck.created_at = chrono::Utc::now();
        deck.title = deck.title.trim().into();
        if deck.title.is_empty()
            || deck.title.chars().count() > 200
            || deck.language.trim().is_empty()
            || deck.language.len() > 64
        {
            return Err(CoreError::invalid("invalid DeckPack deck metadata"));
        }
        let mut cards = Vec::new();
        let mut provenance_expansion_bytes = 0;
        for mut card in pack.cards {
            provenance_expansion_bytes += normalize_import_provenance(&mut card)?;
            card.id = memoswish_core::ids::new_id();
            card.deck_id = deck.id.clone();
            card.revision = 1;
            card.created_at = deck.created_at;
            card.updated_at = deck.created_at;
            if card.language.trim().is_empty() {
                card.language = deck.language.clone();
            }
            // 既有 DeckPack 仅导入内容，TTS/BGM 媒体往返由 S18b 负责。
            card.tts = None;
            card.bgm = None;
            for (_, asset) in memoswish_core::assets::card_asset_slots_mut(&mut card) {
                asset.url.clear();
            }
            memoswish_core::content_validation::validate_card(&card)?;
            cards.push(card);
        }
        Ok(ImportWork {
            result: serde_json::to_value(&deck).map_err(CoreError::internal)?,
            deck,
            cards,
            media: vec![],
            auto_tts,
            identity_expansion_bytes: 0,
            provenance_expansion_bytes,
        })
    }
    pub async fn drive_import(&self, tenant: &str, id: &str) -> CoreResult<ImportOperation> {
        let wait = async {
            loop {
                let current = self.repo.import_operation(tenant, id).await?;
                if current.outcome != "pending" {
                    if self.execute_imports {
                        self.cleanup_import(tenant, id).await?;
                    }
                    return Ok(current);
                }
                let claim =
                    if self.execute_imports { self.repo.claim_import(tenant, id, LEASE_MS).await? } else { None };
                if let Some(claim) = claim {
                    return self.run_import_claim(tenant, id, &claim).await;
                } else {
                    tokio::time::sleep(Duration::from_millis(POLL_MS)).await;
                }
            }
        };
        tokio::time::timeout(Duration::from_millis(LEASE_MS as u64), wait).await.map_err(|_| {
            CoreError::Unavailable("import remains pending; retry with the original request identity".into())
        })?
    }
    /// 恢复只尝试领取一次，已有业务 owner 时立即返回，不阻塞其他任务族。
    pub async fn recover_import_once(&self, tenant: &str, id: &str) -> CoreResult<ImportOperation> {
        if !self.execute_imports {
            return Err(CoreError::Unavailable("this role cannot recover imports".into()));
        }
        let current = self.repo.import_operation(tenant, id).await?;
        if current.outcome != "pending" {
            self.cleanup_import(tenant, id).await?;
            return Ok(current);
        }
        let Some(claim) = self.repo.claim_import(tenant, id, LEASE_MS).await? else { return Ok(current) };
        self.run_import_claim(tenant, id, &claim).await
    }

    async fn run_import_claim(&self, tenant: &str, id: &str, claim: &JobClaim) -> CoreResult<ImportOperation> {
        let result = Self::under_import_lease(
            self.execute_import(tenant, claim),
            self.maintain_import_lease(tenant, claim),
            async { self.repo.commit_import(tenant, claim).await.map(|_| ()) },
        )
        .await;
        if let Err(error) = result {
            // 模糊提交必须先读取原始回执；读取失败时保持预留及所有权。
            let receipt = self.repo.import_operation(tenant, id).await?;
            if receipt.outcome == "committed" {
                self.cleanup_import(tenant, id).await?;
                return Ok(receipt);
            }
            if matches!(
                error,
                CoreError::Forbidden(_)
                    | CoreError::Unauthorized(_)
                    | CoreError::Invalid(_)
                    | CoreError::Unsupported(_)
            ) {
                self.repo.fail_import(tenant, claim).await?;
                self.cleanup_import(tenant, id).await?;
                return Err(error);
            }
            self.repo.retry_import(tenant, claim).await?;
            return Err(CoreError::Unavailable(
                "import remains pending; retry with the original request identity".into(),
            ));
        }
        let receipt = self.repo.import_operation(tenant, id).await?;
        if receipt.outcome == "pending" {
            return Err(CoreError::Unavailable("import remains pending".into()));
        }
        self.cleanup_import(tenant, id).await?;
        Ok(receipt)
    }

    async fn maintain_import_lease(&self, tenant: &str, claim: &JobClaim) -> CoreResult<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(LEASE_MS as u64 / 3));
        interval.tick().await;
        loop {
            interval.tick().await;
            self.repo.heartbeat_import(tenant, claim, LEASE_MS).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), CoreError>(())
    }

    async fn under_import_lease(
        operation: impl Future<Output = CoreResult<()>>,
        heartbeat: impl Future<Output = CoreResult<()>>,
        complete: impl Future<Output = CoreResult<()>>,
    ) -> CoreResult<()> {
        // 心跳等待 SQL 时仍轮询准备；退出 select 后再做带围栏的原子提交。
        tokio::select! { biased; result=operation=>result, result=heartbeat=>result }?;
        complete.await
    }

    async fn execute_import(&self, tenant: &str, claim: &JobClaim) -> CoreResult<()> {
        let execution = self.repo.import_execution(tenant, claim).await?;
        if !execution.work.media.is_empty() {
            let store = self
                .import_store
                .as_ref()
                .ok_or_else(|| CoreError::Unavailable("import object store is not configured".into()))?;
            let namespace = store.namespace()?;
            for (ordinal, media) in execution.work.media.iter().enumerate() {
                let attempt = self.repo.begin_import_upload(tenant, claim, ordinal as i64, &namespace).await?;
                if attempt.store_id != namespace {
                    return Err(CoreError::Conflict("import upload belongs to another store".into()));
                }
                if attempt.outcome == UploadOutcome::InFlight {
                    let receipt = match store.put_versioned(&attempt.key, media.bytes.clone(), &media.asset.mime).await
                    {
                        Ok(r) => r,
                        Err(_) => {
                            self.repo.mark_upload_uncertain(tenant, &attempt).await?;
                            return Err(CoreError::Unavailable("import upload outcome is uncertain".into()));
                        }
                    };
                    if receipt.asset.key != attempt.key
                        || receipt.asset.mime != media.asset.mime
                        || receipt.asset.sha256 != media.asset.sha256
                        || receipt.asset.bytes != media.asset.bytes
                    {
                        self.repo.mark_upload_uncertain(tenant, &attempt).await?;
                        return Err(CoreError::Unavailable("import upload receipt mismatch".into()));
                    }
                    let version = receipt.version.map_or(ObjectVersion::Unversioned, ObjectVersion::VersionId);
                    if self.repo.record_upload(tenant, &attempt, &version).await.is_err() {
                        let _ = self.repo.mark_upload_uncertain(tenant, &attempt).await;
                        return Err(CoreError::Unavailable("import upload receipt persistence is uncertain".into()));
                    }
                    let spec = memoswish_core::assets::AssetSpec {
                        mime: media.asset.mime.clone(),
                        size: media.asset.bytes as i64,
                        sha256: media.asset.sha256.clone(),
                    };
                    memoswish_core::asset_read::register_write(
                        self.repo.as_ref(),
                        store.as_ref(),
                        tenant,
                        &attempt.key,
                        &version,
                        &spec,
                        &media.bytes,
                    )
                    .await?;
                }
                self.repo.select_import_upload(tenant, claim, ordinal as i64, &attempt.id).await?;
            }
        }
        Ok(())
    }
    pub async fn cleanup_import(&self, tenant: &str, id: &str) -> CoreResult<()> {
        use memoswish_core::observability::{Operation, Outcome};
        let mut observation = self.observer.start(Operation::Orphan);
        let result: CoreResult<_> = async {
            if !self.execute_imports {
                return Err(CoreError::Unavailable("import cleanup is not available in this role".into()));
            }
            let Some(store) = &self.import_store else {
                return Ok(());
            };
            for attempt in self.repo.import_cleanup(tenant, id, &store.namespace()?).await? {
                let version = match &attempt.version {
                    ObjectVersion::Unknown => continue,
                    ObjectVersion::Unversioned => None,
                    ObjectVersion::VersionId(v) => Some(v.as_str()),
                };
                // 失败保持 cleanup_pending，字面量 null 作为精确版本原样传递。
                if store.delete_write(&attempt.key, version).await.is_ok() {
                    self.repo.record_asset_cleaned(tenant, &attempt).await?;
                } else {
                    self.repo.retry_import_cleanup(tenant, id, &attempt).await?;
                }
            }
            Ok(())
        }
        .await;
        observation.finish(if result.is_ok() { Outcome::Returned } else { Outcome::Error });
        result
    }
}

pub fn import_result(operation: ImportOperation) -> CoreResult<serde_json::Value> {
    if operation.outcome == "failed" {
        return Err(CoreError::Conflict(
            "import ended without content commit; the original identity is terminal".into(),
        ));
    }
    if operation.outcome != "committed" {
        return Err(CoreError::Unavailable("import did not commit; original identity is retained".into()));
    }
    operation.result.ok_or_else(|| CoreError::internal("committed import receipt is missing"))
}

/// 请求指纹绑定原始格式、选项和自动语音策略，随机输出身份不进入指纹。
pub fn fingerprint<T: serde::Serialize>(format: &str, input: &T, auto_tts: bool) -> CoreResult<String> {
    Ok(memoswish_core::ids::sha256_hex(&serde_json::to_vec(&(format, input, auto_tts)).map_err(CoreError::internal)?))
}

// 原始包先按 S18 正文上限校验；仅计入服务端来源规范化的实际正增量。
pub(crate) fn normalize_import_provenance(card: &mut memoswish_protocol::Card) -> CoreResult<usize> {
    let before = json_bytes(card, PORTABLE_SNAPSHOT_BYTES)?;
    let mut provenance = card.content.as_ref().map(|m| m.provenance.clone()).unwrap_or_default();
    provenance.source_publication_claim.get_or_insert_with(|| {
        card.content.as_ref().map(|m| m.publication.clone()).unwrap_or_else(|| "published".into())
    });
    if let Some(metadata) = &card.content {
        if let Some(observed) = &metadata.observed_generation {
            provenance.source_generation_claim.get_or_insert(observed.clone());
        }
        provenance.source_publication_claim.get_or_insert(metadata.publication.clone());
    }
    set_source_identity(&mut provenance, &card.id);
    provenance.source_revision = Some(card.revision);
    if provenance.method.is_empty() {
        provenance.method = "import".into();
    }
    memoswish_core::content_lifecycle::validate_provenance(&provenance)?;
    card.content = Some(memoswish_protocol::ContentMetadata {
        observed_generation: None,
        publication: "published".into(),
        provenance,
    });
    Ok(json_bytes(card, PORTABLE_SNAPSHOT_BYTES)?.saturating_sub(before))
}

// 首次导出就计入往返需要的来源元数据，不把业务扩展伪装成身份扩展。
pub fn prepare_export_provenance(card: &mut memoswish_protocol::Card) -> CoreResult<()> {
    let id = card.id.clone();
    let revision = card.revision;
    let metadata = card.content.get_or_insert_with(|| memoswish_protocol::ContentMetadata {
        publication: "published".into(),
        observed_generation: None,
        provenance: Default::default(),
    });
    let provenance = &mut metadata.provenance;
    if provenance.method.is_empty() {
        provenance.method = "unknown".into();
    }
    if provenance.source_id.is_none() {
        set_source_identity(provenance, &id);
    }
    provenance.source_revision.get_or_insert(revision);
    provenance.source_publication_claim.get_or_insert(metadata.publication.clone());
    if let Some(observed) = &metadata.observed_generation {
        provenance.source_generation_claim.get_or_insert(observed.clone());
    }
    memoswish_core::content_lifecycle::validate_provenance(provenance)
}

/// 短身份保留原文；长身份保存带类型标志的完整 SHA-256，不截断源身份。
pub fn set_source_identity(provenance: &mut memoswish_protocol::ContentProvenance, source: &str) {
    provenance.source_id_is_digest = source.len() > 1024;
    provenance.source_id = Some(if provenance.source_id_is_digest {
        format!("sha256:{}", memoswish_core::ids::sha256_hex(source.as_bytes()))
    } else {
        source.to_owned()
    });
}

#[cfg(test)]
mod lifecycle_tests {
    #[test]
    fn import_records_the_observed_pack_revision_without_promoting_generation_claims() {
        let mut card = memoswish_protocol::examples::sample_card();
        card.revision = 7;
        card.content = Some(memoswish_protocol::ContentMetadata {
            observed_generation: Some("builtin-heuristic".into()),
            publication: "draft".into(),
            provenance: memoswish_protocol::ContentProvenance {
                method: "agent".into(),
                source_id: Some("earlier-source".into()),
                source_revision: Some(2),
                attribution: "Retained author".into(),
                rights: "Apache-2.0".into(),
                ..Default::default()
            },
        });
        super::prepare_export_provenance(&mut card).unwrap();
        let exported = card.clone();
        super::normalize_import_provenance(&mut card).unwrap();
        let metadata = card.content.as_ref().unwrap();
        assert_eq!(metadata.observed_generation, None);
        assert_eq!(metadata.provenance.source_revision, Some(7));
        assert_eq!(metadata.provenance.source_id.as_deref(), Some(card.id.as_str()));
        assert_eq!(metadata.provenance.source_generation_claim.as_deref(), Some("builtin-heuristic"));
        assert_eq!(metadata.provenance.source_publication_claim.as_deref(), Some("draft"));
        assert_eq!(metadata.provenance.rights, "Apache-2.0");
        assert_eq!(metadata.provenance.attribution, "Retained author");
        assert!(memoswish_core::imports::json_bytes(&card, serde_json::to_vec(&exported).unwrap().len()).is_ok());
        let mut legacy = memoswish_protocol::examples::sample_card();
        legacy.content = None;
        super::prepare_export_provenance(&mut legacy).unwrap();
        assert_eq!(legacy.content.as_ref().unwrap().provenance.method, "unknown");
        let size = serde_json::to_vec(&legacy).unwrap().len();
        super::normalize_import_provenance(&mut legacy).unwrap();
        assert!(memoswish_core::imports::json_bytes(&legacy, size).is_ok());
    }
}

#[cfg(test)]
#[path = "imports_tests.rs"]
mod tests;
