//! 内部资产上传流程。

use crate::OperationTracker;
use memoswish_core::assets::{AssetIntent, AssetSpec, ObjectVersion, UploadAttempt};
use memoswish_core::jobs::JobClaim;
use memoswish_core::repo::Repository;
use memoswish_core::store::ObjectStore;
use memoswish_core::{CoreError, CoreResult, Principal};
use std::sync::Arc;

#[derive(Clone)]
pub struct AssetUploads {
    repo: Arc<dyn Repository>,
    store: Arc<dyn ObjectStore>,
    operations: OperationTracker,
    store_id: String,
}

impl AssetUploads {
    /// store_id 是部署配置中稳定的物理存储命名空间，变更后旧回执须交还原存储处理。
    pub fn new(
        repo: Arc<dyn Repository>,
        store: Arc<dyn ObjectStore>,
        operations: OperationTracker,
        store_id: String,
    ) -> CoreResult<Self> {
        memoswish_core::assets::validate_asset_id(&store_id)?;
        Ok(Self { repo, store, operations, store_id })
    }

    pub async fn prepare(
        &self,
        p: &Principal,
        request: &str,
        bytes: &[u8],
        mime: &str,
        max_attempts: i64,
    ) -> CoreResult<AssetIntent> {
        let spec =
            AssetSpec { mime: mime.into(), size: bytes.len() as i64, sha256: memoswish_core::ids::sha256_hex(bytes) };
        self.repo.prepare_asset(p, request, &spec, max_attempts).await
    }

    /// 句柄被丢弃后已接收任务仍归 OperationTracker，SQL 意图负责进程崩溃后的发现。
    pub fn upload(
        &self,
        tenant: String,
        claim: JobClaim,
        bytes: Vec<u8>,
    ) -> CoreResult<tokio::task::JoinHandle<CoreResult<UploadAttempt>>> {
        let this = self.clone();
        self.operations.spawn(async move {
            let intent = this
                .repo
                .asset_intent(&tenant, &claim.job_id)
                .await?
                .ok_or_else(|| CoreError::NotFound("asset intent".into()))?;
            if intent.spec.size != bytes.len() as i64 || intent.spec.sha256 != memoswish_core::ids::sha256_hex(&bytes) {
                return Err(CoreError::invalid("upload bytes do not match prepared asset"));
            }
            let mut attempt = this.repo.begin_upload(&tenant, &claim, &this.store_id).await?;
            let read_blocks =
                bytes.chunks(memoswish_core::asset_read::BLOCK_BYTES).map(memoswish_core::ids::sha256_hex).collect();
            let receipt = match this.store.put_versioned(&attempt.key, bytes, &intent.spec.mime).await {
                Ok(receipt) => receipt,
                Err(_) => {
                    this.repo.mark_upload_uncertain(&tenant, &attempt).await?;
                    return Err(CoreError::Unavailable("upload outcome is uncertain".into()));
                }
            };
            let asset = &receipt.asset;
            if asset.key != attempt.key
                || asset.mime != intent.spec.mime
                || asset.bytes != intent.spec.size as u64
                || asset.sha256 != intent.spec.sha256
            {
                this.repo.mark_upload_uncertain(&tenant, &attempt).await?;
                return Err(CoreError::Unavailable("upload receipt does not match prepared identity".into()));
            }
            let version = receipt.version.map_or(ObjectVersion::Unversioned, ObjectVersion::VersionId);
            if this.repo.record_upload(&tenant, &attempt, &version).await.is_err() {
                // 回执丢失仍能由已提交 attempt 发现；不能由对象存在推断成功。
                let _ = this.repo.mark_upload_uncertain(&tenant, &attempt).await;
                return Err(CoreError::Unavailable("upload receipt persistence is uncertain".into()));
            }
            memoswish_core::asset_read::register_blocks(
                this.repo.as_ref(),
                this.store.as_ref(),
                &tenant,
                &attempt.key,
                &version,
                &intent.spec,
                read_blocks,
            )
            .await?;
            attempt.version = version;
            attempt.outcome = memoswish_core::assets::UploadOutcome::Uploaded;
            Ok(attempt)
        })
    }

    pub fn cleanup(
        &self,
        tenant: String,
        claim: JobClaim,
        attempt_id: String,
    ) -> CoreResult<tokio::task::JoinHandle<CoreResult<()>>> {
        let this = self.clone();
        self.operations.spawn(async move {
            let attempt = this.repo.begin_asset_cleanup(&tenant, &claim, &attempt_id, &this.store_id).await?;
            if attempt.store_id != this.store_id {
                return Err(CoreError::Conflict("upload belongs to a different object store".into()));
            }
            let version = match &attempt.version {
                ObjectVersion::Unknown => return Err(CoreError::Conflict("unknown upload cannot be deleted".into())),
                ObjectVersion::Unversioned => None,
                ObjectVersion::VersionId(id) => Some(id.as_str()),
            };
            this.store
                .delete_write(&attempt.key, version)
                .await
                .map_err(|_| CoreError::Unavailable("asset cleanup remains pending".into()))?;
            this.repo.record_asset_cleaned(&tenant, &attempt).await
        })
    }
}

impl crate::Services {
    /// 请求断开不会取消已准入的合成/上传/挂载；关闭后不再领取新工作。
    pub(crate) async fn synthesize_owned_card(
        &self,
        p: &Principal,
        card: &str,
        options: &memoswish_media::SynthesizeOptions,
    ) -> CoreResult<memoswish_protocol::Card> {
        let media = self.media.clone();
        let p = p.clone();
        let card = card.to_owned();
        let options = options.clone();
        self.operations
            .spawn(async move { media.synthesize_card(&p, &card, &options).await })?
            .await
            .map_err(|_| CoreError::Unavailable("synthesis task interrupted; durable responsibility retained".into()))?
    }

    pub async fn submit_tts(
        &self,
        p: &Principal,
        request_id: &str,
        card_ids: &[String],
        options: &memoswish_media::SynthesizeOptions,
    ) -> CoreResult<memoswish_protocol::tts::TtsSubmission> {
        let tenant = p.tenant_id.clone();
        let media = self.media.clone();
        let p = p.clone();
        let request_id = request_id.to_owned();
        let card_ids = card_ids.to_vec();
        let options = options.clone();
        let result = self
            .operations
            .spawn(async move {
                let control = crate::OperationControl::current();
                control.checkpoint()?;
                let result = media
                    .submit_tts_controlled(&p, &request_id, &card_ids, &options, || control.begin_acceptance())
                    .await?;
                control.accepted();
                Ok::<_, CoreError>(result)
            })?
            .await
            .map_err(|_| CoreError::Unavailable("submission interrupted; retry the same request ID".into()))??;
        // 接受后即使本轮恢复未准入，SQL 已持有全部责任，下一轮 maintenance 可继续。
        if self.media.executes_work() {
            let media = self.media.clone();
            let items = result.items.clone();
            let operations = self.operations.clone();
            let _ = self.operations.spawn(async move {
                for item in items {
                    let media = media.clone();
                    let tenant = tenant.clone();
                    let _ = operations
                        .spawn(async move { media.recover_submission_item(&tenant, &item.item_id).await })?
                        .await;
                }
                Ok::<(), CoreError>(())
            });
        }
        Ok(result)
    }
    pub async fn tts_submission_status(
        &self,
        p: &Principal,
        request_id: &str,
    ) -> CoreResult<memoswish_protocol::tts::TtsSubmission> {
        self.media.tts_submission_status(p, request_id).await
    }

    /// 兼容内部调用；发现改为分别领取持久的有界任务。
    pub fn recover_speech(&self) -> CoreResult<tokio::task::JoinHandle<CoreResult<()>>> {
        self.require_import_executor()?;
        let services = self.clone();
        self.operations.spawn(async move {
            services
                .recover_scheduled(memoswish_core::maintenance::TaskKind::SpeechRecovery)?
                .await
                .map_err(|_| CoreError::Unavailable("speech discovery interrupted".into()))??;
            services
                .recover_scheduled(memoswish_core::maintenance::TaskKind::AttachmentRecovery)?
                .await
                .map_err(|_| CoreError::Unavailable("attachment discovery interrupted".into()))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use memoswish_core::assets::{AssetReference, AssetRepo, UploadOutcome};
    use memoswish_core::jobs::AssetJobRepo;
    use memoswish_core::repo::{AuthRepo, TenantRecord, UserRecord};
    use memoswish_core::store::{ObjectWrite, StoredObject};
    use memoswish_protocol::AssetRef;
    use memoswish_storage::{LocalDiskStore, sqlite::SqliteRepository};
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::{Notify, Semaphore};

    struct FaultStore {
        disk: LocalDiskStore,
        lose_put: bool,
        lose_delete: bool,
        block_first: AtomicBool,
        reached: Notify,
        resume: Semaphore,
        deletes: Mutex<Vec<(String, Option<String>)>>,
    }

    #[async_trait]
    impl ObjectStore for FaultStore {
        fn kind(&self) -> &'static str {
            "fault-store"
        }
        async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
            self.disk.put(key, bytes, mime).await
        }
        async fn put_versioned(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<ObjectWrite> {
            let mut asset = self.disk.put(key, bytes, mime).await?;
            asset.url = "https://provider.invalid/?token=SECRET_SENTINEL".into();
            if self.block_first.swap(false, Ordering::SeqCst) {
                self.reached.notify_one();
                self.resume.acquire().await.unwrap().forget();
            }
            if self.lose_put {
                return Err(CoreError::internal("provider SECRET_SENTINEL response lost"));
            }
            Ok(ObjectWrite { asset, version: Some("null".into()) })
        }
        async fn delete_write(&self, key: &str, version: Option<&str>) -> CoreResult<()> {
            self.deletes.lock().unwrap().push((key.into(), version.map(str::to_owned)));
            self.disk.delete(key).await?;
            if self.lose_delete {
                return Err(CoreError::internal("provider SECRET_SENTINEL delete response lost"));
            }
            Ok(())
        }
        async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
            self.disk.get(key).await
        }
        async fn exists(&self, key: &str) -> CoreResult<bool> {
            self.disk.exists(key).await
        }
        async fn delete(&self, _key: &str) -> CoreResult<()> {
            panic!("cleanup must use exact write receipt")
        }
        fn url_for(&self, key: &str) -> String {
            self.disk.url_for(key)
        }
    }

    struct Fixture {
        root: std::path::PathBuf,
        url: String,
        repo: Arc<SqliteRepository>,
        p: Principal,
        store: Arc<FaultStore>,
        operations: OperationTracker,
        uploads: AssetUploads,
    }
    impl Fixture {
        async fn new(lose_put: bool, lose_delete: bool, block: bool) -> Self {
            let root = std::env::temp_dir().join(format!("memoswish-s15-app-{}", memoswish_core::ids::new_id()));
            std::fs::create_dir_all(&root).unwrap();
            let url = format!("sqlite://{}", root.join("state.db").display());
            let repo = Arc::new(SqliteRepository::connect(&url).await.unwrap());
            let p = Principal::local_owner("test");
            let now = "2026-11-07T00:00:00Z".parse().unwrap();
            repo.upsert_tenant(&TenantRecord {
                id: p.tenant_id.clone(),
                name: "Assets".into(),
                plan: "free".into(),
                created_at: now,
            })
            .await
            .unwrap();
            repo.insert_user(&UserRecord {
                id: p.user_id.clone(),
                tenant_id: p.tenant_id.clone(),
                email: "local@example.com".into(),
                display_name: "Owner".into(),
                password_hash: String::new(),
                role: memoswish_core::Role::Owner,
                created_at: now,
            })
            .await
            .unwrap();
            let store = Arc::new(FaultStore {
                disk: LocalDiskStore::new(root.join("objects"), "/assets"),
                lose_put,
                lose_delete,
                block_first: AtomicBool::new(block),
                reached: Notify::new(),
                resume: Semaphore::new(0),
                deletes: Mutex::new(Vec::new()),
            });
            let operations = OperationTracker::default();
            let uploads =
                AssetUploads::new(repo.clone(), store.clone(), operations.clone(), "test-store".into()).unwrap();
            Self { root, url, repo, p, store, operations, uploads }
        }
        async fn prepare(&self, budget: i64) -> AssetIntent {
            self.uploads.prepare(&self.p, "request", b"abc", "audio/wav", budget).await.unwrap()
        }
        async fn claim(&self) -> JobClaim {
            self.repo.claim_asset_job(&self.p.tenant_id, "worker", 30_000).await.unwrap().unwrap()
        }
        async fn close(&self) {
            self.operations.close();
            self.operations.wait().await;
            self.repo.pool().close().await;
        }
    }

    #[tokio::test]
    async fn lost_put_response_survives_restart_without_blind_delete_or_overwrite() {
        let f = Fixture::new(true, false, false).await;
        let intent = f.prepare(3).await;
        let job = f.claim().await;
        let error =
            f.uploads.upload(f.p.tenant_id.clone(), job.clone(), b"abc".to_vec()).unwrap().await.unwrap().unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SECRET_SENTINEL"));
        let attempt = f.repo.upload_attempts(&f.p.tenant_id, &intent.id).await.unwrap().remove(0);
        assert_eq!(attempt.outcome, UploadOutcome::Uncertain);
        assert_eq!(attempt.version, ObjectVersion::Unknown);
        assert!(f.store.exists(&attempt.key).await.unwrap());
        assert!(f.uploads.upload(f.p.tenant_id.clone(), job.clone(), b"abc".to_vec()).unwrap().await.unwrap().is_err());
        assert!(f.uploads.cleanup(f.p.tenant_id.clone(), job, attempt.id.clone()).unwrap().await.unwrap().is_err());
        assert!(f.store.deletes.lock().unwrap().is_empty());
        f.close().await;
        let reopened = SqliteRepository::connect(&f.url).await.unwrap();
        assert_eq!(reopened.upload_attempts(&f.p.tenant_id, &intent.id).await.unwrap()[0], attempt);
        assert!(reopened.asset_intent(&f.p.tenant_id, &intent.id).await.unwrap().unwrap().published_attempt.is_none());
        assert_eq!(reopened.unresolved_assets(None, 100).await.unwrap().len(), 1);
        reopened.pool().close().await;
        std::fs::remove_dir_all(f.root).unwrap();
    }

    #[tokio::test]
    async fn cancelled_blocked_put_keeps_attempt_identity_after_takeover_and_publication() {
        let f = Fixture::new(false, false, true).await;
        let intent = f.prepare(5).await;
        let old = f.claim().await;
        let waiter = f.uploads.upload(f.p.tenant_id.clone(), old.clone(), b"abc".to_vec()).unwrap();
        f.store.reached.notified().await;
        drop(waiter);
        let first = f.repo.upload_attempts(&f.p.tenant_id, &intent.id).await.unwrap().remove(0);
        sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2")
            .bind(&f.p.tenant_id)
            .bind(&intent.id)
            .execute(f.repo.pool())
            .await
            .unwrap();
        let fresh = f.claim().await;
        let second =
            f.uploads.upload(f.p.tenant_id.clone(), fresh.clone(), b"abc".to_vec()).unwrap().await.unwrap().unwrap();
        assert_ne!(first.key, second.key);
        let reference =
            AssetReference { asset_id: intent.asset_id.clone(), owner_id: "card".into(), slot: "audio".into() };
        f.repo.publish_asset(&f.p, &fresh, &second.id, &reference).await.unwrap();
        assert!(f.repo.publish_asset(&f.p, &old, &first.id, &reference).await.is_err());
        f.store.resume.add_permits(1);
        // 排空是旧 PUT 完成及回执提交的真实屏障，不能由延时采样代替。
        f.operations.close();
        f.operations.wait().await;
        let attempts = f.repo.upload_attempts(&f.p.tenant_id, &intent.id).await.unwrap();
        assert_eq!(attempts[0].outcome, UploadOutcome::Uploaded);
        assert_eq!(attempts[0].version, ObjectVersion::VersionId("null".into()));
        let cleanup_operations = OperationTracker::default();
        let cleanup =
            AssetUploads::new(f.repo.clone(), f.store.clone(), cleanup_operations.clone(), "test-store".into())
                .unwrap();
        let current = f.claim().await;
        cleanup.cleanup(f.p.tenant_id.clone(), current.clone(), first.id.clone()).unwrap().await.unwrap().unwrap();
        f.repo.finish_asset_job(&f.p.tenant_id, &current).await.unwrap();
        assert_eq!(*f.store.deletes.lock().unwrap(), vec![(first.key.clone(), Some("null".into()))]);
        assert!(f.store.exists(&second.key).await.unwrap());
        assert!(!f.store.exists(&first.key).await.unwrap());
        assert_eq!(f.repo.asset_reference_count(&f.p.tenant_id, &intent.asset_id).await.unwrap(), 1);
        cleanup_operations.close();
        cleanup_operations.wait().await;
        f.repo.pool().close().await;
        std::fs::remove_dir_all(f.root).unwrap();
    }

    #[tokio::test]
    async fn sql_receipt_loss_and_delete_response_loss_remain_durable() {
        let f = Fixture::new(false, true, false).await;
        let intent = f.prepare(1).await;
        let job = f.claim().await;
        sqlx::raw_sql("CREATE TRIGGER lose_receipt BEFORE UPDATE ON asset_upload_attempts WHEN NEW.outcome='uploaded' BEGIN SELECT RAISE(ABORT,'SECRET_SENTINEL'); END;").execute(f.repo.pool()).await.unwrap();
        let error =
            f.uploads.upload(f.p.tenant_id.clone(), job.clone(), b"abc".to_vec()).unwrap().await.unwrap().unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SECRET_SENTINEL"));
        let attempt = f.repo.upload_attempts(&f.p.tenant_id, &intent.id).await.unwrap().remove(0);
        assert_eq!(attempt.outcome, UploadOutcome::Uncertain);
        assert!(f.store.exists(&attempt.key).await.unwrap());
        sqlx::query("DROP TRIGGER lose_receipt").execute(f.repo.pool()).await.unwrap();
        // 精确版本只能由已知写入回执补充，不能由 GET/exists 推断。
        f.repo.record_upload(&f.p.tenant_id, &attempt, &ObjectVersion::VersionId("null".into())).await.unwrap();
        let error = f
            .uploads
            .cleanup(f.p.tenant_id.clone(), job.clone(), attempt.id.clone())
            .unwrap()
            .await
            .unwrap()
            .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SECRET_SENTINEL"));
        assert!(!f.store.exists(&attempt.key).await.unwrap());
        f.repo.retry_asset_job(&f.p.tenant_id, &job, 0).await.unwrap();
        f.close().await;
        let reopened = SqliteRepository::connect(&f.url).await.unwrap();
        assert_eq!(reopened.asset_job(&f.p.tenant_id, &intent.id).await.unwrap().unwrap().state, "dead");
        assert_eq!(
            reopened.upload_attempts(&f.p.tenant_id, &intent.id).await.unwrap()[0].outcome,
            UploadOutcome::CleanupPending
        );
        assert_eq!(reopened.unresolved_assets(None, 100).await.unwrap().len(), 1);
        reopened.pool().close().await;
        std::fs::remove_dir_all(f.root).unwrap();
    }

    #[tokio::test]
    async fn mismatched_bytes_namespace_and_closed_admission_do_not_write_or_delete() {
        let f = Fixture::new(false, false, false).await;
        let intent = f.prepare(3).await;
        let job = f.claim().await;
        assert!(
            f.uploads.upload(f.p.tenant_id.clone(), job.clone(), b"wrong".to_vec()).unwrap().await.unwrap().is_err()
        );
        assert!(f.repo.upload_attempts(&f.p.tenant_id, &intent.id).await.unwrap().is_empty());
        let attempt =
            f.uploads.upload(f.p.tenant_id.clone(), job.clone(), b"abc".to_vec()).unwrap().await.unwrap().unwrap();
        let other =
            AssetUploads::new(f.repo.clone(), f.store.clone(), f.operations.clone(), "other-store".into()).unwrap();
        assert!(other.cleanup(f.p.tenant_id.clone(), job.clone(), attempt.id.clone()).unwrap().await.unwrap().is_err());
        assert!(f.store.deletes.lock().unwrap().is_empty());
        f.operations.close();
        f.operations.wait().await;
        assert_eq!(
            f.repo.upload_attempts(&f.p.tenant_id, &intent.id).await.unwrap()[0].outcome,
            UploadOutcome::Uploaded
        );
        assert!(f.uploads.upload(f.p.tenant_id.clone(), job, b"abc".to_vec()).is_err());
        assert!(f.store.exists(&attempt.key).await.unwrap());
        f.repo.pool().close().await;
        std::fs::remove_dir_all(f.root).unwrap();
    }

    #[tokio::test]
    async fn local_unversioned_cleanup_preserves_adjacent_tenant_and_shared_objects() {
        let f = Fixture::new(false, false, false).await;
        let intent = f.prepare(3).await;
        let job = f.claim().await;
        let disk = Arc::new(f.store.disk.clone());
        disk.put("tenants/local-extra/keep", b"peer".to_vec(), "application/octet-stream").await.unwrap();
        disk.put("shared/keep", b"shared".to_vec(), "application/octet-stream").await.unwrap();
        let local = AssetUploads::new(f.repo.clone(), disk.clone(), f.operations.clone(), "test-store".into()).unwrap();
        let attempt =
            local.upload(f.p.tenant_id.clone(), job.clone(), b"abc".to_vec()).unwrap().await.unwrap().unwrap();
        assert_eq!(attempt.version, ObjectVersion::Unversioned);
        local.cleanup(f.p.tenant_id.clone(), job.clone(), attempt.id).unwrap().await.unwrap().unwrap();
        f.repo.finish_asset_job(&f.p.tenant_id, &job).await.unwrap();
        assert!(f.repo.asset_intent(&f.p.tenant_id, &intent.id).await.unwrap().unwrap().published_attempt.is_none());
        assert!(f.repo.unresolved_assets(None, 100).await.unwrap().is_empty());
        assert!(disk.exists("tenants/local-extra/keep").await.unwrap());
        assert!(disk.exists("shared/keep").await.unwrap());
        assert!(!disk.exists(&attempt.key).await.unwrap());
        f.close().await;
        std::fs::remove_dir_all(f.root).unwrap();
    }
}
