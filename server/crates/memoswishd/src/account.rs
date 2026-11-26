//! 账户导出与可恢复擦除；租户级资产没有成员所有权，成员退出保留共享资料。
use crate::app::AppState;
use memoswish_core::{
    CoreError, CoreResult, Permission, Principal, Role,
    identity::ErasureJob,
    repo::Repository,
    store::{ObjectStore, StoredObject},
};
use memoswish_protocol::AssetRef;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

/// 只更新已知资产位置的 URL，保留导出原始 JSON 中的其他字段。
fn render_export_asset(value: Option<&mut serde_json::Value>, surface: &str, owner: &str) -> CoreResult<()> {
    if let Some(value) = value.filter(|v| !v.is_null()) {
        let mut asset: AssetRef = serde_json::from_value(value.clone()).map_err(CoreError::internal)?;
        memoswish_application::asset_delivery::render_asset(&mut asset, surface, owner);
        value["url"] = asset.url.into();
    }
    Ok(())
}

fn render_export_rows(data: &mut serde_json::Value) -> CoreResult<()> {
    if let Some(rows) = data["cards"].as_array_mut() {
        for body in rows {
            let owner = body["id"].as_str().unwrap_or_default().to_owned();
            for face in ["front", "back"] {
                if let Some(blocks) = body[face]["blocks"].as_array_mut() {
                    for block in blocks {
                        if block["type"] == "image" {
                            render_export_asset(block.get_mut("asset"), "content", &owner)?;
                        }
                    }
                }
            }
            for path in ["/visual/image", "/tts/audio", "/bgm/track/asset"] {
                render_export_asset(body.pointer_mut(path), "content", &owner)?;
            }
        }
    }
    if let Some(rows) = data["bgm_tracks"].as_array_mut() {
        for body in rows {
            let owner = body["id"].as_str().unwrap_or_default().to_owned();
            render_export_asset(body.get_mut("asset"), "media", &owner)?;
        }
    }
    Ok(())
}

pub async fn export(st: &AppState, p: &Principal) -> CoreResult<serde_json::Value> {
    if p.via == "mcp_oauth" {
        return Err(CoreError::Forbidden("MCP credentials cannot export accounts".into()));
    }
    let full = p.can(Permission::AccountExport);
    if !full {
        p.require(Permission::FeedRead)?;
        p.require(Permission::ContentRead)?;
    }
    // 显式完整导出权限涵盖可读账户材料；旧 scope 仅获得原有摘要。
    let mut reader = p.clone();
    if full {
        reader.scopes = None;
    }
    let p = &reader;
    let owner = p.role == Role::Owner;
    let mut data =
        if full { st.repo.account_export(&p.tenant_id, &p.user_id, owner).await? } else { serde_json::json!({}) };
    if full {
        render_export_rows(&mut data)?;
    }
    if full {
        data["tenant"] = serde_json::to_value(st.repo.get_tenant(&p.tenant_id).await?).map_err(CoreError::internal)?;
    }
    data["tenant_id"] = serde_json::json!(p.tenant_id);
    data["user"] = serde_json::to_value(st.services.auth.profile(p).await?).map_err(CoreError::internal)?;
    data["stats"] =
        serde_json::to_value(st.services.feed.stats_for_deck(p, None).await?).map_err(CoreError::internal)?;
    data["usage"] = serde_json::to_value(st.services.quota.snapshot(p).await?).map_err(CoreError::internal)?;
    let mut packs = Vec::new();
    for deck in st.services.content.list_decks(p).await? {
        packs.push(st.services.export_deck(p, &deck.id).await?);
    }
    data["decks"] = serde_json::json!(packs);
    data["exported_at"] = serde_json::json!(chrono::Utc::now());
    if !full {
        return Ok(data);
    }
    data["scope"] = serde_json::json!(if owner { "tenant" } else { "member" });
    let mut assets = Vec::new();
    // 共享内容对所有成员可读，因此成员导出也包含租户资产，但不包含其他成员的账户/学习数据。
    let prefix = p.asset_prefix();
    for key in st.store.list_prefix(&prefix).await? {
        if !key.starts_with(&prefix) {
            return Err(CoreError::internal("object listing escaped workspace"));
        }
        if let Some(object) = st.store.get(&key).await? {
            assets.push(
                serde_json::json!({"key":key,"mime":object.mime,"encoding":"hex","data":hex::encode(object.bytes)}),
            );
        }
    }
    data["assets"] = serde_json::json!(assets);
    Ok(data)
}
/// 调用方等待预算不代表外部 PUT 已经结束。
pub const PUT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
// 调度只使用 background_jobs 的一个 claim 租约；心跳间隔由其推导。
const ERASURE_LEASE_MS: i64 = 300_000;

pub async fn finish(st: &AppState, j: &ErasureJob) -> CoreResult<()> {
    let work = st.clone();
    let job = j.clone();
    st.services
        .operations
        .spawn(async move { finish_owned(&work, &job).await })?
        .await
        .map_err(|_| CoreError::internal("erasure task failed"))?
}

async fn finish_owned(st: &AppState, j: &ErasureJob) -> CoreResult<()> {
    use memoswish_core::observability::{Observer, Operation, Outcome};
    let mut observation = st.metrics.start(Operation::Erasure);
    let result: CoreResult<_> = async {
        if !st.config.role.maintains() {
            return Err(CoreError::Unavailable("erasure pending maintenance".into()));
        }
        let work = st.repo.erasure_work(&j.id).await?.ok_or_else(|| CoreError::NotFound("erasure operation".into()))?;
        if work.progress == "complete" {
            return Ok(());
        }
        let claim = st
            .repo
            .claim_erasure(&j.id, "erasure-worker", ERASURE_LEASE_MS)
            .await?
            .ok_or_else(|| CoreError::Conflict("erasure work is claimed or blocked".into()))?;
        let operation = async {
            // 领取后重读，避免使用另一 worker 已释放密文之前的观察值。
            let work =
                st.repo.erasure_work(&j.id).await?.ok_or_else(|| CoreError::NotFound("erasure operation".into()))?;
            let mut failure = None;
            if work.job.purge_assets
                && let Err(e) =
                    memoswish_application::erasure::clean_assets(st.repo.as_ref(), st.store.as_ref(), &claim).await
            {
                failure = Some(e);
            }
            for (ordinal, (provider, encrypted)) in work.job.credentials.iter().enumerate() {
                if encrypted.is_empty() {
                    continue;
                }
                let revoke: CoreResult<()> = async {
                    #[cfg(feature = "oidc")]
                    st.oidc
                        .as_ref()
                        .ok_or_else(|| {
                            CoreError::internal("OIDC must remain configured until revocation jobs complete")
                        })?
                        .revoke(provider, encrypted)
                        .await?;
                    #[cfg(not(feature = "oidc"))]
                    return Err(CoreError::internal("upstream revocation requires oidc"));
                    #[cfg(feature = "oidc")]
                    st.repo.acknowledge_revocation(&claim, ordinal, provider, encrypted).await
                }
                .await;
                #[cfg(not(feature = "oidc"))]
                let _ = (ordinal, provider);
                if let Err(e) = revoke {
                    failure = Some(e);
                }
            }
            if let Some(e) = failure {
                return Err(e);
            }
            Ok(())
        };
        let result =
            under_erasure_lease(operation, maintain_erasure_lease(st, &claim), st.repo.complete_erasure(&claim)).await;
        if result.is_err() {
            // 失败只释放当前调度权；证据和耗尽责任保持可发现。
            let _ = st.repo.retry_erasure(&claim).await;
        }
        result
    }
    .await;
    observation.finish(if result.is_ok() { Outcome::Returned } else { Outcome::Error });
    result
}
#[cfg(test)]
pub async fn cleanup(st: &AppState) -> CoreResult<()> {
    crate::maintenance_scheduler::due_for_test(&st.config).await?;
    crate::maintenance_scheduler::startup_pass(st).await
}

#[derive(Default)]
struct PutState {
    closed: bool,
    active: usize,
}

/// 所有受保护存储共享准入和任务计数；关闭后拒绝新任务并等待补偿收尾。
pub struct PutTasks {
    observer: Arc<dyn memoswish_core::observability::Observer>,
    permits: Arc<Semaphore>,
    state: Mutex<PutState>,
    finished: Notify,
    admission_timeout: Duration,
    shutdown_timeout: Duration,
}

impl PutTasks {
    pub fn new(config: &crate::config::ObjectStoreConfig) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            (1..=Semaphore::MAX_PERMITS).contains(&config.max_concurrent_puts),
            "object_store.max_concurrent_puts must be between 1 and {}",
            Semaphore::MAX_PERMITS
        );
        Ok(Arc::new(Self {
            observer: memoswish_core::observability::noop(),
            permits: Arc::new(Semaphore::new(config.max_concurrent_puts)),
            state: Mutex::new(PutState::default()),
            finished: Notify::new(),
            admission_timeout: Duration::from_millis(config.put_admission_timeout_ms),
            shutdown_timeout: Duration::from_secs(config.put_shutdown_timeout_secs),
        }))
    }

    pub(crate) fn with_observer(
        mut self: Arc<Self>,
        observer: Arc<dyn memoswish_core::observability::Observer>,
    ) -> Arc<Self> {
        observer.capacity(memoswish_core::observability::AdmissionClass::Put, 0, self.permits.available_permits());
        Arc::get_mut(&mut self).expect("PUT observer is attached before sharing").observer = observer;
        self
    }

    async fn admit(self: &Arc<Self>) -> CoreResult<ActivePut> {
        use memoswish_core::observability::{AdmissionAttempt, AdmissionClass, AdmissionOutcome, Slot};
        let mut attempt = AdmissionAttempt::new(self.observer.clone(), AdmissionClass::Put);
        let permit = tokio::time::timeout(self.admission_timeout, self.permits.clone().acquire_owned())
            .await
            .map_err(|_| {
                attempt.finish(AdmissionOutcome::Rejected);
                CoreError::Unavailable("object PUT capacity reached; retry later".into())
            })?
            .map_err(|_| {
                attempt.finish(AdmissionOutcome::Unavailable);
                CoreError::Unavailable("object PUT admission is closed; retry later".into())
            })?;
        let mut state = self.state.lock().unwrap();
        if state.closed {
            attempt.finish(AdmissionOutcome::Unavailable);
            return Err(CoreError::Unavailable("object PUT admission is closed; retry later".into()));
        }
        state.active += 1;
        attempt.finish(AdmissionOutcome::Accepted);
        Ok(ActivePut {
            tasks: self.clone(),
            _permit: permit,
            _slot: Slot::new(self.observer.clone(), AdmissionClass::Put),
        })
    }

    pub fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        self.permits.close();
    }

    pub async fn shutdown(&self) -> bool {
        self.close();
        let drained = tokio::time::timeout(self.shutdown_timeout, self.wait()).await.is_ok();
        if !drained {
            tracing::warn!(target: "memoswish::account",
                active = self.state.lock().unwrap().active,
                "Object PUT shutdown drain timed out; durable erasure jobs and tenant tombstones will be swept on startup"
            );
        }
        drained
    }

    // 调用方先关闭准入；生产关闭仍由 shutdown 限时，测试收尾等待真实所有者释放。
    pub(crate) async fn wait(&self) {
        loop {
            let finished = self.finished.notified();
            tokio::pin!(finished);
            // 注册后再读计数，避免最后一个任务恰好完成导致丢失通知。
            finished.as_mut().enable();
            if self.state.lock().unwrap().active == 0 {
                break;
            }
            finished.await;
        }
    }
}

struct ActivePut {
    tasks: Arc<PutTasks>,
    _permit: OwnedSemaphorePermit,
    _slot: memoswish_core::observability::Slot,
}

impl Drop for ActivePut {
    fn drop(&mut self) {
        self.tasks.state.lock().unwrap().active -= 1;
        self.tasks.finished.notify_waiters();
    }
}

/// 后台拥有完整 PUT 与前后墓碑检查；晚到写入按回执补偿。
#[derive(Clone)]
pub struct TenantStore {
    pub inner: Arc<dyn ObjectStore>,
    pub repo: Arc<dyn Repository>,
    pub tasks: Arc<PutTasks>,
}
impl TenantStore {
    async fn denied(&self, key: &str) -> CoreResult<bool> {
        if let Some(rest) = key.strip_prefix("tenants/")
            && let Some((tenant, _)) = rest.split_once('/')
        {
            return Ok(self.repo.account_erased_tenant(tenant).await? || self.repo.get_tenant(tenant).await?.is_none());
        }
        if key.starts_with("tenants/") {
            return Err(CoreError::invalid("invalid tenant key"));
        }
        Ok(false)
    }
}
#[async_trait::async_trait]
impl ObjectStore for TenantStore {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn namespace(&self) -> CoreResult<String> {
        self.inner.namespace()
    }
    async fn open_delivery(
        &self,
        key: &str,
        version: &memoswish_core::assets::ObjectVersion,
        size: u64,
    ) -> CoreResult<Option<Box<dyn memoswish_core::asset_read::ObjectReader>>> {
        if self.denied(key).await? {
            return Ok(None);
        }
        self.inner.open_delivery(key, version, size).await
    }
    async fn open_legacy(
        &self,
        key: &str,
        size: u64,
    ) -> CoreResult<Option<Box<dyn memoswish_core::asset_read::ObjectReader>>> {
        if self.denied(key).await? {
            return Ok(None);
        }
        self.inner.open_legacy(key, size).await
    }
    async fn read_delivery(
        &self,
        key: &str,
        version: &memoswish_core::assets::ObjectVersion,
        limit: u64,
    ) -> CoreResult<Option<StoredObject>> {
        if self.denied(key).await? {
            return Ok(None);
        }
        self.inner.read_delivery(key, version, limit).await
    }
    async fn read_legacy(&self, key: &str, limit: u64) -> CoreResult<Option<StoredObject>> {
        if self.denied(key).await? {
            return Ok(None);
        }
        self.inner.read_legacy(key, limit).await
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        Ok(self.put_versioned(key, bytes, mime).await?.asset)
    }
    async fn put_if_absent(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<bool> {
        memoswish_core::store::validate_key(key)?;
        if !key.starts_with("shared/") {
            return Err(CoreError::Forbidden("conditional creation is reserved for shared bootstrap".into()));
        }
        let active = self.tasks.admit().await?;
        let inner = self.inner.clone();
        let key = key.to_owned();
        let mime = mime.to_owned();
        let task = tokio::spawn(async move {
            let _active = active;
            inner.put_if_absent(&key, bytes, &mime).await
        });
        tokio::time::timeout(PUT_TIMEOUT, task)
            .await
            .map_err(|_| CoreError::Unavailable("shared conditional PUT remains uncertain".into()))?
            .map_err(|_| CoreError::Unavailable("shared conditional PUT task interrupted".into()))?
    }
    async fn delete_write(&self, key: &str, version: Option<&str>) -> CoreResult<()> {
        use memoswish_core::observability::{Operation, Outcome};
        let mut operation = self.tasks.observer.start(Operation::ObjectDelete);
        let result = self.inner.delete_write(key, version).await;
        operation.finish(if result.is_ok() { Outcome::Returned } else { Outcome::Error });
        result
    }
    async fn put_versioned(
        &self,
        key: &str,
        bytes: Vec<u8>,
        mime: &str,
    ) -> CoreResult<memoswish_core::store::ObjectWrite> {
        memoswish_core::store::validate_key(key)?;
        // 必须先取得空位再创建任务；调用方超时或取消不能提前归还空位。
        let active = self.tasks.admit().await?;
        let guard = self.clone();
        let key = key.to_string();
        let mime = mime.to_string();
        // 超时只丢弃 JoinHandle，不能丢弃在途 PUT 的 future。
        // 包括排空窗口后才完成的阻塞磁盘操作，都必须执行后置检查与补偿。
        let task = tokio::spawn(async move {
            let _active = active;
            if guard.denied(&key).await? {
                return Err(CoreError::Forbidden("tenant erased".into()));
            }
            // 所有租户写入均先登记，包括仍使用旧接口的 APKG、BGM 和缓存元数据。
            let mut evidence = if let Some(rest) = key.strip_prefix("tenants/") {
                let (tenant, _) = rest.split_once('/').ok_or_else(|| CoreError::invalid("invalid tenant key"))?;
                Some(guard.repo.register_managed_put(tenant, &guard.inner.namespace()?, &key).await?)
            } else {
                None
            };
            let write = guard.inner.put_versioned(&key, bytes, &mime).await?;
            if write.asset.key != key {
                return Err(CoreError::Unavailable("object PUT receipt identity mismatch".into()));
            }
            let version = write
                .version
                .as_ref()
                .map(|v| memoswish_core::assets::ObjectVersion::VersionId(v.clone()))
                .unwrap_or(memoswish_core::assets::ObjectVersion::Unversioned);
            if let Some(object) = evidence.as_mut() {
                guard.repo.record_managed_put(object, &version).await?;
                object.version = version;
            }
            match guard.denied(&key).await {
                Ok(false) => Ok(write),
                denied => {
                    if let Some(object) = &evidence {
                        // 查询失败时保留已知回执；不能凭未知状态授予删除权。
                        guard.repo.prepare_managed_compensation(object).await?;
                    }
                    guard.delete_write(&key, write.version.as_deref()).await?;
                    if let Some(object) = &evidence {
                        guard.repo.record_erasure_object(object).await?;
                    }
                    match denied {
                        Err(e) => Err(e),
                        _ => Err(CoreError::Forbidden("tenant erased during object PUT".into())),
                    }
                }
            }
        });
        tokio::time::timeout(PUT_TIMEOUT, task)
            .await
            .map_err(|_| CoreError::internal("object PUT timed out; background write retains cleanup ownership"))?
            .map_err(|_| CoreError::internal("tenant object write task failed"))?
    }

    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        if self.denied(key).await? {
            return Ok(None);
        }
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> CoreResult<bool> {
        if self.denied(key).await? {
            return Ok(false);
        }
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> CoreResult<()> {
        self.inner.delete(key).await
    }
    async fn list_prefix(&self, prefix: &str) -> CoreResult<Vec<String>> {
        self.inner.list_prefix(prefix).await
    }
    async fn purge_prefix(&self, prefix: &str) -> CoreResult<()> {
        self.inner.purge_prefix(prefix).await
    }
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
}

/// SQL 已提交并释放所有锁，再读取对象；返回前由适配器复核原始凭据。
pub async fn complete_workspace_export(
    st: &AppState,
    p: &Principal,
    data: &mut memoswish_protocol::WorkspaceExport,
) -> CoreResult<()> {
    let mut rows = serde_json::to_value(&data.data).map_err(CoreError::internal)?;
    render_export_rows(&mut rows)?;
    data.data = serde_json::from_value(rows).map_err(CoreError::internal)?;
    let prefix = p.asset_prefix();
    for key in st.store.list_prefix(&prefix).await? {
        if !key.starts_with(&prefix) {
            return Err(CoreError::internal("object listing escaped workspace"));
        }
        if let Some(object) = st.store.get(&key).await? {
            data.assets.push(memoswish_protocol::ExportAsset {
                key,
                mime: object.mime,
                encoding: "hex".into(),
                data: hex::encode(object.bytes),
            });
        }
    }
    Ok(())
}

async fn maintain_erasure_lease(st: &AppState, claim: &memoswish_core::jobs::JobClaim) -> CoreResult<()> {
    let mut interval = tokio::time::interval(Duration::from_millis((ERASURE_LEASE_MS / 3) as u64));
    loop {
        interval.tick().await;
        st.repo.heartbeat_erasure(claim, ERASURE_LEASE_MS).await?;
    }
    #[allow(unreachable_code)]
    Ok::<(), CoreError>(())
}

async fn under_erasure_lease(
    operation: impl Future<Output = CoreResult<()>>,
    heartbeat: impl Future<Output = CoreResult<()>>,
    complete: impl Future<Output = CoreResult<()>>,
) -> CoreResult<()> {
    // 并发轮询避免单连接互等；先丢弃心跳，再由完成事务复核 claim 与外部证据。
    tokio::select! { biased; result=operation=>result, result=heartbeat=>result }?;
    complete.await
}

#[cfg(all(test, feature = "sqlite"))]
mod completion_tests {
    use super::*;

    // 原完成测试与回归共用读库边界；恢复回调允许回归观察真实的调用顺序。
    async fn resume_before_completion_read<T>(resume: impl FnOnce(), read: impl Future<Output = T>) -> T {
        resume();
        read.await
    }

    #[tokio::test]
    async fn erasure_completion_stops_heartbeat_and_preserves_expiry_fence() {
        let dir = std::env::temp_dir().join(format!("hf9-erasure-{}", memoswish_core::ids::new_id()));
        let st = AppState::assemble(crate::Config { data_dir: dir.clone(), seed_demo: false, ..Default::default() })
            .await
            .unwrap();
        let repo = memoswish_storage::sqlite::SqliteRepository::open_runtime(&st.config.database_url()).await.unwrap();
        for expired in [false, true] {
            let id = memoswish_core::ids::new_id();
            let body = serde_json::json!({"id":id,"tenant_id":null,"purge_assets":false,"credentials":[]});
            sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
                .bind(&id)
                .bind(body.to_string())
                .execute(repo.pool())
                .await
                .unwrap();
            let claim = st.repo.claim_erasure(&id, "completion-test", ERASURE_LEASE_MS).await.unwrap().unwrap();
            if expired {
                let result = under_erasure_lease(
                    async {
                        sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE id=$1 AND kind='erasure'")
                            .bind(&id)
                            .execute(repo.pool())
                            .await
                            .unwrap();
                        Ok(())
                    },
                    maintain_erasure_lease(&st, &claim),
                    st.repo.complete_erasure(&claim),
                )
                .await;
                assert!(matches!(result, Err(CoreError::Conflict(_))));
                assert_eq!(st.repo.erasure_work(&id).await.unwrap().unwrap().progress, "reconciling");
                continue;
            }
            let (heartbeat_owner, mut heartbeat_dropped) = tokio::sync::oneshot::channel::<()>();
            let (committed, observed) = tokio::sync::oneshot::channel();
            let (release, held) = tokio::sync::oneshot::channel();
            let owned = st.clone();
            let claim2 = claim.clone();
            let mut task = tokio::spawn(async move {
                under_erasure_lease(
                    async {
                        tokio::task::yield_now().await;
                        Ok(())
                    },
                    async {
                        let _heartbeat_owner = heartbeat_owner;
                        maintain_erasure_lease(&owned, &claim2).await
                    },
                    async {
                        assert!(
                            matches!(
                                heartbeat_dropped.try_recv(),
                                Err(tokio::sync::oneshot::error::TryRecvError::Closed)
                            ),
                            "heartbeat must be dropped before completion starts"
                        );
                        owned.repo.complete_erasure(&claim2).await?;
                        committed.send(()).unwrap();
                        held.await.unwrap();
                        Ok(())
                    },
                )
                .await
            });
            tokio::select! {biased; result=&mut task=>panic!("completion failed before barrier: {result:?}"), result=observed=>result.unwrap()}
            assert!(matches!(st.repo.heartbeat_erasure(&claim, ERASURE_LEASE_MS).await, Err(CoreError::Conflict(_))));
            tokio::time::pause();
            tokio::time::advance(Duration::from_millis(ERASURE_LEASE_MS as u64)).await;
            tokio::select! { biased; result=&mut task=>panic!("completion was cancelled: {result:?}"), _=tokio::task::yield_now()=>{} }
            release.send(()).unwrap();
            task.await.unwrap().unwrap();
            // 虚拟租约检查已结束；真实 SQLite worker 不受 Tokio 时钟驱动。
            let work = resume_before_completion_read(tokio::time::resume, st.repo.erasure_work(&id)).await;
            assert_eq!(work.unwrap().unwrap().progress, "complete");
        }
        repo.pool().close().await;
        crate::runtime::cleanup_test_app(dir, &[&st]).await;
    }

    #[tokio::test]
    async fn hf14_completion_read_resumes_before_io_and_preserves_pool_error_class() {
        use memoswish_core::{erasure::ErasureRepo, observability::*};
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Recording(Arc<Mutex<Vec<(Operation, Outcome)>>>);
        struct Guard(Recording, Option<Operation>);
        impl Observer for Recording {
            fn start(&self, operation: Operation) -> Box<dyn ObservationGuard> {
                Box::new(Guard(self.clone(), Some(operation)))
            }
        }
        impl ObservationGuard for Guard {
            fn finish(&mut self, outcome: Outcome) {
                if let Some(operation) = self.1.take() {
                    self.0.0.lock().unwrap().push((operation, outcome));
                }
            }
        }

        let dir = std::env::temp_dir().join(format!("hf14-erasure-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&dir).unwrap();
        let recording = Recording::default();
        let repo = memoswish_storage::sqlite::SqliteRepository::connect_with_max_connections(
            &format!("sqlite://{}/test.db?mode=rwc", dir.display()),
            1,
        )
        .await
        .unwrap()
        .with_observer(Arc::new(recording.clone()));
        // 占住唯一连接，确定性模拟等待独立 worker；不改变默认 acquire 预算。
        let mut connection = repo.pool().acquire().await.unwrap();
        tokio::time::pause();
        let start = tokio::time::Instant::now();
        assert!(matches!(repo.pool().acquire().await, Err(sqlx::Error::PoolTimedOut)));
        assert!(start.elapsed() >= repo.pool().options().get_acquire_timeout());
        let error = repo.erasure_work("missing").await.err().unwrap();
        assert_eq!(error.to_string(), "asset persistence operation failed");
        assert!(recording.0.lock().unwrap().contains(&(Operation::DbWrite, Outcome::PoolTimeout)));
        let resumed = std::cell::Cell::new(false);
        // 在共用读取边界首次轮询时检查恢复记录，不依赖 SQLite worker 的调度概率。
        let work = resume_before_completion_read(
            || {
                tokio::time::resume();
                resumed.set(true);
            },
            async {
                assert!(resumed.get(), "completion read must resume time before database I/O");
                connection.return_to_pool().await;
                repo.erasure_work("missing").await
            },
        )
        .await;
        assert!(work.unwrap().is_none());
        assert!(recording.0.lock().unwrap().contains(&(Operation::DbWrite, Outcome::Returned)));
        repo.pool().close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }
}
