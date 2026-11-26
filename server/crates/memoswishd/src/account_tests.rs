//! 默认与商业构建都必须执行账户生命周期测试。
use crate::{app::AppState, config::Config};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use memoswish_core::{
    CoreResult, Role,
    ids::new_id,
    repo::UserRecord,
    store::{ObjectStore, StoredObject},
};
use memoswish_protocol::{AssetRef, DeploymentMode, RegisterRequest};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tower::ServiceExt;

async fn fixture() -> (AppState, std::path::PathBuf, String) {
    fixture_with_database(None).await
}

async fn fixture_with_database(database_url: Option<String>) -> (AppState, std::path::PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("memoswish-account-{}", new_id()));
    // PG 夹具保留并发复核所需的双连接，多个实例不沿用生产默认池上限。
    let db_max_connections = if database_url.is_some() { Some(2) } else { Config::default().db_max_connections };
    let st = AppState::build(Config {
        data_dir: dir.clone(),
        mode: DeploymentMode::MultiTenant,
        registration_open: true,
        seed_demo: false,
        db_max_connections,
        database_url,
        ..Default::default()
    })
    .await
    .unwrap();
    let auth = st
        .services
        .auth
        .register(&RegisterRequest {
            email: "owner@example.com".into(),
            password: "password123".into(),
            display_name: "Owner".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    (st, dir, auth.access_token)
}
async fn request(st: &AppState, method: &str, path: &str, jwt: &str) -> (StatusCode, serde_json::Value) {
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let data = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&data).unwrap_or_default())
}

#[tokio::test]
async fn account_member_erasure_preserves_tenant_and_other_members() {
    let (st, dir, jwt) = fixture().await;
    let owner = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let member = UserRecord {
        id: new_id(),
        tenant_id: owner.tenant_id.clone(),
        email: "member@example.com".into(),
        display_name: "Member".into(),
        password_hash: "not-exportable".into(),
        role: Role::Learner,
        created_at: chrono::Utc::now(),
    };
    st.repo.insert_user(&member).await.unwrap();
    let member_auth = st.services.auth.interactive_response(&member).await.unwrap();
    let member_p = st.services.auth.authenticate(Some(&member_auth.access_token)).await.unwrap();
    let member_token = st
        .services
        .auth
        .create_api_token(&member_p, "member-token", vec!["content:read".into()], None)
        .await
        .unwrap_err();
    assert!(matches!(member_token, memoswish_core::CoreError::Forbidden(_)));
    let token = st.services.auth.create_api_token(&owner, "agent", vec!["*".into()], None).await.unwrap();
    for method in ["GET", "DELETE"] {
        let path = if method == "GET" { "/v1/account/export" } else { "/v1/account" };
        assert_eq!(
            request(&st, method, path, &token.plaintext).await.0,
            if method == "GET" { StatusCode::OK } else { StatusCode::FORBIDDEN }
        );
    }
    let key = format!("tenants/{}/imports/test.png", owner.tenant_id);
    st.store.put(&key, b"personal shared material".to_vec(), "image/png").await.unwrap();
    let (s, data) = request(&st, "GET", "/v1/account/export", &member_auth.access_token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(data["scope"], "member");
    assert_eq!(data["users"].as_array().unwrap().len(), 1);
    assert_eq!(data["users"][0]["id"], member.id);
    assert_eq!(data["assets"][0]["data"], hex::encode(b"personal shared material"));
    assert!(!data.to_string().contains("not-exportable"));
    assert_erasure_response(&st, request(&st, "DELETE", "/v1/account", &member_auth.access_token).await.0).await;
    assert_eq!(request(&st, "GET", "/v1/me", &member_auth.access_token).await.0, StatusCode::UNAUTHORIZED);
    assert!(st.store.exists(&key).await.unwrap());
    assert!(st.repo.get_user(&owner.tenant_id, &owner.user_id).await.unwrap().is_some());
    assert_erasure_response(&st, request(&st, "DELETE", "/v1/account", &jwt).await.0).await;
    assert!(!dir.join("assets").join(&key).exists());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

struct FailListing {
    inner: Arc<dyn ObjectStore>,
    fail: AtomicBool,
}

#[tokio::test]
async fn account_erasure_accepted_response_finishes_same_durable_operation() {
    let (mut st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let key = format!("tenants/{}/tts/audio.wav", p.tenant_id);
    st.store.put(&key, b"RIFF".to_vec(), "audio/wav").await.unwrap();
    let store = Arc::new(FailListing { inner: st.store.clone(), fail: AtomicBool::new(true) });
    st.store = store.clone();
    let status = request(&st, "DELETE", "/v1/account", &jwt).await.0;
    assert_eq!(status, StatusCode::ACCEPTED);
    let pending = st.repo.account_erasure_jobs().await.unwrap();
    assert_eq!(pending.len(), 1);
    let job = &pending[0];
    let before = st.repo.erasure_work(&job.id).await.unwrap().unwrap();
    assert_ne!(before.progress, "complete");
    crate::metrics::sample(&st).await;
    let metrics =
        String::from_utf8(st.metrics.response(false).into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(metrics.contains("operation=\"erasure\",outcome=\"error\""));
    assert!(metrics.contains("memoswish_pending_work{kind=\"erasure\"} 1"));
    assert!(!metrics.contains("memoswish_cleanup_lag_seconds{kind=\"erasure\"} NaN"));
    assert!(dir.join("assets").join(&key).exists());
    store.fail.store(false, Ordering::SeqCst);
    assert_erasure_response(&st, status).await;
    let after = st.repo.erasure_work(&job.id).await.unwrap().unwrap();
    assert_eq!((after.progress.as_str(), after.state.as_str()), ("complete", "succeeded"));
    assert_eq!(after.total_attempts, before.total_attempts + 1, "controlled worker must execute once");
    crate::metrics::sample(&st).await;
    let metrics =
        String::from_utf8(st.metrics.response(false).into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(metrics.contains("memoswish_pending_work{kind=\"erasure\"} 0"));
    assert!(metrics.contains("memoswish_cleanup_lag_seconds{kind=\"erasure\"} NaN"));
    assert!(!dir.join("assets").join(&key).exists());
    assert!(st.repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().is_none());
    assert!(st.services.auth.authenticate(Some(&jwt)).await.is_err());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}
#[async_trait::async_trait]
impl ObjectStore for FailListing {
    fn namespace(&self) -> CoreResult<String> {
        self.inner.namespace()
    }
    fn kind(&self) -> &'static str {
        "test"
    }
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        self.inner.put(key, bytes, mime).await
    }
    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> CoreResult<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> CoreResult<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(memoswish_core::CoreError::internal("injected object-store failure"));
        }
        self.inner.delete(key).await
    }
    async fn list_prefix(&self, prefix: &str) -> CoreResult<Vec<String>> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(memoswish_core::CoreError::internal("injected object-store failure"));
        }
        self.inner.list_prefix(prefix).await
    }
}
#[tokio::test]
async fn account_erasure_survives_object_store_failure_and_restart() {
    let (mut st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let key = format!("tenants/{}/tts/audio.wav", p.tenant_id);
    st.store.put(&key, b"RIFF".to_vec(), "audio/wav").await.unwrap();
    st.store = Arc::new(FailListing { inner: st.store.clone(), fail: AtomicBool::new(true) });
    assert_eq!(request(&st, "DELETE", "/v1/account", &jwt).await.0, StatusCode::ACCEPTED);
    assert!(st.repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().is_none());
    assert!(dir.join("assets").join(&key).exists());
    let job = st.repo.account_erasure_jobs().await.unwrap().remove(0);
    erasure_retry_due_for_test(&st, &job).await;
    crate::maintenance_scheduler::due_for_test(&st.config).await.unwrap();
    let reopened = AppState::build(st.config.as_ref().clone()).await.unwrap();
    assert_eq!(reopened.repo.erasure_work(&job.id).await.unwrap().unwrap().progress, "complete");
    complete_pending(&reopened).await;
    assert!(reopened.repo.account_erasure_jobs().await.unwrap().is_empty());
    assert!(!dir.join("assets").join(&key).exists());
    assert!(reopened.services.auth.authenticate(Some(&jwt)).await.is_err());
    crate::runtime::cleanup_test_app(dir, &[&st, &reopened]).await;
}

#[tokio::test]
async fn oidc_is_absent_by_default_and_requires_multi_tenant_and_oidc_build() {
    let (st, dir, jwt) = fixture().await;
    assert!(st.server_info().oidc_providers.is_empty());
    let status = request(&st, "POST", "/v1/auth/oidc/google/start", &jwt).await.0;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let mut config = st.config.as_ref().clone();
    config.oidc.enabled = true;
    config.mode = DeploymentMode::SingleUser;
    assert!(AppState::build(config).await.is_err());
    #[cfg(not(feature = "oidc"))]
    {
        let mut config = st.config.as_ref().clone();
        config.oidc.enabled = true;
        assert!(AppState::build(config).await.is_err());
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn account_tombstone_cleanup_removes_late_objects_after_success() {
    let (st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    assert_erasure_response(&st, request(&st, "DELETE", "/v1/account", &jwt).await.0).await;
    assert!(st.repo.account_erasure_jobs().await.unwrap().is_empty());
    let raw = memoswish_storage::LocalDiskStore::new(dir.join("assets"), "/assets");
    let key = format!("tenants/{}/tts/late.wav", p.tenant_id);
    // 模拟进程中断前已发往对象存储、删除后才落盘的 PUT。
    raw.put(&key, b"late".to_vec(), "audio/wav").await.unwrap();
    assert!(raw.exists(&key).await.unwrap());
    assert!(!st.store.exists(&key).await.unwrap());
    crate::account::cleanup(&st).await.unwrap();
    assert!(!raw.exists(&key).await.unwrap());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn account_export_preserves_legacy_scopes_and_requires_explicit_full_scope() {
    let (st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    for (scopes, status, full) in [
        (vec!["content:read"], StatusCode::FORBIDDEN, false),
        (vec!["feed:read", "content:read"], StatusCode::OK, false),
        (vec!["account:export"], StatusCode::OK, true),
        (vec!["*"], StatusCode::OK, true),
    ] {
        let t = st
            .services
            .auth
            .create_api_token(&p, "export", scopes.into_iter().map(str::to_string).collect(), None)
            .await
            .unwrap();
        let (s, data) = request(&st, "GET", "/v1/account/export", &t.plaintext).await;
        assert_eq!(s, status, "{data}");
        if s == StatusCode::OK {
            for key in ["tenant_id", "user", "stats", "decks", "usage", "exported_at"] {
                assert!(data.get(key).is_some(), "missing {key}");
            }
            assert_eq!(data.get("users").is_some(), full);
            assert_eq!(data.get("assets").is_some(), full);
            assert_eq!(data.get("api_tokens").is_some(), full);
        }
        assert_eq!(request(&st, "DELETE", "/v1/account", &t.plaintext).await.0, StatusCode::FORBIDDEN);
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[cfg(feature = "s3")]
#[tokio::test]
async fn daemon_builds_s3_from_toml_and_sends_objects_to_configured_bucket() {
    use axum::{
        Router,
        extract::{Path, State},
        routing::put,
    };
    use std::sync::Mutex;
    let paths = Arc::new(Mutex::new(Vec::<String>::new()));
    let mock = Router::new()
        .route(
            "/{*path}",
            put(async |State(paths): State<Arc<Mutex<Vec<String>>>>, Path(path): Path<String>| {
                paths.lock().unwrap().push(path);
                StatusCode::OK
            })
            .head(|| async { StatusCode::NOT_FOUND }),
        )
        .with_state(paths.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let mut cfg: Config = toml::from_str(&format!(
        r#"
seed_demo = false
[object_store]
backend = "s3"
[object_store.s3]
endpoint = "http://{addr}"
bucket = "configured-bucket"
region = "test-region"
access_key_id = "mock-access"
secret_access_key = "mock-secret"
"#
    ))
    .unwrap();
    let dir = std::env::temp_dir().join(format!("memoswish-s3-config-{}", new_id()));
    cfg.data_dir = dir.clone();
    cfg.tts.auto_detect_espeak = false;
    let st = AppState::build(cfg).await.unwrap();
    assert_eq!(st.store.kind(), "s3");
    st.store.put("tenants/local/imports/test.png", b"PNG".to_vec(), "image/png").await.unwrap();
    assert!(paths.lock().unwrap().iter().all(|p| p.starts_with("configured-bucket/")));
    assert!(paths.lock().unwrap().contains(&"configured-bucket/tenants/local/imports/test.png".to_string()));
    task.abort();
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[cfg(not(feature = "s3"))]
#[test]
fn daemon_rejects_s3_when_not_compiled() {
    let mut cfg = Config::default();
    cfg.object_store.backend = "s3".into();
    assert!(crate::app::build_object_store(&cfg).is_err());
}

struct PausedPut {
    inner: Arc<dyn ObjectStore>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
#[async_trait::async_trait]
impl ObjectStore for PausedPut {
    fn kind(&self) -> &'static str {
        "paused"
    }
    fn namespace(&self) -> CoreResult<String> {
        self.inner.namespace()
    }
    async fn read_legacy(&self, key: &str, limit: u64) -> CoreResult<Option<StoredObject>> {
        self.inner.read_legacy(key, limit).await
    }
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner.put(key, bytes, mime).await
    }
    async fn put_versioned(
        &self,
        key: &str,
        bytes: Vec<u8>,
        mime: &str,
    ) -> CoreResult<memoswish_core::store::ObjectWrite> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner.put_versioned(key, bytes, mime).await
    }
    async fn delete_write(&self, key: &str, version: Option<&str>) -> CoreResult<()> {
        self.inner.delete_write(key, version).await
    }
    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> CoreResult<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> CoreResult<()> {
        self.inner.delete(key).await
    }
    async fn list_prefix(&self, prefix: &str) -> CoreResult<Vec<String>> {
        self.inner.list_prefix(prefix).await
    }
}

#[tokio::test]
async fn cleanup_waits_for_late_put_after_shutdown_budget() {
    use std::{future::poll_fn, task::Poll, time::Duration};

    let dir = std::env::temp_dir().join(format!("hf9-put-cleanup-{}", new_id()));
    let st =
        AppState::assemble(Config { data_dir: dir.clone(), seed_demo: false, ..Default::default() }).await.unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let raw = Arc::new(VersionedObjects::default());
    let store = Arc::new(crate::account::TenantStore {
        repo: st.repo.clone(),
        tasks: st.put_tasks.clone(),
        inner: Arc::new(PausedPut { inner: raw.clone(), entered: entered.clone(), release: release.clone() }),
    });
    let key = "shared/hf9-late-put";
    let writer =
        st.services.operations.spawn(async move { store.put(key, b"finished".to_vec(), "image/png").await }).unwrap();
    entered.notified().await;
    tokio::time::pause();
    let deadline = st.health.lifecycle.drain();
    tokio::time::advance(deadline - tokio::time::Instant::now()).await;
    // 调用方已超时且应用任务已排空，底层写入仍持有自己的准入许可。
    assert!(writer.await.unwrap().is_err());
    crate::runtime::drain_background(&st).await;
    st.services.operations.wait().await;
    assert_eq!(st.health.lifecycle.phase(), crate::lifecycle::Phase::Stopped);
    assert!(!st.put_tasks.shutdown().await, "blocked PUT must outlive the bounded production drain");
    assert!(!raw.exists(key).await.unwrap());

    let states = [&st];
    let cleanup = crate::runtime::cleanup_test_app(&dir, &states);
    tokio::pin!(cleanup);
    assert!(matches!(poll_fn(|cx| Poll::Ready(cleanup.as_mut().poll(cx))).await, Poll::Pending));
    // 再跨过原 helper 的第二段预算；完成条件只能来自写入所有者，而非计时器。
    let budget = Duration::from_secs(st.config.object_store.put_shutdown_timeout_secs);
    assert!(tokio::time::timeout(budget * 2, cleanup.as_mut()).await.is_err());
    assert!(dir.exists(), "cleanup cannot remove a directory while PUT ownership is active");
    release.notify_one();
    cleanup.await;
    assert_eq!(raw.get(key).await.unwrap().unwrap().bytes, b"finished");
    assert!(st.put_tasks.shutdown().await);
    assert!(!dir.exists());
}

// 只推进单项重试夹具；外部结果仍须由原持久回执证明。
pub(crate) async fn erasure_retry_due_for_test(st: &AppState, job: &memoswish_core::identity::ErasureJob) {
    crate::maintenance_scheduler::business_due_for_test(&st.config, job.tenant_id.as_deref().unwrap_or(""), &job.id)
        .await
        .unwrap();
}

// 完成依赖持久回执，不推进假时钟来替代外部结果。
async fn complete_pending(st: &AppState) {
    for job in st.repo.account_erasure_jobs().await.unwrap() {
        erasure_retry_due_for_test(st, &job).await;
        crate::account::finish(st, &job).await.unwrap();
        let work = st.repo.erasure_work(&job.id).await.unwrap().unwrap();
        assert_eq!((work.progress.as_str(), work.state.as_str()), ("complete", "succeeded"));
    }
    assert!(st.repo.account_erasure_jobs().await.unwrap().is_empty());
}

// HTTP 成功表示事务已提交；受控 worker 的单次执行与持久状态共同证明外部清理完成。
pub(crate) async fn assert_erasure_response(st: &AppState, status: StatusCode) {
    assert!(matches!(status, StatusCode::ACCEPTED | StatusCode::NO_CONTENT), "unexpected erasure response: {status}");
    complete_pending(st).await;
}

#[tokio::test]
async fn account_erasure_keeps_cross_replica_late_put_pending_after_first_sweep() {
    let (mut writer_st, dir, jwt) = fixture().await;
    let eraser_st = AppState::build(writer_st.config.as_ref().clone()).await.unwrap();
    let p = writer_st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let key = format!("tenants/{}/imports/late.png", p.tenant_id);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let raw = Arc::new(VersionedObjects::default());
    writer_st.store = Arc::new(crate::account::TenantStore {
        repo: writer_st.repo.clone(),
        tasks: writer_st.put_tasks.clone(),
        inner: Arc::new(PausedPut { inner: raw.clone(), entered: entered.clone(), release: release.clone() }),
    });
    let mut eraser_st = eraser_st;
    eraser_st.store = raw.clone();
    let writer = {
        let (store, key) = (writer_st.store.clone(), key.clone());
        tokio::spawn(async move { store.put(&key, b"inflight".to_vec(), "image/png").await })
    };
    entered.notified().await;
    // 外部 PUT 不持有 SQL 锁；另一连接池提交墓碑，但未知写入阻止完成。
    assert_eq!(request(&eraser_st, "DELETE", "/v1/account", &jwt).await.0, StatusCode::ACCEPTED);
    assert!(writer_st.repo.account_erased_tenant(&p.tenant_id).await.unwrap());
    assert!(raw.list_prefix(&format!("tenants/{}/", p.tenant_id)).await.unwrap().is_empty());
    let job = eraser_st.repo.account_erasure_jobs().await.unwrap().remove(0);
    erasure_retry_due_for_test(&eraser_st, &job).await;
    assert!(crate::account::finish(&eraser_st, &job).await.is_err());
    tokio::time::pause();
    tokio::time::advance(crate::account::PUT_TIMEOUT * 2).await;
    tokio::time::resume();
    erasure_retry_due_for_test(&eraser_st, &job).await;
    assert!(crate::account::finish(&eraser_st, &job).await.is_err());
    release.notify_one();
    assert!(writer.await.unwrap().is_err(), "late or timed out PUT cannot report success");
    raw.deleted.notified().await;
    // fake 的普通 DELETE 刻意报错，只有按写入回执删版本才能通过。
    assert!(!raw.exists(&key).await.unwrap());
    assert!(writer_st.store.put(&key, b"resurrect".to_vec(), "image/png").await.is_err());
    assert_eq!(eraser_st.repo.account_erasure_jobs().await.unwrap().len(), 1);
    // 模拟外部遗留版本；全部登记写入解决后仍须最终版本清扫。
    raw.put(&key, b"uncertain".to_vec(), "image/png").await.unwrap();
    erasure_retry_due_for_test(&eraser_st, &job).await;
    crate::account::finish(&eraser_st, &job).await.unwrap();
    assert!(!raw.exists(&key).await.unwrap());
    assert!(eraser_st.repo.account_erasure_jobs().await.unwrap().is_empty());
    crate::runtime::cleanup_test_app(dir, &[&writer_st, &eraser_st]).await;
}

#[tokio::test]
async fn cancelled_put_still_compensates_and_put_timeout_is_enforced() {
    for cancel in [true, false] {
        let (mut st, dir, jwt) = fixture().await;
        let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
        let raw = Arc::new(VersionedObjects::default());
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        st.store = Arc::new(crate::account::TenantStore {
            repo: st.repo.clone(),
            tasks: st.put_tasks.clone(),
            inner: Arc::new(PausedPut { inner: raw.clone(), entered: entered.clone(), release: release.clone() }),
        });
        let key = format!("tenants/{}/late", p.tenant_id);
        let writer = {
            let (store, key) = (st.store.clone(), key.clone());
            tokio::spawn(async move { store.put(&key, vec![1], "image/png").await })
        };
        entered.notified().await;
        if cancel {
            writer.abort();
            let _ = writer.await;
            let job = st.repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
            erasure_retry_due_for_test(&st, &job).await;
            assert!(crate::account::finish(&st, &job).await.is_err());
            release.notify_one();
            // 补偿由后台任务完成；屏障观测删除，而不是任意 sleep。
            raw.deleted.notified().await;
            assert!(!raw.exists(&key).await.unwrap());
        } else {
            tokio::time::pause();
            tokio::time::advance(crate::account::PUT_TIMEOUT).await;
            let error = writer.await.unwrap().unwrap_err();
            tokio::time::resume();
            assert!(error.to_string().contains("PUT timed out"));
            let job = st.repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
            erasure_retry_due_for_test(&st, &job).await;
            assert!(crate::account::finish(&st, &job).await.is_err());
            release.notify_one();
            raw.deleted.notified().await;
            assert!(!raw.exists(&key).await.unwrap());
        }
        crate::runtime::cleanup_test_app(dir, &[&st]).await;
    }
}

// 模拟 Tokio 文件操作已进入阻塞池：丢弃等待 future 不会取消实际写入。
struct BlockingDiskPut {
    inner: Arc<dyn ObjectStore>,
    entered: Arc<tokio::sync::Notify>,
    release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    deleted: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl ObjectStore for BlockingDiskPut {
    fn namespace(&self) -> CoreResult<String> {
        self.inner.namespace()
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        let release = self.release.lock().unwrap().take().unwrap();
        let (inner, entered) = (self.inner.clone(), self.entered.clone());
        let (key, mime) = (key.to_owned(), mime.to_owned());
        tokio::task::spawn_blocking(move || {
            entered.notify_one();
            release.recv().unwrap();
            tokio::runtime::Handle::current().block_on(inner.put(&key, bytes, &mime))
        })
        .await
        .unwrap()
    }
    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> CoreResult<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> CoreResult<()> {
        self.inner.delete(key).await?;
        self.deleted.notify_one();
        Ok(())
    }
    async fn list_prefix(&self, prefix: &str) -> CoreResult<Vec<String>> {
        self.inner.list_prefix(prefix).await
    }
}

#[tokio::test]
async fn timed_out_blocking_disk_put_prevents_completion_until_compensated() {
    let (mut writer_st, dir, jwt) = fixture().await;
    let eraser_st = AppState::build(writer_st.config.as_ref().clone()).await.unwrap();
    let p = writer_st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let prefix = format!("tenants/{}/", p.tenant_id);
    let key = format!("{prefix}imports/late.png");
    let entered = Arc::new(tokio::sync::Notify::new());
    let deleted = Arc::new(tokio::sync::Notify::new());
    let (release, receive) = std::sync::mpsc::channel();
    let disk = Arc::new(memoswish_storage::LocalDiskStore::new(dir.join("objects"), "/assets"));
    writer_st.store = Arc::new(crate::account::TenantStore {
        repo: writer_st.repo.clone(),
        tasks: writer_st.put_tasks.clone(),
        inner: Arc::new(BlockingDiskPut {
            inner: disk.clone(),
            entered: entered.clone(),
            release: std::sync::Mutex::new(Some(receive)),
            deleted: deleted.clone(),
        }),
    });
    let mut eraser_st = eraser_st;
    eraser_st.store = disk.clone();
    let writer = {
        let (store, key) = (writer_st.store.clone(), key.clone());
        tokio::spawn(async move { store.put(&key, b"private bytes".to_vec(), "image/png").await })
    };
    entered.notified().await;
    tokio::time::pause();
    // 跨过计时器向上取整的毫秒边界；运行中的阻塞任务会禁止虚拟时钟自动推进。
    tokio::time::advance(crate::account::PUT_TIMEOUT + std::time::Duration::from_millis(1)).await;
    let error = writer.await.unwrap().unwrap_err();
    tokio::time::resume();
    assert!(error.to_string().contains("PUT timed out"));
    assert_eq!(request(&eraser_st, "DELETE", "/v1/account", &jwt).await.0, StatusCode::ACCEPTED);
    let job = eraser_st.repo.account_erasure_jobs().await.unwrap().remove(0);
    // 最终清扫也必须移除前一次崩溃遗留的临时文件，且不触碰其他前缀。
    disk.put(&format!("{prefix}imports/orphan.tmp-abandoned"), b"private temp".to_vec(), "image/png").await.unwrap();
    disk.put("tenants/other/keep.png", b"keep".to_vec(), "image/png").await.unwrap();
    erasure_retry_due_for_test(&eraser_st, &job).await;
    assert!(crate::account::finish(&eraser_st, &job).await.is_err());
    assert_eq!(eraser_st.repo.account_erasure_jobs().await.unwrap().len(), 1);
    // 已跨过旧窗口，真实写入仍未知，所以不能宣告完成。
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), deleted.notified()).await.unwrap();
    assert!(!disk.exists(&key).await.unwrap());
    // 物理删除通知早于 record_erasure_object 提交；排空写任务才证明持久补偿完成。
    assert!(writer_st.put_tasks.shutdown().await);
    erasure_retry_due_for_test(&eraser_st, &job).await;
    crate::account::finish(&eraser_st, &job).await.unwrap();
    assert!(eraser_st.repo.account_erasure_jobs().await.unwrap().is_empty());
    assert!(disk.list_prefix(&prefix).await.unwrap().is_empty(), "no object or temporary file may remain");
    assert!(disk.exists("tenants/other/keep.png").await.unwrap());
    crate::runtime::cleanup_test_app(dir, &[&writer_st, &eraser_st]).await;
}

#[derive(Default)]
struct VersionedObjects {
    versions: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    deleted: tokio::sync::Notify,
    pause_delete: AtomicBool,
    deleting: tokio::sync::Notify,
    release_delete: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl ObjectStore for VersionedObjects {
    fn namespace(&self) -> CoreResult<String> {
        Ok("test-versioned".into())
    }
    fn kind(&self) -> &'static str {
        "versioned-test"
    }
    fn url_for(&self, key: &str) -> String {
        key.into()
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        Ok(self.put_versioned(key, bytes, mime).await?.asset)
    }
    async fn put_versioned(
        &self,
        key: &str,
        bytes: Vec<u8>,
        mime: &str,
    ) -> CoreResult<memoswish_core::store::ObjectWrite> {
        self.versions.lock().unwrap().insert(key.into(), bytes.clone());
        Ok(memoswish_core::store::ObjectWrite {
            asset: AssetRef {
                key: key.into(),
                url: key.into(),
                bytes: bytes.len() as u64,
                mime: mime.into(),
                sha256: String::new(),
            },
            version: Some("exact-version".into()),
        })
    }
    async fn delete_write(&self, key: &str, version: Option<&str>) -> CoreResult<()> {
        assert_eq!(version, Some("exact-version"));
        if self.pause_delete.load(Ordering::SeqCst) {
            self.deleting.notify_one();
            self.release_delete.notified().await;
        }
        self.versions.lock().unwrap().remove(key);
        self.deleted.notify_one();
        Ok(())
    }
    async fn delete(&self, _: &str) -> CoreResult<()> {
        Err(memoswish_core::CoreError::internal("ordinary DELETE leaves historical versions"))
    }
    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        Ok(self
            .versions
            .lock()
            .unwrap()
            .get(key)
            .map(|bytes| StoredObject { bytes: bytes.clone(), mime: "image/png".into() }))
    }
    async fn exists(&self, key: &str) -> CoreResult<bool> {
        Ok(self.versions.lock().unwrap().contains_key(key))
    }
    async fn list_prefix(&self, prefix: &str) -> CoreResult<Vec<String>> {
        Ok(self.versions.lock().unwrap().keys().filter(|key| key.starts_with(prefix)).cloned().collect())
    }
    async fn purge_prefix(&self, prefix: &str) -> CoreResult<()> {
        self.versions.lock().unwrap().retain(|key, _| !key.starts_with(prefix));
        Ok(())
    }
}

#[tokio::test]
async fn guarded_put_saturation_retains_permit_through_timeout_and_compensation() {
    use axum::response::IntoResponse;
    use std::time::Duration;

    let (st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let tasks = crate::account::PutTasks::new(&crate::config::ObjectStoreConfig {
        max_concurrent_puts: 1,
        ..Default::default()
    })
    .unwrap();
    let raw = Arc::new(VersionedObjects::default());
    raw.pause_delete.store(true, Ordering::SeqCst);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store = Arc::new(crate::account::TenantStore {
        repo: st.repo.clone(),
        tasks: tasks.clone(),
        inner: Arc::new(PausedPut { inner: raw.clone(), entered: entered.clone(), release: release.clone() }),
    });
    // 第二个包装器共享预算，不能绕过第一条写入占用的空位。
    let other = crate::account::TenantStore { repo: st.repo.clone(), tasks: tasks.clone(), inner: raw.clone() };
    let key = format!("tenants/{}/late.png", p.tenant_id);
    let writer = {
        let (store, key) = (store.clone(), key.clone());
        tokio::spawn(async move { store.put(&key, vec![1], "image/png").await })
    };
    entered.notified().await;
    tokio::time::pause();
    tokio::time::advance(crate::account::PUT_TIMEOUT + Duration::from_millis(1)).await;
    assert!(writer.await.unwrap().unwrap_err().to_string().contains("PUT timed out"));
    let started = tokio::time::Instant::now();
    let error = other.put("shared/rejected.png", vec![2], "image/png").await.unwrap_err();
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(error.http_status(), 503);
    assert_eq!(error.code(), "temporarily_unavailable");
    let response = crate::api::ApiErr(error).into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"], "temporarily_unavailable");
    assert!(!raw.exists("shared/rejected.png").await.unwrap());
    tokio::time::resume();
    st.repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
    release.notify_one();
    raw.deleting.notified().await;
    assert!(raw.exists(&key).await.unwrap());
    tokio::time::pause();
    assert_eq!(other.put("shared/rejected.png", vec![2], "image/png").await.unwrap_err().http_status(), 503);
    tokio::time::resume();
    raw.release_delete.notify_one();
    raw.deleted.notified().await;
    other.put("shared/accepted.png", vec![3], "image/png").await.unwrap();
    assert!(!raw.exists(&key).await.unwrap());
    assert!(tasks.shutdown().await);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn guarded_put_shutdown_drains_cancelled_caller_through_compensation() {
    let (st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let raw = Arc::new(VersionedObjects::default());
    raw.pause_delete.store(true, Ordering::SeqCst);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store = Arc::new(crate::account::TenantStore {
        repo: st.repo.clone(),
        tasks: st.put_tasks.clone(),
        inner: Arc::new(PausedPut { inner: raw.clone(), entered: entered.clone(), release: release.clone() }),
    });
    let key = format!("tenants/{}/late.png", p.tenant_id);
    let writer = {
        let (store, key) = (store.clone(), key.clone());
        tokio::spawn(async move { store.put(&key, vec![1], "image/png").await })
    };
    entered.notified().await;
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());
    st.repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
    st.put_tasks.close();
    let drain = {
        let tasks = st.put_tasks.clone();
        tokio::spawn(async move { tasks.shutdown().await })
    };
    assert_eq!(store.put("shared/closed.png", vec![2], "image/png").await.unwrap_err().http_status(), 503);
    assert!(!drain.is_finished());
    release.notify_one();
    raw.deleting.notified().await;
    assert!(!drain.is_finished(), "shutdown must wait for compensation too");
    raw.release_delete.notify_one();
    assert!(drain.await.unwrap());
    assert!(!raw.exists(&key).await.unwrap());
    assert!(!raw.exists("shared/closed.png").await.unwrap());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn guarded_put_shutdown_timeout_is_bounded_and_leaves_task_owned() {
    use std::time::Duration;

    let (st, dir, _) = fixture().await;
    let tasks = crate::account::PutTasks::new(&crate::config::ObjectStoreConfig {
        put_shutdown_timeout_secs: 2,
        ..Default::default()
    })
    .unwrap();
    let raw = Arc::new(VersionedObjects::default());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store = Arc::new(crate::account::TenantStore {
        repo: st.repo.clone(),
        tasks: tasks.clone(),
        inner: Arc::new(PausedPut { inner: raw.clone(), entered: entered.clone(), release: release.clone() }),
    });
    let writer = tokio::spawn(async move { store.put("shared/pending.png", vec![1], "image/png").await });
    entered.notified().await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    assert!(!tasks.shutdown().await);
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(!writer.is_finished());
    tokio::time::resume();
    release.notify_one();
    writer.await.unwrap().unwrap();
    assert!(tasks.shutdown().await);
    assert!(raw.exists("shared/pending.png").await.unwrap());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn startup_resweeps_open_erasure_jobs_and_completed_tombstones() {
    let (st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let job = st.repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
    let raw = memoswish_storage::LocalDiskStore::new(dir.join("assets"), "/assets");
    let key = format!("tenants/{}/late.png", p.tenant_id);
    raw.put(&key, vec![1], "image/png").await.unwrap();
    crate::maintenance_scheduler::due_for_test(&st.config).await.unwrap();
    crate::runtime::drain_test_state(&st).await;
    let restarted = AppState::build(st.config.as_ref().clone()).await.unwrap();
    assert!(!raw.exists(&key).await.unwrap());
    assert_eq!(restarted.repo.erasure_work(&job.id).await.unwrap().unwrap().progress, "complete");
    assert!(restarted.repo.account_erasure_jobs().await.unwrap().is_empty());
    raw.put(&key, vec![2], "image/png").await.unwrap();
    crate::maintenance_scheduler::due_for_test(&st.config).await.unwrap();
    crate::runtime::drain_test_state(&restarted).await;
    let restarted = AppState::build(st.config.as_ref().clone()).await.unwrap();
    // 已持久游标在空页处结束前一周期，再运行下一到期页发现重开的旧责任。
    crate::account::cleanup(&restarted).await.unwrap();
    assert!(!raw.exists(&key).await.unwrap());
    assert!(restarted.repo.account_erasure_jobs().await.unwrap().is_empty());
    assert!(restarted.repo.account_erased_tenant(&p.tenant_id).await.unwrap());
    crate::runtime::cleanup_test_app(dir, &[&st, &restarted]).await;
}

#[test]
fn guarded_put_config_defaults_overrides_and_invalid_capacity() {
    use crate::config::ObjectStoreConfig;

    let config: Config = toml::from_str("").unwrap();
    assert_eq!(config.object_store.max_concurrent_puts, 32);
    assert_eq!(config.object_store.put_admission_timeout_ms, 250);
    assert_eq!(config.object_store.put_shutdown_timeout_secs, 65);
    let config: Config = toml::from_str(
        "[object_store]\nmax_concurrent_puts = 2\nput_admission_timeout_ms = 10\nput_shutdown_timeout_secs = 3\n",
    )
    .unwrap();
    assert_eq!(config.object_store.max_concurrent_puts, 2);
    assert_eq!(config.object_store.put_admission_timeout_ms, 10);
    assert_eq!(config.object_store.put_shutdown_timeout_secs, 3);
    assert!(crate::account::PutTasks::new(&config.object_store).is_ok());
    for capacity in [0, tokio::sync::Semaphore::MAX_PERMITS + 1] {
        assert!(
            crate::account::PutTasks::new(&ObjectStoreConfig { max_concurrent_puts: capacity, ..Default::default() })
                .is_err()
        );
    }
}

#[tokio::test]
async fn zero_membership_http_sessions_are_bounded_and_cannot_enter_workspace_or_mcp() {
    let (st, dir, jwt) = fixture().await;
    let malformed = crate::auth_defenses::test_router(st.clone())
        .oneshot(
            Request::post("/v1/auth/account-sessions")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":17}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let error: serde_json::Value =
        serde_json::from_slice(&malformed.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(error["code"], "bad_request");
    let owner = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let api = st.services.auth.create_api_token(&owner, "delegated", vec![], None).await.unwrap();
    for token in [&jwt, &api.plaintext, "lto_at_delegated", "lto_rt_delegated", "upstream-token"] {
        assert_eq!(request(&st, "POST", "/v1/auth/account-sessions/refresh", token).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(request(&st, "DELETE", "/v1/account/empty", token).await.0, StatusCode::UNAUTHORIZED);
    }
    st.repo.membership_remove(&owner.tenant_id, &owner.user_id).await.unwrap();
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(
            Request::post("/v1/auth/account-sessions")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"owner@example.com","password":"password123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let account = body["access_token"].as_str().unwrap();
    assert!(body.get("user").is_none());
    assert!(body["account"].get("tenant_id").is_none());
    assert_eq!(request(&st, "GET", "/v1/account/profile", account).await.0, StatusCode::OK);
    assert_eq!(request(&st, "GET", "/v1/account/empty/export", account).await.0, StatusCode::OK);
    assert_eq!(request(&st, "POST", "/v1/auth/account-sessions/refresh", account).await.0, StatusCode::OK);
    for path in ["/v1/me", "/v1/feed", "/v1/usage", "/v1/decks", "/assets/tenants/private/file", "/v1/account/export"] {
        assert_eq!(request(&st, "GET", path, account).await.0, StatusCode::UNAUTHORIZED, "{path}");
    }
    let mcp=crate::auth_defenses::test_router(st.clone()).oneshot(Request::post("/mcp")
        .header(header::AUTHORIZATION,format!("Bearer {account}"))
        .header(header::CONTENT_TYPE,"application/json")
        .header(header::ACCEPT,"application/json, text/event-stream")
        .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_create","arguments":{"title":"denied"}}}"#)).unwrap()).await.unwrap();
    assert_eq!(mcp.status(), StatusCode::UNAUTHORIZED);
    assert!(st.repo.list_decks(&owner.tenant_id).await.unwrap().is_empty());
    assert_erasure_response(&st, request(&st, "DELETE", "/v1/account/empty", account).await.0).await;
    assert_eq!(request(&st, "GET", "/v1/account/profile", account).await.0, StatusCode::UNAUTHORIZED);
    assert!(st.repo.get_tenant(&owner.tenant_id).await.unwrap().is_some());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn account_session_live_http_roundtrip() {
    let (st, dir, jwt) = fixture().await;
    let principal = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    st.repo.membership_remove(&principal.tenant_id, &principal.user_id).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = crate::auth_defenses::test_router(st.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base}/v1/auth/account-sessions"))
        .json(&serde_json::json!({"email":"owner@example.com","password":"password123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let account: memoswish_protocol::AccountSessionResponse = response.json().await.unwrap();
    for path in ["/v1/account/profile", "/v1/account/empty/export"] {
        assert_eq!(
            client.get(format!("{base}{path}")).bearer_auth(&account.access_token).send().await.unwrap().status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        client
            .post(format!("{base}/v1/auth/account-sessions/refresh"))
            .bearer_auth(&account.access_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client.get(format!("{base}/v1/feed")).bearer_auth(&account.access_token).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_erasure_response(
        &st,
        client
            .delete(format!("{base}/v1/account/empty"))
            .bearer_auth(&account.access_token)
            .send()
            .await
            .unwrap()
            .status(),
    )
    .await;
    server.abort();
    let _ = server.await;
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn opaque_http_pair_logout_and_legacy_bridge_are_separate() {
    use serde_json::json;
    let (st, dir, jwt) = fixture().await;
    let post = |path: &str, body: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(post("/v1/auth/sessions", json!({"email":"owner@example.com","password":"password123"})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let data: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let access = data["access_token"].as_str().unwrap();
    let refresh = data["refresh_token"].as_str().unwrap();
    assert!(access.starts_with("lts_at_"));
    assert!(refresh.starts_with("lts_rt_"));
    assert_eq!(request(&st, "GET", "/v1/me", access).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(request(&st, "GET", "/v1/account/profile", access).await.0, StatusCode::OK);
    assert_eq!(request(&st, "POST", "/v1/auth/account-sessions/refresh", access).await.0, StatusCode::UNAUTHORIZED);
    let (status, list) = request(&st, "GET", "/v1/auth/sessions", access).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!list.to_string().contains(access));
    assert!(!list.to_string().contains(refresh));
    assert!(!list.to_string().contains("hash"));
    let bad = crate::auth_defenses::test_router(st.clone())
        .oneshot(post("/v1/auth/sessions/refresh", json!({"refresh_token":access})))
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(bad.headers()[header::WWW_AUTHENTICATE], r#"Bearer realm="learntok""#);
    let next = crate::auth_defenses::test_router(st.clone())
        .oneshot(post("/v1/auth/sessions/refresh", json!({"refresh_token":refresh})))
        .await
        .unwrap();
    assert_eq!(next.status(), StatusCode::OK);
    let next: serde_json::Value =
        serde_json::from_slice(&next.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        request(&st, "DELETE", "/v1/auth/sessions/current", next["access_token"].as_str().unwrap()).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&st, "GET", "/v1/account/profile", next["access_token"].as_str().unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(request(&st, "GET", "/v1/me", &jwt).await.0, StatusCode::OK);
    // 空/畸形 JSON 保持 REST envelope，不能回退到 legacy access 刷新。
    let invalid = crate::auth_defenses::test_router(st.clone())
        .oneshot(post("/v1/auth/sessions/refresh", json!({})))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn s5_workspace_deletion_preserves_password_accounts_sessions_and_other_memberships() {
    s5_workspace_deletion_case(None).await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_s5_workspace_deletion_preserves_password_accounts() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let (database, url) = crate::feature_tests::postgres_database(&owner).await;
        s5_workspace_deletion_case(Some(url)).await;
        database.cleanup().await;
    });
}

async fn s5_workspace_deletion_case(database_url: Option<String>) {
    let (st, dir, jwt) = fixture_with_database(database_url).await;
    let owner = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let member = UserRecord {
        id: new_id(),
        tenant_id: owner.tenant_id.clone(),
        email: "s5-member@example.com".into(),
        display_name: "Member".into(),
        password_hash: memoswish_auth::password::hash_password("password123").unwrap(),
        role: Role::Learner,
        created_at: chrono::Utc::now(),
    };
    st.repo.insert_user(&member).await.unwrap();
    let member_session = st.services.auth.interactive_response(&member).await.unwrap();
    let opaque_account = st
        .services
        .auth
        .login_session(&memoswish_protocol::LoginRequest {
            email: member.email.clone(),
            password: "password123".into(),
        })
        .await
        .unwrap();
    let opaque_workspace =
        st.services.auth.select_session_workspace(&opaque_account.access_token, &owner.tenant_id).await.unwrap();
    let account_before = st
        .services
        .auth
        .login_account(&memoswish_protocol::LoginRequest {
            email: member.email.clone(),
            password: "password123".into(),
        })
        .await
        .unwrap();
    let owner_account = st
        .services
        .auth
        .login_account(&memoswish_protocol::LoginRequest {
            email: "owner@example.com".into(),
            password: "password123".into(),
        })
        .await
        .unwrap();
    let other = st
        .services
        .auth
        .register(&RegisterRequest {
            email: "s5-other@example.com".into(),
            password: "password123".into(),
            display_name: "Other".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let other_p = st.services.auth.authenticate(Some(&other.access_token)).await.unwrap();
    let other_api = st
        .services
        .auth
        .create_api_token(&other_p, "preserved-workspace-token", vec!["content:read".into()], None)
        .await
        .unwrap();
    st.repo.membership_join(&owner.tenant_id, &other_p.user_id, Role::Editor).await.unwrap();
    for via in ["api_token", "mcp_oauth", "stdio", "upstream"] {
        let mut delegated = owner.clone();
        delegated.via = via.into();
        assert!(
            st.services
                .delete_workspace(
                    &delegated,
                    &memoswish_core::lifecycle::DeleteWorkspace { confirmed_tenant_id: owner.tenant_id.clone() }
                )
                .await
                .is_err()
        );
        assert!(st.services.leave_workspace(&delegated).await.is_err());
    }
    st.services
        .delete_workspace(
            &owner,
            &memoswish_core::lifecycle::DeleteWorkspace { confirmed_tenant_id: owner.tenant_id.clone() },
        )
        .await
        .unwrap();
    assert!(st.services.auth.authenticate(Some(&jwt)).await.is_err());
    assert!(st.services.auth.authenticate(Some(&member_session.access_token)).await.is_err());
    assert!(st.services.auth.authenticate(Some(&other.access_token)).await.is_ok());
    assert!(st.services.auth.authenticate(Some(&other_api.plaintext)).await.is_ok());
    assert!(st.services.auth.authenticate(Some(&opaque_workspace.access_token)).await.is_err());
    assert!(st.services.auth.refresh_session(&opaque_workspace.refresh_token).await.is_err());
    let opaque_account = st.services.auth.refresh_session(&opaque_account.refresh_token).await.unwrap();
    for path in ["/v1/account/profile", "/v1/account/empty/export"] {
        assert_eq!(request(&st, "GET", path, &opaque_account.access_token).await.0, StatusCode::OK);
    }
    assert!(st.services.auth.authenticate_account(&account_before.access_token).await.is_ok());
    assert!(st.services.auth.authenticate_account(&owner_account.access_token).await.is_ok());
    assert!(st.repo.get_user("local", &member.id).await.unwrap().is_none());
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(
            Request::post("/v1/auth/account-sessions")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"s5-member@example.com","password":"password123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let account = body["access_token"].as_str().unwrap();
    for (method, path) in [
        ("GET", "/v1/account/profile"),
        ("GET", "/v1/account/empty/export"),
        ("POST", "/v1/auth/account-sessions/refresh"),
    ] {
        assert_eq!(request(&st, method, path, account).await.0, StatusCode::OK);
    }
    assert_eq!(request(&st, "GET", "/v1/feed", account).await.0, StatusCode::UNAUTHORIZED);
    assert_erasure_response(&st, request(&st, "DELETE", "/v1/account/empty", account).await.0).await;
    assert!(st.repo.account_by_id(&member.id).await.unwrap().is_none());
    assert!(st.services.auth.authenticate_account(&opaque_account.access_token).await.is_err());
    assert!(st.services.auth.refresh_session(&opaque_account.refresh_token).await.is_err());
    assert!(st.repo.account_by_id(&owner.user_id).await.unwrap().is_some());
    assert!(st.repo.get_tenant(&other_p.tenant_id).await.unwrap().is_some());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn s5_local_requires_explicit_close_and_never_reboots_into_a_new_account() {
    let dir = std::env::temp_dir().join(format!("memoswish-s5-local-{}", new_id()));
    let config = Config { data_dir: dir.clone(), seed_demo: false, ..Default::default() };
    let st = AppState::build(config.clone()).await.unwrap();
    let p = st.services.auth.authenticate(None).await.unwrap();
    let jwt_principal = memoswish_core::Principal { via: "jwt".into(), ..p.clone() };
    assert!(
        st.services
            .delete_workspace(
                &jwt_principal,
                &memoswish_core::lifecycle::DeleteWorkspace { confirmed_tenant_id: p.tenant_id.clone() }
            )
            .await
            .is_err()
    );
    let peer = UserRecord {
        id: new_id(),
        tenant_id: p.tenant_id.clone(),
        email: "s5-local-peer@example.com".into(),
        display_name: "Peer owner".into(),
        password_hash: String::new(),
        role: Role::Owner,
        created_at: chrono::Utc::now(),
    };
    st.repo.insert_user(&peer).await.unwrap();
    assert!(st.services.leave_workspace(&p).await.is_err());
    assert!(st.services.leave_workspace(&jwt_principal).await.is_err());
    assert!(
        st.services
            .close_account(
                &memoswish_core::AccountPrincipal {
                    session_id: None,
                    session_access_hash: None,
                    legacy_issued_at: None,
                    user_id: p.user_id.clone(),
                    generation: 0
                },
                &memoswish_core::lifecycle::CloseAccount::default(),
            )
            .await
            .is_err()
    );
    assert!(st.repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().is_some());
    let peer_session = st.services.auth.interactive_response(&peer).await.unwrap();
    let peer_principal = st.services.auth.authenticate(Some(&peer_session.access_token)).await.unwrap();
    st.services.leave_workspace(&peer_principal).await.unwrap();
    assert!(
        st.services
            .delete_workspace(
                &p,
                &memoswish_core::lifecycle::DeleteWorkspace { confirmed_tenant_id: p.tenant_id.clone() }
            )
            .await
            .is_err()
    );
    assert!(
        st.services
            .close_account(
                &memoswish_core::AccountPrincipal {
                    session_id: None,
                    session_access_hash: None,
                    legacy_issued_at: None,
                    user_id: p.user_id.clone(),
                    generation: 0
                },
                &memoswish_core::lifecycle::CloseAccount::default()
            )
            .await
            .is_err()
    );
    st.services
        .close_account(
            &memoswish_core::AccountPrincipal {
                session_id: None,
                session_access_hash: None,
                legacy_issued_at: None,
                user_id: p.user_id.clone(),
                generation: 0,
            },
            &memoswish_core::lifecycle::CloseAccount { confirmed_exclusive_workspaces: vec![p.tenant_id.clone()] },
        )
        .await
        .unwrap();
    let restarted = AppState::build(config).await.unwrap();
    assert!(restarted.services.auth.authenticate(None).await.is_err());
    assert!(restarted.repo.get_tenant("local").await.unwrap().is_none());
    crate::runtime::cleanup_test_app(dir, &[&st, &restarted]).await;
}

#[tokio::test]
async fn s5_opaque_lifecycle_fences_preserve_account_and_other_workspace_sessions() {
    s5_opaque_lifecycle_case(None).await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_s5_opaque_lifecycle_fences_preserve_account_and_other_workspace_sessions() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let (database, url) = crate::feature_tests::postgres_database(&owner).await;
        s5_opaque_lifecycle_case(Some(url)).await;
        database.cleanup().await;
    });
}

async fn s5_opaque_lifecycle_case(database_url: Option<String>) {
    use memoswish_core::lifecycle::{CloseAccount, DeleteWorkspace, TransferOwnership};
    use memoswish_protocol::LoginRequest;

    let (st, dir, jwt) = fixture_with_database(database_url).await;
    let owner = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let successor = st
        .services
        .auth
        .register(&RegisterRequest {
            email: "s5-successor@example.com".into(),
            password: "password123".into(),
            display_name: "Successor".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    st.repo.membership_join(&owner.tenant_id, &successor.user.user_id, Role::Learner).await.unwrap();
    st.repo.membership_join(&successor.user.tenant_id, &owner.user_id, Role::Learner).await.unwrap();
    let owner_account = st
        .services
        .auth
        .login_session(&LoginRequest { email: "owner@example.com".into(), password: "password123".into() })
        .await
        .unwrap();
    let peer_account = st
        .services
        .auth
        .login_session(&LoginRequest { email: "s5-successor@example.com".into(), password: "password123".into() })
        .await
        .unwrap();
    let old_owner =
        st.services.auth.select_session_workspace(&owner_account.access_token, &owner.tenant_id).await.unwrap();
    let old_peer =
        st.services.auth.select_session_workspace(&peer_account.access_token, &owner.tenant_id).await.unwrap();
    let other = st
        .services
        .auth
        .select_session_workspace(&owner_account.access_token, &successor.user.tenant_id)
        .await
        .unwrap();
    let peer_other =
        st.services.auth.select_session_workspace(&peer_account.access_token, &successor.user.tenant_id).await.unwrap();
    let principal = st.services.auth.authenticate(Some(&old_owner.access_token)).await.unwrap();
    assert_eq!(principal.via, "session");
    st.services
        .transfer_ownership(&principal, &TransferOwnership { successor_user_id: successor.user.user_id.clone() })
        .await
        .unwrap();
    // 角色变化只围栏双方旧工作区授权，账户族和其他工作区凭据继续有效。
    for stale in [&old_owner, &old_peer] {
        assert!(st.services.auth.authenticate(Some(&stale.access_token)).await.is_err());
        assert!(st.services.auth.refresh_session(&stale.refresh_token).await.is_err());
    }
    assert!(st.services.auth.authenticate(Some(&other.access_token)).await.is_ok());
    assert!(st.services.auth.authenticate(Some(&peer_other.access_token)).await.is_ok());
    let new_owner =
        st.services.auth.select_session_workspace(&peer_account.access_token, &owner.tenant_id).await.unwrap();
    let departing =
        st.services.auth.select_session_workspace(&owner_account.access_token, &owner.tenant_id).await.unwrap();
    let principal = st.services.auth.authenticate(Some(&departing.access_token)).await.unwrap();
    st.services.leave_workspace(&principal).await.unwrap();
    st.repo.membership_join(&owner.tenant_id, &owner.user_id, Role::Learner).await.unwrap();
    // 重加入也不能恢复旧工作区 access 或 refresh。
    for stale in [&old_owner, &departing] {
        assert!(st.services.auth.authenticate(Some(&stale.access_token)).await.is_err());
        assert!(st.services.auth.refresh_session(&stale.refresh_token).await.is_err());
    }
    let rejoined =
        st.services.auth.select_session_workspace(&owner_account.access_token, &owner.tenant_id).await.unwrap();
    assert!(st.services.auth.authenticate(Some(&rejoined.access_token)).await.is_ok());
    let principal = st.services.auth.authenticate(Some(&new_owner.access_token)).await.unwrap();
    st.services
        .delete_workspace(&principal, &DeleteWorkspace { confirmed_tenant_id: owner.tenant_id.clone() })
        .await
        .unwrap();
    for stale in [&new_owner, &rejoined] {
        assert!(st.services.auth.authenticate(Some(&stale.access_token)).await.is_err());
        assert!(st.services.auth.refresh_session(&stale.refresh_token).await.is_err());
    }
    assert!(st.services.auth.authenticate_account(&owner_account.access_token).await.is_ok());
    assert!(st.services.auth.authenticate_account(&peer_account.access_token).await.is_ok());
    assert!(st.services.auth.authenticate(Some(&other.access_token)).await.is_ok());
    let second_family = st
        .services
        .auth
        .login_session(&LoginRequest { email: "owner@example.com".into(), password: "password123".into() })
        .await
        .unwrap();
    let principal = st.services.auth.authenticate_account(&owner_account.access_token).await.unwrap();
    st.services.close_account(&principal, &CloseAccount::default()).await.unwrap();
    // 销户级联结束全部账户族，保留同工作区的其他账户及其族。
    for stale in [&owner_account, &second_family, &other] {
        assert!(st.services.auth.authenticate_account(&stale.access_token).await.is_err());
        assert!(st.services.auth.authenticate(Some(&stale.access_token)).await.is_err());
        assert!(st.services.auth.refresh_session(&stale.refresh_token).await.is_err());
    }
    assert!(st.services.auth.authenticate(Some(&peer_other.access_token)).await.is_ok());
    assert!(st.services.auth.refresh_session(&peer_account.refresh_token).await.is_ok());
    assert!(st.services.auth.refresh_session(&peer_other.refresh_token).await.is_ok());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn tenant_store_preserves_exact_receipt_and_deletion_delegation() {
    let (st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let inner = Arc::new(VersionedObjects::default());
    let store =
        crate::account::TenantStore { repo: st.repo.clone(), tasks: st.put_tasks.clone(), inner: inner.clone() };
    let key = format!("tenants/{}/exact.wav", p.tenant_id);
    let write = store.put_versioned(&key, vec![1, 2, 3], "audio/wav").await.unwrap();
    assert_eq!(write.version.as_deref(), Some("exact-version"));
    assert!(inner.exists(&key).await.unwrap());
    store.delete_write(&key, write.version.as_deref()).await.unwrap();
    assert!(!inner.exists(&key).await.unwrap());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

struct ErasurePausedTts {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl memoswish_core::tts::TtsEngine for ErasurePausedTts {
    fn id(&self) -> &str {
        "erasure-paused"
    }
    fn voices(&self) -> Vec<memoswish_core::tts::VoiceInfo> {
        vec![]
    }
    async fn synthesize(&self, _: &memoswish_core::tts::TtsRequest) -> CoreResult<memoswish_core::tts::TtsOutput> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(memoswish_core::tts::TtsOutput {
            alignment_quality: None,
            audio_kind: None,
            provenance: None,
            audio: b"abc".to_vec(),
            mime: "audio/mpeg".into(),
            extension: "mp3".into(),
            duration_ms: 100,
            words: vec![],
        })
    }
}

#[tokio::test]
async fn s16_workspace_deletion_fences_late_provider_and_compensates_late_put() {
    for phase in ["provider", "put"] {
        s16_workspace_deletion_case(None, phase).await;
    }
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_s16_workspace_deletion_fences_late_provider_and_compensates_late_put() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        for phase in ["provider", "put"] {
            let (database, url) = crate::feature_tests::postgres_database(&owner).await;
            s16_workspace_deletion_case(Some(url), phase).await;
            database.cleanup().await;
        }
    });
}

async fn s16_workspace_deletion_case(database_url: Option<String>, phase: &str) {
    let (mut writer_st, dir, jwt) = fixture_with_database(database_url.clone()).await;
    let mut eraser_st = AppState::build(writer_st.config.as_ref().clone()).await.unwrap();
    // 启动扫描捕获原媒体服务；先排空，再注入屏障，避免它晚到领取本测试的新任务。
    for state in [&mut writer_st, &mut eraser_st] {
        state.services.operations.close();
        state.services.operations.wait().await;
        state.services.operations = Default::default();
    }
    let p = writer_st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let deck = memoswish_protocol::examples::sample_deck();
    let mut card = memoswish_protocol::examples::sample_card();
    card.tts = None;
    writer_st.repo.insert_deck_with_cards(&p.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    std::fs::create_dir_all(dir.join("tts-race")).unwrap();
    let raw: Arc<dyn ObjectStore> = Arc::new(memoswish_storage::LocalDiskStore::new(dir.join("tts-race"), "/assets"));
    let inner: Arc<dyn ObjectStore> = if phase == "put" {
        Arc::new(PausedPut { inner: raw.clone(), entered: entered.clone(), release: release.clone() })
    } else {
        raw.clone()
    };
    writer_st.store = Arc::new(crate::account::TenantStore {
        repo: writer_st.repo.clone(),
        tasks: writer_st.put_tasks.clone(),
        inner,
    });
    eraser_st.store = raw.clone();
    let engine: Arc<dyn memoswish_core::tts::TtsEngine> = if phase == "provider" {
        Arc::new(ErasurePausedTts { entered: entered.clone(), release: release.clone() })
    } else {
        Arc::new(memoswish_media::tts::placeholder::PlaceholderTts)
    };
    let engine_id = engine.id().to_owned();
    writer_st.services.media = memoswish_media::MediaService::new(
        writer_st.repo.clone(),
        writer_st.store.clone(),
        writer_st.services.quota.clone(),
        vec![engine],
        &engine_id,
    )
    .unwrap();
    let mut writer = {
        let (services, principal, card_id) = (writer_st.services.clone(), p.clone(), card.id.clone());
        tokio::spawn(async move { services.synthesize_cards(&principal, &[card_id], &Default::default()).await })
    };
    tokio::select! {
        _ = entered.notified() => {},
        result = &mut writer => panic!("synthesis ended before the external operation barrier: {result:?}"),
    }
    let (tenant, synthesis) = writer_st
        .repo
        .pending_speech(None, 100)
        .await
        .unwrap()
        .into_iter()
        .find(|(tenant, _)| tenant == &p.tenant_id)
        .unwrap();
    let job = eraser_st
        .services
        .delete_workspace(&p, &memoswish_core::lifecycle::DeleteWorkspace { confirmed_tenant_id: p.tenant_id.clone() })
        .await
        .unwrap();
    // 外部操作未决时不能宣告完成；后续回执保留原责任。
    erasure_retry_due_for_test(&eraser_st, &job).await;
    assert!(crate::account::finish(&eraser_st, &job).await.is_err());
    let blocked = eraser_st.repo.erasure_work(&job.id).await.unwrap().unwrap();
    assert_eq!((blocked.progress.as_str(), blocked.state.as_str()), ("blocked", "queued"));
    release.notify_one();
    assert!(writer.await.unwrap().is_err());
    writer_st.services.operations.close();
    writer_st.services.operations.wait().await;
    assert!(writer_st.put_tasks.shutdown().await);
    assert!(raw.list_prefix(&format!("tenants/{tenant}/")).await.unwrap().is_empty());
    assert!(writer_st.repo.get_card(&tenant, &card.id).await.unwrap().is_none());
    assert!(writer_st.repo.claim_speech(&tenant, &synthesis, 30_000).await.unwrap().is_none());
    let period = chrono::Utc::now().format("%Y-%m").to_string();
    let (held, uncertain) = writer_st.repo.held_speech_usage(&tenant, &period).await.unwrap();
    assert!(held > 0);
    assert_eq!(uncertain, if phase == "provider" { held } else { 0 });
    assert_eq!(writer_st.repo.get_usage(&tenant, "tts_chars", &period).await.unwrap(), 0);
    if phase == "provider" {
        erasure_retry_due_for_test(&eraser_st, &job).await;
        assert!(crate::account::finish(&eraser_st, &job).await.is_err());
        assert!(!writer_st.repo.account_erasure_jobs().await.unwrap().is_empty());
    } else {
        erasure_retry_due_for_test(&eraser_st, &job).await;
        let result = crate::account::finish(&eraser_st, &job).await;
        let work = eraser_st.repo.erasure_work(&job.id).await.unwrap().unwrap();
        assert!(result.is_ok(), "finish={result:?}, progress={}, state={}", work.progress, work.state);
        assert_eq!((work.progress.as_str(), work.state.as_str()), ("complete", "succeeded"));
        assert_eq!(work.total_attempts, 2);
        assert!(writer_st.repo.account_erasure_jobs().await.unwrap().is_empty());
    }
    crate::runtime::cleanup_test_app(dir, &[&writer_st, &eraser_st]).await;
}

#[tokio::test]
async fn s19_registration_failure_prevents_put_and_lost_sql_receipt_blocks_restart_cleanup() {
    let (st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let db = memoswish_storage::sqlite::SqliteRepository::connect(&st.config.database_url()).await.unwrap();
    let key = format!("tenants/{}/imports/receipt.png", p.tenant_id);
    let raw = memoswish_storage::LocalDiskStore::new(dir.join("assets"), "/assets");
    sqlx::raw_sql("CREATE TRIGGER s19_reject_registration BEFORE INSERT ON managed_object_writes BEGIN SELECT RAISE(ABORT,'injected registration failure'); END;")
        .execute(db.pool()).await.unwrap();
    assert!(st.store.put(&key, vec![1], "image/png").await.is_err());
    assert!(!raw.exists(&key).await.unwrap(), "failed durable registration must prevent external PUT");
    let jobs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE tenant_id=$1 AND kind='managed_put'")
            .bind(&p.tenant_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(jobs, 0, "registration and responsibility insertion roll back together");
    sqlx::raw_sql("DROP TRIGGER s19_reject_registration; CREATE TRIGGER s19_lose_put_receipt BEFORE UPDATE OF version_kind ON managed_object_writes BEGIN SELECT RAISE(ABORT,'injected SQL receipt loss'); END;")
        .execute(db.pool()).await.unwrap();
    assert!(st.store.put(&key, vec![2], "image/png").await.is_err());
    assert!(raw.exists(&key).await.unwrap());
    sqlx::raw_sql("DROP TRIGGER s19_lose_put_receipt").execute(db.pool()).await.unwrap();
    let job = st.repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
    erasure_retry_due_for_test(&st, &job).await;
    assert!(crate::account::finish(&st, &job).await.is_err());
    assert!(raw.exists(&key).await.unwrap(), "unknown physical version must not be blind deleted");
    let restarted = AppState::build(st.config.as_ref().clone()).await.unwrap();
    assert_ne!(restarted.repo.erasure_work(&job.id).await.unwrap().unwrap().progress, "complete");
    assert!(raw.exists(&key).await.unwrap());
    assert!(!restarted.store.exists(&key).await.unwrap(), "logical deletion still denies delivery");
    db.pool().close().await;
    crate::runtime::cleanup_test_app(dir, &[&st, &restarted]).await;
}

#[tokio::test]
async fn s21b_http_registration_discovery_and_account_logout() {
    use memoswish_core::{
        CoreError,
        lifecycle::{CloseAccount, DeleteWorkspace, TransferOwnership},
    };
    use memoswish_protocol::LoginRequest;
    use serde_json::json;
    let (st, dir, jwt) = fixture().await;
    let login = LoginRequest { email: "owner@example.com".into(), password: "password123".into() };
    let pair = st.services.auth.login_session(&login).await.unwrap();
    let tenant = st.services.auth.authenticate(Some(&jwt)).await.unwrap().tenant_id;
    let workspace = st.services.auth.select_session_workspace(&pair.access_token, &tenant).await.unwrap();
    let captured_workspace = st.services.auth.authenticate(Some(&workspace.access_token)).await.unwrap();
    let captured_jwt = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let captured_account = st.services.auth.authenticate_account(&pair.access_token).await.unwrap();
    let legacy_account = st.services.auth.login_account(&login).await.unwrap();
    let captured_legacy_account = st.services.auth.authenticate_account(&legacy_account.access_token).await.unwrap();
    let second = st.services.auth.login_session(&login).await.unwrap();
    let (status, memberships) = request(&st, "GET", "/v1/account/memberships", &pair.access_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(memberships[0]["tenant_id"], tenant);
    assert_eq!(memberships[0]["role"], "owner");
    assert_eq!(request(&st, "DELETE", "/v1/auth/sessions", &workspace.access_token).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(request(&st, "DELETE", "/v1/auth/sessions", &jwt).await.0, StatusCode::UNAUTHORIZED);
    let bad = crate::auth_defenses::test_router(st.clone())
        .oneshot(Request::delete("/v1/auth/sessions").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(bad.headers()[header::WWW_AUTHENTICATE], r#"Bearer realm="learntok""#);
    assert_eq!(bad.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(request(&st, "DELETE", "/v1/auth/sessions", &pair.access_token).await.0, StatusCode::NO_CONTENT);
    for p in [&captured_workspace, &captured_jwt] {
        assert!(matches!(st.services.leave_workspace(p).await, Err(CoreError::Unauthorized(_))));
        assert!(matches!(
            st.services.delete_workspace(p, &DeleteWorkspace { confirmed_tenant_id: tenant.clone() }).await,
            Err(CoreError::Unauthorized(_))
        ));
        assert!(matches!(
            st.services.transfer_ownership(p, &TransferOwnership { successor_user_id: new_id() }).await,
            Err(CoreError::Unauthorized(_))
        ));
    }
    for p in [&captured_account, &captured_legacy_account] {
        assert!(matches!(
            st.services.close_account(p, &CloseAccount { confirmed_exclusive_workspaces: vec![tenant.clone()] }).await,
            Err(CoreError::Unauthorized(_))
        ));
    }
    for access in [&pair.access_token, &second.access_token] {
        assert_eq!(request(&st, "GET", "/v1/account/memberships", access).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(request(&st, "GET", "/v1/me", &workspace.access_token).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(request(&st, "GET", "/v1/me", &jwt).await.0, StatusCode::UNAUTHORIZED);
    for token in [&pair.access_token, &workspace.access_token, &jwt, &legacy_account.access_token] {
        assert_eq!(request(&st, "GET", "/v1/account/export/full", token).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            s6_post(
                &st,
                token,
                "/v1/account/close",
                json!({"confirmed_user_id":captured_account.user_id,"confirmed_exclusive_workspaces":[tenant]})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    let mut cfg = (*st.config).clone();
    cfg.sessions.legacy_verify_until = Some(0);
    let cutoff = AppState::build(cfg).await.unwrap();
    let registration = |email: &str| {
        Request::post("/v1/auth/sessions/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"email":email,"password":"password123","display_name":"New"}).to_string()))
            .unwrap()
    };
    let response =
        crate::auth_defenses::test_router(cutoff.clone()).oneshot(registration("new@example.com")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(body["access_token"].as_str().unwrap().starts_with("lts_at_"));
    assert!(body["workspace"].is_null());
    assert_eq!(
        crate::auth_defenses::test_router(cutoff.clone())
            .oneshot(registration("new@example.com"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        crate::auth_defenses::test_router(cutoff.clone()).oneshot(registration("invalid")).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(st.server_info().opaque_sessions);
    crate::runtime::cleanup_test_app(dir, &[&st, &cutoff]).await;
}

async fn s6_post(st: &AppState, token: &str, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

fn assert_s6_policy_link(headers: &axum::http::HeaderMap) {
    let link = headers[header::LINK].to_str().unwrap();
    let (target, attributes) = link.strip_prefix('<').unwrap().split_once('>').unwrap();
    assert_eq!(attributes, "; rel=\"deprecation\"; type=\"text/plain\"");
    for prefix in ["", "/prefix", "/nested/prefix"] {
        let context = reqwest::Url::parse(&format!("https://learn.example{prefix}/v1/account")).unwrap();
        assert_eq!(
            context.join(target).unwrap().as_str(),
            format!("https://learn.example{prefix}/v1/account/lifecycle-policy")
        );
    }
}

#[tokio::test]
async fn s6_legacy_error_policy_link_preserves_deployment_prefix() {
    let (st, dir, _) = fixture().await;
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/account")
                .header(header::AUTHORIZATION, "Bearer invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["deprecation"], "@1794009600");
    assert_s6_policy_link(response.headers());
    let policy = crate::auth_defenses::test_router(st.clone())
        .oneshot(Request::builder().uri("/v1/account/lifecycle-policy").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(policy.status(), StatusCode::OK);
    assert_eq!(policy.headers()[header::CACHE_CONTROL], "no-store");
    let body = policy.into_body().collect().await.unwrap().to_bytes();
    assert!(std::str::from_utf8(&body).unwrap().contains("throughout 2.x"));
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn s6_public_lifecycle_and_export_boundaries() {
    s6_public_case(None).await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_s6_public_lifecycle_and_export_boundaries() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let (database, url) = crate::feature_tests::postgres_database(&owner).await;
        s6_public_case(Some(url)).await;
        database.cleanup().await;
    });
}

async fn s6_public_case(database_url: Option<String>) {
    use serde_json::json;
    let (st, dir, jwt) = fixture_with_database(database_url).await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let root = st
        .services
        .auth
        .login_session(&memoswish_protocol::LoginRequest {
            email: "owner@example.com".into(),
            password: "password123".into(),
        })
        .await
        .unwrap();
    let workspace = st.services.auth.select_session_workspace(&root.access_token, &p.tenant_id).await.unwrap();
    for token in [&jwt, &root.access_token, &workspace.access_token] {
        let (status, data) = request(&st, "GET", "/v1/account/export/full", token).await;
        assert_eq!(status, StatusCode::OK, "{data}");
        assert_eq!(data["account"]["user_id"], p.user_id);
        assert_eq!(data["workspaces"][0]["exclusive"], true);
        let raw = data.to_string();
        for secret in [
            &root.access_token,
            &root.refresh_token,
            "access_hash",
            "refresh_hash",
            "assurance_hash",
            "password_hash",
            "feed_page_receipts",
        ] {
            assert!(!raw.contains(secret));
        }
    }
    for scope in [vec!["account:export".into()], vec!["*".into()]] {
        let token = st.services.auth.create_api_token(&p, "s6", scope, Some(3600)).await.unwrap();
        assert_eq!(request(&st, "GET", "/v1/account/export/full", &token.plaintext).await.0, StatusCode::FORBIDDEN);
        assert_eq!(request(&st, "GET", "/v1/workspace/export", &token.plaintext).await.0, StatusCode::OK);
        assert_eq!(
            s6_post(
                &st,
                &token.plaintext,
                "/v1/account/close",
                json!({"confirmed_user_id":p.user_id,"confirmed_exclusive_workspaces":[p.tenant_id]})
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let before = st.repo.account_erasure_jobs().await.unwrap().len();
    for path in ["/v1/workspace/leave", "/v1/workspace/delete", "/v1/workspace/transfer-ownership", "/v1/account/close"]
    {
        for bad in
            [json!({}), json!({"confirmed_tenant_id":42}), json!({"confirmed_tenant_id":"foreign","extra":"S6_SECRET"})]
        {
            let (status, error) = s6_post(&st, &jwt, path, bad).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {error}");
            assert_eq!(error["code"], "bad_request");
            assert!(!error.to_string().contains("S6_SECRET"));
        }
    }
    assert_eq!(
        s6_post(&st, &jwt, "/v1/workspace/delete", json!({"confirmed_tenant_id":"foreign"})).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        s6_post(
            &st,
            &jwt,
            "/v1/account/close",
            json!({"confirmed_user_id":p.user_id,"confirmed_exclusive_workspaces":[]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(st.repo.account_erasure_jobs().await.unwrap().len(), before);
    let member = UserRecord {
        id: new_id(),
        tenant_id: p.tenant_id.clone(),
        email: "s6-peer@example.com".into(),
        display_name: "Peer".into(),
        password_hash: st.repo.account_by_id(&p.user_id).await.unwrap().unwrap().password_hash,
        role: Role::Learner,
        created_at: chrono::Utc::now(),
    };
    st.repo.insert_user(&member).await.unwrap();
    let peer_root = st
        .services
        .auth
        .login_session(&memoswish_protocol::LoginRequest {
            email: member.email.clone(),
            password: "password123".into(),
        })
        .await
        .unwrap();
    let peer = st.services.auth.interactive_response(&member).await.unwrap();
    assert_eq!(
        s6_post(&st, &peer.access_token, "/v1/workspace/delete", json!({"confirmed_tenant_id":p.tenant_id})).await.0,
        StatusCode::FORBIDDEN
    );
    // legacy owner 只关闭本人，另一个人的账户根凭据和密码保留。
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/account")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_erasure_response(&st, response.status()).await;
    assert_eq!(response.headers()["deprecation"], "@1794009600");
    assert!(response.headers()[header::LINK].to_str().unwrap().contains("lifecycle-policy"));
    assert_s6_policy_link(response.headers());
    assert_eq!(
        request(&st, "GET", "/v1/account/export/full", &peer_root.access_token).await.1["workspaces"],
        json!([])
    );
    assert!(
        st.services
            .auth
            .login_session(&memoswish_protocol::LoginRequest { email: member.email, password: "password123".into() })
            .await
            .is_ok()
    );
    assert_erasure_response(
        &st,
        s6_post(
            &st,
            &peer_root.access_token,
            "/v1/account/close",
            json!({"confirmed_user_id":member.id,"confirmed_exclusive_workspaces":[]}),
        )
        .await
        .0,
    )
    .await;
    assert!(st.repo.account_by_id(&member.id).await.unwrap().is_none());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn s6_legacy_multimembership_is_typed_and_nonmutating() {
    let (st, dir, jwt) = fixture().await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let mut other = st.repo.get_tenant(&p.tenant_id).await.unwrap().unwrap();
    other.id = new_id();
    st.repo.upsert_tenant(&other).await.unwrap();
    st.repo.membership_join(&other.id, &p.user_id, Role::Editor).await.unwrap();
    let (status, error) = request(&st, "DELETE", "/v1/account", &jwt).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        error,
        serde_json::json!({"code":"use_explicit_command","message":"Use LeaveWorkspace, DeleteWorkspace or CloseAccount explicitly."})
    );
    assert!(st.repo.account_erasure_jobs().await.unwrap().is_empty());
    assert!(st.repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().is_some());
    assert!(st.repo.get_user(&other.id, &p.user_id).await.unwrap().is_some());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn s6_local_explicit_close_requires_confirmation_and_survives_restart() {
    let dir = std::env::temp_dir().join(format!("memoswish-s6-local-{}", new_id()));
    let config = Config { data_dir: dir.clone(), seed_demo: false, ..Default::default() };
    let st = AppState::build(config.clone()).await.unwrap();
    let body = serde_json::json!({"confirmed_user_id":"usr_local","confirmed_exclusive_workspaces":[]});
    // 单用户 API 无 Bearer；空的确认集合不能删除 local。
    let post = |body: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri("/v1/account/close")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let response = crate::auth_defenses::test_router(st.clone()).oneshot(post(body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(post(serde_json::json!({"confirmed_user_id":"usr_local","confirmed_exclusive_workspaces":["local"]})))
        .await
        .unwrap();
    assert_erasure_response(&st, response.status()).await;
    let restarted = AppState::build(config).await.unwrap();
    assert!(restarted.repo.account_by_id("usr_local").await.unwrap().is_none());
    crate::runtime::cleanup_test_app(dir, &[&st, &restarted]).await;
}

struct ExportGateStore {
    inner: Arc<dyn ObjectStore>,
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
}
#[async_trait::async_trait]
impl ObjectStore for ExportGateStore {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        self.inner.put(key, bytes, mime).await
    }
    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> CoreResult<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> CoreResult<()> {
        self.inner.delete(key).await
    }
    async fn list_prefix(&self, prefix: &str) -> CoreResult<Vec<String>> {
        self.reached.notify_one();
        self.release.acquire().await.unwrap().forget();
        self.inner.list_prefix(prefix).await
    }
}

#[tokio::test]
async fn s6_export_authorization_surrounds_object_io_without_sql_locks() {
    s6_export_barrier_case(None).await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_s6_export_authorization_surrounds_object_io_without_sql_locks() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let (database, url) = crate::feature_tests::postgres_database(&owner).await;
        s6_export_barrier_case(Some(url)).await;
        database.cleanup().await;
    });
}

async fn s6_export_barrier_case(database_url: Option<String>) {
    let (mut st, dir, jwt) = fixture_with_database(database_url).await;
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    for path in ["/v1/account/export", "/v1/workspace/export"] {
        for revoke_first in [true, false] {
            let token = st
                .services
                .auth
                .create_api_token(&p, "export barrier", vec!["account:export".into()], None)
                .await
                .unwrap();
            let reached = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Semaphore::new(0));
            st.store = Arc::new(ExportGateStore {
                inner: st.store.clone(),
                reached: reached.clone(),
                release: release.clone(),
            });
            let exporting = st.clone();
            let bearer = token.plaintext.clone();
            let task = tokio::spawn(async move { request(&exporting, "GET", path, &bearer).await });
            reached.notified().await;
            if revoke_first {
                // 若导出持有 SQL 锁等待对象，这个撤销将无法先提交。
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    st.repo.revoke_api_token(&p.tenant_id, &token.record.id),
                )
                .await
                .unwrap()
                .unwrap();
            }
            release.add_permits(1);
            // 内层是前一轮已释放的 gate，补充许可避免阻塞后续读取。
            let result = task.await.unwrap();
            assert_eq!(
                result.0,
                if revoke_first { StatusCode::UNAUTHORIZED } else { StatusCode::OK },
                "{path}: {}",
                result.1
            );
            if !revoke_first {
                st.repo.revoke_api_token(&p.tenant_id, &token.record.id).await.unwrap();
            }
            release.add_permits(8);
        }
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

/// 使用真实 TCP/HTTP 验证公开命令的组合，而不通过 router oneshot 替代传输。
#[tokio::test]
async fn s6_live_http_multimembership_leave_delete_and_account_closure() {
    use memoswish_core::repo::TenantRecord;
    use serde_json::json;
    let (mut st, dir, jwt) = fixture().await;
    let store = Arc::new(FailListing { inner: st.store.clone(), fail: AtomicBool::new(false) });
    st.store = store.clone();
    let owner = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let owner_user = st.repo.get_user(&owner.tenant_id, &owner.user_id).await.unwrap().unwrap();
    let b =
        TenantRecord { id: new_id(), name: "Workspace B".into(), plan: "free".into(), created_at: chrono::Utc::now() };
    st.repo.upsert_tenant(&b).await.unwrap();
    st.repo.membership_join(&b.id, &owner.user_id, Role::Editor).await.unwrap();
    let peer =
        UserRecord { id: new_id(), email: "live-peer@example.com".into(), role: Role::Learner, ..owner_user.clone() };
    let orphan =
        UserRecord { id: new_id(), email: "live-orphan@example.com".into(), role: Role::Learner, ..owner_user.clone() };
    st.repo.insert_user(&peer).await.unwrap();
    st.repo.insert_user(&orphan).await.unwrap();
    st.repo.membership_join(&b.id, &peer.id, Role::Owner).await.unwrap();
    let peer_a = st.services.auth.interactive_response(&peer).await.unwrap();
    let peer_b = st
        .services
        .auth
        .interactive_response(&st.repo.get_user(&b.id, &peer.id).await.unwrap().unwrap())
        .await
        .unwrap();
    let orphan_workspace = st.services.auth.interactive_response(&orphan).await.unwrap();
    let owner_b = st
        .services
        .auth
        .interactive_response(&st.repo.get_user(&b.id, &owner.user_id).await.unwrap().unwrap())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = crate::auth_defenses::test_router(st.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    async fn http(
        client: &reqwest::Client,
        base: &str,
        method: &str,
        path: &str,
        token: &str,
        body: serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let mut request = client.request(method.parse().unwrap(), format!("{base}{path}"));
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
        if !body.is_null() {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        (status, response.json().await.unwrap_or_default())
    }
    let login = |email: &str| json!({"email":email,"password":"password123"});
    let (_, account) = http(&client, &base, "POST", "/v1/auth/account-sessions", "", login("owner@example.com")).await;
    let root = account["access_token"].as_str().unwrap();
    let (_, account_peer) = http(&client, &base, "POST", "/v1/auth/account-sessions", "", login(&peer.email)).await;
    let peer_root = account_peer["access_token"].as_str().unwrap();
    let (_, account_orphan) = http(&client, &base, "POST", "/v1/auth/account-sessions", "", login(&orphan.email)).await;
    let orphan_root = account_orphan["access_token"].as_str().unwrap();
    let (status, data) = http(&client, &base, "GET", "/v1/account/export/full", root, serde_json::Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(data["workspaces"].as_array().unwrap().len(), 2);
    let jobs = st.repo.account_erasure_jobs().await.unwrap().len();
    assert_eq!(
        http(&client, &base, "DELETE", "/v1/account", &jwt, serde_json::Value::Null).await.1["code"],
        "use_explicit_command"
    );
    assert_eq!(
        http(&client, &base, "POST", "/v1/workspace/leave", &jwt, json!({"confirmed_tenant_id":owner.tenant_id}))
            .await
            .0,
        409
    );
    assert_eq!(st.repo.account_erasure_jobs().await.unwrap().len(), jobs);
    assert_eq!(
        http(
            &client,
            &base,
            "POST",
            "/v1/workspace/leave",
            &peer_a.access_token,
            json!({"confirmed_tenant_id":owner.tenant_id})
        )
        .await
        .0,
        204
    );
    assert!(st.repo.account_by_id(&peer.id).await.unwrap().is_some());
    // 外部清扫失败保留 202；恢复存储后由同一持久操作完成。
    store.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        http(&client, &base, "POST", "/v1/workspace/delete", &jwt, json!({"confirmed_tenant_id":owner.tenant_id}))
            .await
            .0,
        202
    );
    store.fail.store(false, Ordering::SeqCst);
    crate::account::cleanup(&st).await.unwrap();
    assert_eq!(
        http(&client, &base, "GET", "/v1/account/export/full", orphan_root, serde_json::Value::Null).await.1["workspaces"],
        json!([])
    );
    assert_eq!(
        http(&client, &base, "GET", "/v1/workspace/export", &orphan_workspace.access_token, serde_json::Value::Null)
            .await
            .0,
        401
    );
    assert_erasure_response(
        &st,
        StatusCode::from_u16(
            http(
                &client,
                &base,
                "POST",
                "/v1/account/close",
                orphan_root,
                json!({"confirmed_user_id":orphan.id,"confirmed_exclusive_workspaces":[]}),
            )
            .await
            .0,
        )
        .unwrap(),
    )
    .await;
    assert_eq!(
        http(
            &client,
            &base,
            "POST",
            "/v1/account/close",
            peer_root,
            json!({"confirmed_user_id":peer.id,"confirmed_exclusive_workspaces":[]})
        )
        .await
        .0,
        409
    );
    let visitor = UserRecord {
        id: new_id(),
        tenant_id: b.id.clone(),
        email: "live-visitor@example.com".into(),
        role: Role::Learner,
        ..owner_user
    };
    st.repo.insert_user(&visitor).await.unwrap();
    let visitor_session = st.services.auth.interactive_response(&visitor).await.unwrap();
    assert_erasure_response(
        &st,
        StatusCode::from_u16(
            http(&client, &base, "DELETE", "/v1/account", &visitor_session.access_token, serde_json::Value::Null)
                .await
                .0,
        )
        .unwrap(),
    )
    .await;
    assert!(st.repo.account_by_id(&visitor.id).await.unwrap().is_none());
    assert!(st.repo.get_tenant(&b.id).await.unwrap().is_some());
    assert_eq!(
        http(&client, &base, "POST", "/v1/workspace/leave", &owner_b.access_token, json!({"confirmed_tenant_id":b.id}))
            .await
            .0,
        204
    );
    assert_erasure_response(
        &st,
        StatusCode::from_u16(
            http(
                &client,
                &base,
                "POST",
                "/v1/account/close",
                root,
                json!({"confirmed_user_id":owner.user_id,"confirmed_exclusive_workspaces":[]}),
            )
            .await
            .0,
        )
        .unwrap(),
    )
    .await;
    store.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        http(&client, &base, "DELETE", "/v1/account", &peer_b.access_token, serde_json::Value::Null).await.0,
        202
    );
    assert!(st.repo.account_by_id(&peer.id).await.unwrap().is_none());
    server.abort();
    let _ = server.await;
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn account_access_owner_routes_and_revocation() {
    use memoswish_protocol::{AccessPage, LoginRequest};
    let (st, dir, jwt) = fixture().await;
    let login = LoginRequest { email: "owner@example.com".into(), password: "password123".into() };
    let root = st.services.auth.login_session(&login).await.unwrap();
    let second = st.services.auth.login_session(&login).await.unwrap();
    let legacy = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let workspace = st.services.auth.select_session_workspace(&root.access_token, &legacy.tenant_id).await.unwrap();
    let token = st.services.auth.create_api_token(&legacy, "safe-name", vec!["*".into()], None).await.unwrap();
    for bearer in [&jwt, &token.plaintext, &workspace.access_token, "lto_at_untrusted"] {
        assert_eq!(request(&st, "GET", "/v1/account/access/sessions", bearer).await.0, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = request(&st, "GET", "/v1/account/access/sessions?limit=1", &root.access_token).await;
    assert_eq!(status, StatusCode::OK);
    let page: AccessPage = serde_json::from_value(body).unwrap();
    assert_eq!(page.items.len(), 1);
    assert!(page.next_cursor.is_some());
    let next = format!("/v1/account/access/sessions?after={}&limit=1", page.next_cursor.unwrap());
    assert_eq!(request(&st, "GET", &next, &root.access_token).await.0, StatusCode::OK);
    let (status, body) = request(&st, "GET", "/v1/account/access/api-tokens", &root.access_token).await;
    assert_eq!(status, StatusCode::OK);
    let page: AccessPage = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(page.items[0].id, token.record.id);
    for secret in [&token.plaintext, &token.record.token_hash, &root.access_token, &root.refresh_token] {
        assert!(!body.to_string().contains(secret));
    }
    assert_eq!(request(&st, "GET", "/v1/account/access/grants", &root.access_token).await.0, StatusCode::OK);
    assert_eq!(
        request(&st, "DELETE", "/v1/account/access/grants/unknown?tenant_id=wrong", &root.access_token).await.0,
        StatusCode::NOT_FOUND
    );
    for (method, uri) in [
        ("GET", "/v1/account/access/%FF"),
        ("DELETE", "/v1/account/access/%FF/id"),
        ("DELETE", "/v1/account/access/sessions/%FF"),
        ("GET", "/v1/account/access/sessions?limit=101"),
        ("GET", "/v1/account/access/sessions?limit=no"),
        ("GET", "/v1/account/access/sessions?after=../x"),
    ] {
        let response = crate::api::router(st.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {}", root.access_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(serde_json::from_slice::<memoswish_protocol::ApiError>(&body).is_ok());
    }
    let uri = format!("/v1/account/access/api-tokens/{}?tenant_id=wrong", token.record.id);
    assert_eq!(request(&st, "DELETE", &uri, &root.access_token).await.0, StatusCode::NOT_FOUND);
    assert!(st.services.auth.authenticate(Some(&token.plaintext)).await.is_ok());
    let captured_token = st.services.auth.authenticate(Some(&token.plaintext)).await.unwrap();
    let captured_session = st.services.auth.authenticate(Some(&workspace.access_token)).await.unwrap();
    let uri = format!("/v1/account/access/api-tokens/{}?tenant_id={}", token.record.id, legacy.tenant_id);
    assert_eq!(request(&st, "DELETE", &uri, &root.access_token).await.0, StatusCode::NO_CONTENT);
    assert!(st.services.auth.authenticate(Some(&token.plaintext)).await.is_err());
    assert_retained_mcp_denied(&st, &captured_token).await;
    assert_revoked_library_denied(&st, &captured_token, &token.plaintext).await;
    let uri = format!("/v1/account/access/sessions/{}", second.session_id);
    assert_eq!(request(&st, "DELETE", &uri, &root.access_token).await.0, StatusCode::NO_CONTENT);
    assert_eq!(request(&st, "DELETE", &uri, &root.access_token).await.0, StatusCode::NO_CONTENT);
    assert!(st.services.auth.refresh_session(&second.refresh_token).await.is_err());
    assert!(st.services.auth.authenticate_account(&root.access_token).await.is_ok());
    let uri = format!("/v1/account/access/sessions/{}", root.session_id);
    assert_eq!(request(&st, "DELETE", &uri, &root.access_token).await.0, StatusCode::NO_CONTENT);
    assert!(st.services.auth.authenticate(Some(&workspace.access_token)).await.is_err());
    assert!(st.services.auth.refresh_session(&root.refresh_token).await.is_err());
    assert!(st.services.auth.require_privacy_collection(&captured_session).await.is_err());
    assert_retained_mcp_denied(&st, &captured_session).await;
    assert_revoked_library_denied(&st, &captured_session, &workspace.access_token).await;
    st.services.auth.require_privacy_collection(&legacy).await.unwrap();
    // 撤销路径复用静态路由观察，不把类别、身份、查询参数或凭据变成标签。
    let metrics =
        String::from_utf8(st.metrics.response(false).into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(
        metrics.contains(
            "memoswish_http_responses_total{route=\"/v1/account/access/{kind}/{id}\",status_class=\"2xx\"} 4"
        )
    );
    assert!(metrics.contains("route=\"/v1/account/access/{kind}\",status_class=\"2xx\""));
    for private in [
        &legacy.user_id,
        &legacy.tenant_id,
        &token.record.id,
        &token.record.token_hash,
        &token.plaintext,
        &root.session_id,
        &second.session_id,
        &root.access_token,
        &root.refresh_token,
    ] {
        assert!(!metrics.contains(private));
    }
    tokio::fs::remove_dir_all(dir).await.unwrap();
}

async fn assert_retained_mcp_denied(st: &AppState, p: &memoswish_core::Principal) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (client, peer) = tokio::io::duplex(64 * 1024);
    let (read, write) = tokio::io::split(peer);
    let mcp = st.mcp.clone();
    let captured = p.clone();
    let task = tokio::spawn(async move { memoswish_mcp::stdio::serve(&mcp, &captured, read, write).await });
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    let init = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"access-test","version":"0"}}});
    write.write_all(format!("{init}\n").as_bytes()).await.unwrap();
    let mut line = String::new();
    assert_ne!(read.read_line(&mut line).await.unwrap(), 0);
    assert!(serde_json::from_str::<serde_json::Value>(&line).unwrap().get("result").is_some());
    write.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();
    for (id, method) in [(2, "tools/call"), (3, "resources/list")] {
        let request =
            serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":{"name":"deck_list","arguments":{}}});
        write.write_all(format!("{request}\n").as_bytes()).await.unwrap();
        line.clear();
        assert_ne!(read.read_line(&mut line).await.unwrap(), 0);
        let result: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(result.get("error").is_some() || result["result"]["isError"] == true);
    }
    write.shutdown().await.unwrap();
    drop(write);
    drop(read);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn account_access_mixed_scope_token_remains_usable() {
    access_mixed_scope_case(None).await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_account_access_mixed_scope_token_remains_usable() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let (database, url) = crate::feature_tests::postgres_database(&owner).await;
        access_mixed_scope_case(Some(url)).await;
        database.cleanup().await;
    });
}

async fn access_mixed_scope_case(database_url: Option<String>) {
    use memoswish_core::{CoreError, Permission};
    let (st, dir, jwt) = fixture_with_database(database_url).await;
    let owner = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let owner_record = st.repo.get_user(&owner.tenant_id, &owner.user_id).await.unwrap().unwrap();
    let admin =
        UserRecord { id: new_id(), email: "admin-access@example.com".into(), role: Role::Admin, ..owner_record };
    st.repo.insert_user(&admin).await.unwrap();
    let account = st
        .services
        .auth
        .login_session(&memoswish_protocol::LoginRequest { email: admin.email.clone(), password: "password123".into() })
        .await
        .unwrap();
    let legacy = st.services.auth.interactive_response(&admin).await.unwrap();
    let principal = st.services.auth.authenticate(Some(&legacy.access_token)).await.unwrap();
    let token = st
        .services
        .auth
        .create_api_token(&principal, "Mixed scopes", vec!["content:read".into(), "billing:manage".into()], None)
        .await
        .unwrap();
    let admitted = st.services.auth.authenticate(Some(&token.plaintext)).await.unwrap();
    admitted.require(Permission::ContentRead).unwrap();
    assert!(matches!(admitted.require(Permission::BillingManage), Err(CoreError::Forbidden(_))));
    assert_eq!(request(&st, "GET", "/v1/decks", &token.plaintext).await.0, StatusCode::OK);
    assert_eq!(
        s6_post(&st, &token.plaintext, "/v1/decks", serde_json::json!({"title":"Denied","language":"en"})).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, body) = request(&st, "GET", "/v1/account/access/api-tokens", &account.access_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["status"], "active");
    assert_eq!(body["items"][0]["scopes"], serde_json::json!(["content:read"]));
    assert_eq!(body["items"][0]["scopes_limited"], true);
    std::fs::remove_dir_all(dir).unwrap();
}

// 撤销后的 HTTP 重放及已捕获主体都必须在读取业务数据前被拒绝。
async fn assert_revoked_library_denied(st: &AppState, p: &memoswish_core::Principal, bearer: &str) {
    use memoswish_protocol::{FavoriteCommand, LibraryQuery};
    for path in ["/v1/library", "/v1/history"] {
        let (status, body) = request(st, "GET", path, bearer).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "unauthorized");
    }
    let command = FavoriteCommand { operation_id: "revoked-replay".into(), desired_state: true, expected_revision: 0 };
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(
            Request::post("/v1/library/missing/favorite")
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&command).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(serde_json::from_slice::<memoswish_protocol::ApiError>(&body).unwrap().code, "unauthorized");
    assert_eq!(st.services.library_page(p, &LibraryQuery::default()).await.unwrap_err().http_status(), 401);
    assert_eq!(st.services.review_history(p, &LibraryQuery::default()).await.unwrap_err().http_status(), 401);
    assert_eq!(st.services.set_favorite(p, "missing", &command).await.unwrap_err().http_status(), 401);
}
