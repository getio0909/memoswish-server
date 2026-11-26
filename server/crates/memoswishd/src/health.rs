//! 运维探针只返回固定状态；有界且串行的依赖采样不泄露安装或租户内容。
use crate::{
    Config,
    app::AppState,
    lifecycle::{Lifecycle, Phase},
};
use axum::{Router, extract::State, http::StatusCode, routing::get};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(crate) struct Health {
    pub(crate) lifecycle: Arc<Lifecycle>,
    dependencies: Arc<Mutex<Option<Dependencies>>>,
    metrics: Arc<Mutex<Option<Arc<crate::metrics::Metrics>>>>,
    permits: Arc<tokio::sync::Semaphore>,
    timeout: std::time::Duration,
    probe_key: Arc<str>,
}
#[derive(Clone)]
struct Dependencies {
    repo: Arc<dyn memoswish_core::repo::Repository>,
    store: Arc<dyn memoswish_core::store::ObjectStore>,
    limiters: Vec<(Arc<dyn memoswish_core::rate_limit::RateLimiter>, memoswish_core::rate_limit::FailureMode)>,
    horizontal: bool,
    migrator: bool,
}

impl Health {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            lifecycle: Arc::new(Lifecycle::new(config.object_store.put_shutdown_timeout_secs)),
            dependencies: Default::default(),
            metrics: Default::default(),
            timeout: std::time::Duration::from_millis(config.admission.timeout_ms),
            permits: Arc::new(tokio::sync::Semaphore::new(1)),
            probe_key: memoswish_core::ids::new_id().into(),
        }
    }
    pub(crate) fn attach(&self, st: &AppState) -> anyhow::Result<()> {
        *self.metrics.lock().unwrap() = Some(st.metrics.clone());
        let mut limiters = vec![];
        if st.config.admission.backend == "redis" {
            // 探针键按副本隔离，不消耗用户额度；策略仍使用各入口的 fail-open/closed 配置。
            let mut classes = vec![];
            if st.config.role.serves() {
                classes.push(("auth", st.config.admission.auth_failure));
                if st.config.oauth.enabled {
                    classes.push(("oauth", st.config.admission.oauth_failure));
                }
                if st.config.oidc.enabled {
                    classes.push(("oidc", st.config.admission.oidc_failure));
                }
            }
            if st.config.role.serves() || st.config.role.executes() {
                classes.push(("work", st.config.admission.work_failure));
            }
            for (class, failure) in classes {
                limiters.push((
                    crate::admission::build(&st.config.admission, &format!("probe-{class}"), 120, 4.0, failure)?,
                    failure,
                ));
            }
        }
        *self.dependencies.lock().unwrap() = Some(Dependencies {
            repo: st.repo.clone(),
            store: st.store.clone(),
            limiters,
            migrator: st.config.role == crate::deployment::Role::Migrator,
            horizontal: st.config.profile == crate::deployment::Profile::Horizontal,
        });
        Ok(())
    }
    pub(crate) fn internal_router(&self) -> Router {
        Router::new().route("/metrics", get(full_metrics)).with_state(self.clone()).merge(self.router())
    }
    pub(crate) fn router(&self) -> Router {
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/livez", get(live))
            .route("/startupz", get(startup))
            .route("/readyz", get(ready))
            .with_state(self.clone())
    }
}
async fn live(State(h): State<Health>) -> (StatusCode, &'static str) {
    if matches!(h.lifecycle.phase(), Phase::Failed | Phase::Stopped) {
        (StatusCode::SERVICE_UNAVAILABLE, "stopped")
    } else {
        (StatusCode::OK, "ok")
    }
}
async fn startup(State(h): State<Health>) -> (StatusCode, &'static str) {
    if matches!(h.lifecycle.phase(), Phase::Running | Phase::Draining) {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "starting")
    }
}
async fn ready(State(h): State<Health>) -> (StatusCode, &'static str) {
    if h.lifecycle.phase() != Phase::Running {
        return (StatusCode::SERVICE_UNAVAILABLE, "not_running");
    }
    let Ok(_permit) = h.permits.try_acquire() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "busy");
    };
    let dependencies = h.dependencies.lock().unwrap().clone();
    let Some(d) = dependencies else {
        return (StatusCode::SERVICE_UNAVAILABLE, "starting");
    };
    let deadline = tokio::time::Instant::now() + h.timeout;
    let database_and_store = async {
        // 只读固定租户键；是否存在不影响 DB 健康，不返回业务数据。
        d.repo.get_tenant("local").await?;
        if d.horizontal {
            let marker = d.store.read_legacy("shared/deployment-v1.sha256", 128).await?;
            if marker.is_none() && !d.migrator {
                return Err(memoswish_core::CoreError::Unavailable("bootstrap unavailable".into()));
            }
        }
        Ok::<(), memoswish_core::CoreError>(())
    };
    if !matches!(tokio::time::timeout_at(deadline, database_and_store).await, Ok(Ok(()))) {
        return (StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable");
    }
    for (limiter, failure) in d.limiters {
        let available = if tokio::time::Instant::now() >= deadline {
            matches!(failure, memoswish_core::rate_limit::FailureMode::Open)
        } else {
            match tokio::time::timeout_at(deadline, limiter.check(&h.probe_key, 1.0)).await {
                // 耗尽探针额度也证明 Redis 已成功执行脚本，不能误判为依赖不可用。
                Ok(Ok(()) | Err(memoswish_core::CoreError::QuotaExceeded(_))) => true,
                Ok(Err(_)) => false,
                Err(_) => matches!(failure, memoswish_core::rate_limit::FailureMode::Open),
            }
        };
        if !available {
            return (StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable");
        }
    }
    if h.lifecycle.phase() == Phase::Running {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not_running")
    }
}

pub(crate) struct ProbeServer {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}
impl ProbeServer {
    pub(crate) async fn start(config: &Config, health: Health) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind(&config.health_bind)
            .await
            .map_err(|_| anyhow::anyhow!("cannot bind health listener"))?;
        tracing::info!(target: "memoswish::health", address = %listener.local_addr()?, "Health listener ready");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let lifecycle = health.lifecycle.clone();
        let task = tokio::spawn(crate::lifecycle::serve(
            listener,
            health.internal_router(),
            async {
                let _ = stopped.await;
            },
            lifecycle,
        ));
        Ok(Self { stop: Some(stop), task: Some(task) })
    }
    pub(crate) async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
impl Drop for ProbeServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use memoswish_core::rate_limit::FailureMode;
    use memoswish_storage::sqlite::SqliteRepository;
    use tower::ServiceExt;

    async fn state(config: Config) -> (AppState, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("s26b-probe-{}", memoswish_core::ids::new_id()));
        let st = AppState::build(Config { data_dir: root.clone(), seed_demo: false, ..config }).await.unwrap();
        (st, root)
    }
    #[tokio::test]
    async fn every_role_has_distinct_startup_liveness_readiness_and_draining_states() {
        let (mut st, root) = state(Config::default()).await;
        for role in [
            crate::deployment::Role::AllInOne,
            crate::deployment::Role::Api,
            crate::deployment::Role::Worker,
            crate::deployment::Role::Maintenance,
            crate::deployment::Role::Migrator,
        ] {
            // 使用本地依赖夹具测试角色选择；真实 PG/S3/Redis 交接由 deployment_tests 集成层覆盖。
            let config = Config {
                role,
                profile: if role == crate::deployment::Role::AllInOne {
                    crate::deployment::Profile::Embedded
                } else {
                    crate::deployment::Profile::Horizontal
                },
                ..(*st.config).clone()
            };
            st.config = Arc::new(config.clone());
            let h = Health::new(&config);
            h.attach(&st).unwrap();
            {
                let dependencies = h.dependencies.lock().unwrap();
                let d = dependencies.as_ref().unwrap();
                assert_eq!(d.horizontal, role != crate::deployment::Role::AllInOne);
                assert_eq!(d.migrator, role == crate::deployment::Role::Migrator);
                assert!(d.limiters.is_empty());
            }
            assert_eq!(live(State(h.clone())).await.0, StatusCode::OK);
            assert_eq!(startup(State(h.clone())).await.0, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(ready(State(h.clone())).await.0, StatusCode::SERVICE_UNAVAILABLE);
            h.lifecycle.set(Phase::Running);
            assert_eq!(startup(State(h.clone())).await.0, StatusCode::OK);
            if role != crate::deployment::Role::AllInOne && role != crate::deployment::Role::Migrator {
                assert_eq!(
                    ready(State(h.clone())).await.0,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "runtime requires bootstrap marker"
                );
                st.store.put("shared/deployment-v1.sha256", b"fixture".to_vec(), "text/plain").await.unwrap();
            }
            assert_eq!(ready(State(h.clone())).await.0, StatusCode::OK);
            if role != crate::deployment::Role::AllInOne && role != crate::deployment::Role::Migrator {
                st.store.delete("shared/deployment-v1.sha256").await.unwrap();
            }
            h.lifecycle.drain();
            assert_eq!(live(State(h.clone())).await.0, StatusCode::OK);
            assert_eq!(startup(State(h.clone())).await.0, StatusCode::OK);
            assert_eq!(ready(State(h.clone())).await.0, StatusCode::SERVICE_UNAVAILABLE);
            h.lifecycle.set(Phase::Failed);
            assert_eq!(live(State(h.clone())).await.0, StatusCode::SERVICE_UNAVAILABLE);
            h.lifecycle.set(Phase::Stopped);
            assert_eq!(live(State(h.clone())).await.0, StatusCode::SERVICE_UNAVAILABLE);
            let response = h
                .router()
                .oneshot(axum::http::Request::get("/healthz").body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        crate::runtime::drain_background(&st).await;
        crate::runtime::cleanup_test_app(root, &[&st]).await;
    }
    #[cfg(feature = "redis")]
    #[tokio::test]
    async fn role_dependencies_select_only_applicable_redis_classes() {
        let (mut st, root) = state(Config::default()).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        for (role, count) in [
            (crate::deployment::Role::AllInOne, 4),
            (crate::deployment::Role::Api, 4),
            (crate::deployment::Role::Worker, 1),
            (crate::deployment::Role::Maintenance, 0),
            (crate::deployment::Role::Migrator, 0),
        ] {
            let mut config = (*st.config).clone();
            config.role = role;
            config.admission.backend = "redis".into();
            config.admission.redis_url = Some(format!("redis://{}", listener.local_addr().unwrap()));
            config.admission.auth_failure = FailureMode::Closed;
            config.admission.oauth_failure = FailureMode::Open;
            config.admission.oidc_failure = FailureMode::Closed;
            config.admission.work_failure = FailureMode::Open;
            config.oauth.enabled = true;
            config.oidc.enabled = true;
            st.config = Arc::new(config.clone());
            let h = Health::new(&config);
            h.attach(&st).unwrap();
            let dependencies = h.dependencies.lock().unwrap();
            let failures: Vec<_> =
                dependencies.as_ref().unwrap().limiters.iter().map(|(_, f)| matches!(f, FailureMode::Open)).collect();
            assert_eq!(failures.len(), count, "wrong dependency classes for {role:?}");
            if count == 4 {
                assert_eq!(failures, vec![false, true, false, true]);
            } else if count == 1 {
                assert_eq!(failures, vec![true]);
            }
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept()).await.is_err(),
            "dependency assembly is side-effect-free"
        );
        crate::runtime::drain_background(&st).await;
        crate::runtime::cleanup_test_app(root, &[&st]).await;
    }
    #[tokio::test]
    async fn database_failure_unreadies_without_exposing_details_or_changing_liveness() {
        let (st, root) = state(Config::default()).await;
        let repo = Arc::new(SqliteRepository::in_memory().await.unwrap());
        st.health.dependencies.lock().unwrap().as_mut().unwrap().repo = repo.clone();
        assert_eq!(ready(State(st.health.clone())).await.0, StatusCode::OK);
        repo.pool().close().await;
        assert_eq!(ready(State(st.health.clone())).await, (StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable"));
        assert_eq!(live(State(st.health.clone())).await.0, StatusCode::OK);
        crate::runtime::drain_background(&st).await;
        crate::runtime::cleanup_test_app(root, &[&st]).await;
    }
    struct Blocked;
    #[async_trait::async_trait]
    impl memoswish_core::rate_limit::RateLimiter for Blocked {
        async fn check(&self, _: &str, _: f64) -> memoswish_core::CoreResult<()> {
            std::future::pending().await
        }
    }
    #[tokio::test]
    async fn probe_timeout_and_concurrent_sampling_are_bounded() {
        let (st, root) = state(Config::default()).await;
        tokio::time::pause();
        st.health.dependencies.lock().unwrap().as_mut().unwrap().limiters =
            vec![(Arc::new(Blocked), FailureMode::Closed)];
        let h = st.health.clone();
        let first = tokio::spawn(ready(State(h.clone())));
        while h.permits.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(ready(State(h.clone())).await, (StatusCode::SERVICE_UNAVAILABLE, "busy"));
        tokio::time::advance(h.timeout).await;
        assert_eq!(first.await.unwrap(), (StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable"));
        assert_eq!(h.permits.available_permits(), 1);
        crate::runtime::drain_background(&st).await;
        crate::runtime::cleanup_test_app(root, &[&st]).await;
    }
    #[cfg(feature = "redis")]
    #[tokio::test]
    #[ignore = "integration: requires disposable Redis"]
    async fn shared_redis_probe_budgets_isolate_replicas_and_floods_remain_ready() {
        let redis_url = crate::test_environment::var("MEMOSWISH_TEST_REDIS_URL").expect("disposable Redis is required");
        let url = url::Url::parse(&redis_url).unwrap();
        assert!(matches!(url.host_str(), Some("127.0.0.1")));
        assert!((6380..=6399).contains(&url.port().expect("explicit disposable Redis port is required")));
        let (mut st, root) = state(Config::default()).await;
        let mut config = (*st.config).clone();
        config.admission.backend = "redis".into();
        config.admission.redis_url = Some(redis_url);
        config.admission.namespace = format!("s26b-probe-{}", memoswish_core::ids::new_id());
        st.config = Arc::new(config.clone());
        let replicas: Vec<_> = (0..2)
            .map(|_| {
                let health = Health::new(&config);
                health.attach(&st).unwrap();
                health.lifecycle.set(Phase::Running);
                health
            })
            .collect();
        assert_ne!(replicas[0].probe_key, replicas[1].probe_key);
        assert_eq!(replicas[0].probe_key, replicas[0].clone().probe_key);
        // 同一部署、类别和 Redis 后端；每个副本仍可独立使用完整额度。
        for replica in &replicas {
            let dependencies = replica.dependencies.lock().unwrap().clone().unwrap();
            for (limiter, _) in dependencies.limiters {
                limiter.check(&replica.probe_key, 120.0).await.unwrap();
                assert!(matches!(
                    limiter.check(&replica.probe_key, 120.0).await,
                    Err(memoswish_core::CoreError::QuotaExceeded(_))
                ));
            }
        }
        // 超过原共享 burst 的连续采样不能把成功的 Redis 交互解释为故障。
        for _ in 0..130 {
            for replica in &replicas {
                assert_eq!(ready(State(replica.clone())).await, (StatusCode::OK, "ok"));
                assert_eq!(replica.permits.available_permits(), 1);
            }
        }
        crate::runtime::drain_background(&st).await;
        crate::runtime::cleanup_test_app(root, &[&st]).await;
    }
    #[cfg(feature = "redis")]
    #[tokio::test]
    async fn redis_readiness_respects_each_route_failure_policy_and_ignores_optional_providers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut st, root) = state(Config::default()).await;
        let mut config = (*st.config).clone();
        config.admission.backend = "redis".into();
        config.admission.redis_url = Some(format!("redis://{}", listener.local_addr().unwrap()));
        config.admission.timeout_ms = 20;
        config.ai.base_url = Some("http://127.0.0.1:1".into());
        config.ai.api_key = Some("S26B_CREDENTIAL_SENTINEL".into());
        for (work, auth, expected) in [
            (FailureMode::Open, FailureMode::Open, StatusCode::OK),
            (FailureMode::Closed, FailureMode::Open, StatusCode::SERVICE_UNAVAILABLE),
            (FailureMode::Open, FailureMode::Closed, StatusCode::SERVICE_UNAVAILABLE),
        ] {
            config.admission.work_failure = work;
            config.admission.auth_failure = auth;
            st.config = Arc::new(config.clone());
            let h = Health::new(&config);
            h.attach(&st).unwrap();
            h.lifecycle.set(Phase::Running);
            // 每个 Redis 类别本身可能耗尽预算，整次预算不因类别数而叠加。
            let result = ready(State(h.clone())).await;
            assert_eq!(result.0, expected);
        }
        crate::runtime::drain_background(&st).await;
        crate::runtime::cleanup_test_app(root, &[&st]).await;
    }
}

async fn full_metrics(State(h): State<Health>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let metrics = h.metrics.lock().unwrap().clone();
    match metrics {
        Some(metrics) => metrics.response(false),
        None => (StatusCode::SERVICE_UNAVAILABLE, "metrics starting").into_response(),
    }
}
