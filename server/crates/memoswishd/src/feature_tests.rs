//! 独立认证能力与付费策略的组装回归。
use crate::{app::AppState, config::Config};
use memoswish_auth::Metric;
use memoswish_protocol::{DeploymentMode, RegisterRequest};

#[tokio::test]
async fn feature_matrix_quota_selection_and_metering_are_independent_of_authentication() {
    for mode in [DeploymentMode::SingleUser, DeploymentMode::MultiTenant] {
        let dir = std::env::temp_dir().join(format!("memoswish-e2-{}", memoswish_core::ids::new_id()));
        let cfg =
            Config { mode, data_dir: dir.clone(), seed_demo: false, registration_open: true, ..Config::default() };
        let st = AppState::build(cfg).await.unwrap();
        let p = if mode == DeploymentMode::SingleUser {
            st.services.auth.authenticate(None).await.unwrap()
        } else {
            let auth = st
                .services
                .auth
                .register(&RegisterRequest {
                    email: "quota@example.com".into(),
                    password: "strong-password-123".into(),
                    display_name: "Quota".into(),
                    tenant_name: None,
                })
                .await
                .unwrap();
            st.services.auth.authenticate(Some(&auth.access_token)).await.unwrap()
        };
        let paid = cfg!(feature = "commercial-quota") && mode == DeploymentMode::MultiTenant;
        assert_eq!(st.services.quota.name(), if paid { "plan" } else { "unlimited" });
        for (plan, limit) in [("free", 1_000), ("pro", 50_000), ("team", 500_000)] {
            let mut tenant = st.repo.get_tenant(&p.tenant_id).await.unwrap().unwrap();
            tenant.plan = plan.into();
            st.repo.upsert_tenant(&tenant).await.unwrap();
            let before = st.services.quota.snapshot(&p).await.unwrap();
            let metric = before.metrics.iter().find(|m| m.metric == "mcp_calls").unwrap();
            assert_eq!(metric.limit, if paid { Some(limit) } else { None });
            // 同一租户保留已记录用量，OSS 即使套餐名为 free 也不执行付费上限。
            let amount = limit - metric.used + 1;
            let result = st.services.quota.consume(&p, Metric::McpCalls, amount).await;
            if paid {
                assert!(matches!(result, Err(memoswish_core::CoreError::QuotaExceeded(_))));
                assert_eq!(st.services.quota.snapshot(&p).await.unwrap(), before);
                st.services.quota.consume(&p, Metric::McpCalls, 1).await.unwrap();
            } else {
                result.unwrap();
                let after = st.services.quota.snapshot(&p).await.unwrap();
                assert_eq!(after.metrics.iter().find(|m| m.metric == "mcp_calls").unwrap().used, limit + 1);
            }
        }
        assert!(!st.config.oauth.enabled && !st.config.oidc.enabled);
        assert!(st.server_info().oidc_providers.is_empty());
        crate::runtime::cleanup_test_app(dir, &[&st]).await;
    }
}

#[tokio::test]
async fn feature_matrix_runtime_requirements_fail_before_creating_data() {
    for (capability, compiled) in [("mcp-oauth", cfg!(feature = "mcp-oauth")), ("oidc", cfg!(feature = "oidc"))] {
        let dir = std::env::temp_dir().join(format!("memoswish-e2-invalid-{}", memoswish_core::ids::new_id()));
        let mut cfg = Config { data_dir: dir.clone(), mode: DeploymentMode::MultiTenant, ..Config::default() };
        if capability == "mcp-oauth" {
            cfg.oauth.enabled = true;
        } else {
            cfg.oidc.enabled = true;
        }
        if compiled {
            cfg.mode = DeploymentMode::SingleUser;
        }
        let error = AppState::build(cfg.clone()).await.err().unwrap().to_string();
        assert!(error.contains(if compiled { "multi_tenant" } else { capability }), "{error}");
        assert!(!dir.exists());
        if compiled {
            cfg.mode = DeploymentMode::MultiTenant;
            if capability == "mcp-oauth" {
                cfg.mcp.http_enabled = false;
            }
            assert!(AppState::build(cfg.clone()).await.is_err());
            assert!(!dir.exists());
            cfg.mcp.http_enabled = true;
            // 已编译仍拒绝无效 URL、密钥与提供者配置。
            assert!(AppState::build(cfg).await.is_err());
            assert!(!dir.exists());
        }
    }
}

#[test]
fn feature_matrix_reports_capabilities_and_preserves_alias_bundle() {
    let features = crate::app::compiled_features();
    for (name, enabled) in [
        ("mcp-oauth", cfg!(feature = "mcp-oauth")),
        ("oidc", cfg!(feature = "oidc")),
        ("commercial-quota", cfg!(feature = "commercial-quota")),
    ] {
        assert_eq!(features.iter().any(|f| f == name), enabled);
    }
    if cfg!(feature = "commercial-saas") {
        for name in ["mcp-oauth", "oidc", "commercial-quota", "postgres", "s3"] {
            assert!(features.iter().any(|f| f == name), "{name}");
        }
    }
}

// 借助既有夹具创建 schema，再将其受保护连接参数传给真实 daemon 组装。
#[cfg(feature = "postgres")]
pub(crate) async fn postgres_database(
    owner: &memoswish_storage::pg_test_support::PgTest,
) -> (memoswish_storage::pg_test_support::PgFixture, String) {
    let raw =
        crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("MEMOSWISH_TEST_POSTGRES_URL is required");
    let fixture = owner.fixture(&raw).await;
    let repo = fixture.repository(2).await.unwrap();
    let schema: String = sqlx::query_scalar("SELECT current_schema()").fetch_one(repo.pool()).await.unwrap();
    let mut url = url::Url::parse(&raw).unwrap();
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"))
        .append_pair("application_name", &schema);
    repo.pool().close().await;
    (fixture, url.into())
}

#[tokio::test]
async fn feature_matrix_disabled_oidc_preserves_pending_account_only_revocation() {
    let dir = std::env::temp_dir().join(format!("memoswish-e2-pending-{}", memoswish_core::ids::new_id()));
    let cfg = Config { data_dir: dir.clone(), seed_demo: false, ..Config::default() };
    let st = AppState::build(cfg.clone()).await.unwrap();
    let key = "tenants/local/keep.wav";
    st.store.put(key, b"keep".to_vec(), "audio/wav").await.unwrap();
    let job = memoswish_core::identity::ErasureJob {
        id: memoswish_core::ids::new_id(),
        tenant_id: None,
        purge_assets: false,
        credentials: vec![("legacy-provider".into(), "synthetic-encrypted-credential".into())],
    };
    // 模拟旧商业构建留下的持久任务；不修改 schema 或真实密钥。
    let db = memoswish_storage::sqlite::SqliteRepository::connect(&cfg.database_url()).await.unwrap();
    sqlx::query("INSERT INTO account_erasure_jobs (id, body) VALUES (?, ?)")
        .bind(&job.id)
        .bind(serde_json::to_string(&job).unwrap())
        .execute(db.pool())
        .await
        .unwrap();
    db.pool().close().await;
    crate::runtime::drain_test_state(&st).await;
    drop(st);
    let restarted = AppState::build(cfg).await.unwrap();
    assert!(crate::account::finish(&restarted, &job).await.is_err());
    crate::account::cleanup(&restarted).await.unwrap();
    let pending = restarted.repo.account_erasure_jobs().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(serde_json::to_value(&pending[0]).unwrap(), serde_json::to_value(&job).unwrap());
    assert_eq!(restarted.store.get(key).await.unwrap().unwrap().bytes, b"keep");
    crate::runtime::cleanup_test_app(dir, &[&restarted]).await;
}
