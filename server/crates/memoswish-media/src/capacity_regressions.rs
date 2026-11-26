//! 本地容量拒绝不能伪造外部尝试或在重试耗尽后留下额度。
use crate::{
    MediaService,
    tts::{
        EXECUTIONS,
        command::{CommandTts, CommandTtsConfig},
        http::{HttpTts, HttpTtsConfig},
        placeholder::PlaceholderTts,
    },
};
use memoswish_auth::{AuthConfig, AuthService, QuotaPolicy, Unlimited};
use memoswish_core::{
    Principal,
    repo::Repository,
    tts::{SpeechWork, TtsEngine, TtsRequest},
};
use memoswish_storage::{LocalDiskStore, sqlite::SqliteRepository};
use std::sync::Arc;

async fn saturated_recovery<F: Future<Output = ()>>(repo: Arc<dyn Repository>, elapse: impl Fn(String, String) -> F) {
    AuthService::new(
        repo.clone(),
        AuthConfig {
            mode: memoswish_protocol::DeploymentMode::SingleUser,
            jwt_secret: "k".repeat(32),
            jwt_ttl_secs: 3600,
            registration_open: false,
            default_plan: "self_hosted".into(),
        },
    )
    .unwrap()
    .bootstrap_local()
    .await
    .unwrap();
    let dir = std::env::temp_dir().join(format!("p39-capacity-{}", memoswish_core::ids::new_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let marker = dir.join("provider-called");
    let engines: Vec<Arc<dyn TtsEngine>> = vec![
        Arc::new(HttpTts::new(HttpTtsConfig {
            endpoint: format!("http://{}/speech", listener.local_addr().unwrap()),
            ..Default::default()
        })),
        Arc::new(CommandTts::new(CommandTtsConfig {
            id: "command".into(),
            program: "/usr/bin/touch".into(),
            args: vec![marker.to_string_lossy().into_owned()],
            text_via_stdin: false,
            default_voice: "default".into(),
            timeout_secs: 30,
            external_transfer: false,
        })),
        Arc::new(PlaceholderTts),
    ];
    let p = Principal::local_owner("single_user");
    let mut policy =
        memoswish_protocol::PrivacyPolicy { hosted: false, ..memoswish_protocol::examples::sample_privacy_policy() };
    policy.purpose_versions.insert("external_tts".into(), "provider-policy-v1".into());
    repo.privacy_install_policy(&policy).await.unwrap();
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_tts", "provider-policy-v1", ""),
    ] {
        let state = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
        repo.privacy_update(
            &p.tenant_id,
            &p,
            &policy,
            &memoswish_protocol::PrivacyUpdate {
                expected_revision: state.revision,
                kind: kind.into(),
                version: version.into(),
                decision: true,
                value: value.into(),
            },
        )
        .await
        .unwrap();
    }
    // 同一生产 semaphore 的四个许可保持到三个引擎全部耗尽，不借助 provider 调用占位。
    let held = EXECUTIONS.acquire_many(4).await.unwrap();
    for engine in engines {
        let quota = Arc::new(Unlimited::metered(repo.clone()));
        let media = MediaService::new(
            repo.clone(),
            Arc::new(LocalDiskStore::new(&dir, "/assets")),
            quota.clone(),
            vec![engine.clone()],
            engine.id(),
        )
        .unwrap()
        .with_privacy_policy(policy.clone());
        let privacy = if engine.external_transfer() {
            Some(memoswish_core::privacy::PrivacyFence {
                principal: p.clone(),
                credential_hash: None,
                policy: policy.clone(),
                revision: repo.privacy_admit(&p.tenant_id, &p, &policy, Some("external_tts"), None).await.unwrap(),
            })
        } else {
            None
        };
        let work = SpeechWork {
            provenance: None,
            privacy,
            engine: engine.id().into(),
            namespace: engine.cache_namespace(),
            request: TtsRequest { text: "hello".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
            amount: 5,
            legacy_output: None,
        };
        let accepted = repo.accept_speech(&p, &work, None, None).await.unwrap();
        for attempt in 0..5 {
            elapse(p.tenant_id.clone(), accepted.synthesis_id.clone()).await;
            let error = media.recover_speech_job(&p.tenant_id, &accepted.synthesis_id).await.unwrap_err();
            assert!(error.to_string().contains("capacity exhausted"));
            let snapshot = quota.snapshot(&p).await.unwrap();
            let quota = snapshot.metrics.iter().find(|m| m.metric == "tts_chars").unwrap();
            assert_eq!((quota.used, quota.held, quota.uncertain), (0, if attempt == 4 { 0 } else { 5 }, 0));
        }
        assert_eq!(repo.speech_request(&p.tenant_id, &accepted.id).await.unwrap().outcome, "failed");
        // 新实例恢复已耗尽工作也不会获得外部调用责任。
        media.recover_speech_job(&p.tenant_id, &accepted.synthesis_id).await.unwrap();
    }
    assert!(
        matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "zero HTTP provider calls"
    );
    assert!(!marker.exists(), "zero command provider calls");
    drop(held);
    assert_eq!(EXECUTIONS.available_permits(), 4);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sqlite_capacity_exhaustion_releases_quota_without_provider_attempt() {
    let repo = Arc::new(SqliteRepository::in_memory().await.unwrap());
    saturated_recovery(repo.clone(), |tenant,id| {
            let repo=repo.clone();
            async move {
                // 容量错误尚未外调；显式推进单项期限再验证原耗尽与计量断言。
                sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2 AND state='queued'").bind(tenant).bind(id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
            }
        }).await;
    let attempts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tts_provider_attempts").fetch_one(repo.pool()).await.unwrap();
    assert_eq!(attempts, 0);
}

#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
fn postgres_capacity_exhaustion_releases_quota_without_provider_attempt() {
    memoswish_storage::pg_test_support::run_pg_test(|test| async move {
        let fixture = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let repo = Arc::new(fixture.repository(2).await.unwrap());
        saturated_recovery(repo.clone(), |tenant,id| {
            let repo=repo.clone();
            async move {
                // 容量错误尚未外调；显式推进单项期限再验证原耗尽与计量断言。
                sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2 AND state='queued'").bind(tenant).bind(id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
            }
        }).await;
        let attempts: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tts_provider_attempts").fetch_one(repo.pool()).await.unwrap();
        assert_eq!(attempts, 0);
    });
}

#[tokio::test]
async fn prepared_execution_owns_capacity_before_dispatch_and_releases_on_drop() {
    let request = TtsRequest { text: "hello".into(), language: "en".into(), voice: "default".into(), speed: 1.0 };
    let engine = PlaceholderTts;
    let mut prepared = Vec::new();
    for _ in 0..4 {
        prepared.push(engine.prepare_execution(&request).await.unwrap());
    }
    assert_eq!(EXECUTIONS.available_permits(), 0);
    assert!(engine.prepare_execution(&request).await.is_err());
    drop(prepared);
    assert_eq!(EXECUTIONS.available_permits(), 4);
    engine.synthesize(&request).await.unwrap();
    assert_eq!(EXECUTIONS.available_permits(), 4);
}
