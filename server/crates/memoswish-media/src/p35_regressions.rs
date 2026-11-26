//! 通过媒体服务入口验证旧式目录写入与独立 API/worker 错误重放。
use super::*;
use memoswish_auth::{AuthConfig, AuthService, Unlimited};
use memoswish_core::tts::{SpeechFailure, TtsOutput, TtsRequest};
use memoswish_storage::{LocalDiskStore, sqlite::SqliteRepository};

async fn bootstrap(repo: Arc<dyn Repository>) {
    AuthService::new(
        repo,
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
}

async fn bgm_legacy_writes(repo: Arc<dyn Repository>) {
    bootstrap(repo.clone()).await;
    let dir = std::env::temp_dir().join(format!("p35-lww-{}", memoswish_core::ids::new_id()));
    let media = MediaService::new(
        repo,
        Arc::new(LocalDiskStore::new(&dir, "/assets")),
        Arc::new(Unlimited::new()),
        vec![Arc::new(crate::tts::placeholder::PlaceholderTts)],
        "placeholder",
    )
    .unwrap();
    let p = Principal::local_owner("test");
    let bytes = crate::wav::encode_wav(&vec![0.25; 8000], 8000);
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut published = Vec::new();
    for (title, revision) in [("A", 1), ("B", 2), ("A", 3)] {
        let track = media.upload_bgm(&p, title, vec![], 0.3, 90, &encoded, "CC0").await.unwrap();
        assert_eq!(track.title, title);
        assert_eq!(track.revision, revision);
        assert_eq!(media.repo.get_bgm(&p.tenant_id, &track.id).await.unwrap().unwrap().revision, revision);
        published.push(track);
    }
    assert_eq!(published[0].id, published[2].id);
    assert_ne!(published[0].asset.key, published[2].asset.key);
    let command = memoswish_protocol::BgmClip {
        request_id: "explicit-clip".into(),
        track_id: published[2].id.clone(),
        start_frame: 0,
        end_frame: 8000,
        title: Some("Identified".into()),
    };
    let identified = media.clip_bgm(&p, &command).await.unwrap();
    let replacement = media.upload_bgm(&p, "Later", vec![], 0.4, 95, &encoded, "CC0").await.unwrap();
    assert_eq!(replacement.revision, 4);
    assert_eq!(media.clip_bgm(&p, &command).await.unwrap(), identified);
    let changed = memoswish_protocol::BgmClip { title: Some("Changed command".into()), ..command };
    assert!(matches!(media.clip_bgm(&p, &changed).await, Err(CoreError::Conflict(_))));
    assert_eq!(media.repo.get_bgm(&p.tenant_id, &replacement.id).await.unwrap().unwrap().title, "Later");
    drop(media);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sqlite_bgm_legacy_a_b_a_and_explicit_request_replay() {
    bgm_legacy_writes(Arc::new(SqliteRepository::in_memory().await.unwrap())).await;
}

#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_bgm_legacy_a_b_a_and_explicit_request_replay() {
    memoswish_storage::pg_test_support::run_pg_test(|test| async move {
        let fixture = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let repo = Arc::new(fixture.repository(2).await.unwrap());
        bgm_legacy_writes(repo.clone()).await;
        repo.pool().close().await;
        fixture.cleanup().await;
    });
}

async fn bgm_write(
    media: &MediaService,
    p: &Principal,
    generated: bool,
    label: &str,
    encoded: &str,
    expected: Option<u32>,
) -> CoreResult<BgmTrack> {
    let moods = vec![label.into()];
    if generated {
        // 生成曲目的标题参与目录 ID，因此用 moods 改变同一曲目的命令正文。
        media.generate_bgm_if_revision(p, "Generated CAS", moods, 0.3, 90, expected).await
    } else {
        media.upload_bgm_if_revision(p, label, moods, 0.3, 90, encoded, "CC0", expected).await
    }
}

async fn bgm_current_cas(repo: Arc<dyn Repository>) {
    bootstrap(repo.clone()).await;
    let dir = std::env::temp_dir().join(format!("p35-cas-{}", memoswish_core::ids::new_id()));
    let media = MediaService::new(
        repo,
        Arc::new(LocalDiskStore::new(&dir, "/assets")),
        Arc::new(Unlimited::new()),
        vec![Arc::new(crate::tts::placeholder::PlaceholderTts)],
        "placeholder",
    )
    .unwrap();
    let p = Principal::local_owner("test");
    let encoded = base64::engine::general_purpose::STANDARD.encode(crate::wav::encode_wav(&vec![0.5; 8000], 8000));
    for generated in [false, true] {
        // 复现审查交错：A/1 → A/2（CAS 1）→ B/3 → 重复 A（CAS 1）必须冲突。
        let initial = bgm_write(&media, &p, generated, "A", &encoded, None).await.unwrap();
        assert_eq!(initial.revision, 1);
        let accepted = bgm_write(&media, &p, generated, "A", &encoded, Some(1)).await.unwrap();
        assert_eq!(accepted.revision, 2);
        let current = bgm_write(&media, &p, generated, "B", &encoded, None).await.unwrap();
        assert_eq!(current.id, initial.id);
        assert_eq!(current.revision, 3);
        let stale = bgm_write(&media, &p, generated, "A", &encoded, Some(1)).await.unwrap_err();
        assert!(matches!(&stale, CoreError::Conflict(_)));
        assert_eq!(stale.to_string(), "conflict: revision mismatch; current revision 3");
        assert_eq!(stale.public_message(), "resource conflict; current revision 3");
        assert_eq!(media.repo.get_bgm(&p.tenant_id, &initial.id).await.unwrap().unwrap().moods, vec!["B"]);
        assert_eq!(media.repo.get_bgm(&p.tenant_id, &initial.id).await.unwrap().unwrap().revision, 3);

        // 失败命令不是永久身份；前提随后成立时，相同正文必须重新接受并发布。
        let future = bgm_write(&media, &p, generated, "C", &encoded, Some(4)).await.unwrap_err();
        assert!(matches!(&future, CoreError::Conflict(_)));
        assert_eq!(future.to_string(), "conflict: revision mismatch; current revision 3");
        assert_eq!(bgm_write(&media, &p, generated, "B", &encoded, None).await.unwrap().revision, 4);
        let retry = bgm_write(&media, &p, generated, "C", &encoded, Some(4)).await.unwrap();
        assert_eq!(retry.revision, 5);
        assert_eq!(retry.moods, vec!["C"]);
        let stale = bgm_write(&media, &p, generated, "C", &encoded, Some(4)).await.unwrap_err();
        assert!(matches!(&stale, CoreError::Conflict(_)));
        assert_eq!(stale.to_string(), "conflict: revision mismatch; current revision 5");

        // 上传和生成都覆盖 A → B → A；无身份且无前提的相同命令始终后写覆盖。
        for (label, revision) in [("A", 6), ("B", 7), ("A", 8)] {
            let written = bgm_write(&media, &p, generated, label, &encoded, None).await.unwrap();
            assert_eq!(written.id, initial.id);
            assert_eq!(written.revision, revision);
            assert_eq!(written.moods, vec![label]);
            let catalog = media.repo.get_bgm(&p.tenant_id, &initial.id).await.unwrap().unwrap();
            assert_eq!(catalog.revision, revision);
            assert_eq!(catalog.moods, vec![label]);
        }
    }
    drop(media);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn sqlite_bgm_current_cas_upload_and_generate() {
    bgm_current_cas(Arc::new(SqliteRepository::in_memory().await.unwrap())).await;
}

#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_bgm_current_cas_upload_and_generate() {
    memoswish_storage::pg_test_support::run_pg_test(|test| async move {
        let fixture = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let repo = Arc::new(fixture.repository(2).await.unwrap());
        bgm_current_cas(repo.clone()).await;
        repo.pool().close().await;
        fixture.cleanup().await;
    });
}

struct MissingSpeech(SpeechFailure);

#[async_trait::async_trait]
impl TtsEngine for MissingSpeech {
    fn id(&self) -> &str {
        "missing-speech"
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn validate_request(&self, _: &TtsRequest) -> CoreResult<()> {
        Err(self.0.error())
    }
    async fn synthesize(&self, _: &TtsRequest) -> CoreResult<TtsOutput> {
        panic!("known unavailable speech must not invoke provider")
    }
}

#[tokio::test]
async fn speech_failure_survives_api_worker_exhaustion_and_restart() {
    for failure in [SpeechFailure::EngineUnavailable, SpeechFailure::VoiceUnavailable] {
        let dir = std::env::temp_dir().join(format!("p35-speech-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        let url = format!("sqlite://{}", dir.join("speech.db").display());
        let repo = Arc::new(SqliteRepository::connect(&url).await.unwrap());
        bootstrap(repo.clone()).await;
        let worker = MediaService::new(
            repo.clone(),
            Arc::new(LocalDiskStore::new(dir.join("assets"), "/assets")),
            Arc::new(Unlimited::new()),
            vec![Arc::new(MissingSpeech(failure))],
            "missing-speech",
        )
        .unwrap();
        let api = worker.clone().with_execution(false);
        let p = Principal::local_owner("test");
        let opts = SynthesizeOptions::default();
        let call = api.synthesize(&p, "hello", "en-US", &opts);
        let execute = async {
            let (tenant, id) = loop {
                if let Some(job) = worker.pending_speech_page(None).await.unwrap().pop() {
                    break job;
                }
                tokio::time::sleep(std::time::Duration::from_millis(jobs::POLL_MS)).await;
            };
            for _ in 0..5 {
                // 模拟数据库业务间隔，保留 API 等待、分类错误及重启终态断言。
                sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2 AND state='queued'").bind(&tenant).bind(&id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
                let error = worker.recover_speech_job(&tenant, &id).await.unwrap_err();
                assert_eq!(error.code(), failure.error().code());
            }
        };
        let (result, ()) = tokio::time::timeout(std::time::Duration::from_millis(jobs::LEASE_MS as u64), async {
            tokio::join!(call, execute)
        })
        .await
        .unwrap();
        let error = result.unwrap_err();
        assert_eq!(error.code(), failure.error().code());
        assert!(error.public_message().contains("tts_engines"));
        let snapshot = api.quota.snapshot(&p).await.unwrap();
        let metric = snapshot.metrics.iter().find(|v| v.metric == "tts_chars").unwrap();
        assert_eq!((metric.used, metric.held, metric.uncertain), (0, 0, 0));
        drop(api);
        drop(worker);
        repo.pool().close().await;
        let restarted = Arc::new(SqliteRepository::connect(&url).await.unwrap());
        let api = MediaService::new(
            restarted.clone(),
            Arc::new(LocalDiskStore::new(dir.join("assets"), "/assets")),
            Arc::new(Unlimited::new()),
            vec![Arc::new(MissingSpeech(failure))],
            "missing-speech",
        )
        .unwrap()
        .with_execution(false);
        for _ in 0..2 {
            assert_eq!(api.synthesize(&p, "hello", "en-US", &opts).await.unwrap_err().code(), error.code());
        }
        drop(api);
        restarted.pool().close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }
}
