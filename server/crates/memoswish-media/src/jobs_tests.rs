//! 媒体服务使用独立实例共享 SQL，验证格式、取消前持久责任及旧缓存迁移。
use super::*;
use memoswish_auth::{AuthConfig, AuthService, Unlimited};
use memoswish_core::bgm::BgmPublicationRepo;
use memoswish_core::repo::MediaRepo;
use memoswish_core::store::ObjectStore;
use memoswish_core::tts::{SpeechRepo, TtsEngine, VoiceInfo};
use memoswish_storage::{LocalDiskStore, sqlite::SqliteRepository};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Engine {
    calls: AtomicUsize,
    fail: bool,
}
#[async_trait::async_trait]
impl TtsEngine for Engine {
    fn id(&self) -> &str {
        "test"
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn synthesize(&self, _: &TtsRequest) -> CoreResult<TtsOutput> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(CoreError::internal("SECRET_SENTINEL provider key"));
        }
        Ok(TtsOutput {
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
async fn setup(
    fail: bool,
) -> (MediaService, Arc<SqliteRepository>, Arc<LocalDiskStore>, Arc<Engine>, std::path::PathBuf) {
    let repo = Arc::new(SqliteRepository::in_memory().await.unwrap());
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
    let dir = std::env::temp_dir().join(format!("s16-media-{}", memoswish_core::ids::new_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = Arc::new(LocalDiskStore::new(&dir, "/assets"));
    let engine = Arc::new(Engine { calls: AtomicUsize::new(0), fail });
    let media = MediaService::new(
        repo.clone(),
        store.clone(),
        Arc::new(Unlimited::metered(repo.clone())),
        vec![engine.clone()],
        "test",
    )
    .unwrap();
    (media, repo, store, engine, dir)
}
#[tokio::test]
async fn independent_services_share_non_wav_result_and_charge_once() {
    let (a, repo, store, engine, dir) = setup(false).await;
    let b = MediaService::new(
        repo.clone(),
        store,
        Arc::new(Unlimited::metered(repo.clone())),
        vec![engine.clone()],
        "test",
    )
    .unwrap();
    let p = Principal::local_owner("test");
    let opts = SynthesizeOptions::default();
    let (x, y) = tokio::join!(a.synthesize(&p, "abc", "en", &opts), b.synthesize(&p, "abc", "en", &opts));
    let x = x.unwrap();
    assert_eq!(x, y.unwrap());
    assert_eq!(x.audio.mime, "audio/mpeg");
    assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(a.synthesize(&p, "abc", "en", &opts).await.unwrap(), x);
    assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
    let snapshot = a.quota.snapshot(&p).await.unwrap();
    assert_eq!(snapshot.metrics.iter().find(|v| v.metric == "tts_chars").unwrap().used, 3);
    for speed in [f32::NAN, f32::INFINITY] {
        let bad = SynthesizeOptions { speed: Some(speed), ..Default::default() };
        assert!(a.synthesize(&p, "abc", "en", &bad).await.is_err());
    }
    assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn provider_errors_are_sanitized_and_remain_held() {
    let (media, _, _, engine, dir) = setup(true).await;
    let p = Principal::local_owner("test");
    let err = media.synthesize(&p, "abc", "en", &SynthesizeOptions::default()).await.unwrap_err();
    assert!(!format!("{err:?} {err}").contains("SECRET_SENTINEL"));
    assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
    let snapshot = media.quota.snapshot(&p).await.unwrap();
    let q = snapshot.metrics.iter().find(|v| v.metric == "tts_chars").unwrap();
    assert_eq!((q.used, q.held, q.uncertain), (0, 3, 3));
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn legacy_requires_recorded_digest_and_adopts_without_charge() {
    for valid in [true, false] {
        let (media, _, store, engine, dir) = setup(false).await;
        let p = Principal::local_owner("test");
        let cache = sha256_hex(b"test|default|en|1.00|abc");
        let base = format!("tenants/local/tts/{}", &cache[..32]);
        store.put(&format!("{base}.wav"), b"old".to_vec(), "audio/wav").await.unwrap();
        store.put(&format!("{base}.json"),serde_json::to_vec(&serde_json::json!({"duration_ms":100,"words":[],"sha256":if valid{sha256_hex(b"old")}else{sha256_hex(b"wrong")}})).unwrap(),"application/json").await.unwrap();
        let track = media.synthesize(&p, "abc", "en", &SynthesizeOptions::default()).await.unwrap();
        assert!(track.audio.key.contains("/uploads/"));
        assert_eq!(engine.calls.load(Ordering::SeqCst), usize::from(!valid));
        let snapshot = media.quota.snapshot(&p).await.unwrap();
        assert_eq!(snapshot.metrics.iter().find(|v| v.metric == "tts_chars").unwrap().used, if valid { 0 } else { 3 });
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn accepted_legacy_bytes_recover_without_original_cache_or_provider_charge() {
    use memoswish_core::tts::SpeechRepo;
    let (media, repo, _, engine, dir) = setup(false).await;
    let p = Principal::local_owner("test");
    let work = SpeechWork {
        provenance: Some(memoswish_protocol::ContentProvenance {
            method: "manual".into(),
            rights: "Declared legacy rights".into(),
            ..Default::default()
        }),
        privacy: None,
        engine: "test".into(),
        namespace: engine.cache_namespace(),
        request: TtsRequest { text: "abc".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
        amount: 0,
        legacy_output: Some(TtsOutput {
            alignment_quality: None,
            audio_kind: None,
            provenance: None,
            audio: b"old".to_vec(),
            mime: "audio/wav".into(),
            extension: "wav".into(),
            duration_ms: 100,
            words: vec![],
        }),
    };
    let accepted = repo.accept_speech(&p, &work, None, Some(0)).await.unwrap();
    assert!(repo.speech_work(&p.tenant_id, &accepted.synthesis_id).await.unwrap().legacy_output.is_none());
    // 不存在旧文件；新实例只能从首次准入事务保存的字节恢复。
    let recovered = media.clone();
    recovered.recover_speech_job(&p.tenant_id, &accepted.synthesis_id).await.unwrap();
    let result = repo.speech_track(&p.tenant_id, &accepted.synthesis_id).await.unwrap().unwrap();
    assert_eq!(result.audio.sha256, sha256_hex(b"old"));
    assert_eq!(result.provenance, work.provenance);
    assert!(result.alignment_quality.is_none());
    assert_eq!(repo.speech_request(&p.tenant_id, &accepted.id).await.unwrap().outcome, "published");
    assert_eq!(engine.calls.load(Ordering::SeqCst), 0);
    let snapshot = media.quota.snapshot(&p).await.unwrap();
    let q = snapshot.metrics.iter().find(|q| q.metric == "tts_chars").unwrap();
    assert_eq!((q.used, q.held, q.uncertain), (0, 0, 0));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn submissions_validate_before_admission_and_replay_before_resolving_defaults() {
    use memoswish_core::repo::ContentRepo;
    let (media, repo, _, engine, dir) = setup(false).await;
    let p = Principal::local_owner("test");
    let deck = memoswish_protocol::examples::sample_deck();
    let card = memoswish_protocol::examples::sample_card();
    repo.insert_deck_with_cards(&p.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
    for ids in [vec![], vec![card.id.clone(); 2], vec![card.id.clone(); 101], vec![card.id.clone(), "missing".into()]] {
        assert!(media.submit_tts(&p, "bad", &ids, &SynthesizeOptions::default()).await.is_err());
        assert!(media.tts_submission_status(&p, "bad").await.is_err());
    }
    for options in [
        SynthesizeOptions { speed: Some(f32::NAN), ..Default::default() },
        SynthesizeOptions { expected_revisions: [(card.id.clone(), 0)].into(), ..Default::default() },
        SynthesizeOptions { expected_revisions: [("other".into(), 1)].into(), ..Default::default() },
    ] {
        assert!(media.submit_tts(&p, "bad", std::slice::from_ref(&card.id), &options).await.is_err());
    }
    let mut denied = p.clone();
    denied.scopes = Some(vec!["tts:generate".into()]);
    assert!(
        media.submit_tts(&denied, "bad", std::slice::from_ref(&card.id), &SynthesizeOptions::default()).await.is_err()
    );
    let accepted =
        media.submit_tts(&p, "replay", std::slice::from_ref(&card.id), &SynthesizeOptions::default()).await.unwrap();
    assert_eq!(engine.calls.load(Ordering::SeqCst), 0);
    repo.delete_card(&p.tenant_id, &card.id).await.unwrap();
    assert_eq!(
        media.submit_tts(&p, "replay", std::slice::from_ref(&card.id), &SynthesizeOptions::default()).await.unwrap(),
        accepted
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn privacy_recovery_rejects_unclassified_engine_before_staged_publication() {
    use memoswish_core::tts::SpeechRepo;
    let (media, repo, _, _, dir) = setup(false).await;
    let p = Principal::local_owner("test");
    let work = SpeechWork {
        provenance: None,
        privacy: None,
        engine: "retired-external-engine".into(),
        namespace: "previous-config".into(),
        request: TtsRequest { text: "abc".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
        amount: 3,
        legacy_output: None,
    };
    let accepted = repo.accept_speech(&p, &work, None, Some(100)).await.unwrap();
    let claim = repo.claim_speech(&p.tenant_id, &accepted.synthesis_id, 30_000).await.unwrap().unwrap();
    repo.begin_provider(&p.tenant_id, &claim).await.unwrap();
    repo.materialize_speech(
        &p.tenant_id,
        &claim,
        b"abc",
        &AssetSpec { mime: "audio/mpeg".into(), size: 3, sha256: sha256_hex(b"abc") },
        &SpeechMetadata {
            alignment_quality: None,
            audio_kind: None,
            provenance: None,
            extension: "mp3".into(),
            duration_ms: 100,
            words: vec![],
        },
        false,
    )
    .await
    .unwrap();
    assert!(media.recover_speech_job(&p.tenant_id, &accepted.synthesis_id).await.is_err());
    assert!(repo.speech_track(&p.tenant_id, &accepted.synthesis_id).await.unwrap().is_none());
    assert_eq!(repo.speech_request(&p.tenant_id, &accepted.id).await.unwrap().outcome, "pending");
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn privacy_external_command_is_fenced_before_and_during_execution() {
    use crate::tts::command::{CommandTts, CommandTtsConfig};
    use memoswish_core::{privacy::PrivacyRepo, repo::ContentRepo, tts::SpeechRepo};
    let (_, repo, store, _, dir) = setup(false).await;
    let p = Principal { via: "single_user".into(), ..Principal::local_owner("test") };
    let mut policy = memoswish_protocol::examples::sample_privacy_policy();
    policy.purpose_versions.insert("external_tts".into(), "speech-v1".into());
    repo.privacy_install_policy(&policy).await.unwrap();
    let fifo = dir.join("command-output.fifo");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let cfg: CommandTtsConfig = serde_json::from_value(
        serde_json::json!({"id":"external-command","program":"cat","args":[fifo],"timeout_secs":30}),
    )
    .unwrap();
    let media = MediaService::new(
        repo.clone(),
        store.clone(),
        Arc::new(Unlimited::metered(repo.clone())),
        vec![Arc::new(CommandTts::new(cfg))],
        "external-command",
    )
    .unwrap()
    .with_privacy_policy(policy.clone());
    let deck = memoswish_protocol::examples::sample_deck();
    let mut card = memoswish_protocol::examples::sample_card();
    card.tts = None;
    repo.insert_deck_with_cards(&p.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
    let opts = SynthesizeOptions { text: Some("abc".into()), ..Default::default() };
    assert!(media.submit_tts(&p, "missing", std::slice::from_ref(&card.id), &opts).await.is_err());
    assert!(repo.speech_submission(&p, "missing", None).await.unwrap().is_none());
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_tts", "speech-policy-v1", ""),
    ] {
        let state = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
        if kind == "external_tts" {
            assert!(media.submit_tts(&p, "missing-purpose", std::slice::from_ref(&card.id), &opts).await.is_err());
            assert!(repo.speech_submission(&p, "missing-purpose", None).await.unwrap().is_none());
        }
        // 使用实际部署用途版本，夹具不假定提供者名称。
        let version =
            if kind == "external_tts" { policy.purpose_versions.get(kind).unwrap().as_str() } else { version };
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
    let version = policy.purpose_versions.get("external_tts").unwrap();
    let update = |revision, decision| memoswish_protocol::PrivacyUpdate {
        expected_revision: revision,
        kind: "external_tts".into(),
        version: version.clone(),
        decision,
        value: String::new(),
    };
    for phase in ["before", "during"] {
        let submission = media.submit_tts(&p, phase, std::slice::from_ref(&card.id), &opts).await.unwrap();
        let request = repo.speech_request(&p.tenant_id, &submission.items[0].item_id).await.unwrap();
        let running = if phase == "during" {
            let media = media.clone();
            let tenant = p.tenant_id.clone();
            let id = request.synthesis_id.clone();
            Some(tokio::spawn(async move { media.recover_speech_job(&tenant, &id).await }))
        } else {
            None
        };
        // FIFO 写端打开成功证明真实 cat 已运行并等待读取，不依赖睡眠或新时间窗口。
        let writer = if running.is_some() {
            let path = fifo.clone();
            Some(
                tokio::task::spawn_blocking(move || std::fs::OpenOptions::new().write(true).open(path).unwrap())
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let state = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
        let state = repo.privacy_update(&p.tenant_id, &p, &policy, &update(state.revision, false)).await.unwrap();
        if let Some(mut writer) = writer {
            use std::io::Write;
            writer
                .write_all(&crate::wav::encode_wav(
                    &crate::wav::tone(440.0, 100, 0.2, crate::wav::SAMPLE_RATE),
                    crate::wav::SAMPLE_RATE,
                ))
                .unwrap();
            drop(writer);
            assert!(running.unwrap().await.unwrap().is_err());
        } else {
            media.recover_speech_job(&p.tenant_id, &request.synthesis_id).await.unwrap();
        }
        let terminal = media.tts_submission_status(&p, phase).await.unwrap();
        assert!(terminal.complete);
        assert_eq!(
            terminal.items[0].receipt.as_ref().unwrap().disposition,
            memoswish_protocol::tts::TtsDisposition::Failed
        );
        assert!(repo.speech_upload(&p.tenant_id, &request.synthesis_id).await.unwrap().is_none());
        assert!(repo.speech_track(&p.tenant_id, &request.synthesis_id).await.unwrap().is_none());
        let expected = if phase == "before" { (0, 0) } else { (3, 3) };
        assert_eq!(
            {
                let snapshot = media.quota.snapshot(&p).await.unwrap();
                let metric = snapshot.metrics.iter().find(|v| v.metric == "tts_chars").unwrap();
                (metric.held, metric.uncertain)
            },
            expected
        );
        repo.privacy_update(&p.tenant_id, &p, &policy, &update(state.revision, true)).await.unwrap();
        // 新服务实例按持久状态恢复；旧工作不执行、不发布、不改回执。
        media.clone().recover_speech_job(&p.tenant_id, &request.synthesis_id).await.unwrap();
        assert_eq!(media.tts_submission_status(&p, phase).await.unwrap(), terminal);
    }
    assert!(repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap().tts.is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

struct MissingLocalVoice;
#[async_trait::async_trait]
impl TtsEngine for MissingLocalVoice {
    fn id(&self) -> &str {
        "missing-local-voice"
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn validate_request(&self, _: &TtsRequest) -> CoreResult<()> {
        Err(CoreError::SpeechVoiceUnavailable)
    }
    async fn synthesize(&self, _: &TtsRequest) -> CoreResult<TtsOutput> {
        panic!("invalid local voice must not invoke provider")
    }
}

#[tokio::test]
async fn missing_local_voice_has_actionable_public_error_without_uncertain_provider_usage() {
    let (media, repo, _, _, dir) = setup(false).await;
    let p = Principal::local_owner("test");
    let media = MediaService::new(
        media.repo,
        media.store,
        media.quota,
        vec![Arc::new(MissingLocalVoice)],
        "missing-local-voice",
    )
    .unwrap();
    let error = media.synthesize(&p, "hello", "en-US", &SynthesizeOptions::default()).await.unwrap_err();
    assert!(matches!(error, CoreError::SpeechVoiceUnavailable));
    assert_eq!(error.code(), "speech_voice_unavailable");
    assert!(error.public_message().contains("tts_engines"));
    let pending = media.repo.pending_speech(None, 100).await.unwrap();
    assert_eq!(pending.len(), 1);
    let usage = media.repo.held_speech_usage(&p.tenant_id, &memoswish_auth::quota::current_period()).await.unwrap();
    assert!(usage.0 > 0);
    assert_eq!(usage.1, 0);
    for _ in 0..5 {
        // 显式推进数据库夹具期限，保留原有耗尽及未调用 provider 的断言。
        sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2")
            .bind(&pending[0].0)
            .bind(&pending[0].1)
            .bind(memoswish_core::maintenance::CADENCE_MS)
            .execute(repo.pool())
            .await
            .unwrap();
        let _ = media.recover_speech_job(&pending[0].0, &pending[0].1).await;
    }
    assert_eq!(
        media.repo.held_speech_usage(&p.tenant_id, &memoswish_auth::quota::current_period()).await.unwrap(),
        (0, 0)
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn speech_materialization_stops_heartbeat_before_completion() {
    speech_completion_barrier(false).await;
}

#[tokio::test]
async fn speech_publication_stops_heartbeat_before_completion() {
    speech_completion_barrier(true).await;
}

async fn speech_completion_barrier(publication: bool) {
    let (media, repo, _, engine, dir) = setup(false).await;
    let p = Principal::local_owner("test");
    let work = media.prepare_speech_work(&p, "completion barrier", "en", &Default::default(), None).await.unwrap();
    let request = repo.accept_speech(&p, &work, None, None).await.unwrap();
    let out = engine.synthesize(&work.request).await.unwrap();
    let (spec, meta) = MediaService::validate_speech_output(&out).unwrap();
    if publication {
        let claim = repo.claim_speech("local", &request.synthesis_id, LEASE_MS).await.unwrap().unwrap();
        repo.begin_provider("local", &claim).await.unwrap();
        repo.materialize_speech("local", &claim, &out.audio, &spec, &meta, false).await.unwrap();
    }
    let (id, bytes) = if publication {
        repo.speech_upload("local", &request.synthesis_id).await.unwrap().unwrap()
    } else {
        (request.synthesis_id.clone(), vec![])
    };
    let claim = repo.claim_speech("local", &id, LEASE_MS).await.unwrap().unwrap();
    if !publication {
        repo.begin_provider("local", &claim).await.unwrap();
    }
    let (heartbeat_owner, mut heartbeat_dropped) = tokio::sync::oneshot::channel::<()>();
    let (committed, observed) = tokio::sync::oneshot::channel();
    let (release, held) = tokio::sync::oneshot::channel();
    let owned = media.clone();
    let claim2 = claim.clone();
    let expected_audio = out.audio.clone();
    let out = out.clone();
    let spec = spec.clone();
    let meta = meta.clone();
    let mut task = tokio::spawn(async move {
        let owned = &owned;
        let claim2 = &claim2;
        MediaService::under_speech_lease(
            async {
                tokio::task::yield_now().await;
                if publication { owned.upload_materialized("local", claim2, bytes).await } else { Ok(String::new()) }
            },
            async {
                let _heartbeat_owner = heartbeat_owner;
                owned.maintain_speech_lease("local", claim2).await
            },
            |attempt| async move {
                assert!(
                    matches!(heartbeat_dropped.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Closed)),
                    "heartbeat must be dropped before completion starts"
                );
                if publication {
                    owned.repo.publish_speech("local", claim2, &attempt).await?;
                } else {
                    owned.repo.materialize_speech("local", claim2, &out.audio, &spec, &meta, false).await?;
                }
                committed.send(()).unwrap();
                held.await.unwrap();
                Ok(())
            },
        )
        .await
    });
    tokio::select! {biased; result=&mut task=>panic!("completion failed before barrier: {result:?}"), result=observed=>result.unwrap()}
    assert!(matches!(repo.heartbeat_speech("local", &claim, LEASE_MS).await, Err(CoreError::Conflict(_))));
    tokio::time::pause();
    tokio::time::advance(Duration::from_millis(LEASE_MS as u64)).await;
    tokio::select! { biased; result=&mut task=>panic!("completion was cancelled: {result:?}"), _=tokio::task::yield_now()=>{} }
    release.send(()).unwrap();
    task.await.unwrap().unwrap();
    tokio::time::resume();
    assert_eq!(repo.speech_track("local", &request.synthesis_id).await.unwrap().is_some(), publication);
    if let Some(track) = repo.speech_track("local", &request.synthesis_id).await.unwrap() {
        let manifest = media.repo.asset_read_manifest("local", &track.audio.key).await.unwrap().unwrap();
        assert!(manifest.verified);
        manifest.verify_block(0, &expected_audio).unwrap();
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn bgm_publication_stops_heartbeat_and_preserves_expiry_fence() {
    for expired in [false, true] {
        let (media, repo, _, _, dir) = setup(false).await;
        let p = Principal::local_owner("test");
        let bytes = crate::wav::encode_wav(&vec![0.25; 8000], 8000);
        let mut track = memoswish_protocol::examples::sample_bgm_track();
        track.asset.key = "tenants/local/bgm/completion.wav".into();
        track.asset.bytes = bytes.len() as u64;
        track.asset.sha256 = sha256_hex(&bytes);
        let id = repo.accept_bgm(&p, "completion", &track, &bytes, None, "completion", false).await.unwrap();
        let claim = repo.claim_bgm("local", &id, LEASE_MS).await.unwrap().unwrap();
        if expired {
            let result = MediaService::under_speech_lease(
                async {
                    let attempt = media.upload_materialized("local", &claim, bytes).await?;
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id='local' AND id=$1")
                        .bind(&claim.job_id)
                        .execute(repo.pool())
                        .await
                        .unwrap();
                    Ok(attempt)
                },
                media.maintain_speech_lease("local", &claim),
                |attempt| {
                    let repo = &repo;
                    let claim = &claim;
                    async move { repo.publish_bgm("local", claim, &attempt).await }
                },
            )
            .await;
            assert!(matches!(result, Err(CoreError::Conflict(_))));
            assert!(repo.bgm_result("local", &id).await.unwrap().is_none());
            assert!(repo.bgm_stage("local", &id).await.unwrap().is_some());
            assert!(repo.get_bgm("local", &track.id).await.unwrap().is_none());
        } else {
            let (heartbeat_owner, mut heartbeat_dropped) = tokio::sync::oneshot::channel::<()>();
            let (committed, observed) = tokio::sync::oneshot::channel();
            let (release, held) = tokio::sync::oneshot::channel();
            let owned = media.clone();
            let claim2 = claim.clone();
            let mut task = tokio::spawn(async move {
                let owned = &owned;
                let claim2 = &claim2;
                MediaService::under_speech_lease(
                    owned.upload_materialized("local", claim2, bytes),
                    async {
                        let _heartbeat_owner = heartbeat_owner;
                        owned.maintain_speech_lease("local", claim2).await
                    },
                    |attempt| async move {
                        assert!(matches!(
                            heartbeat_dropped.try_recv(),
                            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
                        ));
                        owned.repo.publish_bgm("local", claim2, &attempt).await?;
                        committed.send(()).unwrap();
                        held.await.unwrap();
                        Ok(())
                    },
                )
                .await
            });
            tokio::select! { biased; result=&mut task=>panic!("completion failed before barrier: {result:?}"), result=observed=>result.unwrap() }
            assert!(matches!(repo.heartbeat_speech("local", &claim, LEASE_MS).await, Err(CoreError::Conflict(_))));
            tokio::time::pause();
            tokio::time::advance(Duration::from_millis(LEASE_MS as u64)).await;
            tokio::select! { biased; result=&mut task=>panic!("completion was cancelled: {result:?}"), _=tokio::task::yield_now()=>{} }
            release.send(()).unwrap();
            task.await.unwrap().unwrap();
            tokio::time::resume();
            let published = repo.bgm_result("local", &id).await.unwrap().unwrap();
            let manifest = media.repo.asset_read_manifest("local", &published.asset.key).await.unwrap().unwrap();
            assert!(manifest.verified);
            let stored = media.store.get(&published.asset.key).await.unwrap().unwrap();
            manifest.verify_block(0, &stored.bytes).unwrap();
            assert!(repo.bgm_stage("local", &id).await.unwrap().is_none());
            assert_eq!(repo.get_bgm("local", &track.id).await.unwrap().unwrap(), published);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn speech_completion_still_rejects_an_expired_claim() {
    let (media, repo, _, engine, dir) = setup(false).await;
    let p = Principal::local_owner("test");
    let work = media.prepare_speech_work(&p, "expired", "en", &Default::default(), None).await.unwrap();
    let request = repo.accept_speech(&p, &work, None, None).await.unwrap();
    let claim = repo.claim_speech("local", &request.synthesis_id, LEASE_MS).await.unwrap().unwrap();
    repo.begin_provider("local", &claim).await.unwrap();
    let out = engine.synthesize(&work.request).await.unwrap();
    let (spec, meta) = MediaService::validate_speech_output(&out).unwrap();
    let result = MediaService::under_speech_lease(
        async {
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id='local' AND id=$1")
                .bind(&claim.job_id)
                .execute(repo.pool())
                .await
                .unwrap();
            Ok(())
        },
        media.maintain_speech_lease("local", &claim),
        |_| repo.materialize_speech("local", &claim, &out.audio, &spec, &meta, false),
    )
    .await;
    assert!(matches!(result, Err(CoreError::Conflict(_))));
    assert!(repo.speech_upload("local", &request.synthesis_id).await.unwrap().is_none());
    std::fs::remove_dir_all(dir).unwrap();
}
