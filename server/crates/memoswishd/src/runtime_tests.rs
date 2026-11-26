//! 启动取消与后续失败必须保留已接收恢复任务，并阻止下一项进入 provider。

use std::{
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use memoswish_core::{
    CoreResult, Principal,
    tts::{SpeechWork, TtsEngine, TtsOutput, TtsRequest, VoiceInfo},
};
use memoswish_media::MediaService;
use tokio::sync::{Semaphore, oneshot};

use super::*;

#[tokio::test]
async fn cleanup_waits_for_every_application_owner_before_removing_directory() {
    use std::task::Poll;

    let root = std::env::temp_dir().join(format!("s26d-cleanup-{}", memoswish_core::ids::new_id()));
    let config = Config { data_dir: root.clone(), seed_demo: false, ..Default::default() };
    let first = AppState::assemble(config.clone()).await.unwrap();
    let second = AppState::assemble(config).await.unwrap();
    let mut releases = Vec::new();
    let mut completions = Vec::new();
    let mut controls = Vec::new();
    for (index, st) in [&first, &second].into_iter().enumerate() {
        let control = memoswish_application::OperationControl::default();
        let mut phases = control.subscribe();
        let (release, blocked) = oneshot::channel();
        let (completed, completion) = oneshot::channel();
        let work = st.clone();
        let task = control
            .scope(async {
                st.services.operations.spawn(async move {
                    let inherited = memoswish_application::OperationControl::current();
                    inherited.begin_acceptance().unwrap();
                    blocked.await.unwrap();
                    inherited.accepted();
                    crate::metrics::sample(&work).await;
                    tokio::fs::write(work.config.data_dir.join(format!("owner-{index}")), b"finished").await.unwrap();
                    completed.send(()).unwrap();
                })
            })
            .await
            .unwrap();
        phases.wait_for(|phase| *phase == "accepting").await.unwrap();
        // MCP 取消并丢弃等待者后，原拥有者仍须完成事务、采样与磁盘写入。
        control.cancel();
        drop(task);
        assert!(control.checkpoint().is_err());
        controls.push(control);
        releases.push(release);
        completions.push(completion);
    }
    let states = [&first, &second];
    let cleanup = cleanup_test_app(&root, &states);
    tokio::pin!(cleanup);
    assert!(matches!(std::future::poll_fn(|cx| Poll::Ready(cleanup.as_mut().poll(cx))).await, Poll::Pending));
    assert!(root.exists());
    for st in states {
        assert!(st.services.operations.spawn(async {}).is_err());
    }
    releases.remove(0).send(()).unwrap();
    completions.remove(0).await.unwrap();
    assert!(matches!(std::future::poll_fn(|cx| Poll::Ready(cleanup.as_mut().poll(cx))).await, Poll::Pending));
    assert!(root.join("owner-0").exists());
    releases.remove(0).send(()).unwrap();
    cleanup.await;
    completions.remove(0).await.unwrap();
    for control in controls {
        assert_eq!(*control.subscribe().borrow(), "accepted");
    }
    assert!(!root.exists());
}

struct PausedRecovery {
    calls: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
}

#[async_trait::async_trait]
impl TtsEngine for PausedRecovery {
    fn id(&self) -> &str {
        "paused-recovery"
    }

    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }

    async fn synthesize(&self, _: &TtsRequest) -> CoreResult<TtsOutput> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        Ok(TtsOutput {
            alignment_quality: None,
            audio_kind: None,
            provenance: None,
            audio: b"recovered".to_vec(),
            mime: "audio/mpeg".into(),
            extension: "mp3".into(),
            duration_ms: 100,
            words: vec![],
        })
    }
}

fn assert_locked(root: &Path) {
    let competing = std::fs::File::open(root).unwrap();
    assert!(fs4::FileExt::try_lock(&competing).is_err(), "startup cleanup must retain the writer lock");
}

async fn interrupted_startup(root: &Path, cancel: bool) {
    let mut config = Config { data_dir: root.into(), seed_demo: false, ..Default::default() };
    config.tts.auto_detect_espeak = false;
    crate::directory_lock::acquire(root).unwrap();
    let mut state = AppState::assemble(config.clone()).await.unwrap();
    let engine =
        Arc::new(PausedRecovery { calls: AtomicUsize::new(0), entered: Semaphore::new(0), release: Semaphore::new(0) });
    state.services.media = MediaService::new(
        state.repo.clone(),
        state.store.clone(),
        state.services.quota.clone(),
        vec![engine.clone()],
        engine.id(),
    )
    .unwrap();
    let principal = Principal::local_owner("test");
    // 直接写入持久 pending，模拟上一进程留下的两项不同合成；此处不调度恢复。
    for text in ["first pending speech", "second pending speech"] {
        let work = SpeechWork {
            provenance: None,
            privacy: None,
            engine: engine.id().into(),
            namespace: engine.cache_namespace(),
            request: TtsRequest { text: text.into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
            amount: text.len() as i64,
            legacy_output: None,
        };
        state.repo.accept_speech(&principal, &work, None, None).await.unwrap();
    }
    let pending = state.repo.pending_speech(None, 100).await.unwrap();
    assert_eq!(pending.len(), 2);
    let observed = state.clone();
    let (started, startup_paused) = oneshot::channel();
    let (fail, failure) = oneshot::channel::<()>();
    let startup = tokio::spawn(Daemon::initialize_with(state, |st| async move {
        st.initialize().await?;
        // 在真实恢复启动后的异步初始化边界暂停；不增加生产 hook、租约或时间常量。
        started.send(()).unwrap();
        failure.await.unwrap();
        anyhow::bail!("injected later startup failure")
    }));
    startup_paused.await.unwrap();
    engine.entered.acquire().await.unwrap().forget();
    assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
    assert!(!startup.is_finished());
    if cancel {
        startup.abort();
        assert!(startup.await.err().unwrap().is_cancelled());
    } else {
        fail.send(()).unwrap();
        let error = startup.await.unwrap().err().unwrap();
        assert_eq!(error.to_string(), "injected later startup failure");
    }
    assert!(observed.services.operations.spawn(async {}).is_err());
    assert!(observed.services.recover_speech().is_err(), "failed startup must reject new recovery passes");
    let drain = observed.services.operations.wait();
    tokio::pin!(drain);
    tokio::select! {
        biased;
        _ = &mut drain => panic!("accepted provider work must still own application responsibility"),
        _ = tokio::task::yield_now() => {},
    }
    assert_locked(root);
    // 应用仍在 provider 阶段时，底层 PUT 准入必须保留；不是仅保住一个 JoinHandle。
    observed.store.put("tenants/local/startup-probe.mp3", vec![1], "audio/mpeg").await.unwrap();
    engine.release.add_permits(1);
    drain.await;
    assert_eq!(engine.calls.load(Ordering::SeqCst), 1, "shutdown cannot admit the second pending job");
    let track = observed.repo.speech_track(&principal.tenant_id, &pending[0].1).await.unwrap().unwrap();
    assert_eq!(observed.store.get(&track.audio.key).await.unwrap().unwrap().bytes, b"recovered");
    assert_eq!(observed.repo.pending_speech(None, 100).await.unwrap(), pending[1..]);
    // 等待现有排空任务关闭 PUT，明确观察应用先于 PUT 的完成条件。
    while observed.store.put("tenants/local/closed-probe.mp3", vec![1], "audio/mpeg").await.is_ok() {
        tokio::task::yield_now().await;
    }
    assert_locked(root);
    assert!(Daemon::start(config).await.is_err(), "restart in the same process remains forbidden");
}

fn isolated(name: &str, cancel: bool) {
    if let Ok(root) = crate::test_environment::var("MEMOSWISH_E3A_STARTUP_ROOT") {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), interrupted_startup(Path::new(&root), cancel))
                .await
                .expect("startup scenario timed out");
        });
        return;
    }
    let root = std::env::temp_dir().join(format!("memoswish-startup-{}", memoswish_core::ids::new_id()));
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("MEMOSWISH_E3A_STARTUP_ROOT", &root)
        .output()
        .unwrap();
    if root.exists() {
        std::fs::remove_dir_all(root).unwrap();
    }
    assert!(
        output.status.success(),
        "startup child failed: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cancelled_startup_owns_recovery_and_closes_admission() {
    isolated("runtime::tests::cancelled_startup_owns_recovery_and_closes_admission", true);
}

#[test]
fn failed_startup_owns_recovery_and_closes_admission() {
    isolated("runtime::tests::failed_startup_owns_recovery_and_closes_admission", false);
}

#[tokio::test]
async fn stdio_shutdown_cancels_blocked_authentication_before_the_shared_deadline() {
    let root = std::env::temp_dir().join(format!("s26b-auth-drain-{}", memoswish_core::ids::new_id()));
    let config = Config {
        data_dir: root.clone(),
        seed_demo: false,
        object_store: crate::ObjectStoreConfig { put_shutdown_timeout_secs: 1, ..Default::default() },
        ..Default::default()
    };
    let mut state = AppState::assemble(config).await.unwrap();
    let repo = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
    state.services.auth = memoswish_auth::AuthService::new(
        repo.clone(),
        memoswish_auth::AuthConfig {
            mode: memoswish_protocol::DeploymentMode::SingleUser,
            jwt_secret: "synthetic-stdio-authentication-secret-with-32-bytes".into(),
            jwt_ttl_secs: 3600,
            registration_open: false,
            default_plan: "self_hosted".into(),
        },
    )
    .unwrap();
    let operations = state.services.operations.clone();
    let daemon = Daemon::initialize_with(state.clone(), |_| async { Ok(()) }).await.unwrap();
    // 占满单连接池，在真实认证查询获取连接之前暂停，不添加生产故障钩子。
    let held = repo.pool().acquire().await.unwrap();
    tokio::time::pause();
    let (stop, stopped) = oneshot::channel();
    let (entered, observed) = oneshot::channel();
    let serve = tokio::spawn(daemon.serve_stdio_with_shutdown(None, tokio::io::empty(), tokio::io::sink(), async {
        entered.send(()).unwrap();
        let _ = stopped.await;
    }));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        observed.await.unwrap();
        stop.send(()).unwrap();
        serve.await.unwrap().unwrap();
    })
    .await
    .expect("authentication cannot outlive the shared shutdown budget");
    assert!(operations.spawn(async {}).is_err());
    drop(held);
    repo.pool().close().await;
    cleanup_test_app(root, &[&state]).await;
}

#[path = "runtime_explanation_tests.rs"]
mod explanations;
