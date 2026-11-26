//! 角色只发现各自目录；周期沿用既有 cadence，任务与单项执行都经共享准入。

use memoswish_core::{CoreError, CoreResult, maintenance::*};

use crate::{app::AppState, deployment::Role};

pub(crate) fn catalog(role: Role, oauth: bool) -> Vec<TaskKind> {
    let mut kinds = Vec::new();
    if role.executes() {
        kinds.extend([
            TaskKind::ImportRecovery,
            TaskKind::SpeechRecovery,
            TaskKind::AttachmentRecovery,
            TaskKind::ExplanationRecovery,
            TaskKind::DiagnosticRecovery,
        ]);
    }
    if role.maintains() {
        kinds.extend([
            TaskKind::PasswordExpiry,
            TaskKind::FeedExpiry,
            TaskKind::IdentityExpiry,
            TaskKind::TombstoneReconcile,
            TaskKind::ErasureRecovery,
        ]);
        if oauth {
            kinds.push(TaskKind::OAuthExpiry);
        }
        kinds.push(TaskKind::Retention);
    }
    kinds
}

fn kinds(st: &AppState) -> Vec<TaskKind> {
    #[cfg(feature = "mcp-oauth")]
    let oauth = st.oauth.is_some();
    #[cfg(not(feature = "mcp-oauth"))]
    let oauth = false;
    let mut kinds = catalog(st.config.role, oauth);
    if !st.config.diagnostic_forwarding.enabled {
        kinds.retain(|kind| *kind != TaskKind::DiagnosticRecovery);
    }
    kinds
}

pub(crate) async fn initialize(st: &AppState) -> CoreResult<()> {
    for kind in kinds(st) {
        if kind != TaskKind::Retention {
            st.repo.register_maintenance(&TaskRegistration::system(kind)).await?;
        }
    }
    pass_inner(st, true).await?;
    Ok(())
}

pub(crate) async fn pass(st: &AppState) -> CoreResult<()> {
    pass_inner(st, false).await
}

#[cfg(test)]
pub(crate) async fn startup_pass(st: &AppState) -> CoreResult<()> {
    pass_inner(st, true).await
}

async fn pass_inner(st: &AppState, await_erasure: bool) -> CoreResult<()> {
    crate::metrics::sample(st).await;
    for kind in kinds(st) {
        if matches!(
            st.health.lifecycle.phase(),
            crate::lifecycle::Phase::Draining | crate::lifecycle::Phase::Stopped | crate::lifecycle::Phase::Failed
        ) {
            break;
        }
        // 目录页只返回已到期任务；已处理任务推迟到下一周期，避免首批租户饿死后续任务。
        let tasks = st.repo.maintenance_tasks(kind, "").await?;
        for id in tasks {
            if matches!(
                st.health.lifecycle.phase(),
                crate::lifecycle::Phase::Draining | crate::lifecycle::Phase::Stopped | crate::lifecycle::Phase::Failed
            ) {
                break;
            }
            if matches!(
                kind,
                TaskKind::ExplanationRecovery
                    | TaskKind::ImportRecovery
                    | TaskKind::SpeechRecovery
                    | TaskKind::AttachmentRecovery
            ) {
                if let Ok(task) = st.services.recover_scheduled(kind) {
                    let metrics = st.metrics.clone();
                    st.services.operations.spawn(async move {
                        observe(&metrics, kind, matches!(task.await, Ok(Ok(()))));
                    })?;
                }
                continue;
            }
            let permit = if kind.discovery() {
                let Ok(permit) = memoswish_application::Services::maintenance_work_permit(kind) else { continue };
                Some(permit)
            } else {
                None
            };
            let work = st.clone();
            let task = st.services.operations.spawn(async move {
                let _permit = permit.map(std::sync::Arc::new);
                let Some(claim) = work.repo.claim_maintenance(&id, &memoswish_core::ids::new_id()).await? else {
                    return Ok(());
                };
                let result = run_claim(&work, &claim, _permit).await;
                if result.is_err() && !claim.kind.discovery() {
                    let _ = work.repo.release_maintenance(&claim, true).await;
                }
                observe(&work.metrics, kind, result.is_ok());
                result
            })?;
            if kind == TaskKind::DiagnosticRecovery || (kind.discovery() && !await_erasure) {
                drop(task);
            } else {
                let _ = task.await;
            }
        }
    }
    Ok(())
}

// S26d 可在此窄钩子接入有限 kind/result 词汇；不提供 tenant、user 或任务 ID 标签。
fn observe(metrics: &crate::metrics::Metrics, kind: TaskKind, success: bool) {
    memoswish_core::observability::Observer::maintenance(metrics, kind, success);
    tracing::debug!(target: "memoswish::maintenance_scheduler",
        task_kind = kind.as_str(),
        outcome = if success { "page_ok" } else { "page_error" },
        "Maintenance scheduling observation"
    );
}

async fn run_claim(
    st: &AppState,
    claim: &MaintenanceClaim,
    permit: Option<std::sync::Arc<tokio::sync::SemaphorePermit<'static>>>,
) -> CoreResult<()> {
    if !claim.kind.discovery() {
        return st.repo.maintenance_sql_page(claim).await;
    }
    let (page, mut failed) = st.services.admit_scheduled_page(claim.clone()).await?;
    for admission in page {
        let work = st.clone();
        let kind = claim.kind;
        let business_permit = permit.clone();
        let task = st.services.operations.spawn(async move {
            let _permit = business_permit;
            if kind == TaskKind::DiagnosticRecovery {
                if let Some((principal, report)) = work.repo.diagnostic_recovery(&admission).await? {
                    crate::diagnostics::forward(&work, &principal, &report).await;
                }
            } else if let Some(job) = work.repo.erasure_work(&admission.item.id).await? {
                crate::account::finish(&work, &job.job).await?;
            }
            Ok::<(), CoreError>(())
        });
        match task {
            Ok(task) => {
                if !matches!(task.await, Ok(Ok(()))) {
                    failed = true;
                }
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    if failed {
        st.services.pace_scheduled_failure(claim.kind).await;
        return Err(CoreError::internal("maintenance page failed"));
    }
    Ok(())
}

pub(crate) async fn run_loop(st: AppState) {
    if matches!(st.config.role, Role::Api | Role::Migrator) {
        return;
    }
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(CADENCE_MS as u64));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { biased; _=st.health.lifecycle.draining()=>return,_=interval.tick()=>{} }
        let work = st.clone();
        let Ok(task) = st.services.operations.spawn(async move { pass(&work).await }) else { return };
        // 丢弃等待者不取消已接纳工作；原共享 shutdown 预算负责排空。
        tokio::select! { _=st.health.lifecycle.draining()=>return, result=task=>{
            if !matches!(result,Ok(Ok(()))) {tracing::error!(target: "memoswish::maintenance_scheduler", "Maintenance scheduling pass failed");}
        }}
    }
}

// 测试模拟下一个数据库调度周期，仅使 queued 任务到期，不夺取 running owner。
#[cfg(test)]
pub(crate) async fn due_for_test(config: &crate::Config) -> CoreResult<()> {
    due_scope_for_test(config, "", "").await
}

// 单项业务重试只推进指定 queued 记录，不能夺取其他业务或扫描器 owner。
#[cfg(test)]
pub(crate) async fn business_due_for_test(config: &crate::Config, tenant: &str, id: &str) -> CoreResult<()> {
    due_scope_for_test(config, tenant, id).await
}

#[cfg(test)]
async fn due_scope_for_test(config: &crate::Config, tenant: &str, id: &str) -> CoreResult<()> {
    let url = config.database_url();
    match memoswish_storage::DatabaseKind::from_url(&url)? {
        #[cfg(feature = "sqlite")]
        memoswish_storage::DatabaseKind::Sqlite => {
            let repo = memoswish_storage::sqlite::SqliteRepository::open_runtime(&url).await?;
            sqlx::query(
                "UPDATE background_jobs SET available_at_ms=0 WHERE state='queued' AND ((work_scope='maintenance' AND $2='') OR (tenant_id=$1 AND id=$2))",
            )
            .bind(tenant)
            .bind(id)
            .execute(repo.pool())
            .await
            .map_err(|_| CoreError::internal("test maintenance clock update failed"))?;
            repo.pool().close().await;
        }
        #[cfg(feature = "postgres")]
        memoswish_storage::DatabaseKind::Postgres => {
            let repo = memoswish_storage::postgres::PostgresRepository::open_runtime(&url, 1).await?;
            sqlx::query(
                "UPDATE background_jobs SET available_at_ms=0 WHERE state='queued' AND ((work_scope='maintenance' AND $2='') OR (tenant_id=$1 AND id=$2))",
            )
            .bind(tenant)
            .bind(id)
            .execute(repo.pool())
            .await
            .map_err(|_| CoreError::internal("test maintenance clock update failed"))?;
            repo.pool().close().await;
        }
        #[allow(unreachable_patterns)]
        _ => return Err(CoreError::Unsupported("test maintenance backend is unavailable".into())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn erasure_scanner_admission_failure_records_page_error_and_retries() {
        for failure_index in [0, 1] {
            let dir = std::env::temp_dir().join(format!("memoswish-scanner-{}", memoswish_core::ids::new_id()));
            let st =
                AppState::assemble(crate::Config { data_dir: dir.clone(), seed_demo: false, ..Default::default() })
                    .await
                    .unwrap();
            let repo =
                memoswish_storage::sqlite::SqliteRepository::open_runtime(&st.config.database_url()).await.unwrap();
            // 使用既有账户级擦除夹具，不创建或借用业务租户。
            for id in ["item-000", "item-001"] {
                let body = serde_json::json!({"id":id,"tenant_id":null,"purge_assets":false,"credentials":[]});
                sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
                    .bind(id)
                    .bind(body.to_string())
                    .execute(repo.pool())
                    .await
                    .unwrap();
            }
            let task =
                st.repo.register_maintenance(&TaskRegistration::system(TaskKind::ErasureRecovery)).await.unwrap();
            sqlx::raw_sql(&format!(
                "CREATE TRIGGER fail_erasure_admission BEFORE UPDATE OF cursor ON maintenance_tasks \
                 WHEN NEW.task_kind='erasure_recovery' AND NEW.cursor LIKE '%item-{failure_index:03}%' \
                 BEGIN SELECT RAISE(ABORT,'private-erasure-sentinel'); END"
            ))
            .execute(repo.pool())
            .await
            .unwrap();
            startup_pass(&st).await.unwrap();
            let schedule: (String, Option<String>) =
                sqlx::query_as("SELECT state,error FROM background_jobs WHERE tenant_id='' AND id=$1")
                    .bind(&task)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert_eq!(schedule, ("queued".into(), Some("maintenance page failed".into())));
            let cursor: String = sqlx::query_scalar("SELECT cursor FROM maintenance_tasks WHERE id=$1")
                .bind(&task)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            let expected = if failure_index == 0 { vec![] } else { vec!["".to_string(), "item-000".to_string()] };
            assert_eq!(serde_json::from_str::<Vec<String>>(&cursor).unwrap(), expected);
            let admitted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM maintenance_admissions WHERE task_id=$1")
                .bind(&task)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(admitted, failure_index as i64);
            assert_ne!(
                st.repo.erasure_work(&format!("item-{failure_index:03}")).await.unwrap().unwrap().progress,
                "complete"
            );
            sqlx::raw_sql("DROP TRIGGER fail_erasure_admission").execute(repo.pool()).await.unwrap();
            due_for_test(&st.config).await.unwrap();
            startup_pass(&st).await.unwrap();
            let error: Option<String> =
                sqlx::query_scalar("SELECT error FROM background_jobs WHERE tenant_id='' AND id=$1")
                    .bind(&task)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert_eq!(error, None);
            for id in ["item-000", "item-001"] {
                assert_eq!(st.repo.erasure_work(id).await.unwrap().unwrap().progress, "complete");
            }
            st.services.operations.close();
            st.services.operations.wait().await;
            repo.pool().close().await;
            crate::runtime::cleanup_test_app(dir, &[&st]).await;
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn diagnostic_startup_detaches_network_and_shared_shutdown_drains_it() {
        use memoswish_storage::sqlite::SqliteRepository;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (connected, connection) = tokio::sync::oneshot::channel();
        let (release, held) = tokio::sync::oneshot::channel();
        let receiver = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            connected.send(()).unwrap();
            let _ = held.await;
            drop(socket);
        });
        let root = std::env::temp_dir().join(format!("s26c-diagnostic-startup-{}", memoswish_core::ids::new_id()));
        let mut forwarding = crate::diagnostics::ForwardingConfig {
            enabled: true,
            endpoint: format!("https://{address}/api/1/envelope/"),
            public_key: "public123".into(),
            purpose_version: String::new(),
        };
        forwarding.purpose_version = forwarding.recipient_version();
        let mut policy = memoswish_protocol::examples::sample_privacy_policy();
        policy.hosted = false;
        policy.purpose_versions.insert("diagnostics".into(), forwarding.purpose_version.clone());
        let mut config = crate::Config {
            data_dir: root.clone(),
            seed_demo: false,
            privacy: policy,
            diagnostic_forwarding: forwarding,
            ..Default::default()
        };
        config.tts.auto_detect_espeak = false;
        // 先准备持久夹具，首次调度仅由下方 initialize 启动，避免空启动扫描抢先消费新报告。
        let st = AppState::assemble(config).await.unwrap();
        st.health.attach(&st).unwrap();
        st.health.lifecycle.set(crate::lifecycle::Phase::Running);
        let p = st.services.auth.authenticate(None).await.unwrap();
        for (kind, version, value) in [
            ("notice", "notice-v1", ""),
            ("terms", "terms-v1", ""),
            ("age", "notice-v1", "example-region"),
            ("diagnostics", st.config.diagnostic_forwarding.purpose_version.as_str(), ""),
        ] {
            let state = st.services.privacy_state(&p).await.unwrap();
            st.services
                .update_privacy(
                    &p,
                    &memoswish_protocol::PrivacyUpdate {
                        expected_revision: state.revision,
                        kind: kind.into(),
                        version: version.into(),
                        value: value.into(),
                        decision: true,
                    },
                )
                .await
                .unwrap();
        }
        let report = memoswish_protocol::DiagnosticReport {
            privacy_revision: st.services.privacy_state(&p).await.unwrap().revision,
            purpose_version: st.config.diagnostic_forwarding.purpose_version.clone(),
            captured_at_ms: chrono::Utc::now().timestamp_millis() - 1000,
            ..memoswish_protocol::examples::sample_diagnostic_report()
        };
        let mut automatic = report.clone();
        automatic.report_id = memoswish_core::ids::new_id().replace('-', "");
        st.services.report_diagnostic(&p, &automatic).await.unwrap();
        st.services.report_forwardable_diagnostic(&p, &report).await.unwrap();
        let repo = SqliteRepository::open_runtime(&st.config.database_url()).await.unwrap();
        let eligible: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM diagnostic_reports WHERE forward_authority IS NOT NULL")
                .fetch_one(repo.pool())
                .await
                .unwrap();
        assert_eq!(eligible, 1, "automatic server events must remain first-party only");
        due_for_test(&st.config).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), initialize(&st))
            .await
            .expect("startup must not await diagnostic network work")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), connection).await.unwrap().unwrap();
        let marked: i64 = sqlx::query_scalar("SELECT SUM(dispatch_started) FROM diagnostic_reports")
            .fetch_one(repo.pool())
            .await
            .unwrap();
        assert_eq!(marked, 1);
        let deadline = st.health.lifecycle.drain();
        {
            let drain = crate::runtime::drain_background(&st);
            tokio::pin!(drain);
            tokio::select! {
                biased;
                _ = &mut drain => panic!("shutdown returned before accepted diagnostic work finished"),
                _ = tokio::task::yield_now() => {},
            }
            assert_eq!(st.health.lifecycle.drain(), deadline);
            release.send(()).unwrap();
            receiver.await.unwrap();
            drain.await;
        }
        assert_eq!(st.health.lifecycle.phase(), crate::lifecycle::Phase::Stopped);
        repo.pool().close().await;
        crate::runtime::cleanup_test_app(root, &[&st]).await;
    }

    struct HandoffTts {
        calls: std::sync::atomic::AtomicUsize,
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
        exhaust: bool,
    }

    #[async_trait::async_trait]
    impl memoswish_core::tts::TtsEngine for HandoffTts {
        fn id(&self) -> &str {
            "hf11-handoff"
        }
        fn voices(&self) -> Vec<memoswish_core::tts::VoiceInfo> {
            vec![]
        }
        async fn synthesize(
            &self,
            request: &memoswish_core::tts::TtsRequest,
        ) -> CoreResult<memoswish_core::tts::TtsOutput> {
            use std::sync::atomic::Ordering;
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
                // 模拟执行任务在 durable uncertain 提交后被终止，跳过普通失败收尾。
                panic!("injected provider executor termination");
            }
            if self.exhaust {
                return Err(CoreError::Unavailable("injected provider refusal".into()));
            }
            memoswish_core::tts::TtsEngine::synthesize(&memoswish_media::tts::placeholder::PlaceholderTts, request)
                .await
        }
    }

    macro_rules! handoff_case {
        ($name:ident, $repo:ty) => {
            async fn $name(mut st: AppState, repo: &$repo, exhaust: bool) {
                std::fs::create_dir_all(st.config.assets_dir()).unwrap();
                use memoswish_core::{repo::ContentRepo, tts::TtsEngine};
                use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
                let engine = Arc::new(HandoffTts { calls: AtomicUsize::new(0), entered: tokio::sync::Semaphore::new(0), release: tokio::sync::Semaphore::new(0), exhaust });
                st.services.media = memoswish_media::MediaService::new(st.repo.clone(), st.store.clone(), st.services.quota.clone(), vec![engine.clone()], engine.id()).unwrap();
                let p = st.services.auth.authenticate(None).await.unwrap();
                let mut deck = memoswish_protocol::examples::sample_deck(); deck.id = memoswish_core::ids::new_id();
                let mut card = memoswish_protocol::examples::sample_card(); card.id = memoswish_core::ids::new_id(); card.deck_id = deck.id.clone(); card.tts = None;
                repo.insert_deck_with_cards(&p.tenant_id, &deck, &[card.clone()]).await.unwrap();
                let request_id = if exhaust { "hf11-exhaust" } else { "hf11-success" };
                let options = memoswish_media::SynthesizeOptions::default();
                let accepted = st.services.media.submit_tts(&p, request_id, std::slice::from_ref(&card.id), &options).await.unwrap();
                let request = st.repo.speech_request(&p.tenant_id, &accepted.items[0].item_id).await.unwrap();
                let task_id = TaskRegistration::system(TaskKind::SpeechRecovery).id().unwrap();
                // 通过真实 daemon scheduler 启动首轮业务，网络屏障不持有 scanner 租约。
                initialize(&st).await.unwrap();
                engine.entered.acquire().await.unwrap().forget();
                let scanner: (String, Option<String>, i64) = sqlx::query_as("SELECT state,token,lease_until_ms FROM background_jobs WHERE tenant_id='' AND id=$1").bind(&task_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(scanner, ("queued".into(), None, 0));
                assert!(memoswish_application::Services::maintenance_work_permit(TaskKind::SpeechRecovery).is_err());
                let old: String = sqlx::query_scalar("SELECT token FROM background_jobs WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                let uncertain: String = sqlx::query_scalar("SELECT outcome FROM tts_provider_attempts WHERE tenant_id=$1 AND synthesis_id=$2 AND claim_token=$3").bind(&p.tenant_id).bind(&request.synthesis_id).bind(&old).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(uncertain, "uncertain");
                pass(&st).await.unwrap();
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM maintenance_admissions WHERE task_id=$1").bind(&task_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(count, 1, "a blocked page cannot accumulate unbounded admissions");
                st.services.operations.close();
                let drain = st.services.operations.wait(); tokio::pin!(drain);
                assert!(matches!(std::future::poll_fn(|cx| std::task::Poll::Ready(drain.as_mut().poll(cx))).await, std::task::Poll::Pending));
                engine.release.add_permits(1);
                drain.await;
                assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
                // 新组装的服务读取旧游标与原不确定尝试，仅夹具推进现有数据库期限。
                sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&request.synthesis_id).execute(repo.pool()).await.unwrap();
                let mut fresh = AppState::assemble(st.config.as_ref().clone()).await.unwrap();
                fresh.services.media = memoswish_media::MediaService::new(fresh.repo.clone(), fresh.store.clone(), fresh.services.quota.clone(), vec![engine.clone()], engine.id()).unwrap();
                for _ in 0..if exhaust { 4 } else { 1 } {
                    // 首次崩溃保留原租约过期路径；后续主动失败须先经过业务重试间隔。
                    sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2 AND state='queued'").bind(&p.tenant_id).bind(&request.synthesis_id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
                    due_for_test(&fresh.config).await.unwrap();
                    let result = fresh.services.recover_scheduled(TaskKind::SpeechRecovery).unwrap().await.unwrap();
                    assert_eq!(result.is_err(), exhaust);
                }
                due_for_test(&fresh.config).await.unwrap();
                fresh.services.recover_scheduled(TaskKind::AttachmentRecovery).unwrap().await.unwrap().unwrap();
                let terminal = fresh.services.tts_submission_status(&p, request_id).await.unwrap();
                assert!(terminal.complete);
                assert_eq!(terminal.items[0].receipt.as_ref().unwrap().disposition, if exhaust { memoswish_protocol::TtsDisposition::Failed } else { memoswish_protocol::TtsDisposition::Attached });
                assert_eq!(fresh.services.media.submit_tts(&p, request_id, std::slice::from_ref(&card.id), &options).await.unwrap(), terminal);
                let attempt: String = sqlx::query_scalar("SELECT outcome FROM tts_provider_attempts WHERE tenant_id=$1 AND synthesis_id=$2 AND claim_token=$3").bind(&p.tenant_id).bind(&request.synthesis_id).bind(&old).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(attempt, "uncertain");
                let job_attempts: i64 = sqlx::query_scalar("SELECT attempts FROM background_jobs WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(job_attempts, if exhaust { 5 } else { 2 });
                let accounting: (String, i64) = sqlx::query_as("SELECT state,amount FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2").bind(&p.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(accounting.0, if exhaust { "reserved" } else { "committed" });
                let usage = fresh.services.quota.snapshot(&p).await.unwrap();
                let usage = usage.metrics.iter().find(|metric| metric.metric == "tts_chars").unwrap();
                assert_eq!((usage.used, usage.held), if exhaust { (0, accounting.1 as u64) } else { (accounting.1 as u64, 0) });
                assert_eq!(engine.calls.load(Ordering::SeqCst), if exhaust { 5 } else { 2 });
                assert!(fresh.repo.fail_speech(&p.tenant_id, &memoswish_core::jobs::JobClaim { job_id: request.synthesis_id, token: old }, None).await.is_err());
                // 重放和后续调度不得再次扣额或调用 provider。
                due_for_test(&fresh.config).await.unwrap();
                fresh.services.recover_scheduled(TaskKind::SpeechRecovery).unwrap().await.unwrap().unwrap();
                assert_eq!(engine.calls.load(Ordering::SeqCst), if exhaust { 5 } else { 2 });
                crate::runtime::cleanup_test_app(&st.config.data_dir, &[&st, &fresh]).await;
            }
        };
    }

    #[cfg(feature = "sqlite")]
    handoff_case!(sqlite_handoff_case, memoswish_storage::sqlite::SqliteRepository);

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn maintenance_sqlite_hf11_scheduler_restart_uncertainty_and_exhaustion() {
        for exhaust in [false, true] {
            let root = std::env::temp_dir().join(format!("hf11-scheduler-{}", memoswish_core::ids::new_id()));
            let mut config = crate::Config { data_dir: root, seed_demo: false, ..Default::default() };
            config.tts.auto_detect_espeak = false;
            let st = AppState::assemble(config).await.unwrap();
            let repo =
                memoswish_storage::sqlite::SqliteRepository::open_runtime(&st.config.database_url()).await.unwrap();
            sqlite_handoff_case(st, &repo, exhaust).await;
            repo.pool().close().await;
        }
    }

    #[cfg(feature = "postgres")]
    handoff_case!(postgres_handoff_case, memoswish_storage::postgres::PostgresRepository);

    #[cfg(feature = "postgres")]
    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn maintenance_postgres_hf11_scheduler_restart_uncertainty_and_exhaustion() {
        memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
            for exhaust in [false, true] {
                let (fixture, url) = crate::feature_tests::postgres_database(&owner).await;
                let root = std::env::temp_dir().join(format!("hf11-scheduler-{}", memoswish_core::ids::new_id()));
                let mut config = crate::Config {
                    data_dir: root,
                    database_url: Some(url),
                    db_max_connections: Some(2),
                    seed_demo: false,
                    ..Default::default()
                };
                config.tts.auto_detect_espeak = false;
                let st = AppState::assemble(config).await.unwrap();
                let repo = fixture.repository(2).await.unwrap();
                postgres_handoff_case(st, &repo, exhaust).await;
                repo.pool().close().await;
                fixture.cleanup().await;
            }
        });
    }

    #[test]
    fn role_catalog_keeps_api_migrator_idle_and_maintenance_provider_free() {
        assert!(catalog(Role::Api, true).is_empty());
        assert!(catalog(Role::Migrator, true).is_empty());
        assert_eq!(
            catalog(Role::Worker, false),
            vec![
                TaskKind::ImportRecovery,
                TaskKind::SpeechRecovery,
                TaskKind::AttachmentRecovery,
                TaskKind::ExplanationRecovery,
                TaskKind::DiagnosticRecovery
            ]
        );
        for kind in catalog(Role::Maintenance, true) {
            assert!(!matches!(
                kind,
                TaskKind::ImportRecovery | TaskKind::SpeechRecovery | TaskKind::AttachmentRecovery
            ));
        }
        assert!(!catalog(Role::AllInOne, false).contains(&TaskKind::OAuthExpiry));
        assert!(catalog(Role::AllInOne, true).contains(&TaskKind::Retention));
    }
}

#[cfg(test)]
async fn maintain_maintenance_lease(st: &AppState, claim: &MaintenanceClaim) -> CoreResult<bool> {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis((LEASE_MS / 3) as u64));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        st.repo.renew_maintenance(claim).await?;
    }
    #[allow(unreachable_code)]
    Ok::<bool, CoreError>(false)
}

#[cfg(test)]
async fn under_maintenance_lease<C>(
    scanner: impl Future<Output = CoreResult<bool>>,
    heartbeat: impl Future<Output = CoreResult<bool>>,
    complete: impl FnOnce(bool) -> C,
) -> CoreResult<()>
where
    C: Future<Output = CoreResult<()>>,
{
    let empty = tokio::select! { biased; result=scanner=>result, result=heartbeat=>result }?;
    // 释放或完成会清除 token；必须在心跳被丢弃后执行，事务围栏继续约束真实过期。
    complete(empty).await
}

#[cfg(all(test, feature = "sqlite"))]
mod completion_tests {
    use super::*;

    #[tokio::test]
    async fn maintenance_completion_stops_heartbeat_and_preserves_expiry_fence() {
        for empty in [false, true] {
            let dir = std::env::temp_dir().join(format!("hf9-scheduler-{}", memoswish_core::ids::new_id()));
            let st =
                AppState::assemble(crate::Config { data_dir: dir.clone(), seed_demo: false, ..Default::default() })
                    .await
                    .unwrap();
            let repo =
                memoswish_storage::sqlite::SqliteRepository::open_runtime(&st.config.database_url()).await.unwrap();
            let id = repo.register_maintenance(&TaskRegistration::system(TaskKind::DiagnosticRecovery)).await.unwrap();
            let claim = repo.claim_maintenance(&id, "completion-test").await.unwrap().unwrap();
            let (heartbeat_owner, mut heartbeat_dropped) = tokio::sync::oneshot::channel::<()>();
            let (committed, observed) = tokio::sync::oneshot::channel();
            let (release, held) = tokio::sync::oneshot::channel();
            let owned = st.clone();
            let claim2 = claim.clone();
            let mut task = tokio::spawn(async move {
                let owned = &owned;
                let claim2 = &claim2;
                under_maintenance_lease(
                    async {
                        tokio::task::yield_now().await;
                        Ok(empty)
                    },
                    async {
                        let _heartbeat_owner = heartbeat_owner;
                        maintain_maintenance_lease(owned, claim2).await
                    },
                    |empty| async move {
                        assert!(
                            matches!(
                                heartbeat_dropped.try_recv(),
                                Err(tokio::sync::oneshot::error::TryRecvError::Closed)
                            ),
                            "heartbeat must be dropped before completion starts"
                        );
                        if empty {
                            owned.repo.complete_maintenance_cycle(claim2).await?;
                        } else {
                            owned.repo.release_maintenance(claim2, false).await?;
                        }
                        committed.send(()).unwrap();
                        held.await.unwrap();
                        Ok(())
                    },
                )
                .await
            });
            tokio::select! {biased; result=&mut task=>panic!("completion failed before barrier: {result:?}"), result=observed=>result.unwrap()}
            assert!(matches!(repo.renew_maintenance(&claim).await, Err(CoreError::Conflict(_))));
            tokio::time::pause();
            tokio::time::advance(std::time::Duration::from_millis(LEASE_MS as u64)).await;
            tokio::select! { biased; result=&mut task=>panic!("completion was cancelled: {result:?}"), _=tokio::task::yield_now()=>{} }
            release.send(()).unwrap();
            task.await.unwrap().unwrap();
            tokio::time::resume();
            // 完成后 token 被清除；下一次领取真实过期的 claim 仍必须拒绝提交。
            sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE tenant_id='' AND id=$1")
                .bind(&id)
                .execute(repo.pool())
                .await
                .unwrap();
            let expired = repo.claim_maintenance(&id, "expired-test").await.unwrap().unwrap();
            let repo = &repo;
            let expired = &expired;
            let result = under_maintenance_lease(
                async {
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id='' AND id=$1")
                        .bind(&id)
                        .execute(repo.pool())
                        .await
                        .unwrap();
                    Ok(empty)
                },
                maintain_maintenance_lease(&st, expired),
                |empty| async move {
                    if empty {
                        repo.complete_maintenance_cycle(expired).await.map(|_| ())
                    } else {
                        repo.release_maintenance(expired, false).await
                    }
                },
            )
            .await;
            assert!(matches!(result, Err(CoreError::Conflict(_))));
            assert!(repo.claim_maintenance(&id, "replacement-test").await.unwrap().is_some());
            repo.pool().close().await;
            crate::runtime::cleanup_test_app(dir, &[&st]).await;
        }
    }
}
