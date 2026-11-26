//! 两库共同验收本人同意、事务排序、有界收件箱及生命周期。
use memoswish_core::{
    CoreError, Principal, identity::IdentityRepo, lifecycle::LifecycleRepo, privacy::PrivacyRepo, repo::MembershipRepo,
    repo::Repository,
};
use memoswish_protocol::{DiagnosticReport, PrivacyPolicy, PrivacyUpdate};

pub(crate) fn policy() -> PrivacyPolicy {
    let mut p = memoswish_protocol::examples::sample_privacy_policy();
    p.purpose_versions.insert("diagnostics".into(), "diagnostics-v1".into());
    p
}
async fn grant(repo: &impl Repository, p: &Principal) -> i64 {
    let policy = policy();
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("diagnostics", "diagnostics-v1", ""),
    ] {
        let state = repo.privacy_state(&p.tenant_id, p).await.unwrap();
        repo.privacy_update(
            &p.tenant_id,
            p,
            &policy,
            &PrivacyUpdate {
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
    repo.privacy_state(&p.tenant_id, p).await.unwrap().revision
}
fn report(revision: i64) -> DiagnosticReport {
    DiagnosticReport {
        report_id: memoswish_core::ids::new_id().replace('-', ""),
        privacy_revision: revision,
        captured_at_ms: chrono::Utc::now().timestamp_millis() - 1000,
        ..memoswish_protocol::examples::sample_diagnostic_report()
    }
}
fn withdrawal(revision: i64) -> PrivacyUpdate {
    PrivacyUpdate {
        expected_revision: revision,
        kind: "diagnostics".into(),
        version: "diagnostics-v1".into(),
        decision: false,
        value: String::new(),
    }
}

async fn prepare_restart(repo: &impl Repository) -> (Principal, DiagnosticReport) {
    let p = Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
    repo.privacy_install_policy(&policy()).await.unwrap();
    let r = report(grant(repo, &p).await);
    repo.diagnostic_insert(&p.tenant_id, &p, &policy(), &r).await.unwrap();
    repo.privacy_update(&p.tenant_id, &p, &policy(), &withdrawal(r.privacy_revision)).await.unwrap();
    (p, r)
}

async fn after_restart(repo: &impl Repository, p: &Principal, r: &DiagnosticReport) {
    assert!(repo.diagnostic_insert(&p.tenant_id, p, &policy(), r).await.is_err());
    assert!(repo.diagnostic_dispatch(&p.tenant_id, p, &policy(), r).await.is_err());
    assert!(repo.export_workspace(p).await.unwrap().data["diagnostic_reports"].is_empty());
}

macro_rules! backend {
    ($repo:ty,$pool:ty,$migrations:literal) => {
        async fn suite(repo: &$repo) {
            use memoswish_core::diagnostics::*;
            let p = Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
            let other = Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
            let policy = policy();
            repo.privacy_install_policy(&policy).await.unwrap();
            assert!(repo.diagnostic_insert(&p.tenant_id, &p, &policy, &report(0)).await.is_err());
            let rev = grant(repo, &p).await;
            let r = report(rev);
            assert!(repo.diagnostic_insert(&other.tenant_id, &p, &policy, &r).await.is_err());
            assert!(repo.diagnostic_insert(&other.tenant_id, &other, &policy, &r).await.is_err());
            assert!(
                repo.diagnostic_insert(&p.tenant_id, &Principal { via: "api_token".into(), ..p.clone() }, &policy, &r)
                    .await
                    .is_err()
            );
            let accepted = repo.diagnostic_receive(&p.tenant_id, &p, &policy, &r, true).await.unwrap();
            assert!(!accepted.duplicate);
            assert!(repo.diagnostic_insert(&p.tenant_id, &p, &policy, &r).await.unwrap().duplicate);
            let expired_recovery = report(rev);
            repo.diagnostic_receive(&p.tenant_id, &p, &policy, &expired_recovery, true).await.unwrap();
            sqlx::query("UPDATE diagnostic_reports SET expires_at_ms=0 WHERE tenant_id=$1 AND user_id=$2 AND report_id=$3")
                .bind(&p.tenant_id).bind(&p.user_id).bind(&expired_recovery.report_id).execute(repo.pool()).await.unwrap();
            use memoswish_core::maintenance::*;
            let task = repo.register_maintenance(&TaskRegistration::system(TaskKind::DiagnosticRecovery)).await.unwrap();
            let claim = repo.claim_maintenance(&task, "diagnostic-scanner").await.unwrap().unwrap();
            let page = repo.maintenance_discover(&claim).await.unwrap();
            assert_eq!(page.len(), 1);
            let mut stale = claim.clone();
            stale.token = "replaced-owner".into();
            assert!(repo.admit_maintenance_item(&stale, &page[0]).await.is_err());
            let admission = repo.admit_maintenance_item(&claim, &page[0]).await.unwrap();
            assert!(repo.admit_maintenance_item(&claim, &page[0]).await.is_err());
            let (original, recovered) = repo.diagnostic_recovery(&admission).await.unwrap().unwrap();
            assert_eq!(original, p);
            assert_eq!(recovered.report_id, r.report_id);
            repo.release_maintenance(&claim, false).await.unwrap();
            let mut changed = r.clone();
            changed.code = "unhandled_error".into();
            assert!(matches!(
                repo.diagnostic_insert(&p.tenant_id, &p, &policy, &changed).await,
                Err(CoreError::Conflict(_))
            ));
            for sentinel in [
                "https://secret:pass@example.invalid/?token=secret",
                "/synthetic-user/private/secret",
                "秘密\npassword=secret",
                "SELECT secret FROM cards",
                "email@example.invalid",
            ] {
                let mut unsafe_report = report(rev);
                unsafe_report.frames = vec![sentinel.into()];
                let error = repo.diagnostic_insert(&p.tenant_id, &p, &policy, &unsafe_report).await.unwrap_err();
                assert!(!format!("{error:?} {error}").contains(sentinel));
            }
            let mut too_many = report(rev);
            too_many.frames = vec!["data".into(); 33];
            assert!(validate(&too_many).is_err());
            let mut expired = report(rev);
            expired.captured_at_ms -= RETENTION_MS;
            assert!(repo.diagnostic_insert(&p.tenant_id, &p, &policy, &expired).await.is_err());
            assert!(repo.diagnostic_dispatch(&p.tenant_id, &p, &policy, &r).await.unwrap());
            assert!(!repo.diagnostic_dispatch(&p.tenant_id, &p, &policy, &r).await.unwrap());
            assert!(repo.diagnostic_recovery(&admission).await.unwrap().is_none());
            let stored:Option<String> = sqlx::query_scalar("SELECT forward_authority FROM diagnostic_reports WHERE tenant_id=$1 AND user_id=$2 AND report_id=$3").bind(&p.tenant_id).bind(&p.user_id).bind(&r.report_id).fetch_one(repo.pool()).await.unwrap();
            assert!(stored.is_none());
            for _ in 1..SUBJECT_CAP - 1 {
                repo.diagnostic_insert(&p.tenant_id, &p, &policy, &report(rev)).await.unwrap();
            }
            let left = report(rev);
            let right = report(rev);
            let (left, right) = tokio::join!(
                repo.diagnostic_insert(&p.tenant_id, &p, &policy, &left),
                repo.diagnostic_insert(&p.tenant_id, &p, &policy, &right)
            );
            assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
            assert!(matches!(
                repo.diagnostic_insert(&p.tenant_id, &p, &policy, &report(rev)).await,
                Err(CoreError::Conflict(_))
            ));
            let personal =
                repo.export_personal(&memoswish_core::lifecycle::AccountAuthority::Workspace(p.clone())).await.unwrap();
            assert_eq!(
                personal.workspaces.iter().find(|w| w.tenant_id == p.tenant_id).unwrap().data["diagnostic_reports"]
                    .len(),
                SUBJECT_CAP as usize
            );
            let export = repo.account_export(&p.tenant_id, &p.user_id, true).await.unwrap();
            assert_eq!(export["diagnostic_reports"].as_array().unwrap().len(), SUBJECT_CAP as usize);
            // 相同租户中的 owner 不能读取成员的诊断。
            let member = crate::lifecycle_conformance::member(repo, &p.tenant_id, memoswish_core::Role::Learner).await;
            let member = Principal { via: "single_user".into(), ..member };
            let mr = report(grant(repo, &member).await);
            repo.diagnostic_insert(&member.tenant_id, &member, &policy, &mr).await.unwrap();
            let workspace = repo.export_workspace(&p).await.unwrap();
            assert!(workspace.data["diagnostic_reports"].iter().all(|v| v["report_id"] != mr.report_id));
            let other_revision = grant(repo, &other).await;
            let neighbor = report(other_revision);
            repo.diagnostic_insert(&other.tenant_id, &other, &policy, &neighbor).await.unwrap();
            repo.privacy_update(&p.tenant_id, &p, &policy, &withdrawal(rev)).await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM diagnostic_reports WHERE tenant_id=$1 AND user_id=$2"
                )
                .bind(&p.tenant_id)
                .bind(&p.user_id)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
                0
            );
            assert!(repo.diagnostic_insert(&p.tenant_id, &p, &policy, &r).await.is_err());
            assert!(repo.diagnostic_dispatch(&p.tenant_id, &p, &policy, &r).await.is_err());
            let regranted = grant(repo, &p).await;
            assert!(regranted > rev);
            assert!(repo.diagnostic_insert(&p.tenant_id, &p, &policy, &r).await.is_err());
            let current = report(regranted);
            repo.diagnostic_insert(&p.tenant_id, &p, &policy, &current).await.unwrap();
            let mut new_policy = policy.clone();
            new_policy.notice_version = "notice-v2".into();
            repo.privacy_install_policy(&new_policy).await.unwrap();
            assert!(repo.diagnostic_insert(&p.tenant_id, &p, &policy, &current).await.is_err());
            assert!(repo.diagnostic_insert(&p.tenant_id, &p, &new_policy, &current).await.is_err());
            repo.privacy_install_policy(&policy).await.unwrap();
            // 恢复撤回复用既有 P2.6 命令；重复重放仍清除快照旧行。
            let mut tx = repo.pool().begin().await.unwrap();
            <$repo>::session_lock(&mut tx).await.unwrap();
            <$repo>::privacy_restore_withdrawal_tx(
                &mut tx,
                &p.tenant_id,
                &p.user_id,
                "diagnostics",
                "diagnostics-v1",
                1794096000,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM diagnostic_reports WHERE user_id=$1")
                    .bind(&p.user_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap(),
                0
            );
            assert!(repo.diagnostic_insert(&p.tenant_id, &p, &policy, &current).await.is_err());
            // TTL 维护预览不修改，应用只移除过期正文。
            sqlx::query("UPDATE diagnostic_reports SET expires_at_ms=0 WHERE tenant_id=$1 AND report_id=$2")
                .bind(&other.tenant_id)
                .bind(&neighbor.report_id)
                .execute(repo.pool())
                .await
                .unwrap();
            let retention = crate::retention::RetentionPolicy {
                version: 1,
                api_metadata_after_expiry_seconds: 0,
                failed_tts_payload_after_schedule_seconds: 0,
            };
            assert_eq!(
                repo.retention_sweep(&other.tenant_id, &retention, 1, false).await.unwrap().expired_diagnostics,
                1
            );
            assert_eq!(
                repo.retention_sweep(&other.tenant_id, &retention, 1, true).await.unwrap().expired_diagnostics,
                1
            );
            assert_eq!(
                repo.retention_sweep(&other.tenant_id, &retention, 1, true).await.unwrap().expired_diagnostics,
                0
            );
            repo.membership_remove(&member.tenant_id, &member.user_id).await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM diagnostic_reports WHERE user_id=$1")
                    .bind(&member.user_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap(),
                0
            );
            let survivor = report(other_revision);
            repo.diagnostic_insert(&other.tenant_id, &other, &policy, &survivor).await.unwrap();
            let fresh = report(grant(repo, &p).await);
            repo.diagnostic_insert(&p.tenant_id, &p, &policy, &fresh).await.unwrap();
            repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM diagnostic_reports WHERE tenant_id=$1")
                    .bind(&p.tenant_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM diagnostic_reports WHERE tenant_id=$1")
                    .bind(&other.tenant_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap(),
                1
            );
            // 通过批量夹具填满安装容量，新主体仍不能绕过全局上限。
            sqlx::query("WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<9999) INSERT INTO diagnostic_reports(tenant_id,user_id,report_id,body,privacy_revision,created_at_ms,expires_at_ms) SELECT $1,$2,CAST(n AS TEXT),$3,$4,$5,$6 FROM numbers")
                .bind(&other.tenant_id).bind(&other.user_id).bind(serde_json::to_string(&survivor).unwrap())
                .bind(other_revision).bind(survivor.captured_at_ms).bind(survivor.captured_at_ms+RETENTION_MS)
                .execute(repo.pool()).await.unwrap();
            let newcomer=Principal{via:"single_user".into(),..crate::asset_conformance::seed(repo).await};
            let newcomer_report=report(grant(repo,&newcomer).await);
            assert!(matches!(repo.diagnostic_insert(&newcomer.tenant_id,&newcomer,&policy,&newcomer_report).await,Err(CoreError::Conflict(_))));
            // 本用例结束后释放合成夹具，不影响后续排序场景。
            repo.account_erase(&other.tenant_id,&other.user_id,true).await.unwrap();
            repo.diagnostic_insert(&newcomer.tenant_id,&newcomer,&policy,&newcomer_report).await.unwrap();
            repo.close_account_authorized(&memoswish_core::lifecycle::AccountAuthority::Workspace(newcomer.clone()),&memoswish_core::lifecycle::CloseAccount{confirmed_exclusive_workspaces:vec![newcomer.tenant_id.clone()]}).await.unwrap();
            assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM diagnostic_reports WHERE user_id=$1").bind(&newcomer.user_id).fetch_one(repo.pool()).await.unwrap(),0);
        }
        async fn ordering(repo: &$repo) {
            use crate::learning::{TestGate, TestPoint};
            use memoswish_core::diagnostics::DiagnosticRepo;
            for point in [TestPoint::BeforeTransaction, TestPoint::BeforeCommit] {
                let p = Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
                let policy = policy();
                repo.privacy_install_policy(&policy).await.unwrap();
                let rev = grant(repo, &p).await;
                let r = report(rev);
                let gate = TestGate::new(point);
                let mut writer = repo.clone();
                writer.learning_gate = Some(gate.clone());
                let wp = p.clone();
                let pol = policy.clone();
                let wr = r.clone();
                let insert = tokio::spawn(async move { writer.diagnostic_insert(&wp.tenant_id, &wp, &pol, &wr).await });
                gate.reached.notified().await;
                if point == TestPoint::BeforeTransaction {
                    repo.privacy_update(&p.tenant_id, &p, &policy, &withdrawal(rev)).await.unwrap();
                    gate.resume.add_permits(1);
                    assert!(insert.await.unwrap().is_err());
                } else {
                    gate.resume.add_permits(1);
                    assert!(insert.await.unwrap().is_ok());
                    repo.privacy_update(&p.tenant_id, &p, &policy, &withdrawal(rev)).await.unwrap();
                }
                assert_eq!(
                    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM diagnostic_reports WHERE user_id=$1")
                        .bind(&p.user_id)
                        .fetch_one(repo.pool())
                        .await
                        .unwrap(),
                    0
                );
            }
        }
        async fn upgrade(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            crate::foundation_conformance::through(&full, 28).run(pool).await.unwrap();
            sqlx::query("CREATE TABLE diagnostic_reports(invalid TEXT)").execute(pool).await.unwrap();
            assert!(full.run(pool).await.is_err());
            sqlx::query("DROP TABLE diagnostic_reports").execute(pool).await.unwrap();
            full.run(pool).await.unwrap();
            full.run(pool).await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM diagnostic_reports").fetch_one(pool).await.unwrap(),
                0
            );
        }
    };
}
#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    backend!(crate::sqlite::SqliteRepository, sqlx::SqlitePool, "./migrations/sqlite");
    #[tokio::test]
    async fn sqlite_diagnostics_policy_bounds_lifecycle_and_ordering() {
        let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
        suite(&repo).await;
        ordering(&repo).await;
    }
    #[tokio::test]
    async fn sqlite_diagnostics_upgrade() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        upgrade(&pool).await;
        pool.close().await;
    }
    #[tokio::test]
    async fn sqlite_diagnostics_restart_after_withdrawal() {
        let path = std::env::temp_dir().join(format!("memoswish-diagnostics-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = crate::sqlite::SqliteRepository::connect(&url).await.unwrap();
        let (p, r) = prepare_restart(&repo).await;
        repo.pool().close().await;
        let repo = crate::sqlite::SqliteRepository::connect(&url).await.unwrap();
        after_restart(&repo, &p, &r).await;
        repo.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    backend!(crate::postgres::PostgresRepository, sqlx::PgPool, "./migrations/postgres");
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_diagnostics_policy_bounds_lifecycle_ordering_and_upgrade() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let fixture = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let repo = crate::postgres::PostgresRepository::connect_with_options(fixture.options(), 4).await.unwrap();
            suite(&repo).await;
            ordering(&repo).await;
            let (p, r) = prepare_restart(&repo).await;
            repo.pool().close().await;
            let repo = crate::postgres::PostgresRepository::connect_with_options(fixture.options(), 4).await.unwrap();
            after_restart(&repo, &p, &r).await;
            repo.pool().close().await;
            fixture.cleanup().await;
            let fixture = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let pool =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            upgrade(&pool).await;
            pool.close().await;
            fixture.cleanup().await;
        });
    }
}
