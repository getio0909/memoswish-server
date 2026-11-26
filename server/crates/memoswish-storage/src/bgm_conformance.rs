//! BGM 双库共享发布、重放、回滚、撤权与过期 claim 场景。
use memoswish_core::bgm::BgmPublicationRepo;
use memoswish_core::identity::IdentityRepo;
use memoswish_core::jobs::AssetJobRepo;
use memoswish_core::{CoreError, Principal, assets::*, repo::*};
use memoswish_protocol::BgmTrack;
use sqlx::Row;

fn track() -> BgmTrack {
    let mut t = memoswish_protocol::examples::sample_bgm_track();
    t.id = "private_bgm".into();
    t.asset.key = "tenants/pending/bgm/source.wav".into();
    t.asset.url = String::new();
    t.asset.bytes = 4;
    t.asset.sha256 = memoswish_core::ids::sha256_hex(b"wave");
    t.provenance = Some(memoswish_protocol::ContentProvenance {
        method: "manual".into(),
        rights: "CC-BY-4.0".into(),
        attribution: "Artist".into(),
        ..Default::default()
    });
    t
}
async fn accept(repo: &impl Repository, p: &Principal, request: &str, expected: Option<u32>) -> String {
    repo.accept_bgm(p, request, &track(), b"wave", expected, request, false).await.unwrap()
}
macro_rules! cases {
    ($repo:ty) => {
        async fn exhausted_prepare(repo: &$repo) -> Vec<(Principal, String, String)> {
            let mut cases = Vec::new();
            for phase in ["final-failure", "expired-final-claim", "legacy-dead-pending", "asset-recovery"] {
                let p = crate::asset_conformance::seed(repo).await;
                let id = accept(repo, &p, phase, None).await;
                sqlx::query("UPDATE background_jobs SET max_attempts=1 WHERE tenant_id=$1 AND id=$2")
                    .bind(&p.tenant_id).bind(&id).execute(repo.pool()).await.unwrap();
                let claim = repo.claim_bgm(&p.tenant_id, &id, 120_000).await.unwrap().unwrap();
                let attempt = repo.begin_upload(&p.tenant_id, &claim, "store").await.unwrap();
                if phase == "final-failure" {
                    repo.retry_asset_job(&p.tenant_id, &claim, 0).await.unwrap();
                    exhausted_assert(repo, &p, &id, &attempt.id).await;
                } else {
                    let state = if phase == "legacy-dead-pending" { "dead" } else { "running" };
                    sqlx::query("UPDATE background_jobs SET state=$3,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2")
                        .bind(&p.tenant_id).bind(&id).bind(state).execute(repo.pool()).await.unwrap();
                    if phase == "asset-recovery" {
                        assert!(repo.claim_asset_job(&p.tenant_id, "cleanup", 120_000).await.unwrap().is_none());
                        exhausted_assert(repo, &p, &id, &attempt.id).await;
                    }
                }
                cases.push((p, id, attempt.id));
            }
            cases
        }

        async fn exhausted_assert(repo: &$repo, p: &Principal, id: &str, attempt: &str) {
            let row = sqlx::query("SELECT b.request_id,b.outcome,b.audio,b.authority,j.state,j.token,j.worker,j.lease_until_ms FROM bgm_publications b JOIN background_jobs j ON j.tenant_id=b.tenant_id AND j.id=b.id WHERE b.tenant_id=$1 AND b.id=$2")
                .bind(&p.tenant_id).bind(id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(row.get::<String,_>("outcome"), "rejected");
            assert_eq!(row.get::<Option<Vec<u8>>,_>("audio"), None);
            assert_eq!(row.get::<String,_>("authority"), "{}");
            assert_eq!(row.get::<String,_>("state"), "dead");
            assert_eq!(row.get::<Option<String>,_>("token"), None);
            assert_eq!(row.get::<Option<String>,_>("worker"), None);
            assert_eq!(row.get::<i64,_>("lease_until_ms"), 0);
            assert!(repo.claim_bgm(&p.tenant_id, id, 120_000).await.unwrap().is_none());
            let request: String = row.get("request_id");
            assert_eq!(repo.bgm_request(p, &request, &request).await.unwrap().as_deref(), Some(id));
            assert_eq!(accept(repo, p, &request, None).await, id);
            let error = repo.bgm_result(&p.tenant_id, id).await.unwrap_err();
            assert!(error.to_string().contains("attempts exhausted"));
            assert_eq!(repo.bgm_result(&p.tenant_id, id).await.unwrap_err().to_string(), error.to_string());
            assert!(!repo.pending_bgm(None, 100).await.unwrap().iter().any(|(t,i)| t==&p.tenant_id && i==id));
            let attempts = repo.upload_attempts(&p.tenant_id, id).await.unwrap();
            assert!(attempts.iter().any(|a| a.id==attempt && a.outcome==UploadOutcome::Uncertain));
            assert!(repo.unresolved_assets(None,100).await.unwrap().iter().any(|(t,i)|t==&p.tenant_id && i.id==id));
            assert!(repo.get_bgm(&p.tenant_id, &track().id).await.unwrap().is_none());
        }

        async fn scenario(repo: &$repo) {
            let p=crate::asset_conformance::seed(repo).await;
            let other=crate::asset_conformance::seed(repo).await;
            let (id,duplicate)=tokio::join!(accept(repo,&p,"request",None),accept(repo,&p,"request",None));
            assert_eq!(id,duplicate);
            // BGM 经既有 speech 调度接纳，指标与发现共享登记权威且只计一次。
            use memoswish_core::{maintenance::*, observability::*};
            let task=repo.register_maintenance(&TaskRegistration::system(TaskKind::SpeechRecovery)).await.unwrap();
            let scheduled=repo.claim_maintenance(&task,"bgm-scanner").await.unwrap().unwrap();
            let page=repo.maintenance_discover(&scheduled).await.unwrap();
            let item=page.iter().find(|item|item.tenant==p.tenant_id && item.id==id).unwrap();
            let admission=repo.admit_maintenance_item(&scheduled,item).await.unwrap();
            assert_eq!(admission.kind,TaskKind::SpeechRecovery);
            repo.release_maintenance(&scheduled,false).await.unwrap();
            let snapshot=repo.operational_snapshot().await.unwrap();
            let backlog=snapshot.pending.iter().find(|w|w.kind==WorkKind::Bgm).unwrap();
            assert_eq!((backlog.count,backlog.unknown,backlog.future),(1,0,0));
            assert!(backlog.oldest_ms.is_some());
            assert!(!snapshot.pending.iter().any(|w|w.kind==WorkKind::Asset));
            assert!(matches!(repo.bgm_request(&p,"request","changed").await,Err(CoreError::Conflict(_))));
            assert_eq!(repo.bgm_request(&other,"request","changed").await.unwrap(),None);
            assert_eq!(repo.bgm_stage(&other.tenant_id,&id).await.unwrap(),None);
            let old=repo.claim_bgm(&p.tenant_id,&id,120_000).await.unwrap().unwrap();
            let old_attempt=repo.begin_upload(&p.tenant_id,&old,"store").await.unwrap();
            repo.record_upload(&p.tenant_id,&old_attempt,&ObjectVersion::Unversioned).await.unwrap();
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&id).execute(repo.pool()).await.unwrap();
            let claim=repo.claim_bgm(&p.tenant_id,&id,120_000).await.unwrap().unwrap();
            assert!(repo.publish_bgm(&p.tenant_id,&old,&old_attempt.id).await.is_err());
            let attempt=repo.begin_upload(&p.tenant_id,&claim,"store").await.unwrap();
            assert_ne!(attempt.key,old_attempt.key);
            repo.record_upload(&p.tenant_id,&attempt,&ObjectVersion::Unversioned).await.unwrap();
            // 目录写入故障必须回滚已发布 attempt、引用和结果，不丢暂存。
            let trigger=if <$repo>::IS_POSTGRES { "CREATE FUNCTION reject_bgm() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SECRET_SENTINEL'; END $$; CREATE TRIGGER reject_bgm BEFORE INSERT ON bgm_tracks FOR EACH ROW EXECUTE FUNCTION reject_bgm();" } else { "CREATE TRIGGER reject_bgm BEFORE INSERT ON bgm_tracks BEGIN SELECT RAISE(ABORT,'SECRET_SENTINEL'); END;" };
            sqlx::raw_sql(trigger).execute(repo.pool()).await.unwrap();
            let error=repo.publish_bgm(&p.tenant_id,&claim,&attempt.id).await.unwrap_err();
            assert!(!format!("{error:?} {error}").contains("SECRET_SENTINEL"));
            assert!(repo.asset_intent(&p.tenant_id,&id).await.unwrap().unwrap().published_attempt.is_none());
            assert!(repo.bgm_stage(&p.tenant_id,&id).await.unwrap().is_some());
            let drop_trigger=if <$repo>::IS_POSTGRES { "DROP TRIGGER reject_bgm ON bgm_tracks; DROP FUNCTION reject_bgm();" } else { "DROP TRIGGER reject_bgm;" };
            sqlx::raw_sql(drop_trigger).execute(repo.pool()).await.unwrap();
            repo.publish_bgm(&p.tenant_id,&claim,&attempt.id).await.unwrap();
            let result=repo.bgm_result(&p.tenant_id,&id).await.unwrap().unwrap();
            assert_eq!(result.provenance,track().provenance);assert_eq!(result.asset.key,attempt.key);
            assert!(repo.bgm_stage(&p.tenant_id,&id).await.unwrap().is_none());
            let asset=repo.asset_intent(&p.tenant_id,&id).await.unwrap().unwrap().asset_id;
            assert_eq!(repo.asset_reference_count(&p.tenant_id,&asset).await.unwrap(),2);
            assert_eq!(repo.bgm_result(&p.tenant_id,&id).await.unwrap().unwrap(),result);
            assert!(repo.publish_bgm(&p.tenant_id,&claim,&attempt.id).await.is_err());
            assert!(repo.begin_asset_cleanup(&p.tenant_id,&claim,&attempt.id,"store").await.is_err());
            let counters:i64=sqlx::query_scalar("SELECT COUNT(*) FROM quota_operations WHERE tenant_id=$1").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();assert_eq!(counters,0);
            // 同一目录版本被其他命令更新后，旧 CAS 不得发布资产或伪造成功。
            let conflict=accept(repo,&p,"cas-request",Some(99)).await;
            let claim=repo.claim_bgm(&p.tenant_id,&conflict,120_000).await.unwrap().unwrap();
            let attempt=repo.begin_upload(&p.tenant_id,&claim,"store").await.unwrap();
            repo.record_upload(&p.tenant_id,&attempt,&ObjectVersion::Unversioned).await.unwrap();
            assert!(repo.publish_bgm(&p.tenant_id,&claim,&attempt.id).await.is_err());
            assert!(repo.bgm_result(&p.tenant_id,&conflict).await.unwrap_err().to_string().contains("current revision 1"));
            assert_eq!(repo.get_bgm(&p.tenant_id,&result.id).await.unwrap().unwrap(),result);
            assert!(repo.bgm_stage(&p.tenant_id,&conflict).await.unwrap().is_none());
            // 替换目录不能令原请求的结果资产失去引用或发布证明。
            let replacement=accept(repo,&p,"replacement",Some(1)).await;
            let replacement_claim=repo.claim_bgm(&p.tenant_id,&replacement,120_000).await.unwrap().unwrap();
            let replacement_attempt=repo.begin_upload(&p.tenant_id,&replacement_claim,"store").await.unwrap();
            repo.record_upload(&p.tenant_id,&replacement_attempt,&ObjectVersion::Unversioned).await.unwrap();
            repo.publish_bgm(&p.tenant_id,&replacement_claim,&replacement_attempt.id).await.unwrap();
            assert_eq!(repo.get_bgm(&p.tenant_id,&result.id).await.unwrap().unwrap().revision,2);
            assert_eq!(repo.bgm_result(&p.tenant_id,&id).await.unwrap().unwrap(),result);
            assert_eq!(repo.asset_reference_count(&p.tenant_id,&asset).await.unwrap(),1);
            assert!(repo.asset_delivery(&p,&result.asset.key,memoswish_core::Permission::MediaRead).await.unwrap().is_some());
            // 两个同版本命令只能有一个发布；失败者保存稳定 CAS 事实。
            let race_a=accept(repo,&p,"race-a",Some(2)).await;
            let race_b=accept(repo,&p,"race-b",Some(2)).await;
            let claim_a=repo.claim_bgm(&p.tenant_id,&race_a,120_000).await.unwrap().unwrap();
            let claim_b=repo.claim_bgm(&p.tenant_id,&race_b,120_000).await.unwrap().unwrap();
            let attempt_a=repo.begin_upload(&p.tenant_id,&claim_a,"store").await.unwrap();
            let attempt_b=repo.begin_upload(&p.tenant_id,&claim_b,"store").await.unwrap();
            repo.record_upload(&p.tenant_id,&attempt_a,&ObjectVersion::Unversioned).await.unwrap();
            repo.record_upload(&p.tenant_id,&attempt_b,&ObjectVersion::Unversioned).await.unwrap();
            let (a,b)=tokio::join!(repo.publish_bgm(&p.tenant_id,&claim_a,&attempt_a.id),repo.publish_bgm(&p.tenant_id,&claim_b,&attempt_b.id));
            assert_ne!(a.is_ok(),b.is_ok());
            let (winner,loser)=if a.is_ok(){(&race_a,&race_b)}else{(&race_b,&race_a)};
            assert_eq!(repo.bgm_result(&p.tenant_id,winner).await.unwrap().unwrap().revision,3);
            assert!(repo.bgm_result(&p.tenant_id,loser).await.unwrap_err().to_string().contains("current revision 3"));
            // PUT 后降权不能借后继凭据升级原始权限。
            let revoked=accept(repo,&p,"revoked",None).await;
            let claim=repo.claim_bgm(&p.tenant_id,&revoked,120_000).await.unwrap().unwrap();
            let attempt=repo.begin_upload(&p.tenant_id,&claim,"store").await.unwrap();
            repo.record_upload(&p.tenant_id,&attempt,&ObjectVersion::Unversioned).await.unwrap();
            sqlx::query("UPDATE tenant_memberships SET role='learner' WHERE tenant_id=$1 AND user_id=$2").bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();
            assert!(repo.publish_bgm(&p.tenant_id,&claim,&attempt.id).await.is_err());
            assert!(repo.bgm_stage(&p.tenant_id,&revoked).await.unwrap().is_none());
            let rows=sqlx::query("SELECT outcome,audio FROM bgm_publications WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&revoked).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(rows.get::<String,_>("outcome"),"rejected");
            // 擦除发生于 PUT 完成前，迟到回执仍归资产账本，不能复活目录或暂存。
            let erased=crate::asset_conformance::seed(repo).await;
            let erased_id=accept(repo,&erased,"erased",None).await;
            let erased_claim=repo.claim_bgm(&erased.tenant_id,&erased_id,120_000).await.unwrap().unwrap();
            let erased_attempt=repo.begin_upload(&erased.tenant_id,&erased_claim,"store").await.unwrap();
            repo.account_erase(&erased.tenant_id,&erased.user_id,true).await.unwrap();
            repo.record_upload(&erased.tenant_id,&erased_attempt,&ObjectVersion::VersionId("late-version".into())).await.unwrap();
            assert!(repo.publish_bgm(&erased.tenant_id,&erased_claim,&erased_attempt.id).await.is_err());
            assert!(repo.bgm_stage(&erased.tenant_id,&erased_id).await.unwrap().is_none());
            assert!(repo.get_bgm(&erased.tenant_id,&track().id).await.unwrap().is_none());
            assert!(repo.unresolved_assets(None,100).await.unwrap().iter().any(|(t,i)|t==&erased.tenant_id&&i.id==erased_id));
        }
    }
}
#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    impl SqliteRepository {
        const IS_POSTGRES: bool = false;
    }
    cases!(SqliteRepository);
    #[tokio::test]
    async fn sqlite_bgm_atomic_publication_and_restart() {
        let path = std::env::temp_dir().join(format!("p35-bgm-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = SqliteRepository::connect(&url).await.unwrap();
        scenario(&repo).await;
        let p = crate::asset_conformance::seed(&repo).await;
        let id = accept(&repo, &p, "restart", None).await;
        let exhausted = exhausted_prepare(&repo).await;
        repo.pool().close().await;
        let repo = SqliteRepository::connect(&url).await.unwrap();
        for (p, id, attempt) in &exhausted {
            assert!(repo.claim_bgm(&p.tenant_id, id, 120_000).await.unwrap().is_none());
            exhausted_assert(&repo, p, id, attempt).await;
        }
        assert_eq!(repo.bgm_stage(&p.tenant_id, &id).await.unwrap().unwrap(), b"wave");
        assert_eq!(repo.bgm_request(&p, "restart", "restart").await.unwrap(), Some(id));
        repo.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::postgres::PostgresRepository;
    impl PostgresRepository {
        const IS_POSTGRES: bool = true;
    }
    cases!(PostgresRepository);
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_bgm_atomic_publication_and_restart() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let fixture = test.fixture(&url).await;
            let repo = fixture.repository(2).await.unwrap();
            scenario(&repo).await;
            let p = crate::asset_conformance::seed(&repo).await;
            let id = accept(&repo, &p, "restart", None).await;
            let exhausted = exhausted_prepare(&repo).await;
            repo.pool().close().await;
            let repo = fixture.repository(2).await.unwrap();
            for (p, id, attempt) in &exhausted {
                assert!(repo.claim_bgm(&p.tenant_id, id, 120_000).await.unwrap().is_none());
                exhausted_assert(&repo, p, id, attempt).await;
            }
            assert_eq!(repo.bgm_stage(&p.tenant_id, &id).await.unwrap().unwrap(), b"wave");
            assert_eq!(repo.bgm_request(&p, "restart", "restart").await.unwrap(), Some(id));
            repo.pool().close().await;
            fixture.cleanup().await;
        });
    }
}
