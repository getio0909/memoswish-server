//! 双库共享擦除验收：原子入队、精确证据、claim、耗尽和升级。
use crate::asset_conformance::{seed, spec};
use memoswish_core::{assets::*, erasure::*, identity::*, lifecycle::*, repo::*};
use sqlx::Row;

async fn evidence(repo: &impl Repository, peer: &impl Repository) {
    // guard 的版本事实不能代替活跃租户调用者的完整上传回执验证。
    let validation_owner = seed(repo).await;
    let validation_intent = repo.prepare_asset(&validation_owner, "validation", &spec(), 3).await.unwrap();
    let validation_claim =
        repo.claim_asset_job(&validation_owner.tenant_id, "validation", 30_000).await.unwrap().unwrap();
    let validation_attempt = repo.begin_upload(&validation_owner.tenant_id, &validation_claim, "disk-a").await.unwrap();
    let managed =
        repo.register_managed_put(&validation_owner.tenant_id, "disk-a", &validation_attempt.key).await.unwrap();
    repo.record_managed_put(&managed, &ObjectVersion::Unversioned).await.unwrap();
    let preserved = repo.upload_attempts(&validation_owner.tenant_id, &validation_intent.id).await.unwrap();
    assert_eq!(preserved[0].outcome, UploadOutcome::InFlight);
    assert_eq!(preserved[0].version, ObjectVersion::Unknown);
    let p = crate::lifecycle_conformance::workspace(repo).await;
    let other = seed(repo).await;
    let intent = repo.prepare_asset(&p, "published", &spec(), 3).await.unwrap();
    let claim = repo.claim_asset_job(&p.tenant_id, "uploader", 30_000).await.unwrap().unwrap();
    let attempt = repo.begin_upload(&p.tenant_id, &claim, "disk-a").await.unwrap();
    repo.record_upload(&p.tenant_id, &attempt, &ObjectVersion::VersionId("null".into())).await.unwrap();
    repo.publish_asset(
        &p,
        &claim,
        &attempt.id,
        &AssetReference { asset_id: intent.asset_id.clone(), owner_id: "card".into(), slot: "image".into() },
    )
    .await
    .unwrap();
    let pending =
        repo.register_managed_put(&p.tenant_id, "disk-a", &format!("tenants/{}/legacy", p.tenant_id)).await.unwrap();
    assert!(repo.register_managed_put(&other.tenant_id, "disk-a", &pending.key).await.is_err());
    assert!(repo.register_managed_put(&p.tenant_id, "disk-a", "shared/keep").await.is_err());
    let job = repo.delete_workspace(&p, &DeleteWorkspace { confirmed_tenant_id: p.tenant_id.clone() }).await.unwrap();
    assert!(repo.account_by_id(&p.user_id).await.unwrap().is_some());
    assert!(repo.asset_intent(&p.tenant_id, &intent.id).await.unwrap().unwrap().published_attempt.is_some());
    assert!(repo.get_tenant(&other.tenant_id).await.unwrap().is_some());
    assert!(repo.register_managed_put(&p.tenant_id, "disk-a", &pending.key).await.is_err());
    let (a, b) =
        tokio::join!(repo.claim_erasure(&job.id, "worker-a", 30_000), peer.claim_erasure(&job.id, "worker-b", 30_000));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a.is_some(), b.is_some());
    let current = a.or(b).unwrap();
    assert!(repo.complete_erasure(&current).await.is_err());
    assert!(!repo.erasure_assets_ready(&current).await.unwrap());
    assert!(repo.acknowledge_erasure_assets(&current).await.is_err());
    let objects = repo.erasure_objects(&current, ("", ""), 100).await.unwrap();
    assert_eq!(objects.len(), 2);
    let published = objects.iter().find(|o| o.source == "asset").unwrap();
    assert_eq!(published.version, ObjectVersion::VersionId("null".into()));
    assert!(repo.begin_erasure_object(&current, published, "disk-b").await.is_err());
    let mut forged = published.clone();
    forged.tenant_id = other.tenant_id.clone();
    assert!(repo.begin_erasure_object(&current, &forged, "disk-a").await.is_err());
    forged = published.clone();
    forged.key = format!("tenants/{}/different", p.tenant_id);
    assert!(repo.begin_erasure_object(&current, &forged, "disk-a").await.is_err());
    assert!(repo.record_erasure_object(published).await.is_err());
    repo.begin_erasure_object(&current, published, "disk-a").await.unwrap();
    // DELETE 成功但 SQL 回执丢失：仍不能完成，重试同一物理身份。
    assert!(repo.complete_erasure(&current).await.is_err());
    repo.begin_erasure_object(&current, published, "disk-a").await.unwrap();
    repo.record_erasure_object(published).await.unwrap();
    repo.record_erasure_object(published).await.unwrap();
    assert!(repo.begin_erasure_object(&current, &pending, "disk-a").await.is_err());
    repo.record_managed_put(&pending, &ObjectVersion::VersionId("late-version".into())).await.unwrap();
    assert!(repo.record_managed_put(&pending, &ObjectVersion::Unversioned).await.is_err());
    let mut late = pending.clone();
    late.version = ObjectVersion::VersionId("late-version".into());
    repo.begin_erasure_object(&current, &late, "disk-a").await.unwrap();
    repo.record_erasure_object(&late).await.unwrap();
    assert!(repo.erasure_assets_ready(&current).await.unwrap());
    assert!(repo.complete_erasure(&current).await.is_err());
    repo.acknowledge_erasure_assets(&current).await.unwrap();
    repo.complete_erasure(&current).await.unwrap();
    assert!(repo.heartbeat_erasure(&current, 30_000).await.is_err());
    assert_eq!(repo.erasure_work(&job.id).await.unwrap().unwrap().progress, "complete");
    assert!(repo.account_erasure_finish(&job.id).await.is_err());
    // 已完成操作和墓碑永久保留；核对使用原任务且有界推进游标。
    for _ in 0..4 {
        repo.reconcile_erasure_tombstones(1).await.unwrap();
    }
    let work = repo.erasure_work(&job.id).await.unwrap().unwrap();
    assert_eq!(work.progress, "pending");
    assert!(repo.claim_erasure(&job.id, "reconciler", 30_000).await.unwrap().is_some());
    assert!(repo.account_erased_tenant(&p.tenant_id).await.unwrap());
}

async fn account_scope(repo: &impl Repository) {
    let p = seed(repo).await;
    repo.membership_remove(&p.tenant_id, &p.user_id).await.unwrap();
    let job = repo.account_close_empty(&p.user_id, 0).await.unwrap();
    assert!(job.tenant_id.is_none());
    assert!(!job.purge_assets);
    let claim = repo.claim_erasure(&job.id, "account-worker", 30_000).await.unwrap().unwrap();
    assert!(repo.erasure_objects(&claim, ("", ""), 10).await.is_err());
    assert!(repo.acknowledge_erasure_assets(&claim).await.is_err());
    repo.complete_erasure(&claim).await.unwrap();
    assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_some());
    assert!(repo.account_by_id(&p.user_id).await.unwrap().is_none());
}

macro_rules! suite {
    ($repo:ty,$pool:ty,$migrations:literal,$clock:literal,$sqlite:literal) => {
        async fn tombstone_reuses_exhausted_purge(repo:&$repo){
            let p=seed(repo).await;
            let suffix=memoswish_core::ids::new_id();
            let earlier=ErasureJob{id:format!("a-{suffix}"),tenant_id:Some(p.tenant_id.clone()),purge_assets:false,credentials:vec![]};
            let purge=ErasureJob{id:format!("z-{suffix}"),tenant_id:Some(p.tenant_id.clone()),purge_assets:true,credentials:vec![]};
            // 模拟发现游标尚未到达、执行器已耗尽后置清理操作的交错。
            sqlx::query("INSERT INTO erased_tenants(tenant_id) VALUES($1)").bind(&p.tenant_id).execute(repo.pool()).await.unwrap();
            for job in [&earlier,&purge] {
                sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)").bind(&job.id).bind(serde_json::to_string(job).unwrap()).execute(repo.pool()).await.unwrap();
            }
            let first:String=sqlx::query_scalar("SELECT id FROM account_erasure_jobs WHERE partition_id=$1 ORDER BY id LIMIT 1").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(first,earlier.id);
            for _ in 0..5 {
                let claim=repo.claim_erasure(&purge.id,"exhaust",30_000).await.unwrap().unwrap();
                repo.retry_erasure(&claim).await.unwrap();
                // 推进夹具期限后继续原有重试与耗尽断言。
                sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$2 WHERE id=$1 AND kind='erasure'").bind(&claim.job_id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
            }
            let dead=repo.erasure_work(&purge.id).await.unwrap().unwrap();
            assert_eq!(dead.state,"dead");assert_eq!(dead.progress,"blocked");assert_eq!(dead.attempts,5);assert_eq!(dead.total_attempts,5);
            let mapped:i64=sqlx::query_scalar("SELECT COUNT(*) FROM erasure_tombstone_work WHERE tenant_id=$1").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(mapped,0);
            for _ in 0..4 {repo.reconcile_erasure_tombstones(100).await.unwrap();}
            let mapped:String=sqlx::query_scalar("SELECT job_id FROM erasure_tombstone_work WHERE tenant_id=$1").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(mapped,purge.id);
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_erasure_jobs WHERE partition_id=$1").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count,2,"reconciliation must not create replacement responsibility");
            let observed=repo.erasure_work(&purge.id).await.unwrap().unwrap();
            assert_eq!(observed.job.id,dead.job.id);assert_eq!(observed.state,dead.state);assert_eq!(observed.progress,dead.progress);
            assert_eq!(observed.revision,dead.revision);assert_eq!(observed.attempts,dead.attempts);assert_eq!(observed.total_attempts,dead.total_attempts);
            assert!(repo.claim_erasure(&purge.id,"discovery",30_000).await.unwrap().is_none());
            assert!(repo.erasure_page("",100).await.unwrap().iter().any(|w|w.job.id==purge.id));
            assert!(repo.requeue_erasure(&purge.id,dead.revision-1).await.is_err());
            repo.requeue_erasure(&purge.id,dead.revision).await.unwrap();
            assert!(repo.requeue_erasure(&purge.id,dead.revision).await.is_err());
            let claim=repo.claim_erasure(&purge.id,"maintenance",30_000).await.unwrap().unwrap();
            assert_eq!(repo.erasure_work(&purge.id).await.unwrap().unwrap().total_attempts,6);
            repo.acknowledge_erasure_assets(&claim).await.unwrap();
            repo.complete_erasure(&claim).await.unwrap();
        }
        async fn fencing(repo:&$repo,peer:&$repo){
            let p=seed(repo).await;
            let job=repo.account_erase(&p.tenant_id,&p.user_id,true).await.unwrap();
            let old=repo.claim_erasure(&job.id,"old",30_000).await.unwrap().unwrap();
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&job.id).execute(repo.pool()).await.unwrap();
            let new=peer.claim_erasure(&job.id,"new",30_000).await.unwrap().unwrap();
            assert_ne!(old.token,new.token);
            assert!(repo.heartbeat_erasure(&old,30_000).await.is_err());
            assert!(repo.retry_erasure(&old).await.is_err());
            assert!(repo.complete_erasure(&old).await.is_err());
            repo.retry_erasure(&new).await.unwrap();
                // 推进夹具期限后继续原有重试与耗尽断言。
                sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$2 WHERE id=$1 AND kind='erasure'").bind(&new.job_id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
            for _ in 0..3 {
                let c=repo.claim_erasure(&job.id,"retry",30_000).await.unwrap().unwrap();
                repo.retry_erasure(&c).await.unwrap();
                // 推进夹具期限后继续原有重试与耗尽断言。
                sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$2 WHERE id=$1 AND kind='erasure'").bind(&c.job_id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
            }
            let dead=repo.erasure_work(&job.id).await.unwrap().unwrap();
            assert_eq!(dead.state,"dead");assert_eq!(dead.progress,"blocked");assert_eq!(dead.total_attempts,5);
            for _ in 0..4 {repo.reconcile_erasure_tombstones(100).await.unwrap();}
            assert!(repo.claim_erasure(&job.id,"sweep",30_000).await.unwrap().is_none());
            assert!(repo.erasure_page("",100).await.unwrap().iter().any(|w|w.job.id==job.id));
            assert!(repo.requeue_erasure(&job.id,dead.revision-1).await.is_err());
            repo.requeue_erasure(&job.id,dead.revision).await.unwrap();
            assert!(repo.requeue_erasure(&job.id,dead.revision).await.is_err());
            let restarted=repo.claim_erasure(&job.id,"repair",30_000).await.unwrap().unwrap();
            assert_eq!(repo.erasure_work(&job.id).await.unwrap().unwrap().total_attempts,6);
            repo.acknowledge_erasure_assets(&restarted).await.unwrap();
            repo.complete_erasure(&restarted).await.unwrap();
            assert!(repo.requeue_erasure(&job.id,dead.revision).await.is_err());
        }
        async fn revocations(repo:&$repo){
            let job=ErasureJob{id:memoswish_core::ids::new_id(),tenant_id:None,purge_assets:false,credentials:vec![("apple".into(),"AAD\nSYNTHETIC_CIPHER_1".into()),("apple".into(),"AAD\nSYNTHETIC_CIPHER_2".into())]};
            sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)").bind(&job.id).bind(serde_json::to_string(&job).unwrap()).execute(repo.pool()).await.unwrap();
            let c=repo.claim_erasure(&job.id,"revoke",30_000).await.unwrap().unwrap();
            assert!(repo.complete_erasure(&c).await.is_err());
            assert!(repo.acknowledge_revocation(&c,0,"other","AAD\nSYNTHETIC_CIPHER_1").await.is_err());
            repo.acknowledge_revocation(&c,0,"apple","AAD\nSYNTHETIC_CIPHER_1").await.unwrap();
            repo.retry_erasure(&c).await.unwrap();
                // 推进夹具期限后继续原有重试与耗尽断言。
                sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$2 WHERE id=$1 AND kind='erasure'").bind(&c.job_id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
            let w=repo.erasure_work(&job.id).await.unwrap().unwrap();
            assert!(w.job.credentials[0].1.is_empty());assert_eq!(w.job.credentials[1].1,"AAD\nSYNTHETIC_CIPHER_2");
            let c2=repo.claim_erasure(&job.id,"revoke-restart",30_000).await.unwrap().unwrap();
            assert!(repo.acknowledge_revocation(&c,1,"apple","AAD\nSYNTHETIC_CIPHER_2").await.is_err());
            repo.acknowledge_revocation(&c2,1,"apple","AAD\nSYNTHETIC_CIPHER_2").await.unwrap();
            repo.complete_erasure(&c2).await.unwrap();
            let body:String=sqlx::query_scalar("SELECT body FROM account_erasure_jobs WHERE id=$1").bind(&job.id).fetch_one(repo.pool()).await.unwrap();
            assert!(!body.contains("SYNTHETIC_CIPHER"));
            assert!(sqlx::query("DELETE FROM account_erasure_jobs WHERE id=$1").bind(&job.id).execute(repo.pool()).await.is_err());
            assert!(sqlx::query("UPDATE account_erasure_jobs SET drain_until_ms=0 WHERE id=$1").bind(&job.id).execute(repo.pool()).await.is_err());
            // 不存在 operation 的伪造 account/tenant 恢复任务均被拒绝。
            for (tenant,scope) in [("","account"),("missing","tenant")] {
                assert!(sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope) VALUES($1,'forged','erasure','forged','{}',3,0,$2)").bind(tenant).bind(scope).execute(repo.pool()).await.is_err());
            }
        }
        async fn rollback(repo:&$repo){
            let p=crate::lifecycle_conformance::workspace(repo).await;
            let install=if $sqlite {"CREATE TRIGGER s19_fail_delete BEFORE DELETE ON tenants BEGIN SELECT RAISE(ABORT,'injected deletion failure'); END;"}else{"CREATE FUNCTION s19_fail_delete_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected deletion failure'; END $$; CREATE TRIGGER s19_fail_delete BEFORE DELETE ON tenants FOR EACH ROW EXECUTE FUNCTION s19_fail_delete_fn();"};
            sqlx::raw_sql(install).execute(repo.pool()).await.unwrap();
            assert!(repo.delete_workspace(&p,&DeleteWorkspace{confirmed_tenant_id:p.tenant_id.clone()}).await.is_err());
            sqlx::raw_sql(if $sqlite {"DROP TRIGGER s19_fail_delete"}else{"DROP TRIGGER s19_fail_delete ON tenants; DROP FUNCTION s19_fail_delete_fn()"}).execute(repo.pool()).await.unwrap();
            assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_some());
            assert!(!repo.account_erased_tenant(&p.tenant_id).await.unwrap());
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE tenant_id=$1 AND kind='erasure'").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();assert_eq!(count,0);
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_erasure_jobs WHERE partition_id=$1").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();assert_eq!(count,0);
        }
        async fn clock_after_lock(repo:&$repo,peer:&$repo){
            let p=seed(repo).await;let job=repo.account_erase(&p.tenant_id,&p.user_id,true).await.unwrap();
            let claim=repo.claim_erasure(&job.id,"clock",30_000).await.unwrap().unwrap();
            let mut held=repo.pool().begin().await.unwrap();
            sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *held).await.unwrap();
            let now:i64=sqlx::query_scalar($clock).fetch_one(&mut *held).await.unwrap();
            sqlx::query("UPDATE background_jobs SET lease_until_ms=$3 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&job.id).bind(now+100).execute(&mut *held).await.unwrap();
            let started=std::sync::Arc::new(tokio::sync::Notify::new());let observed=started.clone();let second=peer.clone();let old=claim.clone();
            let worker=tokio::spawn(async move {observed.notify_one();second.heartbeat_erasure(&old,30_000).await});
            started.notified().await;
            while sqlx::query_scalar::<_,i64>($clock).fetch_one(&mut *held).await.unwrap()<=now+100 {tokio::task::yield_now().await;}
            assert!(!worker.is_finished());held.commit().await.unwrap();
            assert!(worker.await.unwrap().is_err(),"clock must be read after serialization lock acquisition");
            let new=repo.claim_erasure(&job.id,"replacement",30_000).await.unwrap().unwrap();
            assert_ne!(claim.token,new.token);
        }
        async fn upgrade(pool:&$pool){
            use crate::foundation_conformance::{through,LEGACY_DATA};
            let full=sqlx::migrate!($migrations);
            let target=full.iter().find(|m|m.description.as_ref()=="erasure work scope").unwrap().version;
            let previous=full.iter().filter(|m|m.version<target).last().unwrap().version;
            through(&full,8).run(pool).await.unwrap();sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();through(&full,previous).run(pool).await.unwrap();
            for job in [ErasureJob{id:"legacy-account".into(),tenant_id:None,purge_assets:false,credentials:vec![("apple".into(),"SYNTHETIC_UPGRADE_CIPHER".into())]},ErasureJob{id:"legacy-tenant".into(),tenant_id:Some("deleted-tenant".into()),purge_assets:true,credentials:vec![]}] {
                sqlx::query("INSERT INTO account_erasure_jobs(id,body,drain_until_ms) VALUES($1,$2,123456)").bind(&job.id).bind(serde_json::to_string(&job).unwrap()).execute(pool).await.unwrap();
            }
            sqlx::raw_sql("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES('foundation','old-asset','asset_upload','old-asset','{}',5,0); INSERT INTO quota_operations VALUES('foundation','old-asset','asset_bytes','2026-11',3,'reserved'); INSERT INTO asset_records VALUES('foundation','asset','audio/wav',3,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'); INSERT INTO asset_upload_intents(tenant_id,id,asset_id,account_generation) VALUES('foundation','old-asset','asset',7); INSERT INTO asset_upload_attempts(tenant_id,id,intent_id,store_id,object_key,claim_token,outcome,version_kind,version_id) VALUES('foundation','attempt','old-asset','disk-a','tenants/foundation/uploads/old-asset/attempt','old-claim','uploaded','version','null'); UPDATE asset_upload_intents SET published_attempt='attempt' WHERE tenant_id='foundation' AND id='old-asset'; INSERT INTO asset_references VALUES('foundation','asset','account',7,7,'card','audio');").execute(pool).await.unwrap();
            // 模拟旧擦除遗漏的 S17 回执；活跃租户同名记录必须原样保留。
            sqlx::query("INSERT INTO tenants(id,name,plan,created_at) SELECT 's19-deleted-tenant',name,plan,created_at FROM tenants WHERE id='foundation'").execute(pool).await.unwrap();
            sqlx::query("INSERT INTO membership_generations VALUES('s19-deleted-tenant','deleted-user',0)").execute(pool).await.unwrap();
            for (tenant,user,generation) in [("foundation","account",7_i64),("s19-deleted-tenant","deleted-user",0)] {
                sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES($1,'legacy-speech','tts','legacy-speech','{}',5,0)").bind(tenant).execute(pool).await.unwrap();
                sqlx::query("INSERT INTO tts_syntheses(tenant_id,id,work,metadata) VALUES($1,'legacy-speech','{\"private\":\"S19_OLD_TEXT\"}','{\"private\":\"S19_OLD_TIMING\"}')").bind(tenant).execute(pool).await.unwrap();
                sqlx::query("INSERT INTO tts_provider_attempts VALUES($1,'legacy-speech','legacy-provider','uncertain')").bind(tenant).execute(pool).await.unwrap();
                sqlx::query("INSERT INTO quota_operations VALUES($1,'legacy-speech','tts_chars','2026-11',13,'reserved')").bind(tenant).execute(pool).await.unwrap();
                sqlx::query("INSERT INTO tts_requesters(tenant_id,id,synthesis_id,user_id,account_generation,membership_generation,content_permission) VALUES($1,'legacy-requester','legacy-speech',$2,7,$3,1)").bind(tenant).bind(user).bind(generation).execute(pool).await.unwrap();
                sqlx::query("INSERT INTO tts_submissions VALUES($1,$2,'legacy-submission','legacy-command-hash',7,$3)").bind(tenant).bind(user).bind(generation).execute(pool).await.unwrap();
                sqlx::query("INSERT INTO tts_submission_items VALUES($1,$2,'legacy-submission',0,'legacy-requester','{\"private\":\"S19_OLD_RECEIPT\"}')").bind(tenant).bind(user).execute(pool).await.unwrap();
            }
            sqlx::query("INSERT INTO erased_tenants VALUES('s19-deleted-tenant')").execute(pool).await.unwrap();
            sqlx::query("DELETE FROM tenants WHERE id='s19-deleted-tenant'").execute(pool).await.unwrap();
            let mut broken=through(&full,target);let index=broken.migrations.len()-1;let m=&broken.migrations[index];
            let sql=format!("{}\nSELECT * FROM s19_injected_missing_table;",m.sql);let version=m.version;
            broken.migrations.to_mut()[index]=sqlx::migrate::Migration::new(version,"injected failure".into(),sqlx::migrate::MigrationType::Simple,sql.into(),false);
            assert!(broken.run(pool).await.is_err());
            let old:i64=sqlx::query_scalar("SELECT drain_until_ms FROM account_erasure_jobs WHERE id='legacy-account'").fetch_one(pool).await.unwrap();assert_eq!(old,123456);
            let old_receipts:i64=sqlx::query_scalar("SELECT COUNT(*) FROM tts_submission_items WHERE tenant_id='s19-deleted-tenant'").fetch_one(pool).await.unwrap();assert_eq!(old_receipts,1);
            full.run(pool).await.unwrap();full.run(pool).await.unwrap();
            for table in ["tts_submission_items","tts_submissions"] {
                let erased:i64=sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id='s19-deleted-tenant'")).fetch_one(pool).await.unwrap();assert_eq!(erased,0);
                let retained:i64=sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id='foundation'")).fetch_one(pool).await.unwrap();assert_eq!(retained,1);
            }
            let row=sqlx::query("SELECT work,metadata FROM tts_syntheses WHERE tenant_id='s19-deleted-tenant' AND id='legacy-speech'").fetch_one(pool).await.unwrap();
            assert_eq!(row.get::<String,_>("work"),"{}");assert!(row.get::<Option<String>,_>("metadata").is_none());
            let outcome:String=sqlx::query_scalar("SELECT outcome FROM tts_provider_attempts WHERE tenant_id='s19-deleted-tenant'").fetch_one(pool).await.unwrap();assert_eq!(outcome,"uncertain");
            let q=sqlx::query("SELECT amount,state FROM quota_operations WHERE tenant_id='s19-deleted-tenant' AND operation_id='legacy-speech'").fetch_one(pool).await.unwrap();assert_eq!(q.get::<i64,_>("amount"),13);assert_eq!(q.get::<String,_>("state"),"reserved");
            let scope:String=sqlx::query_scalar("SELECT work_scope FROM background_jobs WHERE tenant_id='' AND id='legacy-account'").fetch_one(pool).await.unwrap();assert_eq!(scope,"account");
            let body:String=sqlx::query_scalar("SELECT body FROM account_erasure_jobs WHERE id='legacy-account'").fetch_one(pool).await.unwrap();assert!(body.contains("SYNTHETIC_UPGRADE_CIPHER"));
            let q=sqlx::query("SELECT amount,state FROM quota_operations WHERE tenant_id='foundation' AND operation_id='old-asset'").fetch_one(pool).await.unwrap();assert_eq!(q.get::<i64,_>("amount"),3);assert_eq!(q.get::<String,_>("state"),"reserved");
            let n:i64=sqlx::query_scalar("SELECT COUNT(*) FROM asset_references WHERE tenant_id='foundation' AND asset_id='asset'").fetch_one(pool).await.unwrap();assert_eq!(n,1);
        }
    }
}
#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    suite!(
        SqliteRepository,
        sqlx::SqlitePool,
        "./migrations/sqlite",
        "SELECT CAST((julianday('now')-2440587.5)*86400000 AS BIGINT)",
        true
    );
    #[tokio::test]
    async fn sqlite_s19_erasure_conformance_upgrade_restart() {
        let path = std::env::temp_dir().join(format!("s19-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let options =
            url.parse::<sqlx::sqlite::SqliteConnectOptions>().unwrap().create_if_missing(true).foreign_keys(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        upgrade(&pool).await;
        pool.close().await;
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        let peer = SqliteRepository::connect_test(&url).await.unwrap();
        evidence(&repo, &peer).await;
        account_scope(&repo).await;
        tombstone_reuses_exhausted_purge(&repo).await;
        fencing(&repo, &peer).await;
        revocations(&repo).await;
        rollback(&repo).await;
        clock_after_lock(&repo, &peer).await;
        let pending = repo.erasure_page("", 100).await.unwrap().into_iter().map(|w| w.job.id).collect::<Vec<_>>();
        repo.pool().close().await;
        peer.pool().close().await;
        let restarted = SqliteRepository::connect_test(&url).await.unwrap();
        assert_eq!(
            pending,
            restarted.erasure_page("", 100).await.unwrap().into_iter().map(|w| w.job.id).collect::<Vec<_>>()
        );
        restarted.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::postgres::PostgresRepository;
    suite!(
        PostgresRepository,
        sqlx::PgPool,
        "./migrations/postgres",
        "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT)",
        false
    );
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_s19_erasure_conformance_upgrade_restart() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let fixture = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let pool =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            upgrade(&pool).await;
            pool.close().await;
            let repo = fixture.repository(8).await.unwrap();
            let peer = fixture.repository(8).await.unwrap();
            evidence(&repo, &peer).await;
            account_scope(&repo).await;
            tombstone_reuses_exhausted_purge(&repo).await;
            fencing(&repo, &peer).await;
            revocations(&repo).await;
            rollback(&repo).await;
            clock_after_lock(&repo, &peer).await;
            let pending = repo.erasure_page("", 100).await.unwrap().into_iter().map(|w| w.job.id).collect::<Vec<_>>();
            repo.pool().close().await;
            peer.pool().close().await;
            let restarted = fixture.repository(8).await.unwrap();
            assert_eq!(
                pending,
                restarted.erasure_page("", 100).await.unwrap().into_iter().map(|w| w.job.id).collect::<Vec<_>>()
            );
            restarted.pool().close().await;
            fixture.cleanup().await;
        });
    }
}
