//! 双库资产责任、故障回滚、升级和跨连接竞争的共享验收。

use memoswish_core::assets::*;
use memoswish_core::identity::IdentityRepo;
use memoswish_core::jobs::*;
use memoswish_core::repo::*;
use memoswish_core::{CoreError, Principal, Role};
use sqlx::Row;

pub(crate) async fn seed(repo: &impl Repository) -> Principal {
    let tenant = memoswish_core::ids::new_id();
    let user = memoswish_core::ids::new_id();
    let now = chrono::Utc::now();
    repo.upsert_tenant(&TenantRecord {
        id: tenant.clone(),
        name: "Assets".into(),
        plan: "free".into(),
        created_at: now,
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: user.clone(),
        tenant_id: tenant.clone(),
        email: format!("{user}@example.com"),
        display_name: "Owner".into(),
        password_hash: String::new(),
        role: Role::Owner,
        created_at: now,
    })
    .await
    .unwrap();
    Principal {
        tenant_id: tenant,
        user_id: user,
        role: Role::Owner,
        scopes: None,
        via: "test".into(),
        session_access_hash: None,
        auth_generation: Some(0),
        membership_generation: Some(0),
        legacy_issued_at: None,
    }
}

pub(crate) fn spec() -> AssetSpec {
    AssetSpec { mime: "audio/wav".into(), size: 3, sha256: memoswish_core::ids::sha256_hex(b"abc") }
}

fn reference(intent: &AssetIntent) -> AssetReference {
    AssetReference { asset_id: intent.asset_id.clone(), owner_id: "card".into(), slot: "audio".into() }
}

async fn identity_and_references(repo: &impl Repository) {
    let p = seed(repo).await;
    let prepared_spec = spec();
    let (a, b) = tokio::join!(
        repo.prepare_asset(&p, "same", &prepared_spec, 5),
        repo.prepare_asset(&p, "same", &prepared_spec, 5)
    );
    let intent = a.unwrap();
    assert_eq!(intent, b.unwrap());
    let mut conflict = spec();
    conflict.size += 1;
    assert!(matches!(repo.prepare_asset(&p, "same", &conflict, 5).await, Err(CoreError::Conflict(_))));
    assert!(repo.prepare_asset(&p, "same", &spec(), 6).await.is_err());
    let other = seed(repo).await;
    let independent = repo.prepare_asset(&other, "same", &spec(), 5).await.unwrap();
    assert_ne!(intent.asset_id, independent.asset_id);
    assert!(repo.asset_intent(&other.tenant_id, &intent.id).await.unwrap().is_none());
    assert!(repo.add_asset_reference(&other, &reference(&intent)).await.is_err());
    let (a, b) = tokio::join!(
        repo.claim_asset_job(&p.tenant_id, "worker-a", 30_000),
        repo.claim_asset_job(&p.tenant_id, "worker-b", 30_000)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a.is_some(), b.is_some());
    let claim = a.or(b).unwrap();
    assert!(repo.finish_asset_job(&p.tenant_id, &claim).await.is_err());
    let attempt = repo.begin_upload(&p.tenant_id, &claim, "test-store").await.unwrap();
    assert!(attempt.key.starts_with(&format!("tenants/{}/", p.tenant_id)));
    use memoswish_core::Permission;
    assert!(repo.asset_delivery(&p, &attempt.key, Permission::MediaRead).await.unwrap().is_none());
    assert!(repo.asset_delivery(&other, &attempt.key, Permission::MediaRead).await.unwrap().is_none());
    assert!(repo.begin_upload(&p.tenant_id, &claim, "test-store").await.is_err());
    assert!(repo.record_upload(&other.tenant_id, &attempt, &ObjectVersion::Unversioned).await.is_err());
    assert!(repo.begin_asset_cleanup(&p.tenant_id, &claim, &attempt.id, "test-store").await.is_err());
    assert!(repo.publish_asset(&p, &claim, &attempt.id, &reference(&intent)).await.is_err());
    repo.record_upload(&p.tenant_id, &attempt, &ObjectVersion::VersionId("null".into())).await.unwrap();
    assert!(repo.record_upload(&p.tenant_id, &attempt, &ObjectVersion::Unversioned).await.is_err());
    assert!(repo.asset_delivery(&p, &attempt.key, Permission::MediaRead).await.unwrap().is_none());
    // 引用冲突必须回滚发布标记和 succeeded 状态。
    let mut invalid = reference(&intent);
    invalid.slot = "https://bearer.invalid/SECRET_SENTINEL".into();
    assert!(repo.publish_asset(&p, &claim, &attempt.id, &invalid).await.is_err());
    assert!(repo.asset_intent(&p.tenant_id, &intent.id).await.unwrap().unwrap().published_attempt.is_none());
    repo.publish_asset(&p, &claim, &attempt.id, &reference(&intent)).await.unwrap();
    let delivery = repo.asset_delivery(&p, &attempt.key, Permission::MediaRead).await.unwrap().unwrap();
    assert_eq!(delivery.asset_id, intent.asset_id);
    assert_eq!(delivery.version, ObjectVersion::VersionId("null".into()));
    assert_eq!(delivery.store_id, "test-store");
    let mut narrow = p.clone();
    narrow.scopes = Some(vec!["feed:read".into()]);
    assert!(repo.asset_delivery(&narrow, &attempt.key, Permission::MediaRead).await.is_err());
    assert!(repo.asset_delivery(&narrow, &attempt.key, Permission::FeedRead).await.unwrap().is_some());
    let mut stale = p.clone();
    stale.membership_generation = Some(999);
    assert!(repo.asset_delivery(&stale, &attempt.key, Permission::MediaRead).await.is_err());
    stale = p.clone();
    stale.auth_generation = Some(999);
    assert!(repo.asset_delivery(&stale, &attempt.key, Permission::MediaRead).await.is_err());
    assert_eq!(repo.asset_job(&p.tenant_id, &intent.id).await.unwrap().unwrap().state, "succeeded");
    assert!(repo.heartbeat_asset_job(&p.tenant_id, &claim, 30_000).await.is_err());
    repo.add_asset_reference(&p, &reference(&intent)).await.unwrap();
    let mut peer = seed(repo).await;
    repo.membership_join(&p.tenant_id, &peer.user_id, Role::Editor).await.unwrap();
    peer.tenant_id = p.tenant_id.clone();
    peer.role = Role::Editor;
    assert!(repo.asset_delivery(&peer, &attempt.key, Permission::MediaRead).await.unwrap().is_some());
    repo.add_asset_reference(&peer, &reference(&intent)).await.unwrap();
    assert_eq!(repo.asset_reference_count(&p.tenant_id, &intent.asset_id).await.unwrap(), 2);
    repo.remove_asset_reference(&p, "card", "audio").await.unwrap();
    assert_eq!(repo.asset_reference_count(&p.tenant_id, &intent.asset_id).await.unwrap(), 1);
    // 无引用删除能力不会误清理其他请求者或尚未覆盖的 legacy 对象。
    repo.remove_asset_reference(&peer, "card", "audio").await.unwrap();
    assert!(repo.asset_delivery(&peer, &attempt.key, Permission::MediaRead).await.unwrap().is_none());
    assert!(repo.begin_asset_cleanup(&p.tenant_id, &claim, &attempt.id, "test-store").await.is_err());
    assert!(repo.unresolved_assets(None, 0).await.is_err());
    let page = repo.unresolved_assets(None, 1).await.unwrap();
    if let Some((tenant, intent)) = page.first() {
        let next = repo.unresolved_assets(Some((tenant, &intent.id)), 100).await.unwrap();
        assert!(next.iter().all(|(t, i)| (t.as_str(), i.id.as_str()) > (tenant.as_str(), intent.id.as_str())));
    }
    for bad in ["https://bearer.invalid/SECRET_SENTINEL", "../shared", "", &"a".repeat(129)] {
        let error = repo.prepare_asset(&p, bad, &spec(), 3).await.unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SECRET_SENTINEL"));
    }
    let mut unauthorized = p.clone();
    unauthorized.scopes = Some(vec!["media:read".into()]);
    assert!(repo.prepare_asset(&unauthorized, "restricted", &spec(), 3).await.is_err());
    let mut invalid = spec();
    invalid.mime = "audio/wav?token=SECRET_SENTINEL".into();
    assert!(repo.prepare_asset(&p, "invalid", &invalid, 3).await.is_err());
    invalid = spec();
    invalid.size = 64 * 1024 * 1024 + 1;
    assert!(repo.prepare_asset(&p, "invalid", &invalid, 3).await.is_err());
    invalid = spec();
    invalid.sha256 = "z".repeat(64);
    assert!(repo.prepare_asset(&p, "invalid", &invalid, 3).await.is_err());
}

macro_rules! asset_tests {
    ($repo:ty, $pool:ty, $migrations:literal, $fault:literal, $unfault:literal) => {
        async fn takeover_and_cleanup(repo:&$repo) {
            let p=seed(repo).await;
            let intent=repo.prepare_asset(&p,"takeover",&spec(),5).await.unwrap();
            let old=repo.claim_asset_job(&p.tenant_id,"old",30_000).await.unwrap().unwrap();
            let first=repo.begin_upload(&p.tenant_id, &old, "test-store").await.unwrap();
            assert!(sqlx::query("UPDATE asset_upload_attempts SET store_id='other-store' WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&first.id).execute(repo.pool()).await.is_err());
            assert!(sqlx::query("UPDATE asset_records SET sha256=$3 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&intent.asset_id).bind("0".repeat(64)).execute(repo.pool()).await.is_err());
            assert!(sqlx::query("DELETE FROM background_jobs WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&intent.id).execute(repo.pool()).await.is_err());
            let mut forged=first.clone(); forged.store_id="other-store".into();
            assert!(repo.record_upload(&p.tenant_id,&forged,&ObjectVersion::Unversioned).await.is_err());
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&intent.id).execute(repo.pool()).await.unwrap();
            let fresh=repo.claim_asset_job(&p.tenant_id,"new",30_000).await.unwrap().unwrap();
            assert_ne!(fresh.token,old.token);
            assert_eq!(repo.upload_attempts(&p.tenant_id,&intent.id).await.unwrap()[0].outcome,UploadOutcome::Uncertain);
            assert!(repo.heartbeat_asset_job(&p.tenant_id,&old,30_000).await.is_err());
            assert!(repo.retry_asset_job(&p.tenant_id,&old,0).await.is_err());
            assert!(repo.finish_asset_job(&p.tenant_id,&old).await.is_err());
            let second=repo.begin_upload(&p.tenant_id, &fresh, "test-store").await.unwrap();
            assert_ne!(first.key,second.key);
            repo.record_upload(&p.tenant_id,&second,&ObjectVersion::Unversioned).await.unwrap();
            assert!(repo.publish_asset(&p,&old,&first.id,&reference(&intent)).await.is_err());
            assert!(repo.publish_asset(&p,&fresh,&first.id,&reference(&intent)).await.is_err());
            repo.publish_asset(&p,&fresh,&second.id,&reference(&intent)).await.unwrap();
            // 旧 PUT 的晚到回执保持原 key、原版本，不能切换到新 attempt。
            repo.record_upload(&p.tenant_id,&first,&ObjectVersion::VersionId("old-version".into())).await.unwrap();
            let clean=repo.claim_asset_job(&p.tenant_id,"cleanup",30_000).await.unwrap().unwrap();
            assert!(repo.begin_asset_cleanup(&p.tenant_id, &clean, &second.id, "test-store").await.is_err());
            let pending=repo.begin_asset_cleanup(&p.tenant_id, &clean, &first.id, "test-store").await.unwrap();
            assert_eq!(pending.key,first.key);
            assert_eq!(pending.version,ObjectVersion::VersionId("old-version".into()));
            assert!(repo.finish_asset_job(&p.tenant_id,&clean).await.is_err());
            repo.record_asset_cleaned(&p.tenant_id,&pending).await.unwrap();
            repo.finish_asset_job(&p.tenant_id,&clean).await.unwrap();
            assert!(!repo.unresolved_assets(None,100).await.unwrap().iter().any(|(t,i)|t==&p.tenant_id&&i.id==intent.id));
            assert_eq!(repo.asset_reference_count(&p.tenant_id,&intent.asset_id).await.unwrap(),1);
        }

        async fn exhausted_and_revoked(repo:&$repo) {
            let p=seed(repo).await;
            let intent=repo.prepare_asset(&p,"exhaust",&spec(),1).await.unwrap();
            let claim=repo.claim_asset_job(&p.tenant_id,"worker",30_000).await.unwrap().unwrap();
            let attempt=repo.begin_upload(&p.tenant_id, &claim, "test-store").await.unwrap();
            repo.record_upload(&p.tenant_id,&attempt,&ObjectVersion::VersionId("null".into())).await.unwrap();
            let pending=repo.begin_asset_cleanup(&p.tenant_id, &claim, &attempt.id, "test-store").await.unwrap();
            repo.retry_asset_job(&p.tenant_id,&claim,0).await.unwrap();
            assert_eq!(repo.asset_job(&p.tenant_id,&intent.id).await.unwrap().unwrap().state,"dead");
            assert!(repo.claim_asset_job(&p.tenant_id,"another",30_000).await.unwrap().is_none());
            assert_eq!(repo.upload_attempts(&p.tenant_id,&intent.id).await.unwrap()[0].outcome,UploadOutcome::CleanupPending);
            assert!(repo.unresolved_assets(None,100).await.unwrap().iter().any(|(t,i)|t==&p.tenant_id&&i.id==intent.id));
            // 晚到的精确清理回执可补全事实，但不会重新赋予旧 worker 调度权。
            repo.record_asset_cleaned(&p.tenant_id,&pending).await.unwrap();
            let p=seed(repo).await;
            let intent=repo.prepare_asset(&p,"revoke",&spec(),3).await.unwrap();
            let claim=repo.claim_asset_job(&p.tenant_id,"worker",30_000).await.unwrap().unwrap();
            let attempt=repo.begin_upload(&p.tenant_id, &claim, "test-store").await.unwrap();
            repo.membership_remove(&p.tenant_id,&p.user_id).await.unwrap();
            assert!(repo.asset_delivery(&p,&attempt.key,memoswish_core::Permission::MediaRead).await.is_err());
            assert!(repo.prepare_asset(&p,"after-revoke",&spec(),3).await.is_err());
            repo.record_upload(&p.tenant_id,&attempt,&ObjectVersion::Unversioned).await.unwrap();
            assert!(repo.publish_asset(&p,&claim,&attempt.id,&reference(&intent)).await.is_err());
            let generation=repo.membership_join(&p.tenant_id,&p.user_id,Role::Owner).await.unwrap();
            assert!(generation>0);
            assert!(repo.publish_asset(&p,&claim,&attempt.id,&reference(&intent)).await.is_err());
            repo.retry_asset_job(&p.tenant_id,&claim,0).await.unwrap();
            // 模拟业务重试间隔已过，保留后续撤权与精确清理断言。
            sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&claim.job_id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
            let fresh=repo.claim_asset_job(&p.tenant_id,"replacement",30_000).await.unwrap().unwrap();
            assert!(repo.begin_upload(&p.tenant_id, &fresh, "test-store").await.is_err());
            repo.account_erase(&p.tenant_id,&p.user_id,true).await.unwrap();
            assert!(repo.prepare_asset(&p,"after-erase",&spec(),3).await.is_err());
            assert!(repo.add_asset_reference(&p,&reference(&intent)).await.is_err());
            assert!(repo.asset_intent(&p.tenant_id,&intent.id).await.unwrap().is_some());
            let cleanup=repo.begin_asset_cleanup(&p.tenant_id, &fresh, &attempt.id, "test-store").await.unwrap();
            repo.record_asset_cleaned(&p.tenant_id,&cleanup).await.unwrap();
            repo.finish_asset_job(&p.tenant_id,&fresh).await.unwrap();
            // 擦除在线性化后的 PUT 完成前发生：回执责任保留，业务发布永久拒绝。
            let p=seed(repo).await;
            let intent=repo.prepare_asset(&p,"erase-in-flight",&spec(),3).await.unwrap();
            let claim=repo.claim_asset_job(&p.tenant_id,"worker",30_000).await.unwrap().unwrap();
            let attempt=repo.begin_upload(&p.tenant_id,&claim,"test-store").await.unwrap();
            repo.account_erase(&p.tenant_id,&p.user_id,true).await.unwrap();
            repo.record_upload(&p.tenant_id,&attempt,&ObjectVersion::VersionId("late-version".into())).await.unwrap();
            assert!(repo.publish_asset(&p,&claim,&attempt.id,&reference(&intent)).await.is_err());
            assert!(repo.unresolved_assets(None,100).await.unwrap().iter().any(|(t,i)|t==&p.tenant_id&&i.id==intent.id));
            let cleanup=repo.begin_asset_cleanup(&p.tenant_id, &claim, &attempt.id, "test-store").await.unwrap();
            repo.record_asset_cleaned(&p.tenant_id,&cleanup).await.unwrap();
            repo.finish_asset_job(&p.tenant_id,&claim).await.unwrap();
        }

        async fn preparation_rollback(repo:&$repo) {
            let p=seed(repo).await;
            sqlx::raw_sql($fault).execute(repo.pool()).await.unwrap();
            let error=repo.prepare_asset(&p,"rollback",&spec(),3).await.unwrap_err();
            assert!(!format!("{error:?} {error}").contains("SECRET_SENTINEL"));
            for table in ["background_jobs","asset_records","asset_upload_intents"] {
                let count:i64=sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=$1")).bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(count,0,"{table}");
            }
            sqlx::raw_sql($unfault).execute(repo.pool()).await.unwrap();
            repo.prepare_asset(&p,"rollback",&spec(),3).await.unwrap();
        }

        async fn suite(repo:&$repo) {
            read_metadata(repo).await;
            identity_and_references(repo).await;
            takeover_and_cleanup(repo).await;
            exhausted_and_revoked(repo).await;
            preparation_rollback(repo).await;
            let (tenant, mut card) = crate::content_conformance::seed(repo).await;
            let asset = memoswish_protocol::AssetRef { key: format!("tenants/{tenant}/image.png"), url:"https://expired.invalid/?signature=OLD".into(), mime:"image/png".into(), bytes:3, sha256:spec().sha256 };
            card.id = memoswish_core::ids::new_id();
            card.visual.image = Some(asset.clone());
            repo.insert_card(&tenant, &card).await.unwrap();
            let matches = repo.legacy_asset_cards(&tenant, &asset.key).await.unwrap();
            assert!(matches.iter().any(|c|c.id==card.id));
            assert!(repo.legacy_asset_cards("another", &asset.key).await.unwrap().is_empty());
            revoke_while_upload_waits(repo).await;
        }

        async fn revoke_while_upload_waits(repo:&$repo) {
            let p=seed(repo).await;
            let intent=repo.prepare_asset(&p,"blocked-admission",&spec(),3).await.unwrap();
            let claim=repo.claim_asset_job(&p.tenant_id,"worker",30_000).await.unwrap().unwrap();
            let mut revoke=repo.pool().begin().await.unwrap();
            sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *revoke).await.unwrap();
            let (started,reached)=tokio::sync::oneshot::channel();
            let (copy,tenant,captured)=(repo.clone(),p.tenant_id.clone(),claim.clone());
            let upload=tokio::spawn(async move {
                started.send(()).unwrap();
                copy.begin_upload(&tenant,&captured,"test-store").await
            });
            reached.await.unwrap();
            assert!(!upload.is_finished());
            sqlx::query("DELETE FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2").bind(&p.tenant_id).bind(&p.user_id).execute(&mut *revoke).await.unwrap();
            revoke.commit().await.unwrap();
            assert!(matches!(upload.await.unwrap(),Err(CoreError::Forbidden(_))));
            assert!(repo.upload_attempts(&p.tenant_id,&intent.id).await.unwrap().is_empty());
            assert!(repo.asset_intent(&p.tenant_id,&intent.id).await.unwrap().is_some());
        }

        async fn upgrade_snapshot(pool:&$pool) -> Vec<Vec<Vec<Option<String>>>> {
            let extra=[("background_jobs","tenant_id,id,kind,idempotency_key,user_id,requester_generation,state,attempts,max_attempts,available_at_ms,lease_until_ms,worker,token"),("quota_operations","tenant_id,operation_id,metric,period,amount,state"),("account_auth_epochs","user_id,generation"),("membership_generations","tenant_id,user_id,generation"),("tenant_memberships","tenant_id,user_id,role,generation"),("bgm_tracks","tenant_id,id,revision,body")];
            let mut result=Vec::new();
            for (table,columns) in crate::foundation_conformance::SNAPSHOTS.iter().chain(extra.iter()) {
                let table=if *table=="users" {"user_profiles"} else {table};
                let projection=columns.split(',').map(|c|format!("CAST({c} AS TEXT)")).collect::<Vec<_>>().join(",");
                // 新增擦除工作另有验收，原 job 的完整投影保持逐字段断言。
                let scope=if table=="background_jobs" {"AND kind<>'erasure'"}else{""};
                let rows=sqlx::query(&format!("SELECT {projection} FROM {table} WHERE 1=1 {scope} ORDER BY {projection}")).fetch_all(pool).await.unwrap();
                result.push(rows.iter().map(|row|(0..columns.split(',').count()).map(|i|row.get(i)).collect()).collect());
            }
            result
        }

        async fn upgrade(pool:&$pool) {
            use crate::foundation_conformance::{through,LEGACY_DATA};
            let full=sqlx::migrate!($migrations);
            through(&full,8).run(pool).await.unwrap();
            sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();
            // 先用旧曲目经过 0013 回填，再验证 0014 保留内容版本和既有持久责任。
            through(&full,12).run(pool).await.unwrap();
            let track=memoswish_protocol::examples::sample_bgm_track();
            let mut legacy=serde_json::to_value(&track).unwrap();
            legacy.as_object_mut().unwrap().remove("revision");
            sqlx::query("INSERT INTO bgm_tracks(tenant_id,id,body) VALUES('foundation',$1,$2)")
                .bind(&track.id).bind(sqlx::types::Json(legacy)).execute(pool).await.unwrap();
            through(&full,13).run(pool).await.unwrap();
            let revision:i64=sqlx::query_scalar("SELECT revision FROM bgm_tracks WHERE tenant_id='foundation' AND id=$1")
                .bind(&track.id).fetch_one(pool).await.unwrap();
            assert_eq!(revision,1);
            let body:sqlx::types::Json<memoswish_protocol::BgmTrack>=sqlx::query_scalar("SELECT body FROM bgm_tracks WHERE tenant_id='foundation' AND id=$1")
                .bind(&track.id).fetch_one(pool).await.unwrap();
            assert_eq!(body.0,track);
            sqlx::raw_sql("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES('foundation','preserved','tts','preserved','{}','account',7,3,100); INSERT INTO quota_operations VALUES('foundation','preserved','tts_chars','2026-11',17,'reserved');").execute(pool).await.unwrap();
            let before=upgrade_snapshot(pool).await;
            let previous:i64=sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(previous,13,"asset upgrade must start from the real 0013 schema");
            let mut broken=through(&full,14);
            let index=broken.migrations.len()-1;
            let sql=format!("{}\n SELECT * FROM injected_s15_missing_table;",broken.migrations[index].sql);
            broken.migrations.to_mut()[index]=sqlx::migrate::Migration::new(14,"injected failure".into(),sqlx::migrate::MigrationType::Simple,sql.into(),false);
            assert!(broken.run(pool).await.is_err());
            assert_eq!(upgrade_snapshot(pool).await,before);
            let applied:i64=sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(applied,previous);
            assert!(sqlx::query("SELECT id FROM asset_records").fetch_all(pool).await.is_err());
            let asset_schema=through(&full,14);
            asset_schema.run(pool).await.unwrap();
            asset_schema.run(pool).await.unwrap();
            let applied:i64=sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(applied,14);
            assert_eq!(upgrade_snapshot(pool).await,before);
            let inventory:i64=sqlx::query_scalar("SELECT COUNT(*) FROM asset_records").fetch_one(pool).await.unwrap();
            assert_eq!(inventory,0);
            // 后续规范迁移仍保留原工作、配额和密文；S19 转换另由 erasure_conformance 验证。
            full.run(pool).await.unwrap();
            full.run(pool).await.unwrap();
            let applied:i64=sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(applied,full.iter().last().unwrap().version);
            let cache:i64=sqlx::query_scalar("SELECT COUNT(*) FROM asset_read_metadata").fetch_one(pool).await.unwrap();
            assert_eq!(cache,0,"populated upgrades must not fabricate verified read metadata");
            assert_eq!(upgrade_snapshot(pool).await,before);
            let inventory:i64=sqlx::query_scalar("SELECT COUNT(*) FROM asset_records").fetch_one(pool).await.unwrap();
            assert_eq!(inventory,0);
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    asset_tests!(
        SqliteRepository,
        sqlx::SqlitePool,
        "./migrations/sqlite",
        "CREATE TRIGGER s15_fail_intent BEFORE INSERT ON asset_upload_intents BEGIN SELECT RAISE(ABORT,'SECRET_SENTINEL'); END;",
        "DROP TRIGGER s15_fail_intent;"
    );

    #[tokio::test]
    async fn sqlite_asset_conformance_and_restart() {
        let path = std::env::temp_dir().join(format!("memoswish-s15-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        suite(&repo).await;
        let p = seed(&repo).await;
        let intent = repo.prepare_asset(&p, "restart-prepared", &spec(), 1).await.unwrap();
        let claim = repo.claim_asset_job(&p.tenant_id, "worker", 30_000).await.unwrap().unwrap();
        let attempt = repo.begin_upload(&p.tenant_id, &claim, "test-store").await.unwrap();
        repo.retry_asset_job(&p.tenant_id, &claim, 0).await.unwrap();
        let prepared_owner = seed(&repo).await;
        let prepared = repo.prepare_asset(&prepared_owner, "before-put", &spec(), 3).await.unwrap();
        repo.pool().close().await;
        let reopened = SqliteRepository::connect_test(&url).await.unwrap();
        assert_eq!(
            reopened.asset_intent(&prepared_owner.tenant_id, &prepared.id).await.unwrap(),
            Some(prepared.clone())
        );
        assert!(reopened.upload_attempts(&prepared_owner.tenant_id, &prepared.id).await.unwrap().is_empty());
        assert_eq!(reopened.asset_intent(&p.tenant_id, &intent.id).await.unwrap(), Some(intent.clone()));
        let observed = reopened.upload_attempts(&p.tenant_id, &intent.id).await.unwrap();
        assert_eq!(observed[0].id, attempt.id);
        assert_eq!(observed[0].outcome, UploadOutcome::Uncertain);
        assert_eq!(observed[0].version, ObjectVersion::Unknown);
        assert_eq!(reopened.asset_job(&p.tenant_id, &intent.id).await.unwrap().unwrap().state, "dead");
        assert!(
            reopened
                .unresolved_assets(None, 100)
                .await
                .unwrap()
                .iter()
                .any(|(t, i)| t == &p.tenant_id && i.id == intent.id)
        );
        reopened.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn sqlite_asset_upgrade_failure_and_preservation() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        upgrade(&pool).await;
        pool.close().await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::postgres::PostgresRepository;
    asset_tests!(
        PostgresRepository,
        sqlx::PgPool,
        "./migrations/postgres",
        "CREATE FUNCTION s15_fail_intent() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SECRET_SENTINEL'; END $$; CREATE TRIGGER s15_fail_intent BEFORE INSERT ON asset_upload_intents FOR EACH ROW EXECUTE FUNCTION s15_fail_intent();",
        "DROP TRIGGER s15_fail_intent ON asset_upload_intents; DROP FUNCTION s15_fail_intent();"
    );

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_asset_conformance_and_restart() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let repo = fixture.repository(8).await.unwrap();
            suite(&repo).await;
            let p = seed(&repo).await;
            let intent = repo.prepare_asset(&p, "restart", &spec(), 1).await.unwrap();
            let pending_owner = seed(&repo).await;
            let pending = repo.prepare_asset(&pending_owner, "pending-restart", &spec(), 1).await.unwrap();
            let claim = repo.claim_asset_job(&pending_owner.tenant_id, "worker", 30_000).await.unwrap().unwrap();
            let attempt = repo.begin_upload(&pending_owner.tenant_id, &claim, "test-store").await.unwrap();
            repo.record_upload(&pending_owner.tenant_id, &attempt, &ObjectVersion::VersionId("null".into()))
                .await
                .unwrap();
            repo.begin_asset_cleanup(&pending_owner.tenant_id, &claim, &attempt.id, "test-store").await.unwrap();
            repo.retry_asset_job(&pending_owner.tenant_id, &claim, 0).await.unwrap();
            repo.pool().close().await;
            let reopened = fixture.repository(8).await.unwrap();
            assert_eq!(reopened.asset_job(&pending_owner.tenant_id, &pending.id).await.unwrap().unwrap().state, "dead");
            let observed = reopened.upload_attempts(&pending_owner.tenant_id, &pending.id).await.unwrap();
            assert_eq!(observed[0].outcome, UploadOutcome::CleanupPending);
            assert_eq!(observed[0].version, ObjectVersion::VersionId("null".into()));
            assert_eq!(reopened.asset_intent(&p.tenant_id, &intent.id).await.unwrap(), Some(intent.clone()));
            assert!(reopened.upload_attempts(&p.tenant_id, &intent.id).await.unwrap().is_empty());
            assert!(
                reopened
                    .unresolved_assets(None, 100)
                    .await
                    .unwrap()
                    .iter()
                    .any(|(t, i)| t == &p.tenant_id && i.id == intent.id)
            );
            reopened.pool().close().await;
            fixture.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_asset_upgrade_failure_and_preservation() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            // 失败迁移后的 SQLx session advisory lock 必须由同一连接重新获取并释放。
            let pool =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            upgrade(&pool).await;
            pool.close().await;
            fixture.cleanup().await;
        });
    }
}

async fn read_metadata(repo: &impl Repository) {
    use memoswish_core::asset_read::{ReadIdentity, ReadManifest};
    let p = seed(repo).await;
    let other = seed(repo).await;
    let key = format!("tenants/{}/imports/read.png", p.tenant_id);
    assert!(repo.asset_read_manifest(&p.tenant_id, &key).await.unwrap().is_none());
    let mut manifest = ReadManifest::new(
        "test",
        &key,
        &ObjectVersion::Unversioned,
        &ReadIdentity { cacheable: true, identity: "opened-file".into(), size: 3, mime: "audio/wav".into() },
        &spec(),
    );
    repo.save_asset_read_manifest(&p.tenant_id, &key, &manifest).await.unwrap();
    assert!(!repo.asset_read_manifest(&p.tenant_id, &key).await.unwrap().unwrap().verified);
    manifest.blocks.push(spec().sha256);
    manifest.verified = true;
    repo.save_asset_read_manifest(&p.tenant_id, &key, &manifest).await.unwrap();
    assert_eq!(repo.asset_read_manifest(&p.tenant_id, &key).await.unwrap(), Some(manifest.clone()));
    assert!(repo.asset_read_manifest(&other.tenant_id, &key).await.unwrap().is_none());
    assert!(repo.save_asset_read_manifest(&other.tenant_id, &key, &manifest).await.is_err());
    let mut partial = manifest.clone();
    partial.verified = false;
    partial.blocks.clear();
    repo.save_asset_read_manifest(&p.tenant_id, &key, &partial).await.unwrap();
    assert_eq!(repo.asset_read_manifest(&p.tenant_id, &key).await.unwrap(), Some(manifest.clone()));
    partial.binding = memoswish_core::ids::sha256_hex(b"replacement");
    repo.save_asset_read_manifest(&p.tenant_id, &key, &partial).await.unwrap();
    assert_eq!(repo.asset_read_manifest(&p.tenant_id, &key).await.unwrap(), Some(partial));
    manifest.blocks.push(spec().sha256);
    assert!(repo.save_asset_read_manifest(&p.tenant_id, &key, &manifest).await.is_err());
}
