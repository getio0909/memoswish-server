//! 双后端共享调度验收；独立池竞态、过期 fence、持久分页与填充升级。

use memoswish_core::{
    erasure::ErasureRepo,
    maintenance::*,
    repo::{ContentRepo, Repository},
};

async fn ownership(repo: &impl Repository, peer: &impl Repository) -> MaintenanceClaim {
    let task = TaskRegistration::system(TaskKind::IdentityExpiry);
    let id = repo.register_maintenance(&task).await.unwrap();
    assert_eq!(peer.register_maintenance(&task).await.unwrap(), id);
    let (a, b) = tokio::join!(repo.claim_maintenance(&id, "owner-a"), peer.claim_maintenance(&id, "owner-b"));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a.is_some(), b.is_some());
    let claim = a.or(b).unwrap();
    for field in ["token", "owner", "task", "kind"] {
        let mut wrong = claim.clone();
        match field {
            "token" => wrong.token = "wrong".into(),
            "owner" => wrong.worker = "wrong".into(),
            "task" => wrong.task_id = "wrong".into(),
            _ => wrong.kind = TaskKind::FeedExpiry,
        }
        assert!(peer.renew_maintenance(&wrong).await.is_err());
        assert!(peer.release_maintenance(&wrong, false).await.is_err());
        assert!(peer.maintenance_sql_page(&wrong).await.is_err());
    }
    let other = peer.register_maintenance(&TaskRegistration::system(TaskKind::FeedExpiry)).await.unwrap();
    let independent = peer.claim_maintenance(&other, "independent").await.unwrap().unwrap();
    peer.maintenance_sql_page(&independent).await.unwrap();
    repo.renew_maintenance(&claim).await.unwrap();
    claim
}

macro_rules! suite {
    ($repo:ty,$pool:ty,$migrations:literal,$fail:literal,$unfail:literal) => {
        async fn fences_and_rollback(repo:&$repo,peer:&$repo) {
            let claim=super::ownership(repo,peer).await;
            sqlx::query("INSERT INTO identity_events(issuer,event_hash,expires_at) VALUES('expired','event',0)").execute(repo.pool()).await.unwrap();
            // 完成页时注入失败，已经发生的删除及 cycle 更新必须一起回滚。
            sqlx::raw_sql($fail).execute(repo.pool()).await.unwrap();
            assert!(repo.maintenance_sql_page(&claim).await.is_err());
            let remains:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_events WHERE issuer='expired'").fetch_one(repo.pool()).await.unwrap();
            assert_eq!(remains,1);
            let cycle:i64=sqlx::query_scalar("SELECT cycle FROM maintenance_tasks WHERE id=$1").bind(&claim.task_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(cycle,0);
            sqlx::raw_sql($unfail).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id='' AND id=$1").bind(&claim.task_id).execute(repo.pool()).await.unwrap();
            assert!(repo.renew_maintenance(&claim).await.is_err());
            assert!(repo.release_maintenance(&claim,false).await.is_err());
            assert!(repo.maintenance_sql_page(&claim).await.is_err());
            let takeover=peer.claim_maintenance(&claim.task_id,"takeover").await.unwrap().unwrap();
            assert!(repo.release_maintenance(&claim,false).await.is_err());
            peer.maintenance_sql_page(&takeover).await.unwrap();
            let remains:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_events WHERE issuer='expired'").fetch_one(repo.pool()).await.unwrap();
            assert_eq!(remains,0);
            let due:(i64,String,i64)=sqlx::query_as("SELECT available_at_ms,state,attempts FROM background_jobs WHERE tenant_id='' AND id=$1").bind(&claim.task_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(due.1,"queued");assert_eq!(due.2,0);
            assert!(repo.claim_maintenance(&claim.task_id,"too-soon").await.unwrap().is_none());
            repo.register_maintenance(&TaskRegistration::system(TaskKind::IdentityExpiry)).await.unwrap();
            let unchanged:i64=sqlx::query_scalar("SELECT available_at_ms FROM background_jobs WHERE tenant_id='' AND id=$1").bind(&claim.task_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(unchanged,due.0,"restart registration cannot reset schedule");
        }

        async fn discovery(repo:&$repo,peer:&$repo) {
            // 零成员账户与已删租户都属于擦除发现；不伪造业务租户。
            for n in 0..103 {
                let id=format!("item-{n:03}");
                let body=serde_json::json!({"id":id,"tenant_id":null,"purge_assets":false,"credentials":[]}).to_string();
                sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)").bind(&id).bind(body).execute(repo.pool()).await.unwrap();
            }
            let id=repo.register_maintenance(&TaskRegistration::system(TaskKind::ErasureRecovery)).await.unwrap();
            let claim=repo.claim_maintenance(&id,"scanner").await.unwrap().unwrap();
            let page=repo.maintenance_discover(&claim).await.unwrap();assert_eq!(page.len(),100);
            sqlx::raw_sql($fail).execute(repo.pool()).await.unwrap();
            assert!(repo.admit_maintenance_item(&claim,&page[0]).await.is_err());
            let receipts:i64=sqlx::query_scalar("SELECT COUNT(*) FROM maintenance_admissions").fetch_one(repo.pool()).await.unwrap();assert_eq!(receipts,0);
            sqlx::raw_sql($unfail).execute(repo.pool()).await.unwrap();
            let wrong=DiscoveryItem{tenant:"adjacent".into(),id:page[0].id.clone()};
            assert!(repo.admit_maintenance_item(&claim,&wrong).await.is_err());
            assert!(repo.admit_maintenance_item(&claim,&page[1]).await.is_err());
            assert!(repo.complete_maintenance_cycle(&claim).await.is_err());
            let first=repo.admit_maintenance_item(&claim,&page[0]).await.unwrap();
            assert!(!first.admission_id.is_empty());
            // 扫描过程中在游标两侧插入；前方项续扫可见，后方项等明确周期边界。
            for id in ["early-item", "tail-item"] {
                let body=serde_json::json!({"id":id,"tenant_id":null,"purge_assets":false,"credentials":[]}).to_string();
                sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)").bind(id).bind(body).execute(repo.pool()).await.unwrap();
            }
            assert!(sqlx::query("DELETE FROM maintenance_admissions WHERE admission_id=$1").bind(&first.admission_id).execute(repo.pool()).await.is_err());
            assert!(sqlx::query("UPDATE maintenance_admissions SET item_id='forged' WHERE admission_id=$1").bind(&first.admission_id).execute(repo.pool()).await.is_err());
            assert!(sqlx::query("DELETE FROM maintenance_tasks WHERE id=$1").bind(&id).execute(repo.pool()).await.is_err());
            // 丢失接纳响应不会重复推进，也不会重新执行未接纳的第二项。
            assert!(repo.admit_maintenance_item(&claim,&page[0]).await.is_err());
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id='' AND id=$1").bind(&id).execute(repo.pool()).await.unwrap();
            assert!(repo.admit_maintenance_item(&claim,&page[1]).await.is_err());
            assert!(repo.maintenance_discover(&claim).await.is_err());
            assert!(repo.complete_maintenance_cycle(&claim).await.is_err());
            let next=peer.claim_maintenance(&id,"new-scanner").await.unwrap().unwrap();
            let resumed=peer.maintenance_discover(&next).await.unwrap();assert_eq!(resumed[0],page[1]);assert_eq!(resumed.len(),100);
            for item in &resumed {let _admission=peer.admit_maintenance_item(&next,item).await.unwrap();}
            let tail=peer.maintenance_discover(&next).await.unwrap();assert_eq!(tail.len(),3);
            assert_eq!(tail.last().unwrap().id,"tail-item");
            for item in tail {let _admission=peer.admit_maintenance_item(&next,&item).await.unwrap();}
            assert!(peer.maintenance_discover(&next).await.unwrap().is_empty());
            assert!(peer.complete_maintenance_cycle(&next).await.unwrap());
            let (cursor,cycle):(String,i64)=sqlx::query_as("SELECT cursor,cycle FROM maintenance_tasks WHERE id=$1").bind(&id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(cursor,"[]");assert_eq!(cycle,1);
            // 成功扫描不表示业务完成，已接纳但尚未领取的项仍由原业务记录恢复。
            let pending:i64=sqlx::query_scalar("SELECT COUNT(*) FROM account_erasure_jobs WHERE progress='pending'").fetch_one(repo.pool()).await.unwrap();assert_eq!(pending,105);
            let cycle_two=peer.claim_maintenance(&id,"next-cycle").await.unwrap().unwrap();
            let wrapped=peer.maintenance_discover(&cycle_two).await.unwrap();assert_eq!(wrapped.first().unwrap().id,"early-item");
            peer.release_maintenance(&cycle_two,false).await.unwrap();
            let business=repo.claim_erasure(&first.item.id,"business",300_000).await.unwrap().unwrap();
            assert!(repo.erasure_work(&first.item.id).await.unwrap().unwrap().progress!="complete");
            repo.complete_erasure(&business).await.unwrap();
        }

        async fn hf11_live_speech_wrap_and_restart(repo: &$repo, peer: &$repo) {
            use memoswish_core::{tts::*, assets::AssetRepo};
            let p = crate::asset_conformance::seed(repo).await;
            let work = SpeechWork {
                provenance: None, privacy: None, engine: "test".into(), namespace: "config".into(),
                request: TtsRequest { text: "abc".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
                amount: 3, legacy_output: None,
            };
            let request = repo.accept_speech(&p, &work, None, Some(3)).await.unwrap();
            let old = repo.claim_speech(&p.tenant_id, &request.synthesis_id, 120_000).await.unwrap().unwrap();
            repo.begin_provider(&p.tenant_id, &old).await.unwrap();
            let id = repo.register_maintenance(&TaskRegistration::system(TaskKind::SpeechRecovery)).await.unwrap();
            let scanner = repo.claim_maintenance(&id, "live-scanner").await.unwrap().unwrap();
            let page = repo.maintenance_discover(&scanner).await.unwrap();
            assert_eq!(page, vec![DiscoveryItem { tenant: p.tenant_id.clone(), id: request.synthesis_id.clone() }]);
            let admission = repo.admit_maintenance_item(&scanner, &page[0]).await.unwrap();
            assert!(peer.claim_speech(&p.tenant_id, &admission.item.id, 120_000).await.unwrap().is_none());
            repo.release_maintenance(&scanner, false).await.unwrap();
            assert!(repo.renew_maintenance(&scanner).await.is_err());
            // 立即续页，不手动推进维护时间；模拟接纳后执行前进程退出。
            let suffix = peer.claim_maintenance(&id, "restart-scanner").await.unwrap().unwrap();
            assert!(peer.maintenance_discover(&suffix).await.unwrap().is_empty());
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&request.synthesis_id).execute(repo.pool()).await.unwrap();
            assert!(peer.complete_maintenance_cycle(&suffix).await.unwrap());
            let (a, b) = tokio::join!(repo.claim_maintenance(&id, "wrap-a"), peer.claim_maintenance(&id, "wrap-b"));
            let (a, b) = (a.unwrap(), b.unwrap());
            assert_ne!(a.is_some(), b.is_some());
            let wrapped = a.or(b).unwrap();
            assert!(repo.release_maintenance(&suffix, false).await.is_err());
            let page = peer.maintenance_discover(&wrapped).await.unwrap();
            let replay = peer.admit_maintenance_item(&wrapped, &page[0]).await.unwrap();
            assert_ne!(admission.admission_id, replay.admission_id);
            assert!(repo.admit_maintenance_item(&wrapped, &page[0]).await.is_err());
            peer.release_maintenance(&wrapped, false).await.unwrap();
            let (a, b) = tokio::join!(repo.claim_speech(&p.tenant_id, &replay.item.id, 120_000), peer.claim_speech(&p.tenant_id, &replay.item.id, 120_000));
            let (a, b) = (a.unwrap(), b.unwrap());
            assert_ne!(a.is_some(), b.is_some());
            let current = a.or(b).unwrap();
            let spec = memoswish_core::assets::AssetSpec { mime: "audio/mpeg".into(), size: 3, sha256: memoswish_core::ids::sha256_hex(b"abc") };
            let metadata = SpeechMetadata { alignment_quality: None, audio_kind: None, provenance: None, extension: "mp3".into(), duration_ms: 100, words: vec![] };
            assert!(repo.materialize_speech(&p.tenant_id, &old, b"abc", &spec, &metadata, false).await.is_err());
            peer.begin_provider(&p.tenant_id, &current).await.unwrap();
            peer.materialize_speech(&p.tenant_id, &current, b"abc", &spec, &metadata, false).await.unwrap();
            assert!(repo.materialize_speech(&p.tenant_id, &old, b"abc", &spec, &metadata, false).await.is_err());
            let attempts: Vec<(String, String)> = sqlx::query_as("SELECT claim_token,outcome FROM tts_provider_attempts WHERE tenant_id=$1 ORDER BY outcome")
                .bind(&p.tenant_id).fetch_all(repo.pool()).await.unwrap();
            assert_eq!(attempts, vec![(current.token, "returned".into()), (old.token.clone(), "uncertain".into())]);
            let suffix = repo.claim_maintenance(&id, "paced-error").await.unwrap().unwrap();
            repo.release_maintenance(&suffix, true).await.unwrap();
            assert!(peer.claim_maintenance(&id, "too-soon").await.unwrap().is_none());
            // 清除本夹具责任后，空周期保持 cadence，而不是立即热循环。
            let (upload, _) = peer.speech_upload(&p.tenant_id, &request.synthesis_id).await.unwrap().unwrap();
            let publisher = peer.claim_speech(&p.tenant_id, &upload, 120_000).await.unwrap().unwrap();
            let attempt = peer.begin_upload(&p.tenant_id, &publisher, "store").await.unwrap();
            peer.record_upload(&p.tenant_id, &attempt, &memoswish_core::assets::ObjectVersion::Unversioned).await.unwrap();
            peer.publish_speech(&p.tenant_id, &publisher, &attempt.id).await.unwrap();
            assert!(repo.publish_speech(&p.tenant_id, &old, &attempt.id).await.is_err());
            sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE tenant_id='' AND id=$1").bind(&id).execute(repo.pool()).await.unwrap();
            let empty = peer.claim_maintenance(&id, "quiescent").await.unwrap().unwrap();
            assert!(peer.maintenance_discover(&empty).await.unwrap().is_empty());
            assert!(!peer.complete_maintenance_cycle(&empty).await.unwrap());
            assert!(repo.claim_maintenance(&id, "too-soon").await.unwrap().is_none());
        }

        async fn hf11_admit_speech(repo: &$repo, task: &str, target: &str) -> (MaintenanceClaim, MaintenanceAdmission) {
            let mut scanner=repo.claim_maintenance(task,"admitter").await.unwrap().unwrap();
            if repo.maintenance_discover(&scanner).await.unwrap().is_empty() {
                assert!(repo.complete_maintenance_cycle(&scanner).await.unwrap());
                scanner=repo.claim_maintenance(task,"wrapped-admitter").await.unwrap().unwrap();
            }
            let mut found=None;
            for item in repo.maintenance_discover(&scanner).await.unwrap() {
                let admission=repo.admit_maintenance_item(&scanner,&item).await.unwrap();
                if item.id==target {found=Some(admission);}
            }
            (scanner,found.unwrap())
        }

        async fn hf11_business_error_pacing(repo: &$repo, peer: &$repo) {
            use memoswish_core::{tts::*, assets::*, jobs::AssetJobRepo, imports::ImportRepo, bgm::BgmPublicationRepo};
            // 在真实数据库时钟两侧取界，避免测试依赖宿主或 Tokio 时钟。
            macro_rules! now {
                () => {{let mut tx=repo.asset_tx().await.unwrap();let now=<$repo>::asset_now(&mut tx).await.unwrap();tx.commit().await.unwrap();now}};
            }
            macro_rules! due {
                ($tenant:expr,$id:expr) => {sqlx::query_scalar::<_,i64>("SELECT available_at_ms FROM background_jobs WHERE tenant_id=$1 AND id=$2").bind($tenant).bind($id).fetch_one(repo.pool()).await.unwrap()};
            }
            macro_rules! elapse {
                ($tenant:expr,$id:expr) => {
                    sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2").bind($tenant).bind($id).bind(CADENCE_MS).execute(repo.pool()).await.unwrap();
                };
            }
            macro_rules! paced {
                ($tenant:expr,$id:expr,$failure:expr,$a:expr,$b:expr) => {{
                    let before=now!();
                    $failure.await.unwrap();
                    let after=now!();
                    let due=due!($tenant,$id);
                    assert!((before+CADENCE_MS..=after+CADENCE_MS).contains(&due));
                    assert!($a.await.unwrap().is_none());
                    assert!($b.await.unwrap().is_none());
                    let attempts:i64=sqlx::query_scalar("SELECT attempts FROM background_jobs WHERE tenant_id=$1 AND id=$2").bind($tenant).bind($id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(attempts,1,"denied claims must not consume attempts");
                    // 仅推进夹具业务期限，维护 due/owner 不参与业务可领取性。
                    elapse!($tenant,$id);
                    let (a,b)=tokio::join!($a,$b);
                    let (a,b)=(a.unwrap(),b.unwrap());assert_ne!(a.is_some(),b.is_some());
                    let winner=a.or(b).unwrap();
                    let attempts:i64=sqlx::query_scalar("SELECT attempts FROM background_jobs WHERE tenant_id=$1 AND id=$2").bind($tenant).bind($id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(attempts,2);
                    // 崩溃没有提交失败事务；即使 availability 在未来，租约过期仍立即可接管。
                    sqlx::query("UPDATE background_jobs SET available_at_ms=$3,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind($tenant).bind($id).bind(now!()+CADENCE_MS).execute(repo.pool()).await.unwrap();
                    let (a,b)=tokio::join!($a,$b);let (a,b)=(a.unwrap(),b.unwrap());
                    assert_ne!(a.is_some(),b.is_some());assert_ne!(winner.token,a.or(b).unwrap().token);
                    assert!($failure.await.is_err(),"stale failure cannot pace a replacement owner");
                }};
            }
            for peer_owned in [false,true] {
                let p=crate::asset_conformance::seed(repo).await;
                let work=SpeechWork {provenance:None,privacy:None,engine:"test".into(),namespace:"config".into(),request:TtsRequest{text:"abc".into(),language:"en".into(),voice:"default".into(),speed:1.0},amount:3,legacy_output:None};
                let request=repo.accept_speech(&p,&work,None,Some(3)).await.unwrap();
                let task=repo.register_maintenance(&TaskRegistration::system(TaskKind::SpeechRecovery)).await.unwrap();
                // 第二场景只推进扫描夹具期限，游标按真实周期包裹。
                sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE tenant_id='' AND id=$1").bind(&task).execute(repo.pool()).await.unwrap();
                let (scanner,a)=hf11_admit_speech(repo,&task,&request.synthesis_id).await;
                repo.release_maintenance(&scanner,false).await.unwrap();
                let executor=repo.claim_speech(&p.tenant_id,&a.item.id,120_000).await.unwrap().unwrap();
                repo.begin_provider(&p.tenant_id,&executor).await.unwrap();
                let (scanner,b)=hf11_admit_speech(peer,&task,&request.synthesis_id).await;
                assert_ne!(a.admission_id,b.admission_id);
                if !peer_owned {peer.release_maintenance(&scanner,false).await.unwrap();}
                let before=now!();
                repo.fail_speech(&p.tenant_id,&executor,None).await.unwrap();
                let after=now!();
                assert!((before+CADENCE_MS..=after+CADENCE_MS).contains(&due!(&p.tenant_id,&b.item.id)));
                if peer_owned {
                    assert!(repo.claim_maintenance(&task,"failed-page-pacer").await.unwrap().is_none());
                    peer.renew_maintenance(&scanner).await.unwrap();
                } else {
                    let pacer=repo.claim_maintenance(&task,"failed-page-pacer").await.unwrap().unwrap();
                    repo.release_maintenance(&pacer,true).await.unwrap();
                    assert!(peer.claim_maintenance(&task,"too-soon").await.unwrap().is_none());
                }
                // B 持有的是 A 失败前提交的 admission，而非失败后的新发现。
                assert!(peer.claim_speech(&b.item.tenant,&b.item.id,120_000).await.unwrap().is_none());
                let row:(i64,String,i64)=sqlx::query_as("SELECT j.attempts,q.state,(SELECT COUNT(*) FROM tts_provider_attempts p WHERE p.tenant_id=j.tenant_id AND p.synthesis_id=j.id AND p.outcome='uncertain') FROM background_jobs j JOIN quota_operations q ON q.tenant_id=j.tenant_id AND q.operation_id=j.id WHERE j.tenant_id=$1 AND j.id=$2").bind(&p.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(row,(1,"reserved".into(),1));
                elapse!(&p.tenant_id,&b.item.id);
                let (left,right)=tokio::join!(repo.claim_speech(&p.tenant_id,&a.item.id,120_000),peer.claim_speech(&b.item.tenant,&b.item.id,120_000));
                let (left,right)=(left.unwrap(),right.unwrap());assert_ne!(left.is_some(),right.is_some());
                let current=left.or(right).unwrap();assert_ne!(current.token,executor.token);
                let due=due!(&p.tenant_id,&b.item.id);
                assert!(repo.fail_speech(&p.tenant_id,&executor,None).await.is_err());
                assert_eq!(due!(&p.tenant_id,&b.item.id),due);
                sqlx::query("UPDATE background_jobs SET lease_until_ms=0,available_at_ms=$3 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&a.item.id).bind(now!()+CADENCE_MS).execute(repo.pool()).await.unwrap();
                let replacement=peer.claim_speech(&b.item.tenant,&b.item.id,120_000).await.unwrap().unwrap();
                assert_ne!(replacement.token,current.token);
                if peer_owned {peer.release_maintenance(&scanner,false).await.unwrap();}
            }
            // BGM 和普通上传复用同一围栏失败事务，零延迟调用也不能绕过 cadence。
            let p=crate::asset_conformance::seed(repo).await;
            let mut track=memoswish_protocol::examples::sample_bgm_track();
            track.asset.bytes=4;track.asset.sha256=memoswish_core::ids::sha256_hex(b"wave");
            let id=repo.accept_bgm(&p,"paced-bgm",&track,b"wave",None,"paced-bgm",false).await.unwrap();
            let claim=repo.claim_bgm(&p.tenant_id,&id,120_000).await.unwrap().unwrap();
            let upload=repo.begin_upload(&p.tenant_id,&claim,"store").await.unwrap();
            paced!(&p.tenant_id,&id,repo.retry_asset_job(&p.tenant_id,&claim,0),repo.claim_bgm(&p.tenant_id,&id,120_000),peer.claim_bgm(&p.tenant_id,&id,120_000));
            assert_eq!(repo.upload_attempts(&p.tenant_id,&id).await.unwrap().iter().find(|a|a.id==upload.id).unwrap().outcome,UploadOutcome::Uncertain);
            let p=crate::asset_conformance::seed(repo).await;
            let spec=AssetSpec{mime:"image/png".into(),size:3,sha256:memoswish_core::ids::sha256_hex(b"abc")};
            let intent=repo.prepare_asset(&p,"paced-upload",&spec,5).await.unwrap();
            let claim=repo.claim_asset_job(&p.tenant_id,"a",120_000).await.unwrap().unwrap();
            paced!(&p.tenant_id,&intent.id,repo.retry_asset_job(&p.tenant_id,&claim,0),repo.claim_asset_job(&p.tenant_id,"a",120_000),peer.claim_asset_job(&p.tenant_id,"b",120_000));
            let (authority,_)=crate::import_conformance::authority(repo).await;let p=authority.principal();
            let work=crate::import_conformance::owned_work(&p,1);
            let operation=repo.accept_import(&authority,"paced-import",&"a".repeat(64),&work,None,2).await.unwrap();
            let claim=repo.claim_import(&p.tenant_id,&operation.id,120_000).await.unwrap().unwrap();
            let upload=repo.begin_import_upload(&p.tenant_id,&claim,0,"store").await.unwrap();
            repo.record_upload(&p.tenant_id,&upload,&ObjectVersion::Unversioned).await.unwrap();
            paced!(&p.tenant_id,&operation.id,repo.retry_import(&p.tenant_id,&claim),repo.claim_import(&p.tenant_id,&operation.id,120_000),peer.claim_import(&p.tenant_id,&operation.id,120_000));
            assert_eq!(repo.import_operation(&p.tenant_id,&operation.id).await.unwrap().outcome,"pending");
            // 终态输入失败留下精确清理责任；清理失败同事务推进父业务可用时间。
            sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&operation.id).execute(repo.pool()).await.unwrap();
            let current=repo.claim_import(&p.tenant_id,&operation.id,120_000).await.unwrap().unwrap();
            repo.fail_import(&p.tenant_id,&current).await.unwrap();
            assert!(peer.import_cleanup(&p.tenant_id,&operation.id,"store").await.unwrap().is_empty());
            elapse!(&p.tenant_id,&operation.id);
            let pending=repo.import_cleanup(&p.tenant_id,&operation.id,"store").await.unwrap().pop().unwrap();
            let before=now!();repo.retry_import_cleanup(&p.tenant_id,&operation.id,&pending).await.unwrap();let after=now!();
            assert!((before+CADENCE_MS..=after+CADENCE_MS).contains(&due!(&p.tenant_id,&operation.id)));
            assert!(peer.import_cleanup(&p.tenant_id,&operation.id,"store").await.unwrap().is_empty());
            assert!(peer.retry_import_cleanup(&p.tenant_id,"other-import",&pending).await.is_err());
            elapse!(&p.tenant_id,&operation.id);
            let pending=peer.import_cleanup(&p.tenant_id,&operation.id,"store").await.unwrap().pop().unwrap();
            peer.record_asset_cleaned(&p.tenant_id,&pending).await.unwrap();
            assert!(repo.retry_import_cleanup(&p.tenant_id,&operation.id,&pending).await.is_err());
            assert!(repo.import_cleanup(&p.tenant_id,&operation.id,"store").await.unwrap().is_empty());
            let mut follow_work=crate::import_conformance::owned_work(&p,0);follow_work.auto_tts=true;
            let follow=repo.accept_import(&authority,"paced-followup",&"b".repeat(64),&follow_work,None,2).await.unwrap();
            let claim=repo.claim_import(&p.tenant_id,&follow.id,120_000).await.unwrap().unwrap();
            repo.commit_import(&p.tenant_id,&claim).await.unwrap();
            let card=repo.import_followups(&p.tenant_id,&follow.id).await.unwrap().pop().unwrap().card_id;
            let before=now!();assert!(repo.import_followup(&p.tenant_id,&follow.id,&card,"retry").await.unwrap());let after=now!();
            assert!((before+CADENCE_MS..=after+CADENCE_MS).contains(&due!(&p.tenant_id,&follow.id)));
            assert!(peer.import_followups(&p.tenant_id,&follow.id).await.unwrap().is_empty());
            elapse!(&p.tenant_id,&follow.id);
            assert!(!peer.import_followups(&p.tenant_id,&follow.id).await.unwrap().is_empty());
            // 成功跟进不引入新的延迟，旧终态不能被失败回报改回 pending。
            assert!(peer.import_followup(&p.tenant_id,&follow.id,&card,"succeeded").await.unwrap());
            let due=due!(&p.tenant_id,&follow.id);
            assert!(!repo.import_followup(&p.tenant_id,&follow.id,&card,"retry").await.unwrap());
            assert_eq!(due!(&p.tenant_id,&follow.id),due);
            let body=serde_json::json!({"id":"paced-erasure","tenant_id":null,"purge_assets":false,"credentials":[]}).to_string();
            sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES('paced-erasure',$1)").bind(body).execute(repo.pool()).await.unwrap();
            let claim=repo.claim_erasure("paced-erasure","a",120_000).await.unwrap().unwrap();
            paced!("","paced-erasure",repo.retry_erasure(&claim),repo.claim_erasure("paced-erasure","a",120_000),peer.claim_erasure("paced-erasure","b",120_000));
        }

        async fn recovery_families(repo:&$repo) {
            use memoswish_core::{imports::ImportRepo, tts::{SpeechRepo,SpeechWork,SpeechSubmissionTarget,TtsRequest}};
            let (authority,_)=crate::import_conformance::authority(repo).await;
            let p=authority.principal();
            let work=crate::import_conformance::owned_work(&p,0);
            let operation=repo.accept_import(&authority,"scheduled-import",&"a".repeat(64),&work,None,2).await.unwrap();
            let id=repo.register_maintenance(&TaskRegistration::system(TaskKind::ImportRecovery)).await.unwrap();
            let claim=repo.claim_maintenance(&id,"import-scanner").await.unwrap().unwrap();
            let page=repo.maintenance_discover(&claim).await.unwrap();assert_eq!(page,vec![DiscoveryItem{tenant:p.tenant_id.clone(),id:operation.id}]);
            let admission=repo.admit_maintenance_item(&claim,&page[0]).await.unwrap();assert_eq!(admission.kind,TaskKind::ImportRecovery);
            repo.release_maintenance(&claim,false).await.unwrap();
            let p=crate::asset_conformance::seed(repo).await;
            let mut deck=memoswish_protocol::examples::sample_deck();deck.id=memoswish_core::ids::new_id();
            let mut card=memoswish_protocol::examples::sample_card();card.id=memoswish_core::ids::new_id();card.deck_id=deck.id.clone();card.tts=None;
            repo.insert_deck_with_cards(&p.tenant_id,&deck,&[card.clone()]).await.unwrap();
            let speech=SpeechWork { provenance: None,privacy:None,engine:"placeholder".into(),namespace:"placeholder-v1".into(),request:TtsRequest{text:"scheduled".into(),language:"en".into(),voice:"default".into(),speed:1.0},amount:9,legacy_output:None};
            let submission=repo.submit_speech(&p,"scheduled-speech",&"b".repeat(64),&[SpeechSubmissionTarget{card_id:card.id,revision:card.revision,work:speech}],None).await.unwrap();
            let request=repo.speech_request(&p.tenant_id,&submission.items[0].item_id).await.unwrap();
            for (kind,item) in [(TaskKind::SpeechRecovery,request.synthesis_id),(TaskKind::AttachmentRecovery,request.id)] {
                let id=repo.register_maintenance(&TaskRegistration::system(kind)).await.unwrap();
                let claim=repo.claim_maintenance(&id,"speech-scanner").await.unwrap().unwrap();
                let page=repo.maintenance_discover(&claim).await.unwrap();assert_eq!(page,vec![DiscoveryItem{tenant:p.tenant_id.clone(),id:item}]);
                let admission=repo.admit_maintenance_item(&claim,&page[0]).await.unwrap();assert_eq!(admission.kind,kind);
                repo.release_maintenance(&claim,false).await.unwrap();
            }
            // 发现与接纳不调用 provider，也不释放原始计费预留。
            let held:i64=sqlx::query_scalar("SELECT amount FROM quota_operations WHERE tenant_id=$1 AND state='reserved' AND metric='tts_chars'").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();assert_eq!(held,9);
        }

        async fn producer_wake(repo:&$repo) {
            let erasure=repo.register_maintenance(&TaskRegistration::system(TaskKind::ErasureRecovery)).await.unwrap();
            let tombstone=repo.register_maintenance(&TaskRegistration::system(TaskKind::TombstoneReconcile)).await.unwrap();
            let claim=repo.claim_maintenance(&tombstone,"tombstone-scanner").await.unwrap().unwrap();
            repo.maintenance_sql_page(&claim).await.unwrap();
            let original:Vec<(String,String,i64,i64)>=sqlx::query_as("SELECT m.id,m.cursor,m.cycle,j.available_at_ms FROM maintenance_tasks m JOIN background_jobs j ON j.tenant_id=m.partition_id AND j.id=m.id WHERE m.task_kind IN ('tombstone_reconcile','erasure_recovery') ORDER BY m.id").fetch_all(repo.pool()).await.unwrap();
            assert!(original.iter().all(|r|r.3>0));
            let rollback_id=memoswish_core::ids::new_id();
            let rollback_body=serde_json::json!({"id":rollback_id,"tenant_id":null,"purge_assets":false,"credentials":[]}).to_string();
            let mut tx=repo.pool().begin().await.unwrap();
            sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)").bind(&rollback_id).bind(&rollback_body).execute(&mut *tx).await.unwrap();
            tx.rollback().await.unwrap();
            let after:Vec<(String,String,i64,i64)>=sqlx::query_as("SELECT m.id,m.cursor,m.cycle,j.available_at_ms FROM maintenance_tasks m JOIN background_jobs j ON j.tenant_id=m.partition_id AND j.id=m.id WHERE m.task_kind IN ('tombstone_reconcile','erasure_recovery') ORDER BY m.id").fetch_all(repo.pool()).await.unwrap();assert_eq!(original,after);
            sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)").bind(&rollback_id).bind(&rollback_body).execute(repo.pool()).await.unwrap();
            let woken:Vec<(String,String,i64,i64)>=sqlx::query_as("SELECT m.id,m.cursor,m.cycle,j.available_at_ms FROM maintenance_tasks m JOIN background_jobs j ON j.tenant_id=m.partition_id AND j.id=m.id WHERE m.task_kind IN ('tombstone_reconcile','erasure_recovery') ORDER BY m.id").fetch_all(repo.pool()).await.unwrap();
            for (a,b) in original.iter().zip(&woken) {assert_eq!((&a.0,&a.1,a.2),(&b.0,&b.1,b.2));assert_eq!(b.3,0);}
            let running=repo.claim_maintenance(&erasure,"current-scanner").await.unwrap().unwrap();
            let owned:(String,i64)=sqlx::query_as("SELECT token,lease_until_ms FROM background_jobs WHERE tenant_id='' AND id=$1").bind(&erasure).fetch_one(repo.pool()).await.unwrap();
            let next_id=memoswish_core::ids::new_id();let body=serde_json::json!({"id":next_id,"tenant_id":null,"purge_assets":false,"credentials":[]}).to_string();
            sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)").bind(next_id).bind(body).execute(repo.pool()).await.unwrap();
            let unchanged:(String,i64)=sqlx::query_as("SELECT token,lease_until_ms FROM background_jobs WHERE tenant_id='' AND id=$1").bind(&erasure).fetch_one(repo.pool()).await.unwrap();assert_eq!(owned,unchanged);
            repo.renew_maintenance(&running).await.unwrap();repo.release_maintenance(&running,false).await.unwrap();
        }

        async fn clock_after_lock(repo:&$repo,peer:&$repo) {
            let id=repo.register_maintenance(&TaskRegistration::system(TaskKind::OAuthExpiry)).await.unwrap();
            let claim=repo.claim_maintenance(&id,"clock-owner").await.unwrap().unwrap();
            let mut tx=repo.asset_tx().await.unwrap();
            let now=<$repo>::asset_now(&mut tx).await.unwrap();
            sqlx::query("UPDATE background_jobs SET lease_until_ms=$2 WHERE tenant_id='' AND id=$1").bind(&id).bind(now+80).execute(&mut *tx).await.unwrap();
            let waiting=peer.renew_maintenance(&claim);
            tokio::pin!(waiting);
            // waiter 的事务在锁释放前开始；实际数据库时间必须在等待之后重新观察。
            tokio::select! { result=&mut waiting=>panic!("waiter bypassed held registry lock: {}",result.is_ok()), _=tokio::time::sleep(std::time::Duration::from_millis(160))=>{} }
            tx.commit().await.unwrap();
            assert!(waiting.await.is_err(),"transaction-start clock incorrectly renewed an expired owner");
        }

        async fn bounded_policy(repo:&$repo) {
            let p=crate::asset_conformance::seed(repo).await;
            let other=crate::asset_conformance::seed(repo).await;
            let policy=RetentionPolicy{version:1,api_metadata_after_expiry_seconds:0,failed_tts_payload_after_schedule_seconds:0};
            assert!(repo.register_maintenance(&TaskRegistration::system(TaskKind::Retention)).await.is_err());
            let task=TaskRegistration{kind:TaskKind::Retention,tenant:p.tenant_id.clone(),policy:Some(policy.clone())};
            let id=repo.register_maintenance(&task).await.unwrap();
            let mut wrong=task.clone();wrong.policy.as_mut().unwrap().api_metadata_after_expiry_seconds=1;
            assert!(repo.register_maintenance(&wrong).await.is_err());
            wrong.policy.as_mut().unwrap().version=99;assert!(repo.register_maintenance(&wrong).await.is_err());
            for n in 0..105 {
                sqlx::query("INSERT INTO api_tokens(id,tenant_id,user_id,name,token_hash,scopes,created_at,expires_at) VALUES($1,$2,$3,'test',$4,'[]','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z')").bind(format!("retention-{n}")).bind(&p.tenant_id).bind(&p.user_id).bind(format!("retention-hash-{n}")).execute(repo.pool()).await.unwrap();
            }
            sqlx::query("INSERT INTO api_tokens(id,tenant_id,user_id,name,token_hash,scopes,created_at,expires_at) VALUES('other',$1,$2,'test','other-hash','[]','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z')").bind(&other.tenant_id).bind(&other.user_id).execute(repo.pool()).await.unwrap();
            let preview=repo.retention_sweep(&p.tenant_id,&policy,100,false).await.unwrap();assert_eq!(preview.expired_api_metadata,100);
            let claim=repo.claim_maintenance(&id,"retention").await.unwrap().unwrap();
            repo.maintenance_sql_page(&claim).await.unwrap();
            let remaining:i64=sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE tenant_id=$1").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();assert_eq!(remaining,5);
            let preserved:i64=sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE tenant_id=$1").bind(&other.tenant_id).fetch_one(repo.pool()).await.unwrap();assert_eq!(preserved,1);
        }

        async fn password_expiry(repo:&$repo) {
            // 夹具仅需要身份外键，沿用无口令计算的种子。
            for _ in 0..52 {
                let p=crate::asset_conformance::seed(repo).await;
                for purpose in ["verify","reset"] {
                    sqlx::query("INSERT INTO password_challenges(user_id,purpose,digest,destination,credential_version,generation,expires_at) VALUES($1,$2,$3,'test@example.invalid',0,0,0)")
                        .bind(&p.user_id).bind(purpose).bind(memoswish_core::ids::new_id()).execute(repo.pool()).await.unwrap();
                }
            }
            let survivor=crate::asset_conformance::seed(repo).await;
            sqlx::query("INSERT INTO password_challenges(user_id,purpose,digest,destination,credential_version,generation,expires_at) VALUES($1,'verify',$2,'test@example.invalid',0,0,9223372036854775807)")
                .bind(&survivor.user_id).bind(memoswish_core::ids::new_id()).execute(repo.pool()).await.unwrap();
            let task=repo.register_maintenance(&TaskRegistration::system(TaskKind::PasswordExpiry)).await.unwrap();
            let claim=repo.claim_maintenance(&task,"password-expiry").await.unwrap().unwrap();
            sqlx::raw_sql($fail).execute(repo.pool()).await.unwrap();
            assert!(repo.maintenance_sql_page(&claim).await.is_err());
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM password_challenges").fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count,105);
            sqlx::raw_sql($unfail).execute(repo.pool()).await.unwrap();
            repo.maintenance_sql_page(&claim).await.unwrap();
            assert!(repo.maintenance_sql_page(&claim).await.is_err());
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM password_challenges").fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count,5);
            let live:i64=sqlx::query_scalar("SELECT COUNT(*) FROM password_challenges WHERE user_id=$1").bind(&survivor.user_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(live,1);
        }

        async fn upgrade(pool:&$pool) {
            use crate::foundation_conformance::through;
            let all=sqlx::migrate!($migrations);
            let scheduling=all.iter().find(|m|m.description.as_ref()=="maintenance scheduling").unwrap().version;
            let previous=all.iter().filter(|m|m.version<scheduling).map(|m|m.version).max().unwrap();
            through(&all,previous).run(pool).await.unwrap();
            sqlx::query("INSERT INTO tenants VALUES('upgrade','Upgrade','free','2026-11-11T00:00:00Z')").execute(pool).await.unwrap();
            sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,state,max_attempts,available_at_ms,lease_until_ms,worker,token) VALUES('upgrade','job','asset_upload','job','{}','running',5,123,456,'original-owner','original-token')").execute(pool).await.unwrap();
            sqlx::query("INSERT INTO quota_operations VALUES('upgrade','job','tts_chars','2026-11',17,'reserved')").execute(pool).await.unwrap();
            sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES('account','{\"id\":\"account\",\"tenant_id\":null,\"purge_assets\":false,\"credentials\":[]}')").execute(pool).await.unwrap();
            sqlx::raw_sql("INSERT INTO asset_records VALUES('upgrade','asset','image/png',3,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'); INSERT INTO asset_upload_intents(tenant_id,id,asset_id,account_generation) VALUES('upgrade','job','asset',0); INSERT INTO asset_upload_attempts(tenant_id,id,intent_id,store_id,object_key,claim_token,outcome,version_kind,version_id) VALUES('upgrade','attempt','job','original-store','tenants/upgrade/image','original-token','uploaded','version','null'); UPDATE asset_upload_intents SET published_attempt='attempt' WHERE tenant_id='upgrade' AND id='job'; INSERT INTO managed_object_writes(tenant_id,id,store_id,object_key) VALUES('upgrade','job','original-store','tenants/upgrade/unknown'); INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,state,max_attempts,available_at_ms,lease_until_ms,worker,token) VALUES('upgrade','synthesis','tts_synthesis','synthesis','{}','running',5,123,456,'provider-owner','provider-token'); INSERT INTO tts_syntheses(tenant_id,id,work) VALUES('upgrade','synthesis','{}'); INSERT INTO tts_provider_attempts VALUES('upgrade','synthesis','provider-token','uncertain'); INSERT INTO quota_operations VALUES('upgrade','synthesis','tts_chars','2026-11',23,'reserved');").execute(pool).await.unwrap();
            let before:Vec<(String,String,String,Option<String>,i64)>=sqlx::query_as("SELECT tenant_id,id,state,token,lease_until_ms FROM background_jobs ORDER BY id").fetch_all(pool).await.unwrap();
            let mut broken=through(&all,scheduling);
            let migration=broken.migrations.to_mut().last_mut().unwrap();
            *migration=sqlx::migrate::Migration::new(migration.version,migration.description.clone(),migration.migration_type,format!("{}\nSELECT * FROM s26c_injected_missing;",migration.sql).into(),false);
            assert!(broken.run(pool).await.is_err());
            let head:i64=sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();assert_eq!(head,previous);
            let preserved:Vec<(String,String,String,Option<String>,i64)>=sqlx::query_as("SELECT tenant_id,id,state,token,lease_until_ms FROM background_jobs ORDER BY id").fetch_all(pool).await.unwrap();assert_eq!(before,preserved);
            all.run(pool).await.unwrap();
            let after:Vec<(String,String,String,Option<String>,i64)>=sqlx::query_as("SELECT tenant_id,id,state,token,lease_until_ms FROM background_jobs ORDER BY id").fetch_all(pool).await.unwrap();assert_eq!(before,after);
            let held:i64=sqlx::query_scalar("SELECT amount FROM quota_operations WHERE tenant_id='upgrade' AND operation_id='job' AND state='reserved'").fetch_one(pool).await.unwrap();assert_eq!(held,17);
            let receipt:(String,String,String)=sqlx::query_as("SELECT claim_token,version_kind,version_id FROM asset_upload_attempts WHERE tenant_id='upgrade' AND id='attempt'").fetch_one(pool).await.unwrap();assert_eq!(receipt,("original-token".into(),"version".into(),"null".into()));
            let unresolved:(String,String)=sqlx::query_as("SELECT outcome,version_kind FROM managed_object_writes WHERE tenant_id='upgrade' AND id='job'").fetch_one(pool).await.unwrap();assert_eq!(unresolved,("uncertain".into(),"unknown".into()));
            let provider:(String,String)=sqlx::query_as("SELECT claim_token,outcome FROM tts_provider_attempts WHERE tenant_id='upgrade' AND synthesis_id='synthesis'").fetch_one(pool).await.unwrap();assert_eq!(provider,("provider-token".into(),"uncertain".into()));
            let held_provider:i64=sqlx::query_scalar("SELECT amount FROM quota_operations WHERE tenant_id='upgrade' AND operation_id='synthesis' AND state='reserved'").fetch_one(pool).await.unwrap();assert_eq!(held_provider,23);
            // 父任务、作用域和版本都有数据库约束，失败插入不能留下孤儿。
            for sql in [
                "INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope) VALUES('','forged','tts_synthesis','forged','{}',1,0,'maintenance')",
                "INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope) VALUES('','forged','maintenance','forged','{}',1,0,'maintenance')",
                "INSERT INTO maintenance_tasks(id,task_kind,payload_version) VALUES('orphan','feed_expiry',1)",
                "INSERT INTO maintenance_tasks(id,task_kind,payload_version) VALUES('account','feed_expiry',1)",
                "INSERT INTO maintenance_tasks(id,task_kind,payload_version) VALUES('unknown','unknown',1)",
                "INSERT INTO maintenance_tasks(id,task_kind,payload_version) VALUES('version','feed_expiry',99)",
            ] { assert!(sqlx::query(sql).execute(pool).await.is_err(),"{sql}"); }
            assert!(sqlx::query("UPDATE background_jobs SET work_scope='account' WHERE tenant_id='upgrade'").execute(pool).await.is_err());
            assert!(sqlx::query("DELETE FROM background_jobs WHERE tenant_id='upgrade' AND id='job'").execute(pool).await.is_err());
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    suite!(
        SqliteRepository,
        sqlx::SqlitePool,
        "./migrations/sqlite",
        "CREATE TRIGGER injected_schedule_failure BEFORE UPDATE OF cycle,cursor ON maintenance_tasks BEGIN SELECT RAISE(ABORT,'injected'); END;",
        "DROP TRIGGER injected_schedule_failure;"
    );

    #[tokio::test]
    async fn maintenance_sqlite_independent_pool_fencing_and_rollback() {
        let dir = std::env::temp_dir().join(format!("s26c-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", dir.display());
        let a = SqliteRepository::connect_test(&url).await.unwrap();
        let b = SqliteRepository::connect_test(&url).await.unwrap();
        fences_and_rollback(&a, &b).await;
        clock_after_lock(&a, &b).await;
        discovery(&a, &b).await;
        bounded_policy(&a).await;
        recovery_families(&a).await;
        producer_wake(&a).await;
        password_expiry(&a).await;
        a.pool().close().await;
        b.pool().close().await;
        std::fs::remove_file(dir).unwrap();
    }

    #[tokio::test]
    async fn maintenance_sqlite_hf11_business_error_pacing() {
        let dir = std::env::temp_dir().join(format!("hf11-pacing-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", dir.display());
        let a = SqliteRepository::connect_test(&url).await.unwrap();
        let b = SqliteRepository::connect_test(&url).await.unwrap();
        hf11_business_error_pacing(&a, &b).await;
        a.pool().close().await;
        b.pool().close().await;
        std::fs::remove_file(dir).unwrap();
    }

    #[tokio::test]
    async fn maintenance_sqlite_hf11_live_speech_wrap_and_restart() {
        let dir = std::env::temp_dir().join(format!("hf11-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", dir.display());
        let a = SqliteRepository::connect_test(&url).await.unwrap();
        let b = SqliteRepository::connect_test(&url).await.unwrap();
        hf11_live_speech_wrap_and_restart(&a, &b).await;
        a.pool().close().await;
        b.pool().close().await;
        std::fs::remove_file(dir).unwrap();
    }

    #[tokio::test]
    async fn maintenance_sqlite_populated_upgrade_preserves_claims_and_foreign_keys() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(sqlx::sqlite::SqliteConnectOptions::new().in_memory(true).foreign_keys(true))
            .await
            .unwrap();
        upgrade(&pool).await;
        let violations = sqlx::query("PRAGMA foreign_key_check").fetch_all(&pool).await.unwrap();
        assert!(violations.is_empty());
        let guard: i64 =
            sqlx::query_scalar("SELECT work_scope_guard FROM background_jobs WHERE tenant_id='upgrade' AND id='job'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(guard, 1);
        assert!(
            sqlx::query("UPDATE background_jobs SET work_scope_guard=0 WHERE tenant_id='upgrade' AND id='job'")
                .execute(&pool)
                .await
                .is_err()
        );
        let enabled: i64 = sqlx::query_scalar("PRAGMA foreign_keys").fetch_one(&pool).await.unwrap();
        assert_eq!(enabled, 1);
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
        "CREATE FUNCTION injected_schedule_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$; CREATE TRIGGER injected_schedule_failure BEFORE UPDATE OF cycle,cursor ON maintenance_tasks FOR EACH ROW EXECUTE FUNCTION injected_schedule_failure();",
        "DROP TRIGGER injected_schedule_failure ON maintenance_tasks; DROP FUNCTION injected_schedule_failure();"
    );

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn maintenance_postgres_independent_pool_fencing_and_rollback() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let f = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let a = f.repository(2).await.unwrap();
            let b = f.repository(2).await.unwrap();
            fences_and_rollback(&a, &b).await;
            clock_after_lock(&a, &b).await;
            discovery(&a, &b).await;
            bounded_policy(&a).await;
            recovery_families(&a).await;
            producer_wake(&a).await;
            password_expiry(&a).await;
            a.pool().close().await;
            b.pool().close().await;
            f.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn maintenance_postgres_hf11_business_error_pacing() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let f = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let a = f.repository(2).await.unwrap();
            let b = f.repository(2).await.unwrap();
            hf11_business_error_pacing(&a, &b).await;
            a.pool().close().await;
            b.pool().close().await;
            f.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn maintenance_postgres_hf11_live_speech_wrap_and_restart() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let f = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let a = f.repository(2).await.unwrap();
            let b = f.repository(2).await.unwrap();
            hf11_live_speech_wrap_and_restart(&a, &b).await;
            a.pool().close().await;
            b.pool().close().await;
            f.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn maintenance_postgres_populated_upgrade_preserves_claims_and_foreign_keys() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let f = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(f.options()).await.unwrap();
            upgrade(&pool).await;
            pool.close().await;
            f.cleanup().await;
        });
    }
}
