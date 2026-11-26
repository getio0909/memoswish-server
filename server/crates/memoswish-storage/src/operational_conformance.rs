//! 双库共享升级、历史 unknown、重试/耗尽与真实池故障场景。
use memoswish_core::{
    observability::*,
    repo::{AuthRepo, ContentRepo},
};
use std::sync::{Arc, Mutex};

#[derive(Default, Clone)]
pub(crate) struct Recording(pub(crate) Arc<Mutex<Vec<(Operation, Outcome)>>>);
struct Guard {
    events: Recording,
    operation: Operation,
    finished: bool,
}
impl Observer for Recording {
    fn start(&self, operation: Operation) -> Box<dyn ObservationGuard> {
        Box::new(Guard { events: self.clone(), operation, finished: false })
    }
}
impl ObservationGuard for Guard {
    fn finish(&mut self, outcome: Outcome) {
        if !self.finished {
            self.events.0.lock().unwrap().push((self.operation, outcome));
            self.finished = true;
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.finish(Outcome::Cancelled);
    }
}

macro_rules! conformance {
    ($repo:ty,$pool:ty,$migrations:literal) => {
        async fn authority_coverage(repo: &$repo) {
            use sqlx::Row;
            let rows = sqlx::query(&<$repo>::operational_query()).fetch_all(repo.pool()).await.unwrap();
            let actual: std::collections::BTreeSet<String> = rows.iter()
                .filter_map(|r|r.get::<Option<String>,_>("authority")).collect();
            let expected: std::collections::BTreeSet<String> = crate::recovery::AUTHORITIES.iter()
                .map(|a|a.name.to_string()).chain(crate::recovery::expiry_authorities().map(|e|e.table.to_string())).collect();
            let required: std::collections::BTreeSet<String> = [
                "imports","followups","import_cleanup","speech","bgm","attachments","providers","assets","erasures","objects","tombstones","jobs","retained_speech","retained_api","fences",
                "explanations","explanation_results","diagnostics","diagnostic_expiry","password_expiry","feed_expiry","maintenance",
                "oauth_authorization_requests","auth_browser_sessions","oauth_grants","oauth_clients","oidc_attempts","oidc_handoffs","recent_authentication","identity_events","app_sessions",
            ].into_iter().map(str::to_string).collect();
            assert_eq!(expected,required,"the guard must enumerate every recovery authority, including integrated slices");
            assert_eq!(actual, expected, "every recovery authority must be represented even with no candidates");
            assert_eq!(rows.len(), expected.len()+1, "empty snapshot has bounded coverage and one empty aggregate");
            assert!(repo.operational_snapshot().await.unwrap().pending.is_empty());
            // 逐项移除实际联合分支，证明即使空库也不能靠独立名单伪造覆盖。
            for name in &expected {
                let branch=crate::recovery::projection(name);
                let query=<$repo>::operational_query().replace(branch.as_str(),&format!("{branch} WHERE 1=0"));
                let omitted=sqlx::query(&query).fetch_all(repo.pool()).await.unwrap();
                let covered:std::collections::BTreeSet<String>=omitted.iter().filter_map(|r|r.get::<Option<String>,_>("authority")).collect();
                assert_ne!(covered,expected,"coverage guard must reject a missing authority");
                assert!(!covered.contains(name));
                assert_eq!(covered.len()+1,expected.len());
            }
        }
        async fn integrated_scheduling(repo: &$repo) {
            use memoswish_core::maintenance::{MaintenanceRepo, TaskKind, TaskRegistration};
            let id=repo.register_maintenance(&TaskRegistration::system(TaskKind::PasswordExpiry)).await.unwrap();
            let snapshot=repo.operational_snapshot().await.unwrap();
            assert_eq!(snapshot.maintenance.len(),1);
            assert_eq!(snapshot.maintenance[0].state,TaskState::Queued);
            assert_eq!(snapshot.pending.iter().find(|r|r.kind==WorkKind::Maintenance).unwrap().count,1);
            assert!(!snapshot.pending.iter().any(|r|r.kind==WorkKind::Other),"periodic tasks must not leak into generic jobs");
            let claim=repo.claim_maintenance(&id,"metrics-worker").await.unwrap().unwrap();
            let running=repo.operational_snapshot().await.unwrap();
            assert_eq!(running.maintenance[0].state,TaskState::Running);
            assert!(!running.pending.iter().any(|r|r.kind==WorkKind::Maintenance),"live lease is not overdue");
            repo.maintenance_sql_page(&claim).await.unwrap();
            let waiting=repo.operational_snapshot().await.unwrap();
            assert_eq!(waiting.maintenance[0].state,TaskState::Queued);
            assert!(!waiting.pending.iter().any(|r|r.kind==WorkKind::Maintenance),"future scheduled cycle is not backlog");
            let p=crate::asset_conformance::seed(repo).await;
            sqlx::query("INSERT INTO password_challenges(user_id,purpose,digest,destination,credential_version,generation,expires_at) VALUES($1,'reset','digest','destination',0,0,0)")
                .bind(&p.user_id).execute(repo.pool()).await.unwrap();
            assert_eq!(repo.operational_snapshot().await.unwrap().pending.iter().find(|r|r.kind==WorkKind::ExpiredPassword).unwrap().count,1);
            sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE tenant_id='' AND id=$1").bind(&id).execute(repo.pool()).await.unwrap();
            let claim=repo.claim_maintenance(&id,"metrics-worker").await.unwrap().unwrap();
            repo.maintenance_sql_page(&claim).await.unwrap();
            assert!(!repo.operational_snapshot().await.unwrap().pending.iter().any(|r|r.kind==WorkKind::ExpiredPassword));
            // 测试夹具停用唯一注册，后续终态断言仍要求真实无积压。
            sqlx::query("UPDATE maintenance_tasks SET enabled=0 WHERE id=$1").bind(&id).execute(repo.pool()).await.unwrap();
        }

        async fn followups_prepare(repo: &$repo) -> (memoswish_core::imports::ImportAuthority, memoswish_core::imports::ImportWork, String, i64) {
            use memoswish_core::{imports::ImportRepo};
            let (a, _) = crate::import_conformance::authority(repo).await;
            let mut work = crate::import_conformance::owned_work(&a.principal,0);
            work.auto_tts=true;
            let op=repo.accept_import(&a,"metrics-followups",&"a".repeat(64),&work,None,2).await.unwrap();
            let claim=repo.claim_import(&a.principal.tenant_id,&op.id,30_000).await.unwrap().unwrap();
            let start=repo.operational_snapshot().await.unwrap().pending.iter().find(|r|r.kind==WorkKind::Import).unwrap().oldest_ms.unwrap();
            let committed=repo.commit_import(&a.principal.tenant_id,&claim).await.unwrap();
            assert_eq!(committed.outcome,"committed");
            assert_eq!(repo.get_usage(&a.principal.tenant_id,"card_writes",&chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),2);
            assert_eq!(repo.held_import_usage(&a.principal.tenant_id,&chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),0);
            assert_eq!(repo.import_followups(&a.principal.tenant_id,&op.id).await.unwrap().len(),2);
            assert!(repo.pending_imports(None).await.unwrap().contains(&(a.principal.tenant_id.clone(),op.id.clone())));
            assert_work(repo,WorkKind::Import,1,0,Some(start)).await;
            (a,work,op.id,start)
        }
        async fn assert_work(repo: &$repo, kind: WorkKind,count:i64,unknown:i64,oldest:Option<i64>) {
            let snapshot=repo.operational_snapshot().await.unwrap();
            let row=snapshot.pending.iter().find(|r|r.kind==kind).unwrap();
            assert_eq!((row.count,row.unknown,row.oldest_ms),(count,unknown,oldest));
        }
        async fn followups_finish(repo: &$repo, state:(memoswish_core::imports::ImportAuthority,memoswish_core::imports::ImportWork,String,i64)) {
            use memoswish_core::{imports::ImportRepo};
            let (a,work,id,start)=state;
            assert_work(repo,WorkKind::Import,1,0,Some(start)).await;
            for (position,card) in work.cards.iter().enumerate() {
                assert!(repo.import_followup(&a.principal.tenant_id,&id,&card.id,"running").await.unwrap());
                assert_work(repo,WorkKind::Import,1,0,Some(start)).await;
                assert!(repo.import_followup(&a.principal.tenant_id,&id,&card.id,if position==0 {"succeeded"}else{"failed"}).await.unwrap());
                assert!(repo.get_card(&a.principal.tenant_id,&card.id).await.unwrap().is_some());
            }
            assert!(!repo.pending_imports(None).await.unwrap().contains(&(a.principal.tenant_id.clone(),id.clone())));
            assert!(!repo.operational_snapshot().await.unwrap().pending.iter().any(|r|r.kind==WorkKind::Import));
            assert_eq!(repo.import_operation(&a.principal.tenant_id,&id).await.unwrap().outcome,"committed");
        }
        async fn attachments_prepare(repo: &$repo) -> (memoswish_core::Principal,Vec<memoswish_core::tts::SpeechSubmissionTarget>,Vec<String>,i64) {
            use memoswish_core::{tts::*,assets::*};
            let p=crate::asset_conformance::seed(repo).await;
            let work=crate::import_conformance::owned_work(&p,0);
            repo.insert_deck_with_cards(&p.tenant_id,&work.deck,&work.cards).await.unwrap();
            let speech=SpeechWork { provenance: None, privacy:None,engine:"test".into(),namespace:"attachments".into(),amount:3,legacy_output:None,
                request:TtsRequest{text:"abc".into(),language:"en".into(),voice:"default".into(),speed:1.0}};
            let targets:Vec<_>=work.cards.iter().map(|c|SpeechSubmissionTarget{card_id:c.id.clone(),revision:c.revision,work:speech.clone()}).collect();
            let accepted=repo.submit_speech(&p,"metrics-attachments",&"a".repeat(64),&targets,Some(3)).await.unwrap();
            let first=repo.speech_request(&p.tenant_id,&accepted.items[0].item_id).await.unwrap();
            let start=repo.operational_snapshot().await.unwrap().pending.iter().find(|r|r.kind==WorkKind::Speech).unwrap().oldest_ms.unwrap();
            assert_work(repo,WorkKind::Speech,1,0,Some(start)).await;
            let claim=repo.claim_speech(&p.tenant_id,&first.synthesis_id,30_000).await.unwrap().unwrap();
            repo.begin_provider(&p.tenant_id,&claim).await.unwrap();
            repo.materialize_speech(&p.tenant_id,&claim,b"abc",&crate::asset_conformance::spec(),&SpeechMetadata { alignment_quality: None, audio_kind: None, provenance: None,extension:"wav".into(),duration_ms:100,words:vec![]},false).await.unwrap();
            let (upload,_)=repo.speech_upload(&p.tenant_id,&first.synthesis_id).await.unwrap().unwrap();
            let claim=repo.claim_speech(&p.tenant_id,&upload,30_000).await.unwrap().unwrap();
            let attempt=repo.begin_upload(&p.tenant_id,&claim,"disk").await.unwrap();
            repo.record_upload(&p.tenant_id,&attempt,&ObjectVersion::Unversioned).await.unwrap();
            repo.publish_speech(&p.tenant_id,&claim,&attempt.id).await.unwrap();
            let states:Vec<String>=sqlx::query_scalar("SELECT state FROM background_jobs WHERE tenant_id=$1 AND kind IN ('tts_synthesis','asset_upload')").bind(&p.tenant_id).fetch_all(repo.pool()).await.unwrap();
            assert_eq!(states,vec!["succeeded","succeeded"]);
            assert!(!repo.pending_speech(None,100).await.unwrap().contains(&(p.tenant_id.clone(),first.synthesis_id)));
            assert_work(repo,WorkKind::Speech,1,0,Some(start)).await;
            assert!(!repo.operational_snapshot().await.unwrap().pending.iter().any(|r|r.kind==WorkKind::Orphan));
            assert_eq!(repo.held_speech_usage(&p.tenant_id,&chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),(0,0));
            assert_eq!(repo.get_usage(&p.tenant_id,"tts_chars",&chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),3);
            (p,targets,accepted.items.into_iter().map(|i|i.item_id).collect(),start)
        }
        async fn attachments_finish(repo: &$repo,state:(memoswish_core::Principal,Vec<memoswish_core::tts::SpeechSubmissionTarget>,Vec<String>,i64)) {
            use memoswish_core::{tts::*};
            let (p,targets,items,start)=state;
            assert_work(repo,WorkKind::Speech,1,0,Some(start)).await;
            let pending=repo.pending_speech_attachments(None,100).await.unwrap();
            for item in &items {assert!(pending.contains(&(p.tenant_id.clone(),item.clone())));}
            // 保留现有 CAS 与原子回执约束：一个成功、另一个因并发编辑冲突。
            let mut card=repo.get_card(&p.tenant_id,&targets[1].card_id).await.unwrap().unwrap();
            card.front.title="Competing edit".into();
            repo.mutate_cards(&p.tenant_id,&[crate::content_conformance::edit(&card,Some(card.revision),"Competing edit")]).await.unwrap();
            repo.resolve_speech_attachment(&p.tenant_id,&items[0]).await.unwrap();
            assert_work(repo,WorkKind::Speech,1,0,Some(start)).await;
            repo.resolve_speech_attachment(&p.tenant_id,&items[1]).await.unwrap();
            let complete=repo.speech_submission(&p,"metrics-attachments",None).await.unwrap().unwrap();
            assert!(complete.complete);
            assert_eq!(complete.items[0].receipt.as_ref().unwrap().disposition,memoswish_protocol::tts::TtsDisposition::Attached);
            assert_eq!(complete.items[1].receipt.as_ref().unwrap().disposition,memoswish_protocol::tts::TtsDisposition::Conflict);
            assert!(repo.pending_speech_attachments(None,100).await.unwrap().is_empty());
            assert!(!repo.operational_snapshot().await.unwrap().pending.iter().any(|r|r.kind==WorkKind::Speech));
            for item in &items {repo.resolve_speech_attachment(&p.tenant_id,item).await.unwrap();}
            assert_eq!(repo.speech_submission(&p,"metrics-attachments",None).await.unwrap().unwrap(),complete);
        }
        async fn legacy_publication(pool: &$pool,tenant:&str) {
            sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,state) VALUES($1,'upload','asset_upload','upload','{}',5,0,'succeeded')").bind(tenant).execute(pool).await.unwrap();
            sqlx::query("INSERT INTO asset_records(tenant_id,id,mime,size,sha256) VALUES($1,'asset','audio/wav',3,$2)").bind(tenant).bind("a".repeat(64)).execute(pool).await.unwrap();
            sqlx::query("INSERT INTO asset_upload_intents(tenant_id,id,asset_id,account_generation) VALUES($1,'upload','asset',0)").bind(tenant).execute(pool).await.unwrap();
            sqlx::query("INSERT INTO asset_upload_attempts(tenant_id,id,intent_id,store_id,object_key,claim_token,outcome,version_kind) VALUES($1,'attempt','upload','disk',$2,'claim','uploaded','unversioned')").bind(tenant).bind(format!("tenants/{tenant}/speech")).execute(pool).await.unwrap();
            sqlx::query("UPDATE asset_upload_intents SET published_attempt='attempt' WHERE tenant_id=$1").bind(tenant).execute(pool).await.unwrap();
            sqlx::query("UPDATE tts_syntheses SET upload_id='upload' WHERE tenant_id=$1").bind(tenant).execute(pool).await.unwrap();
        }
        async fn legacy_followup_upgrade(pool: &$pool) {
            let full=sqlx::migrate!($migrations);
            crate::foundation_conformance::through(&full,27).run(pool).await.unwrap();
            sqlx::raw_sql("INSERT INTO tenants(id,name,created_at) VALUES('legacy-followup','Legacy','2026-11-01');
                INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,state) VALUES('legacy-followup','import','content_import','import','{}',5,0,'succeeded');
                INSERT INTO content_imports(tenant_id,id,user_id,fingerprint,authority_id,authority,work,outcome,result) VALUES('legacy-followup','import','user','hash','authority','{}','{}','committed','{}');
                INSERT INTO import_followups VALUES('legacy-followup','import','card-a',1,'pending');
                INSERT INTO import_followups VALUES('legacy-followup','import','card-b',1,'running');
                INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,state) VALUES('legacy-followup','speech','tts_synthesis','speech','{}',5,0,'succeeded');
                INSERT INTO tts_syntheses(tenant_id,id,work) VALUES('legacy-followup','speech','{}');
                INSERT INTO tts_provider_attempts VALUES('legacy-followup','speech','returned','returned');
                INSERT INTO membership_generations(tenant_id,user_id,generation) VALUES('legacy-followup','user',0);
                INSERT INTO tts_requesters(tenant_id,id,synthesis_id,user_id,account_generation,membership_generation,content_permission,card_id,revision,outcome) VALUES('legacy-followup','item','speech','user',0,0,1,'missing',1,'failed');
                INSERT INTO tts_submissions VALUES('legacy-followup','user','request','hash',0,0);
                INSERT INTO tts_submission_items(tenant_id,user_id,request_id,position,item_id) VALUES('legacy-followup','user','request',0,'item');")
                .execute(pool).await.unwrap();
            legacy_publication(pool,"legacy-followup").await;
            full.run(pool).await.unwrap();
        }
        async fn legacy_followup_finish(repo: &$repo) {
            use memoswish_core::{imports::ImportRepo,tts::SpeechRepo};
            assert_work(repo,WorkKind::Import,1,1,None).await;
            assert_work(repo,WorkKind::Speech,1,1,None).await;
            assert_eq!(repo.pending_imports(None).await.unwrap(),vec![("legacy-followup".into(),"import".into())]);
            assert_eq!(repo.pending_speech_attachments(None,100).await.unwrap(),vec![("legacy-followup".into(),"item".into())]);
            repo.import_followup("legacy-followup","import","card-a","succeeded").await.unwrap();
            assert_work(repo,WorkKind::Import,1,1,None).await;
            repo.import_followup("legacy-followup","import","card-b","failed").await.unwrap();
            repo.resolve_speech_attachment("legacy-followup","item").await.unwrap();
            assert!(repo.pending_imports(None).await.unwrap().is_empty());
            assert!(repo.pending_speech_attachments(None,100).await.unwrap().is_empty());
            assert!(repo.operational_snapshot().await.unwrap().pending.is_empty());
        }
        async fn upgrade(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            crate::foundation_conformance::through(&full, 27).run(pool).await.unwrap();
            // 升级前成功的合成仍有历史未决尝试；迁移不能替它补造责任年龄。
            sqlx::raw_sql("INSERT INTO tenants(id,name,created_at) VALUES('legacy-provider','Legacy','2026-11-01');
                INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,state) VALUES('legacy-provider','speech','tts_synthesis','speech','{}',5,0,'succeeded');
                INSERT INTO tts_syntheses(tenant_id,id,work) VALUES('legacy-provider','speech','{}');
                INSERT INTO tts_provider_attempts VALUES('legacy-provider','speech','first','uncertain');
                INSERT INTO tts_provider_attempts VALUES('legacy-provider','speech','retry','returned');
                INSERT INTO quota_operations VALUES('legacy-provider','speech','tts_chars','2026-11',3,'committed');
                INSERT INTO tenants(id,name,created_at) VALUES('legacy-provider-peer','Peer','2026-11-01');
                INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,state) VALUES('legacy-provider-peer','speech','tts_synthesis','speech','{}',5,0,'succeeded');
                INSERT INTO tts_syntheses(tenant_id,id,work) VALUES('legacy-provider-peer','speech','{}');
                INSERT INTO tts_provider_attempts VALUES('legacy-provider-peer','speech','returned','returned');
                INSERT INTO quota_operations VALUES('legacy-provider-peer','speech','tts_chars','2026-11',3,'committed');")
                .execute(pool).await.unwrap();
            legacy_publication(pool,"legacy-provider-peer").await;
            let old = memoswish_core::identity::ErasureJob {
                id: "legacy-account".into(),
                tenant_id: None,
                purge_assets: false,
                credentials: vec![],
            };
            sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
                .bind(&old.id)
                .bind(serde_json::to_string(&old).unwrap())
                .execute(pool)
                .await
                .unwrap();
            full.run(pool).await.unwrap();
            let null_time: Option<i64> = sqlx::query_scalar("SELECT enqueued_at_ms FROM background_jobs WHERE id=$1")
                .bind(&old.id)
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(null_time, None);
            let null_time: Option<i64> =
                sqlx::query_scalar("SELECT responsibility_at_ms FROM account_erasure_jobs WHERE id=$1")
                    .bind(&old.id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(null_time, None);
        }
        async fn responsibility(repo: &$repo) {
            use memoswish_core::erasure::ErasureRepo;
            let historical = repo.operational_snapshot().await.unwrap();
            let provider = historical.pending.iter().find(|r| r.kind == WorkKind::Speech).unwrap();
            assert_eq!((provider.count, provider.unknown, provider.oldest_ms), (1, 1, None));
            let row = historical.pending.iter().find(|r| r.kind == WorkKind::Erasure).unwrap();
            assert_eq!((row.count, row.unknown, row.oldest_ms), (1, 1, None));
            // 旧插入语句无需新列也得到真实 DB 时间；available_at_ms=0 不参与起算。
            let fresh = memoswish_core::identity::ErasureJob {
                id: "new-account".into(),
                tenant_id: None,
                purge_assets: false,
                credentials: vec![],
            };
            sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
                .bind(&fresh.id)
                .bind(serde_json::to_string(&fresh).unwrap())
                .execute(repo.pool())
                .await
                .unwrap();
            let start: i64 = sqlx::query_scalar("SELECT enqueued_at_ms FROM background_jobs WHERE id=$1")
                .bind(&fresh.id)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert!(start >= historical.observed_at_ms);
            sqlx::query("UPDATE background_jobs SET available_at_ms=9999999999999,state='dead' WHERE id=$1")
                .bind(&fresh.id)
                .execute(repo.pool())
                .await
                .unwrap();
            let unchanged: i64 = sqlx::query_scalar("SELECT enqueued_at_ms FROM background_jobs WHERE id=$1")
                .bind(&fresh.id)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(start, unchanged);
            assert!(
                sqlx::query("UPDATE background_jobs SET enqueued_at_ms=1 WHERE id=$1")
                    .bind(&fresh.id)
                    .execute(repo.pool())
                    .await
                    .is_err()
            );
            sqlx::query("UPDATE account_erasure_jobs SET progress='blocked' WHERE id=$1")
                .bind(&fresh.id)
                .execute(repo.pool())
                .await
                .unwrap();
            let snapshot = repo.operational_snapshot().await.unwrap();
            let row = snapshot.pending.iter().find(|r| r.kind == WorkKind::Erasure).unwrap();
            assert_eq!((row.count, row.unknown), (2, 1));
            assert!(row.oldest_ms.unwrap() >= historical.observed_at_ms);
            // 历史 unknown 不因 retry/reconciliation 而伪造；完成后新的责任周期才可用新的真实时间。
            sqlx::query("UPDATE account_erasure_jobs SET progress='blocked' WHERE id='legacy-account'")
                .execute(repo.pool())
                .await
                .unwrap();
            assert_eq!(
                repo.operational_snapshot()
                    .await
                    .unwrap()
                    .pending
                    .iter()
                    .find(|r| r.kind == WorkKind::Erasure)
                    .unwrap()
                    .unknown,
                1
            );
            sqlx::query(
                "UPDATE account_erasure_jobs SET progress='complete',responsibility_at_ms=1 WHERE id='new-account'",
            )
            .execute(repo.pool())
            .await
            .unwrap();
            sqlx::query("UPDATE account_erasure_jobs SET progress='pending' WHERE id='new-account'")
                .execute(repo.pool())
                .await
                .unwrap();
            let reopened: i64 =
                sqlx::query_scalar("SELECT responsibility_at_ms FROM account_erasure_jobs WHERE id='new-account'")
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert!(reopened >= start);
            // 未来损坏时间单独计数，不输出负年龄；未知与未来都不冒充零年龄。
            sqlx::query("UPDATE account_erasure_jobs SET responsibility_at_ms=9999999999999 WHERE id='new-account'")
                .execute(repo.pool())
                .await
                .unwrap();
            let snapshot = repo.operational_snapshot().await.unwrap();
            let row = snapshot.pending.iter().find(|r| r.kind == WorkKind::Erasure).unwrap();
            assert_eq!((row.unknown, row.future, row.oldest_ms), (1, 1, None));
            let claim = repo.claim_erasure("legacy-account", "ops-test", 30_000).await.unwrap().unwrap();
            repo.retry_erasure(&claim).await.unwrap();
            let snapshot = repo.operational_snapshot().await.unwrap();
            assert_eq!(snapshot.pending.iter().find(|r| r.kind == WorkKind::Erasure).unwrap().unknown, 1);
        }
        async fn cleanup_cycles(repo: &$repo) {
            use memoswish_core::{assets::*, erasure::ErasureRepo, jobs::AssetJobRepo};
            let p = crate::asset_conformance::seed(repo).await;
            let object = repo
                .register_managed_put(&p.tenant_id, "disk", &format!("tenants/{}/managed", p.tenant_id))
                .await
                .unwrap();
            let first = repo.operational_snapshot().await.unwrap();
            assert_eq!(first.pending.iter().find(|r| r.kind == WorkKind::ManagedWrite).unwrap().count, 1);
            repo.record_managed_put(&object, &ObjectVersion::Unversioned).await.unwrap();
            assert!(
                !repo.operational_snapshot().await.unwrap().pending.iter().any(|r| r.kind == WorkKind::ManagedWrite)
            );
            sqlx::query("UPDATE managed_object_writes SET responsibility_at_ms=1 WHERE tenant_id=$1")
                .bind(&p.tenant_id)
                .execute(repo.pool())
                .await
                .unwrap();
            let intent = repo.prepare_asset(&p, "orphan", &crate::asset_conformance::spec(), 3).await.unwrap();
            let claim = repo.claim_asset_job(&p.tenant_id, "writer", 30_000).await.unwrap().unwrap();
            let attempt = repo.begin_upload(&p.tenant_id, &claim, "disk").await.unwrap();
            repo.record_upload(&p.tenant_id, &attempt, &ObjectVersion::Unversioned).await.unwrap();
            // 已收到回执但尚未发布仍是待办，不能仅排除 uploaded。
            assert_eq!(
                repo.operational_snapshot()
                    .await
                    .unwrap()
                    .pending
                    .iter()
                    .find(|r| r.kind == WorkKind::Orphan)
                    .unwrap()
                    .count,
                1
            );
            repo.publish_asset(
                &p,
                &claim,
                &attempt.id,
                &AssetReference { asset_id: intent.asset_id, owner_id: "owner".into(), slot: "image".into() },
            )
            .await
            .unwrap();
            assert!(!repo.operational_snapshot().await.unwrap().pending.iter().any(|r| r.kind == WorkKind::Orphan));
            sqlx::query("UPDATE asset_upload_attempts SET responsibility_at_ms=1 WHERE tenant_id=$1")
                .bind(&p.tenant_id)
                .execute(repo.pool())
                .await
                .unwrap();
            let before = repo.operational_snapshot().await.unwrap().observed_at_ms;
            sqlx::query("INSERT INTO erased_tenants(tenant_id) VALUES($1)")
                .bind(&p.tenant_id)
                .execute(repo.pool())
                .await
                .unwrap();
            let after = repo.operational_snapshot().await.unwrap();
            for kind in [WorkKind::ManagedWrite, WorkKind::Orphan] {
                assert!(after.pending.iter().find(|r| r.kind == kind).unwrap().oldest_ms.unwrap() >= before);
            }
            let mut object = object;
            object.version = ObjectVersion::Unversioned;
            repo.prepare_managed_compensation(&object).await.unwrap();
            let after_retry = repo.operational_snapshot().await.unwrap();
            assert_eq!(
                after.pending.iter().find(|r| r.kind == WorkKind::ManagedWrite).unwrap().oldest_ms,
                after_retry.pending.iter().find(|r| r.kind == WorkKind::ManagedWrite).unwrap().oldest_ms
            );
            repo.record_erasure_object(&object).await.unwrap();
            assert!(
                !repo.operational_snapshot().await.unwrap().pending.iter().any(|r| r.kind == WorkKind::ManagedWrite)
            );
        }

        async fn provider_retry(repo: &$repo) -> (memoswish_core::Principal, i64) {
            use memoswish_core::{assets::*, repo::AuthRepo, tts::*};
            let p = crate::asset_conformance::seed(repo).await;
            let work = SpeechWork { provenance: None,
                privacy: None, engine: "test".into(), namespace: "config".into(), amount: 3, legacy_output: None,
                request: TtsRequest { text: "abc".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
            };
            let r = repo.accept_speech(&p, &work, None, Some(3)).await.unwrap();
            let first = repo.operational_snapshot().await.unwrap();
            let start = first.pending.iter().find(|r| r.kind == WorkKind::Speech).unwrap().oldest_ms.unwrap();
            // 两次未知失败后成功，仍只按合成责任计数，不按尝试数重复累加。
            for _ in 0..2 {
                let claim = repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().unwrap();
                repo.begin_provider(&p.tenant_id, &claim).await.unwrap();
                repo.fail_speech(&p.tenant_id, &claim, None).await.unwrap();
                sqlx::query("UPDATE background_jobs SET available_at_ms=available_at_ms-$3 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&claim.job_id).bind(memoswish_core::maintenance::CADENCE_MS).execute(repo.pool()).await.unwrap();
                assert_provider_pending(repo, start).await;
            }
            let claim = repo.claim_speech(&p.tenant_id, &r.synthesis_id, 30_000).await.unwrap().unwrap();
            repo.begin_provider(&p.tenant_id, &claim).await.unwrap();
            repo.materialize_speech(&p.tenant_id, &claim, b"abc", &crate::asset_conformance::spec(),
                &SpeechMetadata { alignment_quality: None, audio_kind: None, provenance: None, extension: "wav".into(), duration_ms: 100, words: vec![] }, false).await.unwrap();
            assert_provider_pending(repo, start).await;
            let (upload, bytes) = repo.speech_upload(&p.tenant_id, &r.synthesis_id).await.unwrap().unwrap();
            assert_eq!(bytes, b"abc");
            let claim = repo.claim_speech(&p.tenant_id, &upload, 30_000).await.unwrap().unwrap();
            let attempt = repo.begin_upload(&p.tenant_id, &claim, "disk").await.unwrap();
            repo.record_upload(&p.tenant_id, &attempt, &ObjectVersion::Unversioned).await.unwrap();
            repo.publish_speech(&p.tenant_id, &claim, &attempt.id).await.unwrap();
            assert_eq!(repo.speech_request(&p.tenant_id, &r.id).await.unwrap().outcome, "published");
            let (state, period): (String, String) = sqlx::query_as("SELECT state,period FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2")
                .bind(&p.tenant_id).bind(&r.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(state, "committed");
            assert_eq!(repo.held_speech_usage(&p.tenant_id, &period).await.unwrap(), (0, 0));
            assert_eq!(repo.get_usage(&p.tenant_id, "tts_chars", &period).await.unwrap(), 3);
            let succeeded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE tenant_id=$1 AND state='succeeded'")
                .bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(succeeded, 2);
            let attempts: Vec<String> = sqlx::query_scalar("SELECT outcome FROM tts_provider_attempts WHERE tenant_id=$1 ORDER BY outcome")
                .bind(&p.tenant_id).fetch_all(repo.pool()).await.unwrap();
            assert_eq!(attempts, ["returned", "uncertain", "uncertain"]);
            assert_provider_pending(repo, start).await;
            assert!(!repo.operational_snapshot().await.unwrap().pending.iter().any(|r| r.kind == WorkKind::Orphan || r.kind == WorkKind::Asset));
            (p, start)
        }
        async fn assert_provider_pending(repo: &$repo, start: i64) {
            let snapshot = repo.operational_snapshot().await.unwrap();
            let row = snapshot.pending.iter().find(|r| r.kind == WorkKind::Speech).unwrap();
            assert_eq!((row.count, row.unknown, row.future, row.oldest_ms), (1, 0, 0, Some(start)));
            assert!(snapshot.observed_at_ms >= start);
        }
        async fn provider_erasure(repo: &$repo, p: &memoswish_core::Principal, start: i64) {
            use memoswish_core::{erasure::ErasureRepo, identity::IdentityRepo};
            let job = repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
            // 墓碑扫描与原擦除任务共享责任，尚未登记扫描映射也不能重复计数。
            let snapshot=repo.operational_snapshot().await.unwrap();
            assert_eq!(snapshot.pending.iter().find(|r|r.kind==WorkKind::Erasure).unwrap().count,1);
            let claim = repo.claim_erasure(&job.id, "provider-test", 30_000).await.unwrap().unwrap();
            for object in repo.erasure_objects(&claim, ("", ""), 100).await.unwrap() {
                repo.begin_erasure_object(&claim, &object, "disk").await.unwrap();
                repo.record_erasure_object(&object).await.unwrap();
            }
            assert!(repo.erasure_assets_ready(&claim).await.unwrap());
            repo.acknowledge_erasure_assets(&claim).await.unwrap();
            assert!(matches!(repo.complete_erasure(&claim).await, Err(memoswish_core::CoreError::Conflict(message)) if message == "erasure external evidence remains unresolved"));
            assert_provider_pending(repo, start).await;
            // 仅夹具模拟所有未决证据已解决；擦除已将原 job 标为 dead，保守积压仍保留。
            sqlx::query("UPDATE tts_provider_attempts SET outcome='returned' WHERE tenant_id=$1")
                .bind(&p.tenant_id).execute(repo.pool()).await.unwrap();
            assert_provider_pending(repo, start).await;
            repo.complete_erasure(&claim).await.unwrap();
            assert_eq!(repo.erasure_work(&job.id).await.unwrap().unwrap().progress, "complete");
            assert!(!repo.operational_snapshot().await.unwrap().pending.iter().any(|r|r.kind==WorkKind::Erasure));
        }

        async fn pressure(repo: $repo) {
            let recorder = Recording::default();
            let repo = repo.with_observer(Arc::new(recorder.clone()));
            let mut held = vec![];
            for _ in 0..repo.pool_snapshot().capacity {
                held.push(repo.pool().acquire().await.unwrap());
            }
            let pool = repo.pool_snapshot();
            assert_eq!((pool.idle, pool.size), (0, pool.capacity));
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), repo.operational_snapshot()).await.is_err()
            );
            assert!(recorder.0.lock().unwrap().contains(&(Operation::DbSample, Outcome::Cancelled)));
            drop(held);
            repo.pool().close().await;
            assert!(repo.operational_snapshot().await.is_err());
            assert!(recorder.0.lock().unwrap().contains(&(Operation::DbSample, Outcome::Closed)));
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    conformance!(SqliteRepository, sqlx::SqlitePool, "./migrations/sqlite");
    #[tokio::test]
    async fn sqlite_legacy_followup_ages_stay_unknown_until_receipts() {
        let path = std::env::temp_dir().join(format!("s26d-legacy-followup-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect(&url).await.unwrap();
        legacy_followup_upgrade(&pool).await;
        pool.close().await;
        let repo = SqliteRepository::open_runtime(&url).await.unwrap();
        legacy_followup_finish(&repo).await;
        repo.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn sqlite_recovery_registry_and_followups_survive_restart() {
        let path = std::env::temp_dir().join(format!("s26d-recovery-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let repo = SqliteRepository::connect(&url).await.unwrap();
        authority_coverage(&repo).await;
        integrated_scheduling(&repo).await;
        let imports = followups_prepare(&repo).await;
        let attachments = attachments_prepare(&repo).await;
        repo.pool().close().await;
        let reopened = SqliteRepository::open_runtime(&url).await.unwrap();
        followups_finish(&reopened, imports).await;
        attachments_finish(&reopened, attachments).await;
        reopened.pool().close().await;
        let terminal = SqliteRepository::open_runtime(&url).await.unwrap();
        assert!(terminal.operational_snapshot().await.unwrap().pending.is_empty());
        terminal.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn sqlite_provider_retry_responsibility_survives_success_and_restart() {
        let path = std::env::temp_dir().join(format!("s26d-provider-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let repo = SqliteRepository::connect(&url).await.unwrap();
        let (owner, start) = provider_retry(&repo).await;
        repo.pool().close().await;
        let reopened = SqliteRepository::open_runtime(&url).await.unwrap();
        assert_provider_pending(&reopened, start).await;
        provider_erasure(&reopened, &owner, start).await;
        reopened.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn sqlite_responsibility_upgrade_restart_and_pressure() {
        let path = std::env::temp_dir().join(format!("s26d-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect(&url).await.unwrap();
        upgrade(&pool).await;
        pool.close().await;
        let repo = SqliteRepository::open_runtime(&url).await.unwrap();
        responsibility(&repo).await;
        cleanup_cycles(&repo).await;
        repo.pool().close().await;
        let reopened = SqliteRepository::open_runtime(&url).await.unwrap();
        let snapshot = reopened.operational_snapshot().await.unwrap();
        assert_eq!(snapshot.pending.iter().find(|r| r.kind == WorkKind::Erasure).unwrap().unknown, 1);
        assert_eq!(snapshot.pending.iter().find(|r| r.kind == WorkKind::Speech).unwrap().unknown, 1);
        pressure(reopened).await;
        std::fs::remove_file(path).unwrap();
    }
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::postgres::PostgresRepository;
    conformance!(PostgresRepository, sqlx::PgPool, "./migrations/postgres");
    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn postgres_legacy_followup_ages_stay_unknown_until_receipts() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let pool =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            legacy_followup_upgrade(&pool).await;
            pool.close().await;
            let repo = fixture.repository(2).await.unwrap();
            legacy_followup_finish(&repo).await;
            repo.pool().close().await;
            fixture.cleanup().await;
        });
    }
    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn postgres_recovery_registry_and_followups_survive_restart() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let repo = fixture.repository(2).await.unwrap();
            authority_coverage(&repo).await;
            integrated_scheduling(&repo).await;
            let imports = followups_prepare(&repo).await;
            let attachments = attachments_prepare(&repo).await;
            repo.pool().close().await;
            let reopened = fixture.repository(2).await.unwrap();
            followups_finish(&reopened, imports).await;
            attachments_finish(&reopened, attachments).await;
            reopened.pool().close().await;
            let terminal = fixture.repository(2).await.unwrap();
            assert!(terminal.operational_snapshot().await.unwrap().pending.is_empty());
            terminal.pool().close().await;
            fixture.cleanup().await;
        });
    }
    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn postgres_provider_retry_responsibility_survives_success_and_restart() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let repo = fixture.repository(2).await.unwrap();
            let (owner, start) = provider_retry(&repo).await;
            repo.pool().close().await;
            let reopened = fixture.repository(2).await.unwrap();
            assert_provider_pending(&reopened, start).await;
            provider_erasure(&reopened, &owner, start).await;
            reopened.pool().close().await;
            fixture.cleanup().await;
        });
    }
    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn postgres_responsibility_upgrade_restart_and_pressure() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let pool =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            upgrade(&pool).await;
            pool.close().await;
            let repo = fixture.repository(2).await.unwrap();
            responsibility(&repo).await;
            cleanup_cycles(&repo).await;
            repo.pool().close().await;
            let reopened = fixture.repository(2).await.unwrap();
            assert_eq!(
                reopened
                    .operational_snapshot()
                    .await
                    .unwrap()
                    .pending
                    .iter()
                    .find(|r| r.kind == WorkKind::Speech)
                    .unwrap()
                    .unknown,
                1
            );
            assert_eq!(
                reopened
                    .operational_snapshot()
                    .await
                    .unwrap()
                    .pending
                    .iter()
                    .find(|r| r.kind == WorkKind::Erasure)
                    .unwrap()
                    .unknown,
                1
            );
            pressure(reopened).await;
            let recorder = Recording::default();
            let target = fixture.repository(1).await.unwrap().with_observer(Arc::new(recorder.clone()));
            sqlx::query("SET lock_timeout='20ms'").execute(target.pool()).await.unwrap();
            let peer = fixture.repository(1).await.unwrap();
            let owner = crate::asset_conformance::seed(&target).await;
            let locked = peer.asset_tx().await.unwrap();
            use memoswish_core::erasure::ErasureRepo;
            assert!(
                target
                    .register_managed_put(&owner.tenant_id, "disk", &format!("tenants/{}/pending", owner.tenant_id))
                    .await
                    .is_err()
            );
            assert!(recorder.0.lock().unwrap().contains(&(Operation::DbWrite, Outcome::Busy)));
            locked.rollback().await.unwrap();
            // 只终止本夹具已确认正等待锁的后端，证明真实断连也改变观察结果。
            let control = fixture.repository(1).await.unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(target.pool()).await.unwrap();
            let mut locked = peer.pool().begin().await.unwrap();
            sqlx::query("LOCK TABLE background_jobs IN ACCESS EXCLUSIVE MODE").execute(&mut *locked).await.unwrap();
            let reader = target.clone();
            let disconnected = tokio::spawn(async move { reader.operational_snapshot().await });
            tokio::time::timeout(std::time::Duration::from_secs(2),async {
                loop {
                    let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND usename=current_user AND wait_event_type='Lock')").bind(pid).bind(&fixture.schema).fetch_one(control.pool()).await.unwrap();
                    if waiting {break;}
                    tokio::task::yield_now().await;
                }
            }).await.expect("owned snapshot backend must reach the lock");
            let killed:bool=sqlx::query_scalar("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND usename=current_user AND datname=current_database()").bind(pid).bind(&fixture.schema).fetch_one(control.pool()).await.unwrap();
            assert!(killed);
            assert!(disconnected.await.unwrap().is_err());
            assert!(recorder.0.lock().unwrap().contains(&(Operation::DbSample, Outcome::Error)));
            locked.rollback().await.unwrap();
            control.pool().close().await;
            target.pool().close().await;
            peer.pool().close().await;
            fixture.cleanup().await;
        });
    }
}
