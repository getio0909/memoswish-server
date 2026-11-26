//! 双库的正文/证据分离、恢复抑制及错误回滚验收。

use crate::restore_suppression::{Suppression, SuppressionBatch, SuppressionEntry};
use memoswish_core::content_lifecycle_repo::ContentLifecycleRepo;
use memoswish_core::{ids::new_id, repo::*, tts::*};

fn batch(actions: Vec<Suppression>) -> SuppressionBatch {
    SuppressionBatch {
        version: 1,
        snapshot_sha256: "a".repeat(64),
        after_sequence: 20,
        through_sequence: 20 + actions.len() as u64,
        entries: actions
            .into_iter()
            .enumerate()
            .map(|(i, action)| SuppressionEntry { sequence: 21 + i as u64, action })
            .collect(),
    }
}

#[test]
fn suppression_input_requires_external_binding_and_complete_order() {
    let mut b = batch(vec![Suppression::DeleteWorkspace { tenant_id: "tenant".into() }]);
    assert!(b.validate(&"a".repeat(64), 20, 21).is_ok());
    assert!(b.validate(&"b".repeat(64), 20, 21).is_err());
    assert!(b.validate(&"a".repeat(64), 19, 21).is_err());
    assert!(b.validate(&"a".repeat(64), 20, 22).is_err());
    b.entries[0].sequence = 22;
    assert!(b.validate(&"a".repeat(64), 20, 21).is_err());
    // 缺少撤回范围/版本的记录与任意 SQL 仍须拒绝。
    for action in [r#"{"kind":"withdraw_purpose","user_id":"u"}"#, r#"{"kind":"sql","sql":"DELETE FROM users"}"#] {
        assert!(serde_json::from_str::<Suppression>(action).is_err());
    }
    assert!(
        serde_json::from_str::<Suppression>(r#"{"kind":"close_account","user_id":"u","secret":"PRIVATE_SENTINEL"}"#)
            .is_err()
    );
}

#[test]
fn suppression_rejects_ambiguous_canonical_identity() {
    let ambiguous = batch(vec![Suppression::UnlinkIdentity {
        user_id: "u".into(),
        issuer: "issuer\0subject".into(),
        subject: "another".into(),
    }]);
    assert!(ambiguous.validate(&"a".repeat(64), 20, 21).is_err());
}

macro_rules! suite {
    ($repo:ty) => {
        async fn restored_privacy(repo: &$repo) -> (memoswish_core::Principal, memoswish_protocol::PrivacyPolicy, memoswish_protocol::PrivacyState) {
            use memoswish_core::lifecycle::LifecycleRepo;
            use memoswish_core::privacy::*;
            use memoswish_protocol::PrivacyUpdate;
            let p = memoswish_core::Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
            let other = memoswish_core::Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
            let mut policy = memoswish_protocol::examples::sample_privacy_policy();
            policy.purpose_versions.insert("external_tts".into(), "speech-v1".into());
            repo.privacy_install_policy(&policy).await.unwrap();
            for owner in [&p, &other] {
                for (kind, version, value) in [("notice", "notice-v1", ""), ("terms", "terms-v1", ""), ("age", "notice-v1", "example-region"), ("external_tts", "speech-v1", "")] {
                    let state = repo.privacy_state(&owner.tenant_id, owner).await.unwrap();
                    repo.privacy_update(&owner.tenant_id, owner, &policy, &PrivacyUpdate {
                        expected_revision: state.revision, kind: kind.into(), version: version.into(), decision: true, value: value.into(),
                    }).await.unwrap();
                }
            }
            let before = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
            let foreign = repo.privacy_state(&other.tenant_id, &other).await.unwrap();
            let work = SpeechWork { provenance: None,
                engine: "restore-test".into(), namespace: new_id(),
                request: TtsRequest { text: "PRIVATE_PAYLOAD".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
                amount: 3, legacy_output: None,
                privacy: Some(PrivacyFence { principal: p.clone(), credential_hash: None, policy: policy.clone(), revision: before.revision }),
            };
            let request = repo.accept_speech(&p, &work, None, Some(100)).await.unwrap();
            let claim = repo.claim_speech(&p.tenant_id, &request.synthesis_id, 30_000).await.unwrap().unwrap();
            repo.begin_provider(&p.tenant_id, &claim).await.unwrap();
            let spec = memoswish_core::assets::AssetSpec { mime: "audio/mpeg".into(), size: 3, sha256: memoswish_core::ids::sha256_hex(b"abc") };
            let metadata = SpeechMetadata { alignment_quality: None, audio_kind: None, provenance: None, extension: "mp3".into(), duration_ms: 100, words: vec![] };
            repo.materialize_speech(&p.tenant_id, &claim, b"abc", &spec, &metadata, false).await.unwrap();
            let withdrawal = || Suppression::WithdrawPurpose {
                tenant_id: p.tenant_id.clone(), user_id: p.user_id.clone(), purpose: "external_tts".into(),
                version: "speech-v1".into(), recorded_at: 100,
            };
            // 旧快照中仍为已授权和已暂存；后序错误必须连同修订与输出一起回滚。
            let invalid = batch(vec![withdrawal(), Suppression::LeaveWorkspace { tenant_id: other.tenant_id.clone(), user_id: other.user_id.clone() }]);
            assert!(repo.replay_suppressions(&invalid).await.is_err());
            assert_eq!(repo.privacy_state(&p.tenant_id, &p).await.unwrap(), before);
            let audio: Option<Vec<u8>> = sqlx::query_scalar("SELECT audio FROM tts_syntheses WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(audio.as_deref(), Some(b"abc".as_slice()));
            let future = batch(vec![Suppression::WithdrawPurpose { tenant_id: p.tenant_id.clone(), user_id: p.user_id.clone(), purpose: "external_tts".into(), version: "speech-v1".into(), recorded_at: 253_402_300_799 }]);
            assert!(repo.replay_suppressions(&future).await.is_err());
            assert_eq!(repo.privacy_state(&p.tenant_id, &p).await.unwrap(), before);
            let b = batch(vec![withdrawal()]);
            repo.replay_suppressions(&b).await.unwrap();
            let withdrawn = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
            assert_eq!(withdrawn.revision, before.revision + 1);
            assert_eq!(withdrawn.account_records, before.account_records);
            let record = withdrawn.purpose_records.iter().find(|r| r.kind == "external_tts").unwrap();
            assert!(!record.decision);
            assert_eq!((record.version.as_str(), record.recorded_at, record.evidence.as_str()), ("speech-v1", 100, "restore_suppression"));
            repo.replay_suppressions(&b).await.unwrap();
            assert_eq!(repo.privacy_state(&p.tenant_id, &p).await.unwrap(), withdrawn);
            assert_eq!(repo.privacy_state(&other.tenant_id, &other).await.unwrap(), foreign);
            assert!(repo.privacy_admit(&p.tenant_id, &p, &policy, Some("external_tts"), None).await.is_err());
            let audio: Option<Vec<u8>> = sqlx::query_scalar("SELECT audio FROM tts_syntheses WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert!(audio.is_none());
            assert!(repo.speech_upload(&p.tenant_id, &request.synthesis_id).await.unwrap().is_none());
            let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tts_provider_attempts WHERE tenant_id=$1 AND synthesis_id=$2")
                .bind(&p.tenant_id).bind(&request.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(attempts, 1);
            // 最短正文策略不能清掉当前同意、撤回、修订或未决费用证据。
            let retention = crate::retention::RetentionPolicy { version: 1, api_metadata_after_expiry_seconds: 0, failed_tts_payload_after_schedule_seconds: 0 };
            repo.retention_sweep(&p.tenant_id, &retention, 100, true).await.unwrap();
            assert_eq!(repo.privacy_state(&p.tenant_id, &p).await.unwrap(), withdrawn);
            assert_eq!(repo.privacy_state(&other.tenant_id, &other).await.unwrap(), foreign);
            let export = repo.export_personal(&memoswish_core::lifecycle::AccountAuthority::Workspace(p.clone())).await.unwrap();
            assert!(serde_json::to_string(&export.privacy_records).unwrap().contains("restore_suppression"));
            // 恢复后显式重新授权仍不能放行旧工作与旧准入修订。
            repo.privacy_update(&p.tenant_id, &p, &policy, &PrivacyUpdate { expected_revision: withdrawn.revision, kind: "external_tts".into(), version: "speech-v1".into(), decision: true, value: String::new() }).await.unwrap();
            assert!(repo.begin_provider(&p.tenant_id, &claim).await.is_err());
            assert!(repo.privacy_admit(&p.tenant_id, &p, &policy, Some("external_tts"), Some(before.revision)).await.is_err());
            // 重放支持旧政策版本，即使当前部署已更换或记录原本缺失。
            policy.purpose_versions.insert("external_tts".into(), "speech-v2".into());
            repo.privacy_install_policy(&policy).await.unwrap();
            repo.replay_suppressions(&b).await.unwrap();
            let withdrawn = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
            let missing = batch(vec![Suppression::WithdrawPurpose { tenant_id: new_id(), user_id: new_id(), purpose: "research".into(), version: "old-v1".into(), recorded_at: 100 }]);
            repo.replay_suppressions(&missing).await.unwrap();
            (p, policy, withdrawn)
        }

        async fn assert_restored_privacy(repo: &$repo, p: &memoswish_core::Principal, policy: &memoswish_protocol::PrivacyPolicy, state: &memoswish_protocol::PrivacyState) {
            use memoswish_core::privacy::PrivacyRepo;
            assert_eq!(repo.privacy_state(&p.tenant_id, p).await.unwrap(), *state);
            assert!(repo.privacy_admit(&p.tenant_id, p, policy, Some("external_tts"), None).await.is_err());
            // 生命周期删除仍负责清除当前证据，恢复撤回不能重建已擦除的范围。
            repo.membership_remove(&p.tenant_id, &p.user_id).await.unwrap();
            let b = batch(vec![Suppression::WithdrawPurpose { tenant_id: p.tenant_id.clone(), user_id: p.user_id.clone(), purpose: "external_tts".into(), version: "speech-v1".into(), recorded_at: 100 }]);
            repo.replay_suppressions(&b).await.unwrap();
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM privacy_purposes WHERE tenant_id=$1 AND user_id=$2").bind(&p.tenant_id).bind(&p.user_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count, 0);
        }

        async fn retention_categories(repo: &$repo) {
            let p = crate::asset_conformance::seed(repo).await;
            let other = crate::asset_conformance::seed(repo).await;
            let policy = crate::retention::RetentionPolicy {
                version: 1, api_metadata_after_expiry_seconds: 0, failed_tts_payload_after_schedule_seconds: 60,
            };
            let old = chrono::DateTime::from_timestamp(100, 0).unwrap();
            let future = chrono::Utc::now() + chrono::Duration::days(1);
            for (id, owner, expiry) in [("old", &p, Some(old)), ("old2", &p, Some(old)), ("old3", &p, Some(old)), ("live", &p, Some(future)), ("forever", &p, None), ("foreign", &other, Some(old))] {
                repo.issue_api_token(&ApiTokenRecord {
                    id: id.into(), tenant_id: owner.tenant_id.clone(), user_id: owner.user_id.clone(),
                    name: "Synthetic".into(), token_hash: new_id(), scopes: vec!["*".into()], created_at: old,
                    generations: memoswish_core::CredentialGenerations { account: 0, membership: 0 },
                    expires_at: expiry, last_used_at: None, revoked: false,
                }).await.unwrap();
            }
            let w = SpeechWork { provenance: None,
                engine: "test".into(), namespace: "retention".into(),
                request: TtsRequest { text: "PRIVATE_PAYLOAD".into(), language: "en".into(), voice: "default".into(), speed: 1.0 },
                amount: 3, legacy_output: None, privacy: None,
            };
            let failed = repo.accept_speech(&p, &w, None, Some(100)).await.unwrap();
            sqlx::query("UPDATE background_jobs SET state='dead',available_at_ms=0 WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&failed.synthesis_id).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE tts_requesters SET outcome='failed' WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&failed.id).execute(repo.pool()).await.unwrap();
            // 未决预留阻止正文回收，预览也不能产生写入。
            let preview = repo.retention_sweep(&p.tenant_id, &policy, 1, false).await.unwrap();
            assert_eq!((preview.expired_api_metadata, preview.failed_tts_payloads), (1, 0));
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE id='old'").fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count, 1);
            sqlx::query("UPDATE quota_operations SET state='released' WHERE tenant_id=$1 AND operation_id=$2")
                .bind(&p.tenant_id).bind(&failed.synthesis_id).execute(repo.pool()).await.unwrap();
            sqlx::query("INSERT INTO tts_provider_attempts(tenant_id,synthesis_id,claim_token,outcome) VALUES($1,$2,'attempt','uncertain')")
                .bind(&p.tenant_id).bind(&failed.synthesis_id).execute(repo.pool()).await.unwrap();
            assert_eq!(repo.retention_sweep(&p.tenant_id, &policy, 1, false).await.unwrap().failed_tts_payloads, 0);
            sqlx::query("UPDATE tts_provider_attempts SET outcome='returned' WHERE tenant_id=$1 AND synthesis_id=$2")
                .bind(&p.tenant_id).bind(&failed.synthesis_id).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE tts_requesters SET outcome='pending' WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&failed.id).execute(repo.pool()).await.unwrap();
            assert_eq!(repo.retention_sweep(&p.tenant_id,&policy,1,false).await.unwrap().failed_tts_payloads,0);
            sqlx::query("UPDATE tts_requesters SET outcome='failed' WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&failed.id).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE background_jobs SET available_at_ms=$3 WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&failed.synthesis_id).bind(future.timestamp_millis()).execute(repo.pool()).await.unwrap();
            assert_eq!(repo.retention_sweep(&p.tenant_id,&policy,1,false).await.unwrap().failed_tts_payloads,0);
            sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&failed.synthesis_id).execute(repo.pool()).await.unwrap();
            let cleaned = repo.retention_sweep(&p.tenant_id, &policy, 1, true).await.unwrap();
            assert_eq!((cleaned.expired_api_metadata, cleaned.failed_tts_payloads), (1, 1));
            let payload: String = sqlx::query_scalar("SELECT work FROM tts_syntheses WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&failed.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(payload, "{}");
            let evidence: (String, String, String) = sqlx::query_as("SELECT j.state,q.state,a.outcome FROM background_jobs j JOIN quota_operations q ON q.tenant_id=j.tenant_id AND q.operation_id=j.id JOIN tts_provider_attempts a ON a.tenant_id=j.tenant_id AND a.synthesis_id=j.id WHERE j.tenant_id=$1 AND j.id=$2")
                .bind(&p.tenant_id).bind(&failed.synthesis_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(evidence, ("dead".into(), "released".into(), "returned".into()));
            let replay = repo.accept_speech(&p, &w, None, Some(100)).await.unwrap();
            assert_eq!(replay.synthesis_id, failed.synthesis_id);
            assert_eq!(replay.outcome, "failed");
            assert!(repo.claim_speech(&p.tenant_id, &failed.synthesis_id, 30_000).await.unwrap().is_none());
            for _ in 0..2 {
                let page = repo.retention_sweep(&p.tenant_id,&policy,1,true).await.unwrap();
                assert_eq!((page.expired_api_metadata,page.failed_tts_payloads),(1,0));
            }
            let again = repo.retention_sweep(&p.tenant_id, &policy, 1, true).await.unwrap();
            assert_eq!((again.expired_api_metadata, again.failed_tts_payloads), (0, 0));
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens").fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count, 3);
            assert!(repo.retention_sweep(&p.tenant_id, &policy, 0, true).await.is_err());
            let mut invalid = policy.clone(); invalid.api_metadata_after_expiry_seconds = -1;
            assert!(repo.retention_sweep(&p.tenant_id, &invalid, 10, true).await.is_err());
        }

        async fn restore_scope_and_recovery(repo: &$repo) {
            use memoswish_core::{assets::ObjectVersion, erasure::ErasureRepo, identity::IdentityRepo, lifecycle::*};
            let p = crate::lifecycle_conformance::workspace(repo).await;
            let member = crate::lifecycle_conformance::member(repo, &p.tenant_id, memoswish_core::Role::Learner).await;
            let other = crate::lifecycle_conformance::workspace(repo).await;
            let card = memoswish_protocol::examples::sample_card();
            repo.insert_deck(&p.tenant_id, &memoswish_protocol::examples::sample_deck()).await.unwrap();
            repo.insert_card(&p.tenant_id, &card).await.unwrap();
            repo.insert_deck(&other.tenant_id, &memoswish_protocol::examples::sample_deck()).await.unwrap();
            repo.insert_card(&other.tenant_id, &card).await.unwrap();
            let (mut feedback, mut memory) = crate::learning_conformance::seed(repo).await;
            feedback.tenant_id = other.tenant_id.clone(); feedback.user_id = other.user_id.clone();
            memory.tenant_id = other.tenant_id.clone(); memory.user_id = other.user_id.clone();
            assert_eq!(repo.try_apply_learning_event(&feedback,None,&memory).await.unwrap(),LearningEventOutcome::Applied);
            let object = repo.register_managed_put(&p.tenant_id, "restore-store", &format!("tenants/{}/object",p.tenant_id)).await.unwrap();
            repo.record_managed_put(&object, &ObjectVersion::VersionId("null".into())).await.unwrap();
            // 旧快照对象存在时重放删除；新 S19 责任仍须精确版本回执才能完成。
            let b = batch(vec![Suppression::DeleteWorkspace { tenant_id: p.tenant_id.clone() }]);
            let (first, concurrent) = tokio::join!(repo.replay_suppressions(&b),repo.replay_suppressions(&b));
            first.unwrap(); concurrent.unwrap();
            assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_none());
            assert!(repo.account_by_id(&p.user_id).await.unwrap().is_some());
            assert!(repo.account_by_id(&member.user_id).await.unwrap().is_some());
            assert!(repo.get_card(&other.tenant_id, &card.id).await.unwrap().is_some());
            let jobs = repo.account_erasure_jobs().await.unwrap();
            let jobs: Vec<_> = jobs.iter().filter(|j|j.tenant_id.as_deref()==Some(&p.tenant_id)).collect();
            assert_eq!(jobs.len(), 1);
            let claim = repo.claim_erasure(&jobs[0].id, "restorer", 30_000).await.unwrap().unwrap();
            assert!(repo.complete_erasure(&claim).await.is_err());
            let objects = repo.erasure_objects(&claim, ("",""),100).await.unwrap();
            assert_eq!(objects[0].version, ObjectVersion::VersionId("null".into()));
            repo.begin_erasure_object(&claim, &objects[0], "restore-store").await.unwrap();
            repo.record_erasure_object(&objects[0]).await.unwrap();
            repo.acknowledge_erasure_assets(&claim).await.unwrap();
            repo.complete_erasure(&claim).await.unwrap();
            assert!(repo.register_managed_put(&p.tenant_id,"restore-store", &object.key).await.is_err());
            // 非 owner 成员离开只清个人数据；同工作区内容与其他成员保留。
            let departing = crate::lifecycle_conformance::member(repo, &other.tenant_id, memoswish_core::Role::Learner).await;
            let b = batch(vec![Suppression::LeaveWorkspace { tenant_id: other.tenant_id.clone(), user_id: departing.user_id.clone() }]);
            repo.replay_suppressions(&b).await.unwrap();
            repo.replay_suppressions(&b).await.unwrap();
            assert!(repo.memberships(&departing.user_id).await.unwrap().is_empty());
            assert!(repo.get_card(&other.tenant_id, &card.id).await.unwrap().is_some());
            let b = batch(vec![Suppression::CloseAccount { user_id: departing.user_id.clone(), identities: vec![] }]);
            repo.replay_suppressions(&b).await.unwrap();
            repo.replay_suppressions(&b).await.unwrap();
            assert!(repo.account_by_id(&departing.user_id).await.unwrap().is_none());
            // 已返回成功的前序动作也须在后序错误时整体回滚。
            let b = batch(vec![
                Suppression::DeleteCard { tenant_id: other.tenant_id.clone(), card_id: card.id.clone() },
                Suppression::LeaveWorkspace { tenant_id: other.tenant_id.clone(), user_id: other.user_id.clone() },
            ]);
            assert!(repo.replay_suppressions(&b).await.is_err());
            assert!(repo.get_card(&other.tenant_id, &card.id).await.unwrap().is_some());
            let b = batch(vec![Suppression::DeleteCard { tenant_id: other.tenant_id.clone(), card_id: card.id.clone() }]);
            repo.replay_suppressions(&b).await.unwrap();
            assert!(repo.insert_card(&other.tenant_id, &card).await.is_err());
            assert!(repo.get_memory(&other.tenant_id,&other.user_id,&card.id).await.unwrap().is_some());
            let personal = repo.export_personal(&AccountAuthority::Workspace(other.clone())).await.unwrap();
            let personal = personal.workspaces.iter().find(|w|w.tenant_id==other.tenant_id).unwrap();
            assert_eq!(personal.data["feedback_events"].len(),1);
            assert_eq!(repo.try_apply_learning_event(&feedback,None,&memory).await.unwrap(),LearningEventOutcome::Duplicate);
        }

        async fn restored_imports(repo: &$repo) {
            use memoswish_core::{assets::*, erasure::ErasureRepo, identity::IdentityRepo, imports::*, lifecycle::*};
            for scope in ["workspace", "member", "account"] {
                let (authority, _) = crate::import_conformance::authority(repo).await;
                let p = authority.principal();
                let survivor = crate::lifecycle_conformance::member(repo, &p.tenant_id, memoswish_core::Role::Owner).await;
                let (foreign, _) = crate::import_conformance::authority(repo).await;
                let foreign_work = crate::import_conformance::owned_work(&foreign.principal(), 1);
                let foreign_op = repo.accept_import(&foreign, "preserved", &"b".repeat(64), &foreign_work, None, 2).await.unwrap();
                let mut committed_work = crate::import_conformance::owned_work(&p, 0);
                committed_work.auto_tts = true;
                let committed = repo.accept_import(&authority, "receipt", &"c".repeat(64), &committed_work, None, 2).await.unwrap();
                let claim = repo.claim_import(&p.tenant_id, &committed.id, 30_000).await.unwrap().unwrap();
                assert!(repo.commit_import(&p.tenant_id, &claim).await.unwrap().result.is_some());
                let card = &committed_work.cards[0];
                let reporter = memoswish_core::Principal {
                    session_access_hash: Some(format!("api:{}", authority.token_hash.as_ref().unwrap())),
                    ..p.clone()
                };
                for reporter in [&reporter, &survivor] {
                    repo.create_content_report(&p.tenant_id, reporter, &card.id, &memoswish_protocol::ReportCreate {
                        observed_revision: card.revision, text: "Retained correction report".into(), sources: vec![],
                    }).await.unwrap();
                }
                let staged = crate::import_conformance::owned_work(&p, 2);
                let pending = repo.accept_import(&authority, "staging", &"d".repeat(64), &staged, None, 2).await.unwrap();
                let stale = repo.claim_import(&p.tenant_id, &pending.id, 30_000).await.unwrap().unwrap();
                let known = repo.begin_import_upload(&p.tenant_id, &stale, 0, "restore-import-store").await.unwrap();
                repo.record_upload(&p.tenant_id, &known, &ObjectVersion::VersionId("restore-version".into())).await.unwrap();
                let unknown = repo.begin_import_upload(&p.tenant_id, &stale, 1, "restore-import-store").await.unwrap();
                let period = chrono::Utc::now().format("%Y-%m").to_string();
                let exported = repo.export_workspace(&survivor).await.unwrap();
                assert_eq!(exported.data["content_revisions"].len(), 2);
                assert_eq!(exported.data["content_reports"].len(), 2);
                assert_eq!(exported.data["content_imports"].len(), 2);
                assert_eq!(exported.data["import_followups"].len(), 2);
                for row in &exported.data["content_imports"] {
                    assert!(row.get("work").is_none());
                    assert!(row.get("authority").is_none());
                }
                // 分类维护不能删除导入正文或去重/回执，也不能结清未决责任。
                let policy = crate::retention::RetentionPolicy {
                    version: 1, api_metadata_after_expiry_seconds: 0, failed_tts_payload_after_schedule_seconds: 0,
                };
                repo.retention_sweep(&p.tenant_id, &policy, 100, true).await.unwrap();
                // 周期保留也必须经当前维护所有者执行，并保留内容历史及报告。
                use memoswish_core::maintenance::{MaintenanceRepo, TaskKind, TaskRegistration};
                let task = TaskRegistration {
                    kind: TaskKind::Retention, tenant: p.tenant_id.clone(), policy: Some(policy.clone()),
                };
                let task_id = repo.register_maintenance(&task).await.unwrap();
                sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE tenant_id='' AND id=$1 AND state='queued'")
                    .bind(&task_id).execute(repo.pool()).await.unwrap();
                let claim = repo.claim_maintenance(&task_id, "content-retention").await.unwrap().unwrap();
                assert!(repo.retention_sweep(&p.tenant_id, &policy, 100, true).await.is_err());
                repo.maintenance_sql_page(&claim).await.unwrap();
                assert!(repo.maintenance_sql_page(&claim).await.is_err());
                let cycle: i64 = sqlx::query_scalar("SELECT cycle FROM maintenance_tasks WHERE id=$1")
                    .bind(&task_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(cycle, 2);
                assert_eq!(repo.import_execution(&p.tenant_id, &stale).await.unwrap().work.media.len(), 2);
                assert!(repo.lookup_import(&authority, "receipt", &"c".repeat(64)).await.unwrap().unwrap().result.is_some());
                assert_eq!(repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), 2);
                let preserved = repo.export_workspace(&survivor).await.unwrap();
                assert_eq!(preserved.data["content_revisions"], exported.data["content_revisions"]);
                assert_eq!(preserved.data["content_reports"], exported.data["content_reports"]);
                let action = match scope {
                    "workspace" => Suppression::DeleteWorkspace { tenant_id: p.tenant_id.clone() },
                    "member" => Suppression::LeaveWorkspace { tenant_id: p.tenant_id.clone(), user_id: p.user_id.clone() },
                    _ => Suppression::CloseAccount { user_id: p.user_id.clone(), identities: vec![] },
                };
                let b = batch(vec![action]);
                repo.replay_suppressions(&b).await.unwrap();
                repo.replay_suppressions(&b).await.unwrap();
                for id in [&committed.id, &pending.id] {
                    let erased: (String, String, Option<String>, String) = sqlx::query_as(
                        "SELECT work,authority,result,outcome FROM content_imports WHERE tenant_id=$1 AND id=$2"
                    ).bind(&p.tenant_id).bind(id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(erased, ("{}".into(), "{}".into(), None, "failed".into()));
                }
                let revisions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_revisions WHERE tenant_id=$1")
                    .bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
                let reports: Vec<String> = sqlx::query_scalar("SELECT user_id FROM content_reports WHERE tenant_id=$1")
                    .bind(&p.tenant_id).fetch_all(repo.pool()).await.unwrap();
                if scope == "workspace" {
                    assert_eq!(revisions, 0);
                    assert!(reports.is_empty());
                } else {
                    assert_eq!(revisions, 2);
                    assert_eq!(reports, vec![survivor.user_id.clone()]);
                }
                let followups: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM import_followups WHERE tenant_id=$1")
                    .bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(followups, 0);
                assert!(repo.commit_import(&p.tenant_id, &stale).await.is_err());
                assert!(repo.claim_import(&p.tenant_id, &pending.id, 30_000).await.unwrap().is_none());
                assert!(repo.import_followups(&p.tenant_id, &committed.id).await.unwrap().is_empty());
                assert_eq!(repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), 0);
                let ledger: Vec<(String, i64)> = sqlx::query_as(
                    "SELECT state,amount FROM quota_operations WHERE tenant_id=$1 ORDER BY state"
                ).bind(&p.tenant_id).fetch_all(repo.pool()).await.unwrap();
                assert_eq!(ledger, vec![("committed".into(), 2), ("released".into(), 2)]);
                let unresolved: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asset_upload_attempts WHERE tenant_id=$1 AND id=$2 AND outcome='uncertain' AND version_kind='unknown'")
                    .bind(&p.tenant_id).bind(&unknown.id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(unresolved, 1);
                let cleanup = repo.import_cleanup(&p.tenant_id, &pending.id, "restore-import-store").await.unwrap();
                assert_eq!(cleanup.len(), 1);
                assert_eq!(cleanup[0].id, known.id);
                assert_eq!(cleanup[0].version, ObjectVersion::VersionId("restore-version".into()));
                let source_keys: Vec<String> = sqlx::query_scalar("SELECT source_key FROM import_uploads WHERE tenant_id=$1")
                    .bind(&p.tenant_id).fetch_all(repo.pool()).await.unwrap();
                assert_eq!(source_keys, vec![String::new(), String::new()]);
                if scope == "workspace" {
                    let jobs = repo.account_erasure_jobs().await.unwrap();
                    let job = jobs.iter().find(|j|j.tenant_id.as_deref()==Some(&p.tenant_id)).unwrap();
                    let claim = repo.claim_erasure(&job.id, "restore-import", 30_000).await.unwrap().unwrap();
                    // 已知版本清理后，仅剩未知 PUT 也不能确认整个租户资产已清。
                    repo.record_asset_cleaned(&p.tenant_id, &cleanup[0]).await.unwrap();
                    assert!(matches!(repo.acknowledge_erasure_assets(&claim).await,
                        Err(memoswish_core::CoreError::Conflict(message)) if message == "managed writes remain unresolved"));
                    assert!(repo.complete_erasure(&claim).await.is_err());
                    assert!(repo.get_deck(&p.tenant_id, &committed_work.deck.id).await.unwrap().is_none());
                } else {
                    assert!(repo.get_deck(&p.tenant_id, &committed_work.deck.id).await.unwrap().is_some());
                    assert!(repo.memberships(&survivor.user_id).await.unwrap().iter().any(|m|m.tenant_id==p.tenant_id));
                }
                assert_eq!(repo.import_operation(&foreign.principal.tenant_id, &foreign_op.id).await.unwrap().outcome, "pending");
                let foreign_claim = repo.claim_import(&foreign.principal.tenant_id, &foreign_op.id, 30_000).await.unwrap().unwrap();
                assert_eq!(repo.import_execution(&foreign.principal.tenant_id, &foreign_claim).await.unwrap().work.media.len(), 1);
            }
        }

        async fn refresh_retention_and_restore(repo: &$repo) {
            use memoswish_core::{identity::IdentityRepo, session::*};
            let (family, cred) = crate::session_conformance::setup(repo).await;
            repo.session_issue(&family, &cred, None).await.unwrap();
            let next = repo.session_rotate(&cred.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.unwrap();
            repo.identity_cleanup(chrono::Utc::now().timestamp()).await.unwrap();
            let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_session_credentials WHERE refresh_hash=$1 AND consumed=1")
                .bind(&cred.refresh_hash).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(exists, 1, "short access expiry cannot erase a consumed parent before family expiry");
            assert!(repo.session_rotate(&cred.refresh_hash,&new_id(),&new_id(),&new_id(),600).await.is_err());
            assert!(repo.session_access(&next.credential.access_hash).await.is_err());
            sqlx::query("UPDATE app_sessions SET auth_time=1,expires_at=2 WHERE id=$1")
                .bind(&family.id).execute(repo.pool()).await.unwrap();
            repo.identity_cleanup(chrono::Utc::now().timestamp()).await.unwrap();
            assert!(repo.session_rotate(&cred.refresh_hash,&new_id(),&new_id(),&new_id(),600).await.is_err());
            let (family, cred) = crate::session_conformance::setup(repo).await;
            repo.session_issue(&family, &cred, None).await.unwrap();
            let (foreign, fc) = crate::session_conformance::setup(repo).await;
            repo.session_issue(&foreign, &fc, None).await.unwrap();
            let b = batch(vec![Suppression::RevokeSessions { user_id: family.user_id.clone(), through_auth_time: family.auth_time }]);
            repo.replay_suppressions(&b).await.unwrap();
            repo.replay_suppressions(&b).await.unwrap();
            assert!(repo.session_access(&cred.access_hash).await.is_err());
            assert!(repo.session_access(&fc.access_hash).await.is_ok());
            assert!(repo.legacy_session_authorize(&family.user_id,0,family.auth_time,None,None).await.is_err());
        }

        async fn revoke_close_replay(repo: &$repo) {
            use memoswish_core::{identity::IdentityRepo, session::*};
            let (family, cred) = crate::session_conformance::setup(repo).await;
            repo.session_issue(&family, &cred, None).await.unwrap();
            let tenant = cred.tenant_id.as_ref().unwrap();
            let (foreign, fc) = crate::session_conformance::setup(repo).await;
            repo.session_issue(&foreign, &fc, None).await.unwrap();
            let absent = new_id();
            let absent_action = || Suppression::RevokeSessions {
                user_id: absent.clone(), through_auth_time: family.auth_time,
            };
            // 注册前快照没有账户；撤销重放不能创建账户或违反 fence 外键。
            let missing = batch(vec![absent_action()]);
            repo.replay_suppressions(&missing).await.unwrap();
            repo.replay_suppressions(&missing).await.unwrap();
            assert!(repo.account_by_id(&absent).await.unwrap().is_none());
            let actions = || vec![
                Suppression::DeleteWorkspace { tenant_id: tenant.clone() },
                absent_action(),
                Suppression::RevokeSessions { user_id: family.user_id.clone(), through_auth_time: family.auth_time },
                Suppression::CloseAccount { user_id: family.user_id.clone(), identities: vec![] },
            ];
            let mut failing = actions();
            failing.push(Suppression::LeaveWorkspace {
                tenant_id: fc.tenant_id.clone().unwrap(), user_id: foreign.user_id.clone(),
            });
            let jobs_before = serde_json::to_value(repo.account_erasure_jobs().await.unwrap()).unwrap();
            let error = repo.replay_suppressions(&batch(failing)).await.unwrap_err();
            assert!(matches!(error, memoswish_core::CoreError::Conflict(message)
                if message == "restore requires prior workspace deletion or ownership reconciliation"));
            // 后序 owner 错误撤回销户、撤销和 S19 工作，保留原凭据与工作区。
            assert!(repo.get_tenant(tenant).await.unwrap().is_some());
            assert!(repo.account_by_id(&family.user_id).await.unwrap().is_some());
            assert!(repo.session_access(&cred.access_hash).await.is_ok());
            assert_eq!(serde_json::to_value(repo.account_erasure_jobs().await.unwrap()).unwrap(), jobs_before);
            let fences: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_session_fences WHERE user_id=$1 OR user_id=$2")
                .bind(&family.user_id).bind(&absent).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(fences, 0);
            // 模拟提交响应丢失，原批次必须完整重放，且不能重复创建清理责任。
            let committed = batch(actions());
            repo.replay_suppressions(&committed).await.unwrap();
            let jobs = repo.account_erasure_jobs().await.unwrap();
            assert_eq!(jobs.iter().filter(|job| job.tenant_id.as_deref() == Some(tenant)).count(), 1);
            repo.replay_suppressions(&committed).await.unwrap();
            assert_eq!(
                serde_json::to_value(repo.account_erasure_jobs().await.unwrap()).unwrap(),
                serde_json::to_value(jobs).unwrap(),
            );
            assert!(repo.get_tenant(tenant).await.unwrap().is_none());
            assert!(repo.account_by_id(&family.user_id).await.unwrap().is_none());
            assert!(repo.session_access(&cred.access_hash).await.is_err());
            assert!(repo.session_rotate(&cred.refresh_hash,&new_id(),&new_id(),&new_id(),600).await.is_err());
            assert!(repo.legacy_session_authorize(&family.user_id,0,family.auth_time,None,None).await.is_err());
            assert!(repo.session_access(&fc.access_hash).await.is_ok());
            assert!(repo.get_tenant(fc.tenant_id.as_ref().unwrap()).await.unwrap().is_some());
        }

        async fn restored_grants_and_unlink(repo: &$repo) {
            use memoswish_core::{identity::IdentityRepo, oauth::*, erasure::ErasureRepo};
            let p = crate::asset_conformance::seed(repo).await;
            let other = crate::asset_conformance::seed(repo).await;
            let id = new_id(); let hash = new_id();
            repo.issue_api_token(&ApiTokenRecord {
                id:id.clone(),tenant_id:p.tenant_id.clone(),user_id:p.user_id.clone(),name:"Synthetic".into(),
                token_hash:hash.clone(),generations:memoswish_core::CredentialGenerations{account:0,membership:0},
                scopes:vec!["*".into()],created_at:chrono::Utc::now(),expires_at:None,last_used_at:None,revoked:false,
            }).await.unwrap();
            let client = OAuthClient {
                id:new_id(),name:"Synthetic".into(),redirect_uris:vec!["https://client.example/callback".into()],
                grant_types:vec!["authorization_code".into(),"refresh_token".into()],scopes:vec!["content:read".into()],
                auth_method:"none".into(),secret_hash:None,created_at:10,expires_at:i64::MAX-1,
            };
            repo.oauth_register(&client).await.unwrap();
            let user = repo.get_user(&p.tenant_id,&p.user_id).await.unwrap().unwrap();
            let code = crate::oauth_conformance::code(repo,&user,&client,i64::MAX-1).await;
            let access = crate::oauth_conformance::token(&code,"access");
            let refresh = crate::oauth_conformance::token(&code,"refresh");
            assert!(repo.oauth_redeem(&p.tenant_id,&code,&[access.clone(),refresh.clone()],10).await.unwrap());
            let wrong = batch(vec![Suppression::RevokeApiToken {
                tenant_id:other.tenant_id.clone(),user_id:other.user_id.clone(),token_id:id.clone(),
            }]);
            assert!(repo.replay_suppressions(&wrong).await.is_err());
            assert!(!repo.find_api_token(&hash).await.unwrap().unwrap().revoked);
            let b = batch(vec![
                Suppression::RevokeApiToken {tenant_id:p.tenant_id.clone(),user_id:p.user_id.clone(),token_id:id},
                Suppression::RevokeOauthGrant {tenant_id:p.tenant_id.clone(),user_id:p.user_id.clone(),grant_id:code.grant.id.clone()},
            ]);
            repo.replay_suppressions(&b).await.unwrap(); repo.replay_suppressions(&b).await.unwrap();
            assert!(repo.find_api_token(&hash).await.unwrap().unwrap().revoked);
            assert!(repo.oauth_token(&access.hash).await.unwrap().is_none());
            assert!(!repo.oauth_rotate(&p.tenant_id,&refresh,&[crate::oauth_conformance::token(&code,"refresh")],10).await.unwrap());
            let (user, identity) = crate::identity_conformance::unlink_fixture(repo,true).await;
            let pending = crate::identity_conformance::claimed_attempt(repo,&identity,false).await;
            sqlx::query("UPDATE federated_identities SET credential='SYNTHETIC_CIPHERTEXT' WHERE issuer=$1 AND subject=$2")
                .bind(&identity.issuer).bind(&identity.subject).execute(repo.pool()).await.unwrap();
            let wrong = batch(vec![Suppression::UnlinkIdentity {user_id:p.user_id.clone(),issuer:identity.issuer.clone(),subject:identity.subject.clone()}]);
            assert!(repo.replay_suppressions(&wrong).await.is_err());
            let b = batch(vec![Suppression::UnlinkIdentity {user_id:user.id.clone(),issuer:identity.issuer.clone(),subject:identity.subject.clone()}]);
            repo.replay_suppressions(&b).await.unwrap(); repo.replay_suppressions(&b).await.unwrap();
            assert!(repo.identity_list(&user.tenant_id,&user.id).await.unwrap().is_empty());
            assert!(repo.identity_resolve(&identity,None,false,None,None,Some(&pending.id)).await.is_err());
            let jobs: Vec<_> = repo.account_erasure_jobs().await.unwrap().into_iter().filter(|j|j.tenant_id.as_deref()==Some(&user.tenant_id)).collect();
            assert_eq!(jobs.len(),1);
            let claim = repo.claim_erasure(&jobs[0].id,"restore-unlink",30_000).await.unwrap().unwrap();
            assert!(repo.complete_erasure(&claim).await.is_err());
            repo.acknowledge_revocation(&claim,0,"google","SYNTHETIC_CIPHERTEXT").await.unwrap();
            repo.complete_erasure(&claim).await.unwrap();
            assert!(repo.account_erasure_jobs().await.unwrap().iter().all(|j|j.credentials.is_empty()));
            // 备份早于注册：仅按不存在的 user_id 销户会遗漏已在途的登录回调。
            let tenant = TenantRecord {id:new_id(),name:"Not restored".into(),plan:"free".into(),created_at:chrono::Utc::now()};
            let mut future_user = user.clone(); future_user.id=new_id(); future_user.tenant_id=tenant.id.clone(); future_user.email=format!("{}@example.invalid",new_id());
            let mut future_identity = identity.clone(); future_identity.issuer=format!("https://{}.example",new_id());
            future_identity.user_id=future_user.id.clone(); future_identity.tenant_id=tenant.id.clone();
            let in_flight = crate::identity_conformance::claimed_attempt(repo,&future_identity,false).await;
            let b = batch(vec![Suppression::CloseAccount {
                user_id:future_user.id.clone(),identities:vec![crate::restore_suppression::SuppressedIdentity {
                    issuer:future_identity.issuer.clone(),subject:future_identity.subject.clone(),
                }],
            }]);
            repo.replay_suppressions(&b).await.unwrap();
            assert!(repo.identity_resolve(&future_identity,Some((&tenant,&future_user)),false,None,None,Some(&in_flight.id)).await.is_err());
            assert!(repo.account_by_id(&future_user.id).await.unwrap().is_none());
            assert!(repo.get_tenant(&tenant.id).await.unwrap().is_none());
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    suite!(crate::sqlite::SqliteRepository);
    #[tokio::test]
    async fn sqlite_retention_and_suppression() {
        let root = std::env::temp_dir().join(format!("memoswish-retention-{}", new_id()));
        std::fs::create_dir(&root).unwrap();
        let url = format!("sqlite://{}", root.join("test.db").display());
        let repo = crate::sqlite::SqliteRepository::connect_test(&url).await.unwrap();
        retention_categories(&repo).await;
        repo.pool().close().await;
        let repo = crate::sqlite::SqliteRepository::connect_test(&url).await.unwrap();
        restore_scope_and_recovery(&repo).await;
        restored_imports(&repo).await;
        refresh_retention_and_restore(&repo).await;
        revoke_close_replay(&repo).await;
        restored_grants_and_unlink(&repo).await;
        let (p, policy, state) = restored_privacy(&repo).await;
        repo.pool().close().await;
        let repo = crate::sqlite::SqliteRepository::connect_test(&url).await.unwrap();
        assert_restored_privacy(&repo, &p, &policy, &state).await;
        repo.pool().close().await;
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    suite!(crate::postgres::PostgresRepository);
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_retention_and_suppression() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("PostgreSQL URL required");
            let fixture = owner.fixture(&url).await;
            let repo = fixture.repository(4).await.unwrap();
            retention_categories(&repo).await;
            restore_scope_and_recovery(&repo).await;
            restored_imports(&repo).await;
            refresh_retention_and_restore(&repo).await;
            revoke_close_replay(&repo).await;
            restored_grants_and_unlink(&repo).await;
            let (p, policy, state) = restored_privacy(&repo).await;
            repo.pool().close().await;
            let repo = fixture.repository(4).await.unwrap();
            assert_restored_privacy(&repo, &p, &policy, &state).await;
            repo.pool().close().await;
            fixture.cleanup().await;
        });
    }
}
