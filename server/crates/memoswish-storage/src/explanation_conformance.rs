//! 双连接共享验收：幂等、跨租户预算、不可重发、结算回滚、过期和升级。
use memoswish_core::{CoreError, Principal, explanations::*, repo::*};
use memoswish_protocol::{Card, ExplainDisposition};

pub(crate) fn policy() -> ExplanationPolicy {
    ExplanationPolicy {
        deployment_id: memoswish_core::ids::new_id(),
        provider_account: memoswish_core::ids::new_id(),
        pricing_version: "test-v1".into(),
        currency: "USD".into(),
        valid_until_ms: i64::MAX,
        input_rate: 1,
        output_rate: 1,
        rate_denominator: 1000,
        tenant_limit: 10_000,
        deployment_limit: 10_000,
        provider_limit: 10_000,
        unresolved_limit: 10_000,
        cache_entry_bytes: 16_384,
        cache_tenant_bytes: 32_768,
        cache_deployment_bytes: 65_536,
        cache_ttl_ms: 60_000,
    }
}
async fn grant_explanation(repo: &impl Repository, p: &Principal) {
    let policy =
        memoswish_protocol::PrivacyPolicy { hosted: false, ..memoswish_protocol::examples::sample_privacy_policy() };
    repo.privacy_install_policy(&policy).await.unwrap();
    let mut owner = p.clone();
    owner.via = "single_user".into();
    owner.scopes = None;
    owner.session_access_hash = None;
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_ai", "provider-policy-v1", ""),
    ] {
        let state = repo.privacy_state(&owner.tenant_id, &owner).await.unwrap();
        repo.privacy_update(
            &owner.tenant_id,
            &owner,
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
}
async fn seed(repo: &impl Repository) -> (Principal, Card, String) {
    let mut p = crate::asset_conformance::seed(repo).await;
    let mut tenant = repo.get_tenant(&p.tenant_id).await.unwrap().unwrap();
    tenant.plan = "self_hosted".into();
    repo.upsert_tenant(&tenant).await.unwrap();
    grant_explanation(repo, &p).await;
    let id = issue_token(repo, &mut p).await;
    let mut deck = memoswish_protocol::examples::sample_deck();
    deck.id = memoswish_core::ids::new_id();
    let mut card = memoswish_protocol::examples::sample_card();
    card.id = memoswish_core::ids::new_id();
    card.deck_id = deck.id.clone();
    repo.insert_deck_with_cards(&p.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
    (p, card, id)
}
async fn issue_token(repo: &impl Repository, p: &mut Principal) -> String {
    let id = memoswish_core::ids::new_id();
    let hash = memoswish_core::ids::sha256_hex(id.as_bytes());
    p.via = "api_token".into();
    p.scopes = Some(vec!["*".into()]);
    p.session_access_hash = Some(format!("api:{hash}"));
    repo.issue_api_token(&ApiTokenRecord {
        id: id.clone(),
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        name: "Explanation test".into(),
        token_hash: hash,
        generations: p.credential_generations().unwrap(),
        scopes: p.scopes.clone().unwrap(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    })
    .await
    .unwrap();
    id
}
fn admission(card: &Card, key: &str, policy: &ExplanationPolicy, cache: Option<&str>) -> ExplanationAdmission {
    ExplanationAdmission {
        context: ExplanationContext {
            locale: card.language.clone(),
            model_profile: "gpt-4o-mini".into(),
            prompt_version: "explain-prompt-v1".into(),
            policy_version: "self-hosted-policy-v1".into(),
        },
        request_id: key.into(),
        command_hash: memoswish_core::ids::sha256_hex(format!("{}:{key}", card.id).as_bytes()),
        card_id: card.id.clone(),
        revision: card.revision,
        cache_key: cache.map(str::to_string),
        profile_id: memoswish_core::ids::sha256_hex(&serde_json::to_vec(policy).unwrap()),
        policy: Some(policy.clone()),
    }
}
async fn shared(repo: &impl Repository, other: &impl Repository) {
    let (p, card, token) = seed(repo).await;
    let policy = policy();
    let a = admission(&card, "same", &policy, Some("default"));
    let (one, two) = tokio::join!(repo.admit_explanation(&p, &a), other.admit_explanation(&p, &a));
    let one = one.unwrap();
    let two = two.unwrap();
    assert_eq!(one.id, two.id);
    let mut changed = a.clone();
    changed.command_hash = "a".repeat(64);
    assert!(matches!(other.admit_explanation(&p, &changed).await, Err(CoreError::Conflict(_))));
    let alias = admission(&card, "alias", &policy, Some("default"));
    assert_eq!(other.admit_explanation(&p, &alias).await.unwrap().id, one.id);
    let (first, second) =
        tokio::join!(repo.begin_explanation_attempt(&p, "same"), other.begin_explanation_attempt(&p, "alias"));
    assert_eq!(u8::from(first.unwrap()) + u8::from(second.unwrap()), 1);
    assert_eq!(
        other.lookup_explanation(&p, "same", None).await.unwrap().unwrap().operation.disposition,
        ExplainDisposition::Unresolved
    );
    assert!(!repo.begin_explanation_attempt(&p, "same").await.unwrap());
    // 未知费用经维护或重放都不退还；已有 paid marker 从不回队列。
    use memoswish_core::maintenance::*;
    let pending = admission(&card, "scheduled-pending", &policy, None);
    repo.admit_explanation(&p, &pending).await.unwrap();
    let task = other.register_maintenance(&TaskRegistration::system(TaskKind::ExplanationRecovery)).await.unwrap();
    let claim = other.claim_maintenance(&task, "explanation-sweep").await.unwrap().unwrap();
    other.maintenance_sql_page(&claim).await.unwrap();
    assert!(other.maintenance_sql_page(&claim).await.is_err());
    assert_eq!(
        repo.lookup_explanation(&p, "scheduled-pending", None).await.unwrap().unwrap().operation.disposition,
        ExplainDisposition::Cancelled
    );
    assert_eq!(
        repo.lookup_explanation(&p, "same", None).await.unwrap().unwrap().operation.disposition,
        ExplainDisposition::Unresolved
    );
    let evidence = ExplanationEvidence::Usage(ExplanationUsage { input_tokens: 11, output_tokens: 2 });
    repo.settle_explanation(&p.tenant_id, &one.id, &evidence).await.unwrap();
    other.settle_explanation(&p.tenant_id, &one.id, &evidence).await.unwrap();
    assert!(matches!(
        other
            .settle_explanation(
                &p.tenant_id,
                &one.id,
                &ExplanationEvidence::Usage(ExplanationUsage { input_tokens: 12, output_tokens: 2 })
            )
            .await,
        Err(CoreError::Conflict(_))
    ));
    let mut text = memoswish_protocol::examples::sample_card_explanation();
    text.card_id = card.id.clone();
    assert!(repo.publish_explanation(&p, "same", &text).await.unwrap());
    assert_eq!(other.lookup_explanation(&p, "alias", None).await.unwrap().unwrap().result, Some(text));
    let (outsider, _, _) = seed(repo).await;
    assert!(repo.lookup_explanation(&outsider, "same", None).await.unwrap().is_none());
    assert!(repo.settle_explanation(&outsider.tenant_id, &one.id, &evidence).await.is_err());
    let mut narrowed = p.clone();
    narrowed.scopes = Some(vec!["feed:read".into()]);
    assert!(matches!(repo.lookup_explanation(&narrowed, "same", None).await, Err(CoreError::Forbidden(_))));

    // 同工作区的另一主体使用相同 request/cache 身份，仍不读取或合并原结果。
    let (mut peer, _, _) = seed(repo).await;
    let generation = repo.membership_join(&p.tenant_id, &peer.user_id, memoswish_core::Role::Owner).await.unwrap();
    peer.tenant_id = p.tenant_id.clone();
    peer.membership_generation = Some(generation);
    peer.role = memoswish_core::Role::Owner;
    peer.scopes = Some(vec!["content:read".into()]);
    grant_explanation(repo, &peer).await;
    let peer_id = memoswish_core::ids::new_id();
    let peer_hash = memoswish_core::ids::sha256_hex(peer_id.as_bytes());
    peer.session_access_hash = Some(format!("api:{peer_hash}"));
    repo.issue_api_token(&ApiTokenRecord {
        id: peer_id,
        tenant_id: peer.tenant_id.clone(),
        user_id: peer.user_id.clone(),
        name: "Peer explanation".into(),
        token_hash: peer_hash,
        generations: peer.credential_generations().unwrap(),
        scopes: peer.scopes.clone().unwrap(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    })
    .await
    .unwrap();
    assert!(repo.lookup_explanation(&peer, "same", None).await.unwrap().is_none());
    let separate = repo.admit_explanation(&peer, &a).await.unwrap();
    assert_ne!(separate.id, one.id);
    assert!(separate.result.is_none());
    // 工作区所有者导出也不得跨主体读取私有解释或上下文。
    let mut exporting_owner = p.clone();
    exporting_owner.via = "single_user".into();
    exporting_owner.scopes = None;
    let export = repo.export_workspace(&exporting_owner).await.unwrap();
    let operations = &export.data["explanation_operations"];
    assert!(operations.iter().any(|row| row["id"] == one.id));
    assert!(operations.iter().all(|row| row["user_id"] == p.user_id));
    assert!(!operations.iter().any(|row| row["id"] == separate.id));
    repo.begin_explanation_attempt(&peer, "same").await.unwrap();
    repo.membership_remove(&p.tenant_id, &peer.user_id).await.unwrap();
    assert!(repo.lookup_explanation(&peer, "same", None).await.is_err());
    assert!(repo.lookup_explanation(&p, "same", None).await.unwrap().unwrap().result.is_some());
    repo.revoke_api_token(&p.tenant_id, &token).await.unwrap();
    assert!(repo.lookup_explanation(&p, "same", None).await.is_err());

    // 未知套餐即使提供预算和用途证据，也不创建付费责任。
    {
        let (p, card, _) = seed(repo).await;
        let mut t = repo.get_tenant(&p.tenant_id).await.unwrap().unwrap();
        t.plan = "unknown".into();
        repo.upsert_tenant(&t).await.unwrap();
        let a = admission(&card, "hosted", &policy, None);
        let op = repo.admit_explanation(&p, &a).await.unwrap();
        assert_eq!(op.operation.disposition, ExplainDisposition::Local);
        assert!(!repo.begin_explanation_attempt(&p, "hosted").await.unwrap());
    }
    // 首次禁止发布即准确报告释放；已有尝试的不确定责任仍保留。
    let (p, card, _) = seed(repo).await;
    for key in ["never-sent", "already-sent"] {
        repo.admit_explanation(&p, &admission(&card, key, &policy, None)).await.unwrap();
    }
    repo.begin_explanation_attempt(&p, "already-sent").await.unwrap();
    let mut tenant = repo.get_tenant(&p.tenant_id).await.unwrap().unwrap();
    tenant.plan = "unknown".into();
    repo.upsert_tenant(&tenant).await.unwrap();
    for _ in 0..2 {
        for (key, held) in [("never-sent", 0), ("already-sent", policy.cost(128_000, 1024).unwrap())] {
            let record = repo.lookup_explanation(&p, key, None).await.unwrap().unwrap();
            assert_eq!(record.operation.disposition, ExplainDisposition::Suppressed);
            assert_eq!(record.operation.accounting.unwrap().held_microcurrency, held);
        }
    }
    // 两个租户争抢最后的部署或提供者预算，失败者不能留下部分预留。
    for provider in [false, true] {
        let (p, card, _) = seed(repo).await;
        let (q, card2, _) = seed(repo).await;
        let mut policy = super::explanation_conformance::policy();
        let cost = policy.cost(128_000, 1024).unwrap();
        if provider {
            policy.provider_limit = cost;
        } else {
            policy.deployment_limit = cost;
        }
        let a = admission(&card, "last", &policy, None);
        let b = admission(&card2, "last", &policy, None);
        let (x, y) = tokio::join!(repo.admit_explanation(&p, &a), other.admit_explanation(&q, &b));
        assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
        if x.is_ok() {
            assert!(matches!(y, Err(CoreError::QuotaExceeded(_))));
            assert!(repo.lookup_explanation(&q, "last", None).await.unwrap().is_none());
        } else {
            assert!(matches!(x, Err(CoreError::QuotaExceeded(_))));
            assert!(repo.lookup_explanation(&p, "last", None).await.unwrap().is_none());
        }
    }

    // 肯定未收费证明受当前财务权限约束；无效证明不释放 hold。
    let (owner, card, _) = seed(repo).await;
    let proof_policy = super::explanation_conformance::policy();
    let a = admission(&card, "no-charge", &proof_policy, None);
    repo.admit_explanation(&owner, &a).await.unwrap();
    repo.begin_explanation_attempt(&owner, "no-charge").await.unwrap();
    let invalid = ExplanationEvidence::NotCharged { reference_sha256: "invalid".into() };
    assert!(repo.reconcile_explanation(&owner, "no-charge", &invalid).await.is_err());
    let mut denied = owner.clone();
    denied.role = memoswish_core::Role::Admin;
    let proof = ExplanationEvidence::NotCharged { reference_sha256: "a".repeat(64) };
    assert!(matches!(repo.reconcile_explanation(&denied, "no-charge", &proof).await, Err(CoreError::Forbidden(_))));
    let before = repo.lookup_explanation(&owner, "no-charge", None).await.unwrap().unwrap();
    assert_eq!(before.operation.accounting.unwrap().held_microcurrency, proof_policy.cost(128_000, 1024).unwrap());
    repo.reconcile_explanation(&owner, "no-charge", &proof).await.unwrap();
    other.reconcile_explanation(&owner, "no-charge", &proof).await.unwrap();
    let settled = repo.lookup_explanation(&owner, "no-charge", None).await.unwrap().unwrap();
    let accounting = settled.operation.accounting.unwrap();
    assert_eq!(accounting.held_microcurrency, 0);
    assert_eq!(accounting.committed_microcurrency, 0);
    assert_eq!(accounting.attempts, 1);
    assert!(!repo.begin_explanation_attempt(&owner, "no-charge").await.unwrap());
    // 同一租户最后预算、任意问题不合并，缺失预算保持持久本地处置。
    let (p, card, _) = seed(repo).await;
    let mut policy = super::explanation_conformance::policy();
    policy.tenant_limit = policy.cost(128_000, 1024).unwrap();
    let a = admission(&card, "last-a", &policy, None);
    let b = admission(&card, "last-b", &policy, None);
    let (x, y) = tokio::join!(repo.admit_explanation(&p, &a), other.admit_explanation(&p, &b));
    assert_ne!(x.is_ok(), y.is_ok());
    let mut local = admission(&card, "local", &policy, None);
    local.policy = None;
    assert_eq!(repo.admit_explanation(&p, &local).await.unwrap().operation.disposition, ExplainDisposition::Local);
    local.policy = Some(policy);
    assert_eq!(repo.admit_explanation(&p, &local).await.unwrap().operation.disposition, ExplainDisposition::Local);
}

macro_rules! sql_suite {
    ($repo:ty,$pool:ty,$migrations:literal,$trigger:literal,$drop:literal) => {
        async fn privacy_retention_and_restore(repo: &$repo) {
            use crate::restore_suppression::{Suppression, SuppressionBatch, SuppressionEntry};
            use memoswish_core::privacy::PrivacyRepo;
            let (p, card, _) = seed(repo).await;
            let policy = policy();
            let mut owner = p.clone();
            owner.via = "single_user".into();
            owner.scopes = None;
            let privacy = memoswish_protocol::PrivacyPolicy {
                hosted: false, ..memoswish_protocol::examples::sample_privacy_policy()
            };
            // 缺用途和撤回用途都在任何持久预算写入前返回 Forbidden。
            sqlx::query("DELETE FROM privacy_purposes WHERE tenant_id=$1 AND user_id=$2")
                .bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();
            assert!(matches!(repo.admit_explanation(&p, &admission(&card, "absent", &policy, None)).await, Err(CoreError::Forbidden(_))));
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations WHERE tenant_id=$1")
                .bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count, 0);
            grant_explanation(repo, &p).await;
            let evidence = ExplanationEvidence::Usage(ExplanationUsage { input_tokens: 10, output_tokens: 2 });
            let mut text = memoswish_protocol::examples::sample_card_explanation();
            text.card_id = card.id.clone();
            for key in ["pending", "in-flight", "cached", "expired"] {
                let op = repo.admit_explanation(&p, &admission(&card, key, &policy, None)).await.unwrap();
                if key != "pending" { assert!(repo.begin_explanation_attempt(&p, key).await.unwrap()); }
                if matches!(key, "cached" | "expired") {
                    repo.settle_explanation(&p.tenant_id, &op.id, &evidence).await.unwrap();
                    assert!(repo.publish_explanation(&p, key, &text).await.unwrap());
                }
            }
            sqlx::query("UPDATE explanation_operations SET expires_at_ms=0 WHERE tenant_id=$1 AND id=(SELECT operation_id FROM explanation_requests WHERE tenant_id=$1 AND user_id=$2 AND request_id='expired')")
                .bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();
            let retention = crate::retention::RetentionPolicy {
                version: 1, api_metadata_after_expiry_seconds: 0, failed_tts_payload_after_schedule_seconds: 0,
            };
            assert_eq!(repo.retention_sweep(&p.tenant_id, &retention, 1, false).await.unwrap().expired_explanation_results, 1);
            assert_eq!(repo.retention_sweep(&p.tenant_id, &retention, 1, true).await.unwrap().expired_explanation_results, 1);
            assert_eq!(repo.retention_sweep(&p.tenant_id, &retention, 1, true).await.unwrap().expired_explanation_results, 0);
            // 缓存正文到期不清财务证据，也不能让同一身份再次付费。
            let expired = repo.lookup_explanation(&p, "expired", None).await.unwrap().unwrap();
            assert!(expired.result.is_none());
            assert_eq!(expired.operation.accounting.unwrap().committed_microcurrency, 2);
            assert!(!repo.begin_explanation_attempt(&p, "expired").await.unwrap());
            let (other, other_card, _) = seed(repo).await;
            repo.admit_explanation(&other, &admission(&other_card, "foreign", &super::policy(), None)).await.unwrap();
            let state = repo.privacy_state(&p.tenant_id, &owner).await.unwrap();
            repo.privacy_update(&p.tenant_id, &owner, &privacy, &memoswish_protocol::PrivacyUpdate {
                expected_revision: state.revision, kind: "external_ai".into(), version: "provider-policy-v1".into(),
                decision: false, value: String::new(),
            }).await.unwrap();
            assert!(matches!(repo.admit_explanation(&p, &admission(&card, "withdrawn", &policy, None)).await, Err(CoreError::Forbidden(_))));
            for (key, held) in [("pending", 0), ("in-flight", policy.cost(128_000, 1024).unwrap()), ("cached", 0)] {
                let record = repo.lookup_explanation(&p, key, None).await.unwrap().unwrap();
                assert!(record.result.is_none());
                assert_eq!(record.operation.disposition, ExplainDisposition::Suppressed);
                assert_eq!(record.operation.accounting.unwrap().held_microcurrency, held);
                assert!(!repo.begin_explanation_attempt(&p, key).await.unwrap());
            }
            let in_flight = repo.lookup_explanation(&p, "in-flight", None).await.unwrap().unwrap();
            repo.settle_explanation(&p.tenant_id, &in_flight.id, &evidence).await.unwrap();
            assert!(!repo.publish_explanation(&p, "in-flight", &text).await.unwrap());
            assert!(repo.lookup_explanation(&other, "foreign", None).await.unwrap().is_some());
            grant_explanation(repo, &p).await;
            assert!(!repo.begin_explanation_attempt(&p, "pending").await.unwrap());
            let restored = repo.admit_explanation(&p, &admission(&card, "restored", &policy, None)).await.unwrap();
            assert!(repo.begin_explanation_attempt(&p, "restored").await.unwrap());
            let mut batch = SuppressionBatch {
                version: 1, snapshot_sha256: "a".repeat(64), after_sequence: 0, through_sequence: 1,
                entries: vec![SuppressionEntry { sequence: 1, action: Suppression::WithdrawPurpose {
                    tenant_id: p.tenant_id.clone(), user_id: p.user_id.clone(), purpose: "external_ai".into(),
                    version: "provider-policy-v1".into(), recorded_at: 100,
                }}],
            };
            let pending = repo.admit_explanation(&p, &admission(&card, "restore-pending", &policy, None)).await.unwrap();
            let cached = repo.admit_explanation(&p, &admission(&card, "restore-cached", &policy, None)).await.unwrap();
            assert!(repo.begin_explanation_attempt(&p, "restore-cached").await.unwrap());
            repo.settle_explanation(&p.tenant_id, &cached.id, &evidence).await.unwrap();
            assert!(repo.publish_explanation(&p, "restore-cached", &text).await.unwrap());
            let before = repo.lookup_explanation(&p, "restore-cached", None).await.unwrap().unwrap();
            let before_privacy = repo.privacy_state(&p.tenant_id, &owner).await.unwrap();
            let before_holds: Vec<(String, String, String, String, i64)> = sqlx::query_as(
                "SELECT tenant_id,operation_id,scope,period,amount FROM explanation_holds ORDER BY tenant_id,operation_id,scope"
            ).fetch_all(repo.pool()).await.unwrap();
            let before_accounts: Vec<(String, String, i64, i64)> = sqlx::query_as(
                "SELECT scope,period,held,committed FROM explanation_accounts ORDER BY scope,period"
            ).fetch_all(repo.pool()).await.unwrap();
            // 后序动作失败必须回滚已清的正文、原授权和已释放的预留。
            batch.through_sequence = 2;
            batch.entries.push(SuppressionEntry { sequence: 2, action: Suppression::LeaveWorkspace {
                tenant_id: other.tenant_id.clone(), user_id: other.user_id.clone(),
            }});
            assert!(repo.replay_suppressions(&batch).await.is_err());
            let after_holds: Vec<(String, String, String, String, i64)> = sqlx::query_as(
                "SELECT tenant_id,operation_id,scope,period,amount FROM explanation_holds ORDER BY tenant_id,operation_id,scope"
            ).fetch_all(repo.pool()).await.unwrap();
            let after_accounts: Vec<(String, String, i64, i64)> = sqlx::query_as(
                "SELECT scope,period,held,committed FROM explanation_accounts ORDER BY scope,period"
            ).fetch_all(repo.pool()).await.unwrap();
            assert_eq!(after_holds, before_holds);
            assert_eq!(after_accounts, before_accounts);
            assert_eq!(repo.privacy_state(&p.tenant_id, &owner).await.unwrap(), before_privacy);
            let after = repo.lookup_explanation(&p, "restore-cached", None).await.unwrap().unwrap();
            assert_eq!(after.result, before.result);
            assert_eq!(after.operation, before.operation);
            assert_eq!(repo.lookup_explanation(&p, "restore-pending", None).await.unwrap().unwrap().operation, pending.operation);
            batch.through_sequence = 1;
            batch.entries.pop();
            repo.replay_suppressions(&batch).await.unwrap();
            repo.replay_suppressions(&batch).await.unwrap();
            assert!(!repo.begin_explanation_attempt(&p, "restored").await.unwrap());
            repo.settle_explanation(&p.tenant_id, &restored.id, &evidence).await.unwrap();
            assert!(!repo.publish_explanation(&p, "restored", &text).await.unwrap());
            grant_explanation(repo, &p).await;
            let deleted = repo.admit_explanation(&p, &admission(&card, "restored-card", &policy, None)).await.unwrap();
            batch.entries[0].action = Suppression::DeleteCard { tenant_id: p.tenant_id.clone(), card_id: card.id.clone() };
            repo.replay_suppressions(&batch).await.unwrap();
            repo.replay_suppressions(&batch).await.unwrap();
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM explanation_holds WHERE tenant_id=$1 AND operation_id=$2")
                .bind(&p.tenant_id).bind(&deleted.id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(count, 0);
            let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations WHERE tenant_id=$1 AND (result IS NOT NULL OR authority<>'{}' OR privacy IS NOT NULL)")
                .bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(retained, 0);
        }
        async fn accounting(repo:&$repo,other:&$repo) {
            use sqlx::Row;
            let (p,card,_)=seed(repo).await;let mut policy=policy();policy.unresolved_limit=policy.cost(128_000,1024).unwrap();let a=admission(&card,"fault",&policy,None);
            let op=repo.admit_explanation(&p,&a).await.unwrap();
            let captured:String=sqlx::query_scalar("SELECT CAST(payload AS TEXT) FROM background_jobs WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&op.id).fetch_one(repo.pool()).await.unwrap();assert_eq!(serde_json::from_str::<ExplanationContext>(&captured).unwrap(),a.context);
            let mut changed_context=a.clone();changed_context.context.locale="zh-CN".into();changed_context.context.prompt_version="later-prompt".into();changed_context.context.policy_version="later-policy".into();repo.admit_explanation(&p,&changed_context).await.unwrap();
            let replayed:String=sqlx::query_scalar("SELECT CAST(payload AS TEXT) FROM background_jobs WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&op.id).fetch_one(repo.pool()).await.unwrap();assert_eq!(captured,replayed);
            assert!(repo.begin_explanation_attempt(&p,"fault").await.unwrap());
            let amount=policy.cost(128_000,1024).unwrap();
            let held=||sqlx::query_scalar::<_,i64>("SELECT CAST(SUM(held) AS BIGINT) FROM explanation_accounts WHERE scope=$1").bind(format!("deployment:{}",policy.deployment_id)).fetch_one(repo.pool());
            assert_eq!(held().await.unwrap(),amount);
            sqlx::raw_sql($trigger).execute(repo.pool()).await.unwrap();
            let evidence=ExplanationEvidence::Usage(ExplanationUsage{input_tokens:10,output_tokens:10});
            assert!(repo.settle_explanation(&p.tenant_id,&op.id,&evidence).await.is_err());assert_eq!(held().await.unwrap(),amount);
            sqlx::raw_sql($drop).execute(repo.pool()).await.unwrap();
            // 将未决责任移到已捕获的旧账期，验证新账期仍受跨期 exposure 限制。
            let mut tx=repo.pool().begin().await.unwrap();
            sqlx::query("INSERT INTO explanation_accounts(scope,period,currency,cap,exposure_cap,committed,held) SELECT scope,'2000-01',currency,cap,exposure_cap,committed,held FROM explanation_accounts WHERE scope IN(SELECT scope FROM explanation_holds WHERE tenant_id=$1 AND operation_id=$2)").bind(&p.tenant_id).bind(&op.id).execute(&mut *tx).await.unwrap();
            sqlx::query("UPDATE explanation_holds SET period='2000-01' WHERE tenant_id=$1 AND operation_id=$2").bind(&p.tenant_id).bind(&op.id).execute(&mut *tx).await.unwrap();
            sqlx::query("DELETE FROM explanation_accounts WHERE period<>'2000-01' AND scope IN(SELECT scope FROM explanation_holds WHERE tenant_id=$1 AND operation_id=$2)").bind(&p.tenant_id).bind(&op.id).execute(&mut *tx).await.unwrap();
            sqlx::query("UPDATE explanation_operations SET period='2000-01' WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&op.id).execute(&mut *tx).await.unwrap();tx.commit().await.unwrap();
            let next=admission(&card,"new-month",&policy,None);assert!(matches!(repo.admit_explanation(&p,&next).await,Err(CoreError::QuotaExceeded(_))));
            repo.settle_explanation(&p.tenant_id,&op.id,&evidence).await.unwrap();assert_eq!(held().await.unwrap(),0);
            let committed:i64=sqlx::query_scalar("SELECT committed FROM explanation_accounts WHERE scope=$1 AND period='2000-01'").bind(format!("deployment:{}",policy.deployment_id)).fetch_one(repo.pool()).await.unwrap();assert_eq!(committed,2);
            // 过界真实费用完整入账，并冻结原定价身份，配置或凭据指纹变化不能绕过。
            let b=admission(&card,"overrun",&policy,None);let over=repo.admit_explanation(&p,&b).await.unwrap();repo.begin_explanation_attempt(&p,"overrun").await.unwrap();
            repo.settle_explanation(&p.tenant_id,&over.id,&ExplanationEvidence::Usage(ExplanationUsage{input_tokens:128_001,output_tokens:2048})).await.unwrap();
            let mut next=admission(&card,"after-overrun",&policy,None);next.profile_id="b".repeat(64);
            assert!(repo.admit_explanation(&p,&next).await.is_err());
            // 正文精确边界与 +1；容量不足不影响已结算账本。
            let policy=super::policy();let a=admission(&card,"cache-bound",&policy,Some("default"));let op=repo.admit_explanation(&p,&a).await.unwrap();repo.begin_explanation_attempt(&p,"cache-bound").await.unwrap();repo.settle_explanation(&p.tenant_id,&op.id,&evidence).await.unwrap();
            let mut text=memoswish_protocol::examples::sample_card_explanation();text.card_id=card.id.clone();text.summary.clear();let base=serde_json::to_vec(&text).unwrap().len();text.summary="x".repeat(policy.cache_entry_bytes as usize-base+1);
            assert!(!repo.publish_explanation(&p,"cache-bound",&text).await.unwrap());text.summary.pop();assert!(repo.publish_explanation(&p,"cache-bound",&text).await.unwrap());
            sqlx::query("UPDATE explanation_operations SET expires_at_ms=0 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&op.id).execute(repo.pool()).await.unwrap();
            assert_eq!(other.lookup_explanation(&p,"cache-bound",None).await.unwrap().unwrap().operation.disposition,ExplainDisposition::Expired);
            assert!(!other.begin_explanation_attempt(&p,"cache-bound").await.unwrap());
            // 撤销后的晚到财务证据仍能结算，文本不能发布。
            let (p,card,token)=seed(repo).await;let policy=super::policy();let a=admission(&card,"late",&policy,None);let op=repo.admit_explanation(&p,&a).await.unwrap();repo.begin_explanation_attempt(&p,"late").await.unwrap();repo.revoke_api_token(&p.tenant_id,&token).await.unwrap();
            repo.settle_explanation(&p.tenant_id,&op.id,&evidence).await.unwrap();assert!(repo.publish_explanation(&p,"late",&text).await.is_err());
            // 安全事件推进账户及成员世代后，当前账务凭据仍可核账，但不能恢复原执行或正文。
            let (old,card,_)=seed(repo).await;let policy=super::policy();let a=admission(&card,"generation",&policy,None);
            let op=repo.admit_explanation(&old,&a).await.unwrap();assert!(repo.begin_explanation_attempt(&old,"generation").await.unwrap());
            sqlx::query("UPDATE account_auth_epochs SET generation=generation+1 WHERE user_id=$1").bind(&old.user_id).execute(repo.pool()).await.unwrap();
            assert!(repo.membership_remove(&old.tenant_id,&old.user_id).await.unwrap());
            let mut current=old.clone();current.auth_generation=Some(repo.account_generation(&old.user_id).await.unwrap());
            current.membership_generation=Some(repo.membership_join(&old.tenant_id,&old.user_id,memoswish_core::Role::Owner).await.unwrap());
            issue_token(repo,&mut current).await;
            assert!(repo.reconcile_explanation(&old,"generation",&evidence).await.is_err());
            assert!(repo.lookup_explanation(&current,"generation",None).await.is_err());
            assert!(repo.begin_explanation_attempt(&current,"generation").await.is_err());
            let (outsider,_,_)=seed(repo).await;
            assert!(matches!(repo.reconcile_explanation(&outsider,"generation",&evidence).await,Err(CoreError::NotFound(_))));
            let mut peer=outsider.clone();peer.tenant_id=current.tenant_id.clone();peer.membership_generation=Some(repo.membership_join(&peer.tenant_id,&peer.user_id,memoswish_core::Role::Owner).await.unwrap());issue_token(repo,&mut peer).await;
            assert!(matches!(repo.reconcile_explanation(&peer,"generation",&evidence).await,Err(CoreError::NotFound(_))));
            let receipt=repo.reconcile_explanation(&current,"generation",&evidence).await.unwrap();
            assert_eq!(receipt.disposition,ExplainDisposition::Settled);let accounting=receipt.accounting.as_ref().unwrap();
            assert_eq!(accounting.held_microcurrency,0);assert_eq!(accounting.committed_microcurrency,2);assert_eq!(accounting.attempts,1);
            assert_eq!(other.reconcile_explanation(&current,"generation",&evidence).await.unwrap(),receipt);
            let conflicting=ExplanationEvidence::NotCharged{reference_sha256:"c".repeat(64)};
            assert!(matches!(other.reconcile_explanation(&current,"generation",&conflicting).await,Err(CoreError::Conflict(_))));
            let mut generation_text=text.clone();generation_text.card_id=card.id.clone();
            assert!(!repo.publish_explanation(&current,"generation",&generation_text).await.unwrap());
            let attempts:i64=sqlx::query_scalar("SELECT attempted FROM explanation_operations WHERE tenant_id=$1 AND id=$2").bind(&old.tenant_id).bind(&op.id).fetch_one(repo.pool()).await.unwrap();assert_eq!(attempts,1);
            // 删除只抑制发布，保留持久责任与收费；没有存活父内容也能结算。
            let (p,card,_)=seed(repo).await;let policy=super::policy();let a=admission(&card,"deleted",&policy,None);let op=repo.admit_explanation(&p,&a).await.unwrap();repo.begin_explanation_attempt(&p,"deleted").await.unwrap();repo.delete_card(&p.tenant_id,&card.id).await.unwrap();
            repo.settle_explanation(&p.tenant_id,&op.id,&evidence).await.unwrap();assert_eq!(repo.lookup_explanation(&p,"deleted",None).await.unwrap().unwrap().operation.disposition,ExplainDisposition::Suppressed);
            let raw=sqlx::query("SELECT evidence FROM explanation_operations WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&op.id).fetch_one(repo.pool()).await.unwrap();assert!(raw.get::<Option<String>,_>("evidence").is_some());
        }

        async fn lifecycle_and_cache_capacity(repo:&$repo,other:&$repo) {
            use memoswish_core::identity::IdentityRepo;
            use memoswish_core::lifecycle::LifecycleRepo;
            let (p,card,_)=seed(repo).await;let mut policy=policy();policy.cache_entry_bytes=1024;policy.cache_tenant_bytes=2048;policy.cache_deployment_bytes=4096;
            let mut text=memoswish_protocol::examples::sample_card_explanation();text.card_id=card.id.clone();text.summary.clear();let base=serde_json::to_vec(&text).unwrap().len();assert!(base<1024);text.summary="x".repeat(1024-base);
            let evidence=ExplanationEvidence::Usage(ExplanationUsage{input_tokens:10,output_tokens:10});
            for key in ["cap-one","cap-two","cap-three"] {let a=admission(&card,key,&policy,None);let op=repo.admit_explanation(&p,&a).await.unwrap();repo.begin_explanation_attempt(&p,key).await.unwrap();repo.settle_explanation(&p.tenant_id,&op.id,&evidence).await.unwrap();}
            let (a,b)=tokio::join!(repo.publish_explanation(&p,"cap-one",&text),other.publish_explanation(&p,"cap-two",&text));assert!(a.unwrap() && b.unwrap());assert!(!repo.publish_explanation(&p,"cap-three",&text).await.unwrap());
            let mut first_party=p.clone();first_party.via="single_user".into();first_party.scopes=None;
            let export=repo.export_personal(&memoswish_core::lifecycle::AccountAuthority::Workspace(first_party)).await.unwrap();
            assert_eq!(export.workspaces[0].data["explanation_operations"][0]["context"]["locale"],card.language);
            let exported=serde_json::to_string(&export).unwrap();assert!(exported.contains("explanation_operations"));assert!(!exported.contains("token_hash"));assert!(!exported.contains(p.session_access_hash.as_deref().unwrap()));
            // 降权后个人导出不能释放草稿解释正文；保持修订相同以独立验证发布状态。
            let mut draft = card.clone();
            draft.content = Some(memoswish_protocol::ContentMetadata { publication: "draft".into(), observed_generation: None, provenance: Default::default() });
            sqlx::query("UPDATE cards SET body=$1 WHERE tenant_id=$2 AND id=$3").bind(sqlx::types::Json(&draft)).bind(&p.tenant_id).bind(&card.id).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE tenant_memberships SET role='learner' WHERE tenant_id=$1 AND user_id=$2").bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();
            let mut first_party=p.clone();first_party.via="single_user".into();first_party.scopes=None;
            let hidden=repo.export_personal(&memoswish_core::lifecycle::AccountAuthority::Workspace(first_party)).await.unwrap();
            assert!(hidden.workspaces[0].data["explanation_operations"].iter().all(|row| row["result"].is_null()));
            sqlx::query("UPDATE tenant_memberships SET role='owner' WHERE tenant_id=$1 AND user_id=$2").bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE cards SET body=$1 WHERE tenant_id=$2 AND id=$3").bind(sqlx::types::Json(&card)).bind(&p.tenant_id).bind(&card.id).execute(repo.pool()).await.unwrap();
            let a=admission(&card,"erased-late",&policy,None);let late=repo.admit_explanation(&p,&a).await.unwrap();repo.begin_explanation_attempt(&p,"erased-late").await.unwrap();
            let (q,card2,_)=seed(repo).await;let other_policy=super::policy();let other_a=admission(&card2,"preserved",&other_policy,None);repo.admit_explanation(&q,&other_a).await.unwrap();
            repo.account_erase(&p.tenant_id,&p.user_id,true).await.unwrap();
            let saved:i64=sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations WHERE tenant_id=$1 AND (result IS NOT NULL OR authority<>'{}')").bind(&p.tenant_id).fetch_one(repo.pool()).await.unwrap();assert_eq!(saved,0);
            repo.settle_explanation(&p.tenant_id,&late.id,&evidence).await.unwrap();assert!(repo.publish_explanation(&p,"erased-late",&text).await.is_err());assert!(repo.lookup_explanation(&q,"preserved",None).await.unwrap().is_some());
        }
        async fn upgrade(pool:&$pool) {
            use crate::foundation_conformance::{through,LEGACY_DATA};
            let full=sqlx::migrate!($migrations);
            through(&full,8).run(pool).await.unwrap();sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();through(&full,27).run(pool).await.unwrap();
            let before:String=sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id='foundation' LIMIT 1").fetch_one(pool).await.unwrap();
            let mut broken=through(&full,28);let index=broken.migrations.len()-1;let m=&broken.migrations[index];let sql=format!("{}\nSELECT * FROM p23_injected_missing_table",m.sql);
            broken.migrations.to_mut()[index]=sqlx::migrate::Migration::new(m.version,"injected failure".into(),sqlx::migrate::MigrationType::Simple,sql.into(),false);
            assert!(broken.run(pool).await.is_err());assert!(sqlx::query("SELECT id FROM explanation_profiles").fetch_all(pool).await.is_err());
            full.run(pool).await.unwrap();full.run(pool).await.unwrap();let after:String=sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id='foundation' LIMIT 1").fetch_one(pool).await.unwrap();assert_eq!(before,after);
            let fabricated:i64=sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations").fetch_one(pool).await.unwrap();assert_eq!(fabricated,0);
        }
    };
}
#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    sql_suite!(
        SqliteRepository,
        sqlx::SqlitePool,
        "./migrations/sqlite",
        "CREATE TRIGGER reject_explanation BEFORE UPDATE OF evidence ON explanation_operations WHEN NEW.evidence IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected settlement failure'); END;",
        "DROP TRIGGER reject_explanation"
    );
    #[tokio::test]
    async fn sqlite_explanation_conformance_restart_and_upgrade() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        upgrade(&pool).await;
        pool.close().await;
        let file = std::env::temp_dir().join(format!("memoswish-explanation-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", file.display());
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        let other = SqliteRepository::connect_test(&url).await.unwrap();
        shared(&repo, &other).await;
        lifecycle_visibility(&repo).await;
        accounting(&repo, &other).await;
        lifecycle_and_cache_capacity(&repo, &other).await;
        privacy_retention_and_restore(&repo).await;
        let (p, card, _) = seed(&repo).await;
        let a = admission(&card, "restart", &policy(), None);
        let op = repo.admit_explanation(&p, &a).await.unwrap();
        repo.begin_explanation_attempt(&p, "restart").await.unwrap();
        repo.pool().close().await;
        other.pool().close().await;
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        assert_eq!(repo.lookup_explanation(&p, "restart", None).await.unwrap().unwrap().id, op.id);
        assert!(!repo.begin_explanation_attempt(&p, "restart").await.unwrap());
        repo.pool().close().await;
        std::fs::remove_file(file).unwrap();
    }
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::postgres::PostgresRepository;
    sql_suite!(
        PostgresRepository,
        sqlx::PgPool,
        "./migrations/postgres",
        "CREATE FUNCTION reject_explanation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected settlement failure'; END $$; CREATE TRIGGER reject_explanation BEFORE UPDATE OF evidence ON explanation_operations FOR EACH ROW EXECUTE FUNCTION reject_explanation();",
        "DROP TRIGGER reject_explanation ON explanation_operations; DROP FUNCTION reject_explanation()"
    );
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_explanation_conformance_restart_and_upgrade() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let f = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let raw = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(f.options()).await.unwrap();
            upgrade(&raw).await;
            raw.close().await;
            let repo = f.repository(2).await.unwrap();
            let other = f.repository(2).await.unwrap();
            shared(&repo, &other).await;
            lifecycle_visibility(&repo).await;
            accounting(&repo, &other).await;
            lifecycle_and_cache_capacity(&repo, &other).await;
            privacy_retention_and_restore(&repo).await;
            let (p, card, _) = seed(&repo).await;
            let a = admission(&card, "restart", &policy(), None);
            repo.admit_explanation(&p, &a).await.unwrap();
            repo.begin_explanation_attempt(&p, "restart").await.unwrap();
            repo.pool().close().await;
            other.pool().close().await;
            let repo = f.repository(2).await.unwrap();
            assert!(!repo.begin_explanation_attempt(&p, "restart").await.unwrap());
            repo.pool().close().await;
            f.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_explanation_rechecks_original_credential_after_lock() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let f = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let repo = f.repository(2).await.unwrap();
            let writer = f.repository(1).await.unwrap();
            let (p, card, token) = seed(&repo).await;
            let a = admission(&card, "lock", &policy(), None);
            repo.admit_explanation(&p, &a).await.unwrap();
            let mut tx = repo.pool().begin().await.unwrap();
            sqlx::query("SELECT id FROM api_tokens WHERE id=$1 FOR UPDATE")
                .bind(&token)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(writer.pool()).await.unwrap();
            let subject = p.clone();
            let waiting = tokio::spawn(async move {
                let result = writer.begin_explanation_attempt(&subject, "lock").await;
                writer.pool().close().await;
                result
            });
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let blocked: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",
                    )
                    .bind(pid)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
                    if blocked {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            sqlx::query("UPDATE api_tokens SET expires_at=clock_timestamp()-interval '1 millisecond' WHERE id=$1")
                .bind(&token)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            assert!(waiting.await.unwrap().is_err());
            let attempted: i64 = sqlx::query_scalar("SELECT attempted FROM explanation_operations WHERE tenant_id=$1")
                .bind(&p.tenant_id)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(attempted, 0);
            repo.pool().close().await;
            f.cleanup().await;
        });
    }
}

// 双库共用可见性验收：准入、发送和结果读取均在事务内重验，不靠调用层过滤。
async fn lifecycle_visibility(repo: &impl Repository) {
    let (owner, mut card, token) = seed(repo).await;
    let mut reader = owner.clone();
    reader.scopes = Some(vec!["content:read".into()]);
    let mut record = repo.find_api_token(&memoswish_core::ids::sha256_hex(token.as_bytes())).await.unwrap().unwrap();
    record.id = memoswish_core::ids::new_id();
    record.token_hash = memoswish_core::ids::sha256_hex(record.id.as_bytes());
    record.scopes = reader.scopes.clone().unwrap();
    reader.session_access_hash = Some(format!("api:{}", record.token_hash));
    repo.issue_api_token(&record).await.unwrap();
    let policy = policy();
    let admitted = admission(&card, "visibility-before-withdrawal", &policy, None);
    repo.admit_explanation(&reader, &admitted).await.unwrap();
    card = repo
        .mutate_cards(
            &owner.tenant_id,
            &[memoswish_core::content::CardMutation::Publication {
                id: card.id.clone(),
                command: memoswish_protocol::PublicationCommand { expected_revision: card.revision, publish: false },
            }],
        )
        .await
        .unwrap()
        .remove(0);
    assert!(!repo.begin_explanation_attempt(&reader, &admitted.request_id).await.unwrap());
    let hidden = repo.lookup_explanation(&reader, &admitted.request_id, None).await.unwrap().unwrap();
    assert_eq!(hidden.operation.disposition, ExplainDisposition::Suppressed);
    assert!(hidden.result.is_none());
    assert_eq!(hidden.operation.accounting.unwrap().attempts, 0);
    assert!(matches!(
        repo.admit_explanation(&reader, &admission(&card, "hidden-draft", &policy, None)).await,
        Err(CoreError::NotFound(_))
    ));
    // 当前作者仍可解释自己的草稿；读权限令牌不能借用 owner 的成员角色。
    repo.admit_explanation(&owner, &admission(&card, "author-draft", &policy, None)).await.unwrap();
}
