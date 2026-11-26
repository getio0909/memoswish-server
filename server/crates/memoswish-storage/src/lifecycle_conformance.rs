//! S5 双数据库共用的保留边界、否定场景与并发回归。

use memoswish_core::lifecycle::*;
use memoswish_core::repo::*;
use memoswish_core::{AccountPrincipal, CoreError, CredentialGenerations, Principal, Role};

pub(crate) async fn workspace(repo: &impl Repository) -> Principal {
    let mut p = crate::asset_conformance::seed(repo).await;
    p.via = "jwt".into();
    p.legacy_issued_at = Some(chrono::Utc::now().timestamp());
    p
}

pub(crate) async fn member(repo: &impl Repository, tenant: &str, role: Role) -> Principal {
    let user = memoswish_core::ids::new_id();
    repo.insert_user(&UserRecord {
        id: user.clone(),
        tenant_id: tenant.into(),
        email: format!("{user}@example.com"),
        display_name: "Member".into(),
        password_hash: "preserved-password-hash".into(),
        role,
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    Principal {
        tenant_id: tenant.into(),
        user_id: user,
        role,
        scopes: None,
        via: "jwt".into(),
        session_access_hash: None,
        legacy_issued_at: Some(chrono::Utc::now().timestamp()),
        auth_generation: Some(0),
        membership_generation: Some(0),
    }
}

pub(crate) fn confirmation(p: &Principal) -> DeleteWorkspace {
    DeleteWorkspace { confirmed_tenant_id: p.tenant_id.clone() }
}

pub(crate) fn account(p: &Principal) -> AccountPrincipal {
    AccountPrincipal {
        session_id: None,
        session_access_hash: None,
        legacy_issued_at: p.legacy_issued_at,
        user_id: p.user_id.clone(),
        generation: p.auth_generation.unwrap(),
    }
}

async fn issued_delivery(repo: &impl Repository, p: &Principal) -> memoswish_protocol::FeedPage {
    let deck = memoswish_protocol::examples::sample_deck();
    let card = memoswish_protocol::examples::sample_card();
    if repo.get_deck(&p.tenant_id, &deck.id).await.unwrap().is_none() {
        repo.insert_deck(&p.tenant_id, &deck).await.unwrap();
    }
    if repo.get_card(&p.tenant_id, &card.id).await.unwrap().is_none() {
        repo.insert_card(&p.tenant_id, &card).await.unwrap();
    }
    let request = crate::feed_issuance_conformance::first();
    let candidate = crate::feed_issuance_conformance::candidate(repo, p, &request, false).await;
    crate::feed_issuance_conformance::committed(repo.feed_issuance(p, &request, Some(&candidate)).await.unwrap())
}

async fn has_delivery(repo: &impl Repository, p: &Principal, page: &memoswish_protocol::FeedPage) -> bool {
    repo.get_delivery(&p.tenant_id, &p.user_id, &page.session_id, page.items[0].slot).await.unwrap().is_some()
}

pub(crate) async fn leave_and_fences(repo: &impl Repository) {
    let (rec, state) = crate::learning_conformance::seed(repo).await;
    let owner = member(repo, &rec.tenant_id, Role::Owner).await;
    let p = Principal {
        tenant_id: rec.tenant_id.clone(),
        user_id: rec.user_id.clone(),
        role: Role::Learner,
        ..owner.clone()
    };
    let other = workspace(repo).await;
    repo.membership_join(&other.tenant_id, &p.user_id, Role::Editor).await.unwrap();
    let g = p.credential_generations().unwrap();
    let session = FeedSession {
        id: "s5-session".into(),
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        next_slot: 2,
        recent_card_ids: vec![state.card_id.clone()],
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    assert_eq!(
        repo.try_apply_learning_event_authorized(&rec, None, &state, g).await.unwrap(),
        LearningEventOutcome::Applied
    );
    repo.save_session_authorized(&session, g).await.unwrap();
    repo.add_usage(&p.tenant_id, "card_writes", "2026-11", 3).await.unwrap();
    let peer_state = MemoryState { user_id: owner.user_id.clone(), ..state.clone() };
    repo.upsert_memory(&peer_state).await.unwrap();
    let leaving_delivery = issued_delivery(repo, &p).await;
    let retained_delivery = issued_delivery(repo, &owner).await;
    let cross_scope = Principal { tenant_id: other.tenant_id.clone(), role: Role::Editor, ..p.clone() };
    let cross_delivery = issued_delivery(repo, &cross_scope).await;
    repo.leave_workspace(&p).await.unwrap();
    assert!(!has_delivery(repo, &p, &leaving_delivery).await);
    assert!(has_delivery(repo, &owner, &retained_delivery).await);
    assert!(has_delivery(repo, &cross_scope, &cross_delivery).await);
    assert!(repo.get_memory(&p.tenant_id, &p.user_id, &state.card_id).await.unwrap().is_none());
    assert!(repo.get_session(&p.tenant_id, &p.user_id, &session.id).await.unwrap().is_none());
    assert!(repo.get_card(&p.tenant_id, &state.card_id).await.unwrap().is_some());
    assert!(repo.get_memory(&p.tenant_id, &owner.user_id, &state.card_id).await.unwrap().is_some());
    assert_eq!(repo.get_usage(&p.tenant_id, "card_writes", "2026-11").await.unwrap(), 3);
    assert_eq!(repo.account_generation(&p.user_id).await.unwrap(), 0);
    assert!(repo.membership_authorize(&other.tenant_id, &p.user_id, g).await.is_ok());
    assert!(repo.account_erasure_jobs().await.unwrap().is_empty());
    assert_eq!(repo.membership_join(&p.tenant_id, &p.user_id, Role::Learner).await.unwrap(), 1);
    assert_eq!(
        repo.try_apply_learning_event_authorized(&rec, None, &state, g).await.unwrap(),
        LearningEventOutcome::MissingScope
    );
    assert!(repo.upsert_memory_authorized(&state, g).await.is_err());
    assert!(repo.insert_feedback_authorized(&rec, g).await.is_err());
    assert!(repo.save_session_authorized(&session, g).await.is_err());
    let new = CredentialGenerations { membership: 1, ..g };
    assert_eq!(
        repo.try_apply_learning_event_authorized(&rec, None, &state, new).await.unwrap(),
        LearningEventOutcome::Applied
    );
    let bad_account = CredentialGenerations { account: 1, ..new };
    assert_eq!(
        repo.try_apply_learning_event_authorized(&rec, Some(1), &state, bad_account).await.unwrap(),
        LearningEventOutcome::MissingScope
    );
    assert!(repo.upsert_memory_authorized(&state, bad_account).await.is_err());
    assert!(repo.insert_feedback_authorized(&rec, bad_account).await.is_err());
    assert!(repo.save_session_authorized(&session, bad_account).await.is_err());
    assert!(matches!(repo.leave_workspace(&owner).await, Err(CoreError::Conflict(_))));
    assert!(repo.get_user(&owner.tenant_id, &owner.user_id).await.unwrap().is_some());
    assert!(repo.account_erasure_jobs().await.unwrap().is_empty());
}

pub(crate) async fn ownership_and_deletion(repo: &impl Repository) {
    let owner = workspace(repo).await;
    assert!(matches!(repo.leave_workspace(&owner).await, Err(CoreError::Conflict(_))));
    assert!(matches!(
        repo.delete_workspace(&owner, &DeleteWorkspace { confirmed_tenant_id: "other".into() }).await,
        Err(CoreError::Invalid(_))
    ));
    for role in [Role::Admin, Role::Editor, Role::Learner] {
        let p = member(repo, &owner.tenant_id, role).await;
        let mut alleged_owner = p.clone();
        alleged_owner.role = Role::Owner;
        assert!(matches!(
            repo.delete_workspace(&alleged_owner, &confirmation(&owner)).await,
            Err(CoreError::Forbidden(_))
        ));
        assert!(matches!(
            repo.transfer_ownership(&alleged_owner, &TransferOwnership { successor_user_id: owner.user_id.clone() })
                .await,
            Err(CoreError::Forbidden(_))
        ));
    }
    for via in ["api_token", "mcp_oauth", "stdio", "upstream"] {
        let mut delegated = owner.clone();
        delegated.via = via.into();
        assert!(repo.leave_workspace(&delegated).await.is_err());
        assert!(repo.delete_workspace(&delegated, &confirmation(&owner)).await.is_err());
        assert!(
            repo.transfer_ownership(&delegated, &TransferOwnership { successor_user_id: owner.user_id.clone() })
                .await
                .is_err()
        );
    }
    let mut scoped = owner.clone();
    scoped.scopes = Some(vec!["*".into()]);
    assert!(repo.delete_workspace(&scoped, &confirmation(&owner)).await.is_err());
    for (account_generation, membership_generation) in [(None, Some(0)), (Some(0), None), (Some(-1), Some(0))] {
        let missing = Principal { auth_generation: account_generation, membership_generation, ..owner.clone() };
        assert!(repo.delete_workspace(&missing, &confirmation(&owner)).await.is_err());
        assert!(repo.leave_workspace(&missing).await.is_err());
    }
    let mut stale = owner.clone();
    stale.auth_generation = Some(1);
    assert!(repo.delete_workspace(&stale, &confirmation(&owner)).await.is_err());
    stale = owner.clone();
    stale.membership_generation = Some(1);
    assert!(repo.delete_workspace(&stale, &confirmation(&owner)).await.is_err());
    let successor = member(repo, &owner.tenant_id, Role::Learner).await;
    assert!(repo.transfer_ownership(&owner, &TransferOwnership { successor_user_id: "absent".into() }).await.is_err());
    assert!(
        repo.transfer_ownership(&owner, &TransferOwnership { successor_user_id: owner.user_id.clone() }).await.is_err()
    );
    repo.transfer_ownership(&owner, &TransferOwnership { successor_user_id: successor.user_id.clone() }).await.unwrap();
    assert!(
        repo.membership_authorize(&owner.tenant_id, &owner.user_id, owner.credential_generations().unwrap())
            .await
            .is_err()
    );
    assert!(
        repo.membership_authorize(
            &successor.tenant_id,
            &successor.user_id,
            successor.credential_generations().unwrap()
        )
        .await
        .is_err()
    );
    assert!(repo.delete_workspace(&owner, &confirmation(&owner)).await.is_err());
    assert_eq!(repo.get_user(&owner.tenant_id, &owner.user_id).await.unwrap().unwrap().role, Role::Admin);
    assert_eq!(repo.account_generation(&owner.user_id).await.unwrap(), 0);
    let active = Principal { role: Role::Owner, membership_generation: Some(1), ..successor.clone() };
    assert!(matches!(repo.leave_workspace(&active).await, Err(CoreError::Conflict(_))));
    let job = repo.delete_workspace(&active, &confirmation(&active)).await.unwrap();
    assert!(job.purge_assets && job.credentials.is_empty());
    assert_eq!(job.tenant_id, Some(owner.tenant_id.clone()));
    assert!(repo.account_erased_tenant(&owner.tenant_id).await.unwrap());
    assert!(repo.get_tenant(&owner.tenant_id).await.unwrap().is_none());
    for p in [&owner, &successor] {
        assert_eq!(repo.account_generation(&p.user_id).await.unwrap(), 0);
        assert_eq!(
            repo.account_by_id(&p.user_id).await.unwrap().unwrap().password_hash,
            if p.user_id == owner.user_id { "" } else { "preserved-password-hash" }
        );
        assert!(repo.memberships(&p.user_id).await.unwrap().is_empty());
    }
    assert!(repo.membership_join(&owner.tenant_id, &owner.user_id, Role::Owner).await.is_err());
}

pub(crate) async fn closure_is_atomic(repo: &impl Repository) {
    let jobs_before = repo.account_erasure_jobs().await.unwrap().len();
    let p = workspace(repo).await;
    let shared = workspace(repo).await;
    repo.membership_join(&shared.tenant_id, &p.user_id, Role::Owner).await.unwrap();
    let blocked = workspace(repo).await;
    repo.membership_join(&blocked.tenant_id, &p.user_id, Role::Owner).await.unwrap();
    repo.leave_workspace(&blocked).await.unwrap();
    let other_member = member(repo, &blocked.tenant_id, Role::Learner).await;
    let command = CloseAccount { confirmed_exclusive_workspaces: vec![p.tenant_id.clone()] };
    assert!(matches!(repo.close_account(&account(&p), &command).await, Err(CoreError::Conflict(_))));
    assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_some());
    assert_eq!(repo.memberships(&p.user_id).await.unwrap().len(), 3);
    assert_eq!(repo.account_erasure_jobs().await.unwrap().len(), jobs_before);
    repo.leave_workspace(&other_member).await.unwrap();
    for confirmations in [
        vec![],
        vec![p.tenant_id.clone()],
        vec![p.tenant_id.clone(), shared.tenant_id.clone()],
        vec![p.tenant_id.clone(), blocked.tenant_id.clone(), blocked.tenant_id.clone()],
    ] {
        assert!(matches!(
            repo.close_account(&account(&p), &CloseAccount { confirmed_exclusive_workspaces: confirmations }).await,
            Err(CoreError::Invalid(_))
        ));
        assert_eq!(repo.memberships(&p.user_id).await.unwrap().len(), 3);
        assert_eq!(repo.account_erasure_jobs().await.unwrap().len(), jobs_before);
    }
    let command = CloseAccount { confirmed_exclusive_workspaces: vec![blocked.tenant_id.clone(), p.tenant_id.clone()] };
    assert!(repo.close_account(&AccountPrincipal { generation: 1, ..account(&p) }, &command).await.is_err());
    let exclusive_delivery = issued_delivery(repo, &p).await;
    let shared_scope = Principal { tenant_id: shared.tenant_id.clone(), ..p.clone() };
    let personal_shared_delivery = issued_delivery(repo, &shared_scope).await;
    let retained_delivery = issued_delivery(repo, &shared).await;
    let jobs = repo.close_account(&account(&p), &command).await.unwrap();
    assert!(!has_delivery(repo, &p, &exclusive_delivery).await);
    assert!(!has_delivery(repo, &shared_scope, &personal_shared_delivery).await);
    assert!(has_delivery(repo, &shared, &retained_delivery).await);
    assert_eq!(jobs.len(), 3);
    assert_eq!(jobs.iter().filter(|j| j.purge_assets).count(), 2);
    assert!(repo.account_by_id(&p.user_id).await.unwrap().is_none());
    assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_none());
    assert!(repo.get_tenant(&blocked.tenant_id).await.unwrap().is_none());
    assert!(repo.get_tenant(&shared.tenant_id).await.unwrap().is_some());
    assert!(repo.get_user(&shared.tenant_id, &shared.user_id).await.unwrap().is_some());
    assert!(repo.account_by_id(&other_member.user_id).await.unwrap().is_some());
}

pub(crate) async fn concurrent_owners(repo: &impl Repository) {
    for close in [false, true] {
        let a = workspace(repo).await;
        let b = member(repo, &a.tenant_id, Role::Owner).await;
        let barrier = tokio::sync::Barrier::new(2);
        let action = |p: Principal| {
            let barrier = &barrier;
            async move {
                barrier.wait().await;
                if close {
                    repo.close_account(&account(&p), &CloseAccount::default()).await.map(|_| ())
                } else {
                    repo.leave_workspace(&p).await
                }
            }
        };
        let (left, right) = tokio::join!(action(a.clone()), action(b.clone()));
        assert_ne!(left.is_ok(), right.is_ok());
        let survivor = if left.is_ok() { &b } else { &a };
        assert_eq!(repo.get_user(&survivor.tenant_id, &survivor.user_id).await.unwrap().unwrap().role, Role::Owner);
        assert!(repo.get_tenant(&a.tenant_id).await.unwrap().is_some());
    }
}

pub(crate) async fn co_owner_transfers(repo: &impl Repository) {
    let a = workspace(repo).await;
    let b = member(repo, &a.tenant_id, Role::Owner).await;
    let c = member(repo, &a.tenant_id, Role::Learner).await;
    let to = |p: &Principal| TransferOwnership { successor_user_id: p.user_id.clone() };
    // 已有 owner 不能作为接任者；拒绝不能消耗任一方的成员世代。
    assert!(matches!(repo.transfer_ownership(&a, &to(&b)).await, Err(CoreError::Conflict(_))));
    for p in [&a, &b] {
        assert_eq!(
            repo.membership_authorize(&p.tenant_id, &p.user_id, p.credential_generations().unwrap()).await.unwrap(),
            Role::Owner
        );
    }
    repo.transfer_ownership(&a, &to(&c)).await.unwrap();
    for (p, role, generation) in [(&a, Role::Admin, 1), (&b, Role::Owner, 0), (&c, Role::Owner, 1)] {
        assert_eq!(
            repo.membership_authorize(
                &p.tenant_id,
                &p.user_id,
                CredentialGenerations { account: 0, membership: generation }
            )
            .await
            .unwrap(),
            role
        );
        assert_eq!(repo.account_generation(&p.user_id).await.unwrap(), 0);
    }
    // 角色缓存不能让转移双方的旧凭据重新获得权限；另一共同所有者仍然有效。
    for stale in [&a, &c] {
        assert!(matches!(repo.transfer_ownership(stale, &to(&b)).await, Err(CoreError::Unauthorized(_))));
        assert!(repo.delete_workspace(stale, &confirmation(stale)).await.is_err());
        assert!(
            repo.membership_authorize(&stale.tenant_id, &stale.user_id, stale.credential_generations().unwrap())
                .await
                .is_err()
        );
    }
    let bad_account = Principal { auth_generation: Some(1), ..b.clone() };
    assert!(matches!(repo.transfer_ownership(&bad_account, &to(&a)).await, Err(CoreError::Unauthorized(_))));
    assert!(repo.account_erasure_jobs().await.unwrap().iter().all(|j| j.tenant_id.as_deref() != Some(&a.tenant_id)));

    // 两个共同所有者同时转移，分别覆盖独立接任者和争用同一接任者。
    for same_successor in [false, true] {
        let a = workspace(repo).await;
        let b = member(repo, &a.tenant_id, Role::Owner).await;
        let c = member(repo, &a.tenant_id, Role::Learner).await;
        let d = member(repo, &a.tenant_id, Role::Editor).await;
        let barrier = tokio::sync::Barrier::new(2);
        let transfer = |p: Principal, successor: Principal| {
            let barrier = &barrier;
            async move {
                barrier.wait().await;
                repo.transfer_ownership(&p, &to(&successor)).await
            }
        };
        let (left, right) = tokio::join!(
            transfer(a.clone(), c.clone()),
            transfer(b.clone(), if same_successor { c.clone() } else { d.clone() })
        );
        if same_successor {
            assert_ne!(left.is_ok(), right.is_ok());
            let rejected = if left.is_ok() { &right } else { &left };
            assert!(matches!(rejected, Err(CoreError::Conflict(_))));
        } else {
            left.as_ref().unwrap();
            right.as_ref().unwrap();
        }
        let expected = [
            (&a, if left.is_ok() { Role::Admin } else { Role::Owner }, i64::from(left.is_ok())),
            (&b, if right.is_ok() { Role::Admin } else { Role::Owner }, i64::from(right.is_ok())),
            (&c, Role::Owner, 1),
            (&d, if same_successor { Role::Editor } else { Role::Owner }, i64::from(!same_successor)),
        ];
        let mut owners = 0;
        for (p, role, generation) in expected {
            let actual = repo
                .membership_authorize(
                    &p.tenant_id,
                    &p.user_id,
                    CredentialGenerations { account: 0, membership: generation },
                )
                .await
                .unwrap();
            assert_eq!(actual, role);
            owners += usize::from(actual == Role::Owner);
            if generation > 0 {
                assert!(
                    repo.membership_authorize(&p.tenant_id, &p.user_id, p.credential_generations().unwrap())
                        .await
                        .is_err()
                );
            }
        }
        assert_eq!(owners, 2);
    }
}

// 捕获的账户或工作区主体始终绑定认证时的原始 access 摘要。
pub(crate) async fn opaque_fixture(
    repo: &impl Repository,
    boundary: &str,
) -> (Principal, AccountPrincipal, memoswish_core::session::SessionCredential, Principal, memoswish_protocol::Card) {
    use memoswish_core::session::*;
    let (tenant, card) = crate::content_conformance::seed(repo).await;
    let mut p = member(repo, &tenant, Role::Owner).await;
    let peer_role = if boundary == "transfer" { Role::Learner } else { Role::Owner };
    let peer = member(repo, &tenant, peer_role).await;
    let other = workspace(repo).await;
    repo.membership_join(&other.tenant_id, &p.user_id, Role::Editor).await.unwrap();
    let now = chrono::Utc::now().timestamp();
    let f = SessionFamily {
        id: memoswish_core::ids::new_id(),
        user_id: p.user_id.clone(),
        generation: 0,
        provenance: "password".into(),
        auth_time: now,
        expires_at: now + 3600,
        revoked: false,
    };
    let c = SessionCredential {
        access_hash: memoswish_core::ids::new_id(),
        refresh_hash: memoswish_core::ids::new_id(),
        assurance_hash: memoswish_core::ids::new_id(),
        session_id: f.id.clone(),
        tenant_id: (boundary != "close").then(|| tenant.clone()),
        membership_generation: (boundary != "close").then_some(0),
        expires_at: now + 600,
    };
    repo.session_issue(&f, &c, None).await.unwrap();
    let a = repo.session_access(&c.access_hash).await.unwrap();
    p.via = "session".into();
    p.session_access_hash = Some(a.credential.access_hash.clone());
    let account = AccountPrincipal {
        session_id: Some(a.family.id),
        session_access_hash: Some(a.credential.access_hash),
        legacy_issued_at: None,
        user_id: a.family.user_id,
        generation: a.family.generation,
    };
    (p, account, c, peer, card)
}

pub(crate) async fn opaque_command(
    repo: &impl Repository,
    boundary: &str,
    p: &Principal,
    a: &AccountPrincipal,
    peer: &Principal,
) -> memoswish_core::CoreResult<()> {
    match boundary {
        "leave" => repo.leave_workspace(p).await,
        "delete" => repo.delete_workspace(p, &confirmation(p)).await.map(|_| ()),
        "transfer" => repo.transfer_ownership(p, &TransferOwnership { successor_user_id: peer.user_id.clone() }).await,
        "close" => repo.close_account(a, &CloseAccount::default()).await.map(|_| ()),
        _ => unreachable!(),
    }
}

pub(crate) async fn opaque_snapshot(
    repo: &impl Repository,
    p: &Principal,
    peer: &Principal,
    card: &memoswish_protocol::Card,
) -> String {
    let mut jobs = repo.account_erasure_jobs().await.unwrap();
    jobs.sort_by(|a, b| a.id.cmp(&b.id));
    format!(
        "{:?}",
        (
            repo.get_tenant(&p.tenant_id).await.unwrap(),
            repo.account_by_id(&p.user_id).await.unwrap(),
            repo.account_by_id(&peer.user_id).await.unwrap(),
            repo.memberships(&p.user_id).await.unwrap(),
            repo.memberships(&peer.user_id).await.unwrap(),
            repo.get_card(&p.tenant_id, &card.id).await.unwrap(),
            repo.account_erased_tenant(&p.tenant_id).await.unwrap(),
            jobs,
        )
    )
}

pub(crate) async fn retire_opaque(
    repo: &impl Repository,
    retirement: &str,
    c: &memoswish_core::session::SessionCredential,
) {
    use memoswish_core::ids::new_id;
    match retirement {
        "logout" => assert!(repo.session_revoke(&c.access_hash, &c.session_id).await.unwrap()),
        "rotate" => {
            repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.unwrap();
        }
        "reuse" => assert!(matches!(
            repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await,
            Err(CoreError::Unauthorized(_))
        )),
        _ => unreachable!(),
    }
}

macro_rules! lifecycle_tests {
    ($repo:ty, $fault:literal, $unfault:literal) => {
        async fn lifecycle_suite(repo: &$repo) {
            crate::lifecycle_conformance::leave_and_fences(repo).await;
            crate::lifecycle_conformance::ownership_and_deletion(repo).await;
            crate::lifecycle_conformance::closure_is_atomic(repo).await;
            crate::lifecycle_conformance::concurrent_owners(repo).await;
            crate::lifecycle_conformance::co_owner_transfers(repo).await;
            s5_faults_and_history(repo).await;
            s5_delayed_learning(repo).await;
            s5_waiting_owner_recheck(repo).await;
            s5_oauth_revocation(repo).await;
            s5_transfer_rollback(repo).await;
            s5_global_identity_closure(repo).await;
            s5_issuance_barriers(repo).await;
            s5_close_join_and_identity_barriers(repo).await;
            s5_workspace_oidc_completion(repo).await;
            s5_opaque_credential_barriers(repo).await;
            s21b_logout_lifecycle_barriers(repo).await;
            s5_feed_credential_barriers(repo).await;
            s5_archived_feedback_credentials(repo).await;
            s5_feed_history_boundaries(repo).await;
            s5_feed_commit_before_lifecycle(repo).await;
            crate::lifecycle_conformance::s6_exports_and_legacy(repo).await;
            s6_legacy_rollback_and_classification(repo).await;
            s6_historical_export(repo).await;
            s6_legacy_cancel_and_duplicate(repo).await;
        }

        async fn s21b_logout_lifecycle_barriers(repo: &$repo) {
            use crate::learning::{TestGate, TestPoint};
            use crate::lifecycle_conformance::*;
            use memoswish_core::lifecycle::*;
            use memoswish_core::session::SessionRepo;

            for boundary in ["leave", "delete", "transfer", "close"] {
                for legacy in [false, true] {
                    for logout_first in [true, false] {
                        let (mut p, mut a, c, peer, card) = opaque_fixture(repo, boundary).await;
                        let family = repo.session_access(&c.access_hash).await.unwrap().family;
                        // 根会话与工作区凭据共属账户，但使用独立族建立注销入口。
                        let mut family = family;
                        family.id = memoswish_core::ids::new_id();
                        let root = crate::session_conformance::credential(&family, None);
                        repo.session_issue(&family, &root, None).await.unwrap();
                        if legacy {
                            p.via = "jwt".into();
                            p.session_access_hash = None;
                            p.legacy_issued_at = Some(family.auth_time);
                            a.session_id = None;
                            a.session_access_hash = None;
                            a.legacy_issued_at = Some(family.auth_time);
                        }
                        let before = opaque_snapshot(repo, &p, &peer, &card).await;
                        let gate = TestGate::new(TestPoint::BeforeCommit);
                        let mut first = repo.clone();
                        first.lifecycle_gate = Some(gate.clone());
                        let second = repo.clone();
                        let (principal, account, successor) = (p.clone(), a.clone(), peer.clone());
                        if logout_first {
                            let logout = tokio::spawn(async move { first.session_revoke_all(&root.access_hash).await });
                            gate.reached.notified().await;
                            let command = tokio::spawn(async move {
                                opaque_command(&second, boundary, &principal, &account, &successor).await
                            });
                            s5_observe_wait(repo).await;
                            gate.resume.add_permits(1);
                            logout.await.unwrap().unwrap();
                            assert!(matches!(command.await.unwrap(), Err(CoreError::Unauthorized(_))));
                            for authority in [AccountAuthority::Account(a.clone()), AccountAuthority::Workspace(p.clone())] {
                                assert!(matches!(repo.export_personal(&authority).await, Err(CoreError::Unauthorized(_))));
                                assert!(matches!(repo.revalidate_account_export(&authority).await, Err(CoreError::Unauthorized(_))));
                            }
                            assert!(matches!(repo.export_workspace(&p).await, Err(CoreError::Unauthorized(_))));
                            assert!(matches!(repo.legacy_close_account(&p).await, Err(CoreError::Unauthorized(_))));
                            assert_eq!(opaque_snapshot(repo, &p, &peer, &card).await, before);
                        } else {
                            let command = tokio::spawn(async move {
                                opaque_command(&first, boundary, &principal, &account, &successor).await
                            });
                            gate.reached.notified().await;
                            let logout = tokio::spawn(async move { second.session_revoke_all(&root.access_hash).await });
                            s5_observe_wait(repo).await;
                            gate.resume.add_permits(1);
                            command.await.unwrap().unwrap();
                            // 销户删除账户族；工作区命令保留账户根，随后注销可以继续完成。
                            assert_eq!(logout.await.unwrap().is_ok(), boundary != "close");
                        }
                        assert!(repo.session_access(&c.access_hash).await.is_err());
                        assert!(repo.legacy_session_authorize(&p.user_id, 0, family.auth_time, None, None).await.is_err());
                    }
                }
            }
        }

        async fn s5_feed_credential_barriers(repo: &$repo) {
            use crate::feed_issuance_conformance::{candidate, committed, continuation, first};
            use crate::learning::{TestGate, TestPoint};
            use crate::lifecycle_conformance::*;
            use memoswish_core::session::SessionRepo;
            // 同时覆盖首次签发、会话推进和重放续期；凭据失效不必改变账户或成员世代。
            for operation in ["first", "next", "replay"] {
                for retirement in ["logout", "rotate", "reuse", "expire", "missing", "mismatch"] {
                    let (mut p, _, c, peer, _) = opaque_fixture(repo, "leave").await;
                    if retirement == "reuse" {
                        let next = repo.session_rotate(&c.refresh_hash, &memoswish_core::ids::new_id(), &memoswish_core::ids::new_id(), &memoswish_core::ids::new_id(), 600).await.unwrap();
                        p.session_access_hash = Some(next.credential.access_hash);
                    }
                    let req = first();
                    let initial = candidate(repo, &p, &req, false).await;
                    let page = committed(repo.feed_issuance(&p, &req, Some(&initial)).await.unwrap());
                    let request = match operation { "first" => first(), "next" => continuation(&page), _ => req };
                    let pending = if operation == "replay" { None } else { Some(candidate(repo, &p, &request, false).await) };
                    let before: (i64, i64) = sqlx::query_as("SELECT issuance_revision,expires_at_ms FROM feed_sessions WHERE tenant_id=$1 AND user_id=$2 AND id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(&page.session_id).fetch_one(repo.pool()).await.unwrap();
                    let gate = TestGate::new(TestPoint::BeforeTransaction);
                    let mut paused = repo.clone(); paused.feed_gate = Some(gate.clone());
                    let mut captured = p.clone();
                    if retirement == "missing" { captured.session_access_hash = None; }
                    if retirement == "mismatch" { captured.user_id = peer.user_id.clone(); }
                    let writer = tokio::spawn(async move { paused.feed_issuance(&captured, &request, pending.as_ref()).await });
                    gate.reached.notified().await;
                    match retirement {
                        "expire" => { sqlx::query("UPDATE app_session_credentials SET expires_at=0 WHERE access_hash=$1").bind(&p.session_access_hash).execute(repo.pool()).await.unwrap(); }
                        "missing" | "mismatch" => {}
                        _ => retire_opaque(repo, retirement, &c).await,
                    }
                    gate.resume.add_permits(1);
                    assert!(matches!(writer.await.unwrap(), Err(CoreError::Unauthorized(_))), "{operation}/{retirement}");
                    let after: (i64, i64) = sqlx::query_as("SELECT issuance_revision,expires_at_ms FROM feed_sessions WHERE tenant_id=$1 AND user_id=$2 AND id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(&page.session_id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(after, before, "{operation}/{retirement}");
                    let receipts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feed_page_receipts WHERE tenant_id=$1 AND user_id=$2")
                        .bind(&p.tenant_id).bind(&p.user_id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(receipts, 1, "{operation}/{retirement}");
                }
            }
        }

        async fn s5_archived_feedback_credentials(repo: &$repo) {
            use crate::learning::{TestGate, TestPoint};
            use crate::lifecycle_conformance::*;
            use memoswish_core::session::SessionRepo;
            use memoswish_core::repo::LearningEventOutcome::*;
            // 原事件在删卡后可判重或报载荷冲突，但失效会话不得恢复历史回执或提交新事件。
            for retirement in ["logout", "rotate", "reuse", "expire", "missing"] {
                for operation in ["duplicate", "conflict", "fresh"] {
                    let (mut p, _, c, _, card) = opaque_fixture(repo, "leave").await;
                    let (mut rec, mut state) = crate::learning_conformance::seed(repo).await;
                    rec.tenant_id = p.tenant_id.clone(); rec.user_id = p.user_id.clone(); rec.event.card_id = card.id.clone();
                    state.tenant_id = p.tenant_id.clone(); state.user_id = p.user_id.clone(); state.card_id = card.id.clone();
                    repo.save_session(&FeedSession {
                        id: rec.session_id.clone(), tenant_id: p.tenant_id.clone(), user_id: p.user_id.clone(),
                        next_slot: 1, recent_card_ids: vec![], created_at: rec.received_at, updated_at: rec.received_at,
                    }).await.unwrap();
                    if retirement == "reuse" {
                        let next = repo.session_rotate(&c.refresh_hash, &memoswish_core::ids::new_id(), &memoswish_core::ids::new_id(), &memoswish_core::ids::new_id(), 600).await.unwrap();
                        p.session_access_hash = Some(next.credential.access_hash);
                    }
                    assert_eq!(repo.try_apply_learning_event_for_principal(&p, &rec, None, &state).await.unwrap(), Applied);
                    assert!(repo.delete_card(&p.tenant_id, &card.id).await.unwrap());
                    assert_eq!(repo.try_apply_learning_event_for_principal(&p, &rec, None, &state).await.unwrap(), Duplicate);
                    let before = repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap();
                    if operation == "conflict" { rec.event.double_tapped = !rec.event.double_tapped; }
                    if operation == "fresh" { rec.event.event_id.push_str("fresh"); }
                    if retirement == "missing" { p.session_access_hash = None; }
                    let gate = TestGate::new(TestPoint::BeforeTransaction);
                    let mut paused = repo.clone(); paused.learning_gate = Some(gate.clone());
                    let captured = p.clone();
                    let writer = tokio::spawn(async move { paused.try_apply_learning_event_for_principal(&captured, &rec, None, &state).await });
                    gate.reached.notified().await;
                    match retirement {
                        "expire" => { sqlx::query("UPDATE app_session_credentials SET expires_at=0 WHERE access_hash=$1").bind(&p.session_access_hash).execute(repo.pool()).await.unwrap(); }
                        "missing" => {}
                        _ => retire_opaque(repo, retirement, &c).await,
                    }
                    gate.resume.add_permits(1);
                    assert_eq!(writer.await.unwrap().unwrap(), MissingScope, "{operation}/{retirement}");
                    let after = repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap();
                    for table in ["memory_states", "feedback_events"] { assert_eq!(after[table], before[table], "{operation}/{retirement}/{table}"); }
                }
            }
        }

        async fn s5_feed_history_boundaries(repo: &$repo) {
            use memoswish_core::lifecycle::*;
            use crate::feed_issuance_conformance::{candidate, committed, continuation, first};
            use crate::learning::{TestGate, TestPoint};
            use crate::lifecycle_conformance::*;
            use memoswish_core::repo::LearningEventOutcome::*;
            // 内容归档仍允许回执恢复，但生命周期擦除必须清掉相应学习历史和私有快照。
            for boundary in ["leave", "delete", "close", "exclusive", "transfer"] {
                let (rec, state) = crate::learning_conformance::seed(repo).await;
                sqlx::query("UPDATE tenant_memberships SET role='owner' WHERE tenant_id=$1 AND user_id=$2")
                    .bind(&rec.tenant_id).bind(&rec.user_id).execute(repo.pool()).await.unwrap();
                let p = Principal { tenant_id:rec.tenant_id.clone(), user_id:rec.user_id.clone(), via:"jwt".into(), legacy_issued_at:Some(chrono::Utc::now().timestamp()), ..Principal::local_owner("jwt") };
                let peer = if boundary == "exclusive" { None } else {
                    Some(member(repo, &p.tenant_id, if boundary == "transfer" { Role::Learner } else { Role::Owner }).await)
                };
                let g = p.credential_generations().unwrap();
                assert_eq!(repo.try_apply_learning_event_authorized(&rec, None, &state, g).await.unwrap(), Applied);
                let req = first();
                let initial = candidate(repo, &p, &req, false).await;
                let page = committed(repo.feed_issuance(&p, &req, Some(&initial)).await.unwrap());
                let mut peer_page = None;
                if let Some(peer) = &peer {
                    repo.upsert_memory(&MemoryState { user_id:peer.user_id.clone(), ..state.clone() }).await.unwrap();
                    repo.insert_feedback(&FeedbackEventRecord { user_id:peer.user_id.clone(), ..rec.clone() }).await.unwrap();
                    let request = first();
                    peer_page = Some(committed(repo.feed_issuance(peer, &request, Some(&candidate(repo, peer, &request, false).await)).await.unwrap()));
                }
                let other = crate::feed_issuance_conformance::seed(repo).await;
                let other_req = first();
                let other_page = committed(repo.feed_issuance(&other, &other_req, Some(&candidate(repo, &other, &other_req, false).await)).await.unwrap());
                assert!(repo.delete_card(&p.tenant_id, &rec.event.card_id).await.unwrap());
                assert_eq!(committed(repo.feed_issuance(&p, &req, None).await.unwrap()), page);
                assert_eq!(repo.try_apply_learning_event_authorized(&rec, None, &state, g).await.unwrap(), Duplicate);
                let mut changed = rec.clone(); changed.event.double_tapped = !changed.event.double_tapped;
                assert_eq!(repo.try_apply_learning_event_authorized(&changed, None, &state, g).await.unwrap(), PayloadConflict);
                changed.event.event_id.push_str("fresh");
                assert_eq!(repo.try_apply_learning_event_authorized(&changed, None, &state, g).await.unwrap(), MissingCard);
                assert!(repo.list_memory(&p.tenant_id, &p.user_id).await.unwrap().is_empty());
                assert_eq!(repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap()["memory_states"].as_array().unwrap().len(), 1);
                let next = continuation(&page);
                let pending = candidate(repo, &p, &next, true).await;
                let gate = TestGate::new(TestPoint::BeforeTransaction);
                let mut paused = repo.clone(); paused.feed_gate = Some(gate.clone());
                let captured = p.clone();
                let writer = tokio::spawn(async move { paused.feed_issuance(&captured, &next, Some(&pending)).await });
                gate.reached.notified().await;
                match boundary {
                    "leave" => { repo.leave_workspace(&p).await.unwrap(); repo.membership_join(&p.tenant_id, &p.user_id, Role::Learner).await.unwrap(); }
                    "delete" => { repo.delete_workspace(&p, &confirmation(&p)).await.unwrap(); }
                    "close" | "exclusive" => {
                        repo.close_account(&account(&p), &CloseAccount { confirmed_exclusive_workspaces: if boundary == "exclusive" { vec![p.tenant_id.clone()] } else { vec![] } }).await.unwrap();
                    }
                    _ => repo.transfer_ownership(&p, &TransferOwnership { successor_user_id:peer.as_ref().unwrap().user_id.clone() }).await.unwrap(),
                }
                gate.resume.add_permits(1);
                assert!(matches!(writer.await.unwrap(), Err(CoreError::Unauthorized(_))), "{boundary}");
                assert!(matches!(repo.feed_issuance(&p, &req, None).await, Err(CoreError::Unauthorized(_))), "{boundary}");
                assert_eq!(repo.try_apply_learning_event_authorized(&rec, None, &state, g).await.unwrap(), MissingScope);
                assert_eq!(repo.try_apply_learning_event_authorized(&changed, None, &state, g).await.unwrap(), MissingScope);
                let retained = boundary == "transfer";
                assert_eq!(repo.get_memory(&p.tenant_id, &p.user_id, &state.card_id).await.unwrap().is_some(), retained);
                for table in ["feedback_events", "feed_page_receipts"] {
                    let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=$1 AND user_id=$2"))
                        .bind(&p.tenant_id).bind(&p.user_id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(count, i64::from(retained), "{boundary}/{table}");
                }
                if let Some(peer) = &peer {
                    assert_eq!(repo.get_memory(&p.tenant_id, &peer.user_id, &state.card_id).await.unwrap().is_some(), boundary != "delete");
                    assert_eq!(repo.get_session(&p.tenant_id, &peer.user_id, &peer_page.unwrap().session_id).await.unwrap().is_some(), boundary != "delete");
                }
                let tombstone: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deleted_card_ids WHERE tenant_id=$1 AND card_id=$2")
                    .bind(&p.tenant_id).bind(&state.card_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(tombstone, 1, "{boundary}");
                assert_eq!(committed(repo.feed_issuance(&other, &other_req, None).await.unwrap()), other_page);
                if boundary == "leave" {
                    let current = Principal { membership_generation:Some(1), role:Role::Learner, ..p.clone() };
                    assert_eq!(repo.try_apply_learning_event_authorized(&rec, None, &state, current.credential_generations().unwrap()).await.unwrap(), MissingCard);
                    assert!(repo.insert_card(&p.tenant_id, &page.items[0].card).await.is_err());
                }
            }
        }

        async fn s5_feed_commit_before_lifecycle(repo: &$repo) {
            use memoswish_core::lifecycle::*;
            use crate::feed_issuance_conformance::{candidate, committed, first};
            use crate::learning::{TestGate, TestPoint};
            use crate::lifecycle_conformance::*;
            // 已持注册锁的发页先完整提交，随后生命周期事务级联清理全部回执。
            for boundary in ["leave", "delete", "close"] {
                let mut p = crate::feed_issuance_conformance::seed(repo).await;
                p.via = "jwt".into();
                p.legacy_issued_at = Some(chrono::Utc::now().timestamp());
                let owner = member(repo, &p.tenant_id, Role::Owner).await;
                let req = first();
                let pending = candidate(repo, &p, &req, false).await;
                let gate = TestGate::new(TestPoint::BeforeCommit);
                let mut paused = repo.clone(); paused.feed_gate = Some(gate.clone());
                let captured = p.clone(); let request = req.clone();
                let writer = tokio::spawn(async move { paused.feed_issuance(&captured, &request, Some(&pending)).await });
                gate.reached.notified().await;
                let other = repo.clone(); let scope = p.clone();
                let eraser = tokio::spawn(async move {
                    match boundary {
                        "leave" => other.leave_workspace(&Principal {via:"jwt".into(), ..scope}).await,
                        "delete" => other.delete_workspace(&owner, &confirmation(&owner)).await.map(|_| ()),
                        _ => other.close_account(&account(&scope), &CloseAccount::default()).await.map(|_| ()),
                    }
                });
                s5_observe_wait(repo).await;
                gate.resume.add_permits(1);
                committed(writer.await.unwrap().unwrap());
                eraser.await.unwrap().unwrap();
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feed_page_receipts WHERE tenant_id=$1 AND user_id=$2")
                    .bind(&p.tenant_id).bind(&p.user_id).fetch_one(repo.pool()).await.unwrap();
                assert_eq!(count, 0, "{boundary}");
                assert!(matches!(repo.feed_issuance(&p, &req, None).await, Err(CoreError::Unauthorized(_))));
            }
        }

        async fn s5_opaque_credential_barriers(repo: &$repo) {
            use crate::lifecycle_conformance::*;
            use memoswish_core::session::SessionRepo;
            for boundary in ["leave", "delete", "transfer", "close"] {
                for retirement in ["logout", "rotate", "reuse"] {
                    let (mut p, mut a, original, peer, card) = opaque_fixture(repo, boundary).await;
                    // 重放撤销必须针对刚旋转出的仍有效主体，而非已消费父凭据。
                    if retirement == "reuse" {
                        let next = repo
                            .session_rotate(
                                &original.refresh_hash,
                                &memoswish_core::ids::new_id(),
                                &memoswish_core::ids::new_id(),
                                &memoswish_core::ids::new_id(),
                                600,
                            )
                            .await
                            .unwrap();
                        p.session_access_hash = Some(next.credential.access_hash.clone());
                        a.session_access_hash = Some(next.credential.access_hash);
                    }
                    let before = opaque_snapshot(repo, &p, &peer, &card).await;
                    let gate = crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
                    let mut retiring = repo.clone();
                    retiring.lifecycle_gate = Some(gate.clone());
                    let c = original.clone();
                    let retirement_task = tokio::spawn(async move { retire_opaque(&retiring, retirement, &c).await });
                    gate.reached.notified().await;
                    let waiting = repo.clone();
                    let (waiting_principal, waiting_account, successor) = (p.clone(), a.clone(), peer.clone());
                    let mutation = tokio::spawn(async move {
                        opaque_command(&waiting, boundary, &waiting_principal, &waiting_account, &successor).await
                    });
                    s5_observe_wait(repo).await;
                    gate.resume.add_permits(1);
                    retirement_task.await.unwrap();
                    assert!(
                        matches!(mutation.await.unwrap(), Err(CoreError::Unauthorized(_))),
                        "{retirement}-first {boundary}"
                    );
                    assert_eq!(
                        opaque_snapshot(repo, &p, &peer, &card).await,
                        before,
                        "{retirement}-first {boundary} preservation"
                    );

                    // 相反提交顺序允许已持锁且凭据有效的命令完成，随后旧权限不能继续使用。
                    let (mut p, mut a, c, peer, _) = opaque_fixture(repo, boundary).await;
                    if retirement == "reuse" {
                        let next = repo
                            .session_rotate(
                                &c.refresh_hash,
                                &memoswish_core::ids::new_id(),
                                &memoswish_core::ids::new_id(),
                                &memoswish_core::ids::new_id(),
                                600,
                            )
                            .await
                            .unwrap();
                        p.session_access_hash = Some(next.credential.access_hash.clone());
                        a.session_access_hash = Some(next.credential.access_hash);
                    }
                    let gate = crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
                    let mut first = repo.clone();
                    first.lifecycle_gate = Some(gate.clone());
                    let (waiting_principal, waiting_account, successor) = (p.clone(), a.clone(), peer.clone());
                    let mutation = tokio::spawn(async move {
                        opaque_command(&first, boundary, &waiting_principal, &waiting_account, &successor).await
                    });
                    gate.reached.notified().await;
                    let waiting = repo.clone();
                    let credential = c.clone();
                    let retirement_task = tokio::spawn(async move {
                        if retirement == "logout" {
                            waiting
                                .session_revoke(&credential.access_hash, &credential.session_id)
                                .await
                                .map(|_| ())
                        } else {
                            waiting
                                .session_rotate(
                                    &credential.refresh_hash,
                                    &memoswish_core::ids::new_id(),
                                    &memoswish_core::ids::new_id(),
                                    &memoswish_core::ids::new_id(),
                                    600,
                                )
                                .await
                                .map(|_| ())
                        }
                    });
                    s5_observe_wait(repo).await;
                    gate.resume.add_permits(1);
                    mutation.await.unwrap().unwrap();
                    // 工作区命令已改变成员世代，CloseAccount 已删除族，旧凭据的撤销/旋转均被拒绝。
                    assert!(retirement_task.await.unwrap().is_err(), "{boundary}-first {retirement}");
                    assert!(repo.session_access(&c.access_hash).await.is_err());
                    match boundary {
                        "delete" => assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_none()),
                        "close" => assert!(repo.account_by_id(&p.user_id).await.unwrap().is_none()),
                        "leave" => assert!(repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().is_none()),
                        "transfer" => assert_eq!(
                            repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().unwrap().role,
                            Role::Admin
                        ),
                        _ => unreachable!(),
                    }
                }
                for invalid in ["access-expired", "family-expired", "missing", "foreign", "wrong-scope"] {
                    let (mut p, mut a, c, peer, card) = opaque_fixture(repo, boundary).await;
                    let before = opaque_snapshot(repo, &p, &peer, &card).await;
                    match invalid {
                        "access-expired" => {
                            sqlx::query("UPDATE app_session_credentials SET expires_at=0 WHERE access_hash=$1")
                                .bind(&c.access_hash)
                                .execute(repo.pool())
                                .await
                                .unwrap();
                        }
                        "family-expired" => {
                            sqlx::query("UPDATE app_sessions SET auth_time=-2,expires_at=-1 WHERE id=$1")
                                .bind(&c.session_id)
                                .execute(repo.pool())
                                .await
                                .unwrap();
                        }
                        "missing" => {
                            p.session_access_hash = None;
                            a.session_access_hash = None;
                        }
                        "foreign" => {
                            let (_, other, _, _, _) = opaque_fixture(repo, boundary).await;
                            p.session_access_hash = other.session_access_hash.clone();
                            a.session_access_hash = other.session_access_hash;
                        }
                        "wrong-scope" => {
                            let mut other = c.clone();
                            other.access_hash = memoswish_core::ids::new_id();
                            other.refresh_hash = memoswish_core::ids::new_id();
                            if boundary == "close" {
                                other.tenant_id = Some(p.tenant_id.clone());
                                other.membership_generation = Some(0);
                            } else {
                                other.tenant_id = None;
                                other.membership_generation = None;
                            }
                            let f = repo.session_access(&c.access_hash).await.unwrap().family;
                            // 在同族另一个凭据域插入测试夹具，拒绝混用账户与工作区授权。
                            sqlx::query("INSERT INTO app_session_credentials(access_hash,refresh_hash,assurance_hash,session_id,tenant_id,membership_generation,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
                            .bind(&other.access_hash).bind(&other.refresh_hash).bind(&other.assurance_hash).bind(&f.id)
                            .bind(&other.tenant_id).bind(other.membership_generation).bind(other.expires_at).execute(repo.pool()).await.unwrap();
                            p.session_access_hash = Some(other.access_hash.clone());
                            a.session_access_hash = Some(other.access_hash);
                        }
                        _ => unreachable!(),
                    }
                    assert!(
                        matches!(
                            opaque_command(repo, boundary, &p, &a, &peer).await,
                            Err(CoreError::Unauthorized(_))
                        ),
                        "{invalid} {boundary}"
                    );
                    // foreign 夹具增加了独立账户，但本场景保护的账户、内容及任务保持原样。
                    assert_eq!(
                        opaque_snapshot(repo, &p, &peer, &card).await,
                        before,
                        "{invalid} {boundary} preservation"
                    );
                }
            }
        }

        async fn s6_legacy_cancel_and_duplicate(repo: &$repo) {
            use memoswish_core::lifecycle::LifecycleRepo;
            use crate::lifecycle_conformance::*;
            let p=workspace(repo).await;
            let peer=member(repo,&p.tenant_id,Role::Learner).await;
            let before=repo.account_erasure_jobs().await.unwrap().len();
            let gate=crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
            let mut cancelling=repo.clone();cancelling.lifecycle_gate=Some(gate.clone());
            let captured=p.clone();
            let task=tokio::spawn(async move {cancelling.legacy_close_account(&captured).await});
            gate.reached.notified().await;
            task.abort();assert!(task.await.unwrap_err().is_cancelled());
            assert!(repo.account_by_id(&p.user_id).await.unwrap().is_some());
            assert!(repo.get_user(&p.tenant_id,&peer.user_id).await.unwrap().is_some());
            assert_eq!(repo.account_erasure_jobs().await.unwrap().len(),before);
            let (a,b)=tokio::join!(repo.legacy_close_account(&p),repo.legacy_close_account(&p));
            assert_eq!(usize::from(a.is_ok())+usize::from(b.is_ok()),1);
            assert_eq!(repo.account_erasure_jobs().await.unwrap().len(),before+2);
            assert!(repo.account_by_id(&peer.user_id).await.unwrap().is_some());
        }

        async fn s6_historical_export(repo: &$repo) {
            use memoswish_core::CredentialGenerations;
            use memoswish_core::lifecycle::*;
            use crate::lifecycle_conformance::*;
            let (user, identity) = crate::identity_conformance::unlink_fixture(repo, true).await;
            repo.identity_resolve(&identity, None, true, Some("S6_PROVIDER_CIPHERTEXT"), Some(CredentialGenerations {account:0,membership:0}), None).await.unwrap();
            sqlx::query("UPDATE federated_identities SET tenant_id='historical-hint' WHERE user_id=$1").bind(&user.id).execute(repo.pool()).await.unwrap();
            sqlx::query("WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<1001) INSERT INTO memory_states(tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures) SELECT $1,$2,CAST(n AS TEXT),1,1,0,0,0 FROM seq")
                .bind(&user.tenant_id).bind(&user.id).execute(repo.pool()).await.unwrap();
            let a=AccountAuthority::Account(AccountPrincipal {user_id:user.id.clone(),generation:0,session_id:None,session_access_hash:None,legacy_issued_at:Some(chrono::Utc::now().timestamp())});
            let exported=repo.export_personal(&a).await.unwrap();
            assert_eq!(exported.identities.len(),1);
            assert_eq!(exported.identities[0].subject,identity.subject);
            assert_eq!(exported.workspaces[0].data["memory_states"].len(),1001);
            assert!(!serde_json::to_string(&exported).unwrap().contains("S6_PROVIDER_CIPHERTEXT"));
            // 物化后撤销先完成时，最终披露屏障拒绝该原始主体。
            let p=Principal {tenant_id:user.tenant_id.clone(),user_id:user.id.clone(),role:Role::Owner,scopes:None,via:"jwt".into(),auth_generation:Some(0),membership_generation:Some(0),session_access_hash:None,legacy_issued_at:Some(chrono::Utc::now().timestamp())};
            let authority=AccountAuthority::Workspace(p.clone());
            repo.revalidate_account_export(&authority).await.unwrap();
            repo.delete_workspace(&p,&confirmation(&p)).await.unwrap();
            assert!(repo.revalidate_account_export(&authority).await.is_err());
            // 根会话不依赖已删除工作区，零成员导出继续可用。
            assert!(repo.export_personal(&a).await.unwrap().workspaces.is_empty());
        }

        async fn s6_legacy_rollback_and_classification(repo: &$repo) {
            use memoswish_core::lifecycle::LifecycleRepo;
            use crate::lifecycle_conformance::*;
            let p = workspace(repo).await;
            let peer = member(repo, &p.tenant_id, Role::Learner).await;
            let jobs = repo.account_erasure_jobs().await.unwrap().len();
            sqlx::raw_sql($fault).execute(repo.pool()).await.unwrap();
            assert!(repo.legacy_close_account(&p).await.is_err());
            sqlx::raw_sql($unfault).execute(repo.pool()).await.unwrap();
            assert_eq!(repo.account_erasure_jobs().await.unwrap().len(), jobs);
            assert!(!repo.account_erased_tenant(&p.tenant_id).await.unwrap());
            assert!(repo.get_user(&p.tenant_id, &peer.user_id).await.unwrap().is_some());
            assert!(repo.account_by_id(&p.user_id).await.unwrap().is_some());
            let b = workspace(repo).await;
            let mut tx = repo.pool().begin().await.unwrap();
            sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.unwrap();
            let delayed = repo.clone();
            let captured = p.clone();
            let task = tokio::spawn(async move {delayed.legacy_close_account(&captured).await});
            s5_observe_wait(repo).await;
            sqlx::query("INSERT INTO membership_generations(tenant_id,user_id,generation) VALUES($1,$2,0)").bind(&b.tenant_id).bind(&p.user_id).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO tenant_memberships(tenant_id,user_id,role,generation,revision,joined_at) VALUES($1,$2,'learner',0,0,$3)").bind(&b.tenant_id).bind(&p.user_id).bind(chrono::Utc::now()).execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
            assert!(matches!(task.await.unwrap(), Err(CoreError::UseExplicitCommand)));
            assert_eq!(repo.account_erasure_jobs().await.unwrap().len(), jobs);
            assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_some());
        }

        async fn s5_faults_and_history(repo: &$repo) {
            use crate::lifecycle_conformance::*;
            use memoswish_core::assets::*;
            use memoswish_core::jobs::AssetJobRepo;
            use memoswish_core::lifecycle::*;
            let p = workspace(repo).await;
            let member = member(repo, &p.tenant_id, Role::Editor).await;
            let intent = repo
                .prepare_asset(&member, "retained-job", &crate::asset_conformance::spec(), 3)
                .await
                .unwrap();
            sqlx::query("INSERT INTO quota_operations(tenant_id,operation_id,metric,period,amount,state) VALUES($1,$2,'tts_chars','2026-11',7,'reserved')")
                        .bind(&p.tenant_id).bind(&intent.id).execute(repo.pool()).await.unwrap();
            let jobs_before = repo.account_erasure_jobs().await.unwrap().len();
            sqlx::raw_sql($fault).execute(repo.pool()).await.unwrap();
            assert!(
                repo.delete_workspace(
                    &p,
                    &DeleteWorkspace {
                        confirmed_tenant_id: p.tenant_id.clone()
                    }
                )
                .await
                .is_err()
            );
            assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_some());
            assert!(!repo.account_erased_tenant(&p.tenant_id).await.unwrap());
            assert_eq!(repo.account_erasure_jobs().await.unwrap().len(), jobs_before);
            assert!(repo.get_user(&p.tenant_id, &member.user_id).await.unwrap().is_some());
            repo.leave_workspace(&member).await.unwrap();
            assert!(
                repo.close_account(
                    &AccountPrincipal {
                        session_id: None, session_access_hash: None, legacy_issued_at: Some(chrono::Utc::now().timestamp()),
                        user_id: p.user_id.clone(),
                        generation: 0
                    },
                    &CloseAccount {
                        confirmed_exclusive_workspaces: vec![p.tenant_id.clone()]
                    }
                )
                .await
                .is_err()
            );
            assert!(repo.get_tenant(&p.tenant_id).await.unwrap().is_some());
            assert!(repo.account_by_id(&p.user_id).await.unwrap().is_some());
            assert_eq!(repo.account_erasure_jobs().await.unwrap().len(), jobs_before);
            sqlx::raw_sql($unfault).execute(repo.pool()).await.unwrap();
            assert!(repo.asset_job(&p.tenant_id, &intent.id).await.unwrap().is_some());
            let history: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM membership_generations WHERE tenant_id=$1 AND user_id=$2")
                    .bind(&p.tenant_id)
                    .bind(&member.user_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert_eq!(history, 1);
            repo.delete_workspace(
                &p,
                &DeleteWorkspace {
                    confirmed_tenant_id: p.tenant_id.clone(),
                },
            )
            .await
            .unwrap();
            assert!(repo.asset_job(&p.tenant_id, &intent.id).await.unwrap().is_some());
            let reservation: String =
                sqlx::query_scalar("SELECT state FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2")
                    .bind(&p.tenant_id)
                    .bind(&intent.id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert_eq!(reservation, "reserved");
            let history: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM membership_generations WHERE tenant_id=$1 AND user_id=$2")
                    .bind(&p.tenant_id)
                    .bind(&member.user_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert_eq!(history, 1);
        }

        async fn s5_delayed_learning(repo: &$repo) {
            use crate::lifecycle_conformance::*;
            use memoswish_core::lifecycle::LifecycleRepo;
            let (record, state) = crate::learning_conformance::seed(repo).await;
            member(repo, &record.tenant_id, Role::Owner).await;
            let p = Principal {
                tenant_id: record.tenant_id.clone(),
                user_id: record.user_id.clone(),
                role: Role::Learner,
                scopes: None,
                via: "jwt".into(), session_access_hash: None, legacy_issued_at: Some(chrono::Utc::now().timestamp()),
                auth_generation: Some(0),
                membership_generation: Some(0),
            };
            let g = p.credential_generations().unwrap();
            let gate = crate::learning::TestGate::new(crate::learning::TestPoint::BeforeTransaction);
            let mut paused = repo.clone();
            paused.learning_gate = Some(gate.clone());
            let tid = record.tenant_id.clone();
            let uid = record.user_id.clone();
            let writer = tokio::spawn(async move {
                paused
                    .try_apply_learning_event_authorized(&record, None, &state, g)
                    .await
            });
            gate.reached.notified().await;
            repo.leave_workspace(&p).await.unwrap();
            assert_eq!(repo.membership_join(&tid, &uid, Role::Learner).await.unwrap(), 1);
            gate.resume.add_permits(1);
            assert_eq!(writer.await.unwrap().unwrap(), LearningEventOutcome::MissingScope);
            assert!(repo.list_memory(&tid, &uid).await.unwrap().is_empty());
        }

        async fn s5_waiting_owner_recheck(repo: &$repo) {
            use crate::lifecycle_conformance::*;
            use memoswish_core::lifecycle::*;
            let a = workspace(repo).await;
            let b = member(repo, &a.tenant_id, Role::Owner).await;
            let mut controller = repo.pool().begin().await.unwrap();
            sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                .execute(&mut *controller)
                .await
                .unwrap();
            let waiting_repo = repo.clone();
            let request = a.clone();
            let waiter = tokio::spawn(async move { waiting_repo.leave_workspace(&request).await });
            s5_observe_wait(repo).await;
            sqlx::query("DELETE FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2")
                .bind(&b.tenant_id)
                .bind(&b.user_id)
                .execute(&mut *controller)
                .await
                .unwrap();
            controller.commit().await.unwrap();
            assert!(matches!(waiter.await.unwrap(), Err(CoreError::Conflict(_))));
            assert!(repo.get_user(&a.tenant_id, &a.user_id).await.unwrap().is_some());
            let successor = member(repo, &a.tenant_id, Role::Learner).await;
            let mut controller = repo.pool().begin().await.unwrap();
            sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                .execute(&mut *controller)
                .await
                .unwrap();
            let waiting_repo = repo.clone();
            let request = a.clone();
            let command = TransferOwnership {
                successor_user_id: successor.user_id.clone(),
            };
            let waiter = tokio::spawn(async move { waiting_repo.transfer_ownership(&request, &command).await });
            s5_observe_wait(repo).await;
            sqlx::query("DELETE FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2")
                .bind(&successor.tenant_id)
                .bind(&successor.user_id)
                .execute(&mut *controller)
                .await
                .unwrap();
            controller.commit().await.unwrap();
            assert!(matches!(waiter.await.unwrap(), Err(CoreError::Conflict(_))));
            assert_eq!(
                repo.get_user(&a.tenant_id, &a.user_id).await.unwrap().unwrap().role,
                Role::Owner
            );
        }

        async fn s5_oauth_revocation(repo: &$repo) {
            use crate::lifecycle_conformance::*;
            use memoswish_core::lifecycle::LifecycleRepo;
            use memoswish_core::oauth::*;
            let owner = workspace(repo).await;
            let p = member(repo, &owner.tenant_id, Role::Owner).await;
            let user = repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().unwrap();
            let client = OAuthClient {
                id: memoswish_core::ids::new_id(),
                name: "S5".into(),
                redirect_uris: vec!["https://client.example/callback".into()],
                grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                scopes: vec!["content:read".into()],
                auth_method: "none".into(),
                secret_hash: None,
                created_at: 0,
                expires_at: i64::MAX,
            };
            repo.oauth_register(&client).await.unwrap();
            let code = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 1).await;
            let refresh = crate::oauth_conformance::token(&code, "refresh");
            let access = crate::oauth_conformance::token(&code, "access");
            repo.oauth_redeem(&p.tenant_id, &code, &[refresh.clone(), access.clone()], 10)
                .await
                .unwrap();
            let pending = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 1).await;
            repo.leave_workspace(&p).await.unwrap();
            repo.membership_join(&p.tenant_id, &p.user_id, Role::Owner)
                .await
                .unwrap();
            assert!(repo.oauth_token(&access.hash).await.unwrap().is_none());
            assert!(
                !repo
                    .oauth_redeem(&p.tenant_id, &pending, &[], 10)
                    .await
                    .is_ok_and(|accepted| accepted)
            );
            assert!(repo.oauth_client(&client.id).await.unwrap().is_some());
            assert!(
                repo.issue_api_token(&ApiTokenRecord {
                    id: memoswish_core::ids::new_id(),
                    tenant_id: p.tenant_id.clone(),
                    user_id: p.user_id.clone(),
                    name: "stale".into(),
                    token_hash: memoswish_core::ids::new_id(),
                    generations: p.credential_generations().unwrap(),
                    scopes: vec!["*".into()],
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                    last_used_at: None,
                    revoked: false
                })
                .await
                .is_err()
            );
        }

        async fn s5_transfer_rollback(repo: &$repo) {
            use crate::lifecycle_conformance::*;
            use memoswish_core::lifecycle::*;
            let owner = workspace(repo).await;
            let peer = member(repo, &owner.tenant_id, Role::Owner).await;
            let successor = member(repo, &owner.tenant_id, Role::Learner).await;
            // 接任者已经提升后，原 owner 的历史世代耗尽使整个事务失败。
            sqlx::query("INSERT INTO membership_generations(tenant_id,user_id,generation) VALUES($1,$2,$3)")
                .bind(&owner.tenant_id)
                .bind(&owner.user_id)
                .bind(i64::MAX)
                .execute(repo.pool())
                .await
                .unwrap();
            assert!(matches!(
                repo.transfer_ownership(
                    &owner,
                    &TransferOwnership {
                        successor_user_id: successor.user_id.clone()
                    }
                )
                .await,
                Err(CoreError::Conflict(_))
            ));
            assert_eq!(
                repo.membership_authorize(
                    &owner.tenant_id,
                    &owner.user_id,
                    owner.credential_generations().unwrap()
                )
                .await
                .unwrap(),
                Role::Owner
            );
            assert_eq!(
                repo.membership_authorize(
                    &successor.tenant_id,
                    &successor.user_id,
                    successor.credential_generations().unwrap()
                )
                .await
                .unwrap(),
                Role::Learner
            );
            let history: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM membership_generations WHERE tenant_id=$1 AND user_id=$2")
                    .bind(&successor.tenant_id)
                    .bind(&successor.user_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert_eq!(history, 1);
            assert_eq!(
                repo.membership_authorize(&peer.tenant_id, &peer.user_id, peer.credential_generations().unwrap())
                    .await
                    .unwrap(),
                Role::Owner
            );
        }

        async fn s5_global_identity_closure(repo: &$repo) {
            use memoswish_core::identity::IdentityRepo;
            use memoswish_core::lifecycle::*;
            let (user, identity) = crate::identity_conformance::unlink_fixture(repo, true).await;
            let g = memoswish_core::CredentialGenerations {
                account: 0,
                membership: 0,
            };
            repo.identity_resolve(&identity, None, true, Some("sealed-s5-credential"), Some(g), None)
                .await
                .unwrap();
            // 历史租户提示不决定全局身份的清理范围。
            sqlx::query("UPDATE federated_identities SET tenant_id='historic-workspace' WHERE user_id=$1")
                .bind(&user.id)
                .execute(repo.pool())
                .await
                .unwrap();
            let jobs = repo
                .close_account(
                    &AccountPrincipal {
                        session_id: None, session_access_hash: None, legacy_issued_at: Some(chrono::Utc::now().timestamp()),
                        user_id: user.id.clone(),
                        generation: 0,
                    },
                    &CloseAccount {
                        confirmed_exclusive_workspaces: vec![user.tenant_id.clone()],
                    },
                )
                .await
                .unwrap();
            let global = jobs.iter().find(|j| j.tenant_id.is_none()).unwrap();
            assert_eq!(global.credentials.len(), 1);
            assert_eq!(global.credentials[0].1, "sealed-s5-credential");
            let hash = memoswish_core::ids::sha256_hex(format!("{}\0{}", identity.issuer, identity.subject).as_bytes());
            let fences: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_unlink_fences WHERE identity_hash=$1")
                .bind(hash)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(fences, 1);
            let identities: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM federated_identities WHERE user_id=$1")
                .bind(&user.id)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(identities, 0);
        }

        async fn s5_issuance_barriers(repo: &$repo) {
            use crate::lifecycle_conformance::*;
            use memoswish_core::lifecycle::*;
            use memoswish_core::oauth::*;
            for boundary in ["leave", "delete", "close"] {
                for operation in ["api", "login", "consent", "redeem", "refresh"] {
                    let owner = workspace(repo).await;
                    let p = member(repo, &owner.tenant_id, Role::Owner).await;
                    let user = repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().unwrap();
                    let client = OAuthClient {
                        id: memoswish_core::ids::new_id(),
                        name: "S5 race".into(),
                        redirect_uris: vec!["https://client.example/callback".into()],
                        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                        scopes: vec!["content:read".into()],
                        auth_method: "none".into(),
                        secret_hash: None,
                        created_at: 0,
                        expires_at: i64::MAX,
                    };
                    repo.oauth_register(&client).await.unwrap();
                    let code = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 1).await;
                    let refresh = crate::oauth_conformance::token(&code, "refresh");
                    repo.oauth_redeem(&p.tenant_id, &code, std::slice::from_ref(&refresh), 10)
                        .await
                        .unwrap();
                    let redeem = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 1).await;
                    let (request, session) =
                        crate::oauth_conformance::pending_authorization(repo, &user, &client, i64::MAX - 1).await;
                    let consent = AuthorizationCode {
                        hash: memoswish_core::ids::new_id(),
                        grant: OAuthGrant {
                            id: memoswish_core::ids::new_id(),
                            tenant_id: p.tenant_id.clone(),
                            user_id: p.user_id.clone(),
                            client_id: client.id.clone(),
                            resource: request.resource.clone(),
                            scopes: request.scopes.clone(),
                            expires_at: i64::MAX - 1,
                            generations: p.credential_generations().unwrap(),
                        },
                        redirect_uri: request.redirect_uri.clone(),
                        challenge: request.challenge.clone(),
                        expires_at: i64::MAX - 1,
                    };
                    let anonymous = BrowserSession {
                        hash: memoswish_core::ids::new_id(),
                        tenant_id: None,
                        user_id: None,
                        auth_time: 0,
                        auth_method: "anonymous".into(),
                        generations: None,
                        expires_at: i64::MAX - 1,
                    };
                    let login = AuthorizationRequest {
                        id: memoswish_core::ids::new_id(),
                        browser_hash: anonymous.hash.clone(),
                        ..request.clone()
                    };
                    repo.oauth_begin(&anonymous, &login).await.unwrap();
                    let api = ApiTokenRecord {
                        id: memoswish_core::ids::new_id(),
                        tenant_id: p.tenant_id.clone(),
                        user_id: p.user_id.clone(),
                        name: "S5 race".into(),
                        token_hash: memoswish_core::ids::new_id(),
                        generations: p.credential_generations().unwrap(),
                        scopes: vec!["content:read".into()],
                        created_at: chrono::Utc::now(),
                        expires_at: None,
                        last_used_at: None,
                        revoked: false,
                    };
                    let gate = crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
                    let mut mutator = repo.clone();
                    mutator.lifecycle_gate = Some(gate.clone());
                    let mutation_p = p.clone();
                    let mutation = tokio::spawn(async move {
                        match boundary {
                            "leave" => mutator.leave_workspace(&mutation_p).await,
                            "delete" => mutator
                                .delete_workspace(
                                    &mutation_p,
                                    &DeleteWorkspace {
                                        confirmed_tenant_id: mutation_p.tenant_id.clone(),
                                    },
                                )
                                .await
                                .map(|_| ()),
                            "close" => mutator
                                .close_account(
                                    &AccountPrincipal {
                                        session_id: None, session_access_hash: None, legacy_issued_at: Some(chrono::Utc::now().timestamp()),
                                        user_id: mutation_p.user_id.clone(),
                                        generation: 0,
                                    },
                                    &CloseAccount::default(),
                                )
                                .await
                                .map(|_| ()),
                            _ => unreachable!(),
                        }
                    });
                    gate.reached.notified().await;
                    let issuer = repo.clone();
                    let tid = p.tenant_id.clone();
                    let issuance = tokio::spawn(async move {
                        match operation {
                            "api" => issuer.issue_api_token(&api).await.map(|_| true),
                            "login" => issuer.oauth_login(&tid, &login, &session, 10).await,
                            "consent" => issuer.oauth_consent(&tid, &request, Some(&consent), 10).await,
                            "redeem" => {
                                issuer
                                    .oauth_redeem(&tid, &redeem, &[crate::oauth_conformance::token(&redeem, "access")], 10)
                                    .await
                            }
                            "refresh" => {
                                issuer
                                    .oauth_rotate(&tid, &refresh, &[crate::oauth_conformance::token(&code, "refresh")], 10)
                                    .await
                            }
                            _ => unreachable!(),
                        }
                    });
                    s5_observe_wait(repo).await;
                    gate.resume.add_permits(1);
                    mutation.await.unwrap().unwrap();
                    assert!(
                        !issuance.await.unwrap().is_ok_and(|accepted| accepted),
                        "{boundary}-first {operation}"
                    );
                    assert!(repo.oauth_client(&client.id).await.unwrap().is_some());
                }
            }
        }

        async fn s5_close_join_and_identity_barriers(repo: &$repo) {
            use crate::lifecycle_conformance::*;
            use memoswish_core::identity::IdentityRepo;
            use memoswish_core::lifecycle::*;
            for operation in ["join", "workspace-complete", "account-complete", "unlink"] {
                let (user, identity) = crate::identity_conformance::unlink_fixture(repo, true).await;
                let shared = workspace(repo).await;
                let g = memoswish_core::CredentialGenerations {
                    account: 0,
                    membership: 0,
                };
                repo.identity_recent_auth(
                    &user.tenant_id,
                    &user.id,
                    g,
                    "recent",
                    chrono::Utc::now().timestamp() + 300,
                )
                .await
                .unwrap();
                let attempt = crate::identity_conformance::claimed_attempt(repo, &identity, false).await;
                repo.identity_resolve(&identity, None, false, None, None, Some(&attempt.id))
                    .await
                    .unwrap();
                let gate = crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
                let mut mutator = repo.clone();
                mutator.lifecycle_gate = Some(gate.clone());
                let uid = user.id.clone();
                let tenant = user.tenant_id.clone();
                let close = tokio::spawn(async move {
                    mutator
                        .close_account(
                            &AccountPrincipal {
                                session_id: None, session_access_hash: None, legacy_issued_at: Some(chrono::Utc::now().timestamp()),
                                user_id: uid,
                                generation: 0,
                            },
                            &CloseAccount {
                                confirmed_exclusive_workspaces: vec![tenant],
                            },
                        )
                        .await
                });
                gate.reached.notified().await;
                let contender = repo.clone();
                let request = user.clone();
                let worker = tokio::spawn(async move {
                    let now = chrono::Utc::now().timestamp();
                    match operation {
                        "join" => contender
                            .membership_join(&shared.tenant_id, &request.id, Role::Learner)
                            .await
                            .map(|_| ()),
                        "workspace-complete" => {
                            contender
                                .identity_complete(&attempt.id, &request.tenant_id, &request.id, g, "new-session", now)
                                .await
                        }
                        "account-complete" => {
                            contender
                                .identity_complete_account(
                                    &attempt.id,
                                    &request.tenant_id,
                                    &request.id,
                                    0,
                                    "new-session",
                                    now,
                                )
                                .await
                        }
                        "unlink" => contender
                            .identity_unlink(&request.tenant_id, &request.id, g, "google", "recent", now, &[])
                            .await
                            .map(|_| ()),
                        _ => unreachable!(),
                    }
                });
                s5_observe_wait(repo).await;
                gate.resume.add_permits(1);
                close.await.unwrap().unwrap();
                assert!(worker.await.unwrap().is_err(), "close-first {operation}");
                assert!(repo.account_by_id(&user.id).await.unwrap().is_none());
                assert!(repo.memberships(&user.id).await.unwrap().is_empty());
            }
        }

        async fn s5_workspace_oidc_completion(repo: &$repo) {
            use crate::lifecycle_conformance::*;
            use memoswish_core::identity::IdentityRepo;
            use memoswish_core::lifecycle::*;
            for boundary in ["leave", "delete"] {
                let (user, identity) = crate::identity_conformance::unlink_fixture(repo, true).await;
                member(repo, &user.tenant_id, Role::Owner).await;
                let generations = memoswish_core::CredentialGenerations {
                    account: 0,
                    membership: 0,
                };
                let attempt = crate::identity_conformance::claimed_attempt(repo, &identity, false).await;
                repo.identity_resolve(&identity, None, false, None, None, Some(&attempt.id))
                    .await
                    .unwrap();
                let gate = crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
                let mut mutator = repo.clone();
                mutator.lifecycle_gate = Some(gate.clone());
                let principal = Principal {
                    tenant_id: user.tenant_id.clone(),
                    user_id: user.id.clone(),
                    role: Role::Owner,
                    scopes: None,
                    via: "jwt".into(), session_access_hash: None, legacy_issued_at: Some(chrono::Utc::now().timestamp()),
                    auth_generation: Some(0),
                    membership_generation: Some(0),
                };
                let mutation = tokio::spawn(async move {
                    if boundary == "leave" {
                        mutator.leave_workspace(&principal).await
                    } else {
                        mutator
                            .delete_workspace(
                                &principal,
                                &DeleteWorkspace {
                                    confirmed_tenant_id: principal.tenant_id.clone(),
                                },
                            )
                            .await
                            .map(|_| ())
                    }
                });
                gate.reached.notified().await;
                let contender = repo.clone();
                let completion_user = user.clone();
                let attempt_id = attempt.id.clone();
                let completion = tokio::spawn(async move {
                    contender
                        .identity_complete(
                            &attempt_id,
                            &completion_user.tenant_id,
                            &completion_user.id,
                            generations,
                            "old-workspace-session",
                            chrono::Utc::now().timestamp(),
                        )
                        .await
                });
                s5_observe_wait(repo).await;
                gate.resume.add_permits(1);
                mutation.await.unwrap().unwrap();
                assert!(completion.await.unwrap().is_err());
                if boundary == "leave" {
                    repo.membership_join(&user.tenant_id, &user.id, Role::Owner)
                        .await
                        .unwrap();
                    assert!(
                        repo.identity_complete(
                            &attempt.id,
                            &user.tenant_id,
                            &user.id,
                            memoswish_core::CredentialGenerations {
                                account: 0,
                                membership: 1
                            },
                            "upgraded-workspace-session",
                            chrono::Utc::now().timestamp()
                        )
                        .await
                        .is_err()
                    );
                }
                // 工作区授权退役不撤销全局登录，原一次性续接仍可完成账户认证。
                repo.identity_complete_account(
                    &attempt.id,
                    &user.tenant_id,
                    &user.id,
                    0,
                    "account-session",
                    chrono::Utc::now().timestamp(),
                )
                .await
                .unwrap();
            }
        }
    };
}
pub(crate) use lifecycle_tests;

/// S6 跨工作区个人范围、保留历史及兼容删除的共同断言。
pub(crate) async fn s6_exports_and_legacy(repo: &impl Repository) {
    let (rec, state) = crate::learning_conformance::seed(repo).await;
    repo.upsert_memory(&state).await.unwrap();
    repo.insert_feedback(&rec).await.unwrap();
    let owner = member(repo, &rec.tenant_id, Role::Owner).await;
    let p = Principal {
        tenant_id: rec.tenant_id.clone(),
        user_id: rec.user_id.clone(),
        role: Role::Learner,
        ..owner.clone()
    };
    let other = workspace(repo).await;
    repo.membership_join(&other.tenant_id, &p.user_id, Role::Editor).await.unwrap();
    let peer_state = MemoryState { user_id: owner.user_id.clone(), ..state.clone() };
    repo.upsert_memory(&peer_state).await.unwrap();
    let page = issued_delivery(repo, &p).await;
    let peer_page = issued_delivery(repo, &owner).await;
    repo.delete_card(&p.tenant_id, &state.card_id).await.unwrap();
    let authority = AccountAuthority::Workspace(p.clone());
    let exported = repo.export_personal(&authority).await.unwrap();
    assert_eq!(exported.workspaces.len(), 2);
    assert_eq!(exported.account.user_id, p.user_id);
    let personal = exported.workspaces.iter().find(|w| w.tenant_id == p.tenant_id).unwrap();
    assert_eq!(personal.data["memory_states"].len(), 1);
    assert_eq!(personal.data["memory_states"][0]["card_id"], state.card_id);
    assert_eq!(personal.data["feedback_events"].len(), 1);
    let deliveries = &personal.data["feed_deliveries"];
    assert_eq!(deliveries.len(), page.items.len());
    assert_eq!(deliveries[0]["session_id"], page.session_id);
    let record =
        repo.get_delivery(&p.tenant_id, &p.user_id, &page.session_id, page.items[0].slot).await.unwrap().unwrap();
    assert_eq!(deliveries[0]["body"], serde_json::to_value(record).unwrap());
    assert!(!serde_json::to_string(deliveries).unwrap().contains(&peer_page.session_id));
    assert!(!personal.data.contains_key("feed_page_receipts"));
    assert!(!personal.data.contains_key("cards"));
    let raw = serde_json::to_string(&exported).unwrap();
    for secret in ["password_hash", "access_hash", "refresh_hash", "assurance_hash", "preserved-password-hash"] {
        assert!(!raw.contains(secret));
    }
    let shared = repo.export_workspace(&p).await.unwrap();
    assert_eq!(shared.tenant_id, p.tenant_id);
    for personal_table in
        ["users", "memory_states", "feedback_events", "federated_identities", "app_sessions", "api_tokens"]
    {
        assert!(!shared.data.contains_key(personal_table));
    }
    let jobs_before = repo.account_erasure_jobs().await.unwrap().len();
    assert!(matches!(repo.legacy_close_account(&p).await, Err(CoreError::UseExplicitCommand)));
    assert_eq!(repo.account_erasure_jobs().await.unwrap().len(), jobs_before);
    assert!(repo.account_by_id(&p.user_id).await.unwrap().is_some());
    let mut delegated = p.clone();
    delegated.via = "api_token".into();
    delegated.scopes = Some(vec!["*".into()]);
    assert!(repo.export_personal(&AccountAuthority::Workspace(delegated.clone())).await.is_err());
    assert!(
        repo.close_account_authorized(&AccountAuthority::Workspace(delegated), &CloseAccount::default()).await.is_err()
    );
    repo.leave_workspace(&p).await.unwrap();
    assert!(repo.revalidate_account_export(&authority).await.is_err());
    assert!(repo.revalidate_workspace_export(&p, None).await.is_err());
    let remaining = Principal { tenant_id: other.tenant_id.clone(), role: Role::Editor, ..p.clone() };
    repo.legacy_close_account(&remaining).await.unwrap();
    assert!(repo.get_tenant(&other.tenant_id).await.unwrap().is_some());
    assert!(repo.account_by_id(&p.user_id).await.unwrap().is_none());
    assert!(repo.account_by_id(&owner.user_id).await.unwrap().is_some());

    let a = workspace(repo).await;
    let survivor = member(repo, &a.tenant_id, Role::Learner).await;
    let b = workspace(repo).await;
    repo.membership_join(&b.tenant_id, &survivor.user_id, Role::Editor).await.unwrap();
    let orphan = member(repo, &a.tenant_id, Role::Learner).await;
    let jobs = repo.legacy_close_account(&a).await.unwrap();
    assert_eq!(jobs.len(), 2);
    assert!(repo.get_tenant(&a.tenant_id).await.unwrap().is_none());
    assert!(repo.account_by_id(&a.user_id).await.unwrap().is_none());
    for member in [&survivor, &orphan] {
        assert!(repo.account_by_id(&member.user_id).await.unwrap().is_some());
        let exported = repo.export_personal(&AccountAuthority::Account(account(member))).await.unwrap();
        assert_eq!(exported.workspaces.len(), if member.user_id == orphan.user_id { 0 } else { 1 });
    }
    repo.close_account_authorized(&AccountAuthority::Account(account(&orphan)), &CloseAccount::default())
        .await
        .unwrap();
    assert!(repo.legacy_close_account(&a).await.is_err());
}
