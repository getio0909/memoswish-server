//! 身份唯一性、事务消费、账户导出和两级擦除在两个数据库共享验证。
use chrono::Utc;
use memoswish_core::{CoreError, CredentialGenerations, Role, identity::*, ids::new_id, repo::*};
use memoswish_protocol::examples;

const INITIAL: CredentialGenerations = CredentialGenerations { account: 0, membership: 0 };

pub async fn run<R: Repository>(repo: &R) {
    let now = Utc::now().timestamp();
    let tid = new_id();
    let other_tid = new_id();
    for id in [&tid, &other_tid] {
        repo.upsert_tenant(&TenantRecord {
            id: id.clone(),
            name: "Identity conformance".into(),
            plan: "team".into(),
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    }
    let owner = UserRecord {
        id: new_id(),
        tenant_id: tid.clone(),
        email: format!("{}@example.com", new_id()),
        display_name: "Owner".into(),
        password_hash: "private-password-hash".into(),
        role: Role::Owner,
        created_at: Utc::now(),
    };
    let mut member = owner.clone();
    member.id = new_id();
    member.email = format!("{}@example.com", new_id());
    member.role = Role::Learner;
    let mut other = owner.clone();
    other.id = new_id();
    other.email = format!("{}@example.com", new_id());
    other.tenant_id = other_tid.clone();
    for u in [&owner, &member, &other] {
        repo.insert_user(u).await.unwrap();
    }
    let mut i = FederatedIdentity {
        client_id: "client".into(),
        issuer: format!("https://issuer-{}.example", new_id()),
        subject: new_id(),
        provider: "generic".into(),
        tenant_id: tid.clone(),
        user_id: member.id.clone(),
        email: None,
        email_verified: false,
        display_name: Some("Identity".into()),
        created_at: now,
        authenticated_at: now,
    };
    assert_eq!(
        repo.identity_resolve(&i, None, true, Some("encrypted-only"), Some(INITIAL), None).await.unwrap(),
        (tid.clone(), member.id.clone(), 0)
    );
    let subject = i.subject.clone();
    i.tenant_id = other_tid.clone();
    i.user_id = other.id.clone();
    assert!(matches!(
        repo.identity_resolve(&i, None, true, None, Some(INITIAL), None).await,
        Err(CoreError::Conflict(_))
    ));
    i.tenant_id = tid.clone();
    i.user_id = member.id.clone();
    // 首次并发登录在全局身份锁内只创建一个租户和用户。
    let mut candidates = Vec::new();
    for _ in 0..2 {
        let t = TenantRecord { id: new_id(), name: "New".into(), plan: "free".into(), created_at: Utc::now() };
        let u = UserRecord {
            id: new_id(),
            tenant_id: t.id.clone(),
            email: format!("{}@example.com", new_id()),
            ..owner.clone()
        };
        let identity = FederatedIdentity {
            subject: format!("new-{subject}"),
            tenant_id: t.id.clone(),
            user_id: u.id.clone(),
            ..i.clone()
        };
        candidates.push((t, u, identity));
    }
    let ((t1, u1, i1), (t2, u2, i2)) = (&candidates[0], &candidates[1]);
    let (a, b) = tokio::join!(
        repo.identity_resolve(i1, Some((t1, u1)), false, None, None, None),
        repo.identity_resolve(i2, Some((t2, u2)), false, None, None, None)
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert_ne!(
        repo.get_tenant(&t1.id).await.unwrap().is_some(),
        repo.get_tenant(&t2.id).await.unwrap().is_some(),
        "no orphan tenant from losing provision"
    );
    let attempt = LoginAttempt {
        link_legacy_issued_at: Some(now),
        link_access_hash: None,
        id: new_id(),
        provider: "generic".into(),
        state_hash: new_id(),
        launch_hash: new_id(),
        browser_hash: String::new(),
        nonce: new_id(),
        verifier_ciphertext: "encrypted-pkce".into(),
        client_id: "client".into(),
        return_uri: "dev.learntok.app:/auth/callback".into(),
        app_state: "app-state".into(),
        challenge: "challenge".into(),
        native: false,
        link_tenant: Some(tid.clone()),
        link_user: Some(member.id.clone()),
        link_generation: Some(0),
        link_membership_generation: Some(0),
        link_session_hash: Some("session".into()),
        expires_at: now + 300,
    };
    repo.identity_attempt_insert(&attempt).await.unwrap();
    assert!(!repo.identity_launch(&attempt.id, "wrong", "browser", now).await.unwrap());
    assert!(repo.identity_launch(&attempt.id, &attempt.launch_hash, "browser", now).await.unwrap());
    assert!(!repo.identity_launch(&attempt.id, &attempt.launch_hash, "browser", now).await.unwrap());
    assert!(!repo.identity_claim(&attempt.id, "other", "browser", false, now).await.unwrap());
    assert!(!repo.identity_claim(&attempt.id, "generic", "wrong", false, now).await.unwrap());
    let (a, b) = tokio::join!(
        repo.identity_claim(&attempt.id, "generic", "browser", false, now),
        repo.identity_claim(&attempt.id, "generic", "browser", false, now)
    );
    assert_ne!(a.unwrap(), b.unwrap());
    let h = LoginHandoff {
        attempt_id: None,
        generation: 0,
        pending_identity: None,
        link_session_hash: None,
        hash: new_id(),
        provider: "generic".into(),
        tenant_id: tid.clone(),
        user_id: member.id.clone(),
        challenge: "challenge".into(),
        expires_at: now + 60,
    };
    repo.identity_handoff_insert(&h).await.unwrap();
    assert!(repo.identity_handoff_consume(&h.hash, "generic", "wrong", now).await.unwrap().is_none());
    let (a, b) = tokio::join!(
        repo.identity_handoff_consume(&h.hash, "generic", "challenge", now),
        repo.identity_handoff_consume(&h.hash, "generic", "challenge", now)
    );
    assert_eq!([a.unwrap(), b.unwrap()].iter().filter(|v| v.is_some()).count(), 1);
    let mut exp = h.clone();
    exp.hash = new_id();
    exp.expires_at = now;
    repo.identity_handoff_insert(&exp).await.unwrap();
    assert!(repo.identity_handoff_consume(&exp.hash, "generic", "challenge", now).await.unwrap().is_none());
    let mut deck = examples::sample_deck();
    deck.id = new_id();
    let mut card = examples::sample_card();
    card.id = new_id();
    card.deck_id = deck.id.clone();
    repo.insert_deck_with_cards(&tid, &deck, &[card.clone()]).await.unwrap();
    repo.insert_deck_with_cards(&other_tid, &deck, &[card.clone()]).await.unwrap();
    let mut bgm = examples::sample_bgm_track();
    bgm.id = new_id();
    repo.save_bgm(Some(&tid), &bgm, None).await.unwrap();
    repo.add_usage(&tid, "cards", "2026-11", 5).await.unwrap();
    let mut mem = MemoryState {
        tenant_id: tid.clone(),
        user_id: member.id.clone(),
        card_id: card.id.clone(),
        stability: 1.0,
        difficulty: 5.0,
        reps: 1,
        lapses: 0,
        exposures: 1,
        last_review: Some(Utc::now()),
        due: None,
        starred: true,
        last_rating: Some(3),
    };
    for u in [&owner, &member] {
        mem.user_id = u.id.clone();
        repo.upsert_memory(&mem).await.unwrap();
        let token = ApiTokenRecord {
            generations: memoswish_core::CredentialGenerations { account: 0, membership: 0 },
            id: new_id(),
            tenant_id: tid.clone(),
            user_id: u.id.clone(),
            name: "token".into(),
            token_hash: format!("secret-hash-{}", new_id()),
            scopes: vec!["*".into()],
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
            revoked: false,
        };
        repo.insert_api_token(&token).await.unwrap();
        let event = FeedbackEventRecord {
            tenant_id: tid.clone(),
            user_id: u.id.clone(),
            session_id: new_id(),
            event: examples::sample_feedback_batch().events[0].clone(),
            rating: Some(3),
            received_at: Utc::now(),
            application: None,
        };
        repo.insert_feedback(&event).await.unwrap();
        repo.save_session(&FeedSession {
            id: event.session_id.clone(),
            tenant_id: tid.clone(),
            user_id: u.id.clone(),
            next_slot: 1,
            recent_card_ids: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .await
        .unwrap();
        crate::oauth_conformance::run(repo, u).await;
    }
    repo.identity_recent_auth(&tid, &member.id, INITIAL, "secret-session-hash", now + 300).await.unwrap();
    let member_export = repo.account_export(&tid, &member.id, false).await.unwrap();
    for table in ["users", "api_tokens", "memory_states", "feedback_events", "feed_sessions", "federated_identities"] {
        assert_eq!(member_export[table].as_array().unwrap().len(), 1, "{table}");
    }
    assert!(!member_export["oauth_grants"].as_array().unwrap().is_empty());
    assert_eq!(member_export["oauth_grants"][0]["metadata"]["resource"], "https://learn.example/mcp");
    let serialized = member_export.to_string();
    for forbidden in [
        "password_hash",
        "secret-hash-",
        "token_hash",
        "encrypted-only",
        "secret-session-hash",
        "encrypted-pkce",
        "csrf_hash",
        "challenge",
    ] {
        assert!(!serialized.contains(forbidden), "export leaked {forbidden}");
    }
    repo.identity_event(&i.issuer, &i.subject, "email-event", "email-disabled", now, now).await.unwrap();
    assert_eq!(repo.identity_generation(&tid, &member.id).await.unwrap(), 0);
    repo.identity_event(&i.issuer, &i.subject, "revoked-event", "consent-revoked", now, now).await.unwrap();
    assert_eq!(repo.identity_generation(&tid, &member.id).await.unwrap(), 1);
    repo.identity_event(&i.issuer, &i.subject, "revoked-event", "consent-revoked", now, now).await.unwrap();
    repo.identity_event(&i.issuer, &i.subject, "old-revoked-event", "consent-revoked", now - 1, now).await.unwrap();
    assert_eq!(repo.identity_generation(&tid, &member.id).await.unwrap(), 1);
    // 使用当前账户世代，单独验证上游撤销时间边界。
    assert!(
        repo.identity_resolve(&i, None, true, None, Some(CredentialGenerations { account: 1, membership: 0 }), None)
            .await
            .is_err()
    );
    i.authenticated_at = now + 1;
    assert!(
        repo.identity_resolve(&i, None, true, Some("encrypted-only"), Some(INITIAL), None).await.is_err(),
        "revoked native/link generation cannot be upgraded"
    );
    let resolved = repo
        .identity_resolve(
            &i,
            None,
            true,
            Some("encrypted-only"),
            Some(CredentialGenerations { account: 1, membership: 0 }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(resolved.2, 1, "handoff receives the transaction-validated generation");
    repo.identity_event(&i.issuer, &i.subject, "deleted-event", "account-deleted", now + 2, now + 2).await.unwrap();
    i.authenticated_at = now + 3;
    // 使用当前账户世代，保留永久删除身份无法恢复的原断言。
    assert!(
        repo.identity_resolve(&i, None, true, None, Some(CredentialGenerations { account: 2, membership: 0 }), None)
            .await
            .is_err()
    );
    let mut extra = i.clone();
    extra.subject = new_id();
    repo.identity_resolve(
        &extra,
        None,
        true,
        Some("encrypted-only"),
        Some(CredentialGenerations { account: 2, membership: 0 }),
        None,
    )
    .await
    .unwrap();
    assert!(repo.account_erase(&other_tid, &member.id, false).await.is_err());
    let job = repo.account_erase(&tid, &member.id, false).await.unwrap();
    assert!(!job.purge_assets);
    assert_eq!(job.credentials.len(), 1);
    assert!(repo.get_user(&tid, &member.id).await.unwrap().is_none());
    assert!(repo.get_user(&tid, &owner.id).await.unwrap().is_some());
    let erased = repo.account_export(&tid, &member.id, false).await.unwrap();
    for table in [
        "users",
        "api_tokens",
        "memory_states",
        "feedback_events",
        "feed_sessions",
        "federated_identities",
        "oauth_grants",
        "oauth_token_metadata",
    ] {
        assert!(erased[table].as_array().unwrap().is_empty(), "member erasure left {table}");
    }
    assert!(repo.identity_attempt(&attempt.id, false).await.unwrap().is_none());
    assert!(!repo.identity_check_recent(&tid, &member.id, INITIAL, "secret-session-hash", now).await.unwrap());
    assert_eq!(repo.get_usage(&tid, "cards", "2026-11").await.unwrap(), 5);
    assert!(repo.get_deck(&tid, &deck.id).await.unwrap().is_some());
    mem.user_id = member.id.clone();
    assert!(repo.upsert_memory(&mem).await.is_err(), "late member write must fail");
    assert!(repo.account_erasure_finish(&job.id).await.is_err());
    let owner_job = repo.account_erase(&tid, &owner.id, true).await.unwrap();
    assert!(owner_job.purge_assets);
    assert!(repo.get_tenant(&tid).await.unwrap().is_none());
    assert!(repo.get_user(&tid, &owner.id).await.unwrap().is_none());
    let erased = repo.account_export(&tid, &owner.id, true).await.unwrap();
    for table in [
        "users",
        "api_tokens",
        "decks",
        "cards",
        "bgm_tracks",
        "usage_counters",
        "memory_states",
        "feedback_events",
        "feed_sessions",
        "federated_identities",
        "oauth_grants",
        "oauth_token_metadata",
    ] {
        assert!(erased[table].as_array().unwrap().is_empty(), "tenant erasure left {table}");
    }
    assert!(repo.account_erased_tenant(&tid).await.unwrap());
    assert!(!repo.account_erased_tenant(&other_tid).await.unwrap());
    assert!(repo.insert_deck(&tid, &deck).await.is_err());
    assert!(repo.add_usage(&tid, "cards", "2026-11", 1).await.is_err());
    assert!(repo.get_user(&other_tid, &other.id).await.unwrap().is_some());
    assert!(repo.get_card(&other_tid, &card.id).await.unwrap().is_some());
    assert!(repo.account_erasure_finish(&owner_job.id).await.is_err());
    unlink_conformance(repo).await;
    unlink_pending_conformance(repo).await;
    unlink_alias_conformance(repo).await;
    unlink_usable_conformance(repo).await;
    repo.identity_cleanup(now + 400).await.unwrap();
    assert!(repo.identity_handoff_consume(&exp.hash, "generic", "challenge", now).await.unwrap().is_none());
}

async fn unlink_conformance<R: Repository>(repo: &R) {
    let now = Utc::now().timestamp();
    let tenant = TenantRecord { id: new_id(), name: "Unlink".into(), plan: "team".into(), created_at: Utc::now() };
    repo.upsert_tenant(&tenant).await.unwrap();
    let user = UserRecord {
        id: new_id(),
        tenant_id: tenant.id.clone(),
        email: format!("{}@example.com", new_id()),
        display_name: "Social only".into(),
        password_hash: String::new(),
        role: Role::Owner,
        created_at: Utc::now(),
    };
    repo.insert_user(&user).await.unwrap();
    for provider in ["google", "apple"] {
        let identity = FederatedIdentity {
            client_id: "client".into(),
            issuer: format!("https://{}.example/{}", provider, new_id()),
            subject: new_id(),
            provider: provider.into(),
            tenant_id: tenant.id.clone(),
            user_id: user.id.clone(),
            email: None,
            email_verified: false,
            display_name: None,
            created_at: now,
            authenticated_at: now,
        };
        repo.identity_resolve(&identity, None, true, Some("encrypted-revoke"), Some(INITIAL), None).await.unwrap();
    }
    let clients = repo
        .identity_list(&tenant.id, &user.id)
        .await
        .unwrap()
        .into_iter()
        .map(|i| (i.provider, i.issuer, vec!["client".into()]))
        .collect::<Vec<_>>();
    assert_eq!(repo.identity_list(&tenant.id, &user.id).await.unwrap().len(), 2);
    assert!(repo.identity_list("other-tenant", &user.id).await.unwrap().is_empty());
    assert!(matches!(
        repo.identity_unlink(&tenant.id, &user.id, INITIAL, "google", "missing", now, &clients).await,
        Err(CoreError::Forbidden(_))
    ));
    repo.identity_recent_auth(&tenant.id, &user.id, INITIAL, "recent", now + 300).await.unwrap();
    assert!(matches!(
        repo.identity_unlink(&tenant.id, &user.id, INITIAL, "google", "recent", now + 300, &clients).await,
        Err(CoreError::Forbidden(_))
    ));
    // 并发删除两种登录方式时，只允许一个事务提交，另一个必须保留最后登录方式。
    let (a, b) = tokio::join!(
        repo.identity_unlink(&tenant.id, &user.id, INITIAL, "google", "recent", now, &clients),
        repo.identity_unlink(&tenant.id, &user.id, INITIAL, "apple", "recent", now, &clients),
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(if a.is_err() { a } else { b }, Err(CoreError::Conflict(_))));
    assert_eq!(repo.identity_list(&tenant.id, &user.id).await.unwrap().len(), 1);
    let job = repo
        .account_erasure_jobs()
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.tenant_id.as_deref() == Some(tenant.id.as_str()))
        .unwrap();
    assert!(!job.purge_assets);
    assert_eq!(job.credentials.len(), 1);
    assert!(repo.get_user(&tenant.id, &user.id).await.unwrap().is_some());
    assert!(repo.account_erasure_finish(&job.id).await.is_err());
}

pub(crate) async fn unlink_fixture<R: Repository>(repo: &R, password: bool) -> (UserRecord, FederatedIdentity) {
    let tenant =
        TenantRecord { id: new_id(), name: "Unlink fences".into(), plan: "team".into(), created_at: Utc::now() };
    repo.upsert_tenant(&tenant).await.unwrap();
    let user = UserRecord {
        id: new_id(),
        tenant_id: tenant.id,
        email: format!("{}@example.com", new_id()),
        display_name: "Owner".into(),
        password_hash: if password { "password-hash".into() } else { String::new() },
        role: Role::Owner,
        created_at: Utc::now(),
    };
    repo.insert_user(&user).await.unwrap();
    let identity = FederatedIdentity {
        client_id: "browser-client".into(),
        issuer: format!("https://{}.example", new_id()),
        subject: new_id(),
        provider: "google".into(),
        tenant_id: user.tenant_id.clone(),
        user_id: user.id.clone(),
        email: None,
        email_verified: false,
        display_name: None,
        created_at: Utc::now().timestamp(),
        authenticated_at: Utc::now().timestamp(),
    };
    repo.identity_resolve(&identity, None, true, None, Some(INITIAL), None).await.unwrap();
    (user, identity)
}

pub(crate) async fn claimed_attempt<R: Repository>(repo: &R, identity: &FederatedIdentity, link: bool) -> LoginAttempt {
    let a = LoginAttempt {
        link_legacy_issued_at: link.then(|| Utc::now().timestamp()),
        link_access_hash: None,
        id: new_id(),
        provider: identity.provider.clone(),
        state_hash: new_id(),
        launch_hash: new_id(),
        browser_hash: String::new(),
        nonce: new_id(),
        verifier_ciphertext: "sealed".into(),
        client_id: identity.client_id.clone(),
        return_uri: "dev.learntok.app:/auth/callback".into(),
        app_state: new_id(),
        challenge: new_id(),
        native: false,
        link_tenant: link.then(|| identity.tenant_id.clone()),
        link_user: link.then(|| identity.user_id.clone()),
        link_generation: link.then_some(0),
        link_membership_generation: link.then_some(0),
        link_session_hash: link.then(|| "recent".into()),
        expires_at: Utc::now().timestamp() + 300,
    };
    repo.identity_attempt_insert(&a).await.unwrap();
    assert!(repo.identity_launch(&a.id, &a.launch_hash, "browser", Utc::now().timestamp()).await.unwrap());
    assert!(repo.identity_claim(&a.id, &a.provider, "browser", false, Utc::now().timestamp()).await.unwrap());
    a
}

async fn unlink_pending_conformance<R: Repository>(repo: &R) {
    let (user, identity) = unlink_fixture(repo, true).await;
    let now = Utc::now().timestamp();
    let recent = new_id();
    let unresolved = claimed_attempt(repo, &identity, false).await;
    let resolved = claimed_attempt(repo, &identity, false).await;
    repo.identity_resolve(&identity, None, false, None, None, Some(&resolved.id)).await.unwrap();
    let linking = claimed_attempt(repo, &identity, true).await;
    let handoff = LoginHandoff {
        attempt_id: Some(resolved.id.clone()),
        generation: 0,
        pending_identity: None,
        link_session_hash: None,
        hash: new_id(),
        provider: identity.provider.clone(),
        tenant_id: user.tenant_id.clone(),
        user_id: user.id.clone(),
        challenge: "challenge".into(),
        expires_at: now + 60,
    };
    repo.identity_handoff_insert(&handoff).await.unwrap();
    let mut consumed = handoff.clone();
    consumed.hash = new_id();
    repo.identity_handoff_insert(&consumed).await.unwrap();
    let consumed = repo.identity_handoff_consume(&consumed.hash, "google", "challenge", now).await.unwrap().unwrap();
    repo.identity_recent_auth(&user.tenant_id, &user.id, INITIAL, &recent, now + 300).await.unwrap();
    repo.identity_unlink(&user.tenant_id, &user.id, INITIAL, "google", &recent, now, &[]).await.unwrap();
    assert!(repo.identity_handoff_consume(&handoff.hash, "google", "challenge", now).await.unwrap().is_none());
    assert!(repo.identity_attempt(&resolved.id, false).await.unwrap().is_none());
    assert!(repo.identity_attempt(&linking.id, false).await.unwrap().is_none());
    assert!(repo.identity_handoff_insert(&consumed).await.is_err(), "late handoff insert cannot cross unlink");
    assert!(repo.identity_resolve(&identity, None, true, None, Some(INITIAL), Some(&linking.id)).await.is_err());
    assert!(
        repo.identity_resolve(&identity, None, true, None, Some(INITIAL), Some(&unresolved.id)).await.is_err(),
        "callback claimed before unlink cannot relink or provision"
    );
    assert!(repo.identity_list(&user.tenant_id, &user.id).await.unwrap().is_empty());
    assert_eq!(
        repo.identity_generation(&user.tenant_id, &user.id).await.unwrap(),
        0,
        "existing app sessions survive unlink"
    );
    let fresh = claimed_attempt(repo, &identity, true).await;
    repo.identity_resolve(&identity, None, true, None, Some(INITIAL), Some(&fresh.id)).await.unwrap();
    assert!(
        repo.identity_list(&user.tenant_id, &user.id).await.unwrap().is_empty(),
        "link resolution remains pending until completion"
    );
    repo.identity_complete(&fresh.id, &user.tenant_id, &user.id, INITIAL, "fresh-link-assurance", now).await.unwrap();
    assert_eq!(
        repo.identity_list(&user.tenant_id, &user.id).await.unwrap().len(),
        1,
        "new interactive linking remains available"
    );
    repo.account_erase(&user.tenant_id, &user.id, true).await.unwrap();
}

async fn unlink_alias_conformance<R: Repository>(repo: &R) {
    let (user, identity) = unlink_fixture(repo, true).await;
    let now = Utc::now().timestamp();
    let alias = FederatedIdentity { provider: "google-alias".into(), ..identity.clone() };
    let unresolved = claimed_attempt(repo, &alias, false).await;
    let linking = claimed_attempt(repo, &alias, true).await;
    let resolved = claimed_attempt(repo, &alias, false).await;
    assert_eq!(
        repo.identity_resolve(&alias, None, false, None, None, Some(&resolved.id)).await.unwrap(),
        (user.tenant_id.clone(), user.id.clone(), 0)
    );
    assert_eq!(repo.identity_list(&user.tenant_id, &user.id).await.unwrap()[0].provider, identity.provider);
    let handoff = LoginHandoff {
        attempt_id: Some(resolved.id.clone()),
        generation: 0,
        pending_identity: None,
        link_session_hash: None,
        hash: new_id(),
        provider: alias.provider.clone(),
        tenant_id: user.tenant_id.clone(),
        user_id: user.id.clone(),
        challenge: "challenge".into(),
        expires_at: now + 60,
    };
    repo.identity_handoff_insert(&handoff).await.unwrap();
    let consumed = LoginHandoff { hash: new_id(), ..handoff.clone() };
    repo.identity_handoff_insert(&consumed).await.unwrap();
    let consumed =
        repo.identity_handoff_consume(&consumed.hash, &alias.provider, "challenge", now).await.unwrap().unwrap();
    // 相同账户的其他规范身份仍可完成登录。
    let unrelated = FederatedIdentity { subject: new_id(), ..alias.clone() };
    repo.identity_resolve(&unrelated, None, true, None, Some(INITIAL), None).await.unwrap();
    let unrelated_attempt = claimed_attempt(repo, &unrelated, false).await;
    repo.identity_resolve(&unrelated, None, false, None, None, Some(&unrelated_attempt.id)).await.unwrap();
    let recent = new_id();
    repo.identity_recent_auth(&user.tenant_id, &user.id, INITIAL, &recent, now + 300).await.unwrap();
    repo.identity_unlink(&user.tenant_id, &user.id, INITIAL, &identity.provider, &recent, now, &[]).await.unwrap();
    assert!(repo.identity_attempt(&resolved.id, false).await.unwrap().is_none());
    assert!(repo.identity_handoff_consume(&handoff.hash, &alias.provider, "challenge", now).await.unwrap().is_none());
    assert!(repo.identity_handoff_insert(&consumed).await.is_err());
    let rejected_session = new_id();
    assert!(
        repo.identity_complete(&resolved.id, &user.tenant_id, &user.id, INITIAL, &rejected_session, now).await.is_err()
    );
    assert!(!repo.identity_check_recent(&user.tenant_id, &user.id, INITIAL, &rejected_session, now).await.unwrap());
    for attempt in [&unresolved, &linking] {
        assert!(repo.identity_resolve(&alias, None, true, None, Some(INITIAL), Some(&attempt.id)).await.is_err());
    }
    let other_session = new_id();
    assert!(
        repo.identity_complete(&unrelated_attempt.id, &user.tenant_id, "wrong-user", INITIAL, &other_session, now)
            .await
            .is_err()
    );
    assert!(
        repo.identity_complete(
            &unrelated_attempt.id,
            &user.tenant_id,
            &user.id,
            CredentialGenerations { account: 1, membership: 0 },
            &other_session,
            now
        )
        .await
        .is_err()
    );
    repo.identity_complete(&unrelated_attempt.id, &user.tenant_id, &user.id, INITIAL, &other_session, now)
        .await
        .unwrap();
    assert!(repo.identity_check_recent(&user.tenant_id, &user.id, INITIAL, &other_session, now).await.unwrap());
    assert!(
        repo.identity_complete(&unrelated_attempt.id, &user.tenant_id, &user.id, INITIAL, &new_id(), now)
            .await
            .is_err()
    );
    // 缺少规范身份绑定的历史事务须重新认证。
    let legacy = claimed_attempt(repo, &alias, false).await;
    assert!(repo.identity_complete(&legacy.id, &user.tenant_id, &user.id, INITIAL, &new_id(), now).await.is_err());
    let fresh = claimed_attempt(repo, &alias, true).await;
    repo.identity_resolve(&alias, None, true, None, Some(INITIAL), Some(&fresh.id)).await.unwrap();
    assert!(repo.identity_complete(&resolved.id, &user.tenant_id, &user.id, INITIAL, &new_id(), now).await.is_err());
    repo.identity_complete(&fresh.id, &user.tenant_id, &user.id, INITIAL, &new_id(), now).await.unwrap();
    assert_eq!(repo.identity_generation(&user.tenant_id, &user.id).await.unwrap(), 0);
    repo.account_erase(&user.tenant_id, &user.id, true).await.unwrap();
}

async fn unlink_usable_conformance<R: Repository>(repo: &R) {
    for case in
        ["missing-provider", "wrong-issuer", "removed-client", "account-deleted", "consent-revoked", "usable", "legacy"]
    {
        let (user, google) = unlink_fixture(repo, false).await;
        let apple = FederatedIdentity {
            provider: "apple".into(),
            issuer: format!("https://{}.example", new_id()),
            subject: new_id(),
            client_id: if case == "legacy" { String::new() } else { "native-client".into() },
            ..google.clone()
        };
        repo.identity_resolve(&apple, None, true, None, Some(INITIAL), None).await.unwrap();
        let now = Utc::now().timestamp();
        let recent = new_id();
        if ["account-deleted", "consent-revoked"].contains(&case) {
            repo.identity_event(&apple.issuer, &apple.subject, &new_id(), case, now, now).await.unwrap();
        }
        let clients = if case == "missing-provider" {
            vec![]
        } else {
            vec![(
                "apple".into(),
                if case == "wrong-issuer" { "https://removed.example".into() } else { apple.issuer.clone() },
                vec![if case == "removed-client" { "replacement-client".into() } else { "native-client".into() }],
            )]
        };
        // 此处模拟安全通知之后重新交互登录，继续验证最后可用方式保护。
        let current =
            CredentialGenerations { account: repo.account_generation(&user.id).await.unwrap(), membership: 0 };
        repo.identity_recent_auth(&user.tenant_id, &user.id, current, &recent, now + 300).await.unwrap();
        let result = repo.identity_unlink(&user.tenant_id, &user.id, current, "google", &recent, now, &clients).await;
        if case == "usable" {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(CoreError::Conflict(_))), "unusable remaining login allowed unlink: {case}");
            assert_eq!(
                repo.identity_list(&user.tenant_id, &user.id).await.unwrap().len(),
                2,
                "rejected unlink must roll back"
            );
            if case == "legacy" {
                let refreshed = FederatedIdentity { client_id: "native-client".into(), ..apple.clone() };
                repo.identity_resolve(&refreshed, None, true, None, Some(INITIAL), None).await.unwrap();
                repo.identity_unlink(&user.tenant_id, &user.id, current, "google", &recent, now, &clients)
                    .await
                    .unwrap();
            }
        }
        repo.account_erase(&user.tenant_id, &user.id, true).await.unwrap();
    }
}
