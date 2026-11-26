//! 学习控制的隔离、CAS、事务屏障与生命周期通过同一双库场景验证。
use memoswish_core::learning_controls::LearningControlsRepo;
use memoswish_core::{CoreError, Permission, Principal, repo::*};
use memoswish_protocol::*;

async fn suite(repo: &impl Repository, other: &impl Repository) {
    revoked_controls(repo).await;
    let p = crate::feed_issuance_conformance::seed(repo).await;
    let tenant = &p.tenant_id;
    let card = examples::sample_card().id;
    let prefs = repo.learner_preferences(tenant, &p, 0.9).await.unwrap();
    assert_eq!((prefs.revision, prefs.desired_retention, prefs.effective_retention), (0, None, 0.9));
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.4999, 0.99001] {
        assert!(matches!(
            repo.set_retention(
                tenant,
                &p,
                &RetentionCommand { expected_revision: 0, desired_retention: Some(Some(bad)) },
                0.9
            )
            .await,
            Err(CoreError::Invalid(_))
        ));
    }
    let a = RetentionCommand { expected_revision: 0, desired_retention: Some(Some(0.50)) };
    let b = RetentionCommand { expected_revision: 0, desired_retention: Some(Some(0.99)) };
    let (a, b) = tokio::join!(repo.set_retention(tenant, &p, &a, 0.9), other.set_retention(tenant, &p, &b, 0.9));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let loser = if a.is_err() { a } else { b };
    assert!(matches!(loser, Err(CoreError::Conflict(_))));
    let req = crate::feed_issuance_conformance::first();
    let stale = crate::feed_issuance_conformance::candidate(repo, &p, &req, false).await;
    let before = repo.learner_preferences(tenant, &p, 0.9).await.unwrap();
    let unchanged = repo
        .set_retention(tenant, &p, &RetentionCommand { expected_revision: 1, desired_retention: None }, 0.9)
        .await
        .unwrap();
    assert_eq!(unchanged, before);
    let after_noop = crate::feed_issuance_conformance::candidate(repo, &p, &req, false).await;
    assert_eq!(after_noop.expected.controls_epoch, stale.expected.controls_epoch);
    assert_eq!(after_noop.expected.desired_retention, stale.expected.desired_retention);
    assert!(matches!(
        repo.set_retention(tenant, &p, &RetentionCommand { expected_revision: 0, desired_retention: None }, 0.9).await,
        Err(CoreError::Conflict(_))
    ));
    let prefs = repo
        .set_retention(tenant, &p, &RetentionCommand { expected_revision: 1, desired_retention: Some(None) }, 0.9)
        .await
        .unwrap();
    assert_eq!((prefs.revision, prefs.desired_retention), (2, None));
    assert!(matches!(repo.feed_issuance(&p, &req, Some(&stale)).await.unwrap(), FeedIssuanceOutcome::Retry(_)));
    let stale = crate::feed_issuance_conformance::candidate(repo, &p, &req, false).await;
    let before = chrono::Utc::now();
    let buried = repo
        .set_card_control(
            tenant,
            &p,
            &card,
            &CardControlCommand { expected_revision: 0, action: CardControlAction::Bury },
        )
        .await
        .unwrap();
    let deadline = buried.buried_until.unwrap();
    assert!(deadline >= before + chrono::Duration::hours(24) - chrono::Duration::milliseconds(2));
    assert!(deadline <= chrono::Utc::now() + chrono::Duration::hours(24));
    assert!(repo.get_memory(tenant, &p.user_id, &card).await.unwrap().is_none());
    assert_eq!(other.card_control(tenant, &p, &card).await.unwrap(), buried);
    assert!(matches!(repo.feed_issuance(&p, &req, Some(&stale)).await.unwrap(), FeedIssuanceOutcome::Retry(_)));
    assert!(matches!(
        repo.set_card_control(
            tenant,
            &p,
            &card,
            &CardControlCommand { expected_revision: 0, action: CardControlAction::Bury }
        )
        .await,
        Err(CoreError::Conflict(_))
    ));
    assert_eq!(repo.card_control(tenant, &p, &card).await.unwrap(), buried);
    let suspended = repo
        .set_card_control(
            tenant,
            &p,
            &card,
            &CardControlCommand { expected_revision: 1, action: CardControlAction::Suspend },
        )
        .await
        .unwrap();
    assert!(suspended.suspended && suspended.buried_until.is_none());
    assert!(matches!(
        repo.set_card_control(
            tenant,
            &p,
            &card,
            &CardControlCommand { expected_revision: 2, action: CardControlAction::Bury }
        )
        .await,
        Err(CoreError::Conflict(_))
    ));
    let page = repo.hidden_cards(tenant, &p, None, 1).await.unwrap();
    assert_eq!(page.items, vec![suspended]);
    assert!(page.next_after.is_none());
    let before_stats = repo.feed_summary(tenant, &p.user_id, None).await.unwrap();
    repo.set_card_control(
        tenant,
        &p,
        &card,
        &CardControlCommand { expected_revision: 2, action: CardControlAction::Resume },
    )
    .await
    .unwrap();
    assert_eq!(repo.feed_summary(tenant, &p.user_id, None).await.unwrap(), before_stats);
    assert!(repo.hidden_cards(tenant, &p, None, 50).await.unwrap().items.is_empty());
    let candidate = crate::feed_issuance_conformance::candidate(repo, &p, &req, false).await;
    let second = crate::feed_issuance_conformance::first();
    let concurrent = crate::feed_issuance_conformance::candidate(repo, &p, &second, false).await;
    let issued =
        crate::feed_issuance_conformance::committed(repo.feed_issuance(&p, &req, Some(&candidate)).await.unwrap());
    assert!(matches!(repo.feed_issuance(&p, &second, Some(&concurrent)).await.unwrap(), FeedIssuanceOutcome::Retry(_)));
    repo.set_card_control(
        tenant,
        &p,
        &card,
        &CardControlCommand { expected_revision: 3, action: CardControlAction::Suspend },
    )
    .await
    .unwrap();
    let before_replay = repo.feed_issuance(&p, &second, None).await.unwrap();
    assert_eq!(crate::feed_issuance_conformance::committed(repo.feed_issuance(&p, &req, None).await.unwrap()), issued);
    assert_eq!(repo.feed_issuance(&p, &second, None).await.unwrap(), before_replay);
    let foreign = crate::feed_issuance_conformance::seed(repo).await;
    assert_eq!(repo.card_control(&foreign.tenant_id, &foreign, &card).await.unwrap().revision, 0);
    assert!(repo.card_control(tenant, &foreign, &card).await.is_err());
    assert!(
        repo.set_card_control(
            tenant,
            &foreign,
            &card,
            &CardControlCommand { expected_revision: 4, action: CardControlAction::Resume }
        )
        .await
        .is_err()
    );
    assert!(repo.learner_preferences(tenant, &foreign, 0.9).await.is_err());
    assert!(
        repo.set_retention(
            tenant,
            &foreign,
            &RetentionCommand { expected_revision: 2, desired_retention: Some(Some(0.85)) },
            0.9
        )
        .await
        .is_err()
    );
    let read_only = Principal { scopes: Some(vec![Permission::FeedRead.as_scope().into()]), ..p.clone() };
    assert!(
        repo.set_card_control(
            tenant,
            &read_only,
            &card,
            &CardControlCommand { expected_revision: 4, action: CardControlAction::Resume }
        )
        .await
        .is_err()
    );
    // 同租户另一用户与同用户另一租户均拥有独立的偏好和控制。
    let generation = repo.membership_join(tenant, &foreign.user_id, memoswish_core::Role::Learner).await.unwrap();
    let peer = Principal { tenant_id: tenant.clone(), membership_generation: Some(generation), ..foreign.clone() };
    assert_eq!(repo.card_control(tenant, &peer, &card).await.unwrap().revision, 0);
    repo.set_retention(
        tenant,
        &peer,
        &RetentionCommand { expected_revision: 0, desired_retention: Some(Some(0.6)) },
        0.9,
    )
    .await
    .unwrap();
    repo.set_card_control(
        tenant,
        &peer,
        &card,
        &CardControlCommand { expected_revision: 0, action: CardControlAction::Bury },
    )
    .await
    .unwrap();
    assert!(repo.card_control(tenant, &p, &card).await.unwrap().suspended);
    assert_eq!(repo.learner_preferences(tenant, &p, 0.9).await.unwrap().desired_retention, None);
    let generation = repo.membership_join(&foreign.tenant_id, &p.user_id, memoswish_core::Role::Learner).await.unwrap();
    let alternate =
        Principal { tenant_id: foreign.tenant_id.clone(), membership_generation: Some(generation), ..p.clone() };
    assert_eq!(repo.learner_preferences(&alternate.tenant_id, &alternate, 0.9).await.unwrap().revision, 0);
    repo.set_retention(
        &alternate.tenant_id,
        &alternate,
        &RetentionCommand { expected_revision: 0, desired_retention: Some(Some(0.7)) },
        0.9,
    )
    .await
    .unwrap();
    for suffix in ["p33-extra-a", "p33-extra-b"] {
        let mut extra = examples::sample_card();
        extra.id = suffix.into();
        repo.insert_card(tenant, &extra).await.unwrap();
        repo.set_card_control(
            tenant,
            &p,
            suffix,
            &CardControlCommand { expected_revision: 0, action: CardControlAction::Suspend },
        )
        .await
        .unwrap();
    }
    let mut reached = std::collections::BTreeSet::new();
    let mut after = None;
    loop {
        let page = repo.hidden_cards(tenant, &p, after.as_deref(), 1).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert!(reached.insert(page.items[0].card_id.clone()));
        after = page.next_after;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(reached, std::collections::BTreeSet::from([card.clone(), "p33-extra-a".into(), "p33-extra-b".into()]));
    let exported = repo
        .export_personal(&memoswish_core::lifecycle::AccountAuthority::Workspace(Principal {
            via: "single_user".into(),
            ..p.clone()
        }))
        .await
        .unwrap();
    let data = &exported.workspaces.iter().find(|w| w.tenant_id == *tenant).unwrap().data;
    assert_eq!(data["learner_preferences"].len(), 1);
    assert_eq!(data["learner_card_controls"].len(), 3);
    repo.membership_remove(tenant, &p.user_id).await.unwrap();
    assert!(repo.card_control(tenant, &p, &card).await.is_err());
    assert!(repo.get_card(tenant, &card).await.unwrap().is_some());
    let generation = repo.membership_join(tenant, &p.user_id, memoswish_core::Role::Learner).await.unwrap();
    let returned = Principal { membership_generation: Some(generation), ..p.clone() };
    assert_eq!(repo.learner_preferences(tenant, &returned, 0.9).await.unwrap().revision, 0);
    assert_eq!(repo.card_control(tenant, &returned, &card).await.unwrap().revision, 0);
    assert_eq!(repo.learner_preferences(tenant, &peer, 0.9).await.unwrap().desired_retention, Some(0.6));
    assert!(repo.card_control(tenant, &peer, &card).await.unwrap().buried_until.is_some());
    assert_eq!(
        repo.learner_preferences(&alternate.tenant_id, &alternate, 0.9).await.unwrap().desired_retention,
        Some(0.7)
    );
}

async fn revoked_controls(repo: &impl Repository) {
    use memoswish_core::session::{AccessKind, SessionFamily};
    let p = crate::feed_issuance_conformance::seed(repo).await;
    let family = SessionFamily {
        id: memoswish_core::ids::new_id(),
        user_id: p.user_id.clone(),
        generation: p.auth_generation.unwrap(),
        provenance: "password".into(),
        auth_time: chrono::Utc::now().timestamp(),
        expires_at: chrono::Utc::now().timestamp() + 3600,
        revoked: false,
    };
    let root = crate::session_conformance::credential(&family, None);
    repo.session_issue(&family, &root, None).await.unwrap();
    let token = ApiTokenRecord {
        id: memoswish_core::ids::new_id(),
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        name: "Controls revocation test".into(),
        token_hash: memoswish_core::ids::new_id(),
        scopes: vec!["feed:read".into(), "feedback:write".into()],
        generations: p.credential_generations().unwrap(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    };
    repo.insert_api_token(&token).await.unwrap();
    let held = Principal {
        via: "api_token".into(),
        session_access_hash: Some(format!("api:{}", token.token_hash)),
        scopes: Some(token.scopes.clone()),
        ..p
    };
    let tenant = &held.tenant_id;
    let card = examples::sample_card().id;
    repo.learner_preferences(tenant, &held, 0.9).await.unwrap();
    repo.card_control(tenant, &held, &card).await.unwrap();
    repo.set_retention(tenant, &held, &RetentionCommand { expected_revision: 0, desired_retention: None }, 0.9)
        .await
        .unwrap();
    assert!(repo.access_revoke(&root.access_hash, AccessKind::ApiTokens, Some(tenant), &token.id).await.unwrap());
    // 保留认证前捕获的主体，证明事务内仍会拒绝撤销后的所有控制操作。
    let errors = [
        repo.learner_preferences(tenant, &held, 0.9).await.unwrap_err(),
        repo.card_control(tenant, &held, &card).await.unwrap_err(),
        repo.hidden_cards(tenant, &held, None, 50).await.unwrap_err(),
        repo.set_retention(
            tenant,
            &held,
            &RetentionCommand { expected_revision: 0, desired_retention: Some(Some(0.85)) },
            0.9,
        )
        .await
        .unwrap_err(),
        repo.set_card_control(
            tenant,
            &held,
            &card,
            &CardControlCommand { expected_revision: 0, action: CardControlAction::Suspend },
        )
        .await
        .unwrap_err(),
    ];
    assert!(errors.iter().all(|error| error.http_status() == 401));
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_learning_controls_conformance() {
    let path = std::env::temp_dir().join(format!("p33-{}.db", memoswish_core::ids::new_id()));
    let url = format!("sqlite://{}", path.display());
    let a = crate::sqlite::SqliteRepository::connect_test(&url).await.unwrap();
    let b = crate::sqlite::SqliteRepository::connect_test(&url).await.unwrap();
    suite(&a, &b).await;
    a.pool().close().await;
    b.pool().close().await;
    std::fs::remove_file(path).unwrap();
}
#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires isolated PostgreSQL schema"]
fn postgres_learning_controls_conformance() {
    crate::pg_test_support::run_pg_test(|owner| async move {
        let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let a = fixture.repository(2).await.unwrap();
        let b = fixture.repository(2).await.unwrap();
        suite(&a, &b).await;
        a.pool().close().await;
        b.pool().close().await;
        fixture.cleanup().await;
    });
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_control_failure_rolls_back_epoch_and_does_not_create_memory() {
    let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
    let p = crate::feed_issuance_conformance::seed(&repo).await;
    sqlx::raw_sql("CREATE TRIGGER p33_fail BEFORE INSERT ON learner_card_controls BEGIN SELECT RAISE(ABORT,'injected control failure'); END;").execute(repo.pool()).await.unwrap();
    assert!(
        repo.set_card_control(
            &p.tenant_id,
            &p,
            &examples::sample_card().id,
            &CardControlCommand { expected_revision: 0, action: CardControlAction::Bury }
        )
        .await
        .is_err()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM learner_preferences").fetch_one(repo.pool()).await.unwrap();
    assert_eq!(count, 0);
    assert!(repo.list_memory(&p.tenant_id, &p.user_id).await.unwrap().is_empty());
    assert_eq!(repo.card_control(&p.tenant_id, &p, &examples::sample_card().id).await.unwrap().revision, 0);
}
