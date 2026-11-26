//! 收藏覆盖、CAS 竞争、分页和真实历史由同一场景验收两个后端。
#[cfg(feature = "postgres")]
use memoswish_core::library::LibraryRepo;
use memoswish_core::{CoreError, Principal, repo::*};
use memoswish_protocol::*;

async fn seed(repo: &impl Repository) -> (Principal, FeedbackEventRecord, MemoryState) {
    seed_with_scopes(repo, vec!["*".into()]).await
}
async fn seed_with_scopes(
    repo: &impl Repository,
    scopes: Vec<String>,
) -> (Principal, FeedbackEventRecord, MemoryState) {
    let (rec, state) = crate::learning_conformance::seed(repo).await;
    let mut p =
        Principal { tenant_id: rec.tenant_id.clone(), user_id: rec.user_id.clone(), ..Principal::local_owner("test") };
    let hash = memoswish_core::ids::sha256_hex(memoswish_core::ids::new_id().as_bytes());
    p.via = "api_token".into();
    p.scopes = Some(scopes);
    p.session_access_hash = Some(format!("api:{hash}"));
    repo.insert_api_token(&ApiTokenRecord {
        id: memoswish_core::ids::new_id(),
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        name: "Library tests".into(),
        token_hash: hash,
        generations: p.credential_generations().unwrap(),
        scopes: p.scopes.clone().unwrap(),
        created_at: rec.received_at,
        expires_at: None,
        last_used_at: None,
        revoked: false,
    })
    .await
    .unwrap();
    (p, rec, state)
}
async fn suite(repo: &impl Repository) {
    feedback_only_receipts(repo).await;
    publication_visibility(repo).await;
    let (p, mut rec, mut state) = seed(repo).await;
    let card = rec.event.card_id.clone();
    let command = FavoriteCommand { operation_id: "unstar".into(), desired_state: false, expected_revision: 0 };
    let a = repo.set_favorite(&p, &card, &command).await.unwrap();
    assert_eq!((a.starred, a.revision), (false, 1));
    let memory = repo.get_versioned_memory(&p.tenant_id, &p.user_id, &card).await.unwrap().unwrap();
    assert_eq!((memory.state.exposures, memory.state.reps), (0, 0));
    // 模拟在显式写入前捕获的旧投影；失败不能提交事件回执。
    assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), LearningEventOutcome::Retry);
    state.starred = true;
    assert_eq!(
        repo.try_apply_learning_event(&rec, Some(memory.version), &state).await.unwrap(),
        LearningEventOutcome::Applied
    );
    assert!(!repo.get_memory(&p.tenant_id, &p.user_id, &card).await.unwrap().unwrap().starred);
    assert_eq!(repo.set_favorite(&p, &card, &command).await.unwrap(), a);
    let star = FavoriteCommand { operation_id: "star".into(), desired_state: true, expected_revision: 1 };
    repo.set_favorite(&p, &card, &star).await.unwrap();
    assert_eq!(repo.set_favorite(&p, &card, &command).await.unwrap(), a);
    assert!(repo.get_memory(&p.tenant_id, &p.user_id, &card).await.unwrap().unwrap().starred);
    assert!(matches!(
        repo.set_favorite(&p, &card, &FavoriteCommand { operation_id: "conflict".into(), ..command.clone() }).await,
        Err(CoreError::Conflict(_))
    ));
    let mut mismatch = command.clone();
    mismatch.desired_state = true;
    assert!(matches!(repo.set_favorite(&p, &card, &mismatch).await, Err(CoreError::Conflict(_))));
    let page = repo.library_page(&p, &LibraryQuery::default()).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].favorite.revision, 2);
    for (revision, action) in [(0, CardControlAction::Bury), (1, CardControlAction::Suspend)] {
        let control = repo
            .set_card_control(&p.tenant_id, &p, &card, &CardControlCommand { expected_revision: revision, action })
            .await
            .unwrap();
        let page =
            repo.library_page(&p, &LibraryQuery { card_id: Some(card.clone()), ..Default::default() }).await.unwrap();
        assert_eq!(page.items[0].control.as_ref(), Some(&control));
        assert!(page.items[0].favorite.starred);
        let history = repo.review_history(&p, &LibraryQuery::default()).await.unwrap();
        assert_eq!(history.items[0].control.as_ref(), Some(&control));
    }

    let mut second = examples::sample_card();
    second.id = "zz-page".into();
    second.front = CardFace::simple("100%_literal", "unique");
    second.back = CardFace::default();
    second.tags.clear();
    repo.insert_card(&p.tenant_id, &second).await.unwrap();
    for (q, count) in [("%_", 1), ("%wildcard", 0), ("SERENDIPITY", 0), ("sha256", 0), ("serendipity", 1)] {
        assert_eq!(
            repo.library_page(&p, &LibraryQuery { query: Some(q.into()), ..Default::default() })
                .await
                .unwrap()
                .items
                .len(),
            count
        );
    }
    let q = LibraryQuery { limit: Some(1), ..Default::default() };
    let page = repo.library_page(&p, &q).await.unwrap();
    assert!(page.next_cursor.is_some());
    let next = LibraryQuery { cursor: page.next_cursor.clone(), ..q.clone() };
    assert_eq!(repo.library_page(&p, &next).await.unwrap().items[0].card.id, "zz-page");
    assert!(repo.library_page(&p, &LibraryQuery { query: Some("changed".into()), ..next.clone() }).await.is_err());
    let (foreign, _, _) = seed(repo).await;
    assert!(repo.library_page(&foreign, &next).await.is_err());
    for q in [
        LibraryQuery { limit: Some(0), ..Default::default() },
        LibraryQuery { limit: Some(101), ..Default::default() },
        LibraryQuery { query: Some("中".repeat(86)), ..Default::default() },
        LibraryQuery { cursor: Some("bad".into()), ..Default::default() },
    ] {
        assert!(repo.library_page(&p, &q).await.is_err());
    }
    let history = repo.review_history(&p, &LibraryQuery::default()).await.unwrap();
    assert_eq!(history.items.len(), 1);
    assert_eq!(history.items[0].disposition, "scheduled");
    assert_eq!(
        repo.feedback_receipts(&p, &[rec.event.event_id.clone()]).await.unwrap()[0].disposition.as_deref(),
        Some("scheduled")
    );
    for (index, disposition) in
        [LearningDisposition::LateNotScheduled, LearningDisposition::FutureNotScheduled, LearningDisposition::NotRated]
            .into_iter()
            .enumerate()
    {
        let snapshot = repo.get_versioned_memory(&p.tenant_id, &p.user_id, &card).await.unwrap().unwrap();
        let mut event = rec.clone();
        event.event.event_id = format!("disposition-{index}");
        let application = event.application.as_mut().unwrap();
        application.disposition = disposition;
        application.effective_at = None;
        if disposition == LearningDisposition::NotRated {
            event.rating = None;
        }
        let mut successor = snapshot.state;
        successor.exposures += 1;
        assert_eq!(
            repo.try_apply_learning_event(&event, Some(snapshot.version), &successor).await.unwrap(),
            LearningEventOutcome::Applied
        );
    }
    let dispositions: std::collections::BTreeSet<_> = repo
        .review_history(&p, &LibraryQuery::default())
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|e| e.disposition)
        .collect();
    assert_eq!(
        dispositions,
        std::collections::BTreeSet::from([
            "scheduled".into(),
            "late_not_scheduled".into(),
            "future_not_scheduled".into(),
            "not_rated".into()
        ])
    );
    // 历史无 provenance 必须保持未知，不能从 rating 伪造已复习。
    rec.event.event_id = "legacy".into();
    rec.application = None;
    repo.insert_feedback(&rec).await.unwrap();
    let history = repo.review_history(&p, &LibraryQuery { limit: Some(1), ..Default::default() }).await.unwrap();
    assert!(history.next_cursor.is_some());
    let next = repo
        .review_history(&p, &LibraryQuery { limit: Some(1), cursor: history.next_cursor, ..Default::default() })
        .await
        .unwrap();
    assert_eq!(next.items.len(), 1);
    repo.delete_card(&p.tenant_id, &card).await.unwrap();
    assert!(repo.review_history(&p, &LibraryQuery::default()).await.unwrap().items.iter().all(|e| e.archived));
    assert_eq!(repo.library_page(&p, &LibraryQuery::default()).await.unwrap().items.len(), 1);
    assert!(
        repo.set_favorite(&p, &card, &FavoriteCommand { operation_id: "missing".into(), expected_revision: 2, ..star })
            .await
            .is_err()
    );
    repo.membership_remove(&p.tenant_id, &p.user_id).await.unwrap();
    assert!(repo.library_page(&p, &LibraryQuery::default()).await.is_err());
}

async fn publication_visibility(repo: &impl Repository) {
    let (p, rec, state) = seed_with_scopes(repo, vec!["content:read".into(), "feedback:write".into()]).await;
    let card = &rec.event.card_id;
    let command =
        FavoriteCommand { operation_id: "before-unpublish".into(), desired_state: true, expected_revision: 0 };
    let receipt = repo.set_favorite(&p, card, &command).await.unwrap();
    let snapshot = repo.get_versioned_memory(&p.tenant_id, &p.user_id, card).await.unwrap().unwrap();
    assert_eq!(
        repo.try_apply_learning_event(&rec, Some(snapshot.version), &state).await.unwrap(),
        LearningEventOutcome::Applied
    );
    let current = repo.get_card(&p.tenant_id, card).await.unwrap().unwrap();
    repo.mutate_cards(
        &p.tenant_id,
        &[memoswish_core::content::CardMutation::Publication {
            id: card.clone(),
            command: PublicationCommand { expected_revision: current.revision, publish: false },
        }],
    )
    .await
    .unwrap();
    for query in [
        LibraryQuery::default(),
        LibraryQuery { card_id: Some(card.clone()), ..Default::default() },
        LibraryQuery { query: Some("serendipity".into()), starred: Some(true), ..Default::default() },
    ] {
        assert!(repo.library_page(&p, &query).await.unwrap().items.is_empty());
    }
    assert!(repo.review_history(&p, &LibraryQuery::default()).await.unwrap().items.is_empty());
    // 原回执可恢复，首见命令与反馈不能作用于撤回内容。
    assert_eq!(repo.set_favorite(&p, card, &command).await.unwrap(), receipt);
    assert!(matches!(
        repo.set_favorite(
            &p,
            card,
            &FavoriteCommand { operation_id: "after-unpublish".into(), expected_revision: 1, ..command }
        )
        .await,
        Err(CoreError::NotFound(_))
    ));
    assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), LearningEventOutcome::Duplicate);
    let mut fresh = rec.clone();
    fresh.event.event_id = "after-unpublish".into();
    assert_eq!(repo.try_apply_learning_event(&fresh, None, &state).await.unwrap(), LearningEventOutcome::MissingCard);
    assert!(repo.feedback_receipts(&p, &[fresh.event.event_id]).await.unwrap().is_empty());
    assert_eq!(repo.feedback_receipts(&p, std::slice::from_ref(&rec.event.event_id)).await.unwrap().len(), 1);
    repo.delete_card(&p.tenant_id, card).await.unwrap();
    assert!(repo.review_history(&p, &LibraryQuery::default()).await.unwrap().items[0].archived);
}

async fn feedback_only_receipts(repo: &impl Repository) {
    let (p, rec, state) = seed_with_scopes(repo, vec!["feedback:write".into()]).await;
    repo.save_session(&FeedSession {
        id: rec.session_id.clone(),
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        next_slot: rec.event.slot + 1,
        recent_card_ids: vec![],
        created_at: rec.received_at,
        updated_at: rec.received_at,
    })
    .await
    .unwrap();
    let ids = [rec.event.event_id.clone()];
    let mut original = None;
    for expected in [LearningEventOutcome::Applied, LearningEventOutcome::Duplicate] {
        assert_eq!(repo.try_apply_learning_event_for_principal(&p, &rec, None, &state).await.unwrap(), expected);
        let receipts = repo.feedback_receipts(&p, &ids).await.unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].event_id, ids[0]);
        assert_eq!(receipts[0].disposition.as_deref(), Some("scheduled"));
        if let Some(previous) = &original {
            assert_eq!(&receipts, previous);
        }
        original = Some(receipts);
    }
    let memory = repo.get_versioned_memory(&p.tenant_id, &p.user_id, &rec.event.card_id).await.unwrap().unwrap();
    assert_eq!((memory.version, memory.state.exposures, memory.state.reps), (1, 1, 1));
    assert!(matches!(repo.library_page(&p, &LibraryQuery::default()).await, Err(CoreError::Forbidden(_))));
    assert!(matches!(repo.review_history(&p, &LibraryQuery::default()).await, Err(CoreError::Forbidden(_))));
    // 回执只读原主体的事件；不能借更换主体、世代或缺失凭据取得已提交事实。
    let (foreign, _, _) = seed_with_scopes(repo, vec!["feedback:write".into()]).await;
    assert!(repo.feedback_receipts(&foreign, &ids).await.unwrap().is_empty());
    for invalid in [
        Principal { session_access_hash: None, ..p.clone() },
        Principal { auth_generation: Some(1), ..p.clone() },
        Principal { membership_generation: Some(1), ..p.clone() },
        Principal { user_id: foreign.user_id, ..p.clone() },
        Principal { tenant_id: foreign.tenant_id, ..p.clone() },
        Principal { scopes: Some(vec!["content:read".into()]), ..p.clone() },
    ] {
        assert!(repo.feedback_receipts(&invalid, &ids).await.is_err());
    }
    let hash = p.session_access_hash.as_deref().unwrap().strip_prefix("api:").unwrap();
    let token = repo.find_api_token(hash).await.unwrap().unwrap();
    repo.revoke_api_token(&p.tenant_id, &token.id).await.unwrap();
    assert!(matches!(repo.feedback_receipts(&p, &ids).await, Err(CoreError::Unauthorized(_))));
}
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_personal_library_conformance() {
    let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
    suite(&repo).await;
}
#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
fn postgres_personal_library_conformance() {
    crate::pg_test_support::run_pg_test(|owner| async move {
        let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let repo = fixture.repository(2).await.unwrap();
        suite(&repo).await;
        let (p, mut event, _) = seed(&repo).await;
        event.application = None;
        repo.insert_feedback(&event).await.unwrap();
        event.event.event_id = "timezone-next".into();
        event.received_at += chrono::Duration::seconds(1);
        repo.insert_feedback(&event).await.unwrap();
        let mut cursors = Vec::new();
        for timezone in ["UTC", "Pacific/Honolulu"] {
            let mut a = repo.pool().acquire().await.unwrap();
            let mut b = repo.pool().acquire().await.unwrap();
            let statement = format!("SET TIME ZONE '{timezone}'");
            sqlx::query(&statement).execute(&mut *a).await.unwrap();
            sqlx::query(&statement).execute(&mut *b).await.unwrap();
            drop((a, b));
            let page = repo.review_history(&p, &LibraryQuery { limit: Some(1), ..Default::default() }).await.unwrap();
            assert_eq!(page.items[0].event_id, "timezone-next");
            cursors.push(page.next_cursor.unwrap());
        }
        assert_eq!(cursors[0], cursors[1], "history cursor must not depend on connection timezone");
        repo.pool().close().await;
        fixture.cleanup().await;
    });
}

async fn beyond_legacy_limit(repo: &impl Repository) {
    let (p, _, _) = seed(repo).await;
    let mut deck = examples::sample_deck();
    deck.id = "large-library".into();
    let cards: Vec<_> = (0..5005)
        .map(|i| {
            let mut c = examples::sample_card();
            c.id = format!("z{i:06}");
            c.deck_id = deck.id.clone();
            c.front = CardFace::simple(if i == 5004 { "needle_%_last" } else { "ordinary" }, "");
            c.back = CardFace::default();
            c.tags.clear();
            c
        })
        .collect();
    repo.insert_deck_with_cards(&p.tenant_id, &deck, &cards).await.unwrap();
    repo.set_favorite(
        &p,
        "z005004",
        &FavoriteCommand { operation_id: "last-star".into(), desired_state: true, expected_revision: 0 },
    )
    .await
    .unwrap();
    let found = repo
        .library_page(&p, &LibraryQuery { query: Some("needle_%_".into()), starred: Some(true), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(found.items.len(), 1);
    assert_eq!(found.items[0].card.id, "z005004");
    let mut q = LibraryQuery { limit: Some(100), ..Default::default() };
    let mut ids = std::collections::BTreeSet::new();
    loop {
        let page = repo.library_page(&p, &q).await.unwrap();
        for e in page.items {
            assert!(ids.insert(e.card.id));
        }
        q.cursor = page.next_cursor;
        if q.cursor.is_none() {
            break;
        }
    }
    assert_eq!(ids.len(), 5006);
}
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_library_search_and_keysets_beyond_5000() {
    let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
    beyond_legacy_limit(&repo).await;
}
#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
fn postgres_library_search_and_keysets_beyond_5000() {
    crate::pg_test_support::run_pg_test(|owner| async move {
        let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let repo = fixture.repository(2).await.unwrap();
        beyond_legacy_limit(&repo).await;
        repo.pool().close().await;
        fixture.cleanup().await;
    });
}

async fn concurrent_favorite_and_review(repo: &impl Repository, other: &impl Repository) {
    for existing in [false, true] {
        let (p, mut event, mut state) = seed(repo).await;
        if existing {
            assert_eq!(
                repo.try_apply_learning_event(&event, None, &state).await.unwrap(),
                LearningEventOutcome::Applied
            );
            event.event.event_id = "concurrent-next".into();
            state.reps += 1;
            state.exposures += 1;
        }
        let snapshot = repo.get_versioned_memory(&p.tenant_id, &p.user_id, &state.card_id).await.unwrap();
        let expected = snapshot.map(|s| s.version);
        let command =
            FavoriteCommand { operation_id: "concurrent-unstar".into(), desired_state: false, expected_revision: 0 };
        let barrier = tokio::sync::Barrier::new(2);
        let (review, favorite) = tokio::join!(
            async {
                barrier.wait().await;
                repo.try_apply_learning_event(&event, expected, &state).await.unwrap()
            },
            async {
                barrier.wait().await;
                other.set_favorite(&p, &state.card_id, &command).await.unwrap()
            }
        );
        assert!(!favorite.starred);
        if review == LearningEventOutcome::Retry {
            let expected =
                repo.get_versioned_memory(&p.tenant_id, &p.user_id, &state.card_id).await.unwrap().unwrap().version;
            assert_eq!(
                repo.try_apply_learning_event(&event, Some(expected), &state).await.unwrap(),
                LearningEventOutcome::Applied
            );
        } else {
            assert_eq!(review, LearningEventOutcome::Applied);
        }
        let final_state = repo.get_memory(&p.tenant_id, &p.user_id, &state.card_id).await.unwrap().unwrap();
        assert_eq!(
            (final_state.starred, final_state.reps, final_state.exposures),
            (false, state.reps, state.exposures)
        );
        assert_eq!(repo.try_apply_learning_event(&event, None, &state).await.unwrap(), LearningEventOutcome::Duplicate);
        assert_eq!(repo.set_favorite(&p, &state.card_id, &command).await.unwrap(), favorite);
    }
}
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_library_favorite_review_independent_connections() {
    let path = std::env::temp_dir().join(format!("library-race-{}.db", memoswish_core::ids::new_id()));
    let url = format!("sqlite://{}", path.display());
    let a = crate::sqlite::SqliteRepository::connect(&url).await.unwrap();
    let b = crate::sqlite::SqliteRepository::connect(&url).await.unwrap();
    concurrent_favorite_and_review(&a, &b).await;
    a.pool().close().await;
    b.pool().close().await;
    std::fs::remove_file(path).unwrap();
}
#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
fn postgres_library_favorite_review_independent_connections() {
    crate::pg_test_support::run_pg_test(|owner| async move {
        let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let a = fixture.repository(2).await.unwrap();
        let b = fixture.repository(2).await.unwrap();
        concurrent_favorite_and_review(&a, &b).await;
        a.pool().close().await;
        b.pool().close().await;
        fixture.cleanup().await;
    });
}
