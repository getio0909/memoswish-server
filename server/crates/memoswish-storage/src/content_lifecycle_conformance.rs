//! 真实双库共用发布、冲突、报告归属与事务回滚场景。
use memoswish_core::content_lifecycle_repo::ContentLifecycleRepo;
use memoswish_core::{CoreError, Permission, Principal, Role, content::CardMutation, repo::*};
use memoswish_protocol::*;

fn save(card: &Card, publish: bool) -> CardMutation {
    CardMutation::Author {
        observed_generation: None,
        id: card.id.clone(),
        save: Box::new(CardSave {
            card: CardDraft {
                id: Some(card.id.clone()),
                expected_revision: Some(card.revision),
                deck_id: card.deck_id.clone(),
                template: None,
                language: Some(card.language.clone()),
                front: card.front.clone(),
                back: card.back.clone(),
                tags: card.tags.clone(),
                attributes: Default::default(),
                ducking: None,
                visual: None,
            },
            publish,
            provenance: None,
            report_id: None,
        }),
    }
}
async fn setup(repo: &impl Repository) -> (Principal, Deck, Card) {
    let p = Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
    let mut deck = examples::sample_deck();
    deck.id = memoswish_core::ids::new_id();
    deck.card_count = 0;
    repo.insert_deck(&p.tenant_id, &deck).await.unwrap();
    let mut card = examples::sample_card();
    card.id = memoswish_core::ids::new_id();
    card.deck_id = deck.id.clone();
    card.tts = None;
    card.bgm = None;
    card.visual.image = None;
    card.revision = 1;
    let mut mutation = save(&card, false);
    if let CardMutation::Author { save, .. } = &mut mutation {
        save.card.id = None;
        save.card.expected_revision = None;
        save.provenance =
            Some(ContentProvenance { method: "manual".into(), rights: "Apache-2.0".into(), ..Default::default() });
    }
    let card = repo.author_card(&p.tenant_id, &p, &mutation, None).await.unwrap();
    (p, deck, card)
}
async fn suite(repo: &impl Repository, other: &impl Repository) {
    let (p, deck, card) = setup(repo).await;
    let tenant = &p.tenant_id;
    assert!(!memoswish_core::content_lifecycle::published(&card));
    assert_eq!(repo.feed_summary(tenant, &p.user_id, None).await.unwrap().total_cards, 0);
    assert!(repo.hydrate_feed_cards(tenant, None, std::slice::from_ref(&card.id)).await.unwrap().is_empty());
    assert!(repo.visible_cards(tenant, None, false, 50, 0).await.unwrap().is_empty());
    assert_eq!(repo.content_revisions(tenant, &p, &card.id, u64::from(u32::MAX) + 1, 50).await.unwrap().len(), 1);
    let mut bad = save(&card, true);
    if let CardMutation::Author { save, .. } = &mut bad {
        save.card.expected_revision = None;
    }
    assert!(matches!(repo.author_card(tenant, &p, &bad, None).await, Err(CoreError::Invalid(_))));
    let mut bad = save(&card, true);
    if let CardMutation::Author { save, .. } = &mut bad {
        save.card.expected_revision = Some(0);
    }
    assert!(repo.author_card(tenant, &p, &bad, None).await.is_err());
    let narrow = Principal { scopes: Some(vec![Permission::ContentRead.as_scope().into()]), ..p.clone() };
    assert!(repo.author_card(tenant, &narrow, &save(&card, true), None).await.is_err());
    let learner = Principal { role: Role::Learner, ..p.clone() };
    assert!(repo.author_card(tenant, &learner, &save(&card, true), None).await.is_err());
    let foreign = Principal { via: "single_user".into(), ..crate::asset_conformance::seed(repo).await };
    assert!(repo.author_card(tenant, &foreign, &save(&card, true), None).await.is_err());
    assert!(repo.content_revisions(tenant, &foreign, &card.id, u64::from(u32::MAX) + 1, 50).await.is_err());
    let a = save(&card, true);
    let b = save(&card, false);
    let (a, b) = tokio::join!(repo.author_card(tenant, &p, &a, None), other.author_card(tenant, &p, &b, None));
    assert_eq!([&a, &b].iter().filter(|v| v.is_ok()).count(), 1);
    assert!(matches!(a.as_ref().err().or(b.as_ref().err()), Some(CoreError::Conflict(_))));
    let current = a.or(b).unwrap();
    assert_eq!(current.revision, 2);
    let current = repo.author_card(tenant, &p, &save(&current, true), None).await.unwrap();
    let member_generation = repo.membership_join(tenant, &foreign.user_id, Role::Learner).await.unwrap();
    let member = Principal {
        tenant_id: tenant.clone(),
        role: Role::Learner,
        membership_generation: Some(member_generation),
        ..foreign.clone()
    };
    let forged_owner = Principal { role: Role::Owner, ..member.clone() };
    assert!(repo.author_card(tenant, &forged_owner, &save(&current, true), None).await.is_err());
    assert_eq!(repo.feed_summary(tenant, &p.user_id, None).await.unwrap().total_cards, 1);
    let input = ReportCreate {
        observed_revision: current.revision,
        text: "Original answer may be wrong".into(),
        sources: vec!["https://example.org/source".into()],
    };
    // 当前发布不赋予 learner 报告既有私有草稿修订的权限。
    for reader in [&learner, &member] {
        assert!(matches!(
            repo.create_content_report(
                tenant,
                reader,
                &card.id,
                &ReportCreate { observed_revision: card.revision, ..input.clone() }
            )
            .await,
            Err(CoreError::NotFound(_))
        ));
    }
    let report = repo.create_content_report(tenant, &learner, &card.id, &input).await.unwrap();
    let personal = repo.create_content_report(tenant, &member, &card.id, &input).await.unwrap();
    assert_eq!(
        repo.content_reports(tenant, &member, &card.id, 0, 50)
            .await
            .unwrap()
            .iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>(),
        vec![personal.id]
    );
    repo.membership_remove(tenant, &member.user_id).await.unwrap();
    assert!(repo.create_content_report(tenant, &member, &card.id, &input).await.is_err());
    assert_eq!(repo.content_reports(tenant, &p, &card.id, 0, 50).await.unwrap().len(), 1);
    assert_eq!(report.observed_revision, current.revision);
    assert!(report.evidence_available);
    assert!(
        repo.create_content_report(
            tenant,
            &p,
            &card.id,
            &ReportCreate { observed_revision: current.revision + 1, ..input.clone() }
        )
        .await
        .is_err()
    );
    assert!(
        repo.create_content_report(tenant, &p, &card.id, &ReportCreate { text: "x".repeat(2049), ..input.clone() })
            .await
            .is_err()
    );
    assert!(
        repo.create_content_report(
            tenant,
            &p,
            &card.id,
            &ReportCreate { sources: vec!["https://user:secret@example.org".into()], ..input.clone() }
        )
        .await
        .is_err()
    );
    assert!(repo.create_content_report(&foreign.tenant_id, &foreign, &card.id, &input).await.is_err());
    assert!(repo.author_card(tenant, &p, &save(&card, true), Some(&report.id)).await.is_err());
    assert_eq!(repo.content_reports(tenant, &p, &card.id, 0, 50).await.unwrap()[0].corrected_revision, None);
    let corrected = repo.author_card(tenant, &p, &save(&current, true), Some(&report.id)).await.unwrap();
    assert_eq!(
        repo.content_reports(tenant, &p, &card.id, 0, 50).await.unwrap()[0].corrected_revision,
        Some(corrected.revision)
    );
    assert_eq!(repo.content_reports(tenant, &p, &card.id, 0, 50).await.unwrap()[0].observed_revision, current.revision);
    assert!(repo.author_card(tenant, &p, &save(&corrected, true), Some(&report.id)).await.is_err());
    let deck_edit = DeckEdit {
        expected_revision: deck.revision.unwrap(),
        title: "Updated deck".into(),
        description: "description".into(),
        language: "ja-JP".into(),
    };
    let edited = repo.edit_deck(tenant, &p, &deck.id, &deck_edit).await.unwrap();
    assert_eq!(edited.revision, Some(2));
    assert!(repo.edit_deck(tenant, &p, &deck.id, &deck_edit).await.is_err());
    assert_eq!(repo.get_card(tenant, &card.id).await.unwrap().unwrap().language, card.language);
    let withdrawn = repo
        .author_card(
            tenant,
            &p,
            &CardMutation::Publication {
                id: card.id.clone(),
                command: PublicationCommand { expected_revision: corrected.revision, publish: false },
            },
            None,
        )
        .await
        .unwrap();
    let late = repo
        .create_content_report(
            tenant,
            &learner,
            &card.id,
            &ReportCreate {
                observed_revision: current.revision,
                text: "Late report on the published revision".into(),
                sources: vec![],
            },
        )
        .await
        .unwrap();
    assert!(late.evidence_available);
    assert_eq!(late.observed_revision, current.revision);
    assert!(
        repo.create_content_report(
            tenant,
            &learner,
            &card.id,
            &ReportCreate {
                observed_revision: withdrawn.revision,
                text: "Current private draft".into(),
                sources: vec![]
            }
        )
        .await
        .is_err()
    );
    let legacy = crate::content_conformance::edit(&withdrawn, None, "Legacy edit preserves draft");
    let legacy = repo.mutate_cards(tenant, &[legacy]).await.unwrap().remove(0);
    assert!(!memoswish_core::content_lifecycle::published(&legacy));
    assert_eq!(
        repo.content_revisions(tenant, &p, &card.id, u64::from(u32::MAX) + 1, 50).await.unwrap().len(),
        legacy.revision as usize
    );
    repo.delete_card(tenant, &card.id).await.unwrap();
    assert!(repo.author_card(tenant, &p, &save(&legacy, true), None).await.is_err());
    assert!(repo.content_reports(tenant, &p, &card.id, 0, 50).await.unwrap().is_empty());
    assert!(repo.content_revisions(tenant, &p, &card.id, u64::from(u32::MAX) + 1, 50).await.unwrap().is_empty());
}

macro_rules! backend_tests {
    ($repo:ty,$db:ty,$fail:literal,$undo:literal) => {
        async fn full_domain(repo: &$repo) {
            let (p, deck, base) = setup(repo).await;
            for start in (0..5001).step_by(500) {
                let cards = (start..(start + 500).min(5001))
                    .map(|i| {
                        let mut c = base.clone();
                        c.id = format!("prefix-{i:06}");
                        c
                    })
                    .collect::<Vec<_>>();
                let mut sql = sqlx::QueryBuilder::<$db>::new(
                    "INSERT INTO cards(id,tenant_id,deck_id,template,revision,body,created_at,updated_at) ",
                );
                sql.push_values(&cards, |mut row, c| {
                    row.push_bind(&c.id)
                        .push_bind(&p.tenant_id)
                        .push_bind(&c.deck_id)
                        .push_bind(&c.template)
                        .push_bind(i64::from(c.revision))
                        .push_bind(sqlx::types::Json(c))
                        .push_bind(c.created_at)
                        .push_bind(c.updated_at);
                });
                sql.build().execute(repo.pool()).await.unwrap();
            }
            let published = repo.author_card(&p.tenant_id, &p, &save(&base, true), None).await.unwrap();
            assert_eq!(repo.feed_summary(&p.tenant_id, &p.user_id, Some(&deck.id)).await.unwrap().total_cards, 1);
            let mut ids = Vec::new();
            repo.visit_feed_metadata(&p.tenant_id, &p.user_id, Some(&deck.id), &mut |m| {
                ids.push(m.card_id);
                Ok(())
            })
            .await
            .unwrap();
            assert_eq!(ids, vec![published.id.clone()]);
            assert_eq!(repo.visible_cards(&p.tenant_id, Some(&deck.id), false, 50, 0).await.unwrap().len(), 1);
            for _ in 0..100 {
                repo.create_content_report(
                    &p.tenant_id,
                    &p,
                    &base.id,
                    &ReportCreate { observed_revision: 1, text: "Bounded report".into(), sources: vec![] },
                )
                .await
                .unwrap();
            }
            assert!(matches!(
                repo.create_content_report(
                    &p.tenant_id,
                    &p,
                    &base.id,
                    &ReportCreate { observed_revision: 1, text: "Capacity plus one".into(), sources: vec![] }
                )
                .await,
                Err(CoreError::Conflict(_))
            ));
        }
        async fn rollback(repo: &$repo) {
            let (p, _, card) = setup(repo).await;
            let report = repo
                .create_content_report(
                    &p.tenant_id,
                    &p,
                    &card.id,
                    &ReportCreate { observed_revision: 1, text: "Correction".into(), sources: vec![] },
                )
                .await
                .unwrap();
            sqlx::raw_sql($fail).execute(repo.pool()).await.unwrap();
            assert!(repo.author_card(&p.tenant_id, &p, &save(&card, true), Some(&report.id)).await.is_err());
            assert_eq!(repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap(), card);
            assert_eq!(
                repo.content_reports(&p.tenant_id, &p, &card.id, 0, 50).await.unwrap()[0].corrected_revision,
                None
            );
            assert_eq!(
                repo.content_revisions(&p.tenant_id, &p, &card.id, u64::from(u32::MAX) + 1, 50).await.unwrap().len(),
                1
            );
            sqlx::raw_sql($undo).execute(repo.pool()).await.unwrap();
            let changes = [
                save(&card, true),
                CardMutation::Publication {
                    id: "missing".into(),
                    command: PublicationCommand { expected_revision: 1, publish: true },
                },
            ];
            assert!(repo.author_cards(&p.tenant_id, &p, &changes).await.is_err());
            assert_eq!(repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap(), card);
            let gate = crate::learning::TestGate::new(crate::learning::TestPoint::BeforeCommit);
            let mut paused = repo.clone();
            paused.content_gate = Some(gate.clone());
            let principal = p.clone();
            let mutation = save(&card, true);
            let report_id = report.id.clone();
            let cancelled = tokio::spawn(async move {
                paused.author_card(&principal.tenant_id, &principal, &mutation, Some(&report_id)).await
            });
            gate.reached.notified().await;
            cancelled.abort();
            assert!(cancelled.await.unwrap_err().is_cancelled());
            assert_eq!(repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap(), card);
            assert_eq!(
                repo.content_reports(&p.tenant_id, &p, &card.id, 0, 50).await.unwrap()[0].corrected_revision,
                None
            );
            assert_eq!(
                repo.content_revisions(&p.tenant_id, &p, &card.id, u64::from(u32::MAX) + 1, 50).await.unwrap().len(),
                1
            );

            sqlx::query("DELETE FROM content_revisions WHERE tenant_id=$1 AND card_id=$2")
                .bind(&p.tenant_id)
                .bind(&card.id)
                .execute(repo.pool())
                .await
                .unwrap();
            assert!(
                !repo
                    .create_content_report(
                        &p.tenant_id,
                        &p,
                        &card.id,
                        &ReportCreate {
                            observed_revision: 1,
                            text: "Missing upgrade evidence".into(),
                            sources: vec![]
                        }
                    )
                    .await
                    .unwrap()
                    .evidence_available
            );
            // 数据库派生未知状态关闭学习资格。
            let mut unknown = card.clone();
            unknown.content.as_mut().unwrap().publication = "future-state".into();
            sqlx::query("UPDATE cards SET body=$3 WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id)
                .bind(&card.id)
                .bind(sqlx::types::Json(&unknown))
                .execute(repo.pool())
                .await
                .unwrap();
            assert_eq!(repo.feed_summary(&p.tenant_id, &p.user_id, None).await.unwrap().total_cards, 0);
        }
    };
}
#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    backend_tests!(
        SqliteRepository,
        sqlx::Sqlite,
        "CREATE TRIGGER p31_fail BEFORE UPDATE ON cards BEGIN SELECT RAISE(ABORT,'injected lifecycle failure'); END;",
        "DROP TRIGGER p31_fail;"
    );
    #[tokio::test]
    async fn lifecycle_cas_publication_reports_and_rollback() {
        let path = std::env::temp_dir().join(format!("p31-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = SqliteRepository::connect(&url).await.unwrap();
        let other = SqliteRepository::connect(&url).await.unwrap();
        suite(&repo, &other).await;
        rollback(&repo).await;
        issued_and_feedback(&repo).await;
        full_domain(&repo).await;
        repo.pool().close().await;
        other.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::postgres::PostgresRepository;
    backend_tests!(
        PostgresRepository,
        sqlx::Postgres,
        "CREATE FUNCTION p31_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected lifecycle failure'; END $$; CREATE TRIGGER p31_fail BEFORE UPDATE ON cards FOR EACH ROW EXECUTE FUNCTION p31_fail();",
        "DROP TRIGGER p31_fail ON cards; DROP FUNCTION p31_fail();"
    );
    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn lifecycle_cas_publication_reports_and_rollback() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let repo = fixture.repository(2).await.unwrap();
            let other = fixture.repository(2).await.unwrap();
            suite(&repo, &other).await;
            rollback(&repo).await;
            issued_and_feedback(&repo).await;
            full_domain(&repo).await;
            repo.pool().close().await;
            other.pool().close().await;
            fixture.cleanup().await;
        });
    }
}

async fn issued_and_feedback(repo: &impl Repository) {
    let (record, state) = crate::learning_conformance::seed(repo).await;
    let card = repo.get_card(&record.tenant_id, &record.event.card_id).await.unwrap().unwrap();
    let p = Principal {
        tenant_id: record.tenant_id.clone(),
        user_id: record.user_id.clone(),
        role: Role::Learner,
        ..Principal::local_owner("single_user")
    };
    let request = crate::feed_issuance_conformance::first();
    let candidate = crate::feed_issuance_conformance::candidate(repo, &p, &request, false).await;
    let change = CardMutation::Publication {
        id: card.id.clone(),
        command: PublicationCommand { expected_revision: card.revision, publish: false },
    };
    let withdrawn = repo.mutate_cards(&p.tenant_id, &[change]).await.unwrap().remove(0);
    assert!(matches!(repo.feed_issuance(&p, &request, Some(&candidate)).await.unwrap(), FeedIssuanceOutcome::Retry(_)));
    let change = CardMutation::Publication {
        id: card.id.clone(),
        command: PublicationCommand { expected_revision: withdrawn.revision, publish: true },
    };
    let published = repo.mutate_cards(&p.tenant_id, &[change]).await.unwrap().remove(0);
    let mut candidate = crate::feed_issuance_conformance::candidate(repo, &p, &request, false).await;
    candidate.page.items[0].card = published.clone();
    let page =
        crate::feed_issuance_conformance::committed(repo.feed_issuance(&p, &request, Some(&candidate)).await.unwrap());
    assert_eq!(repo.try_apply_learning_event(&record, None, &state).await.unwrap(), LearningEventOutcome::Applied);
    repo.mutate_cards(
        &p.tenant_id,
        &[CardMutation::Publication {
            id: card.id,
            command: PublicationCommand { expected_revision: published.revision, publish: false },
        }],
    )
    .await
    .unwrap();
    assert_eq!(repo.try_apply_learning_event(&record, None, &state).await.unwrap(), LearningEventOutcome::Duplicate);
    let mut fresh = record.clone();
    fresh.event.event_id = memoswish_core::ids::new_id();
    assert_eq!(
        repo.try_apply_learning_event(&fresh, Some(1), &state).await.unwrap(),
        LearningEventOutcome::MissingCard
    );
    assert_eq!(
        repo.get_versioned_memory(&p.tenant_id, &p.user_id, &record.event.card_id).await.unwrap().unwrap().version,
        1
    );
    assert_eq!(
        crate::feed_issuance_conformance::committed(repo.feed_issuance(&p, &request, None).await.unwrap()),
        page
    );
}
