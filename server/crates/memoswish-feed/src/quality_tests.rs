// 固定时钟与会话种子走生产发页和反馈路径，不把被动曝光当作效果证明。
#[tokio::test]
async fn quality_finite_population_fairness_survives_fresh_sessions_and_restart() {
    for (mode, dwell, loops, muted, rating, star) in [
        ("no-feedback", None, 0, false, None, false),
        ("fast-swipes", Some(100), 0, false, Some(Rating::Easy), false),
        ("audible-loops", Some(8000), 3, false, Some(Rating::Hard), true),
        ("muted-loops", Some(8000), 3, true, Some(Rating::Good), false),
        ("idle", Some(SignalPolicy::default().idle_ms + 1), 0, false, None, false),
    ] {
        let (mut feed, repo, p) = seeded(37).await;
        let mut seen = HashSet::new();
        for page_no in 0..37 {
            // 每次请求新会话，证明公平性不依赖客户端近期窗口。
            let page = feed
                .next_page(
                    &p,
                    &FeedQuery {
                        session_id: Some(format!("seed-{mode}-{page_no}")),
                        limit: Some(1),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(page.items.len(), 1);
            let item = &page.items[0];
            seen.insert(item.card.id.clone());
            if let Some(dwell) = dwell {
                let mut exposure = event(&item.card.id, item.slot, dwell, loops);
                exposure.muted = muted;
                exposure.event_id = format!("quality-{mode}-{page_no}");
                exposure.delivery_id = item.delivery_id.clone();
                let ack = feed
                    .record_feedback(
                        &p,
                        &FeedbackBatch {
                            session_id: page.session_id.clone(),
                            client_id: "quality".into(),
                            sent_at: test_now(),
                            events: vec![exposure],
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(ack.accepted, 1);
                let memory = repo.get_memory(&p.tenant_id, &p.user_id, &item.card.id).await.unwrap().unwrap();
                assert_eq!(memory.last_rating, rating.map(|value| value as u8));
                assert_eq!(memory.reps, u32::from(rating.is_some()));
                assert_eq!(memory.exposures, 1);
                assert_eq!(memory.starred, star);
            } else {
                assert!(repo.get_memory(&p.tenant_id, &p.user_id, &item.card.id).await.unwrap().is_none());
            }
            // 重建服务，持久排序不能退回稳定前缀。
            feed = FeedService::new(repo.clone(), FeedConfig::default(), Arc::new(test_now)).unwrap();
        }
        assert_eq!(seen.len(), 37, "mode {mode}: every continuously eligible card within N pages");
    }
}

#[tokio::test]
async fn quality_large_overdue_population_hard_limits_and_exposure_only_new_cards() {
    let (feed, repo, p) = seeded(240).await;
    for i in 0..200 {
        repo.upsert_memory(&MemoryState {
            tenant_id: p.tenant_id.clone(),
            user_id: p.user_id.clone(),
            card_id: format!("card-{i:03}"),
            stability: 1.0,
            difficulty: 5.0,
            reps: if i == 0 { 0 } else { 1 },
            lapses: 0,
            exposures: 1,
            last_review: Some(test_now() - Duration::days(30)),
            due: Some(test_now() - Duration::days(29)),
            starred: true,
            last_rating: Some(2),
        })
        .await
        .unwrap();
    }
    let mut seen = HashSet::new();
    for i in 0..240 {
        let page = feed
            .next_page(
                &p,
                &FeedQuery { session_id: Some(format!("overdue-seed-{i}")), limit: Some(10), ..Default::default() },
            )
            .await
            .unwrap();
        let mut ids = HashSet::new();
        let mut fresh = 0;
        for item in &page.items {
            assert!(ids.insert(&item.card.id));
            seen.insert(item.card.id.clone());
            fresh += usize::from(
                repo.get_memory(&p.tenant_id, &p.user_id, &item.card.id).await.unwrap().is_none_or(|m| m.reps == 0),
            );
        }
        assert!(fresh <= 4);
        assert!(!page.items.is_empty());
    }
    assert_eq!(seen.len(), 240);
}

#[tokio::test]
async fn quality_controls_preserve_issued_policy_feedback_and_statistics() {
    let (feed, repo, p) = seeded(5).await;
    let q = FeedQuery { request_id: Some("quality-issued".into()), limit: Some(10), ..Default::default() };
    let first = feed.next_page(&p, &q).await.unwrap();
    assert_eq!(first.items.len(), 4);
    feed.set_retention(
        &p,
        &memoswish_protocol::RetentionCommand { expected_revision: 0, desired_retention: Some(Some(0.75)) },
    )
    .await
    .unwrap();
    let item = &first.items[0];
    let before = feed.stats(&p).await.unwrap();
    for card in repo.list_cards(&p.tenant_id, None, 100, 0).await.unwrap() {
        feed.set_card_control(
            &p,
            &card.id,
            &memoswish_protocol::CardControlCommand {
                expected_revision: 0,
                action: memoswish_protocol::CardControlAction::Suspend,
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(feed.stats(&p).await.unwrap(), before);
    assert_eq!(feed.next_page(&p, &q).await.unwrap(), first);
    let empty =
        feed.next_page(&p, &FeedQuery { session_id: Some("all-hidden".into()), ..Default::default() }).await.unwrap();
    assert!(empty.items.is_empty());
    assert!(repo.get_memory(&p.tenant_id, &p.user_id, &item.card.id).await.unwrap().is_none());
    let mut exposure = event(&item.card.id, item.slot, 5000, 1);
    exposure.delivery_id = item.delivery_id.clone();
    let batch = FeedbackBatch {
        session_id: first.session_id.clone(),
        client_id: "quality".into(),
        sent_at: test_now(),
        events: vec![exposure],
    };
    assert_eq!(feed.record_feedback(&p, &batch).await.unwrap().accepted, 1);
    assert_eq!(feed.record_feedback(&p, &batch).await.unwrap().duplicates, 1);
    let provenance = exported_provenance(repo.as_ref(), &p, &item.card.id).await;
    assert_eq!(provenance[0].1.application.desired_retention, 0.9);
    assert!(feed.card_control(&p, &item.card.id).await.unwrap().suspended);
    feed.set_card_control(
        &p,
        &item.card.id,
        &memoswish_protocol::CardControlCommand {
            expected_revision: 1,
            action: memoswish_protocol::CardControlAction::Resume,
        },
    )
    .await
    .unwrap();
    let next = feed
        .next_page(
            &p,
            &FeedQuery {
                session_id: Some(first.session_id.clone()),
                cursor: Some(first.next_cursor.clone()),
                limit: Some(10),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(next.items.len(), 1);
    let delivery =
        repo.get_delivery(&p.tenant_id, &p.user_id, &next.session_id, next.items[0].slot).await.unwrap().unwrap();
    let policy: IssuedPolicy = delivery.policy.decode().unwrap();
    assert_eq!(policy.configuration.desired_retention, 0.75);
    let memory_before = repo.get_memory(&p.tenant_id, &p.user_id, &item.card.id).await.unwrap();
    let history_before = exported_provenance(repo.as_ref(), &p, &item.card.id).await;
    feed.set_retention(
        &p,
        &memoswish_protocol::RetentionCommand { expected_revision: 1, desired_retention: Some(Some(0.99)) },
    )
    .await
    .unwrap();
    assert_eq!(repo.get_memory(&p.tenant_id, &p.user_id, &item.card.id).await.unwrap(), memory_before);
    assert_eq!(exported_provenance(repo.as_ref(), &p, &item.card.id).await, history_before);
}

#[tokio::test]
async fn quality_burial_selection_exact_elapsed_deadline_after_service_restart() {
    let (feed, repo, p) = seeded(1).await;
    let control = feed
        .set_card_control(
            &p,
            "card-000",
            &memoswish_protocol::CardControlCommand {
                expected_revision: 0,
                action: memoswish_protocol::CardControlAction::Bury,
            },
        )
        .await
        .unwrap();
    let deadline = control.buried_until.unwrap();
    drop(feed);
    let restarted = FeedService::new(repo, FeedConfig::default(), Arc::new(test_now)).unwrap();
    assert_eq!(restarted.card_control(&p, "card-000").await.unwrap(), control);
    let session = FeedSession {
        id: "burial-seed".into(),
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        next_slot: 0,
        recent_card_ids: vec![],
        created_at: test_now(),
        updated_at: test_now(),
    };
    let q = FeedQuery::default();
    assert!(
        restarted
            .generate_page(&p, &q, session.clone(), deadline - Duration::milliseconds(1))
            .await
            .unwrap()
            .0
            .items
            .is_empty()
    );
    for at in [deadline, deadline + Duration::milliseconds(1), deadline + Duration::days(1)] {
        assert_eq!(restarted.generate_page(&p, &q, session.clone(), at).await.unwrap().0.items.len(), 1);
    }
    // 观察过到期后再回拨时钟，仍按持久截止判断，不能永久清除隐藏状态。
    assert!(
        restarted
            .generate_page(&p, &q, session, deadline - Duration::hours(1))
            .await
            .unwrap()
            .0
            .items
            .is_empty()
    );
}

#[tokio::test]
async fn quality_retention_override_schedules_the_upstream_interval_and_resume_preserves_memory() {
    let mut due_dates = Vec::new();
    for retention in [0.6, 0.97] {
        let (feed, repo, p) = seeded(1).await;
        let previous = MemoryState {
            tenant_id: p.tenant_id.clone(),
            user_id: p.user_id.clone(),
            card_id: "card-000".into(),
            stability: 20.0,
            difficulty: 5.0,
            reps: 4,
            lapses: 0,
            exposures: 4,
            last_review: Some(test_now() - Duration::days(10)),
            due: Some(test_now() - Duration::days(1)),
            starred: true,
            last_rating: Some(3),
        };
        repo.upsert_memory(&previous).await.unwrap();
        feed.set_retention(
            &p,
            &memoswish_protocol::RetentionCommand { expected_revision: 0, desired_retention: Some(Some(retention)) },
        )
        .await
        .unwrap();
        let page = feed
            .next_page(&p, &FeedQuery { session_id: Some("retention-seed".into()), ..Default::default() })
            .await
            .unwrap();
        let mut exposure = event("card-000", 0, 5000, 1);
        exposure.shown_at = test_now();
        exposure.delivery_id = page.items[0].delivery_id.clone();
        let rating = feed.cfg.signals.interpret(&exposure).rating.unwrap();
        let expected = Fsrs::new(&feed.cfg.fsrs_parameters, retention)
            .unwrap()
            .review(Some(Memory { stability: previous.stability, difficulty: previous.difficulty }), 10.0, rating)
            .unwrap();
        let batch = FeedbackBatch {
            session_id: page.session_id,
            client_id: "retention-quality".into(),
            sent_at: test_now(),
            events: vec![exposure],
        };
        assert_eq!(feed.record_feedback(&p, &batch).await.unwrap().accepted, 1);
        let applied = repo.get_memory(&p.tenant_id, &p.user_id, "card-000").await.unwrap().unwrap();
        assert_eq!(applied.stability, expected.memory.stability);
        assert_eq!(applied.difficulty, expected.memory.difficulty);
        let expected_due = test_now() + Duration::milliseconds((expected.interval_days * 86_400_000.0) as i64);
        assert_eq!(applied.due, Some(expected_due));
        due_dates.push(expected_due);
        let stats = feed.stats(&p).await.unwrap();
        for (revision, action) in [
            (0, memoswish_protocol::CardControlAction::Suspend),
            (1, memoswish_protocol::CardControlAction::Resume),
        ] {
            feed.set_card_control(
                &p,
                "card-000",
                &memoswish_protocol::CardControlCommand { expected_revision: revision, action },
            )
            .await
            .unwrap();
            assert_eq!(repo.get_memory(&p.tenant_id, &p.user_id, "card-000").await.unwrap(), Some(applied.clone()));
            assert_eq!(feed.stats(&p).await.unwrap(), stats);
        }
    }
    assert!(due_dates[0] > due_dates[1]);
}

#[tokio::test]
async fn quality_legacy_issued_feed_policy_remains_accepted_after_guardrail_version_change() {
    let (feed, repo, p) = seeded(1).await;
    let request = FeedIssuanceRequest {
        query: FeedQuery { request_id: Some("legacy-feed-policy".into()), ..Default::default() },
        new_session_id: "legacy-policy-session".into(),
        legacy_request_id: "legacy-request".into(),
        now: test_now(),
    };
    let FeedIssuanceOutcome::Ready(expected) = repo.feed_issuance(&p, &request, None).await.unwrap() else {
        panic!("expected unissued state")
    };
    let (mut page, successor) =
        feed.generate_page(&p, &request.query, expected.session.clone(), test_now()).await.unwrap();
    let mut configuration = feed.cfg.clone();
    configuration.fsrs_parameters = feed.fsrs.parameters().to_vec();
    let policy = memoswish_core::repo::DeliveryPolicy::new(
        LEGACY_ISSUED_POLICY_VERSION,
        &IssuedPolicy { effective_page_limit: 10, deck_id: None, configuration },
    )
    .unwrap();
    page.mode = Some("learning".into());
    page.policy_version = Some(policy.version.clone());
    page.items[0].delivery_id = Some("legacy-policy-delivery".into());
    let candidate = FeedIssuanceCandidate { expected, page, successor, policy: Some(policy) };
    let FeedIssuanceOutcome::Committed(page) = repo.feed_issuance(&p, &request, Some(&candidate)).await.unwrap() else {
        panic!("expected committed legacy issuance")
    };
    let mut exposure = event("card-000", 0, 5000, 1);
    exposure.delivery_id = page.items[0].delivery_id.clone();
    let ack = feed
        .record_feedback(
            &p,
            &FeedbackBatch {
                session_id: page.session_id,
                client_id: "legacy-offline".into(),
                sent_at: test_now(),
                events: vec![exposure],
            },
        )
        .await
        .unwrap();
    assert_eq!(ack.accepted, 1);
    assert!(ISSUED_POLICY_VERSION.ends_with("feed2"));
}
