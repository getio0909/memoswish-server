//! S24 双库共用服务场景与可重复的完整域资源测量。

use super::*;
use memoswish_core::Role;
use memoswish_core::repo::{FeedCardMetadata, ReviewRepo, TenantRecord, UserRecord};
use memoswish_protocol::examples;

fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-07T12:00:00.123Z").unwrap().with_timezone(&Utc)
}

async fn library(repo: &dyn Repository, count: usize) -> (Principal, String) {
    let mut p = Principal::local_owner("s24");
    p.tenant_id = new_id();
    p.user_id = new_id();
    let now = fixed_now();
    repo.upsert_tenant(&TenantRecord {
        id: p.tenant_id.clone(),
        name: "S24".into(),
        plan: "free".into(),
        created_at: now,
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: p.user_id.clone(),
        tenant_id: p.tenant_id.clone(),
        email: format!("{}@example.invalid", p.user_id),
        display_name: "S24".into(),
        password_hash: "test-only".into(),
        role: Role::Owner,
        created_at: now,
    })
    .await
    .unwrap();
    let mut deck = examples::sample_deck();
    deck.id = "s24-deck".into();
    let cards: Vec<_> = (0..count)
        .map(|index| {
            let mut card = examples::sample_card();
            card.id = format!("s24-{index:06}");
            card.deck_id = deck.id.clone();
            card.created_at = now;
            card.updated_at = now;
            card
        })
        .collect();
    repo.insert_deck_with_cards(&p.tenant_id, &deck, &cards).await.unwrap();
    (p, deck.id)
}

fn state(p: &Principal, id: String) -> MemoryState {
    MemoryState {
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        card_id: id,
        stability: 10.0,
        difficulty: 5.0,
        reps: 1,
        lapses: 0,
        exposures: 2,
        last_review: Some(fixed_now() - Duration::days(5)),
        due: Some(fixed_now() + Duration::days(10)),
        starred: false,
        last_rating: Some(3),
    }
}

fn session(p: &Principal, id: &str) -> FeedSession {
    FeedSession {
        id: id.into(),
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        next_slot: 0,
        recent_card_ids: vec![],
        created_at: fixed_now(),
        updated_at: fixed_now(),
    }
}

async fn complete_domain(repo: Arc<dyn Repository>, seed_prefix: impl AsyncFnOnce(&Principal)) {
    // 前 5000 张均不属于候选桶，尾部四张分别覆盖旧默认扫描上限之外的唯一候选。
    let (p, deck) = library(repo.as_ref(), 5_004).await;
    let fsrs = Fsrs::default();
    let r = fsrs.retrievability(5.0, 10.0);
    assert!((0.9..=0.95).contains(&r), "prefix must belong to no bucket: {r}");
    seed_prefix(&p).await;
    let mut due = state(&p, "s24-005000".into());
    due.due = Some(fixed_now());
    repo.upsert_memory(&due).await.unwrap();
    let mut hard = state(&p, "s24-005002".into());
    hard.last_rating = Some(2);
    repo.upsert_memory(&hard).await.unwrap();
    let mut surprise = state(&p, "s24-005003".into());
    surprise.last_review = Some(fixed_now());
    repo.upsert_memory(&surprise).await.unwrap();

    let cases = [
        (FeedReason::Due, "s24-005000", 1.0, 0.0, 0.0, 0.0),
        (FeedReason::New, "s24-005001", 0.0, 1.0, 0.0, 0.0),
        (FeedReason::Reinforce, "s24-005002", 0.0, 0.0, 1.0, 0.0),
        (FeedReason::Surprise, "s24-005003", 1.0, 0.0, 0.0, 1.0),
    ];
    let account_snapshot = || async {
        let mut export = repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap();
        // 导出集合没有行序契约，只规范化顶层行序，保留行内容及页内项目等嵌套顺序。
        for collection in export.as_object_mut().unwrap().values_mut() {
            if let Some(rows) = collection.as_array_mut() {
                rows.sort_by_cached_key(ToString::to_string);
            }
        }
        export
    };
    let before = account_snapshot().await;
    let mut issuance_cases = Vec::new();
    for (reason, id, due_weight, new_weight, reinforce_weight, surprise_rate) in cases {
        let cfg =
            FeedConfig { scan_limit: 1, due_weight, new_weight, reinforce_weight, surprise_rate, ..Default::default() };
        let feed = FeedService::new(repo.clone(), cfg, Arc::new(fixed_now)).unwrap();
        for scope in [None, Some(deck.clone())] {
            let query = FeedQuery { deck_id: scope, limit: Some(2), ..Default::default() };
            let (page, _) = feed.generate_page(&p, &query, session(&p, "tail"), fixed_now()).await.unwrap();
            assert_eq!(page.items.len(), 2);
            assert_eq!((&page.items[1].reason, page.items[1].card.id.as_str()), (&reason, id));

            // 超过旧扫描边界的四类候选均走同一生成路径，预览不留下任何学习写入。
            let preview_query = FeedQuery { mode: Some("preview".into()), ..query.clone() };
            let preview = feed.next_page(&p, &preview_query).await.unwrap();
            assert_eq!(preview.generated_at, fixed_now());
            assert_eq!(preview.items.len(), 2);
            assert_eq!((&preview.items[1].reason, preview.items[1].card.id.as_str()), (&reason, id));
            assert_eq!(preview.mode.as_deref(), Some("preview"));
            assert!(preview.next_cursor.is_empty());
            assert!(preview.policy_version.is_none());
            assert!(preview.items[0].delivery_id.is_none());
            issuance_cases.push((feed.clone(), query, reason, id));
        }
    }
    assert!(account_snapshot().await == before, "preview changed stored account state");
    drop(before);

    // 正式签发保留逐投递的 S12 归因证据，重放仍直接返回 S11 原回执。
    let mut replay_cases = Vec::new();
    for (feed, query, reason, id) in issuance_cases {
        let issued_query = FeedQuery { request_id: Some(new_id()), ..query };
        let issued = feed.next_page(&p, &issued_query).await.unwrap();
        assert_eq!(issued.generated_at, fixed_now());
        assert_eq!(issued.items.len(), 2);
        let item = &issued.items[1];
        assert_eq!((&item.reason, item.card.id.as_str()), (&reason, id));
        let delivery =
            repo.get_delivery(&p.tenant_id, &p.user_id, &issued.session_id, item.slot).await.unwrap().unwrap();
        assert_eq!(delivery.card_id, item.card.id);
        assert_eq!(Some(&delivery.attribution.delivery_id), item.delivery_id.as_ref());
        assert_eq!(Some(&delivery.attribution.policy_version), issued.policy_version.as_ref());
        assert_eq!(delivery.attribution.revision_at_issuance, item.card.revision);
        assert_eq!(delivery.attribution.issued_at, fixed_now());
        assert_eq!(delivery.policy.decode::<IssuedPolicy>().unwrap().configuration.scan_limit, 1);
        replay_cases.push((feed, issued_query, issued));
    }
    let committed = account_snapshot().await;
    for (feed, query, issued) in replay_cases {
        assert_eq!(feed.next_page(&p, &query).await.unwrap(), issued);
    }
    assert!(account_snapshot().await == committed, "receipt replay changed stored account state");
    drop(committed);
    let mut starred = surprise.clone();
    starred.starred = true;
    repo.upsert_memory(&starred).await.unwrap();
    let feed = FeedService::new(repo.clone(), FeedConfig { scan_limit: 0, ..Default::default() }, Arc::new(fixed_now))
        .unwrap();
    for scope in [None, Some(deck.as_str())] {
        let stats = feed.stats_for_deck_at(&p, scope, fixed_now()).await.unwrap();
        assert_eq!(
            (stats.total_cards, stats.seen_cards, stats.due_cards, stats.starred_cards, stats.total_exposures),
            (5_004, 5_003, 1, 1, 10_006)
        );
        let observed = fixed_now();
        let memories = repo.list_memory(&p.tenant_id, &p.user_id).await.unwrap();
        let oracle =
            (memories.iter().map(|memory| feed.retrievability(memory, observed)).sum::<f64>() / 5_003.0) as f32;
        assert!((stats.average_retrievability - oracle).abs() < 1e-6);
        assert_eq!(feed.list_starred_cards(&p, scope).await.unwrap()[0].id, starred.card_id);
    }
    let absent = feed.stats_for_deck(&p, Some("missing")).await.unwrap();
    assert_eq!((absent.total_cards, absent.total_exposures), (0, 0));
    assert!(feed.list_starred_cards(&p, Some("missing")).await.unwrap().is_empty());
    let mut peer = p.clone();
    peer.user_id = "other-user".into();
    assert_eq!(feed.stats(&peer).await.unwrap().seen_cards, 0);
    assert!(feed.list_starred_cards(&peer, None).await.unwrap().is_empty());
    let mut foreign = p.clone();
    foreign.tenant_id = "foreign-tenant".into();
    assert_eq!(feed.stats(&foreign).await.unwrap().total_cards, 0);
    assert!(repo.hydrate_feed_cards(&foreign.tenant_id, None, &[starred.card_id.clone()]).await.unwrap().is_empty());
    assert!(
        repo.hydrate_feed_cards(&p.tenant_id, Some("missing"), &[starred.card_id.clone()]).await.unwrap().is_empty()
    );
    repo.delete_card(&p.tenant_id, &starred.card_id).await.unwrap();
    assert!(repo.get_memory(&p.tenant_id, &p.user_id, &starred.card_id).await.unwrap().is_some());
    assert_eq!(feed.stats(&p).await.unwrap().total_cards, 5_003);
    assert!(feed.list_starred_cards(&p, None).await.unwrap().is_empty());
    let fresh_feed = FeedService::new(
        repo.clone(),
        FeedConfig {
            scan_limit: 0,
            due_weight: 0.0,
            new_weight: 1.0,
            reinforce_weight: 0.0,
            surprise_rate: 0.0,
            ..Default::default()
        },
        Arc::new(fixed_now),
    )
    .unwrap();
    let query = FeedQuery { deck_id: Some(deck), limit: Some(2), request_id: Some(new_id()), ..Default::default() };
    let issued = fresh_feed.next_page(&p, &query).await.unwrap();
    assert_eq!(issued.items[1].card.id, "s24-005001");
    repo.delete_card(&p.tenant_id, "s24-005001").await.unwrap();
    assert_eq!(feed.next_page(&p, &query).await.unwrap(), issued);
}

async fn classification_and_resources(repo: Arc<dyn Repository>) {
    let (p, deck) = library(repo.as_ref(), 180).await;
    let now = fixed_now();
    for index in 0..180 {
        let mut m = state(&p, format!("s24-{index:06}"));
        match index % 9 {
            0 => {
                m.reps = 0;
                m.due = None;
                m.last_review = None;
                m.last_rating = None;
            }
            1 => {
                m.starred = true;
                m.due = Some(now);
            }
            2 => {
                m.due = None;
                m.last_review = Some(now - Duration::days(100));
            }
            3 => {
                m.due = None;
                m.last_review = Some(now + Duration::days(1));
            }
            4 => {
                m.stability = 0.0;
                m.last_rating = Some(1);
            }
            5 => {
                m.stability = -1.0;
                m.last_rating = Some(2);
            }
            6 => {
                m.due = Some(now + Duration::milliseconds(1));
                m.last_review = Some(now);
            }
            7 => {
                m.due = Some(now - Duration::milliseconds(1));
            }
            _ => {
                m.last_review = Some(now - Duration::milliseconds(1));
                m.last_rating = None;
            }
        }
        repo.upsert_memory(&m).await.unwrap();
    }
    let mut params = fsrs::DEFAULT_PARAMETERS.to_vec();
    params[20] = 0.2;
    let cfg = FeedConfig {
        recent_window: 2,
        max_page: 50,
        fsrs_parameters: params,
        desired_retention: 0.97,
        ..Default::default()
    };
    let feed = FeedService::new(repo.clone(), cfg.clone(), Arc::new(fixed_now)).unwrap();
    let previous = "s24-000179".to_string();
    let mut sess = session(&p, "classification");
    sess.recent_card_ids.push(previous.clone());
    let set = crate::candidates::CandidateSet::load(
        repo.as_ref(),
        &p,
        &cfg,
        &feed.fsrs,
        &sess,
        crate::candidates::CandidateRequest { deck: Some(&deck), now, page: 1 },
    )
    .await
    .unwrap();
    assert_eq!(set.distinct, 180);
    assert!(set.cards.iter().any(|card| card.id == previous));
    assert!(!set.fresh.is_empty(), "exposure-only reps=0 rows consume the new-card budget");
    assert!(set.cards.len() <= 5 * (cfg.recent_window + 1 + 16) + 2);
    let metadata: Vec<_> = repo.list_memory(&p.tenant_id, &p.user_id).await.unwrap();
    let stats = feed.stats_for_deck_at(&p, Some(&deck), now).await.unwrap();
    let reviewed: Vec<_> = metadata.iter().filter(|m| m.reps > 0).collect();
    assert_eq!(stats.total_cards, 180);
    assert_eq!(stats.seen_cards as usize, reviewed.len());
    assert_eq!(stats.starred_cards as usize, metadata.iter().filter(|m| m.starred).count());
    assert_eq!(stats.total_exposures, metadata.iter().map(|m| u64::from(m.exposures)).sum::<u64>());
    assert_eq!(stats.due_cards as usize, reviewed.iter().filter(|m| m.due.is_some_and(|due| due <= now)).count());
    let oracle = (reviewed.iter().map(|m| feed.retrievability(m, now)).sum::<f64>() / reviewed.len() as f64) as f32;
    assert!((stats.average_retrievability - oracle).abs() < 1e-6);
    let mut due: Vec<_> = metadata
        .iter()
        .filter(|m| m.reps > 0)
        .filter_map(|m| {
            let r = feed.retrievability(m, now);
            (m.due.is_some_and(|due| due <= now) || r < cfg.desired_retention).then_some((r, m.card_id.clone()))
        })
        .collect();
    due.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
    assert_eq!(set.due, due.into_iter().take(19).map(|(_, id)| id).collect::<Vec<_>>());
    let mut reinforce: Vec<_> =
        metadata.iter().filter(|m| m.reps > 0 && (m.starred || m.last_rating.is_some_and(|r| r <= 2))).collect();
    reinforce.sort_by_key(|m| (m.last_review.unwrap_or(DateTime::UNIX_EPOCH), m.card_id.clone()));
    assert_eq!(set.reinforce, reinforce.into_iter().take(19).map(|m| m.card_id.clone()).collect::<Vec<_>>());
    let again = crate::candidates::CandidateSet::load(
        repo.as_ref(),
        &p,
        &cfg,
        &feed.fsrs,
        &sess,
        crate::candidates::CandidateRequest { deck: Some(&deck), now, page: 1 },
    )
    .await
    .unwrap();
    assert_eq!(set.surprise, again.surprise);
    let expected_surprise: HashSet<_> = metadata
        .iter()
        .filter(|memory| {
            let r = feed.retrievability(memory, now);
            memory.reps > 0
                && !memory.due.is_some_and(|due| due <= now)
                && r >= cfg.desired_retention
                && (r > 0.95 || memory.starred)
        })
        .map(|memory| memory.card_id.clone())
        .collect();
    let mut reached = HashSet::new();
    for seed in 0..64 {
        let sess = session(&p, &format!("reservoir-{seed}"));
        let set = crate::candidates::CandidateSet::load(
            repo.as_ref(),
            &p,
            &cfg,
            &feed.fsrs,
            &sess,
            crate::candidates::CandidateRequest { deck: Some(&deck), now, page: 1 },
        )
        .await
        .unwrap();
        reached.extend(set.surprise);
    }
    assert_eq!(reached, expected_surprise);

    let mut visited = 0;
    let failed = repo
        .visit_feed_metadata(&p.tenant_id, &p.user_id, None, &mut |_: FeedCardMetadata| {
            visited += 1;
            Err(CoreError::internal("injected metadata visitor failure"))
        })
        .await;
    assert!(matches!(failed, Err(CoreError::Internal(_))));
    assert_eq!(visited, 1);
}

async fn stats_snapshot(repo: Arc<dyn Repository>) {
    for deck_scoped in [false, true] {
        for (learn, delete) in [(true, false), (false, true), (true, true)] {
            let (p, deck) = library(repo.as_ref(), if delete { 2 } else { 1 }).await;
            let writer = FeedService::new(repo.clone(), FeedConfig::default(), Arc::new(fixed_now)).unwrap();
            if delete {
                let mut memory = state(&p, "s24-000001".into());
                memory.starred = true;
                repo.upsert_memory(&memory).await.unwrap();
            }
            let scope = deck_scoped.then_some(deck.as_str());
            let before = writer.stats_for_deck_at(&p, scope, fixed_now()).await.unwrap();
            assert_eq!(
                (before.total_cards, before.seen_cards, before.due_cards, before.starred_cards, before.total_exposures),
                if delete { (2, 1, 0, 1, 2) } else { (1, 0, 0, 0, 0) }
            );

            let gate = Arc::new(tokio::sync::Barrier::new(2));
            let mut reader = writer.clone();
            reader.stats_gate = Some(gate.clone());
            let reader_p = p.clone();
            let reader_deck = deck_scoped.then_some(deck.clone());
            let read = tokio::spawn(async move {
                reader.stats_for_deck_at(&reader_p, reader_deck.as_deref(), fixed_now()).await.unwrap()
            });
            // 暂停在原汇总与元数据读取的边界，提交真实反馈和删除后才放行。
            gate.wait().await;
            if learn {
                // 真实签发提供 S12 所需绑定，历史曝光时间仍用于验证已到期的首次学习。
                let page = writer
                    .next_page(&p, &FeedQuery { deck_id: Some(deck.clone()), limit: Some(2), ..Default::default() })
                    .await
                    .unwrap();
                let item = page.items.iter().find(|item| item.card.id == "s24-000000").unwrap();
                let mut batch = examples::sample_feedback_batch();
                batch.session_id = page.session_id.clone();
                batch.events.truncate(1);
                let event = &mut batch.events[0];
                event.card_id = item.card.id.clone();
                event.slot = item.slot;
                event.delivery_id = item.delivery_id.clone();
                event.shown_at = fixed_now() - Duration::days(100);
                event.dwell_time_ms = 4_000;
                event.loop_count = 1;
                event.double_tapped = true;
                event.long_pressed = false;
                let ack = writer.record_feedback_at(&p, &batch, fixed_now()).await.unwrap();
                assert_eq!((ack.accepted, ack.duplicates, ack.rejected.len()), (1, 0, 0));
            }
            if delete {
                repo.delete_card(&p.tenant_id, "s24-000001").await.unwrap();
                assert!(repo.get_memory(&p.tenant_id, &p.user_id, "s24-000001").await.unwrap().is_some());
            }
            gate.wait().await;
            let observed = read.await.unwrap();
            let expected = if learn {
                let memory = repo.get_memory(&p.tenant_id, &p.user_id, "s24-000000").await.unwrap().unwrap();
                assert_eq!(memory.reps, 1);
                assert!(memory.due.is_some_and(|due| due <= fixed_now()));
                LearningStats {
                    total_cards: 1,
                    seen_cards: 1,
                    due_cards: 1,
                    starred_cards: 1,
                    total_exposures: 1,
                    average_retrievability: writer.retrievability(&memory, fixed_now()) as f32,
                }
            } else {
                LearningStats {
                    total_cards: 1,
                    seen_cards: 0,
                    due_cards: 0,
                    starred_cards: 0,
                    total_exposures: 0,
                    average_retrievability: 0.0,
                }
            };
            assert_eq!(observed, expected, "deck_scoped={deck_scoped}, learn={learn}, delete={delete}");
            assert_eq!(writer.stats_for_deck_at(&p, scope, fixed_now()).await.unwrap(), expected);
            assert!(observed.due_cards <= observed.seen_cards);
            let mut peer = p.clone();
            peer.user_id = new_id();
            let peer_stats = writer.stats_for_deck_at(&peer, scope, fixed_now()).await.unwrap();
            assert_eq!((peer_stats.seen_cards, peer_stats.starred_cards, peer_stats.total_exposures), (0, 0, 0));
            let mut foreign = p.clone();
            foreign.tenant_id = new_id();
            assert_eq!(writer.stats_for_deck_at(&foreign, scope, fixed_now()).await.unwrap().total_cards, 0);
        }
    }
}

#[tokio::test]
async fn sqlite_s24_stats_snapshot() {
    stats_snapshot(Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap())).await;
}

#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
fn postgres_s24_stats_snapshot() {
    memoswish_storage::pg_test_support::run_pg_test(|test| async move {
        let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
            .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
        let fixture = test.fixture(&url).await;
        let repo = Arc::new(fixture.repository(8).await.unwrap());
        stats_snapshot(repo.clone()).await;
        drop(repo);
        fixture.cleanup().await;
    });
}

#[tokio::test]
async fn sqlite_s24_complete_domain() {
    let repo = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
    complete_domain(repo.clone(), async |p| {
        for index in 0..5_000 {
            repo.upsert_memory(&state(p, format!("s24-{index:06}"))).await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn sqlite_s24_classification_and_resources() {
    classification_and_resources(Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap()))
        .await;
}

#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
fn postgres_s24_service_conformance() {
    memoswish_storage::pg_test_support::run_pg_test(|test| async move {
        let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
            .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
        let fixture = test.fixture(&url).await;
        let repo = Arc::new(fixture.repository(8).await.unwrap());
        complete_domain(repo.clone(), async |p| {
            // 保留旧 5000 上限之后的四类候选，批量构造同质前缀以降低 PG 事务成本。
            repo.s24_conformance_memory_prefix(&state(p, String::new()), "s24-005000").await;
        })
        .await;
        classification_and_resources(repo.clone()).await;
        drop(repo);
        fixture.cleanup().await;
    });
}

#[expect(clippy::disallowed_methods, reason = "S24 fixture benchmark measures real elapsed time")]
async fn measure(repo: Arc<dyn Repository>, p: Principal, backend: &str, count: usize, dense: bool) {
    let feed = FeedService::new(repo.clone(), FeedConfig::default(), Arc::new(fixed_now)).unwrap();
    let deck = examples::sample_deck().id;
    for scope in [None, Some(deck.as_str())] {
        let mut baseline = vec![];
        let mut final_times = vec![];
        let mut hydrated = 0;
        let mut retained = 0;
        for _ in 0..3 {
            let start = std::time::Instant::now();
            let cards = repo.list_cards(&p.tenant_id, scope, 5_000, 0).await.unwrap();
            let memory = repo.list_memory(&p.tenant_id, &p.user_id).await.unwrap();
            baseline.push(start.elapsed().as_secs_f64() * 1_000.0);
            assert_eq!(cards.len(), count.min(5_000));
            assert_eq!(memory.len(), if dense { count } else { 0 });
            drop((cards, memory));
            let start = std::time::Instant::now();
            let set = crate::candidates::CandidateSet::load(
                repo.as_ref(),
                &p,
                &feed.cfg,
                &feed.fsrs,
                &session(&p, "measure"),
                crate::candidates::CandidateRequest { deck: scope, now: fixed_now(), page: 10 },
            )
            .await
            .unwrap();
            final_times.push(start.elapsed().as_secs_f64() * 1_000.0);
            assert_eq!(set.distinct, count);
            hydrated = set.cards.len();
            retained = set.due.len() + set.fresh.len() + set.reinforce.len() + set.surprise.len() + set.fallback.len();
            // 有界桶之外仅允许公平首位和上一张上下文各补一张正文。
            assert!(hydrated <= 5 * (20 + 10 + 16) + 2);
        }
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let rss = status.lines().find(|line| line.starts_with("VmRSS:")).unwrap();
        println!("S24_PROCESS_MEMORY backend={backend} count={count} dense={dense} deck={} {rss}", scope.is_some());
        baseline.sort_by(f64::total_cmp);
        final_times.sort_by(f64::total_cmp);
        println!(
            "S24_MEASURE backend={backend} count={count} dense={dense} deck={} baseline_read_ms={:.3} final_candidates_ms={:.3} metadata_rows={count} hydrated={hydrated} retained_entries={retained} candidate_selects=2",
            scope.is_some(),
            baseline[1],
            final_times[1]
        );
        let start = std::time::Instant::now();
        let (page, _) = feed
            .generate_page(
                &p,
                &FeedQuery { deck_id: scope.map(str::to_owned), ..Default::default() },
                session(&p, "measure-page"),
                fixed_now(),
            )
            .await
            .unwrap();
        println!(
            "S24_PAGE backend={backend} count={count} dense={dense} deck={} ms={:.3} items={}",
            scope.is_some(),
            start.elapsed().as_secs_f64() * 1_000.0,
            page.items.len()
        );
        assert_eq!(page.items.len(), if dense { 10 } else { 4 });
        assert_eq!(page.items.iter().map(|item| &item.card.id).collect::<HashSet<_>>().len(), page.items.len());
    }
}

async fn sqlite_measurement(count: usize, dense: bool) {
    let repo = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
    let p = repo.s24_measurement_fixture(count, dense).await;
    let deck = examples::sample_deck().id;
    for scope in [None, Some(deck.as_str())] {
        println!(
            "S24_PLAN backend=sqlite count={count} dense={dense} deck={}\n{}",
            scope.is_some(),
            repo.s24_query_plans(&p, scope).await.join("\n")
        );
    }
    measure(repo, p, "sqlite", count, dense).await;
}

fn postgres_measurement(count: usize, dense: bool) {
    memoswish_storage::pg_test_support::run_pg_test(|test| async move {
        let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
            .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
        let fixture = test.fixture(&url).await;
        let repo = Arc::new(fixture.repository(8).await.unwrap());
        let p = repo.s24_measurement_fixture(count, dense).await;
        let deck = examples::sample_deck().id;
        for scope in [None, Some(deck.as_str())] {
            println!(
                "S24_PLAN backend=postgres count={count} dense={dense} deck={}\n{}",
                scope.is_some(),
                repo.s24_query_plans(&p, scope).await.join("\n")
            );
        }
        measure(repo.clone(), p, "postgres", count, dense).await;
        drop(repo);
        fixture.cleanup().await;
    });
}

macro_rules! measurement_cases {
    ($sqlite:ident, $postgres:ident, $count:literal, $dense:literal) => {
        #[tokio::test]
        #[ignore = "measurement: run S24 fixture benchmark explicitly"]
        async fn $sqlite() {
            sqlite_measurement($count, $dense).await;
        }

        #[test]
        #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL; S24 measurement"]
        fn $postgres() {
            postgres_measurement($count, $dense);
        }
    };
}

measurement_cases!(sqlite_s24_measure_6001_sparse, postgres_s24_measure_6001_sparse, 6_001, false);
measurement_cases!(sqlite_s24_measure_6001_dense, postgres_s24_measure_6001_dense, 6_001, true);
measurement_cases!(sqlite_s24_measure_10000_sparse, postgres_s24_measure_10000_sparse, 10_000, false);
measurement_cases!(sqlite_s24_measure_10000_dense, postgres_s24_measure_10000_dense, 10_000, true);
measurement_cases!(sqlite_s24_measure_100000_sparse, postgres_s24_measure_100000_sparse, 100_000, false);
measurement_cases!(sqlite_s24_measure_100000_dense, postgres_s24_measure_100000_dense, 100_000, true);

async fn archived_and_skewed(repo: Arc<dyn Repository>, p: Principal, backend: &str) {
    let stats = repo.feed_summary(&p.tenant_id, &p.user_id, None).await.unwrap();
    assert_eq!(
        (stats.total_cards, stats.seen_cards, stats.starred_cards, stats.total_exposures),
        (1_000, 1_000, 1_000, 2_000)
    );
    assert_eq!(repo.starred_feed_cards(&p.tenant_id, &p.user_id, None).await.unwrap().len(), 1_000);
    measure(repo, p, backend, 1_000, true).await;
}

#[tokio::test]
#[ignore = "measurement: run S24 fixture benchmark explicitly"]
async fn sqlite_s24_measure_archived_skewed() {
    let repo = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
    let p = repo.s24_measurement_fixture(10_000, true).await;
    let _foreign = repo.s24_measurement_fixture(100_000, false).await;
    repo.s24_measurement_archive_prefix(&p, "measure-009000").await;
    let deck = examples::sample_deck().id;
    for scope in [None, Some(deck.as_str())] {
        println!(
            "S24_PLAN backend=sqlite-archived-skewed deck={}\n{}",
            scope.is_some(),
            repo.s24_query_plans(&p, scope).await.join("\n")
        );
    }
    archived_and_skewed(repo, p, "sqlite-archived-skewed").await;
}

#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL; S24 measurement"]
fn postgres_s24_measure_archived_skewed() {
    memoswish_storage::pg_test_support::run_pg_test(|test| async move {
        let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
        let fixture = test.fixture(&url).await;
        let repo = Arc::new(fixture.repository(8).await.unwrap());
        let p = repo.s24_measurement_fixture(10_000, true).await;
        let _foreign = repo.s24_measurement_fixture(100_000, false).await;
        repo.s24_measurement_archive_prefix(&p, "measure-009000").await;
        let deck = examples::sample_deck().id;
        for scope in [None, Some(deck.as_str())] {
            println!(
                "S24_PLAN backend=postgres-archived-skewed deck={}\n{}",
                scope.is_some(),
                repo.s24_query_plans(&p, scope).await.join("\n")
            );
        }
        archived_and_skewed(repo.clone(), p, "postgres-archived-skewed").await;
        drop(repo);
        fixture.cleanup().await;
    });
}
