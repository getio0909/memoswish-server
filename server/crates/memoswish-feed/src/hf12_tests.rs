// 手动轮询固定排队顺序，避免用 sleep 推测调用者是否已登记。
#[tokio::test]
async fn hf12_blocked_learner_isolation_cancellation_and_generation_clock() {
    use crate::coordinator::tests::pending;

    let (feed, repo, p) = seeded(4).await;
    let peer = Principal { user_id: "hf12-peer".into(), ..p.clone() };
    let other_tenant = Principal { tenant_id: "hf12-other".into(), ..p.clone() };
    for principal in [&peer, &other_tenant] {
        repo.upsert_tenant(&memoswish_core::repo::TenantRecord {
            id: principal.tenant_id.clone(), name: "HF12".into(), plan: "free".into(), created_at: test_now(),
        }).await.unwrap();
        if principal.user_id == p.user_id {
            assert_eq!(repo.membership_join(&principal.tenant_id, &principal.user_id, memoswish_core::Role::Owner).await.unwrap(), 0);
        } else {
            repo.insert_user(&memoswish_core::repo::UserRecord {
                id: principal.user_id.clone(), tenant_id: principal.tenant_id.clone(),
                email: format!("{}@example.invalid", principal.user_id), display_name: "HF12".into(),
                password_hash: String::new(), role: memoswish_core::Role::Owner, created_at: test_now(),
            }).await.unwrap();
        }
    }
    let time = Arc::new(Mutex::new(test_now()));
    let source = time.clone();
    let feed = FeedService { clock: Arc::new(move || *source.lock().unwrap()), ..feed };
    let holder = feed.coordinator.acquire(&p.tenant_id, &p.user_id).await.unwrap();
    let query = FeedQuery { request_id: Some("queued-clock".into()), limit: Some(1), ..Default::default() };
    let mut queued = Box::pin(feed.next_page(&p, &query));
    pending(queued.as_mut());
    let cancelled_query = FeedQuery { request_id: Some("cancelled".into()), ..Default::default() };
    let mut cancelled = Box::pin(feed.next_page(&p, &cancelled_query));
    pending(cancelled.as_mut());
    drop(cancelled);
    // 不同学习者与租户通过真实仓储成功发页，阻塞者仍持有原锁。
    for principal in [&peer, &other_tenant] {
        feed.next_page(principal, &FeedQuery { request_id: Some("independent".into()), ..Default::default() })
            .await
            .unwrap();
    }
    assert_eq!(feed.coordinator.registered(), 2);
    let after_wait = test_now() + Duration::minutes(2);
    *time.lock().unwrap() = after_wait;
    drop(holder);
    assert_eq!(queued.await.unwrap().generated_at, after_wait);
    assert_eq!(feed.coordinator.registered(), 0);
    let export = repo.account_export(&p.tenant_id, &p.user_id, false).await.unwrap();
    assert_eq!(export["learner_preferences"][0]["epoch"], "1");
    assert_eq!(export["feed_sessions"].as_array().unwrap().len(), 6);
}

#[tokio::test]
async fn hf12_file_wal_ten_distinct_and_identical_requests() {
    let root = std::env::temp_dir().join(format!("hf12-feed-{}", new_id()));
    std::fs::create_dir(&root).unwrap();
    let url = format!("sqlite://{}", root.join("feed.db").display());
    let repo = Arc::new(SqliteRepository::connect_with_max_connections(&url, 2).await.unwrap());
    let (feed, backend, p) = seeded_in(repo.clone(), 12).await;
    for identical in [false, true] {
        let barrier = Arc::new(tokio::sync::Barrier::new(10));
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..10 {
            let service = feed.clone();
            let principal = p.clone();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                let q = FeedQuery {
                    request_id: Some(format!("burst-{}", if identical { 10 } else { index })),
                    limit: Some(2),
                    ..Default::default()
                };
                barrier.wait().await;
                (q.clone(), service.next_page(&principal, &q).await.unwrap())
            });
        }
        let mut pages = vec![];
        while let Some(result) = tasks.join_next().await {
            let (query, page) = result.unwrap();
            assert_eq!(page.items.len(), 2);
            assert_eq!(feed.next_page(&p, &query).await.unwrap(), page);
            pages.push(page);
        }
        let session_count = pages.iter().map(|page| &page.session_id).collect::<HashSet<_>>().len();
        let deliveries = pages.iter().flat_map(|page| page.items.iter().map(|item| &item.delivery_id));
        assert_eq!(session_count, if identical { 1 } else { 10 });
        assert_eq!(deliveries.collect::<HashSet<_>>().len(), if identical { 2 } else { 20 });
        let export = backend.account_export(&p.tenant_id, &p.user_id, false).await.unwrap();
        let issued = if identical { 11 } else { 10 };
        assert_eq!(export["feed_sessions"].as_array().unwrap().len(), 5 + issued);
        assert_eq!(export["learner_preferences"][0]["epoch"], issued.to_string());
        assert_eq!(export["learner_preferences"][0]["issuance_seq"], issued.to_string());
    }
    assert_eq!(feed.coordinator.registered(), 0);
    drop(feed);
    drop(backend);
    repo.pool().close().await;
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn hf12_retry_causes_count_once_per_attempt_including_exhaustion() {
    use memoswish_core::observability::{FeedRetryCause, Observer};
    use memoswish_core::repo::FeedIssuanceOutcome;
    #[derive(Default)]
    struct Counts(Mutex<Vec<FeedRetryCause>>);
    impl Observer for Counts {
        fn feed_retry(&self, cause: FeedRetryCause) {
            self.0.lock().unwrap().push(cause);
        }
    }
    let counts = Counts::default();
    let page = examples::sample_feed_page();
    let mut results = vec![
        Ok(FeedIssuanceOutcome::Retry(FeedRetryCause::StateMismatch)),
        Ok(FeedIssuanceOutcome::Retry(FeedRetryCause::SessionRevision)),
        Err(CoreError::FeedRetry(FeedRetryCause::DatabaseBusyLocked)),
        Err(CoreError::FeedRetry(FeedRetryCause::Other)),
        Err(CoreError::Unavailable("private SQL/request/tenant payload".into())),
        Ok(FeedIssuanceOutcome::Committed(page.clone())),
    ].into_iter();
    assert_eq!(retry_issuance(&counts, || std::future::ready(results.next().unwrap())).await.unwrap(), page);
    assert_eq!(*counts.0.lock().unwrap(), [FeedRetryCause::StateMismatch, FeedRetryCause::SessionRevision,
        FeedRetryCause::DatabaseBusyLocked, FeedRetryCause::Other, FeedRetryCause::Other]);
    let counts = Counts::default();
    let error = retry_issuance(&counts, || std::future::ready(Err(CoreError::FeedRetry(FeedRetryCause::DatabaseBusyLocked)))).await.unwrap_err();
    assert!(matches!(error, CoreError::Unavailable(_)));
    assert_eq!(*counts.0.lock().unwrap(), vec![FeedRetryCause::DatabaseBusyLocked; TRANSACTION_ATTEMPTS]);
    let counts = Counts::default();
    assert!(retry_issuance(&counts, || std::future::ready(Err(CoreError::invalid("private")))).await.is_err());
    assert!(counts.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn hf12_candidate_queries_preserve_busy_cause_through_retry_accounting() {
    use memoswish_core::observability::{FeedRetryCause, Observer};
    use memoswish_core::repo::{FeedCandidateRepo, FeedIssuanceOutcome};

    #[derive(Default)]
    struct Counts(Mutex<Vec<FeedRetryCause>>);
    impl Observer for Counts {
        fn feed_retry(&self, cause: FeedRetryCause) {
            self.0.lock().unwrap().push(cause);
        }
    }

    for hydrate in [false, true] {
        let root = std::env::temp_dir().join(format!("hf12-candidates-{}", new_id()));
        std::fs::create_dir(&root).unwrap();
        let url = format!("sqlite://{}", root.join("feed.db").display());
        let repo = SqliteRepository::connect_with_max_connections(&url, 1).await.unwrap();
        // 仅夹具切换为回滚日志，让独占事务确定性阻塞 SELECT；单连接保留零等待配置。
        repo.pool()
            .begin_with("PRAGMA journal_mode=DELETE; PRAGMA busy_timeout=0; BEGIN")
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        let options = repo.pool().connect_options().as_ref().clone()
            .pragma("journal_mode", "DELETE")
            .busy_timeout(std::time::Duration::ZERO);
        let blocker = repo.pool().options().clone().connect_with(options).await.unwrap();
        for exhaust in [false, true] {
            let holder = tokio::sync::Mutex::new(Some(blocker.begin_with("BEGIN EXCLUSIVE").await.unwrap()));
            let counts = Counts::default();
            let mut attempts = 0;
            let result = retry_issuance(&counts, || {
                attempts += 1;
                let release = !exhaust && attempts == 3;
                let holder = &holder;
                let repo = &repo;
                async move {
                    if release {
                        holder.lock().await.take().unwrap().rollback().await.unwrap();
                    }
                    // 两个真实仓储入口都必须经 SQLx 错误映射后进入唯一计数点。
                    let query = if hydrate {
                        repo.hydrate_feed_cards("hf12", None, &["card".into()]).await.map(|_| ())
                    } else {
                        repo.visit_feed_metadata("hf12", "learner", None, &mut |_| Ok(())).await
                    };
                    if let Err(error) = query {
                        assert!(matches!(error, CoreError::FeedRetry(FeedRetryCause::DatabaseBusyLocked)));
                        return Err(error);
                    }
                    Ok(FeedIssuanceOutcome::Committed(examples::sample_feed_page()))
                }
            }).await;
            let expected = if exhaust { TRANSACTION_ATTEMPTS } else { 2 };
            assert_eq!(*counts.0.lock().unwrap(), vec![FeedRetryCause::DatabaseBusyLocked; expected]);
            assert_eq!(attempts, if exhaust { TRANSACTION_ATTEMPTS } else { 3 });
            if exhaust {
                let error = result.unwrap_err();
                assert!(matches!(error, CoreError::Unavailable(_)));
                assert_eq!(error.public_message(), "temporarily unavailable");
                holder.lock().await.take().unwrap().rollback().await.unwrap();
            } else {
                assert_eq!(result.unwrap(), examples::sample_feed_page());
            }
        }
        blocker.close().await;
        repo.pool().close().await;
        std::fs::remove_dir_all(root).unwrap();
    }
}
