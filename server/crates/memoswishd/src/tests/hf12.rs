//! 生产服务、数据库持久结果与 HTTP 错误映射的 HF12 回归。

use super::*;
use memoswish_core::repo::{Repository, ReviewRepo, TenantRecord, UserRecord};
use memoswish_core::{Principal, Role};
use memoswish_feed::{FeedConfig, FeedService};
use memoswish_protocol::{FeedQuery, examples};
use std::collections::HashSet;
use std::sync::Arc;

async fn seed(repo: &dyn Repository) -> Principal {
    let p = Principal::local_owner("hf12");
    let deck = examples::sample_deck();
    repo.upsert_tenant(&TenantRecord {
        id: p.tenant_id.clone(),
        name: "HF12".into(),
        plan: "free".into(),
        created_at: deck.created_at,
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: p.user_id.clone(),
        tenant_id: p.tenant_id.clone(),
        email: "hf12@example.invalid".into(),
        display_name: "HF12".into(),
        password_hash: String::new(),
        role: Role::Owner,
        created_at: deck.created_at,
    })
    .await
    .unwrap();
    let cards: Vec<_> = (0..12)
        .map(|index| {
            let mut card = examples::sample_card();
            card.id = format!("hf12-{index}");
            card
        })
        .collect();
    repo.insert_deck_with_cards(&p.tenant_id, &deck, &cards).await.unwrap();
    p
}

fn service(repo: Arc<dyn Repository>) -> FeedService {
    FeedService::new(repo, FeedConfig::default(), Arc::new(chrono::Utc::now)).unwrap()
}

async fn burst(services: &[FeedService], p: &Principal, query: FeedQuery, distinct: bool) -> Vec<FeedPage> {
    let barrier = Arc::new(tokio::sync::Barrier::new(10));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..10 {
        let feed = services[index % services.len()].clone();
        let p = p.clone();
        let barrier = barrier.clone();
        let mut q = query.clone();
        if distinct {
            q.request_id = Some(format!("{}-{index}", query.request_id.as_ref().unwrap()));
        }
        tasks.spawn(async move {
            barrier.wait().await;
            let page = feed.next_page(&p, &q).await.unwrap();
            assert_eq!(page.items.len(), 2);
            assert_eq!(feed.next_page(&p, &q).await.unwrap(), page);
            page
        });
    }
    let mut pages = vec![];
    while let Some(result) = tasks.join_next().await {
        pages.push(result.unwrap());
    }
    if distinct {
        assert_eq!(pages.iter().map(|page| &page.session_id).collect::<HashSet<_>>().len(), 10);
        assert_eq!(
            pages.iter().flat_map(|page| page.items.iter().map(|item| &item.delivery_id)).collect::<HashSet<_>>().len(),
            20
        );
    } else {
        assert!(pages.iter().all(|page| page == &pages[0]));
    }
    pages
}

macro_rules! counts {
    ($pool:expr, $p:expr, $sessions:expr, $receipts:expr, $deliveries:expr, $epoch:expr) => {{
        for (table, expected) in
            [("feed_sessions", $sessions), ("feed_page_receipts", $receipts), ("feed_deliveries", $deliveries)]
        {
            let query = format!("SELECT COUNT(*) FROM {table} WHERE tenant_id=$1 AND user_id=$2");
            let count: i64 =
                sqlx::query_scalar(&query).bind(&$p.tenant_id).bind(&$p.user_id).fetch_one($pool).await.unwrap();
            assert_eq!(count, expected, "unexpected committed count for {table}");
        }
        let state: (i64, i64) =
            sqlx::query_as("SELECT epoch,issuance_seq FROM learner_preferences WHERE tenant_id=$1 AND user_id=$2")
                .bind(&$p.tenant_id)
                .bind(&$p.user_id)
                .fetch_one($pool)
                .await
                .unwrap();
        assert_eq!(state, ($epoch, $epoch));
    }};
}

macro_rules! scenario {
    ($repo:expr) => {{
        let p = seed($repo.as_ref()).await;
        let feed = service($repo.clone());
        let q = FeedQuery { request_id: Some("distinct".into()), limit: Some(2), ..Default::default() };
        burst(std::slice::from_ref(&feed), &p, q, true).await;
        counts!($repo.pool(), p, 10, 10, 20, 10);
        let q = FeedQuery { request_id: Some("identical".into()), limit: Some(2), ..Default::default() };
        let first = burst(std::slice::from_ref(&feed), &p, q.clone(), false).await.remove(0);
        counts!($repo.pool(), p, 11, 11, 22, 11);
        let continuation = FeedQuery {
            session_id: Some(first.session_id.clone()),
            cursor: Some(first.next_cursor.clone()),
            limit: Some(2),
            ..Default::default()
        };
        let next = burst(std::slice::from_ref(&feed), &p, continuation.clone(), false).await.remove(0);
        assert_eq!(next.items[0].slot, 2);
        let stored = $repo.get_session(&p.tenant_id, &p.user_id, &first.session_id).await.unwrap().unwrap();
        assert_eq!(stored.next_slot, 4);
        let restarted = service($repo.clone());
        assert_eq!(restarted.next_page(&p, &q).await.unwrap(), first);
        assert_eq!(restarted.next_page(&p, &continuation).await.unwrap(), next);
        for mut changed in [q, continuation] {
            changed.limit = Some(3);
            assert!(matches!(restarted.next_page(&p, &changed).await, Err(memoswish_core::CoreError::Conflict(_))));
        }
        counts!($repo.pool(), p, 11, 12, 24, 12);
        (p, feed)
    }};
}

#[tokio::test]
async fn hf12_sqlite_durable_counts_replay_and_overload() {
    use axum::response::IntoResponse;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let root = std::env::temp_dir().join(format!("hf12-durable-{}", memoswish_core::ids::new_id()));
    std::fs::create_dir(&root).unwrap();
    let url = format!("sqlite://{}", root.join("feed.db").display());
    let repo =
        Arc::new(memoswish_storage::sqlite::SqliteRepository::connect_with_max_connections(&url, 1).await.unwrap());
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode").fetch_one(repo.pool()).await.unwrap();
    assert_eq!(journal, "wal");
    let (p, feed) = scenario!(repo);
    // 占满唯一连接，使持有者停在首个数据库操作，等待者只占应用队列。
    let connection = repo.pool().acquire().await.unwrap();
    let query = FeedQuery { request_id: Some("overloaded".into()), limit: Some(2), ..Default::default() };
    let mut calls: Vec<_> = (0..32).map(|_| Box::pin(feed.next_page(&p, &query))).collect();
    let started = std::time::Instant::now();
    for call in &mut calls {
        assert!(matches!(call.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Pending));
    }
    let error = feed.next_page(&p, &query).await.unwrap_err();
    let response = crate::api::ApiErr(error).into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "temporarily_unavailable");
    let queued = calls.pop().unwrap();
    let response = crate::api::ApiErr(queued.await.unwrap_err()).into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    assert!(started.elapsed() >= std::time::Duration::from_secs(2));
    assert!(started.elapsed() < std::time::Duration::from_millis(2500));
    // 取消持有者及余下等待者后，先验证零接受，再重试同一身份。
    drop(calls);
    drop(connection);
    counts!(repo.pool(), p, 11, 12, 24, 12);
    feed.next_page(&p, &query).await.unwrap();
    counts!(repo.pool(), p, 12, 13, 26, 13);
    drop(feed);
    repo.pool().close().await;
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
fn hf12_postgres_durable_bursts_and_independent_instances() {
    memoswish_storage::pg_test_support::run_pg_test(|test| async move {
        let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
            .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
        let fixture = test.fixture(&url).await;
        let repo = Arc::new(fixture.repository(2).await.unwrap());
        let (p, feed) = scenario!(repo);
        // 两个独立仓储和服务实例，不能共享进程内协调器。
        let other = Arc::new(fixture.repository(2).await.unwrap());
        let replica = service(other.clone());
        let services = [feed, replica];
        let q = FeedQuery { request_id: Some("replicas-identical".into()), limit: Some(2), ..Default::default() };
        burst(&services, &p, q, false).await;
        counts!(repo.pool(), p, 12, 13, 26, 13);
        let q = FeedQuery { request_id: Some("replicas-distinct".into()), limit: Some(2), ..Default::default() };
        burst(&services, &p, q, true).await;
        counts!(repo.pool(), p, 22, 23, 46, 23);
        drop(services);
        repo.pool().close().await;
        other.pool().close().await;
        fixture.cleanup().await;
    });
}

#[tokio::test]
async fn hf12_http_burst_and_effective_pool_configuration() {
    let (router, state, dir) = app(DeploymentMode::SingleUser).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(10));
    let mut requests = tokio::task::JoinSet::new();
    for index in 0..10 {
        let router = router.clone();
        let barrier = barrier.clone();
        requests.spawn(async move {
            barrier.wait().await;
            let (status, _, body) = send(&router, get(&format!("/v1/feed?request_id=burst-{index}&limit=2"))).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            serde_json::from_slice::<FeedPage>(&body).unwrap()
        });
    }
    let mut ids = HashSet::new();
    while let Some(result) = requests.join_next().await {
        assert!(ids.insert(result.unwrap().session_id));
    }
    assert_eq!(ids.len(), 10);
    assert_eq!(state.repo.pool_snapshot().capacity, 8);
    drop(router);
    crate::runtime::cleanup_test_app(dir, &[&state]).await;
}

#[tokio::test]
async fn hf12_assembly_honors_explicit_sqlite_pool_limit() {
    for maximum in [2, 10] {
        let root = std::env::temp_dir().join(format!("hf12-assembly-{}", memoswish_core::ids::new_id()));
        let state =
            AppState::build(Config { data_dir: root.clone(), db_max_connections: Some(maximum), ..Default::default() })
                .await
                .unwrap();
        assert_eq!(state.repo.pool_snapshot().capacity, maximum);
        crate::runtime::cleanup_test_app(root, &[&state]).await;
    }
}

// 经真实 TOML 和同一环境合并器解析，不修改进程全局环境，避免测试之间相互覆盖。
fn pool_config(root: &std::path::Path, url: &str, maximum: Option<u32>, alias: Option<&str>) -> Config {
    let text = maximum.map_or_else(String::new, |m| format!("db_max_connections={m}"));
    let initial = if alias.is_some() { "sqlite::memory:" } else { url };
    let text = format!("{text}\ndatabase_url={initial:?}");
    let mut cfg = Config::parse_with_env(&text, &|key| (Some(key) == alias).then(|| url.to_owned())).unwrap();
    cfg.data_dir = root.to_owned();
    cfg
}

async fn pool_assembly_case(cfg: Config, expected: u32) {
    for migrate in [true, false] {
        let metrics = crate::metrics::Metrics::new(cfg.mode).unwrap();
        let repo = crate::app::build_repository(&cfg, migrate, metrics).await.unwrap();
        assert_eq!(repo.pool_snapshot().capacity, expected);
        drop(repo);
    }
}

#[tokio::test]
async fn hf12_sqlite_omitted_explicit_and_environment_pool_assembly() {
    for maximum in [None, Some(2), Some(10)] {
        for alias in [None, Some("MEMOSWISH_DATABASE_URL"), Some("DATABASE_URL")] {
            let root = std::env::temp_dir().join(format!("hf12-pool-{}", memoswish_core::ids::new_id()));
            std::fs::create_dir(&root).unwrap();
            let url = format!("sqlite://{}", root.join("feed.db").display());
            pool_assembly_case(pool_config(&root, &url, maximum, alias), maximum.unwrap_or(8)).await;
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
fn hf12_postgres_omitted_explicit_and_environment_pool_assembly() {
    memoswish_storage::pg_test_support::run_pg_test(|test| async move {
        let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
        let fixture = test.fixture(&url).await;
        for maximum in [None, Some(2), Some(8)] {
            for alias in [None, Some("MEMOSWISH_DATABASE_URL"), Some("DATABASE_URL")] {
                let root = std::env::temp_dir().join(format!("hf12-pool-{}", memoswish_core::ids::new_id()));
                std::fs::create_dir(&root).unwrap();
                pool_assembly_case(pool_config(&root, &fixture.database_url(), maximum, alias), maximum.unwrap_or(10))
                    .await;
                std::fs::remove_dir_all(root).unwrap();
            }
        }
        fixture.cleanup().await;
    });
}

#[tokio::test]
async fn hf12_retry_causes_keep_public_envelope_generic() {
    use axum::response::IntoResponse;
    for cause in memoswish_core::observability::FeedRetryCause::ALL {
        let error = memoswish_core::CoreError::FeedRetry(*cause);
        // MCP tools/call 使用相同 code/public_message，内部原因不可进入文本。
        assert_eq!(
            format!("[{}] {}", error.code(), error.public_message()),
            "[temporarily_unavailable] temporarily unavailable"
        );
        let response = crate::api::ApiErr(error).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "temporarily_unavailable");
        assert_eq!(body["message"], "temporarily unavailable");
        assert!(!body.to_string().contains(cause.label()));
    }
}

#[tokio::test]
async fn hf12_memory_omitted_and_explicit_pool_assembly() {
    for maximum in [None, Some(1), Some(2)] {
        for alias in [None, Some("MEMOSWISH_DATABASE_URL"), Some("DATABASE_URL")] {
            let url = format!("sqlite:file:hf12-{}?mode=memory&cache=shared", memoswish_core::ids::new_id());
            let cfg = pool_config(std::path::Path::new("unused"), &url, maximum, alias);
            let migrated =
                crate::app::build_repository(&cfg, true, memoswish_core::observability::noop()).await.unwrap();
            assert_eq!(migrated.pool_snapshot().capacity, maximum.unwrap_or(1));
            let runtime =
                crate::app::build_repository(&cfg, false, memoswish_core::observability::noop()).await.unwrap();
            assert_eq!(runtime.pool_snapshot().capacity, maximum.unwrap_or(1));
            drop(runtime);
            drop(migrated);
        }
    }
}
