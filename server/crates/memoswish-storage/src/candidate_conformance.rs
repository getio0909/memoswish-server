//! S24 查询隔离、历史保留、失败传播及索引升级的双库场景。

use memoswish_core::CoreError;
use memoswish_core::identity::IdentityRepo;
use memoswish_core::repo::*;
use memoswish_protocol::examples;

async fn scope_and_errors(repo: &impl Repository) {
    let (record, memory) = crate::learning_conformance::seed(repo).await;
    repo.upsert_memory(&memory).await.unwrap();
    let (foreign, foreign_memory) = crate::learning_conformance::seed(repo).await;
    repo.upsert_memory(&foreign_memory).await.unwrap();
    assert_eq!(record.event.card_id, foreign.event.card_id);
    let card = examples::sample_card();
    for scope in [None, Some(card.deck_id.as_str())] {
        let mut rows = Vec::new();
        repo.visit_feed_metadata(&record.tenant_id, &record.user_id, scope, &mut |row| {
            rows.push(row);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].memory.as_ref(), Some(&memory));
        assert_eq!(repo.feed_summary(&record.tenant_id, &record.user_id, scope).await.unwrap().starred_cards, 1);
        assert_eq!(
            repo.starred_feed_cards(&record.tenant_id, &record.user_id, scope).await.unwrap(),
            vec![card.clone()]
        );
        assert_eq!(repo.feed_summary(&record.tenant_id, &foreign.user_id, scope).await.unwrap().starred_cards, 0);
        assert!(repo.starred_feed_cards(&record.tenant_id, &foreign.user_id, scope).await.unwrap().is_empty());
    }
    assert!(
        repo.hydrate_feed_cards(&record.tenant_id, Some("foreign-deck"), std::slice::from_ref(&card.id))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repo.hydrate_feed_cards(&record.tenant_id, None, &[card.id.clone(), card.id.clone()]).await.unwrap(),
        vec![card.clone()]
    );
    let failed = repo
        .visit_feed_metadata(&record.tenant_id, &record.user_id, None, &mut |_| {
            Err(CoreError::internal("injected visitor failure"))
        })
        .await;
    assert!(matches!(failed, Err(CoreError::Internal(_))));
    repo.delete_card(&record.tenant_id, &card.id).await.unwrap();
    assert!(repo.get_memory(&record.tenant_id, &record.user_id, &card.id).await.unwrap().is_some());
    assert_eq!(repo.feed_summary(&record.tenant_id, &record.user_id, None).await.unwrap().total_cards, 0);
    assert!(repo.starred_feed_cards(&record.tenant_id, &record.user_id, None).await.unwrap().is_empty());
    assert_eq!(repo.feed_summary(&foreign.tenant_id, &foreign.user_id, None).await.unwrap().starred_cards, 1);
}

macro_rules! candidate_backend_tests {
    ($repo:ty, $pool:ty, $migrations:literal) => {
        async fn s24_upgrade(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            let target = full.migrations.iter().position(|migration| migration.description == "feed candidate indexes").unwrap();
            let version = full.migrations[target].version;
            let previous = full.migrations[target - 1].version;
            crate::foundation_conformance::through(&full, previous).run(pool).await.unwrap();
            // 升级前持久化历史状态，覆盖未复习记录和已删除卡片的记忆。
            sqlx::raw_sql("INSERT INTO tenants(id,name,plan,created_at) VALUES ('s24-upgrade','Upgrade','free','2026-11-07T00:00:00Z'); INSERT INTO users(id,default_tenant_id,email,display_name,password_hash,created_at) VALUES ('s24-user','s24-upgrade','s24-upgrade@example.invalid','Upgrade','test-only','2026-11-07T00:00:00Z'); INSERT INTO membership_generations(tenant_id,user_id,generation) VALUES ('s24-upgrade','s24-user',0); INSERT INTO tenant_memberships(tenant_id,user_id,role,generation,joined_at) VALUES ('s24-upgrade','s24-user','owner',0,'2026-11-07T00:00:00Z'); INSERT INTO memory_states(tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures,last_review,due,starred,last_rating) VALUES ('s24-upgrade','s24-user','archived',0,0,0,0,7,NULL,NULL,TRUE,NULL);").execute(pool).await.unwrap();
            let before: i64 = sqlx::query_scalar("SELECT exposures FROM memory_states WHERE tenant_id='s24-upgrade'").fetch_one(pool).await.unwrap();
            // 人为冲突让第二条建索引失败，验证第一条和迁移历史一起回滚。
            sqlx::query("CREATE INDEX idx_cards_feed_deck ON cards(tenant_id)").execute(pool).await.unwrap();
            assert!(full.run(pool).await.is_err());
            let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version=$1").bind(version).fetch_one(pool).await.unwrap();
            assert_eq!(applied, 0);
            sqlx::query("DROP INDEX idx_cards_feed_deck").execute(pool).await.unwrap();
            // 若上一条建索引未回滚，此次迁移会因重名失败。
            full.run(pool).await.unwrap();
            full.run(pool).await.unwrap();
            let after: i64 = sqlx::query_scalar("SELECT exposures FROM memory_states WHERE tenant_id='s24-upgrade'").fetch_one(pool).await.unwrap();
            assert_eq!(before, after);
        }

        async fn s24_history_survives_indexes(repo: &$repo) {
            let (record, state) = crate::learning_conformance::seed(repo).await;
            assert_eq!(repo.try_apply_learning_event(&record, None, &state).await.unwrap(), LearningEventOutcome::Applied);
            let p = memoswish_core::Principal { tenant_id: record.tenant_id.clone(), user_id: record.user_id.clone(), ..memoswish_core::Principal::local_owner("S24 upgrade") };
            let request = crate::feed_issuance_conformance::first();
            let candidate = crate::feed_issuance_conformance::candidate(repo, &p, &request, false).await;
            let page = crate::feed_issuance_conformance::committed(repo.feed_issuance(&p, &request, Some(&candidate)).await.unwrap());
            repo.delete_card(&p.tenant_id, &state.card_id).await.unwrap();
            let export = repo.account_export(&p.tenant_id, &p.user_id, true).await.unwrap();
            let snapshot = repo.get_versioned_memory(&p.tenant_id, &p.user_id, &state.card_id).await.unwrap();
            let full = sqlx::migrate!($migrations);
            let version = full.migrations.iter().find(|migration| migration.description == "feed candidate indexes").unwrap().version;
            // 本次测试的新索引没有改变数据模式，恢复成升级前的等价索引状态。
            sqlx::raw_sql("DROP INDEX idx_cards_feed_global; DROP INDEX idx_cards_feed_deck; DROP INDEX idx_memory_feed_starred;").execute(repo.pool()).await.unwrap();
            sqlx::query("DELETE FROM _sqlx_migrations WHERE version=$1").bind(version).execute(repo.pool()).await.unwrap();
            full.run(repo.pool()).await.unwrap();
            assert_eq!(repo.get_versioned_memory(&p.tenant_id, &p.user_id, &state.card_id).await.unwrap(), snapshot);
            assert_eq!(repo.account_export(&p.tenant_id, &p.user_id, true).await.unwrap(), export);
            assert_eq!(crate::feed_issuance_conformance::committed(repo.feed_issuance(&p, &request, None).await.unwrap()), page);
            assert!(repo.insert_card(&p.tenant_id, &examples::sample_card()).await.is_err());
        }

        async fn s24_queries(repo: &$repo) {
            s24_history_survives_indexes(repo).await;
            crate::candidate_conformance::scope_and_errors(repo).await;
            let (record, _) = crate::learning_conformance::seed(repo).await;
            // 真实 SQL 失败不能伪装为空库。
            sqlx::query("ALTER TABLE memory_states RENAME TO s24_hidden_memory").execute(repo.pool()).await.unwrap();
            assert!(repo.visit_feed_metadata(&record.tenant_id, &record.user_id, None, &mut |_| Ok(())).await.is_err());
            assert!(repo.feed_summary(&record.tenant_id, &record.user_id, None).await.is_err());
            assert!(repo.starred_feed_cards(&record.tenant_id, &record.user_id, None).await.is_err());
            sqlx::query("ALTER TABLE s24_hidden_memory RENAME TO memory_states").execute(repo.pool()).await.unwrap();
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    candidate_backend_tests!(SqliteRepository, sqlx::SqlitePool, "./migrations/sqlite");

    #[tokio::test]
    async fn sqlite_s24_storage_conformance_and_upgrade() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        s24_upgrade(&pool).await;
        pool.close().await;
        let repo = SqliteRepository::in_memory().await.unwrap();
        s24_queries(&repo).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::postgres::PostgresRepository;
    candidate_backend_tests!(PostgresRepository, sqlx::PgPool, "./migrations/postgres");

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_s24_storage_conformance_and_upgrade() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let fixture = test.fixture(&url).await;
            let pool =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            s24_upgrade(&pool).await;
            pool.close().await;
            let repo = fixture.repository(8).await.unwrap();
            s24_queries(&repo).await;
            repo.pool().close().await;
            fixture.cleanup().await;
        });
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_s24_historical_timestamps_and_decode_failure() {
    let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
    let (record, memory) = crate::learning_conformance::seed(&repo).await;
    repo.upsert_memory(&memory).await.unwrap();
    sqlx::query(
        "UPDATE memory_states SET last_review='2026-11-07T14:00:00.123456789+02:00', due='2026-11-07T12:00:00.124Z'",
    )
    .execute(repo.pool())
    .await
    .unwrap();
    let mut rows = Vec::new();
    repo.visit_feed_metadata(&record.tenant_id, &record.user_id, None, &mut |metadata| {
        rows.push(metadata);
        Ok(())
    })
    .await
    .unwrap();
    let memory = rows[0].memory.as_ref().unwrap();
    let expected =
        chrono::DateTime::parse_from_rfc3339("2026-11-07T12:00:00.123456789Z").unwrap().with_timezone(&chrono::Utc);
    assert_eq!(memory.last_review, Some(expected));
    assert_eq!((memory.due.unwrap() - expected).num_nanoseconds(), Some(543_211));
    sqlx::query("UPDATE memory_states SET last_review='invalid-timestamp'").execute(repo.pool()).await.unwrap();
    assert!(repo.visit_feed_metadata(&record.tenant_id, &record.user_id, None, &mut |_| Ok(())).await.is_err());
    assert!(repo.starred_feed_cards(&record.tenant_id, &record.user_id, None).await.is_err());
    assert!(sqlx::query("UPDATE cards SET body='invalid-json'").execute(repo.pool()).await.is_err());
    sqlx::query("UPDATE cards SET body='{\"id\":42}'").execute(repo.pool()).await.unwrap();
    assert!(
        repo.hydrate_feed_cards(&record.tenant_id, None, std::slice::from_ref(&record.event.card_id)).await.is_err()
    );
}
