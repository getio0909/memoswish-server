//! 每个主线协议边界共用填充升级场景；冻结 SQL 与旧 migrator 都来自精确来源。
#[path = "checkpoint_migrations.rs"]
mod checkpoint_migrations;

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

macro_rules! checkpoint_tests {
    ($pool:ty, $backend:literal, $current:literal) => {
        use sqlx::Row;
        use crate::foundation_conformance::{LEGACY_DATA, through};

        async fn rows(pool: &$pool, sql: &str) -> Vec<Vec<Option<String>>> {
            sqlx::query(sql).fetch_all(pool).await.unwrap().iter()
                .map(|row| (0..row.len()).map(|i| row.get(i)).collect()).collect()
        }

        async fn preserved(pool: &$pool, head: i64) -> Vec<Vec<Vec<Option<String>>>> {
            let mut result = Vec::new();
            let users = if head >= 9 { "user_profiles" } else { "users" };
            for sql in [
                format!("SELECT id,email,password_hash FROM {users} ORDER BY id"),
                "SELECT id,tenant_id,token_hash FROM api_tokens ORDER BY id".into(),
                "SELECT id,tenant_id,title FROM decks ORDER BY id".into(),
                "SELECT id,tenant_id,CAST(body AS TEXT) FROM cards ORDER BY id".into(),
                "SELECT tenant_id,user_id,card_id,CAST(reps AS TEXT),CAST(exposures AS TEXT) FROM memory_states ORDER BY card_id".into(),
                "SELECT tenant_id,user_id,event_id,CAST(body AS TEXT) FROM feedback_events ORDER BY event_id".into(),
                "SELECT issuer,subject,credential FROM federated_identities ORDER BY issuer,subject".into(),
                "SELECT tenant_id FROM erased_tenants ORDER BY tenant_id".into(),
                "SELECT tenant_id,user_id FROM erased_users ORDER BY tenant_id,user_id".into(),
                "SELECT id,CAST(body AS TEXT) FROM account_erasure_jobs ORDER BY id".into(),
            ] { result.push(rows(pool, &sql).await); }
            result
        }

        async fn ledger(pool: &$pool) -> Vec<(i64, bool, Vec<u8>)> {
            sqlx::query("SELECT version,success,checksum FROM _sqlx_migrations ORDER BY version").fetch_all(pool).await.unwrap().iter().map(|row| (row.get(0), row.get(1), row.get(2))).collect()
        }

        async fn responsibility(pool: &$pool, head: i64) -> Vec<Vec<Vec<Option<String>>>> {
            let mut result = Vec::new();
            if head >= 10 {
                result.push(rows(pool, "SELECT tenant_id,id,state,CAST(payload AS TEXT),token FROM background_jobs WHERE kind<>'erasure' ORDER BY id").await);
                result.push(rows(pool, "SELECT tenant_id,operation_id,state,CAST(amount AS TEXT) FROM quota_operations ORDER BY operation_id").await);
            }
            if head >= 17 {
                result.push(rows(pool, "SELECT id,user_id,CAST(generation AS TEXT),CAST(revoked AS TEXT) FROM app_sessions ORDER BY id").await);
                result.push(rows(pool, "SELECT access_hash,refresh_hash,assurance_hash,session_id,CAST(consumed AS TEXT) FROM app_session_credentials ORDER BY access_hash").await);
            }
            if head >= 26 {
                result.push(rows(pool, "SELECT tenant_id,id,user_id,fingerprint,authority_id,authority,work,outcome,result FROM content_imports ORDER BY id").await);
            }
            result
        }

        async fn erasure_upgrade(pool: &$pool) {
            let work: Vec<(String, String, String, i64, i64, i64)> = sqlx::query_as(
                "SELECT id,partition_id,progress,revision,total_attempts,assets_ack FROM account_erasure_jobs ORDER BY id"
            ).fetch_all(pool).await.unwrap();
            assert_eq!(work, vec![
                ("account-cleanup".into(), "".into(), "pending".into(), 0, 0, 0),
                ("cleanup".into(), "deleted-tenant".into(), "pending".into(), 0, 0, 0),
            ]);
            let jobs: Vec<(String, String, String, String, i64, i64, Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT id,tenant_id,work_scope,state,max_attempts,available_at_ms,user_id,token FROM background_jobs WHERE kind='erasure' ORDER BY id"
            ).fetch_all(pool).await.unwrap();
            assert_eq!(jobs, vec![
                ("account-cleanup".into(), "".into(), "account".into(), "queued".into(), 5, 0, None, None),
                ("cleanup".into(), "deleted-tenant".into(), "tenant".into(), "queued".into(), 5, 0, None, None),
            ]);
            let invalid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE kind<>'erasure' AND work_scope<>'tenant'")
                .fetch_one(pool).await.unwrap();
            assert_eq!(invalid, 0);
            assert!(sqlx::query("SELECT drain_until_ms FROM account_erasure_jobs").fetch_all(pool).await.is_err());
        }

        async fn checkpoint(pool: &$pool, minor: u64) {
            let root = super::root();
            let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(root.join("compatibility/matrix.json")).unwrap()).unwrap();
            let row = &manifest["checkpoints"][(minor - 1) as usize];
            assert_eq!(row["protocol_version"], format!("2.{minor}.0"));
            let path = super::checkpoint_migrations::directory(&root, row, $backend);
            let old = sqlx::migrate::Migrator::new(path.as_path()).await.unwrap();
            let head = row["migration_head"].as_i64().unwrap();
            assert_eq!(old.iter().last().unwrap().version, head);
            let current = sqlx::migrate!($current);
            let target = current.iter().last().unwrap().version;
            let combination = manifest["combinations"].as_array().unwrap().iter().find(|row| row["id"] == "current").unwrap();
            assert_eq!(combination["migration_head"], target);
            assert_eq!(combination["protocol_version"], memoswish_protocol::PROTOCOL_VERSION);
            through(&old, 8).run(pool).await.unwrap();
            sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();
            through(&old, head.min(24)).run(pool).await.unwrap();
            sqlx::raw_sql(r#"INSERT INTO account_erasure_jobs(id,body,drain_until_ms) VALUES('account-cleanup','{"id":"account-cleanup","tenant_id":null,"purge_assets":false,"credentials":[["apple","encrypted-account-material"]]}',2000000000000);"#).execute(pool).await.unwrap();
            old.run(pool).await.unwrap();
            if head >= 10 {
                sqlx::raw_sql("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,state,max_attempts,available_at_ms,lease_until_ms,worker,token) VALUES('foundation','s23-pending','synthesis','s23-pending','{\"pending\":true}','account',7,'running',3,100,200,'worker','original-claim'); INSERT INTO quota_operations VALUES('foundation','s23-pending','tts_chars','2026-11',17,'reserved');").execute(pool).await.unwrap();
            }
            if head >= 17 {
                sqlx::raw_sql("INSERT INTO app_sessions(id,user_id,generation,provenance,auth_time,expires_at) VALUES('s23-family','account',7,'password',100,2000000000); INSERT INTO app_session_credentials(access_hash,refresh_hash,assurance_hash,session_id,tenant_id,membership_generation,expires_at,consumed) VALUES('s23-access-hash','s23-refresh-hash','s23-assurance-hash','s23-family','foundation',7,2000000000,1);").execute(pool).await.unwrap();
            }
            if head >= 26 {
                sqlx::raw_sql("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES('foundation','s23-import','content_import','s23-import','{}','account',7,5,100); INSERT INTO content_imports(tenant_id,id,user_id,fingerprint,authority_id,authority,work) VALUES('foundation','s23-import','account','fingerprint','authority','{}','{}'); INSERT INTO quota_operations VALUES('foundation','s23-import','card_writes','2026-11',2,'reserved');").execute(pool).await.unwrap();
            }
            let before = preserved(pool, head).await;
            let original_drain = rows(pool, if head < 25 {"SELECT id,CAST(drain_until_ms AS TEXT) FROM account_erasure_jobs ORDER BY id"} else {"SELECT id,CAST(assets_ack AS TEXT) FROM account_erasure_jobs ORDER BY id"}).await;
            let original_ledger = ledger(pool).await;
            let pending = responsibility(pool, head).await;

            // 损坏账本只注入本次独有夹具，检查失败不能修复或改写它。
            let checksum = old.iter().last().unwrap().checksum.to_vec();
            sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=$2").bind(vec![0_u8]).bind(head).execute(pool).await.unwrap();
            let damaged = ledger(pool).await;
            assert!(matches!(old.run(pool).await, Err(sqlx::migrate::MigrateError::VersionMismatch(_))));
            assert_eq!(ledger(pool).await, damaged);
            sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=$2").bind(checksum).bind(head).execute(pool).await.unwrap();
            sqlx::query("UPDATE _sqlx_migrations SET success=FALSE WHERE version=$1").bind(head).execute(pool).await.unwrap();
            let dirty = ledger(pool).await;
            assert!(matches!(old.run(pool).await, Err(sqlx::migrate::MigrateError::Dirty(_))));
            assert_eq!(ledger(pool).await, dirty);
            sqlx::query("UPDATE _sqlx_migrations SET success=TRUE WHERE version=$1").bind(head).execute(pool).await.unwrap();
            assert_eq!(ledger(pool).await, original_ledger);
            let incomplete: Vec<i64> = old.iter().map(|migration|migration.version).filter(|version| *version != 2).collect();
            assert!(crate::migrations::validate_history(&old, &incomplete).is_err());

            // 下一迁移故障必须回滚；冻结输入与已发布 SQL 均不修改。
            if head < target {
                let next = current.iter().find(|migration|migration.version>head).unwrap().version;
                let mut broken = through(&current, next);
                let last = broken.migrations.to_mut().last_mut().unwrap();
                *last = sqlx::migrate::Migration::new(last.version, last.description.clone(), last.migration_type,
                    format!("{}\nSELECT * FROM s23_injected_missing_table;", last.sql).into(), false);
                assert!(broken.run(pool).await.is_err());
                assert_eq!(ledger(pool).await, original_ledger);
                assert_eq!(preserved(pool, head).await, before);
                assert_eq!(rows(pool, if head < 25 {"SELECT id,CAST(drain_until_ms AS TEXT) FROM account_erasure_jobs ORDER BY id"} else {"SELECT id,CAST(assets_ack AS TEXT) FROM account_erasure_jobs ORDER BY id"}).await, original_drain);
            }
            // 在最后一个旧布局上注入 0025 故障，窗口、回执和队列必须一起回滚。
            if head < 25 {
            through(&current, 24).run(pool).await.unwrap();
            let before_scope = ledger(pool).await;
            let drain = rows(pool, if head < 25 {"SELECT id,CAST(drain_until_ms AS TEXT) FROM account_erasure_jobs ORDER BY id"} else {"SELECT id,CAST(assets_ack AS TEXT) FROM account_erasure_jobs ORDER BY id"}).await;
            let mut broken_scope = through(&current, 25);
            let last = broken_scope.migrations.to_mut().last_mut().unwrap();
            *last = sqlx::migrate::Migration::new(last.version, last.description.clone(), last.migration_type,
                format!("{}\nSELECT * FROM s19_injected_missing_table;", last.sql).into(), false);
            assert!(broken_scope.run(pool).await.is_err());
            assert_eq!(ledger(pool).await, before_scope);
            assert_eq!(preserved(pool, 24).await, before);
            assert_eq!(rows(pool, if head < 25 {"SELECT id,CAST(drain_until_ms AS TEXT) FROM account_erasure_jobs ORDER BY id"} else {"SELECT id,CAST(assets_ack AS TEXT) FROM account_erasure_jobs ORDER BY id"}).await, drain);
            assert_eq!(responsibility(pool, head).await, pending);
            }
            current.run(pool).await.unwrap();
            current.run(pool).await.unwrap();
            erasure_upgrade(pool).await;
            assert_eq!(preserved(pool, target).await, before);
            assert_eq!(responsibility(pool, head).await, pending);
            let revoked: i64 = sqlx::query_scalar("SELECT revoked FROM oauth_grants WHERE id='grant'").fetch_one(pool).await.unwrap();
            assert_eq!(revoked, 1, "migration 0012 must invalidate malformed legacy authority");
            let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oidc_attempts").fetch_one(pool).await.unwrap();
            assert_eq!(attempts, 0, "invalidated OIDC flows must not revive");
            let api_hash: String = sqlx::query_scalar("SELECT token_hash FROM api_tokens WHERE id='api'").fetch_one(pool).await.unwrap();
            assert_eq!(api_hash, "preserved-hash");
            let migrated = ledger(pool).await;
            if head < target {
                assert!(matches!(old.run(pool).await, Err(sqlx::migrate::MigrateError::VersionMissing(_))));
                assert_eq!(ledger(pool).await, migrated, "old migrator must not mutate new history");
            }
            let prefix = through(&old, 8);
            assert!(matches!(prefix.run(pool).await, Err(sqlx::migrate::MigrateError::VersionMissing(_))));
            assert_eq!(ledger(pool).await, migrated);
            assert_eq!(preserved(pool, target).await, before);
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use crate::sqlite::SqliteRepository;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    checkpoint_tests!(sqlx::SqlitePool, "sqlite", "./migrations/sqlite");

    async fn run(minor: u64) {
        let file = std::env::temp_dir().join(format!("memoswish-s23-{}.db", memoswish_core::ids::new_id()));
        let options = SqliteConnectOptions::new().filename(&file).create_if_missing(true).foreign_keys(true);
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        checkpoint(&pool, minor).await;
        let expected = preserved(&pool, 25).await;
        let pending = responsibility(&pool, 25).await;
        pool.close().await;
        let repo = SqliteRepository::connect_test(&format!("sqlite://{}", file.display())).await.unwrap();
        assert_eq!(preserved(repo.pool(), 25).await, expected);
        assert_eq!(responsibility(repo.pool(), 25).await, pending);
        erasure_upgrade(repo.pool()).await;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(preserved(repo.pool(), 25).await[3][0][2].as_ref().unwrap())
                .unwrap(),
            serde_json::json!({"legacy":true})
        );
        assert!(sqlx::query("PRAGMA foreign_key_check").fetch_all(repo.pool()).await.unwrap().is_empty());
        repo.pool().close().await;
        std::fs::remove_file(file).unwrap();
    }
    macro_rules! cases { ($($name:ident => $minor:expr),*) => { $(
        #[tokio::test] async fn $name() { run($minor).await; }
    )* }; }
    cases!(compatibility_sqlite_2_1 => 1, compatibility_sqlite_2_2 => 2, compatibility_sqlite_2_3 => 3,
        compatibility_sqlite_2_4 => 4, compatibility_sqlite_2_5 => 5, compatibility_sqlite_2_6 => 6,
        compatibility_sqlite_2_7 => 7, compatibility_sqlite_2_8 => 8, compatibility_sqlite_2_9 => 9,
        compatibility_sqlite_2_10 => 10, compatibility_sqlite_2_11 => 11, compatibility_sqlite_2_12 => 12, compatibility_sqlite_2_13 => 13, compatibility_sqlite_2_14 => 14, compatibility_sqlite_2_15 => 15, compatibility_sqlite_2_16 => 16, compatibility_sqlite_2_17 => 17, compatibility_sqlite_2_18 => 18, compatibility_sqlite_2_19 => 19, compatibility_sqlite_2_20 => 20, compatibility_sqlite_2_21 => 21, compatibility_sqlite_2_22 => 22);
}

#[cfg(feature = "postgres")]
mod postgres {
    use sqlx::postgres::PgPoolOptions;
    checkpoint_tests!(sqlx::PgPool, "postgres", "./migrations/postgres");

    fn run(minor: u64) {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("MISSING prerequisite: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let pool = PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            checkpoint(&pool, minor).await;
            let expected = preserved(&pool, 25).await;
            let pending = responsibility(&pool, 25).await;
            pool.close().await;
            let repo = fixture.repository(1).await.unwrap();
            assert_eq!(preserved(repo.pool(), 25).await, expected);
            assert_eq!(responsibility(repo.pool(), 25).await, pending);
            erasure_upgrade(repo.pool()).await;
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(preserved(repo.pool(), 25).await[3][0][2].as_ref().unwrap())
                    .unwrap(),
                serde_json::json!({"legacy":true})
            );
            repo.pool().close().await;
            fixture.cleanup().await;
        });
    }
    macro_rules! cases { ($($name:ident => $minor:expr),*) => { $(
        #[test] #[ignore = "integration: requires PostgreSQL"] fn $name() { run($minor); }
    )* }; }
    cases!(compatibility_postgres_2_1 => 1, compatibility_postgres_2_2 => 2, compatibility_postgres_2_3 => 3,
        compatibility_postgres_2_4 => 4, compatibility_postgres_2_5 => 5, compatibility_postgres_2_6 => 6,
        compatibility_postgres_2_7 => 7, compatibility_postgres_2_8 => 8, compatibility_postgres_2_9 => 9,
        compatibility_postgres_2_10 => 10, compatibility_postgres_2_11 => 11, compatibility_postgres_2_12 => 12, compatibility_postgres_2_13 => 13, compatibility_postgres_2_14 => 14, compatibility_postgres_2_15 => 15, compatibility_postgres_2_16 => 16, compatibility_postgres_2_17 => 17, compatibility_postgres_2_18 => 18, compatibility_postgres_2_19 => 19, compatibility_postgres_2_20 => 20, compatibility_postgres_2_21 => 21, compatibility_postgres_2_22 => 22);
}
