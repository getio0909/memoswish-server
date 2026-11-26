//! 补充 SQLx 的规范历史完整性检查，未知版本仍交由 SQLx 拒绝。
use memoswish_core::{CoreError, CoreResult};
use sqlx::migrate::Migrator;

pub(crate) fn validate_history(migrator: &Migrator, applied: &[i64]) -> CoreResult<()> {
    if applied.iter().any(|version| !migrator.version_exists(*version)) {
        return Ok(());
    }
    let latest = applied.last().copied().unwrap_or(0);
    for migration in migrator.iter().filter(|migration| migration.version <= latest) {
        if !applied.contains(&migration.version) {
            return Err(CoreError::internal(format!(
                "migration history is incomplete at version {}; restore a supported backup with the canonical main migration history",
                migration.version
            )));
        }
    }
    Ok(())
}

/// 运行角色只读取账本，精确匹配随二进制发布的完整规范历史；不创建迁移表或取得 DDL 锁。
pub(crate) async fn validate_runtime<C>(connection: &mut C, migrator: &Migrator) -> CoreResult<()>
where
    C: sqlx::migrate::Migrate,
{
    let invalid = || {
        CoreError::Unavailable(
            "database schema is not supported; run the matching migrator with canonical history".into(),
        )
    };
    if connection.dirty_version().await.map_err(|_| invalid())?.is_some() {
        return Err(invalid());
    }
    let applied = connection.list_applied_migrations().await.map_err(|_| invalid())?;
    let expected: Vec<_> = migrator.iter().collect();
    if applied.len() != expected.len()
        || applied
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.version != expected.version || actual.checksum != expected.checksum)
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::sqlite::SqliteRepository;

    #[tokio::test]
    async fn runtime_rejects_noncanonical_history_without_repairing_it() {
        let repo = SqliteRepository::in_memory().await.unwrap();
        let migrator = sqlx::migrate!("./migrations/sqlite");
        let mut conn = repo.pool().acquire().await.unwrap();
        validate_runtime(&mut *conn, &migrator).await.unwrap();
        for mutation in [
            "DELETE FROM _sqlx_migrations WHERE version=2",
            "UPDATE _sqlx_migrations SET success=0 WHERE version=2",
            "UPDATE _sqlx_migrations SET checksum=X'00' WHERE version=2",
            "DELETE FROM _sqlx_migrations WHERE version=(SELECT MAX(version) FROM _sqlx_migrations)",
            "UPDATE _sqlx_migrations SET version=999 WHERE version=2",
        ] {
            sqlx::query("SAVEPOINT history_test").execute(&mut *conn).await.unwrap();
            sqlx::query(mutation).execute(&mut *conn).await.unwrap();
            assert!(validate_runtime(&mut *conn, &migrator).await.is_err(), "{mutation}");
            sqlx::query("ROLLBACK TO history_test").execute(&mut *conn).await.unwrap();
            sqlx::query("RELEASE history_test").execute(&mut *conn).await.unwrap();
        }
        sqlx::query("DROP TABLE _sqlx_migrations").execute(&mut *conn).await.unwrap();
        assert!(validate_runtime(&mut *conn, &migrator).await.is_err());
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name='_sqlx_migrations'")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(exists, 0);
    }

    #[tokio::test]
    async fn runtime_does_not_create_missing_sqlite_installation() {
        let path = std::env::temp_dir().join(format!("s26a-missing-{}.db", memoswish_core::ids::new_id()));
        assert!(SqliteRepository::open_runtime(&format!("sqlite://{}", path.display())).await.is_err());
        assert!(!path.exists());
    }
}

#[cfg(all(test, feature = "postgres"))]
mod postgres_tests {
    use super::*;

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
    fn runtime_validates_without_ddl_and_refuses_dirty_unknown_or_incomplete_history() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let fixture = owner.fixture(&url).await;
            let repo = fixture.repository(2).await.unwrap();
            let mut conn = repo.pool().acquire().await.unwrap();
            sqlx::query("SET default_transaction_read_only=on").execute(&mut *conn).await.unwrap();
            validate_runtime(&mut *conn, &sqlx::migrate!("./migrations/postgres")).await.unwrap();
            assert!(sqlx::query("CREATE TABLE forbidden_ddl(id INT)").execute(&mut *conn).await.is_err());
            sqlx::query("SET default_transaction_read_only=off").execute(&mut *conn).await.unwrap();
            for mutation in [
                "DELETE FROM _sqlx_migrations WHERE version=2",
                "UPDATE _sqlx_migrations SET success=false WHERE version=2",
                "UPDATE _sqlx_migrations SET checksum='\\x00' WHERE version=2",
                "DELETE FROM _sqlx_migrations WHERE version=(SELECT MAX(version) FROM _sqlx_migrations)",
                "UPDATE _sqlx_migrations SET version=999 WHERE version=2",
            ] {
                sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
                sqlx::query(mutation).execute(&mut *conn).await.unwrap();
                assert!(
                    validate_runtime(&mut *conn, &sqlx::migrate!("./migrations/postgres")).await.is_err(),
                    "{mutation}"
                );
                sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
            }
            drop(conn);
            repo.pool().close().await;
            fixture.cleanup().await;
        });
    }
}
