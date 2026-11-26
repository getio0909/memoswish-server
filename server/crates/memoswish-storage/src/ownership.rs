//! 维护入口：不迁移、不创建数据库，只返回一致快照内的聚合诊断，不暴露内容或用户 ID。

use memoswish_core::{CoreError, CoreResult};
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct OrphanCount {
    pub category: String,
    pub row_count: i64,
}

// 复用同一诊断语义；JSON 表达式由各数据库提供，不解码或重写历史正文。
const REPORT: &str = "
SELECT 'decks_missing_tenant' AS category, COUNT(*) AS row_count FROM decks d
 WHERE NOT EXISTS(SELECT 1 FROM tenants t WHERE t.id=d.tenant_id)
UNION ALL SELECT 'cards_missing_owned_deck', COUNT(*) FROM cards c
 WHERE NOT EXISTS(SELECT 1 FROM decks d WHERE d.tenant_id=c.tenant_id AND d.id=c.deck_id)
UNION ALL SELECT 'memory_without_live_card', COUNT(*) FROM memory_states m
 WHERE NOT EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=m.tenant_id AND c.id=m.card_id)
UNION ALL SELECT 'feedback_without_live_card', COUNT(*) FROM feedback_events e
 WHERE NOT EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=e.tenant_id AND c.id=e.card_id)
UNION ALL SELECT 'memory_missing_membership', COUNT(*) FROM memory_states m
 WHERE NOT EXISTS(SELECT 1 FROM tenant_memberships u WHERE u.tenant_id=m.tenant_id AND u.user_id=m.user_id)
UNION ALL SELECT 'feedback_missing_membership', COUNT(*) FROM feedback_events e
 WHERE NOT EXISTS(SELECT 1 FROM tenant_memberships u WHERE u.tenant_id=e.tenant_id AND u.user_id=e.user_id)
UNION ALL SELECT 'content_in_erased_tenant', COUNT(*) FROM (
 SELECT tenant_id FROM decks UNION ALL SELECT tenant_id FROM cards
) c WHERE EXISTS(SELECT 1 FROM erased_tenants t WHERE t.tenant_id=c.tenant_id)
UNION ALL SELECT 'learning_in_erased_scope', COUNT(*) FROM (
 SELECT tenant_id,user_id FROM memory_states UNION ALL SELECT tenant_id,user_id FROM feedback_events
) m WHERE EXISTS(SELECT 1 FROM erased_tenants t WHERE t.tenant_id=m.tenant_id)
 OR EXISTS(SELECT 1 FROM erased_users u WHERE u.tenant_id=m.tenant_id AND u.user_id=m.user_id)
UNION ALL SELECT 'card_body_identity_disagreement', COUNT(*) FROM cards c WHERE __IDENTITY__
";

/// 本机维护专用全局查询；不启动 AppState、不执行迁移或清理，不输出连接 URL。
pub async fn content_orphan_report(url: &str) -> CoreResult<Vec<OrphanCount>> {
    match crate::DatabaseKind::from_url(url)? {
        crate::DatabaseKind::Sqlite => {
            #[cfg(feature = "sqlite")]
            {
                use std::str::FromStr;
                let options = sqlx::sqlite::SqliteConnectOptions::from_str(url)
                    .map_err(|_| CoreError::invalid("invalid SQLite report URL"))?
                    .read_only(true)
                    .create_if_missing(false);
                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect_with(options)
                    .await
                    .map_err(|_| CoreError::internal("cannot open SQLite database for read-only orphan report"))?;
                let result = sqlite_report(&pool).await;
                pool.close().await;
                result
            }
            #[cfg(not(feature = "sqlite"))]
            Err(CoreError::Unsupported("this build has no SQLite support".into()))
        }
        crate::DatabaseKind::Postgres => {
            #[cfg(feature = "postgres")]
            {
                let pool =
                    sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(url).await.map_err(|_| {
                        CoreError::internal("cannot open PostgreSQL database for read-only orphan report")
                    })?;
                let result = postgres_report(&pool).await;
                pool.close().await;
                result
            }
            #[cfg(not(feature = "postgres"))]
            Err(CoreError::Unsupported("this build has no PostgreSQL support".into()))
        }
    }
}

macro_rules! report {
    ($name:ident, $pool:ty, $identity:literal, $readonly:literal, $has_tombstones:literal) => {
        pub(crate) async fn $name(pool: &$pool) -> CoreResult<Vec<OrphanCount>> {
            use sqlx::Row;
            let result: Result<_, sqlx::Error> = async {
                let mut tx = pool.begin().await?;
                sqlx::query($readonly).execute(&mut *tx).await?;
                let rows = sqlx::query(&REPORT.replace("__IDENTITY__", $identity)).fetch_all(&mut *tx).await?;
                let mut counts: Vec<_> = rows.iter().map(|r| OrphanCount {
                    category: r.get("category"), row_count: r.get("row_count"),
                }).collect();
                let present: bool = sqlx::query_scalar($has_tombstones).fetch_one(&mut *tx).await?;
                if present {
                    let count = sqlx::query_scalar("SELECT COUNT(*) FROM cards c JOIN deleted_card_ids d ON d.tenant_id=c.tenant_id AND d.card_id=c.id")
                        .fetch_one(&mut *tx).await?;
                    counts.push(OrphanCount { category: "live_card_with_deleted_id".into(), row_count: count });
                }
                tx.rollback().await?;
                Ok(counts)
            }.await;
            // SQL 错误可能携带数据库名称等细节；报告失败仅暴露固定操作上下文。
            result.map_err(|_| CoreError::internal("orphan report failed; use a canonical schema at migration 0016 or later"))
        }
    };
}

#[cfg(feature = "sqlite")]
report!(
    sqlite_report,
    sqlx::SqlitePool,
    "CASE WHEN json_valid(c.body) THEN (json_extract(c.body,'$.id')<>c.id OR json_extract(c.body,'$.deck_id')<>c.deck_id OR json_extract(c.body,'$.revision')<>c.revision) ELSE TRUE END",
    "SELECT 1",
    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='deleted_card_ids')"
);
#[cfg(feature = "postgres")]
report!(
    postgres_report,
    sqlx::PgPool,
    "c.body->>'id'<>c.id OR c.body->>'deck_id'<>c.deck_id OR c.body->>'revision'<>CAST(c.revision AS TEXT)",
    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
    "SELECT to_regclass('deleted_card_ids') IS NOT NULL"
);
