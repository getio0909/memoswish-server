//! 运维聚合仅提供固定分类、数据库时间与连接池估计，不读取正文或输出身份。

use memoswish_core::observability::Outcome;

pub(crate) fn classify(error: &sqlx::Error) -> Outcome {
    match error {
        sqlx::Error::PoolTimedOut => Outcome::PoolTimeout,
        sqlx::Error::PoolClosed => Outcome::Closed,
        sqlx::Error::Database(error)
            if matches!(
                error.code().as_deref(),
                Some("5" | "6" | "261" | "262" | "517" | "773" | "55P03" | "40P01")
            ) =>
        {
            Outcome::Busy
        }
        _ => Outcome::Error,
    }
}

macro_rules! operational_impl {
    ($repo:ty, $clock:literal, $api_expiry_ms:literal) => {
        impl $repo {
            pub(crate) fn operational_query() -> String {
                crate::recovery::snapshot_query($clock, $api_expiry_ms)
            }
        }
        #[async_trait::async_trait]
        impl memoswish_core::observability::OperationalRepo for $repo {
            fn pool_snapshot(&self) -> memoswish_core::observability::PoolSnapshot {
                memoswish_core::observability::PoolSnapshot {
                    size: self.pool.size(),
                    idle: self.pool.num_idle(),
                    capacity: self.pool.options().get_max_connections(),
                }
            }
            async fn operational_snapshot(
                &self,
            ) -> memoswish_core::CoreResult<memoswish_core::observability::OperationalSnapshot> {
                use memoswish_core::observability::*;
                use sqlx::Row;
                let mut guard = self.observer.start(Operation::DbSample);
                let result = async {
                    // 单条聚合与数据库时间使用同一 statement 快照，结果规模只随固定分类增长。
                    let query = Self::operational_query();
                    let rows = sqlx::query(&query).fetch_all(&self.pool).await.map_err(|e| {
                        guard.finish(crate::operational_metrics::classify(&e));
                        memoswish_core::CoreError::Unavailable("operational snapshot unavailable".into())
                    })?;
                    let observed_at_ms = rows[0].get("now_ms");
                    let maintenance = rows
                        .iter()
                        .filter_map(|row| {
                            let authority: Option<String> = row.get("authority");
                            let (kind, state) =
                                authority.as_deref()?.strip_prefix("maintenance_state:")?.split_once(':')?;
                            Some(MaintenanceCount {
                                kind: *memoswish_core::maintenance::TaskKind::ALL
                                    .iter()
                                    .find(|k| k.as_str() == kind)?,
                                state: *TaskState::ALL.iter().find(|s| s.label() == state)?,
                                count: row.get("count"),
                            })
                        })
                        .collect();
                    let pending = rows
                        .into_iter()
                        .filter_map(|row| {
                            let kind: Option<String> = row.get("kind");
                            kind.map(|kind| PendingWork {
                                kind: WorkKind::ALL
                                    .iter()
                                    .copied()
                                    .find(|k| k.label() == kind)
                                    .unwrap_or(WorkKind::Other),
                                count: row.get("count"),
                                unknown: row.get("unknown"),
                                future: row.get("future"),
                                oldest_ms: row.get("oldest"),
                            })
                        })
                        .collect();
                    Ok(OperationalSnapshot { observed_at_ms, pending, maintenance })
                }
                .await;
                if result.is_ok() {
                    guard.finish(Outcome::Returned);
                }
                result
            }
        }
    };
}
pub(crate) use operational_impl;
