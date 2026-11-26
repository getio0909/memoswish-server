//! 双库共用候选查询形状，SQLx 负责方言绑定，既有转换器负责精确时间解析。

pub(crate) fn query_error(error: sqlx::Error) -> memoswish_core::CoreError {
    if crate::learning::retryable(&error) {
        // 复用事务路径的脱敏前分类，候选查询仍使用原有可重试范围。
        crate::feed_issuance::db_error(error)
    } else {
        memoswish_core::CoreError::internal(format!("database error: {error}"))
    }
}

macro_rules! feed_candidate_repo {
    ($repo:ty, $db:ty) => {
        fn feed_metadata_sql<'a>(tenant_id: &'a str, user_id: &'a str, deck_id: Option<&'a str>) -> sqlx::QueryBuilder<'a, $db> {
                let mut sql = sqlx::QueryBuilder::<$db>::new(
                    candidate_metadata_columns(),
                );
                sql.push(" FROM cards c LEFT JOIN memory_states m ON m.tenant_id=c.tenant_id AND m.card_id=c.id AND m.user_id=");
                sql.push_bind(user_id);
                sql.push(" LEFT JOIN learner_card_controls l ON l.tenant_id=c.tenant_id AND l.card_id=c.id AND l.user_id=").push_bind(user_id).push(" WHERE c.publication='published' AND c.tenant_id=").push_bind(tenant_id);
                if let Some(deck) = deck_id {
                    sql.push(" AND c.deck_id=").push_bind(deck);
                }
                sql.push(" ORDER BY c.created_at, c.id");
            sql
        }

        fn feed_summary_sql<'a>(tenant_id: &'a str, user_id: &'a str, deck_id: Option<&'a str>) -> sqlx::QueryBuilder<'a, $db> {
                let mut sql = sqlx::QueryBuilder::<$db>::new(
                    "SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN m.reps>0 THEN 1 ELSE 0 END),0) AS seen, COALESCE(SUM(CASE WHEN m.starred THEN 1 ELSE 0 END),0) AS starred, CAST(COALESCE(SUM(m.exposures),0) AS BIGINT) AS exposures FROM cards c LEFT JOIN memory_states m ON m.tenant_id=c.tenant_id AND m.card_id=c.id AND m.user_id=",
                );
                sql.push_bind(user_id).push(" WHERE c.publication='published' AND c.tenant_id=").push_bind(tenant_id);
                if let Some(deck) = deck_id {
                    sql.push(" AND c.deck_id=").push_bind(deck);
                }
            sql
        }

        fn feed_starred_sql<'a>(tenant_id: &'a str, user_id: &'a str, deck_id: Option<&'a str>) -> sqlx::QueryBuilder<'a, $db> {
                let mut sql = sqlx::QueryBuilder::<$db>::new(
                    "SELECT c.body, m.last_review FROM memory_states m JOIN cards c ON c.tenant_id=m.tenant_id AND c.id=m.card_id WHERE c.publication='published' AND m.starred AND m.tenant_id=",
                );
                sql.push_bind(tenant_id).push(" AND m.user_id=").push_bind(user_id);
                if let Some(deck) = deck_id {
                    sql.push(" AND c.deck_id=").push_bind(deck);
                }
            sql
        }

        #[async_trait::async_trait]
        impl FeedCandidateRepo for $repo {
            async fn visit_feed_metadata(
                &self,
                tenant_id: &str,
                user_id: &str,
                deck_id: Option<&str>,
                visit: &mut (dyn FnMut(FeedCardMetadata) -> CoreResult<()> + Send),
            ) -> CoreResult<()> {
                let mut sql = feed_metadata_sql(tenant_id, user_id, deck_id);
                let query = sql.build();
                let mut rows = query.fetch(&self.pool);
                while let Some(row) = std::future::poll_fn(|cx| rows.as_mut().poll_next(cx)).await {
                    let row = row.map_err(crate::feed_candidates::query_error)?;
                    visit(candidate_metadata(&row)?)?;
                }
                Ok(())
            }

            async fn hydrate_feed_cards(
                &self,
                tenant_id: &str,
                deck_id: Option<&str>,
                card_ids: &[String],
            ) -> CoreResult<Vec<Card>> {
                if card_ids.is_empty() {
                    return Ok(Vec::new());
                }
                let mut sql = sqlx::QueryBuilder::<$db>::new("SELECT body FROM cards WHERE publication='published' AND tenant_id=");
                sql.push_bind(tenant_id);
                if let Some(deck) = deck_id {
                    sql.push(" AND deck_id=").push_bind(deck);
                }
                // 单个 JSON 参数避免候选数量跨越数据库的绑定参数上限。
                sql.push(" AND id IN (").push(candidate_ids_sql());
                sql.push_bind(serde_json::json!(card_ids)).push("))");
                let rows = sql.build().fetch_all(&self.pool).await.map_err(crate::feed_candidates::query_error)?;
                rows.iter().map(candidate_card).collect()
            }

            async fn feed_summary(
                &self,
                tenant_id: &str,
                user_id: &str,
                deck_id: Option<&str>,
            ) -> CoreResult<memoswish_protocol::LearningStats> {
                let mut sql = feed_summary_sql(tenant_id, user_id, deck_id);
                let row = sql.build().fetch_one(&self.pool).await.map_err(crate::feed_candidates::query_error)?;
                let count = |column| -> CoreResult<u32> {
                    u32::try_from(row.try_get::<i64, _>(column).map_err(crate::feed_candidates::query_error)?)
                        .map_err(|_| CoreError::internal("learning count exceeds protocol range"))
                };
                Ok(memoswish_protocol::LearningStats {
                    total_cards: count("total")?,
                    seen_cards: count("seen")?,
                    starred_cards: count("starred")?,
                    total_exposures: u64::try_from(row.try_get::<i64, _>("exposures").map_err(crate::feed_candidates::query_error)?)
                        .map_err(|_| CoreError::internal("invalid exposure total"))?,
                    due_cards: 0,
                    average_retrievability: 0.0
                })
            }

            async fn starred_feed_cards(
                &self,
                tenant_id: &str,
                user_id: &str,
                deck_id: Option<&str>,
            ) -> CoreResult<Vec<Card>> {
                let mut sql = feed_starred_sql(tenant_id, user_id, deck_id);
                let rows = sql.build().fetch_all(&self.pool).await.map_err(crate::feed_candidates::query_error)?;
                let mut cards = rows.iter().map(|row| {
                    Ok((candidate_last_review(row)?.unwrap_or(DateTime::<Utc>::UNIX_EPOCH), candidate_card(row)?))
                }).collect::<CoreResult<Vec<_>>>()?;
                // 历史 SQLite 文本可有时区与精度差异，统一解析后比较。
                cards.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.created_at.cmp(&b.1.created_at)).then(a.1.id.cmp(&b.1.id)));
                Ok(cards.into_iter().map(|(_, card)| card).collect())
            }
        }
    };
}
