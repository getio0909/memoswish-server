//! 测量夹具只在测试或 test-support 特性下编译，生产仓储不暴露此入口。

use memoswish_core::repo::*;
use memoswish_core::{Principal, Role};
use memoswish_protocol::{Card, Deck, examples};

#[cfg(feature = "postgres")]
impl crate::postgres::PostgresRepository {
    /// 一条语句构造 S24 的同质前缀；边界候选仍通过正常仓储写入。
    pub async fn s24_conformance_memory_prefix(&self, state: &MemoryState, before: &str) {
        let inserted = sqlx::query(
            "INSERT INTO memory_states(tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures,last_review,due,starred,last_rating,projection_version)
             SELECT tenant_id,$2,id,$3,$4,$5,$6,$7,$8,$9,$10,$11,1 FROM cards WHERE tenant_id=$1 AND id<$12",
        )
        .bind(&state.tenant_id)
        .bind(&state.user_id)
        .bind(state.stability)
        .bind(state.difficulty)
        .bind(state.reps as i64)
        .bind(state.lapses as i64)
        .bind(state.exposures as i64)
        .bind(state.last_review)
        .bind(state.due)
        .bind(state.starred)
        .bind(state.last_rating.map(i64::from))
        .bind(before)
        .execute(self.pool())
        .await
        .unwrap();
        assert_eq!(inserted.rows_affected(), 5_000);
    }
}

async fn measurement_data(repo: &dyn Repository, count: usize) -> (Principal, Deck, Vec<Card>) {
    let tenant = memoswish_core::ids::new_id();
    let mut p = Principal::local_owner("S24 measurement");
    p.tenant_id = tenant;
    p.user_id = memoswish_core::ids::new_id();
    let now = chrono::DateTime::parse_from_rfc3339("2026-11-07T12:00:00Z").unwrap().with_timezone(&chrono::Utc);
    repo.upsert_tenant(&TenantRecord {
        id: p.tenant_id.clone(),
        name: "Measurement".into(),
        plan: "free".into(),
        created_at: now,
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: p.user_id.clone(),
        tenant_id: p.tenant_id.clone(),
        email: format!("{}@example.invalid", p.user_id),
        display_name: "Measurement".into(),
        password_hash: "test-only".into(),
        role: Role::Owner,
        created_at: now,
    })
    .await
    .unwrap();
    let deck = examples::sample_deck();
    let mut card = examples::sample_card();
    card.created_at = now;
    card.updated_at = now;
    let cards: Vec<_> = (0..count)
        .map(|index| {
            let mut card = card.clone();
            card.id = format!("measure-{index:06}");
            card
        })
        .collect();
    (p, deck, cards)
}

#[cfg(feature = "sqlite")]
pub(crate) async fn populate(repo: &dyn Repository, count: usize) -> Principal {
    let (p, deck, cards) = measurement_data(repo, count).await;
    repo.insert_deck_with_cards(&p.tenant_id, &deck, &cards).await.unwrap();
    p
}

#[cfg(feature = "postgres")]
pub(crate) async fn populate_postgres(repo: &crate::postgres::PostgresRepository, count: usize) -> Principal {
    let (p, deck, cards) = measurement_data(repo, count).await;
    repo.insert_deck(&p.tenant_id, &deck).await.unwrap();
    let mut tx = repo.pool().begin().await.unwrap();
    // 测量候选查询而非导入吞吐；分批构造同样的卡片，避免十万次 SQL 往返。
    for chunk in cards.chunks(500) {
        let mut sql = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO cards(id,tenant_id,deck_id,template,revision,body,created_at,updated_at) ",
        );
        sql.push_values(chunk, |mut row, card| {
            row.push_bind(&card.id)
                .push_bind(&p.tenant_id)
                .push_bind(&card.deck_id)
                .push_bind(&card.template)
                .push_bind(i64::from(card.revision))
                .push_bind(sqlx::types::Json(card))
                .push_bind(card.created_at)
                .push_bind(card.updated_at);
        });
        let inserted = sql.build().execute(&mut *tx).await.unwrap();
        assert_eq!(inserted.rows_affected(), chunk.len() as u64);
    }
    tx.commit().await.unwrap();
    p
}

macro_rules! candidate_measurement_support {
    ($repo:ty, $db:ty, $populate:path) => {
        #[cfg(any(test, feature = "test-support"))]
        impl $repo {
            /// 构造历史归档记忆和偏斜租户的计划夹具，仅修改测试拥有的租户。
            pub async fn s24_measurement_archive_prefix(&self, p: &memoswish_core::Principal, keep_from: &str) {
                let mut sql = sqlx::QueryBuilder::<$db>::new("UPDATE memory_states SET starred=TRUE WHERE tenant_id=");
                sql.push_bind(&p.tenant_id);
                sql.build().execute(self.pool()).await.unwrap();
                let mut sql = sqlx::QueryBuilder::<$db>::new("DELETE FROM cards WHERE tenant_id=");
                sql.push_bind(&p.tenant_id).push(" AND id<").push_bind(keep_from);
                sql.build().execute(self.pool()).await.unwrap();
                sqlx::raw_sql("ANALYZE cards; ANALYZE memory_states;").execute(self.pool()).await.unwrap();
            }

            /// 在本运行拥有的数据库或 schema 内构造完整测量域。
            pub async fn s24_measurement_fixture(&self, count: usize, dense: bool) -> memoswish_core::Principal {
                let p = $populate(self, count).await;
                if dense {
                    let mut sql = sqlx::QueryBuilder::<$db>::new(
                        "INSERT INTO memory_states(tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures,last_review,due,starred,last_rating) SELECT tenant_id,",
                    );
                    sql.push_bind(&p.user_id).push(",id,10.0,5.0,1,0,2,created_at,created_at,FALSE,3 FROM cards WHERE tenant_id=").push_bind(&p.tenant_id);
                    sql.build().execute(self.pool()).await.unwrap();
                }
                sqlx::raw_sql("ANALYZE cards; ANALYZE memory_states;").execute(self.pool()).await.unwrap();
                p
            }
        }
    };
}

macro_rules! candidate_plan_support {
    ($repo:ty, $prefix:literal, $version:literal) => {
        #[cfg(any(test, feature = "test-support"))]
        impl $repo {
            /// 使用生产构造器及原绑定参数解释完整作用域的查询。
            pub async fn s24_query_plans(&self, p: &memoswish_core::Principal, deck: Option<&str>) -> Vec<String> {
                use sqlx::Execute;
                let version: String = sqlx::query_scalar($version).fetch_one(self.pool()).await.unwrap();
                let mut result = vec![format!("VERSION {version}")];
                for (name, mut builder) in [
                    ("metadata", feed_metadata_sql(&p.tenant_id, &p.user_id, deck)),
                    ("summary", feed_summary_sql(&p.tenant_id, &p.user_id, deck)),
                    ("starred", feed_starred_sql(&p.tenant_id, &p.user_id, deck)),
                ] {
                    let mut query = builder.build();
                    let sql = format!("{}{}", $prefix, query.sql());
                    let arguments = query.take_arguments().unwrap().unwrap();
                    let rows = sqlx::query_with(&sql, arguments).fetch_all(self.pool()).await.unwrap();
                    result.push(format!("QUERY {name} SQL {}", builder.sql()));
                    for row in rows {
                        result.push(candidate_plan_row(&row));
                    }
                }
                result
            }
        }
    };
}
