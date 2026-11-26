//! PostgreSQL 实现：商业 SaaS 必选、自托管可选后端。
//!
//! 与 SQLite 实现保持行为一致，二者共享 `conformance` 测试套件。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use memoswish_core::content::{CardMutation, check_revision, next_revision};
use memoswish_core::repo::*;
use memoswish_core::{CoreError, CoreResult, Role};
use memoswish_protocol::{BgmTrack, Card, Deck, ImplicitFeedback};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use std::str::FromStr;

/// PostgreSQL 仓储。
#[derive(Clone)]
pub struct PostgresRepository {
    pub(crate) observer: std::sync::Arc<dyn memoswish_core::observability::Observer>,
    pool: PgPool,
    #[cfg(test)]
    pub(crate) learning_gate: Option<std::sync::Arc<crate::learning::TestGate>>,
    #[cfg(test)]
    pub(crate) content_gate: Option<std::sync::Arc<crate::learning::TestGate>>,
    #[cfg(test)]
    feed_gate: Option<std::sync::Arc<crate::learning::TestGate>>,
    #[cfg(test)]
    lifecycle_gate: Option<std::sync::Arc<crate::learning::TestGate>>,
}

fn db_err(e: sqlx::Error) -> CoreError {
    CoreError::internal(format!("database error: {e}"))
}

impl PostgresRepository {
    pub fn with_observer(mut self, observer: std::sync::Arc<dyn memoswish_core::observability::Observer>) -> Self {
        self.observer = observer;
        self
    }

    /// 连接数据库并执行迁移。`url` 例如 `postgres://host:5432/memoswish`。
    pub async fn connect(url: &str, max_connections: u32) -> CoreResult<Self> {
        let opts = PgConnectOptions::from_str(url).map_err(db_err)?;
        Self::connect_with_options(opts, max_connections).await
    }

    pub(crate) async fn connect_with_options(opts: PgConnectOptions, max_connections: u32) -> CoreResult<Self> {
        Self::connect_mode(opts, max_connections, true).await
    }

    /// 使用无 DDL 权限的运行凭据打开规范安装。
    pub async fn open_runtime(url: &str, max_connections: u32) -> CoreResult<Self> {
        let opts = PgConnectOptions::from_str(url).map_err(|_| CoreError::invalid("invalid PostgreSQL URL"))?;
        Self::connect_mode(opts, max_connections, false).await
    }

    async fn connect_mode(opts: PgConnectOptions, max_connections: u32, migrate: bool) -> CoreResult<Self> {
        let pool =
            PgPoolOptions::new().max_connections(max_connections.max(1)).connect_with(opts).await.map_err(db_err)?;
        if migrate {
            Self::migrate(&pool).await?;
        } else {
            let mut connection = pool.acquire().await.map_err(db_err)?;
            crate::migrations::validate_runtime(&mut *connection, &sqlx::migrate!("./migrations/postgres")).await?;
        }
        Ok(Self {
            observer: memoswish_core::observability::noop(),
            pool,
            #[cfg(test)]
            learning_gate: None,
            #[cfg(test)]
            content_gate: None,
            #[cfg(test)]
            feed_gate: None,
            #[cfg(test)]
            lifecycle_gate: None,
        })
    }

    // UPDATE/DELETE 在触发行级触发器前已取行锁，必须显式先取父租户锁。
    async fn tenant_write(&self, tenant_id: &str) -> CoreResult<sqlx::Transaction<'_, sqlx::Postgres>> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR SHARE")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        Ok(tx)
    }

    // 内容变更按租户串行，锁序为租户、卡组、卡片，协调擦除及卡组删除。
    async fn content_write(&self, tenant_id: &str) -> CoreResult<sqlx::Transaction<'_, sqlx::Postgres>> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        Ok(tx)
    }

    async fn migrate(pool: &PgPool) -> CoreResult<()> {
        let migrator = sqlx::migrate!("./migrations/postgres");
        let history_exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await
            .map_err(db_err)?;
        if history_exists {
            let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                .fetch_all(pool)
                .await
                .map_err(db_err)?;
            crate::migrations::validate_history(&migrator, &applied)?;
        }
        migrator.run(pool)
            .await
            .map_err(|e| CoreError::internal(format!("migration failed: {e}; use the canonical main migration history; restore a supported backup for unpublished WIP databases")))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

fn row_to_user(r: &PgRow) -> CoreResult<UserRecord> {
    Ok(UserRecord {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        email: r.get("email"),
        display_name: r.get("display_name"),
        password_hash: r.get("password_hash"),
        role: Role::parse(r.get::<String, _>("role").as_str())?,
        created_at: r.get("created_at"),
    })
}

fn row_to_token(r: &PgRow) -> ApiTokenRecord {
    ApiTokenRecord {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        user_id: r.get("user_id"),
        name: r.get("name"),
        token_hash: r.get("token_hash"),
        generations: memoswish_core::CredentialGenerations {
            account: r.get("account_generation"),
            membership: r.get("membership_generation"),
        },
        scopes: r.get::<Json<Vec<String>>, _>("scopes").0,
        created_at: r.get("created_at"),
        expires_at: r.get("expires_at"),
        last_used_at: r.get("last_used_at"),
        revoked: r.get("revoked"),
    }
}

fn row_to_deck(r: &PgRow) -> Deck {
    Deck {
        revision: Some(r.get::<i64, _>("revision") as u32),
        id: r.get("id"),
        title: r.get("title"),
        description: r.get("description"),
        language: r.get("language"),
        tags: r.get::<Json<Vec<String>>, _>("tags").0,
        card_count: r.get::<i64, _>("card_count") as u32,
        created_at: r.get("created_at"),
    }
}

fn row_to_memory(r: &PgRow) -> MemoryState {
    MemoryState {
        tenant_id: r.get("tenant_id"),
        user_id: r.get("user_id"),
        card_id: r.get("card_id"),
        stability: r.get("stability"),
        difficulty: r.get("difficulty"),
        reps: r.get::<i64, _>("reps") as u32,
        lapses: r.get::<i64, _>("lapses") as u32,
        exposures: r.get::<i64, _>("exposures") as u32,
        last_review: r.get("last_review"),
        due: r.get("due"),
        starred: r.get("starred"),
        last_rating: r.get::<Option<i64>, _>("last_rating").map(|v| v as u8),
    }
}

#[async_trait]
impl AuthRepo for PostgresRepository {
    async fn upsert_tenant(&self, t: &TenantRecord) -> CoreResult<()> {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, created_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, plan = EXCLUDED.plan",
        )
        .bind(&t.id)
        .bind(&t.name)
        .bind(&t.plan)
        .bind(t.created_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_tenant(&self, tenant_id: &str) -> CoreResult<Option<TenantRecord>> {
        use memoswish_core::observability::{Operation, Outcome};
        let mut observation = self.observer.start(Operation::DbRead);
        let result: CoreResult<_> = async {
            let row = sqlx::query("SELECT * FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| {
                    observation.finish(crate::operational_metrics::classify(&error));
                    db_err(error)
                })?;
            Ok(row.map(|r| TenantRecord {
                id: r.get("id"),
                name: r.get("name"),
                plan: r.get("plan"),
                created_at: r.get("created_at"),
            }))
        }
        .await;
        observation.finish(if result.is_ok() { Outcome::Returned } else { Outcome::Error });
        result
    }

    async fn insert_user(&self, u: &UserRecord) -> CoreResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        Self::insert_identity(&mut tx, u).await?;
        tx.commit().await.map_err(db_err)
    }

    async fn get_user(&self, tenant_id: &str, user_id: &str) -> CoreResult<Option<UserRecord>> {
        let row = sqlx::query("SELECT * FROM user_profiles WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.as_ref().map(row_to_user).transpose()
    }

    async fn find_user_by_email(&self, email: &str) -> CoreResult<Option<UserRecord>> {
        let row = sqlx::query("SELECT p.* FROM user_profiles p JOIN users u ON u.id=p.id WHERE p.email = $1 ORDER BY CASE WHEN p.tenant_id=u.default_tenant_id THEN 0 ELSE 1 END,p.tenant_id LIMIT 1")
            .bind(email.to_lowercase())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.as_ref().map(row_to_user).transpose()
    }

    async fn insert_api_token(&self, t: &ApiTokenRecord) -> CoreResult<()> {
        self.insert_api_token_bound(t, false).await
    }

    async fn find_api_token(&self, token_hash: &str) -> CoreResult<Option<ApiTokenRecord>> {
        let row = sqlx::query("SELECT * FROM api_tokens WHERE token_hash = $1")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.as_ref().map(row_to_token))
    }

    async fn list_api_tokens(&self, tenant_id: &str) -> CoreResult<Vec<ApiTokenRecord>> {
        let rows = sqlx::query("SELECT * FROM api_tokens WHERE tenant_id = $1 ORDER BY created_at")
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(rows.iter().map(row_to_token).collect())
    }

    async fn revoke_api_token(&self, tenant_id: &str, token_id: &str) -> CoreResult<bool> {
        let mut tx = self.tenant_write(tenant_id).await?;
        let res = sqlx::query("UPDATE api_tokens SET revoked = TRUE WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(token_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    async fn touch_api_token(&self, token_id: &str, at: DateTime<Utc>) -> CoreResult<()> {
        // 全局认证索引只读查租户，不锁 token 行；随后在同一事务中先父后子。
        let tenant: Option<String> = sqlx::query_scalar("SELECT tenant_id FROM api_tokens WHERE id=$1")
            .bind(token_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        if let Some(tenant) = tenant {
            let mut tx = self.tenant_write(&tenant).await?;
            sqlx::query("UPDATE api_tokens SET last_used_at = $1 WHERE id = $2 AND tenant_id=$3")
                .bind(at)
                .bind(token_id)
                .bind(tenant)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            tx.commit().await.map_err(db_err)?;
        }
        Ok(())
    }

    async fn add_usage(&self, tenant_id: &str, metric: &str, period: &str, amount: i64) -> CoreResult<i64> {
        let row = sqlx::query(
            "INSERT INTO usage_counters (tenant_id, metric, period, amount) VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, metric, period) DO UPDATE SET amount = usage_counters.amount + EXCLUDED.amount
             RETURNING amount",
        )
        .bind(tenant_id)
        .bind(metric)
        .bind(period)
        .bind(amount)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.get("amount"))
    }

    async fn try_add_usage(
        &self,
        tenant_id: &str,
        metric: &str,
        period: &str,
        amount: i64,
        limit: i64,
    ) -> CoreResult<Option<i64>> {
        self.import_try_usage(tenant_id, metric, period, amount, limit).await
    }

    async fn get_usage(&self, tenant_id: &str, metric: &str, period: &str) -> CoreResult<i64> {
        let row = sqlx::query("SELECT amount FROM usage_counters WHERE tenant_id = $1 AND metric = $2 AND period = $3")
            .bind(tenant_id)
            .bind(metric)
            .bind(period)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.map(|r| r.get("amount")).unwrap_or(0))
    }
}

const DECK_SELECT: &str = "SELECT d.*, (SELECT COUNT(*) FROM cards c WHERE c.tenant_id = d.tenant_id AND c.deck_id = d.id) AS card_count FROM decks d";

#[async_trait]
impl ContentRepo for PostgresRepository {
    async fn insert_deck(&self, tenant_id: &str, d: &Deck) -> CoreResult<()> {
        sqlx::query(
            "INSERT INTO decks (id, tenant_id, title, description, language, tags, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&d.id)
        .bind(tenant_id)
        .bind(&d.title)
        .bind(&d.description)
        .bind(&d.language)
        .bind(Json(&d.tags))
        .bind(d.created_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn insert_deck_with_cards(&self, tenant_id: &str, d: &Deck, cards: &[Card]) -> CoreResult<()> {
        let mut ids = std::collections::HashSet::new();
        if cards.iter().any(|c| c.revision == 0 || c.deck_id != d.id || !ids.insert(&c.id)) {
            return Err(CoreError::invalid("import cards must belong to the deck and have unique IDs"));
        }
        let mut tx = self.content_write(tenant_id).await?;
        sqlx::query(
            "INSERT INTO decks (id, tenant_id, title, description, language, tags, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&d.id)
        .bind(tenant_id)
        .bind(&d.title)
        .bind(&d.description)
        .bind(&d.language)
        .bind(Json(&d.tags))
        .bind(d.created_at)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        for c in cards {
            sqlx::query(
            "INSERT INTO cards (id, tenant_id, deck_id, template, revision, body, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&c.id)
        .bind(tenant_id)
        .bind(&c.deck_id)
        .bind(&c.template)
        .bind(c.revision as i64)
        .bind(Json(c))
        .bind(c.created_at)
        .bind(c.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn get_deck(&self, tenant_id: &str, deck_id: &str) -> CoreResult<Option<Deck>> {
        let row = sqlx::query(&format!("{DECK_SELECT} WHERE d.tenant_id = $1 AND d.id = $2"))
            .bind(tenant_id)
            .bind(deck_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.as_ref().map(row_to_deck))
    }

    async fn list_decks(&self, tenant_id: &str) -> CoreResult<Vec<Deck>> {
        let rows = sqlx::query(&format!("{DECK_SELECT} WHERE d.tenant_id = $1 ORDER BY d.created_at"))
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(rows.iter().map(row_to_deck).collect())
    }

    async fn delete_deck(&self, tenant_id: &str, deck_id: &str) -> CoreResult<bool> {
        let mut tx = self.content_write(tenant_id).await?;
        sqlx::query("DELETE FROM cards WHERE tenant_id = $1 AND deck_id = $2")
            .bind(tenant_id)
            .bind(deck_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        let res = sqlx::query("DELETE FROM decks WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(deck_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        #[cfg(test)]
        if let Some(gate) = &self.content_gate {
            gate.pause(crate::learning::TestPoint::BeforeCommit).await;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    async fn insert_card(&self, tenant_id: &str, c: &Card) -> CoreResult<()> {
        if c.revision == 0 {
            return Err(CoreError::invalid("revision must be positive"));
        }
        let mut tx = self.content_write(tenant_id).await?;
        if sqlx::query("SELECT id FROM decks WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(&c.deck_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?
            .is_none()
        {
            return Err(CoreError::NotFound(format!("deck `{}`", c.deck_id)));
        }
        sqlx::query("INSERT INTO cards (id, tenant_id, deck_id, template, revision, body, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
            .bind(&c.id).bind(tenant_id).bind(&c.deck_id).bind(&c.template)
            .bind(i64::from(c.revision)).bind(Json(c))
            .bind(c.created_at).bind(c.updated_at).execute(&mut *tx).await.map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn mutate_cards(&self, tenant_id: &str, changes: &[CardMutation]) -> CoreResult<Vec<Card>> {
        let mut ids = std::collections::HashSet::new();
        if changes.len() > 500 || changes.iter().any(|c| !ids.insert(c.id())) {
            return Err(CoreError::invalid("at most 500 unique card targets per call"));
        }
        let mut tx = self.content_write(tenant_id).await?;
        let mut out = Vec::with_capacity(changes.len());
        for change in changes {
            let row = sqlx::query("SELECT body FROM cards WHERE tenant_id=$1 AND id=$2")
                .bind(tenant_id)
                .bind(change.id())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            let current = row.map(|row| row.get::<Json<Card>, _>("body").0);
            let deck_id = match change {
                CardMutation::Draft { draft, .. } => Some(draft.deck_id.as_str()),
                _ => current.as_ref().map(|c| c.deck_id.as_str()),
            };
            let row = sqlx::query(&format!("{DECK_SELECT} WHERE d.tenant_id=$1 AND d.id=$2"))
                .bind(tenant_id)
                .bind(deck_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            let deck = row.as_ref().map(row_to_deck);
            let previous_revision = current.as_ref().map(|c| c.revision);
            let card = change.apply(current, deck.as_ref(), Utc::now())?;
            match previous_revision {
                None => {
                    sqlx::query("INSERT INTO cards (id, tenant_id, deck_id, template, revision, body, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
                        .bind(&card.id).bind(tenant_id).bind(&card.deck_id).bind(&card.template)
            .bind(i64::from(card.revision)).bind(Json(&card))
            .bind(card.created_at).bind(card.updated_at)
                        .execute(&mut *tx).await.map_err(db_err)?;
                }
                Some(revision) => {
                    let changed = sqlx::query("UPDATE cards SET deck_id=$1, template=$2, revision=revision+1, body=$3, updated_at=$4 WHERE tenant_id=$5 AND id=$6 AND revision=$7")
                        .bind(&card.deck_id).bind(&card.template).bind(Json(&card))
                        .bind(card.updated_at)
                        .bind(tenant_id).bind(&card.id).bind(i64::from(revision)).execute(&mut *tx).await.map_err(db_err)?;
                    if changed.rows_affected() != 1 {
                        return Err(CoreError::Conflict(format!("card changed; current revision {revision}")));
                    }
                }
            }
            out.push(card);
        }
        #[cfg(test)]
        if let Some(gate) = &self.content_gate {
            gate.pause(crate::learning::TestPoint::BeforeCommit).await;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(out)
    }

    async fn get_card(&self, tenant_id: &str, card_id: &str) -> CoreResult<Option<Card>> {
        let row = sqlx::query("SELECT body FROM cards WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(card_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.map(|r| r.get::<Json<Card>, _>("body").0))
    }

    async fn list_cards(
        &self,
        tenant_id: &str,
        deck_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> CoreResult<Vec<Card>> {
        let rows = sqlx::query(
            "SELECT body FROM cards WHERE tenant_id = $1 AND ($2::text IS NULL OR deck_id = $2)
             ORDER BY created_at, id LIMIT $3 OFFSET $4",
        )
        .bind(tenant_id)
        .bind(deck_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(|r| r.get::<Json<Card>, _>("body").0).collect())
    }

    async fn delete_card_if_revision(
        &self,
        tenant_id: &str,
        card_id: &str,
        expected_revision: Option<u32>,
    ) -> CoreResult<bool> {
        let mut tx = self.content_write(tenant_id).await?;
        let revision: Option<i64> = sqlx::query_scalar("SELECT revision FROM cards WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(card_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        let Some(revision) = revision else {
            return Ok(false);
        };
        check_revision(expected_revision, revision as u32)?;
        let res = sqlx::query("DELETE FROM cards WHERE tenant_id=$1 AND id=$2 AND revision=$3")
            .bind(tenant_id)
            .bind(card_id)
            .bind(revision)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        #[cfg(test)]
        if let Some(gate) = &self.content_gate {
            gate.pause(crate::learning::TestPoint::BeforeCommit).await;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }
}

#[async_trait]
impl MediaRepo for PostgresRepository {
    async fn save_bgm(
        &self,
        tenant_id: Option<&str>,
        t: &BgmTrack,
        expected_revision: Option<u32>,
    ) -> CoreResult<BgmTrack> {
        let scope = tenant_id.unwrap_or("");
        let mut tx = self.content_write(scope).await?;
        // 共享曲库没有父租户，以固定事务 advisory lock 协调启动副本。
        if tenant_id.is_none() {
            sqlx::query("SELECT pg_advisory_xact_lock(73130013)").execute(&mut *tx).await.map_err(db_err)?;
        }
        let revision: Option<i64> = sqlx::query_scalar("SELECT revision FROM bgm_tracks WHERE tenant_id=$1 AND id=$2")
            .bind(scope)
            .bind(&t.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        let mut track = t.clone();
        track.revision = match revision {
            Some(current) => next_revision(expected_revision, current as u32)?,
            None => {
                if expected_revision == Some(0) {
                    return Err(CoreError::invalid("expected_revision must be positive"));
                }
                if expected_revision.is_some() {
                    return Err(CoreError::NotFound(format!("bgm `{}`", t.id)));
                }
                1
            }
        };
        let changed = sqlx::query("INSERT INTO bgm_tracks (tenant_id,id,revision,body) VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id,id) DO UPDATE SET revision=bgm_tracks.revision+1,body=EXCLUDED.body WHERE bgm_tracks.revision=$5")
            .bind(scope).bind(&track.id).bind(i64::from(track.revision)).bind(Json(&track))
            .bind(revision.unwrap_or(0))
            .execute(&mut *tx).await.map_err(db_err)?;
        if changed.rows_affected() != 1 {
            return Err(CoreError::Conflict("bgm revision changed".into()));
        }
        tx.commit().await.map_err(db_err)?;
        Ok(track)
    }

    async fn get_bgm(&self, tenant_id: &str, track_id: &str) -> CoreResult<Option<BgmTrack>> {
        // 租户私有曲目优先于共享曲目。
        let row = sqlx::query(
            "SELECT body FROM bgm_tracks WHERE id = $1 AND (tenant_id = $2 OR tenant_id = '')
             ORDER BY tenant_id DESC LIMIT 1",
        )
        .bind(track_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(|r| r.get::<Json<BgmTrack>, _>("body").0))
    }

    async fn list_bgm(&self, tenant_id: &str) -> CoreResult<Vec<BgmTrack>> {
        let rows = sqlx::query("SELECT body FROM bgm_tracks WHERE tenant_id = $1 OR tenant_id = '' ORDER BY id")
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(|r| r.get::<Json<BgmTrack>, _>("body").0).collect())
    }
}

#[async_trait]
impl ReviewRepo for PostgresRepository {
    async fn get_versioned_memory(
        &self,
        tenant_id: &str,
        user_id: &str,
        card_id: &str,
    ) -> CoreResult<Option<VersionedMemory>> {
        use memoswish_core::observability::{Operation, Outcome};
        let mut observation = self.observer.start(Operation::DbRead);
        let result: CoreResult<_> = async {
            let row = sqlx::query("SELECT * FROM memory_states WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3")
                .bind(tenant_id)
                .bind(user_id)
                .bind(card_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| {
                    observation.finish(crate::operational_metrics::classify(&error));
                    db_err(error)
                })?;
            row.map(|row| Ok(VersionedMemory { version: row.get("projection_version"), state: row_to_memory(&row) }))
                .transpose()
        }
        .await;
        observation.finish(if result.is_ok() { Outcome::Returned } else { Outcome::Error });
        result
    }

    async fn try_apply_learning_event(
        &self,
        rec: &FeedbackEventRecord,
        expected: Option<i64>,
        s: &MemoryState,
    ) -> CoreResult<LearningEventOutcome> {
        self.try_apply_learning_event_inner(rec, expected, s, None, None).await
    }

    async fn try_apply_learning_event_for_principal(
        &self,
        p: &memoswish_core::Principal,
        rec: &FeedbackEventRecord,
        expected: Option<i64>,
        s: &MemoryState,
    ) -> CoreResult<LearningEventOutcome> {
        p.require(memoswish_core::Permission::FeedbackWrite)?;
        if p.tenant_id != rec.tenant_id || p.user_id != rec.user_id {
            return Err(CoreError::invalid("learning event does not match principal"));
        }
        self.try_apply_learning_event_inner(rec, expected, s, Some(p.credential_generations()?), Some(p)).await
    }

    async fn try_apply_learning_event_authorized(
        &self,
        rec: &FeedbackEventRecord,
        expected: Option<i64>,
        s: &MemoryState,
        generations: memoswish_core::CredentialGenerations,
    ) -> CoreResult<LearningEventOutcome> {
        self.try_apply_learning_event_inner(rec, expected, s, Some(generations), None).await
    }

    async fn get_memory(&self, tenant_id: &str, user_id: &str, card_id: &str) -> CoreResult<Option<MemoryState>> {
        let row = sqlx::query("SELECT * FROM memory_states WHERE tenant_id = $1 AND user_id = $2 AND card_id = $3")
            .bind(tenant_id)
            .bind(user_id)
            .bind(card_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.as_ref().map(row_to_memory))
    }

    async fn upsert_memory(&self, s: &MemoryState) -> CoreResult<()> {
        self.upsert_memory_inner(s, None).await
    }

    async fn upsert_memory_authorized(
        &self,
        s: &MemoryState,
        generations: memoswish_core::CredentialGenerations,
    ) -> CoreResult<()> {
        self.upsert_memory_inner(s, Some(generations)).await
    }

    async fn list_memory(&self, tenant_id: &str, user_id: &str) -> CoreResult<Vec<MemoryState>> {
        let rows = sqlx::query("SELECT m.* FROM memory_states m JOIN cards c ON c.tenant_id=m.tenant_id AND c.id=m.card_id WHERE m.tenant_id = $1 AND m.user_id = $2")
            .bind(tenant_id)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(rows.iter().map(row_to_memory).collect())
    }

    async fn insert_feedback(&self, rec: &FeedbackEventRecord) -> CoreResult<bool> {
        self.insert_feedback_inner(rec, None).await
    }

    async fn insert_feedback_authorized(
        &self,
        rec: &FeedbackEventRecord,
        generations: memoswish_core::CredentialGenerations,
    ) -> CoreResult<bool> {
        self.insert_feedback_inner(rec, Some(generations)).await
    }

    async fn get_session(&self, tenant_id: &str, user_id: &str, session_id: &str) -> CoreResult<Option<FeedSession>> {
        let row = sqlx::query("SELECT * FROM feed_sessions WHERE tenant_id = $1 AND user_id = $2 AND id = $3")
            .bind(tenant_id)
            .bind(user_id)
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.as_ref().map(Self::feed_session_row).transpose()
    }

    async fn save_session(&self, s: &FeedSession) -> CoreResult<()> {
        self.save_session_inner(s, None).await
    }

    async fn save_session_authorized(
        &self,
        s: &FeedSession,
        generations: memoswish_core::CredentialGenerations,
    ) -> CoreResult<()> {
        self.save_session_inner(s, Some(generations)).await
    }
    async fn feed_issuance(
        &self,
        p: &memoswish_core::Principal,
        request: &FeedIssuanceRequest,
        candidate: Option<&FeedIssuanceCandidate>,
    ) -> CoreResult<FeedIssuanceOutcome> {
        self.feed_issuance_command(p, request, candidate).await
    }

    async fn recover_learning_event(
        &self,
        p: &memoswish_core::Principal,
        record: &FeedbackEventRecord,
    ) -> CoreResult<Option<LearningEventOutcome>> {
        p.require(memoswish_core::Permission::FeedbackWrite)?;
        if record.tenant_id != p.tenant_id || record.user_id != p.user_id {
            return Err(CoreError::Forbidden("learning receipt scope mismatch".into()));
        }
        let mut tx = self.learning_write_tx(&p.tenant_id, &p.user_id, Some(p.credential_generations()?)).await?;
        Self::learning_principal_tx(&mut tx, p).await?;
        let row = sqlx::query("SELECT session_id,CAST(body AS TEXT) AS body,payload_hash FROM feedback_events WHERE tenant_id=$1 AND user_id=$2 AND event_id=$3")
            .bind(&p.tenant_id).bind(&p.user_id).bind(&record.event.event_id).fetch_optional(&mut *tx).await.map_err(db_err)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let hash = crate::learning::payload_hash(&record.session_id, &record.event)?;
        let identical = match row.get::<Option<String>, _>("payload_hash") {
            Some(stored) => stored == hash,
            None => {
                row.get::<String, _>("session_id") == record.session_id
                    && serde_json::from_str::<memoswish_protocol::ImplicitFeedback>(&row.get::<String, _>("body"))
                        .map_err(CoreError::internal)?
                        == record.event
            }
        };
        Ok(Some(if identical { LearningEventOutcome::Duplicate } else { LearningEventOutcome::PayloadConflict }))
    }

    async fn get_delivery(
        &self,
        tenant: &str,
        user: &str,
        session: &str,
        slot: u64,
    ) -> CoreResult<Option<memoswish_core::repo::DeliveryRecord>> {
        let Some(slot) = i64::try_from(slot).ok() else {
            return Ok(None);
        };
        let body: Option<String> = sqlx::query_scalar(
            "SELECT body FROM feed_deliveries WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND slot=$4",
        )
        .bind(tenant)
        .bind(user)
        .bind(session)
        .bind(slot)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        body.map(|s| serde_json::from_str(&s).map_err(CoreError::internal)).transpose()
    }

    async fn authorize_feed_preview(&self, p: &memoswish_core::Principal) -> CoreResult<()> {
        p.require(memoswish_core::Permission::FeedRead)?;
        let mut tx = self.learning_write_tx(&p.tenant_id, &p.user_id, Some(p.credential_generations()?)).await?;
        Self::learning_principal_tx(&mut tx, p).await?;
        let role: String = sqlx::query_scalar("SELECT role FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2")
            .bind(&p.tenant_id)
            .bind(&p.user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        if !memoswish_core::Role::parse(&role)?.allows(memoswish_core::Permission::FeedRead) {
            return Err(CoreError::Forbidden("current role cannot read feed".into()));
        }
        Ok(())
    }

    async fn expire_feed_sessions(&self, limit: u32) -> CoreResult<u64> {
        self.expire_feed_sessions_command(limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn privacy_inventory() -> BTreeSet<String> {
        let inventory: BTreeSet<String> =
            serde_json::from_str(include_str!("postgres-privacy-tables.json")).expect("invalid privacy inventory JSON");
        assert!(!inventory.is_empty(), "privacy inventory must not be empty");
        inventory
    }

    // 只查询本次夹具的持久基表；视图、临时表和 SQLx 迁移账本不属于业务清单。
    async fn persistent_tables(connection: &mut sqlx::PgConnection, schema: &str) -> BTreeSet<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema=$1 AND table_type='BASE TABLE' AND table_name <> '_sqlx_migrations'",
        )
        .bind(schema)
        .fetch_all(connection)
        .await
        .unwrap()
        .into_iter()
        .collect()
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_privacy_inventory_covers_migrated_schema() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let inventory = privacy_inventory();
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let repo = fixture.repository(1).await.unwrap();
            let mut connection = repo.pool.acquire().await.unwrap();
            let actual = persistent_tables(&mut connection, &fixture.schema).await;
            let missing: Vec<_> = actual.difference(&inventory).collect();
            let stale: Vec<_> = inventory.difference(&actual).collect();
            assert!(
                missing.is_empty() && stale.is_empty(),
                "PostgreSQL privacy inventory: unlisted={missing:?}, stale={stale:?}"
            );

            // 真实引擎执行带注释的过程 DDL，证明最终目录能发现静态解析容易漏掉的表。
            sqlx::raw_sql("DO $$ BEGIN CREATE /* migration rationale */ TABLE hf6_unlisted_data(id TEXT); END $$;")
                .execute(&mut *connection)
                .await
                .unwrap();
            let actual = persistent_tables(&mut connection, &fixture.schema).await;
            assert_eq!(actual.difference(&inventory).cloned().collect::<Vec<_>>(), ["hf6_unlisted_data"]);
            sqlx::query("DROP TABLE hf6_unlisted_data").execute(&mut *connection).await.unwrap();

            // 固定同一连接，临时表遮蔽及无 schema 的 DROP 不能掩盖持久同名表。
            sqlx::query("CREATE TEMP TABLE hf6_unlisted_data(id TEXT)").execute(&mut *connection).await.unwrap();
            assert_eq!(persistent_tables(&mut connection, &fixture.schema).await, inventory);
            sqlx::query(&format!("CREATE TABLE IF NOT EXISTS {}.hf6_unlisted_data(id TEXT)", fixture.schema))
                .execute(&mut *connection)
                .await
                .unwrap();
            sqlx::query("DROP TABLE hf6_unlisted_data").execute(&mut *connection).await.unwrap();
            let actual = persistent_tables(&mut connection, &fixture.schema).await;
            assert_eq!(actual.difference(&inventory).cloned().collect::<Vec<_>>(), ["hf6_unlisted_data"]);
            sqlx::query("DROP TABLE hf6_unlisted_data").execute(&mut *connection).await.unwrap();

            // 删表与改名都必须同时暴露失效清单项，不能只检查新增遗漏。
            sqlx::query("ALTER TABLE privacy_deployment_policy RENAME TO hf6_renamed")
                .execute(&mut *connection)
                .await
                .unwrap();
            let actual = persistent_tables(&mut connection, &fixture.schema).await;
            assert_eq!(actual.difference(&inventory).cloned().collect::<Vec<_>>(), ["hf6_renamed"]);
            assert_eq!(inventory.difference(&actual).cloned().collect::<Vec<_>>(), ["privacy_deployment_policy"]);
            sqlx::query("DROP TABLE hf6_renamed").execute(&mut *connection).await.unwrap();
            let actual = persistent_tables(&mut connection, &fixture.schema).await;
            assert!(actual.difference(&inventory).next().is_none());
            assert_eq!(inventory.difference(&actual).cloned().collect::<Vec<_>>(), ["privacy_deployment_policy"]);
            drop(connection);
            repo.pool.close().await;
            fixture.cleanup().await;
        });
    }

    /// 集成层必须设置 PostgreSQL URL，普通测试显式忽略。
    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_conformance() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 4).await.unwrap();
            crate::conformance::run(&repo).await;
        });
    }

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_fixture_migration_failure_cleans_schema() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let schema = fixture.schema.clone();
            let admin = PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
            // 损坏本次夹具的迁移账本，验证仓储初始化失败也受 guard 保护。
            sqlx::query(&format!("CREATE TABLE {schema}._sqlx_migrations (invalid integer)"))
                .execute(&admin)
                .await
                .unwrap();
            assert!(PostgresRepository::connect_with_options(fixture.options(), 1).await.is_err());
            fixture.cleanup().await;
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=$1)")
                .bind(schema)
                .fetch_one(&admin)
                .await
                .unwrap();
            assert!(!exists, "migration failure must not leak a schema");
            admin.close().await;
        });
    }
}

oauth_impl!(PostgresRepository);

identity_impl!(
    PostgresRepository,
    sqlx::Postgres,
    "SELECT id FROM tenants WHERE id=$1 FOR UPDATE",
    "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT"
);

#[cfg(test)]
mod erasure_race_tests {
    use super::*;
    use memoswish_core::identity::IdentityRepo;
    use memoswish_core::ids::new_id;
    use std::{sync::Arc, time::Duration};

    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_erasure_blocks_overlapping_insert_until_parent_is_gone() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 5).await.unwrap();
            let repo = Arc::new(repo);
            for owner in [false, true] {
                let tid = new_id();
                let uid = new_id();
                repo.upsert_tenant(&TenantRecord {
                    id: tid.clone(),
                    name: "Race".into(),
                    plan: "free".into(),
                    created_at: Utc::now(),
                })
                .await
                .unwrap();
                repo.insert_user(&UserRecord {
                    id: uid.clone(),
                    tenant_id: tid.clone(),
                    email: format!("{uid}@example.com"),
                    display_name: "Race".into(),
                    password_hash: String::new(),
                    role: if owner { Role::Owner } else { Role::Learner },
                    created_at: Utc::now(),
                })
                .await
                .unwrap();
                let insert = "INSERT INTO feedback_events(tenant_id,user_id,event_id,session_id,card_id,body,received_at) VALUES($1,$2,$3,'s','c','{}',CURRENT_TIMESTAMP)";
                sqlx::query(insert).bind(&tid).bind(&uid).bind("before").execute(repo.pool()).await.unwrap();
                let mut controller = repo.pool().acquire().await.unwrap();
                let key: i64 =
                    sqlx::query_scalar("SELECT pg_backend_pid()::bigint").fetch_one(&mut *controller).await.unwrap();
                sqlx::query("SELECT pg_advisory_lock($1)").bind(key).execute(&mut *controller).await.unwrap();
                let suffix = uid.replace('-', "");
                let function = format!("erasure_pause_{suffix}");
                // 行已删除但事务未提交时暂停真实 account_erase，观测连接只控制屏障。
                sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.tenant_id='{tid}' THEN PERFORM pg_advisory_xact_lock({key}); END IF; RETURN OLD; END $$")).execute(&mut *controller).await.unwrap();
                sqlx::query(&format!(
                    "CREATE TRIGGER {function} AFTER DELETE ON feedback_events FOR EACH ROW EXECUTE FUNCTION {function}()"
                ))
                .execute(&mut *controller)
                .await
                .unwrap();
                let eraser = {
                    let (repo, tid, uid) = (repo.clone(), tid.clone(), uid.clone());
                    tokio::spawn(async move { repo.account_erase(&tid, &uid, owner).await })
                };
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_locks WHERE locktype='advisory' AND objid=$1::bigint::oid AND NOT granted").bind(key).fetch_one(&mut *controller).await.unwrap();
                        if waiting > 0 { break; }
                        tokio::task::yield_now().await;
                    }
                }).await.unwrap();
                let mut writer = repo.pool().acquire().await.unwrap();
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *writer).await.unwrap();
                let mut inserting = {
                    let (tid, uid) = (tid.clone(), uid.clone());
                    tokio::spawn(async move {
                        sqlx::query(insert).bind(tid).bind(uid).bind("during").execute(&mut *writer).await
                    })
                };
                let blocked = tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        tokio::select! {
                            result = &mut inserting => { return (false, Some(result)); }
                            waiting = sqlx::query_scalar::<_, bool>("SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1").bind(pid).fetch_one(&mut *controller) => {
                                if waiting.unwrap() { return (true, None); }
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                }).await.unwrap();
                sqlx::query("SELECT pg_advisory_unlock($1)").bind(key).execute(&mut *controller).await.unwrap();
                let job = eraser.await.unwrap().unwrap();
                let result = match blocked.1 {
                    Some(r) => r,
                    None => inserting.await,
                };
                sqlx::query(&format!("DROP TRIGGER {function} ON feedback_events"))
                    .execute(&mut *controller)
                    .await
                    .unwrap();
                sqlx::query(&format!("DROP FUNCTION {function}()")).execute(&mut *controller).await.unwrap();
                assert!(blocked.0, "overlapping insert must wait for erasure, not observe an uncommitted tombstone");
                assert!(result.unwrap().is_err(), "insert after erasure cannot resurrect data");
                let count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM feedback_events WHERE tenant_id=$1 AND user_id=$2")
                        .bind(&tid)
                        .bind(&uid)
                        .fetch_one(repo.pool())
                        .await
                        .unwrap();
                assert_eq!(count, 0);
                assert!(repo.account_erasure_finish(&job.id).await.is_err());
            }
        });
    }
    #[test]
    #[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL"]
    fn postgres_token_updates_lock_parent_before_rows_during_erasure() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 5).await.unwrap();
            let repo = Arc::new(repo);
            for (owner, revoke) in [(false, false), (false, true), (true, false), (true, true)] {
                let tid = new_id();
                let uid = new_id();
                let token = new_id();
                repo.upsert_tenant(&TenantRecord {
                    id: tid.clone(),
                    name: "Update race".into(),
                    plan: "free".into(),
                    created_at: Utc::now(),
                })
                .await
                .unwrap();
                repo.insert_user(&UserRecord {
                    id: uid.clone(),
                    tenant_id: tid.clone(),
                    email: format!("{uid}@example.com"),
                    display_name: "Update race".into(),
                    password_hash: String::new(),
                    role: if owner { Role::Owner } else { Role::Learner },
                    created_at: Utc::now(),
                })
                .await
                .unwrap();
                repo.insert_api_token(&ApiTokenRecord {
                    generations: memoswish_core::CredentialGenerations { account: 0, membership: 0 },
                    id: token.clone(),
                    tenant_id: tid.clone(),
                    user_id: uid.clone(),
                    name: "Race".into(),
                    token_hash: token.clone(),
                    scopes: vec!["*".into()],
                    created_at: Utc::now(),
                    expires_at: None,
                    last_used_at: None,
                    revoked: false,
                })
                .await
                .unwrap();
                sqlx::query("INSERT INTO feedback_events(tenant_id,user_id,event_id,session_id,card_id,body,received_at) VALUES($1,$2,'before','s','c','{}',CURRENT_TIMESTAMP)")
                    .bind(&tid).bind(&uid).execute(repo.pool()).await.unwrap();
                let mut controller = repo.pool().acquire().await.unwrap();
                let key: i64 =
                    sqlx::query_scalar("SELECT pg_backend_pid()::bigint").fetch_one(&mut *controller).await.unwrap();
                let function = format!("token_erasure_pause_{}", uid.replace('-', ""));
                sqlx::query("SELECT pg_advisory_lock($1)").bind(key).execute(&mut *controller).await.unwrap();
                // 擦除持父租户锁、尚未删除 token 时暂停。
                sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.tenant_id='{tid}' THEN PERFORM pg_advisory_xact_lock({key}); END IF; RETURN OLD; END $$"))
                    .execute(&mut *controller).await.unwrap();
                sqlx::query(&format!(
                    "CREATE TRIGGER {function} AFTER DELETE ON feedback_events FOR EACH ROW EXECUTE FUNCTION {function}()"
                ))
                .execute(&mut *controller)
                .await
                .unwrap();
                let eraser = {
                    let (repo, tid, uid) = (repo.clone(), tid.clone(), uid.clone());
                    tokio::spawn(async move { repo.account_erase(&tid, &uid, owner).await })
                };
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_locks WHERE locktype='advisory' AND objid=$1::bigint::oid AND NOT granted")
                            .bind(key).fetch_one(&mut *controller).await.unwrap();
                        if waiting > 0 { break; }
                        tokio::task::yield_now().await;
                    }
                }).await.unwrap();
                let updater = {
                    let (repo, tid, token) = (repo.clone(), tid.clone(), token.clone());
                    tokio::spawn(async move {
                        if revoke {
                            repo.revoke_api_token(&tid, &token).await.map(|_| ())
                        } else {
                            repo.touch_api_token(&token, Utc::now()).await
                        }
                    })
                };
                // 在真实数据库中确认更新已阻塞在持父锁的擦除连接上，不能仅用 task.is_finished。
                let blocked = tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity w WHERE w.datname=current_database() AND w.wait_event_type='Lock' AND EXISTS(SELECT 1 FROM pg_locks e WHERE e.locktype='advisory' AND e.objid=$1::bigint::oid AND NOT e.granted AND e.pid=ANY(pg_blocking_pids(w.pid))))")
                            .bind(key).fetch_one(&mut *controller).await.unwrap();
                        if waiting { break; }
                        tokio::task::yield_now().await;
                    }
                }).await;
                // 此时 token 行必须尚未被更新锁住；旧实现的 BEFORE UPDATE 触发器会倒序持行锁。
                let token_unlocked = sqlx::query("SELECT id FROM api_tokens WHERE id=$1 FOR UPDATE NOWAIT")
                    .bind(&token)
                    .fetch_one(&mut *controller)
                    .await
                    .is_ok();
                sqlx::query("SELECT pg_advisory_unlock($1)").bind(key).execute(&mut *controller).await.unwrap();
                let erased = tokio::time::timeout(Duration::from_secs(10), eraser).await.unwrap().unwrap();
                let updated = tokio::time::timeout(Duration::from_secs(10), updater).await.unwrap().unwrap();
                sqlx::query(&format!("DROP TRIGGER {function} ON feedback_events"))
                    .execute(&mut *controller)
                    .await
                    .unwrap();
                sqlx::query(&format!("DROP FUNCTION {function}()")).execute(&mut *controller).await.unwrap();
                assert!(blocked.is_ok(), "updater must reach the parent-lock barrier");
                assert!(token_unlocked, "updater must not lock the token before the parent tenant");
                let job = erased.expect("erasure must commit without deadlock");
                updated.expect("late token update is a successful no-op");
                assert!(repo.find_api_token(&token).await.unwrap().is_none());
                assert!(repo.get_user(&tid, &uid).await.unwrap().is_none());
                assert!(repo.account_erasure_finish(&job.id).await.is_err());
            }
        });
    }
}

crate::membership::membership_impl!(PostgresRepository, sqlx::Postgres, |time: &DateTime<Utc>| *time);

#[cfg(test)]
mod foundation_tests {
    use super::*;
    crate::foundation_conformance::foundation_tests!(
        PgPool,
        PostgresRepository,
        "./migrations/postgres",
        "ALTER TABLE feed_sessions DISABLE TRIGGER missing_user_feed_sessions; UPDATE feed_sessions SET user_id='orphan' WHERE id='session'; ALTER TABLE feed_sessions ENABLE TRIGGER missing_user_feed_sessions;"
    );

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_foundation_duplicate_registration_overlapping_transactions() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 3).await.unwrap();
            let (winner, loser) = registration_contenders(&repo).await;
            let mut first = repo.pool.begin().await.unwrap();
            let mut second = repo.pool.begin().await.unwrap();
            let first_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *first).await.unwrap();
            let second_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *second).await.unwrap();
            assert_ne!(first_pid, second_pid);
            PostgresRepository::insert_identity(&mut first, &winner).await.unwrap();
            let contender = tokio::spawn(async move {
                let result = PostgresRepository::insert_identity(&mut second, &loser).await;
                second.rollback().await.unwrap();
                (loser, result)
            });
            // 独立观测连接确认第二个真实事务阻塞在第一个事务，不能只看任务是否完成。
            let blocked = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    let waiting: bool = sqlx::query_scalar("SELECT $1=ANY(pg_blocking_pids($2))")
                        .bind(first_pid)
                        .bind(second_pid)
                        .fetch_one(repo.pool())
                        .await
                        .unwrap();
                    if waiting {
                        break;
                    }
                    assert!(!contender.is_finished(), "duplicate registration must wait for the uncommitted winner");
                    tokio::task::yield_now().await;
                }
            })
            .await;
            first.commit().await.unwrap();
            let (loser, result) = contender.await.unwrap();
            assert!(blocked.is_ok(), "duplicate registration must reach the database lock barrier");
            assert!(matches!(result, Err(CoreError::Conflict(_))));
            assert_registration_winner(&repo, &winner, &loser).await;
            repo.pool.close().await;
            fixture.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_foundation_populated_upgrade_and_histories() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let pool = PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            populated_upgrade(&pool).await;
            let objects: Vec<String> = sqlx::query_scalar("SELECT relname::text FROM pg_class WHERE relnamespace=(SELECT oid FROM pg_namespace WHERE nspname=current_schema())")
                .fetch_all(&pool).await.unwrap();
            for expected in crate::foundation_conformance::REQUIRED_SCHEMA_OBJECTS {
                assert!(objects.iter().any(|name| name == expected), "missing schema object {expected}");
            }
            let triggers: Vec<String> = sqlx::query_scalar(
                "SELECT tgname::text FROM pg_trigger WHERE tgrelid='background_jobs'::regclass AND NOT tgisinternal",
            )
            .fetch_all(&pool)
            .await
            .unwrap();
            assert!(triggers.iter().any(|name| name == "job_requester"));
            assert!(triggers.iter().any(|name| name == "erased_jobs"));
            let invalid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_constraint WHERE connamespace=(SELECT oid FROM pg_namespace WHERE nspname=current_schema()) AND NOT convalidated")
                .fetch_one(&pool).await.unwrap();
            assert_eq!(invalid, 0);
            pool.close().await;
            let reopened = PostgresRepository::connect_with_options(fixture.options(), 1).await.unwrap();
            assert_eq!(job_snapshot(reopened.pool()).await.len(), 5);
            reopened.pool.close().await;
            fixture.cleanup().await;
            for scenario in [0, 1, 2] {
                let fixture = test.fixture(&url).await;
                let pool = PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
                if scenario == 0 {
                    invalid_legacy(&pool).await;
                } else if scenario == 1 {
                    rejected_histories(&pool).await;
                } else {
                    dependency_conflict(&pool).await;
                }
                pool.close().await;
                fixture.cleanup().await;
            }
        });
    }
}

#[cfg(test)]
mod atomic_feedback_tests {
    use super::*;
    crate::learning_conformance::learning_tests!(
        PostgresRepository,
        PgPool,
        "./migrations/postgres",
        "CREATE FUNCTION s9_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected memory failure'; END $$; CREATE TRIGGER s9_fail BEFORE INSERT ON memory_states FOR EACH ROW EXECUTE FUNCTION s9_fail();",
        "CREATE FUNCTION s9_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$; CREATE TRIGGER s9_fail AFTER UPDATE ON memory_states FOR EACH ROW EXECUTE FUNCTION s9_fail();",
        "DROP TRIGGER s9_fail ON memory_states; DROP FUNCTION s9_fail();"
    );

    async fn retry_classification(repo: &PostgresRepository) {
        for code in ["40001", "40P01", "23514"] {
            let (rec, state) = seed(repo).await;
            sqlx::raw_sql(&format!("CREATE FUNCTION s9_retry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='{code}', MESSAGE='injected SQLSTATE'; END $$; CREATE TRIGGER s9_retry BEFORE INSERT ON memory_states FOR EACH ROW EXECUTE FUNCTION s9_retry();"))
                .execute(repo.pool()).await.unwrap();
            let result = repo.try_apply_learning_event(&rec, None, &state).await;
            if code == "23514" {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Retry);
            }
            assert_eq!(event_count(repo, &rec).await, 0);
            assert!(snapshot(repo, &rec).await.is_none());
            sqlx::raw_sql("DROP TRIGGER s9_retry ON memory_states; DROP FUNCTION s9_retry();")
                .execute(repo.pool())
                .await
                .unwrap();
            assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), Applied);
        }
    }

    async fn revision_at_acceptance_overlap(repo: &PostgresRepository) {
        // S13 在租户行上序列化内容写入；先写内容的屏障必须位于学习事务取锁之前。
        for point in [TestPoint::BeforeTransaction, TestPoint::BeforeCommit] {
            let (rec, state) = seed(repo).await;
            let card = repo.get_card(&rec.tenant_id, &rec.event.card_id).await.unwrap().unwrap();
            let original = card.revision;
            let change = crate::content_conformance::edit(&card, Some(original), "concurrent content update");
            let gate = TestGate::new(point);
            let mut paused = repo.clone();
            paused.learning_gate = Some(gate.clone());
            let record = rec.clone();
            let writer = tokio::spawn(async move { paused.try_apply_learning_event(&record, None, &state).await });
            gate.reached.notified().await;
            let updater = repo.clone();
            let tenant = rec.tenant_id.clone();
            let update = tokio::spawn(async move { updater.mutate_cards(&tenant, &[change]).await });
            if point == TestPoint::BeforeTransaction {
                let updated = update.await.unwrap().unwrap();
                assert_eq!(updated[0].revision, original + 1);
                gate.resume.add_permits(1);
            } else {
                observe_overlap(repo).await;
                gate.resume.add_permits(1);
                assert_eq!(writer.await.unwrap().unwrap(), Applied);
                let updated = update.await.unwrap().unwrap();
                assert_eq!(updated[0].revision, original + 1);
                assert_eq!(stored_provenance(repo, &rec).await.unwrap().revision_at_acceptance, original);
                continue;
            }
            assert_eq!(writer.await.unwrap().unwrap(), Applied);
            assert_eq!(stored_provenance(repo, &rec).await.unwrap().revision_at_acceptance, original + 1);
        }
    }

    async fn observe_overlap(repo: &PostgresRepository) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=current_setting('application_name') AND wait_event_type='Lock')")
                    .fetch_one(repo.pool()).await.unwrap();
                if blocked { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_atomic_feedback_conformance() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let pool = PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            atomic_feedback_upgrade(&pool).await;
            pool.close().await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            atomic_feedback_suite(&repo).await;
            retry_classification(&repo).await;
            revision_at_acceptance_overlap(&repo).await;
            repo.pool.close().await;
            fixture.cleanup().await;
        });
    }
}

impl PostgresRepository {
    async fn insert_api_token_bound(&self, t: &ApiTokenRecord, require_management: bool) -> CoreResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_err)?;
        let role = Self::authorize_tx(&mut tx, &t.tenant_id, &t.user_id, t.generations).await?;
        if require_management && !role.allows(memoswish_core::Permission::TokenManage) {
            return Err(CoreError::Forbidden("token management requires current permission".into()));
        }
        sqlx::query(
            "INSERT INTO api_tokens (id, tenant_id, user_id, name, token_hash, scopes, created_at, expires_at, last_used_at, revoked, account_generation, membership_generation)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(&t.id)
        .bind(&t.tenant_id)
        .bind(&t.user_id)
        .bind(&t.name)
        .bind(&t.token_hash)
        .bind(Json(&t.scopes))
        .bind(t.created_at)
        .bind(t.expires_at)
        .bind(t.last_used_at)
        .bind(t.revoked)
        .bind(t.generations.account)
        .bind(t.generations.membership)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    crate::membership_conformance::membership_tests!(PostgresRepository, sqlx::PgPool, "./migrations/postgres");
    async fn observe_membership_wait(repo: &PostgresRepository) {
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock')").fetch_one(repo.pool()).await.unwrap();
                if blocked {break;}
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
    }
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_membership_generations_and_upgrade() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let pool =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            membership_upgrade(&pool).await;
            pool.close().await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            membership_suite(&repo).await;
            membership_issuance_races(&repo).await;
            membership_identity_races(&repo).await;
            zero_account_cleanup_responsibility(&repo).await;
            let user = persistent_member_setup(&repo).await;
            repo.pool().close().await;
            let restarted = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            persistent_member_resume(&restarted, &user).await;
            restarted.pool().close().await;
            fixture.cleanup().await;
        });
    }
}

#[cfg(test)]
mod content_cas_tests {
    use super::*;
    crate::content_conformance::content_tests!(
        PostgresRepository,
        PgPool,
        "./migrations/postgres",
        "CREATE FUNCTION s13_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.body->'front'->>'title'='SQL_FAIL' THEN RAISE EXCEPTION 'injected card failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER s13_fail BEFORE UPDATE ON cards FOR EACH ROW EXECUTE FUNCTION s13_fail();",
        "DROP TRIGGER s13_fail ON cards; DROP FUNCTION s13_fail();",
        crate::ownership::postgres_report
    );

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_content_ownership_upgrade_and_retention() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let fixture = test.fixture(&url).await;
            let pool = PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            s14_upgrade(&pool).await;
            pool.close().await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            s14_ownership_and_retention(&repo).await;
            s14_delete_rollback_and_orderings(&repo).await;
            s14_content_write_and_erasure(&repo).await;
            let report = crate::ownership::postgres_report(repo.pool()).await.unwrap();
            assert_eq!(report.iter().find(|r| r.category == "cards_missing_owned_deck").unwrap().row_count, 0);
            repo.pool.close().await;
            fixture.cleanup().await;
        });
    }

    async fn s13_observe_content_wait(repo: &PostgresRepository) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=current_setting('application_name') AND wait_event_type='Lock')")
                    .fetch_one(repo.pool()).await.unwrap();
                if blocked { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("content writer did not overlap the held transaction");
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_deleted_card_id_reuse_with_stale_snapshot() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let fixture = test.fixture(&url).await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            let (rec, state) = crate::learning_conformance::seed(&repo).await;
            let card = repo.get_card(&rec.tenant_id, &state.card_id).await.unwrap().unwrap();
            assert_eq!(repo.try_apply_learning_event(&rec, None, &state).await.unwrap(), LearningEventOutcome::Applied);
            let history = crate::learning_conformance::snapshot(&repo, &rec).await;

            // 删除先持租户锁并写入墓碑，但尚未提交。
            let mut deleting = repo.pool.begin().await.unwrap();
            sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE")
                .bind(&rec.tenant_id)
                .fetch_one(&mut *deleting)
                .await
                .unwrap();
            sqlx::query("DELETE FROM cards WHERE tenant_id=$1 AND id=$2")
                .bind(&rec.tenant_id)
                .bind(&card.id)
                .execute(&mut *deleting)
                .await
                .unwrap();

            // 第二条连接在删除提交前固定快照，确保看不到新墓碑。
            let mut stale = repo.pool.begin().await.unwrap();
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ").execute(&mut *stale).await.unwrap();
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM deleted_card_ids WHERE tenant_id=$1 AND card_id=$2")
                    .bind(&rec.tenant_id)
                    .bind(&card.id)
                    .fetch_one(&mut *stale)
                    .await
                    .unwrap();
            assert_eq!(count, 0);
            let tenant = rec.tenant_id.clone();
            let replacement = tokio::spawn(async move {
                sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE")
                    .bind(&tenant)
                    .fetch_one(&mut *stale)
                    .await
                    .unwrap();
                let count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM deleted_card_ids WHERE tenant_id=$1 AND card_id=$2")
                        .bind(&tenant)
                        .bind(&card.id)
                        .fetch_one(&mut *stale)
                        .await
                        .unwrap();
                assert_eq!(count, 0, "tenant locking must not refresh the repeatable-read snapshot");
                let result = sqlx::query("INSERT INTO cards(id,tenant_id,deck_id,template,revision,body,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                    .bind(&card.id).bind(&tenant).bind(&card.deck_id).bind(card.template.as_str())
                    .bind(card.revision as i32).bind(Json(&card)).bind(card.created_at).bind(card.updated_at)
                    .execute(&mut *stale).await;
                if result.is_ok() {
                    stale.commit().await.unwrap();
                } else {
                    stale.rollback().await.unwrap();
                }
                result
            });
            // 观察真实数据库等待后才提交，不依赖睡眠推断交错。
            s13_observe_content_wait(&repo).await;
            deleting.commit().await.unwrap();
            let error = replacement.await.unwrap().expect_err("a stale snapshot must not resurrect a deleted card ID");
            let database_error = error.as_database_error().unwrap();
            assert_eq!(database_error.code().as_deref(), Some("23505"));
            assert_eq!(database_error.constraint(), Some("deleted_card_ids_pkey"));
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM deleted_card_ids WHERE tenant_id=$1 AND card_id=$2")
                    .bind(&rec.tenant_id)
                    .bind(&state.card_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
            assert_eq!(count, 1);
            assert!(repo.get_card(&rec.tenant_id, &state.card_id).await.unwrap().is_none());
            assert!(
                repo.get_deck(&rec.tenant_id, &memoswish_protocol::examples::sample_deck().id).await.unwrap().is_some()
            );
            assert_eq!(crate::learning_conformance::snapshot(&repo, &rec).await, history);
            assert!(repo.list_memory(&rec.tenant_id, &rec.user_id).await.unwrap().is_empty());
            assert_eq!(
                repo.try_apply_learning_event(&rec, None, &state).await.unwrap(),
                LearningEventOutcome::Duplicate
            );
            repo.pool.close().await;
            fixture.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_content_cas_upgrade_atomicity_and_independent_connections() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let pool = PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            s13_upgrade(&pool).await;
            pool.close().await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            let other = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            crate::content_conformance::suite(&repo, &other).await;
            s13_sql_failure_and_overflow(&repo).await;
            s13_cancel_before_commit(&repo).await;
            s13_overlapping_transactions(&repo).await;
            other.pool.close().await;
            repo.pool.close().await;
            fixture.cleanup().await;
        });
    }
}
crate::assets::asset_impl!(
    PostgresRepository,
    sqlx::Postgres,
    sqlx::postgres::PgRow,
    "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT)",
    " FOR SHARE OF t,m,a"
);

crate::sessions::sessions_impl!(
    PostgresRepository,
    sqlx::Postgres,
    "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT",
    |d: &chrono::DateTime<chrono::Utc>| *d
);

#[cfg(test)]
mod opaque_session_lock_tests {
    use super::*;
    use memoswish_core::{identity::IdentityRepo, session::SessionRepo};
    crate::session_conformance::upgrade_tests!(PostgresRepository, sqlx::PgPool, "./migrations/postgres");
    crate::session_conformance::prerequisites_tests!(
        PostgresRepository,
        sqlx::PgPool,
        "./migrations/postgres",
        "CREATE FUNCTION reject_fence_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected fence failure'; END $$; CREATE TRIGGER reject_fence BEFORE INSERT OR UPDATE ON app_session_fences FOR EACH ROW EXECUTE FUNCTION reject_fence_write()",
        "DROP TRIGGER reject_fence ON app_session_fences"
    );

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_s21b_pending_links_recheck_logout() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("PostgreSQL URL required");
            let fixture = owner.fixture(&url).await;
            let repo = fixture.repository(4).await.unwrap();
            s21b_pending_links_recheck_logout(&repo.pool).await;
            repo.pool.close().await;
            fixture.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_s21b_atomicity_and_populated_upgrade() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("PostgreSQL URL required");
            let fixture = owner.fixture(&url).await;
            let pool = PgPoolOptions::new().max_connections(4).connect_with(fixture.options()).await.unwrap();
            s21b_populated_upgrade(&pool).await;
            s21b_atomicity(&pool).await;
            pool.close().await;
            fixture.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_pre_s21_pending_links_are_invalidated_on_upgrade() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("PostgreSQL URL required");
            let fixture = owner.fixture(&url).await;
            let pool = PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            pre_s21_links_upgrade(&pool).await;
            pool.close().await;
            fixture.cleanup().await;
        });
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_link_deadline_is_observed_after_registration_lock() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("PostgreSQL URL required");
            let fixture = owner.fixture(&url).await;
            let repo = std::sync::Arc::new(fixture.repository(4).await.unwrap());
            let (f, _, i, a) = crate::session_conformance::staged_link(&*repo).await;
            let mut tx = repo.pool.begin().await.unwrap();
            sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.unwrap();
            let (started, waiting) = tokio::sync::oneshot::channel();
            let task = {
                let (repo, f, i, a) = (repo.clone(), f.clone(), i.clone(), a.clone());
                tokio::spawn(async move {
                    let _ = started.send(());
                    repo.identity_complete(
                        &a.id,
                        &i.tenant_id,
                        &f.user_id,
                        memoswish_core::CredentialGenerations { account: 0, membership: 0 },
                        "lock-wait-assurance",
                        Utc::now().timestamp(),
                    )
                    .await
                })
            };
            waiting.await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(10),async{
                loop{
                    let blocked:i64=sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND wait_event_type='Lock' AND query LIKE '%UPDATE oauth_registry%'")
                        .bind(&fixture.schema).fetch_one(&mut *tx).await.unwrap();
                    if blocked>0{break;}tokio::task::yield_now().await;
                }
            }).await.unwrap();
            // 持锁期间跨越持久期限，调用前采样时间不得让完成越过屏障。
            sqlx::query(
                "UPDATE oidc_attempts SET expires_at=FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT WHERE id=$1",
            )
            .bind(&a.id)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            assert!(task.await.unwrap().is_err());
            assert!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().is_empty());
            assert!(
                !repo
                    .identity_check_recent(
                        &i.tenant_id,
                        &f.user_id,
                        memoswish_core::CredentialGenerations { account: 0, membership: 0 },
                        "lock-wait-assurance",
                        Utc::now().timestamp()
                    )
                    .await
                    .unwrap()
            );
            // PostgreSQL 重连保留已消费父凭据与撤销，不依赖进程内缓存。
            let (f, c, _, _) = crate::session_conformance::staged_link(&*repo).await;
            let next = repo
                .session_rotate(&c.refresh_hash, "pg-next-access", "pg-next-refresh", "pg-next-assurance", 600)
                .await
                .unwrap();
            let restarted = fixture.repository(2).await.unwrap();
            assert!(
                restarted
                    .session_rotate(&c.refresh_hash, "pg-retry-access", "pg-retry-refresh", "pg-retry-assurance", 600)
                    .await
                    .is_err()
            );
            assert!(restarted.session_access(&next.credential.access_hash).await.is_err());
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT revoked FROM app_sessions WHERE id=$1")
                    .bind(&f.id)
                    .fetch_one(&restarted.pool)
                    .await
                    .unwrap(),
                1
            );
            fixture.cleanup().await;
        });
    }
}

impl PostgresRepository {
    fn feed_session_row(r: &sqlx::postgres::PgRow) -> CoreResult<FeedSession> {
        Ok(FeedSession {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            user_id: r.get("user_id"),
            next_slot: r.get::<i64, _>("next_slot") as u64,
            recent_card_ids: r.get::<Json<Vec<String>>, _>("recent_card_ids").0,
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        })
    }
}
crate::feed_issuance::feed_issuance_impl!(
    PostgresRepository,
    sqlx::Postgres,
    sqlx::postgres::PgRow,
    "BEGIN",
    "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT)",
    " FOR SHARE OF t,m,a",
    " FOR SHARE",
    |ids: &Vec<String>| -> CoreResult<Json<Vec<String>>> { Ok(Json(ids.clone())) },
    |t: &DateTime<Utc>| *t,
    Self::feed_session_row
);

#[cfg(test)]
mod feed_issuance_tests {
    use super::*;
    crate::feed_issuance_conformance::backend_tests!(
        PostgresRepository,
        sqlx::PgPool,
        "./migrations/postgres",
        "CREATE FUNCTION s11_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected feed failure'; END $$; CREATE TRIGGER s11_fail BEFORE UPDATE OF issuance_revision ON feed_sessions FOR EACH ROW EXECUTE FUNCTION s11_fail();",
        "DROP TRIGGER s11_fail ON feed_sessions; DROP FUNCTION s11_fail();"
    );

    async fn observe_feed_overlap(repo: &PostgresRepository) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock')")
                    .fetch_one(repo.pool()).await.unwrap();
                if blocked { break; }
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_replayable_feed_conformance() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let pool = PgPoolOptions::new().max_connections(1).connect_with(fixture.options()).await.unwrap();
            feed_upgrade(&pool).await;
            pool.close().await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            let other = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            feed_backend_scenarios(&repo, &other).await;
            let p = crate::feed_issuance_conformance::seed(&repo).await;
            let req = crate::feed_issuance_conformance::first();
            let a = crate::feed_issuance_conformance::candidate(&repo, &p, &req, false).await;
            let page =
                crate::feed_issuance_conformance::committed(repo.feed_issuance(&p, &req, Some(&a)).await.unwrap());
            repo.pool.close().await;
            other.pool.close().await;
            let reopened = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            assert_eq!(
                crate::feed_issuance_conformance::committed(reopened.feed_issuance(&p, &req, None).await.unwrap()),
                page
            );
            reopened.pool.close().await;
            fixture.cleanup().await;
        });
    }
}

crate::lifecycle::lifecycle_impl!(PostgresRepository, sqlx::Postgres, "SELECT id FROM tenants WHERE id=$1 FOR UPDATE");

impl PostgresRepository {
    async fn learning_write_tx(
        &self,
        tenant: &str,
        user: &str,
        generations: Option<memoswish_core::CredentialGenerations>,
    ) -> CoreResult<sqlx::Transaction<'_, sqlx::Postgres>> {
        let mut tx = self.lifecycle_tx(&[tenant.into()]).await?;
        if let Some(g) = generations {
            Self::authorize_tx(&mut tx, tenant, user, g).await?;
        }
        Ok(tx)
    }
    async fn try_apply_learning_event_inner(
        &self,
        rec: &FeedbackEventRecord,
        expected: Option<i64>,
        s: &MemoryState,
        generations: Option<memoswish_core::CredentialGenerations>,
        principal: Option<&memoswish_core::Principal>,
    ) -> CoreResult<LearningEventOutcome> {
        use memoswish_core::observability::{Operation, Outcome};
        let mut observation = self.observer.start(Operation::DbWrite);
        let result: CoreResult<_> = async {
        crate::learning::validate(rec, expected, s)?;
        let hash = crate::learning::payload_hash(&rec.session_id, &rec.event)?;
        let body = Json(&rec.event);
        let result: Result<LearningEventOutcome, sqlx::Error> = async {
            #[cfg(test)]
            if let Some(gate) = &self.learning_gate { gate.pause(crate::learning::TestPoint::BeforeTransaction).await; }
            let mut tx = self.pool.begin().await?;
            sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await?;
            if let Some(p) = principal {
                match Self::learning_principal_tx(&mut tx, p).await {
                    Ok(()) => {}
                    Err(CoreError::Unauthorized(_)) => return Ok(LearningEventOutcome::MissingScope),
                    Err(_) => return Err(sqlx::Error::Protocol("learning session validation failed".into())),
                }
            }
            if sqlx::query("SELECT 1 FROM tenants WHERE id=$1 FOR SHARE").bind(&rec.tenant_id)
                .fetch_optional(&mut *tx).await?.is_none() {
                return Ok(LearningEventOutcome::MissingScope);
            }
            if sqlx::query("SELECT 1 FROM users WHERE id=$1 FOR SHARE").bind(&rec.user_id)
                .fetch_optional(&mut *tx).await?.is_none() {
                return Ok(LearningEventOutcome::MissingScope);
            }
            if sqlx::query("SELECT 1 FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2 FOR SHARE").bind(&rec.tenant_id).bind(&rec.user_id)
                .fetch_optional(&mut *tx).await?.is_none() {
                return Ok(LearningEventOutcome::MissingScope);
            }
            if let Some(g) = generations {
                let valid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships m JOIN account_auth_epochs a ON a.user_id=m.user_id WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.generation=$3 AND a.generation=$4")
                    .bind(&rec.tenant_id).bind(&rec.user_id).bind(g.membership).bind(g.account).fetch_one(&mut *tx).await?;
                if valid != 1 { return Ok(LearningEventOutcome::MissingScope); }
            }
            let inserted = sqlx::query("INSERT INTO feedback_events(tenant_id,user_id,event_id,session_id,card_id,rating,body,received_at,payload_hash)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,user_id,event_id) DO NOTHING")
                .bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.event.event_id).bind(&rec.session_id)
                .bind(&rec.event.card_id).bind(rec.rating.map(i64::from)).bind(body)
                .bind(rec.received_at).bind(&hash).execute(&mut *tx).await?;
            if inserted.rows_affected() == 0 {
                let row = sqlx::query("SELECT session_id,body,payload_hash FROM feedback_events WHERE tenant_id=$1 AND user_id=$2 AND event_id=$3")
                    .bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.event.event_id).fetch_one(&mut *tx).await?;
                let stored_hash: Option<String> = row.get("payload_hash");
                let identical = match stored_hash {
                    Some(stored) => stored == hash,
                    None => row.get::<String, _>("session_id") == rec.session_id && row.get::<Json<ImplicitFeedback>, _>("body").0 == rec.event,
                };
                return Ok(if identical { LearningEventOutcome::Duplicate } else { LearningEventOutcome::PayloadConflict });
            }
            let card = sqlx::query("SELECT revision, publication FROM cards WHERE tenant_id=$1 AND id=$2 FOR SHARE")
                .bind(&rec.tenant_id).bind(&rec.event.card_id).fetch_optional(&mut *tx).await?;
            let Some(card) = card else {
                return Ok(LearningEventOutcome::MissingCard);
            };
            if card.get::<String, _>("publication") != "published" {
                return Ok(LearningEventOutcome::MissingCard);
            }
            // 重复事件已经恢复；新事件在同一个接受事务核验不可变绑定。
            let body: Option<String> = sqlx::query_scalar("SELECT body FROM feed_deliveries WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND slot=$4")
                .bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.session_id).bind(i64::try_from(rec.event.slot).unwrap_or(-1))
                .fetch_optional(&mut *tx).await?;
            let legacy_limit: Option<i64> = sqlx::query_scalar("SELECT COALESCE(attribution_start_slot,next_slot) FROM feed_sessions WHERE tenant_id=$1 AND user_id=$2 AND id=$3")
                .bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.session_id).fetch_optional(&mut *tx).await?;
            if !crate::learning::valid_delivery(rec, body.as_deref(), legacy_limit, principal.is_none())? {
                return Ok(LearningEventOutcome::InvalidDelivery);
            }
            let provenance = crate::learning::provenance(rec, expected, card.get("revision"))?;
            let provenance = Json(provenance);
            sqlx::query("UPDATE feedback_events SET application_provenance=$1 WHERE tenant_id=$2 AND user_id=$3 AND event_id=$4")
                .bind(provenance).bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.event.event_id)
                .execute(&mut *tx).await?;
            #[cfg(test)]
            if let Some(gate) = &self.learning_gate { gate.pause(crate::learning::TestPoint::AfterInsert).await; }
            let explicit_star: Option<bool> = sqlx::query_scalar("SELECT starred FROM personal_favorites WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3").bind(&s.tenant_id).bind(&s.user_id).bind(&s.card_id).fetch_optional(&mut *tx).await?;
            let changed = sqlx::query("INSERT INTO memory_states(tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures,last_review,due,starred,last_rating,projection_version) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13 WHERE $14 IS NULL OR EXISTS(SELECT 1 FROM memory_states WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3)
                ON CONFLICT(tenant_id,user_id,card_id) DO UPDATE SET stability=CASE WHEN $15 THEN excluded.stability ELSE memory_states.stability END,difficulty=CASE WHEN $15 THEN excluded.difficulty ELSE memory_states.difficulty END,reps=CASE WHEN $15 THEN excluded.reps ELSE memory_states.reps END,lapses=CASE WHEN $15 THEN excluded.lapses ELSE memory_states.lapses END,exposures=excluded.exposures,last_review=CASE WHEN $15 THEN excluded.last_review ELSE memory_states.last_review END,due=CASE WHEN $15 THEN excluded.due ELSE memory_states.due END,starred=excluded.starred,last_rating=CASE WHEN $15 THEN excluded.last_rating ELSE memory_states.last_rating END,projection_version=excluded.projection_version WHERE memory_states.projection_version=$14")
                .bind(&s.tenant_id).bind(&s.user_id).bind(&s.card_id).bind(s.stability).bind(s.difficulty)
                .bind(i64::from(s.reps)).bind(i64::from(s.lapses)).bind(i64::from(s.exposures))
                .bind(s.last_review).bind(s.due).bind(explicit_star.unwrap_or(s.starred)).bind(s.last_rating.map(i64::from))
                .bind(expected.map_or(1, |v| v + 1)).bind(expected)
                .bind(rec.application.as_ref().is_some_and(|a| a.effective_at.is_some())).execute(&mut *tx).await?;
            if changed.rows_affected() == 0 {
                tx.rollback().await?;
                return Ok(LearningEventOutcome::Retry);
            }
            #[cfg(test)]
            if let Some(gate) = &self.learning_gate { gate.pause(crate::learning::TestPoint::BeforeCommit).await; }
            tx.commit().await?;
            Ok(LearningEventOutcome::Applied)
        }.await;
        match result {
            Ok(outcome) => Ok(outcome),
            Err(error) if crate::learning::retryable(&error) => Ok(LearningEventOutcome::Retry),
            Err(error) => Err(db_err(error)),
        }

        }.await;
        observation.finish(if result.is_ok() { Outcome::Returned } else { Outcome::Error });
        result
    }

    async fn upsert_memory_inner(
        &self,
        s: &MemoryState,
        generations: Option<memoswish_core::CredentialGenerations>,
    ) -> CoreResult<()> {
        let mut tx = self.learning_write_tx(&s.tenant_id, &s.user_id, generations).await?;
        sqlx::query(
            "INSERT INTO memory_states (tenant_id, user_id, card_id, stability, difficulty, reps, lapses, exposures, last_review, due, starred, last_rating, projection_version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 1)
             ON CONFLICT (tenant_id, user_id, card_id) DO UPDATE SET stability = EXCLUDED.stability,
               difficulty = EXCLUDED.difficulty, reps = EXCLUDED.reps, lapses = EXCLUDED.lapses,
               exposures = EXCLUDED.exposures, last_review = EXCLUDED.last_review, due = EXCLUDED.due,
               starred = EXCLUDED.starred, last_rating = EXCLUDED.last_rating, projection_version = memory_states.projection_version + 1",
        )
        .bind(&s.tenant_id)
        .bind(&s.user_id)
        .bind(&s.card_id)
        .bind(s.stability)
        .bind(s.difficulty)
        .bind(s.reps as i64)
        .bind(s.lapses as i64)
        .bind(s.exposures as i64)
        .bind(s.last_review)
        .bind(s.due)
        .bind(s.starred)
        .bind(s.last_rating.map(|v| v as i64))
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn insert_feedback_inner(
        &self,
        rec: &FeedbackEventRecord,
        generations: Option<memoswish_core::CredentialGenerations>,
    ) -> CoreResult<bool> {
        let mut tx = self.learning_write_tx(&rec.tenant_id, &rec.user_id, generations).await?;
        let res = sqlx::query(
            "INSERT INTO feedback_events (tenant_id, user_id, event_id, session_id, card_id, rating, body, received_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        )
        .bind(&rec.tenant_id)
        .bind(&rec.user_id)
        .bind(&rec.event.event_id)
        .bind(&rec.session_id)
        .bind(&rec.event.card_id)
        .bind(rec.rating.map(|v| v as i64))
        .bind(Json::<&ImplicitFeedback>(&rec.event))
        .bind(rec.received_at)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    async fn save_session_inner(
        &self,
        s: &FeedSession,
        generations: Option<memoswish_core::CredentialGenerations>,
    ) -> CoreResult<()> {
        let mut tx = self.learning_write_tx(&s.tenant_id, &s.user_id, generations).await?;
        let changed = sqlx::query(
            "INSERT INTO feed_sessions (id, tenant_id, user_id, next_slot, recent_card_ids, created_at, updated_at, expires_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (tenant_id, user_id, id) DO UPDATE SET next_slot = EXCLUDED.next_slot,
               recent_card_ids = EXCLUDED.recent_card_ids, updated_at = EXCLUDED.updated_at, expires_at_ms = EXCLUDED.expires_at_ms WHERE feed_sessions.issuance_revision=0 AND feed_sessions.first_request_id IS NULL AND feed_sessions.issuance_cursor IS NULL",
        )
        .bind(&s.id)
        .bind(&s.tenant_id)
        .bind(&s.user_id)
        .bind(s.next_slot as i64)
        .bind(Json(&s.recent_card_ids))
        .bind(s.created_at)
        .bind(s.updated_at)
        .bind(s.updated_at.timestamp_millis().saturating_add(crate::feed_issuance::SESSION_LIFETIME_MS))
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        if changed.rows_affected() != 1 {
            return Err(CoreError::Conflict("feed session is managed by issuance".into()));
        }
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use memoswish_core::identity::IdentityRepo;
    use memoswish_core::{AccountPrincipal, Principal};
    crate::lifecycle_conformance::lifecycle_tests!(
        PostgresRepository,
        "CREATE FUNCTION s5_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected lifecycle failure'; END $$; CREATE TRIGGER s5_fault BEFORE DELETE ON tenants FOR EACH ROW EXECUTE FUNCTION s5_fault();",
        "DROP TRIGGER s5_fault ON tenants; DROP FUNCTION s5_fault();"
    );

    async fn s5_observe_wait(repo: &PostgresRepository) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock')").fetch_one(repo.pool()).await.unwrap();
                if blocked { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("lifecycle command did not wait on held registry lock");
    }

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_lifecycle_commands() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL")
                .expect("integration prerequisite missing: MEMOSWISH_TEST_POSTGRES_URL");
            let fixture = test.fixture(&url).await;
            let repo = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            lifecycle_suite(&repo).await;
            let jobs = repo.account_erasure_jobs().await.unwrap();
            assert!(!jobs.is_empty());
            repo.pool().close().await;
            let restarted = PostgresRepository::connect_with_options(fixture.options(), 8).await.unwrap();
            assert_eq!(
                restarted.account_erasure_jobs().await.unwrap().iter().map(|j| &j.id).collect::<Vec<_>>(),
                jobs.iter().map(|j| &j.id).collect::<Vec<_>>()
            );
            restarted.pool().close().await;
        });
    }
}

#[cfg(test)]
mod session_prerequisite_lock_tests {
    use super::*;
    use memoswish_core::{identity::IdentityRepo, session::SessionRepo};

    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_s21b_logout_blocks_waiting_legacy_rotate_select_and_ack() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("PostgreSQL URL required");
            let fixture = owner.fixture(&url).await;
            let repo = std::sync::Arc::new(fixture.repository(4).await.unwrap());
            for operation in [
                "legacy-account",
                "legacy-workspace",
                "rotate",
                "select",
                "ack",
                "deadline",
                "link-workspace",
                "link-account",
                "link-opaque",
                "link-stage",
            ] {
                let (f, c, i, a) =
                    crate::session_conformance::staged_link_with_legacy(&*repo, operation.starts_with("link-")).await;
                let mut root_family = f.clone();
                root_family.id = memoswish_core::ids::new_id();
                let root = crate::session_conformance::credential(&root_family, None);
                repo.session_issue(&root_family, &root, None).await.unwrap();
                let selection = crate::session_conformance::credential(&root_family, Some((i.tenant_id.clone(), 0)));
                let mut tx = repo.pool.begin().await.unwrap();
                let now = PostgresRepository::session_lock(&mut tx).await.unwrap();
                if operation == "deadline" {
                    sqlx::query("UPDATE oidc_attempts SET expires_at=$1 WHERE id=$2")
                        .bind(now)
                        .bind(&a.id)
                        .execute(&mut *tx)
                        .await
                        .unwrap();
                } else {
                    // 持锁执行真实注销事务体，在提交屏障暂停等待中的操作。
                    PostgresRepository::session_revoke_all_tx(&mut tx, &root.access_hash, now).await.unwrap();
                }
                let (started, waiting) = tokio::sync::oneshot::channel();
                let task = {
                    let (repo, f, c, i, a, root) =
                        (repo.clone(), f.clone(), c.clone(), i.clone(), a.clone(), root.clone());
                    tokio::spawn(async move {
                        let _ = started.send(());
                        match operation {
                            "legacy-account" => {
                                repo.legacy_session_authorize(&f.user_id, 0, now - 1, Some(now), None).await
                            }
                            "legacy-workspace" => {
                                repo.legacy_session_authorize(
                                    &f.user_id,
                                    0,
                                    now - 1,
                                    Some(now),
                                    Some((&i.tenant_id, 0)),
                                )
                                .await
                            }
                            "rotate" => repo
                                .session_rotate(
                                    &c.refresh_hash,
                                    "waiting-access",
                                    "waiting-refresh",
                                    "waiting-assurance",
                                    600,
                                )
                                .await
                                .map(|_| ()),
                            "select" => repo.session_select(&root.access_hash, &selection).await,
                            "link-workspace" => {
                                repo.identity_complete(
                                    &a.id,
                                    &i.tenant_id,
                                    &f.user_id,
                                    memoswish_core::CredentialGenerations { account: 0, membership: 0 },
                                    "waiting-assurance",
                                    now,
                                )
                                .await
                            }
                            "link-account" => {
                                repo.identity_complete_account(
                                    &a.id,
                                    &i.tenant_id,
                                    &f.user_id,
                                    0,
                                    "waiting-assurance",
                                    now,
                                )
                                .await
                            }
                            "link-stage" => repo
                                .identity_resolve(
                                    &i,
                                    None,
                                    true,
                                    None,
                                    Some(memoswish_core::CredentialGenerations { account: 0, membership: 0 }),
                                    Some(&a.id),
                                )
                                .await
                                .map(|_| ()),
                            "link-opaque" => {
                                let mut fresh = f.clone();
                                fresh.id = memoswish_core::ids::new_id();
                                let credential = crate::session_conformance::credential(&fresh, None);
                                repo.session_issue(&fresh, &credential, Some(&a.id)).await
                            }
                            _ => repo.session_link_ack(&c.access_hash, &a.id).await,
                        }
                    })
                };
                waiting.await.unwrap();
                tokio::time::timeout(std::time::Duration::from_secs(10),async {
                    loop {
                        let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND wait_event_type='Lock' AND query LIKE '%UPDATE oauth_registry%')")
                            .bind(&fixture.schema).fetch_one(&repo.pool).await.unwrap();
                        if blocked {break;}
                        tokio::task::yield_now().await;
                    }
                }).await.unwrap();
                tx.commit().await.unwrap();
                assert!(task.await.unwrap().is_err(), "{operation}");
                assert!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().is_empty());
                if operation != "deadline" {
                    let restarted = fixture.repository(2).await.unwrap();
                    assert!(restarted.session_access(&root.access_hash).await.is_err());
                    assert!(restarted.legacy_session_authorize(&f.user_id, 0, now, None, None).await.is_err());
                    restarted.pool.close().await;
                }
            }
            repo.pool.close().await;
            fixture.cleanup().await;
        });
    }
}

crate::account_export::account_export_impl!(PostgresRepository, sqlx::Postgres);

// 候选读取复用共享 SQL 形状与本后端的类型转换。
feed_candidate_repo!(PostgresRepository, sqlx::Postgres);

fn candidate_metadata_columns() -> &'static str {
    "SELECT c.id AS live_card_id, c.created_at AS card_created_at, COALESCE(l.suspended,0) AS control_suspended, l.buried_until_ms, COALESCE(l.last_issued_seq,0) AS last_issued_seq, m.*"
}

fn candidate_metadata(row: &sqlx::postgres::PgRow) -> CoreResult<FeedCardMetadata> {
    let memory = if row.try_get::<Option<String>, _>("card_id").map_err(crate::feed_candidates::query_error)?.is_some()
    {
        Some(candidate_memory(row)?)
    } else {
        None
    };
    Ok(FeedCardMetadata {
        suspended: row.get::<i64, _>("control_suspended") != 0,
        buried_until_ms: row.get("buried_until_ms"),
        last_issued_seq: row.get("last_issued_seq"),
        card_id: row.try_get("live_card_id").map_err(crate::feed_candidates::query_error)?,
        created_at: candidate_created_at(row)?,
        memory,
    })
}

fn candidate_created_at(row: &sqlx::postgres::PgRow) -> CoreResult<DateTime<Utc>> {
    row.try_get("card_created_at").map_err(db_err)
}

fn candidate_last_review(row: &sqlx::postgres::PgRow) -> CoreResult<Option<DateTime<Utc>>> {
    row.try_get("last_review").map_err(db_err)
}

fn candidate_card(row: &sqlx::postgres::PgRow) -> CoreResult<Card> {
    serde_json::from_value(row.try_get("body").map_err(db_err)?)
        .map_err(|error| CoreError::internal(format!("json error: {error}")))
}

fn candidate_ids_sql() -> &'static str {
    "SELECT value FROM jsonb_array_elements_text("
}

fn candidate_memory(row: &sqlx::postgres::PgRow) -> CoreResult<MemoryState> {
    Ok(row_to_memory(row))
}

#[cfg(any(test, feature = "test-support"))]
candidate_measurement_support!(PostgresRepository, sqlx::Postgres, crate::candidate_test_support::populate_postgres);

#[cfg(any(test, feature = "test-support"))]
candidate_plan_support!(PostgresRepository, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ", "SELECT version()");

#[cfg(any(test, feature = "test-support"))]
fn candidate_plan_row(row: &sqlx::postgres::PgRow) -> String {
    serde_json::to_string_pretty(&row.get::<serde_json::Value, _>(0)).unwrap()
}
crate::erasure::erasure_impl!(
    PostgresRepository,
    sqlx::Postgres,
    sqlx::postgres::PgRow,
    "SELECT id FROM account_erasure_jobs WHERE partition_id=$1 AND body::jsonb->>'purge_assets'='true' ORDER BY id LIMIT 1"
);

crate::imports::imports_impl!(PostgresRepository, sqlx::Postgres, sqlx::postgres::PgRow, |d: &chrono::DateTime<
    chrono::Utc,
>| *d);
crate::retention::retention_impl!(PostgresRepository, sqlx::Postgres, "expires_at<=$2");
crate::restore_suppression::restore_suppression_impl!(PostgresRepository, sqlx::Postgres);
crate::privacy::privacy_impl!(PostgresRepository, sqlx::Postgres);

crate::explanations::explanations_impl!(PostgresRepository, sqlx::Postgres, sqlx::postgres::PgRow);
crate::password_lifecycle::password_lifecycle_impl!(PostgresRepository, sqlx::Postgres);
crate::diagnostics::diagnostics_impl!(PostgresRepository, sqlx::Postgres);
crate::content_lifecycle::content_lifecycle_impl!(PostgresRepository, sqlx::Postgres);
crate::maintenance::maintenance_impl!(PostgresRepository, sqlx::Postgres);

crate::operational_metrics::operational_impl!(
    PostgresRepository,
    "CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000 AS BIGINT)",
    "CAST(EXTRACT(EPOCH FROM expires_at)*1000 AS BIGINT)"
);

crate::access::access_impl!(PostgresRepository, sqlx::Postgres);

#[cfg(test)]
mod access_tests {
    use super::*;
    use memoswish_core::{oauth::OAuthIndex, session::SessionRepo};
    crate::access_conformance::bulk_test!(PostgresRepository, sqlx::Postgres);
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_account_access_inventory() {
        crate::pg_test_support::run_pg_test(|owner| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let fixture = owner.fixture(&url).await;
            let repo = fixture.repository(2).await.unwrap();
            let (revoked, other, token, grant) = crate::access_conformance::run(&repo).await;
            access_bulk_pages(&repo).await;
            repo.pool.close().await;
            let repo = fixture.repository(2).await.unwrap();
            assert!(repo.session_access(&revoked.access_hash).await.is_err());
            assert!(repo.session_access(&other.access_hash).await.is_ok());
            assert!(repo.find_api_token(&token).await.unwrap().unwrap().revoked);
            assert!(repo.oauth_token(&grant).await.unwrap().is_none());
            repo.pool.close().await;
            fixture.cleanup().await;
        });
    }
}
crate::library::library_impl!(
    PostgresRepository,
    sqlx::Postgres,
    crate::library::visible_sql(true),
    "strpos",
    |row: &sqlx::postgres::PgRow| -> CoreResult<DateTime<Utc>> { Ok(row.get("received_at")) },
    "to_char(h.received_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US')"
);

crate::learning_controls::learning_controls_impl!(PostgresRepository, sqlx::Postgres);
