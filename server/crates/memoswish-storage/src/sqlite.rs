//! SQLite 实现：单机自托管默认后端。

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use memoswish_core::content::{CardMutation, check_revision, next_revision};
use memoswish_core::repo::*;
use memoswish_core::{CoreError, CoreResult, Role};
use memoswish_protocol::{BgmTrack, Card, Deck};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{ConnectOptions, Connection, Row, SqlitePool};
use std::str::FromStr;

/// SQLite 仓储。
#[derive(Clone)]
pub struct SqliteRepository {
    pub(crate) observer: std::sync::Arc<dyn memoswish_core::observability::Observer>,
    pool: SqlitePool,
    #[cfg(test)]
    pub(crate) learning_gate: Option<std::sync::Arc<crate::learning::TestGate>>,
    #[cfg(test)]
    pub(crate) content_gate: Option<std::sync::Arc<crate::learning::TestGate>>,
    #[cfg(test)]
    feed_gate: Option<std::sync::Arc<crate::learning::TestGate>>,
    #[cfg(test)]
    lifecycle_gate: Option<std::sync::Arc<crate::learning::TestGate>>,
}

// 只在 SQLite 的实际打开结果为内存库时应用此有限身份集合。
#[derive(Clone, Copy, PartialEq, Eq)]
enum MemoryIdentity {
    Private,
    NamedShared,
    MemdbShared,
}

fn db_err(e: sqlx::Error) -> CoreError {
    CoreError::internal(format!("database error: {e}"))
}

fn json_err(e: serde_json::Error) -> CoreError {
    CoreError::internal(format!("json error: {e}"))
}

fn fmt_ts(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn parse_ts(s: &str) -> CoreResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| CoreError::internal(format!("bad timestamp `{s}`: {e}")))
}

fn parse_opt_ts(s: Option<String>) -> CoreResult<Option<DateTime<Utc>>> {
    s.as_deref().map(parse_ts).transpose()
}

impl SqliteRepository {
    pub fn with_observer(mut self, observer: std::sync::Arc<dyn memoswish_core::observability::Observer>) -> Self {
        self.observer = observer;
        self
    }

    /// 连接（必要时创建）数据库并执行迁移。`url` 例如 `sqlite://data/learntok.db` 或 `sqlite::memory:`。
    pub async fn connect(url: &str) -> CoreResult<Self> {
        Self::connect_with_max_connections(url, Self::default_max_connections(url)?).await
    }

    /// 打开既有规范安装，不建库、不升级 schema。
    pub async fn open_runtime(url: &str) -> CoreResult<Self> {
        Self::open_runtime_with_max_connections(url, Self::default_max_connections(url)?).await
    }

    /// 使用已解析的 SQLx 选项决定省略值，不自行解析 URL 查询字符串。
    pub fn default_max_connections(url: &str) -> CoreResult<u32> {
        Ok(if Self::is_memory(&Self::options(url, false)?) { 1 } else { 8 })
    }

    fn is_memory(opts: &SqliteConnectOptions) -> bool {
        Self::memory_identity(opts).is_some()
    }

    // SQLx 没有公开这些字段的 getter；安全占位文件名确保序列化只暴露已解析选项。
    // 不读取原始 URL，也不把 filename 中的文本再解释为 URI 查询参数。
    fn memory_identity(opts: &SqliteConnectOptions) -> Option<MemoryIdentity> {
        let fields = opts.clone().filename("/").to_url_lossy();
        let memory = fields.query_pairs().any(|(key, value)| key == "mode" && value == "memory");
        let shared = fields.query_pairs().any(|(key, value)| key == "cache" && value == "shared");
        let immutable = fields.query_pairs().any(|(key, value)| key == "immutable" && value == "true");
        let vfs = fields.query_pairs().find(|(key, _)| key == "vfs").map(|(_, value)| value.into_owned());
        // mode=memory 和 create_if_missing 会遮住序列化的 read_only，清除副本的遮蔽位再读取。
        let access = opts.clone().filename("/").in_memory(false).create_if_missing(false).to_url_lossy();
        let read_only = access.query_pairs().any(|(key, value)| key == "mode" && value == "ro");
        let filename = opts.get_filename().to_str()?;
        if immutable || read_only {
            return None;
        }
        // 支持集只接受普通名字；嵌套 URI、查询、转义与反斜线不参与身份推断。
        let simple_name = |name: &str| {
            !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        };
        if let Some(vfs) = vfs {
            return (vfs == "memdb" && !memory && filename.strip_prefix('/').is_some_and(simple_name))
                .then_some(MemoryIdentity::MemdbShared);
        }
        if memory && simple_name(filename.strip_prefix("file:").unwrap_or(filename)) {
            return Some(if shared { MemoryIdentity::NamedShared } else { MemoryIdentity::Private });
        }
        None
    }

    /// 使用显式连接上限执行迁移。
    pub async fn connect_with_max_connections(url: &str, max: u32) -> CoreResult<Self> {
        Self::connect_options(true, Self::options(url, true)?, max).await
    }

    /// 运行期只读校验 schema，并使用相同的连接上限规则。
    pub async fn open_runtime_with_max_connections(url: &str, max: u32) -> CoreResult<Self> {
        Self::connect_options(false, Self::options(url, false)?, max).await
    }

    fn options(url: &str, migrate: bool) -> CoreResult<SqliteConnectOptions> {
        let mut opts = SqliteConnectOptions::from_str(url).map_err(db_err)?;
        // 匿名来源仅由原始输入的闭集精确匹配确认；解析后的生成名前缀不能证明来源。
        if matches!(url, "sqlite::memory:" | "sqlite://:memory:" | ":memory:") {
            // 将已确认的匿名输入标记为私有，后续 keeper 再赋予独有共享缓存身份。
            opts = opts.shared_cache(false);
        } else if opts
            .get_filename()
            .to_str()
            .is_some_and(|filename| filename.strip_prefix("file:").unwrap_or(filename).starts_with("sqlx-in-memory-"))
        {
            return Err(CoreError::invalid(
                "reserved name: the 'sqlx-in-memory-' prefix is reserved for SQLx anonymous databases; \
                 choose a different database name or use exactly sqlite::memory:, sqlite://:memory: or :memory:",
            ));
        }
        Ok(opts.create_if_missing(migrate).foreign_keys(true).journal_mode(sqlx::sqlite::SqliteJournalMode::Wal))
    }

    // 行为夹具保留 WAL、外键、多连接与正常迁移，只在关闭时 checkpoint。
    // NORMAL 仍覆盖进程重启；独立 FULL 用例保留生产配置和未关闭 WAL 的恢复路径。
    #[cfg(test)]
    pub(crate) async fn connect_test(url: &str) -> CoreResult<Self> {
        let opts = Self::options(url, true)?
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .pragma("wal_autocheckpoint", "0");
        Self::connect_options(true, opts, 8).await
    }

    async fn memory_keeper(opts: &mut SqliteConnectOptions) -> CoreResult<Option<sqlx::SqliteConnection>> {
        // 以 SQLite 的实际打开结果判定，覆盖 SQLx 未设置 in_memory 的原生 URI 与编码形式。
        // 本入口统一请求 WAL；只有内存库无法切换到 WAL，仍返回 memory。
        let mut probe = opts.connect().await.map_err(db_err)?;
        let journal: String =
            sqlx::query_scalar("PRAGMA main.journal_mode").fetch_one(&mut probe).await.map_err(db_err)?;
        if journal != "memory" {
            probe.close().await.map_err(db_err)?;
            return Ok(None);
        }
        let identity = Self::memory_identity(opts);
        // 规范具名 file: URI 与 memdb 已按原名共享；保留 probe 和原始选项。
        if identity == Some(MemoryIdentity::MemdbShared)
            || (identity == Some(MemoryIdentity::NamedShared)
                && opts.get_filename().to_string_lossy().starts_with("file:"))
        {
            return Ok(Some(probe));
        }
        match identity {
            Some(MemoryIdentity::Private) => {
                // 私有库独有命名；不让相同输入的两个仓储意外共享。
                *opts = opts.clone().filename(format!("file:memoswish-memory-{}", memoswish_core::ids::new_id()));
            }
            Some(MemoryIdentity::NamedShared) => {
                // 普通名字沿用既有稳定映射，SQLite 只有 URI 名称才能跨连接共享内存 pager。
                let filename = opts.get_filename().to_string_lossy();
                *opts =
                    opts.clone().filename(format!("file:memoswish-named-memory-{}", hex::encode(filename.as_bytes())));
            }
            _ => {
                probe.close().await.map_err(db_err)?;
                return Err(CoreError::invalid(
                    "unsupported in-memory SQLite options; supported forms: sqlite::memory:, sqlite://:memory:, \
                     sqlite:<name>?mode=memory&cache=private, sqlite:<name>?mode=memory&cache=shared \
                     (named forms also allow a file: prefix), \
                     sqlite:/<name>?vfs=memdb (optional cache=private or cache=shared); \
                     use a simple name containing only ASCII letters, digits, '.', '_' or '-'; \
                     remove immutable, read-only mode, nested URI/query text and mixed mode/VFS flags, \
                     or use a file-backed database",
                ));
            }
        }
        *opts = opts.clone().in_memory(true).shared_cache(true);
        // 在打开规范化连接后才释放探测连接，保留已经存在的显式共享库。
        let keeper = opts.connect().await.map_err(db_err)?;
        probe.close().await.map_err(db_err)?;
        Ok(Some(keeper))
    }

    async fn connect_options(migrate: bool, mut opts: SqliteConnectOptions, max: u32) -> CoreResult<Self> {
        if max == 0 {
            return Err(CoreError::invalid("db_max_connections must be positive"));
        }
        let keeper = Self::memory_keeper(&mut opts).await?;
        let pool = SqlitePoolOptions::new().max_connections(max).connect_with(opts).await.map_err(db_err)?;
        if let Some(keeper) = keeper {
            // CloseEvent 不持有池的强引用，显式 close 和最后一次 drop 都唤醒关闭任务。
            // 任务独占 keeper，不占业务连接，也不让仍存活的已关闭池副本继续保活数据库。
            let closed = pool.close_event();
            // 测试在真实关闭完成后检查销毁，避免不断打开的探测连接参与共享库保活。
            #[cfg(test)]
            let completion =
                hf13_memory_tests::KEEPER_COMPLETION.try_with(|slot| slot.borrow_mut().take()).ok().flatten();
            tokio::spawn(async move {
                closed.await;
                let _ = keeper.close().await;
                #[cfg(test)]
                if let Some(completion) = completion {
                    let _ = completion.send(());
                }
            });
        }
        if migrate {
            Self::migrate(&pool).await?;
        } else {
            let mut connection = pool.acquire().await.map_err(db_err)?;
            crate::migrations::validate_runtime(&mut *connection, &sqlx::migrate!("./migrations/sqlite")).await?;
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

    /// 测试用内存库。
    pub async fn in_memory() -> CoreResult<Self> {
        Self::connect("sqlite::memory:").await
    }

    async fn migrate(pool: &SqlitePool) -> CoreResult<()> {
        let migrator = sqlx::migrate!("./migrations/sqlite");
        let history_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations')",
        )
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

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn row_to_user(r: &sqlx::sqlite::SqliteRow) -> CoreResult<UserRecord> {
    Ok(UserRecord {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        email: r.get("email"),
        display_name: r.get("display_name"),
        password_hash: r.get("password_hash"),
        role: Role::parse(r.get::<String, _>("role").as_str())?,
        created_at: parse_ts(r.get::<String, _>("created_at").as_str())?,
    })
}

fn row_to_token(r: &sqlx::sqlite::SqliteRow) -> CoreResult<ApiTokenRecord> {
    Ok(ApiTokenRecord {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        user_id: r.get("user_id"),
        name: r.get("name"),
        token_hash: r.get("token_hash"),
        generations: memoswish_core::CredentialGenerations {
            account: r.get("account_generation"),
            membership: r.get("membership_generation"),
        },
        scopes: serde_json::from_str(r.get::<String, _>("scopes").as_str()).map_err(json_err)?,
        created_at: parse_ts(r.get::<String, _>("created_at").as_str())?,
        expires_at: parse_opt_ts(r.get("expires_at"))?,
        last_used_at: parse_opt_ts(r.get("last_used_at"))?,
        revoked: r.get::<i64, _>("revoked") != 0,
    })
}

fn row_to_deck(r: &sqlx::sqlite::SqliteRow) -> CoreResult<Deck> {
    Ok(Deck {
        revision: Some(r.get::<i64, _>("revision") as u32),
        id: r.get("id"),
        title: r.get("title"),
        description: r.get("description"),
        language: r.get("language"),
        tags: serde_json::from_str(r.get::<String, _>("tags").as_str()).map_err(json_err)?,
        card_count: r.get::<i64, _>("card_count") as u32,
        created_at: parse_ts(r.get::<String, _>("created_at").as_str())?,
    })
}

fn row_to_memory(r: &sqlx::sqlite::SqliteRow) -> CoreResult<MemoryState> {
    Ok(MemoryState {
        tenant_id: r.get("tenant_id"),
        user_id: r.get("user_id"),
        card_id: r.get("card_id"),
        stability: r.get("stability"),
        difficulty: r.get("difficulty"),
        reps: r.get::<i64, _>("reps") as u32,
        lapses: r.get::<i64, _>("lapses") as u32,
        exposures: r.get::<i64, _>("exposures") as u32,
        last_review: parse_opt_ts(r.get("last_review"))?,
        due: parse_opt_ts(r.get("due"))?,
        starred: r.get::<i64, _>("starred") != 0,
        last_rating: r.get::<Option<i64>, _>("last_rating").map(|v| v as u8),
    })
}

#[async_trait]
impl AuthRepo for SqliteRepository {
    async fn upsert_tenant(&self, t: &TenantRecord) -> CoreResult<()> {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, created_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, plan = excluded.plan",
        )
        .bind(&t.id)
        .bind(&t.name)
        .bind(&t.plan)
        .bind(fmt_ts(&t.created_at))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_tenant(&self, tenant_id: &str) -> CoreResult<Option<TenantRecord>> {
        use memoswish_core::observability::{Operation, Outcome};
        let mut observation = self.observer.start(Operation::DbRead);
        let result: CoreResult<_> = async {
            let row = sqlx::query("SELECT * FROM tenants WHERE id = ?")
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| {
                    observation.finish(crate::operational_metrics::classify(&error));
                    db_err(error)
                })?;
            row.map(|r| {
                Ok(TenantRecord {
                    id: r.get("id"),
                    name: r.get("name"),
                    plan: r.get("plan"),
                    created_at: parse_ts(r.get::<String, _>("created_at").as_str())?,
                })
            })
            .transpose()
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
        let row = sqlx::query("SELECT * FROM user_profiles WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.as_ref().map(row_to_user).transpose()
    }

    async fn find_user_by_email(&self, email: &str) -> CoreResult<Option<UserRecord>> {
        let row = sqlx::query("SELECT p.* FROM user_profiles p JOIN users u ON u.id=p.id WHERE p.email = ? ORDER BY CASE WHEN p.tenant_id=u.default_tenant_id THEN 0 ELSE 1 END,p.tenant_id LIMIT 1")
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
        let row = sqlx::query("SELECT * FROM api_tokens WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.as_ref().map(row_to_token).transpose()
    }

    async fn list_api_tokens(&self, tenant_id: &str) -> CoreResult<Vec<ApiTokenRecord>> {
        let rows = sqlx::query("SELECT * FROM api_tokens WHERE tenant_id = ? ORDER BY created_at")
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.iter().map(row_to_token).collect()
    }

    async fn revoke_api_token(&self, tenant_id: &str, token_id: &str) -> CoreResult<bool> {
        let res = sqlx::query("UPDATE api_tokens SET revoked = 1 WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() > 0)
    }

    async fn touch_api_token(&self, token_id: &str, at: DateTime<Utc>) -> CoreResult<()> {
        sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
            .bind(fmt_ts(&at))
            .bind(token_id)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn add_usage(&self, tenant_id: &str, metric: &str, period: &str, amount: i64) -> CoreResult<i64> {
        let row = sqlx::query(
            "INSERT INTO usage_counters (tenant_id, metric, period, amount) VALUES (?, ?, ?, ?)
             ON CONFLICT(tenant_id, metric, period) DO UPDATE SET amount = amount + excluded.amount
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
        let row = sqlx::query("SELECT amount FROM usage_counters WHERE tenant_id = ? AND metric = ? AND period = ?")
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
impl ContentRepo for SqliteRepository {
    async fn insert_deck(&self, tenant_id: &str, d: &Deck) -> CoreResult<()> {
        sqlx::query(
            "INSERT INTO decks (id, tenant_id, title, description, language, tags, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&d.id)
        .bind(tenant_id)
        .bind(&d.title)
        .bind(&d.description)
        .bind(&d.language)
        .bind(serde_json::to_string(&d.tags).map_err(json_err)?)
        .bind(fmt_ts(&d.created_at))
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
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db_err)?;
        sqlx::query(
            "INSERT INTO decks (id, tenant_id, title, description, language, tags, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&d.id)
        .bind(tenant_id)
        .bind(&d.title)
        .bind(&d.description)
        .bind(&d.language)
        .bind(serde_json::to_string(&d.tags).map_err(json_err)?)
        .bind(fmt_ts(&d.created_at))
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        for c in cards {
            sqlx::query(
            "INSERT INTO cards (id, tenant_id, deck_id, template, revision, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&c.id)
        .bind(tenant_id)
        .bind(&c.deck_id)
        .bind(&c.template)
        .bind(c.revision as i64)
        .bind(serde_json::to_string(c).map_err(json_err)?)
        .bind(fmt_ts(&c.created_at))
        .bind(fmt_ts(&c.updated_at))
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn get_deck(&self, tenant_id: &str, deck_id: &str) -> CoreResult<Option<Deck>> {
        let row = sqlx::query(&format!("{DECK_SELECT} WHERE d.tenant_id = ? AND d.id = ?"))
            .bind(tenant_id)
            .bind(deck_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.as_ref().map(row_to_deck).transpose()
    }

    async fn list_decks(&self, tenant_id: &str) -> CoreResult<Vec<Deck>> {
        let rows = sqlx::query(&format!("{DECK_SELECT} WHERE d.tenant_id = ? ORDER BY d.created_at"))
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.iter().map(row_to_deck).collect()
    }

    async fn delete_deck(&self, tenant_id: &str, deck_id: &str) -> CoreResult<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db_err)?;
        sqlx::query("DELETE FROM cards WHERE tenant_id = ? AND deck_id = ?")
            .bind(tenant_id)
            .bind(deck_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        let res = sqlx::query("DELETE FROM decks WHERE tenant_id = ? AND id = ?")
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
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db_err)?;
        if sqlx::query("SELECT id FROM decks WHERE tenant_id=? AND id=?")
            .bind(tenant_id)
            .bind(&c.deck_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?
            .is_none()
        {
            return Err(CoreError::NotFound(format!("deck `{}`", c.deck_id)));
        }
        sqlx::query("INSERT INTO cards (id, tenant_id, deck_id, template, revision, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&c.id).bind(tenant_id).bind(&c.deck_id).bind(&c.template)
            .bind(i64::from(c.revision)).bind(serde_json::to_string(c).map_err(json_err)?)
            .bind(fmt_ts(&c.created_at)).bind(fmt_ts(&c.updated_at)).execute(&mut *tx).await.map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn mutate_cards(&self, tenant_id: &str, changes: &[CardMutation]) -> CoreResult<Vec<Card>> {
        let mut ids = std::collections::HashSet::new();
        if changes.len() > 500 || changes.iter().any(|c| !ids.insert(c.id())) {
            return Err(CoreError::invalid("at most 500 unique card targets per call"));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db_err)?;
        let mut out = Vec::with_capacity(changes.len());
        for change in changes {
            let row = sqlx::query("SELECT body FROM cards WHERE tenant_id=? AND id=?")
                .bind(tenant_id)
                .bind(change.id())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            let current = match row {
                Some(row) => {
                    Some(serde_json::from_str::<Card>(row.get::<String, _>("body").as_str()).map_err(json_err)?)
                }
                None => None,
            };
            let deck_id = match change {
                CardMutation::Draft { draft, .. } => Some(draft.deck_id.as_str()),
                _ => current.as_ref().map(|c| c.deck_id.as_str()),
            };
            let row = sqlx::query(&format!("{DECK_SELECT} WHERE d.tenant_id=? AND d.id=?"))
                .bind(tenant_id)
                .bind(deck_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
            let deck = match row {
                Some(row) => Some(row_to_deck(&row)?),
                None => None,
            };
            let previous_revision = current.as_ref().map(|c| c.revision);
            let card = change.apply(current, deck.as_ref(), Utc::now())?;
            match previous_revision {
                None => {
                    sqlx::query("INSERT INTO cards (id, tenant_id, deck_id, template, revision, body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                        .bind(&card.id).bind(tenant_id).bind(&card.deck_id).bind(&card.template)
            .bind(i64::from(card.revision)).bind(serde_json::to_string(&card).map_err(json_err)?)
            .bind(fmt_ts(&card.created_at)).bind(fmt_ts(&card.updated_at))
                        .execute(&mut *tx).await.map_err(db_err)?;
                }
                Some(revision) => {
                    let changed = sqlx::query("UPDATE cards SET deck_id=?, template=?, revision=revision+1, body=?, updated_at=? WHERE tenant_id=? AND id=? AND revision=?")
                        .bind(&card.deck_id).bind(&card.template).bind(serde_json::to_string(&card).map_err(json_err)?)
                        .bind(fmt_ts(&card.updated_at))
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
        let row = sqlx::query("SELECT body FROM cards WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(card_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(|r| serde_json::from_str(r.get::<String, _>("body").as_str()).map_err(json_err)).transpose()
    }

    async fn list_cards(
        &self,
        tenant_id: &str,
        deck_id: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> CoreResult<Vec<Card>> {
        let rows = match deck_id {
            Some(d) => sqlx::query(
                "SELECT body FROM cards WHERE tenant_id = ? AND deck_id = ? ORDER BY created_at, id LIMIT ? OFFSET ?",
            )
            .bind(tenant_id)
            .bind(d)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await,
            None => {
                sqlx::query("SELECT body FROM cards WHERE tenant_id = ? ORDER BY created_at, id LIMIT ? OFFSET ?")
                    .bind(tenant_id)
                    .bind(limit as i64)
                    .bind(offset as i64)
                    .fetch_all(&self.pool)
                    .await
            }
        }
        .map_err(db_err)?;
        rows.iter().map(|r| serde_json::from_str(r.get::<String, _>("body").as_str()).map_err(json_err)).collect()
    }

    async fn delete_card_if_revision(
        &self,
        tenant_id: &str,
        card_id: &str,
        expected_revision: Option<u32>,
    ) -> CoreResult<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db_err)?;
        let revision: Option<i64> = sqlx::query_scalar("SELECT revision FROM cards WHERE tenant_id=? AND id=?")
            .bind(tenant_id)
            .bind(card_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        let Some(revision) = revision else {
            return Ok(false);
        };
        check_revision(expected_revision, revision as u32)?;
        let res = sqlx::query("DELETE FROM cards WHERE tenant_id=? AND id=? AND revision=?")
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
impl MediaRepo for SqliteRepository {
    async fn save_bgm(
        &self,
        tenant_id: Option<&str>,
        t: &BgmTrack,
        expected_revision: Option<u32>,
    ) -> CoreResult<BgmTrack> {
        let scope = tenant_id.unwrap_or("");
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db_err)?;

        let revision: Option<i64> = sqlx::query_scalar("SELECT revision FROM bgm_tracks WHERE tenant_id=? AND id=?")
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
        let changed = sqlx::query("INSERT INTO bgm_tracks (tenant_id,id,revision,body) VALUES (?, ?, ?, ?) ON CONFLICT (tenant_id,id) DO UPDATE SET revision=bgm_tracks.revision+1,body=excluded.body WHERE bgm_tracks.revision=?")
            .bind(scope).bind(&track.id).bind(i64::from(track.revision)).bind(serde_json::to_string(&track).map_err(json_err)?)
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
            "SELECT body FROM bgm_tracks WHERE id = ? AND (tenant_id = ? OR tenant_id = '')
             ORDER BY tenant_id DESC LIMIT 1",
        )
        .bind(track_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.map(|r| serde_json::from_str(r.get::<String, _>("body").as_str()).map_err(json_err)).transpose()
    }

    async fn list_bgm(&self, tenant_id: &str) -> CoreResult<Vec<BgmTrack>> {
        let rows = sqlx::query("SELECT body FROM bgm_tracks WHERE tenant_id = ? OR tenant_id = '' ORDER BY id")
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.iter().map(|r| serde_json::from_str(r.get::<String, _>("body").as_str()).map_err(json_err)).collect()
    }
}

#[async_trait]
impl ReviewRepo for SqliteRepository {
    async fn get_versioned_memory(
        &self,
        tenant_id: &str,
        user_id: &str,
        card_id: &str,
    ) -> CoreResult<Option<VersionedMemory>> {
        use memoswish_core::observability::{Operation, Outcome};
        let mut observation = self.observer.start(Operation::DbRead);
        let result: CoreResult<_> = async {
            let row = sqlx::query("SELECT * FROM memory_states WHERE tenant_id=? AND user_id=? AND card_id=?")
                .bind(tenant_id)
                .bind(user_id)
                .bind(card_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| {
                    observation.finish(crate::operational_metrics::classify(&error));
                    db_err(error)
                })?;
            row.map(|row| Ok(VersionedMemory { version: row.get("projection_version"), state: row_to_memory(&row)? }))
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
        let row = sqlx::query("SELECT * FROM memory_states WHERE tenant_id = ? AND user_id = ? AND card_id = ?")
            .bind(tenant_id)
            .bind(user_id)
            .bind(card_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.as_ref().map(row_to_memory).transpose()
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
        let rows = sqlx::query("SELECT m.* FROM memory_states m JOIN cards c ON c.tenant_id=m.tenant_id AND c.id=m.card_id WHERE m.tenant_id = ? AND m.user_id = ?")
            .bind(tenant_id)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.iter().map(row_to_memory).collect()
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
        let row = sqlx::query("SELECT * FROM feed_sessions WHERE tenant_id = ? AND user_id = ? AND id = ?")
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

    async fn assert_connection_pragmas(repo: &SqliteRepository, synchronous: i64, checkpoint: i64) {
        let mut held = Vec::new();
        for _ in 0..8 {
            let mut connection = repo.pool().acquire().await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>("PRAGMA synchronous").fetch_one(&mut *connection).await.unwrap(),
                synchronous
            );
            assert_eq!(
                sqlx::query_scalar::<_, String>("PRAGMA journal_mode").fetch_one(&mut *connection).await.unwrap(),
                "wal"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys").fetch_one(&mut *connection).await.unwrap(),
                1
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("PRAGMA wal_autocheckpoint").fetch_one(&mut *connection).await.unwrap(),
                checkpoint
            );
            held.push(connection);
        }
    }

    #[tokio::test]
    async fn sqlite_full_durability_and_restart() {
        const CHILD: &str = "MEMOSWISH_SQLITE_DURABILITY_CHILD";
        if let Ok(path) = crate::test_environment::var(CHILD) {
            let repo = SqliteRepository::connect(&format!("sqlite://{path}")).await.unwrap();
            assert_connection_pragmas(&repo, 2, 1000).await;
            repo.upsert_tenant(&TenantRecord {
                id: "durable".into(),
                name: "Committed before exit".into(),
                plan: "free".into(),
                created_at: Utc::now(),
            })
            .await
            .unwrap();
            // 提交后直接退出进程，不运行连接池 Drop 或关闭 checkpoint。
            std::process::exit(0);
        }
        let directory = std::env::temp_dir().join(format!("memoswish-full-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("durable.db");
        let status = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "sqlite::tests::sqlite_full_durability_and_restart", "--nocapture"])
            .env(CHILD, &path)
            .status()
            .await
            .unwrap();
        assert!(status.success(), "durability writer must commit successfully");
        assert!(std::fs::metadata(directory.join("durable.db-wal")).unwrap().len() > 32);
        let url = format!("sqlite://{}", path.display());
        let reopened = SqliteRepository::open_runtime(&url).await.unwrap();
        assert_connection_pragmas(&reopened, 2, 1000).await;
        assert_eq!(reopened.get_tenant("durable").await.unwrap().unwrap().name, "Committed before exit");
        assert_eq!(
            sqlx::query_scalar::<_, String>("PRAGMA integrity_check").fetch_one(reopened.pool()).await.unwrap(),
            "ok"
        );
        reopened.pool().close().await;
        // 测试专用设置必须覆盖后续新建的每个池连接，且不改变生产入口。
        let fixture = SqliteRepository::connect_test(&url).await.unwrap();
        assert_connection_pragmas(&fixture, 1, 0).await;
        fixture.pool().close().await;
        let production = SqliteRepository::open_runtime(&url).await.unwrap();
        assert_connection_pragmas(&production, 2, 1000).await;
        production.pool().close().await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn sqlite_durability_child_rejects_legacy_environment_before_database_creation() {
        const LEGACY: &str = "LEARNTOK_SQLITE_DURABILITY_CHILD";
        const CANONICAL: &str = "MEMOSWISH_SQLITE_DURABILITY_CHILD";
        const SENTINEL: &str = "private-durability-child-sentinel";
        let directory =
            std::env::temp_dir().join(format!("memoswish-durability-guard-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&directory).unwrap();
        let database = directory.join("durable.db");
        for value in ["", SENTINEL] {
            for coexist in [false, true] {
                let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                command
                    .args(["--exact", "sqlite::tests::sqlite_full_durability_and_restart", "--nocapture"])
                    .env("TMPDIR", &directory)
                    .env(LEGACY, value)
                    .env_remove(CANONICAL);
                if coexist {
                    command.env(CANONICAL, &database);
                }
                let output = command.output().unwrap();
                assert!(!output.status.success(), "legacy child input must fail");
                let diagnostics =
                    format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
                assert!(diagnostics.contains(LEGACY) && diagnostics.contains(CANONICAL), "{diagnostics}");
                assert!(!diagnostics.contains(SENTINEL), "legacy value must remain private");
                assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
            }
        }
        std::fs::remove_dir(directory).unwrap();
    }

    #[tokio::test]
    async fn sqlite_conformance() {
        let repo = SqliteRepository::in_memory().await.unwrap();
        crate::conformance::run(&repo).await;
    }
}

oauth_impl!(SqliteRepository);

#[cfg(test)]
mod oauth_migration_tests {
    use super::*;
    #[tokio::test]
    async fn oauth_migration_preserves_legacy_records_and_file_database_conformance() {
        let dir = std::env::temp_dir().join(format!("memoswish-oauth-migration-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let migrations = dir.join("migrations");
        std::fs::create_dir(&migrations).unwrap();
        std::fs::write(migrations.join("0001_init.sql"), include_str!("../migrations/sqlite/0001_init.sql")).unwrap();
        let url = format!("sqlite://{}", dir.join("legacy.db").display());
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::from_str(&url).unwrap().create_if_missing(true).foreign_keys(true))
            .await
            .unwrap();
        sqlx::migrate::Migrator::new(migrations.as_path()).await.unwrap().run(&pool).await.unwrap();
        sqlx::raw_sql("INSERT INTO tenants VALUES('legacy','Legacy','free','2026-11-01T00:00:00Z'); INSERT INTO users VALUES('legacy-user','legacy','legacy@example.com','Legacy','legacy-password-hash','owner','2026-11-01T00:00:00Z'); INSERT INTO api_tokens(id,tenant_id,user_id,name,token_hash,scopes,created_at) VALUES('legacy-token','legacy','legacy-user','Legacy','legacy-token-hash','[\"content:read\"]','2026-11-01T00:00:00Z');").execute(&pool).await.unwrap();
        pool.close().await;
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        assert_eq!(
            repo.get_user("legacy", "legacy-user").await.unwrap().unwrap().password_hash,
            "legacy-password-hash"
        );
        assert_eq!(repo.find_api_token("legacy-token-hash").await.unwrap().unwrap().scopes, vec!["content:read"]);
        crate::conformance::run(&repo).await;
        repo.pool.close().await;
        let reopened = SqliteRepository::connect_test(&url).await.unwrap();
        assert!(reopened.get_user("legacy", "legacy-user").await.unwrap().is_some());
        reopened.pool.close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }
}

identity_impl!(
    SqliteRepository,
    sqlx::Sqlite,
    "SELECT id FROM tenants WHERE id=$1",
    "SELECT CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)"
);

#[cfg(test)]
mod erasure_race_tests {
    use super::*;
    use memoswish_core::identity::IdentityRepo;
    use memoswish_core::ids::new_id;
    use std::sync::Arc;

    #[tokio::test]
    async fn sqlite_writer_serialization_prevents_erasure_resurrection() {
        let path = std::env::temp_dir().join(format!("memoswish-erasure-{}.db", new_id()));
        let repo = Arc::new(SqliteRepository::connect_test(&format!("sqlite://{}", path.display())).await.unwrap());
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
            role: Role::Owner,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
        // 普通数据库写事务仍串行化；网络 PUT 不再占用此事务。
        let mut write = repo.pool().begin().await.unwrap();
        sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *write).await.unwrap();
        let ready = Arc::new(tokio::sync::Barrier::new(2));
        let task = {
            let (repo, tid, uid, ready) = (repo.clone(), tid.clone(), uid.clone(), ready.clone());
            tokio::spawn(async move {
                ready.wait().await;
                repo.account_erase(&tid, &uid, true).await
            })
        };
        ready.wait().await;
        assert!(!task.is_finished());
        write.commit().await.unwrap();
        let job = task.await.unwrap().unwrap();
        assert!(repo.account_erased_tenant(&tid).await.unwrap());
        assert!(memoswish_core::erasure::ErasureRepo::erasure_work(repo.as_ref(), &job.id).await.unwrap().is_some());
        assert!(repo.add_usage(&tid, "late", "period", 1).await.is_err());
        assert!(sqlx::query("INSERT INTO feedback_events(tenant_id,user_id,event_id,session_id,card_id,body,received_at) VALUES($1,$2,'late','s','c','{}','2026-11-07T00:00:00Z')").bind(&tid).bind(&uid).execute(repo.pool()).await.is_err());
        assert!(repo.account_erasure_finish(&job.id).await.is_err());
        repo.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
}

crate::membership::membership_impl!(SqliteRepository, sqlx::Sqlite, |time: &DateTime<Utc>| fmt_ts(time));

#[cfg(test)]
mod foundation_tests {
    use super::*;
    crate::foundation_conformance::foundation_tests!(
        SqlitePool,
        SqliteRepository,
        "./migrations/sqlite",
        "UPDATE feed_sessions SET user_id='orphan' WHERE id='session';"
    );

    #[tokio::test]
    async fn sqlite_foundation_duplicate_registration_overlapping_transactions() {
        let path = std::env::temp_dir().join(format!("memoswish-registration-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        let (winner, loser) = registration_contenders(&repo).await;
        let mut first = repo.pool.begin().await.unwrap();
        let mut second = repo.pool.begin().await.unwrap();
        // 只在此连接关闭忙等待，用真实 SQLITE_BUSY 证明独立事务已争用写锁。
        sqlx::query("PRAGMA busy_timeout=0").execute(&mut *second).await.unwrap();
        SqliteRepository::insert_identity(&mut first, &winner).await.unwrap();
        let blocked = SqliteRepository::insert_identity(&mut second, &loser).await.unwrap_err();
        assert!(
            blocked.to_string().contains("(code: 5)"),
            "expected SQLITE_BUSY while winner is uncommitted: {blocked}"
        );
        // 第一事务提交后，在仍开放的第二事务重试相同注册，唯一键必须返回业务冲突。
        first.commit().await.unwrap();
        assert!(matches!(SqliteRepository::insert_identity(&mut second, &loser).await, Err(CoreError::Conflict(_))));
        second.rollback().await.unwrap();
        assert_registration_winner(&repo, &winner, &loser).await;
        assert!(sqlx::query("PRAGMA foreign_key_check").fetch_all(repo.pool()).await.unwrap().is_empty());
        repo.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn sqlite_foundation_populated_upgrade_and_reopen() {
        let path = std::env::temp_dir().join(format!("memoswish-foundation-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::from_str(&url).unwrap().create_if_missing(true).foreign_keys(true))
            .await
            .unwrap();
        populated_upgrade(&pool).await;
        let objects: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master").fetch_all(&pool).await.unwrap();
        for expected in crate::foundation_conformance::REQUIRED_SCHEMA_OBJECTS {
            assert!(objects.iter().any(|name| name == expected), "missing schema object {expected}");
        }
        assert!(objects.iter().any(|name| name == "erased_memberships_insert"));
        assert!(objects.iter().any(|name| name == "job_requester_insert"));
        assert!(sqlx::query("PRAGMA foreign_key_check").fetch_all(&pool).await.unwrap().is_empty());
        pool.close().await;
        let reopened = SqliteRepository::connect_test(&url).await.unwrap();
        assert_eq!(job_snapshot(reopened.pool()).await.len(), 5);
        assert!(sqlx::query("PRAGMA foreign_key_check").fetch_all(reopened.pool()).await.unwrap().is_empty());
        reopened.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn sqlite_foundation_rejects_unmapped_job_foreign_key() {
        let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        dependency_conflict(&pool).await;
    }

    #[tokio::test]
    async fn sqlite_foundation_rejects_invalid_legacy() {
        let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        invalid_legacy(&pool).await;
    }

    #[tokio::test]
    async fn sqlite_foundation_rejects_unknown_changed_and_dirty_histories() {
        let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        rejected_histories(&pool).await;
    }
}

#[cfg(test)]
mod atomic_feedback_tests {
    use super::*;
    crate::learning_conformance::learning_tests!(
        SqliteRepository,
        SqlitePool,
        "./migrations/sqlite",
        "CREATE TRIGGER s9_fail BEFORE INSERT ON memory_states BEGIN SELECT RAISE(ABORT, 'injected memory failure'); END;",
        "CREATE TRIGGER s9_fail AFTER UPDATE ON memory_states BEGIN SELECT RAISE(ABORT, 'injected commit failure'); END;",
        "DROP TRIGGER s9_fail;"
    );

    async fn observe_overlap(repo: &SqliteRepository) {
        // 文件库连接实际持有 RESERVED 写锁；独立连接的立即写入必须报告 BUSY。
        let mut connection = repo.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA busy_timeout=0").execute(&mut *connection).await.unwrap();
        let error = sqlx::Connection::begin_with(&mut *connection, "BEGIN IMMEDIATE").await.unwrap_err();
        assert!(crate::learning::retryable(&error));
        sqlx::query("PRAGMA busy_timeout=5000").execute(&mut *connection).await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_atomic_feedback_conformance() {
        let path = std::env::temp_dir().join(format!("memoswish-s9-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let options = SqliteConnectOptions::from_str(&url).unwrap().create_if_missing(true).foreign_keys(true);
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        atomic_feedback_upgrade(&pool).await;
        pool.close().await;
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        atomic_feedback_suite(&repo).await;
        repo.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }
}

impl SqliteRepository {
    async fn insert_api_token_bound(&self, t: &ApiTokenRecord, require_management: bool) -> CoreResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_err)?;
        let role = Self::authorize_tx(&mut tx, &t.tenant_id, &t.user_id, t.generations).await?;
        if require_management && !role.allows(memoswish_core::Permission::TokenManage) {
            return Err(CoreError::Forbidden("token management requires current permission".into()));
        }
        sqlx::query(
            "INSERT INTO api_tokens (id, tenant_id, user_id, name, token_hash, scopes, created_at, expires_at, last_used_at, revoked, account_generation, membership_generation)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&t.id)
        .bind(&t.tenant_id)
        .bind(&t.user_id)
        .bind(&t.name)
        .bind(&t.token_hash)
        .bind(serde_json::to_string(&t.scopes).map_err(json_err)?)
        .bind(fmt_ts(&t.created_at))
        .bind(t.expires_at.as_ref().map(fmt_ts))
        .bind(t.last_used_at.as_ref().map(fmt_ts))
        .bind(t.revoked as i64)
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
    crate::membership_conformance::membership_tests!(SqliteRepository, SqlitePool, "./migrations/sqlite");
    async fn observe_membership_wait(repo: &SqliteRepository) {
        let mut conn = repo.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA busy_timeout=0").execute(&mut *conn).await.unwrap();
        assert!(sqlx::Connection::begin_with(&mut *conn, "BEGIN IMMEDIATE").await.is_err());
        sqlx::query("PRAGMA busy_timeout=5000").execute(&mut *conn).await.unwrap();
    }
    #[tokio::test]
    async fn sqlite_membership_generations_and_upgrade() {
        let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        membership_upgrade(&pool).await;
        pool.close().await;
        let path = std::env::temp_dir().join(format!("memoswish-s4-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        membership_suite(&repo).await;
        membership_issuance_races(&repo).await;
        membership_identity_races(&repo).await;
        zero_account_cleanup_responsibility(&repo).await;
        let history: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM membership_generations").fetch_one(repo.pool()).await.unwrap();
        let user = persistent_member_setup(&repo).await;
        repo.pool().close().await;
        let restarted = SqliteRepository::connect_test(&url).await.unwrap();
        let persisted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM membership_generations")
            .fetch_one(restarted.pool())
            .await
            .unwrap();
        assert_eq!(persisted, history + 1);
        persistent_member_resume(&restarted, &user).await;
        restarted.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod content_cas_tests {
    use super::*;
    crate::content_conformance::content_tests!(
        SqliteRepository,
        SqlitePool,
        "./migrations/sqlite",
        "CREATE TRIGGER s13_fail BEFORE UPDATE ON cards WHEN json_extract(NEW.body,'$.front.title')='SQL_FAIL' BEGIN SELECT RAISE(ABORT, 'injected card failure'); END;",
        "DROP TRIGGER s13_fail;",
        crate::ownership::sqlite_report
    );

    #[tokio::test]
    async fn sqlite_content_ownership_upgrade_and_retention() {
        let path = std::env::temp_dir().join(format!("memoswish-s14-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let options = SqliteConnectOptions::from_str(&url).unwrap().create_if_missing(true).foreign_keys(true);
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        s14_upgrade(&pool).await;
        pool.close().await;
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        s14_ownership_and_retention(&repo).await;
        s14_delete_rollback_and_orderings(&repo).await;
        s14_content_write_and_erasure(&repo).await;
        let report = crate::ownership::content_orphan_report(&url).await.unwrap();
        assert_eq!(report.iter().find(|r| r.category == "cards_missing_owned_deck").unwrap().row_count, 0);
        repo.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }

    async fn s13_observe_content_wait(repo: &SqliteRepository) {
        let mut connection = repo.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA busy_timeout=0").execute(&mut *connection).await.unwrap();
        let error = sqlx::Connection::begin_with(&mut *connection, "BEGIN IMMEDIATE").await.unwrap_err();
        assert!(crate::learning::retryable(&error));
        sqlx::query("PRAGMA busy_timeout=5000").execute(&mut *connection).await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_content_cas_upgrade_atomicity_and_independent_connections() {
        let path = std::env::temp_dir().join(format!("memoswish-s13-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let options = SqliteConnectOptions::from_str(&url).unwrap().create_if_missing(true).foreign_keys(true);
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        s13_upgrade(&pool).await;
        pool.close().await;
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        let other = SqliteRepository::connect_test(&url).await.unwrap();
        crate::content_conformance::suite(&repo, &other).await;
        s13_sql_failure_and_overflow(&repo).await;
        s13_cancel_before_commit(&repo).await;
        s13_overlapping_transactions(&repo).await;
        other.pool.close().await;
        repo.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }
}
crate::assets::asset_impl!(
    SqliteRepository,
    sqlx::Sqlite,
    sqlx::sqlite::SqliteRow,
    "SELECT CAST((julianday('now')-2440587.5)*86400000 AS BIGINT)",
    ""
);

crate::sessions::sessions_impl!(SqliteRepository, sqlx::Sqlite, "SELECT CAST(strftime('%s','now') AS BIGINT)", fmt_ts);

#[cfg(test)]
mod opaque_session_restart_tests {
    use super::*;
    use memoswish_core::session::*;
    crate::session_conformance::upgrade_tests!(SqliteRepository, SqlitePool, "./migrations/sqlite");
    crate::session_conformance::prerequisites_tests!(
        SqliteRepository,
        SqlitePool,
        "./migrations/sqlite",
        "CREATE TRIGGER reject_fence BEFORE INSERT ON app_session_fences BEGIN SELECT RAISE(ABORT, 'injected fence failure'); END",
        "DROP TRIGGER reject_fence"
    );

    #[tokio::test]
    async fn sqlite_s21b_pending_links_recheck_logout() {
        let repo = SqliteRepository::in_memory().await.unwrap();
        s21b_pending_links_recheck_logout(&repo.pool).await;
        repo.pool.close().await;
    }

    #[tokio::test]
    async fn sqlite_s21b_atomicity_and_populated_upgrade() {
        let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        s21b_populated_upgrade(&pool).await;
        s21b_atomicity(&pool).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn sqlite_pre_s21_pending_links_are_invalidated_on_upgrade() {
        let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        pre_s21_links_upgrade(&pool).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn expired_access_refresh_and_replay_survive_restart() {
        let dir = std::env::temp_dir().join(format!("memoswish-session-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&dir).unwrap();
        let url = format!("sqlite://{}", dir.join("test.db").display());
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        let (family, credential, _, _) = crate::session_conformance::staged_link(&repo).await;
        sqlx::query("UPDATE app_session_credentials SET expires_at=0 WHERE access_hash=$1")
            .bind(&credential.access_hash)
            .execute(&repo.pool)
            .await
            .unwrap();
        assert!(repo.session_access(&credential.access_hash).await.is_err());
        let next = repo
            .session_rotate(&credential.refresh_hash, "next-access", "next-refresh", "next-assurance", 600)
            .await
            .unwrap();
        repo.pool.close().await;
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        assert!(repo.session_access(&next.credential.access_hash).await.is_ok());
        assert!(
            repo.session_rotate(&credential.refresh_hash, "lost-access", "lost-refresh", "lost-assurance", 600)
                .await
                .is_err()
        );
        repo.pool.close().await;
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        assert!(repo.session_access(&next.credential.access_hash).await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT revoked FROM app_sessions WHERE id=$1")
                .bind(&family.id)
                .fetch_one(&repo.pool)
                .await
                .unwrap(),
            1
        );
        let (f, mut c) = crate::session_conformance::setup(&repo).await;
        c.tenant_id = None;
        c.membership_generation = None;
        repo.session_issue(&f, &c, None).await.unwrap();
        repo.session_revoke_all(&c.access_hash).await.unwrap();
        repo.pool.close().await;
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        assert!(repo.session_access(&c.access_hash).await.is_err());
        assert!(repo.legacy_session_authorize(&f.user_id, 0, 0, None, None).await.is_err());
        repo.pool.close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }
}

impl SqliteRepository {
    fn feed_session_row(r: &sqlx::sqlite::SqliteRow) -> CoreResult<FeedSession> {
        Ok(FeedSession {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            user_id: r.get("user_id"),
            next_slot: r.get::<i64, _>("next_slot") as u64,
            recent_card_ids: serde_json::from_str(&r.get::<String, _>("recent_card_ids")).map_err(json_err)?,
            created_at: parse_ts(&r.get::<String, _>("created_at"))?,
            updated_at: parse_ts(&r.get::<String, _>("updated_at"))?,
        })
    }
}
crate::feed_issuance::feed_issuance_impl!(
    SqliteRepository,
    sqlx::Sqlite,
    sqlx::sqlite::SqliteRow,
    "BEGIN IMMEDIATE",
    "SELECT CAST((julianday('now')-2440587.5)*86400000 AS BIGINT)",
    "",
    "",
    |ids: &Vec<String>| -> CoreResult<String> { serde_json::to_string(ids).map_err(CoreError::internal) },
    fmt_ts,
    Self::feed_session_row
);

#[cfg(test)]
mod feed_issuance_tests {
    use super::*;
    crate::feed_issuance_conformance::backend_tests!(
        SqliteRepository,
        SqlitePool,
        "./migrations/sqlite",
        "CREATE TRIGGER s11_fail BEFORE UPDATE OF issuance_revision ON feed_sessions BEGIN SELECT RAISE(ABORT,'injected feed failure'); END;",
        "DROP TRIGGER s11_fail;"
    );

    async fn observe_feed_overlap(repo: &SqliteRepository) {
        let mut connection = repo.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA busy_timeout=0").execute(&mut *connection).await.unwrap();
        assert!(sqlx::Connection::begin_with(&mut *connection, "BEGIN IMMEDIATE").await.is_err());
        sqlx::query("PRAGMA busy_timeout=5000").execute(&mut *connection).await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_replayable_feed_upgrade() {
        let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        feed_upgrade(&pool).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn sqlite_replayable_feed_conformance() {
        let path = std::env::temp_dir().join(format!("memoswish-s11-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        let other = SqliteRepository::connect_test(&url).await.unwrap();
        feed_backend_scenarios(&repo, &other).await;
        let p = crate::feed_issuance_conformance::seed(&repo).await;
        let req = crate::feed_issuance_conformance::first();
        let a = crate::feed_issuance_conformance::candidate(&repo, &p, &req, false).await;
        let page = crate::feed_issuance_conformance::committed(repo.feed_issuance(&p, &req, Some(&a)).await.unwrap());
        repo.pool.close().await;
        other.pool.close().await;
        let reopened = SqliteRepository::connect_test(&url).await.unwrap();
        assert_eq!(
            crate::feed_issuance_conformance::committed(reopened.feed_issuance(&p, &req, None).await.unwrap()),
            page
        );
        reopened.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }
}

crate::lifecycle::lifecycle_impl!(SqliteRepository, sqlx::Sqlite, "SELECT id FROM tenants WHERE id=$1");

impl SqliteRepository {
    async fn learning_write_tx(
        &self,
        tenant: &str,
        user: &str,
        generations: Option<memoswish_core::CredentialGenerations>,
    ) -> CoreResult<sqlx::Transaction<'_, sqlx::Sqlite>> {
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
        let body = serde_json::to_string(&rec.event).map_err(CoreError::internal)?;
        let result: Result<LearningEventOutcome, sqlx::Error> = async {
            #[cfg(test)]
            if let Some(gate) = &self.learning_gate { gate.pause(crate::learning::TestPoint::BeforeTransaction).await; }
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await?;
            if let Some(p) = principal {
                match Self::learning_principal_tx(&mut tx, p).await {
                    Ok(()) => {}
                    Err(CoreError::Unauthorized(_)) => return Ok(LearningEventOutcome::MissingScope),
                    Err(_) => return Err(sqlx::Error::Protocol("learning session validation failed".into())),
                }
            }
            if sqlx::query("SELECT 1 FROM tenants WHERE id=?").bind(&rec.tenant_id)
                .fetch_optional(&mut *tx).await?.is_none() {
                return Ok(LearningEventOutcome::MissingScope);
            }
            if sqlx::query("SELECT 1 FROM users WHERE id=?").bind(&rec.user_id)
                .fetch_optional(&mut *tx).await?.is_none() {
                return Ok(LearningEventOutcome::MissingScope);
            }
            if sqlx::query("SELECT 1 FROM tenant_memberships WHERE tenant_id=? AND user_id=?").bind(&rec.tenant_id).bind(&rec.user_id)
                .fetch_optional(&mut *tx).await?.is_none() {
                return Ok(LearningEventOutcome::MissingScope);
            }
            if let Some(g) = generations {
                let valid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships m JOIN account_auth_epochs a ON a.user_id=m.user_id WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.generation=$3 AND a.generation=$4")
                    .bind(&rec.tenant_id).bind(&rec.user_id).bind(g.membership).bind(g.account).fetch_one(&mut *tx).await?;
                if valid != 1 { return Ok(LearningEventOutcome::MissingScope); }
            }
            let inserted = sqlx::query("INSERT INTO feedback_events(tenant_id,user_id,event_id,session_id,card_id,rating,body,received_at,payload_hash)
                VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,user_id,event_id) DO NOTHING")
                .bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.event.event_id).bind(&rec.session_id)
                .bind(&rec.event.card_id).bind(rec.rating.map(i64::from)).bind(body)
                .bind(fmt_ts(&rec.received_at)).bind(&hash).execute(&mut *tx).await?;
            if inserted.rows_affected() == 0 {
                let row = sqlx::query("SELECT session_id,body,payload_hash FROM feedback_events WHERE tenant_id=? AND user_id=? AND event_id=?")
                    .bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.event.event_id).fetch_one(&mut *tx).await?;
                let stored_hash: Option<String> = row.get("payload_hash");
                let identical = match stored_hash {
                    Some(stored) => stored == hash,
                    None => row.get::<String, _>("session_id") == rec.session_id && serde_json::from_str::<memoswish_protocol::ImplicitFeedback>(&row.get::<String, _>("body")).map_err(|e| sqlx::Error::Decode(Box::new(e)))? == rec.event,
                };
                return Ok(if identical { LearningEventOutcome::Duplicate } else { LearningEventOutcome::PayloadConflict });
            }
            let card = sqlx::query("SELECT revision, publication FROM cards WHERE tenant_id=? AND id=?")
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
            let provenance = serde_json::to_string(&provenance).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
            sqlx::query("UPDATE feedback_events SET application_provenance=$1 WHERE tenant_id=$2 AND user_id=$3 AND event_id=$4")
                .bind(provenance).bind(&rec.tenant_id).bind(&rec.user_id).bind(&rec.event.event_id)
                .execute(&mut *tx).await?;
            #[cfg(test)]
            if let Some(gate) = &self.learning_gate { gate.pause(crate::learning::TestPoint::AfterInsert).await; }
            let explicit_star: Option<bool> = sqlx::query_scalar("SELECT starred FROM personal_favorites WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3").bind(&s.tenant_id).bind(&s.user_id).bind(&s.card_id).fetch_optional(&mut *tx).await?;
            let changed = sqlx::query("INSERT INTO memory_states(tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures,last_review,due,starred,last_rating,projection_version) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13 WHERE ?14 IS NULL OR EXISTS(SELECT 1 FROM memory_states WHERE tenant_id=?1 AND user_id=?2 AND card_id=?3)
                ON CONFLICT(tenant_id,user_id,card_id) DO UPDATE SET stability=CASE WHEN ?15 THEN excluded.stability ELSE memory_states.stability END,difficulty=CASE WHEN ?15 THEN excluded.difficulty ELSE memory_states.difficulty END,reps=CASE WHEN ?15 THEN excluded.reps ELSE memory_states.reps END,lapses=CASE WHEN ?15 THEN excluded.lapses ELSE memory_states.lapses END,exposures=excluded.exposures,last_review=CASE WHEN ?15 THEN excluded.last_review ELSE memory_states.last_review END,due=CASE WHEN ?15 THEN excluded.due ELSE memory_states.due END,starred=excluded.starred,last_rating=CASE WHEN ?15 THEN excluded.last_rating ELSE memory_states.last_rating END,projection_version=excluded.projection_version WHERE memory_states.projection_version=?14")
                .bind(&s.tenant_id).bind(&s.user_id).bind(&s.card_id).bind(s.stability).bind(s.difficulty)
                .bind(i64::from(s.reps)).bind(i64::from(s.lapses)).bind(i64::from(s.exposures))
                .bind(s.last_review.as_ref().map(fmt_ts)).bind(s.due.as_ref().map(fmt_ts)).bind(explicit_star.unwrap_or(s.starred)).bind(s.last_rating.map(i64::from))
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
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
             ON CONFLICT(tenant_id, user_id, card_id) DO UPDATE SET stability = excluded.stability,
               difficulty = excluded.difficulty, reps = excluded.reps, lapses = excluded.lapses,
               exposures = excluded.exposures, last_review = excluded.last_review, due = excluded.due,
               starred = excluded.starred, last_rating = excluded.last_rating, projection_version = memory_states.projection_version + 1",
        )
        .bind(&s.tenant_id)
        .bind(&s.user_id)
        .bind(&s.card_id)
        .bind(s.stability)
        .bind(s.difficulty)
        .bind(s.reps as i64)
        .bind(s.lapses as i64)
        .bind(s.exposures as i64)
        .bind(s.last_review.as_ref().map(fmt_ts))
        .bind(s.due.as_ref().map(fmt_ts))
        .bind(s.starred as i64)
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
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(&rec.tenant_id)
        .bind(&rec.user_id)
        .bind(&rec.event.event_id)
        .bind(&rec.session_id)
        .bind(&rec.event.card_id)
        .bind(rec.rating.map(|v| v as i64))
        .bind(serde_json::to_string(&rec.event).map_err(json_err)?)
        .bind(fmt_ts(&rec.received_at))
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
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(tenant_id, user_id, id) DO UPDATE SET next_slot = excluded.next_slot,
               recent_card_ids = excluded.recent_card_ids, updated_at = excluded.updated_at, expires_at_ms = excluded.expires_at_ms WHERE feed_sessions.issuance_revision=0 AND feed_sessions.first_request_id IS NULL AND feed_sessions.issuance_cursor IS NULL",
        )
        .bind(&s.id)
        .bind(&s.tenant_id)
        .bind(&s.user_id)
        .bind(s.next_slot as i64)
        .bind(serde_json::to_string(&s.recent_card_ids).map_err(json_err)?)
        .bind(fmt_ts(&s.created_at))
        .bind(fmt_ts(&s.updated_at))
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
        SqliteRepository,
        "CREATE TRIGGER s5_fault BEFORE DELETE ON tenants BEGIN SELECT RAISE(ABORT,'injected lifecycle failure'); END;",
        "DROP TRIGGER s5_fault;"
    );

    async fn s5_observe_wait(_: &SqliteRepository) {
        // 单线程运行器调度到等待中的 SQLx 调用；PostgreSQL 另查真实锁等待。
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn sqlite_lifecycle_commands() {
        let path = std::env::temp_dir().join(format!("memoswish-s5-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        lifecycle_suite(&repo).await;
        let jobs = repo.account_erasure_jobs().await.unwrap();
        assert!(!jobs.is_empty());
        repo.pool().close().await;
        let restarted = SqliteRepository::connect_test(&url).await.unwrap();
        assert_eq!(
            restarted.account_erasure_jobs().await.unwrap().iter().map(|j| &j.id).collect::<Vec<_>>(),
            jobs.iter().map(|j| &j.id).collect::<Vec<_>>()
        );
        restarted.pool().close().await;
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(test)]
mod session_prerequisite_wait_tests {
    use super::*;
    use memoswish_core::session::SessionRepo;

    #[tokio::test]
    async fn sqlite_legacy_renewal_waits_and_rechecks_original_evidence() {
        let repo = SqliteRepository::in_memory().await.unwrap();
        let (family, mut root) = crate::session_conformance::setup(&repo).await;
        let tenant = root.tenant_id.clone().unwrap();
        root.tenant_id = None;
        root.membership_generation = None;
        repo.session_issue(&family, &root, None).await.unwrap();
        for workspace in [None, Some((tenant.as_str(), 0))] {
            let mut tx = repo.pool.begin().await.unwrap();
            let now = SqliteRepository::session_lock(&mut tx).await.unwrap();
            let renewal = repo.legacy_session_authorize(&family.user_id, 0, now - 1, Some(now), workspace);
            tokio::pin!(renewal);
            // 单连接池的等待调用已经被轮询，事务持有连接直到提交。
            tokio::select! {
                biased;
                result=&mut renewal=>panic!("renewal passed the held transaction: {result:?}"),
                _=tokio::task::yield_now()=>{}
            }
            if workspace.is_none() {
                SqliteRepository::session_revoke_all_tx(&mut tx, &root.access_hash, now).await.unwrap();
            }
            tx.commit().await.unwrap();
            assert!(renewal.await.is_err());
        }
    }
}
crate::account_export::account_export_impl!(SqliteRepository, sqlx::Sqlite);

// 候选读取复用共享 SQL 形状与本后端的类型转换。
feed_candidate_repo!(SqliteRepository, sqlx::Sqlite);

// SQLx 的 SQLite worker 会逐列复制值；单列 JSON 避免为每张未学习卡复制整组 NULL。
// 数组字段顺序与下面两个私有解码结构保持一致，仍逐行流式读取完整作用域。
fn candidate_metadata_columns() -> &'static str {
    "SELECT json_array(c.id,c.created_at,COALESCE(l.suspended,0),l.buried_until_ms,COALESCE(l.last_issued_seq,0),\
     CASE WHEN m.card_id IS NULL THEN NULL ELSE json_array(\
     m.tenant_id,m.user_id,m.card_id,\
     CASE WHEN typeof(m.stability) IN ('real','integer') THEN printf('%!.26g',m.stability) END,\
     CASE WHEN typeof(m.difficulty) IN ('real','integer') THEN printf('%!.26g',m.difficulty) END,\
     m.reps,m.lapses,m.exposures,m.last_review,m.due,m.starred,m.last_rating) END) AS metadata"
}

#[derive(serde::Deserialize)]
struct SqliteFeedMetadata {
    card_id: String,
    created_at: String,
    suspended: i64,
    buried_until_ms: Option<i64>,
    last_issued_seq: i64,
    memory: Option<SqliteFeedMemory>,
}

#[derive(serde::Deserialize)]
struct SqliteFeedMemory {
    tenant_id: String,
    user_id: String,
    card_id: String,
    // 浮点以 SQLite 的 26 位往返文本传递，避免 JSON 数字格式化丢失精度。
    stability: String,
    difficulty: String,
    reps: i64,
    lapses: i64,
    exposures: i64,
    last_review: Option<String>,
    due: Option<String>,
    starred: i64,
    last_rating: Option<i64>,
}

fn candidate_metadata(row: &sqlx::sqlite::SqliteRow) -> CoreResult<FeedCardMetadata> {
    let raw: SqliteFeedMetadata =
        serde_json::from_str(row.try_get::<&str, _>("metadata").map_err(db_err)?).map_err(json_err)?;
    let memory = raw
        .memory
        .map(|memory| -> CoreResult<MemoryState> {
            Ok(MemoryState {
                tenant_id: memory.tenant_id,
                user_id: memory.user_id,
                card_id: memory.card_id,
                stability: memory.stability.parse().map_err(CoreError::internal)?,
                difficulty: memory.difficulty.parse().map_err(CoreError::internal)?,
                reps: memory.reps as u32,
                lapses: memory.lapses as u32,
                exposures: memory.exposures as u32,
                last_review: parse_opt_ts(memory.last_review)?,
                due: parse_opt_ts(memory.due)?,
                starred: memory.starred != 0,
                last_rating: memory.last_rating.map(|rating| rating as u8),
            })
        })
        .transpose()?;
    Ok(FeedCardMetadata {
        card_id: raw.card_id,
        created_at: parse_ts(&raw.created_at)?,
        suspended: raw.suspended != 0,
        buried_until_ms: raw.buried_until_ms,
        last_issued_seq: raw.last_issued_seq,
        memory,
    })
}

fn candidate_last_review(row: &sqlx::sqlite::SqliteRow) -> CoreResult<Option<DateTime<Utc>>> {
    parse_opt_ts(row.try_get("last_review").map_err(db_err)?)
}

fn candidate_card(row: &sqlx::sqlite::SqliteRow) -> CoreResult<Card> {
    serde_json::from_str(row.try_get::<String, _>("body").map_err(db_err)?.as_str()).map_err(json_err)
}

fn candidate_ids_sql() -> &'static str {
    "SELECT value FROM json_each("
}

#[cfg(any(test, feature = "test-support"))]
candidate_measurement_support!(SqliteRepository, sqlx::Sqlite, crate::candidate_test_support::populate);

#[cfg(any(test, feature = "test-support"))]
candidate_plan_support!(SqliteRepository, "EXPLAIN QUERY PLAN ", "SELECT sqlite_version()");

#[cfg(any(test, feature = "test-support"))]
fn candidate_plan_row(row: &sqlx::sqlite::SqliteRow) -> String {
    row.get::<String, _>("detail")
}
crate::erasure::erasure_impl!(
    SqliteRepository,
    sqlx::Sqlite,
    sqlx::sqlite::SqliteRow,
    "SELECT id FROM account_erasure_jobs WHERE partition_id=$1 AND json_extract(body,'$.purge_assets')=1 ORDER BY id LIMIT 1"
);

crate::imports::imports_impl!(SqliteRepository, sqlx::Sqlite, sqlx::sqlite::SqliteRow, fmt_ts);
crate::retention::retention_impl!(SqliteRepository, sqlx::Sqlite, "julianday(expires_at)<=julianday($2)");
crate::restore_suppression::restore_suppression_impl!(SqliteRepository, sqlx::Sqlite);
crate::privacy::privacy_impl!(SqliteRepository, sqlx::Sqlite);

crate::explanations::explanations_impl!(SqliteRepository, sqlx::Sqlite, sqlx::sqlite::SqliteRow);
crate::password_lifecycle::password_lifecycle_impl!(SqliteRepository, sqlx::Sqlite);
crate::diagnostics::diagnostics_impl!(SqliteRepository, sqlx::Sqlite);
crate::content_lifecycle::content_lifecycle_impl!(SqliteRepository, sqlx::Sqlite);
crate::maintenance::maintenance_impl!(SqliteRepository, sqlx::Sqlite);

crate::operational_metrics::operational_impl!(
    SqliteRepository,
    "CAST((julianday('now')-2440587.5)*86400000 AS BIGINT)",
    "CAST((julianday(expires_at)-2440587.5)*86400000 AS BIGINT)"
);

#[cfg(test)]
mod operational_pressure_tests {
    use super::*;
    use memoswish_core::{erasure::ErasureRepo, observability::*};
    use std::sync::Arc;

    #[tokio::test]
    async fn sqlite_pool_timeout_and_real_writer_lock_are_distinct_signals() {
        let path = std::env::temp_dir().join(format!("s26d-pressure-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let mut repo = SqliteRepository::connect(&url).await.unwrap();
        repo.pool.close().await;
        repo.pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(20))
            .connect(&url)
            .await
            .unwrap();
        let recording = crate::operational_conformance::Recording::default();
        repo = repo.with_observer(Arc::new(recording.clone()));
        let p = crate::asset_conformance::seed(&repo).await;
        let held = repo.pool.acquire().await.unwrap();
        assert!(repo.operational_snapshot().await.is_err());
        assert!(recording.0.lock().unwrap().contains(&(Operation::DbSample, Outcome::PoolTimeout)));
        drop(held);
        sqlx::query("PRAGMA busy_timeout=1").execute(&repo.pool).await.unwrap();
        let peer = SqliteRepository::open_runtime(&url).await.unwrap();
        let mut locked = peer.asset_tx().await.unwrap();
        let error = repo
            .register_managed_put(&p.tenant_id, "disk", &format!("tenants/{}/pending", p.tenant_id))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "asset persistence operation failed");
        assert!(recording.0.lock().unwrap().contains(&(Operation::DbWrite, Outcome::Busy)));
        sqlx::query("SELECT 1").execute(&mut *locked).await.unwrap();
        locked.rollback().await.unwrap();
        peer.pool.close().await;
        repo.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }
}

crate::access::access_impl!(SqliteRepository, sqlx::Sqlite);

#[cfg(test)]
mod access_tests {
    use super::*;
    use memoswish_core::{oauth::OAuthIndex, session::SessionRepo};
    crate::access_conformance::bulk_test!(SqliteRepository, sqlx::Sqlite);
    #[tokio::test]
    async fn sqlite_account_access_inventory() {
        let dir = std::env::temp_dir().join(format!("memoswish-access-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&dir).unwrap();
        let url = format!("sqlite://{}", dir.join("db.sqlite").display());
        let repo = SqliteRepository::connect(&url).await.unwrap();
        let (revoked, other, token, grant) = crate::access_conformance::run(&repo).await;
        access_bulk_pages(&repo).await;
        repo.pool.close().await;
        let repo = SqliteRepository::connect(&url).await.unwrap();
        assert!(repo.session_access(&revoked.access_hash).await.is_err());
        assert!(repo.session_access(&other.access_hash).await.is_ok());
        assert!(repo.find_api_token(&token).await.unwrap().unwrap().revoked);
        assert!(repo.oauth_token(&grant).await.unwrap().is_none());
        repo.pool.close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }
}
crate::library::library_impl!(
    SqliteRepository,
    sqlx::Sqlite,
    crate::library::visible_sql(false),
    "instr",
    |row: &sqlx::sqlite::SqliteRow| parse_ts(&row.get::<String, _>("received_at")),
    "CAST(h.received_at AS TEXT)"
);

crate::learning_controls::learning_controls_impl!(SqliteRepository, sqlx::Sqlite);

#[cfg(test)]
mod hf12_pool_tests {
    use super::*;
    use memoswish_core::observability::OperationalRepo;

    #[tokio::test]
    async fn hf12_sqlite_pool_limits_all_entry_points() {
        let root = std::env::temp_dir().join(format!("hf12-pool-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&root).unwrap();
        let url = format!("sqlite://{}", root.join("pool.db").display());
        for max in [2, 10] {
            let repo = SqliteRepository::connect_with_max_connections(&url, max).await.unwrap();
            assert_eq!(repo.pool_snapshot().capacity, max);
            let mut connections = vec![];
            for _ in 0..max {
                connections.push(repo.pool().acquire().await.unwrap());
            }
            assert!(repo.pool().try_acquire().is_none());
            drop(connections);
            repo.pool().close().await;
        }
        let repo = SqliteRepository::open_runtime_with_max_connections(&url, 3).await.unwrap();
        assert_eq!(repo.pool_snapshot().capacity, 3);
        repo.pool().close().await;
        let repo = crate::connect(&url, 4).await.unwrap();
        assert_eq!(repo.pool_snapshot().capacity, 4);
        drop(repo);
        let repo = crate::open_runtime(&url, 6).await.unwrap();
        assert_eq!(repo.pool_snapshot().capacity, 6);
        drop(repo);
        for migrate in [true, false] {
            let repo = crate::connect_observed(&url, 5, migrate, memoswish_core::observability::noop()).await.unwrap();
            assert_eq!(repo.pool_snapshot().capacity, 5);
            drop(repo);
        }
        assert!(matches!(SqliteRepository::connect_with_max_connections(&url, 0).await, Err(CoreError::Invalid(_))));
        assert!(matches!(
            SqliteRepository::open_runtime_with_max_connections(&url, 0).await,
            Err(CoreError::Invalid(_))
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn hf12_memory_urls_keep_one_connection() {
        for url in [
            "sqlite::memory:",
            "sqlite://:memory:",
            "sqlite:hf12-named?mode=memory&cache=private",
            "sqlite:hf12-encoded?mode=%6demory",
        ] {
            let repo = SqliteRepository::connect(url).await.unwrap();
            assert_eq!(repo.pool_snapshot().capacity, 1);
            repo.pool().close().await;
            let explicit = SqliteRepository::connect_with_max_connections(url, 10).await.unwrap();
            assert_eq!(explicit.pool_snapshot().capacity, 10);
            explicit.pool().close().await;
        }
    }
}

#[cfg(test)]
mod perf1_tests {
    use super::*;

    #[tokio::test]
    async fn sqlite_feed_metadata_matches_native_values_and_preserves_failure() {
        sqlite_feed_metadata_oracle(false).await;
    }

    #[tokio::test]
    async fn hf13_sqlite_feed_metadata_preserves_native_values_after_connection_replacement() {
        sqlite_feed_metadata_oracle(true).await;
    }

    async fn sqlite_feed_metadata_oracle(replace_connections: bool) {
        let repo = SqliteRepository::in_memory().await.unwrap();
        let version: String = sqlx::query_scalar("SELECT sqlite_version()").fetch_one(repo.pool()).await.unwrap();
        eprintln!("SQLite metadata oracle runtime: {version}");
        let p = repo.s24_measurement_fixture(64, false).await;
        let values = [
            0.0,
            -0.0,
            0.1,
            1.0000000000000002,
            f64::MIN_POSITIVE,
            f64::from_bits(1),
            f64::MAX,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];
        for index in (0..64).step_by(2) {
            repo.upsert_memory(&MemoryState {
                tenant_id: p.tenant_id.clone(),
                user_id: p.user_id.clone(),
                card_id: format!("measure-{index:06}"),
                stability: values[(index / 2) % values.len()],
                difficulty: values[(index / 2 + 3) % values.len()],
                reps: u32::MAX,
                lapses: 7,
                exposures: 19,
                last_review: Some(
                    chrono::DateTime::parse_from_rfc3339("2026-11-07T14:00:00.123456789+02:00")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
                due: None,
                starred: index % 4 == 0,
                last_rating: Some(3),
            })
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO learner_card_controls(tenant_id,user_id,card_id,suspended,buried_until_ms,last_issued_seq) VALUES($1,$2,'measure-000003',1,NULL,42),($1,$2,'measure-000005',0,1900000000123,43)")
            .bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();
        // JSON 整数必须保留有符号边界，历史计数字段继续使用原生读取的转换语义。
        for (card, value) in [("measure-000000", i64::MIN), ("measure-000002", i64::MAX)] {
            sqlx::query("UPDATE memory_states SET reps=$1,lapses=$1,exposures=$1,starred=$1,last_rating=$1 WHERE tenant_id=$2 AND user_id=$3 AND card_id=$4")
                .bind(value).bind(&p.tenant_id).bind(&p.user_id).bind(card).execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE learner_card_controls SET buried_until_ms=$1,last_issued_seq=$2 WHERE tenant_id=$3 AND user_id=$4 AND card_id='measure-000005'")
                .bind(value).bind(i64::MAX).bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();
            let mut actual = None;
            repo.visit_feed_metadata(&p.tenant_id, &p.user_id, None, &mut |row| {
                if row.card_id == "measure-000005" {
                    actual = Some((row.buried_until_ms, row.last_issued_seq));
                }
                Ok(())
            })
            .await
            .unwrap();
            let native = sqlx::query("SELECT buried_until_ms,last_issued_seq FROM learner_card_controls WHERE tenant_id=$1 AND user_id=$2 AND card_id='measure-000005'")
                .bind(&p.tenant_id).bind(&p.user_id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(actual, Some((native.get("buried_until_ms"), native.get("last_issued_seq"))));
            assert_eq!(actual, Some((Some(value), i64::MAX)));
        }
        // 池内全部连接替换后，继续执行完整原生值及损坏数据 oracle，验证保活与投影的交互。
        if replace_connections {
            repo.pool().acquire().await.unwrap().close().await.unwrap();
            assert_eq!(repo.pool().size(), 0);
        }
        // 旧的逐列读取作为独立 oracle，包含无记忆行、完整控制、浮点极值与历史时间精度。
        let native = sqlx::query("SELECT c.id AS live_card_id,c.created_at AS card_created_at,COALESCE(l.suspended,0) AS control_suspended,l.buried_until_ms,COALESCE(l.last_issued_seq,0) AS last_issued_seq,m.* FROM cards c LEFT JOIN memory_states m ON m.tenant_id=c.tenant_id AND m.card_id=c.id AND m.user_id=$1 LEFT JOIN learner_card_controls l ON l.tenant_id=c.tenant_id AND l.card_id=c.id AND l.user_id=$1 WHERE c.publication='published' AND c.tenant_id=$2 ORDER BY c.created_at,c.id")
            .bind(&p.user_id).bind(&p.tenant_id).fetch_all(repo.pool()).await.unwrap();
        let mut actual = Vec::new();
        repo.visit_feed_metadata(&p.tenant_id, &p.user_id, None, &mut |row| {
            actual.push(row);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(actual.len(), native.len());
        for (actual, native) in actual.iter().zip(&native) {
            assert_eq!(actual.card_id, native.get::<String, _>("live_card_id"));
            assert_eq!(actual.created_at, parse_ts(&native.get::<String, _>("card_created_at")).unwrap());
            assert_eq!(actual.suspended, native.get::<i64, _>("control_suspended") != 0);
            assert_eq!(actual.buried_until_ms, native.get::<Option<i64>, _>("buried_until_ms"));
            assert_eq!(actual.last_issued_seq, native.get::<i64, _>("last_issued_seq"));
            let expected = native.get::<Option<String>, _>("card_id").map(|_| row_to_memory(native).unwrap());
            assert_eq!(actual.memory, expected);
            if let (Some(actual), Some(expected)) = (&actual.memory, &expected) {
                assert_eq!(actual.stability.to_bits(), expected.stability.to_bits());
                assert_eq!(actual.difficulty.to_bits(), expected.difficulty.to_bits());
            }
        }
        let error = repo
            .visit_feed_metadata(&p.tenant_id, &p.user_id, None, &mut |_| {
                Err(CoreError::invalid("injected metadata visitor failure"))
            })
            .await
            .unwrap_err();
        assert!(matches!(error, CoreError::Invalid(_)));
        // 回调拒绝后单连接池仍可用，查询错误不能被解释为空候选。
        assert_eq!(repo.feed_summary(&p.tenant_id, &p.user_id, None).await.unwrap().total_cards, 64);
        for field in ["stability", "difficulty"] {
            // 锁定的 SQLite 将 NaN 存为 NULL；NOT NULL 必须拒绝，不能生成有效候选。
            let error = sqlx::query(&format!("UPDATE memory_states SET {field}=$1 WHERE tenant_id=$2"))
                .bind(f64::NAN)
                .bind(&p.tenant_id)
                .execute(repo.pool())
                .await
                .unwrap_err();
            assert!(
                error.as_database_error().is_some_and(|error| error.kind() == sqlx::error::ErrorKind::NotNullViolation)
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>(&format!(
                    "SELECT COUNT(*) FROM memory_states WHERE {field} IS NULL AND tenant_id=$1"
                ))
                .bind(&p.tenant_id)
                .fetch_one(repo.pool())
                .await
                .unwrap(),
                0
            );
            // printf 会将非数值文本或 BLOB 转换成零，原生与投影读取都必须拒绝损坏类型。
            for corrupt in ["'invalid-float'", "X'0001FF'"] {
                sqlx::query(&format!("UPDATE memory_states SET {field}={corrupt} WHERE tenant_id=$1"))
                    .bind(&p.tenant_id)
                    .execute(repo.pool())
                    .await
                    .unwrap();
                let native = sqlx::query(&format!("SELECT {field} FROM memory_states WHERE tenant_id=$1 LIMIT 1"))
                    .bind(&p.tenant_id)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
                assert!(native.try_get::<f64, _>(field).is_err());
                assert!(repo.visit_feed_metadata(&p.tenant_id, &p.user_id, None, &mut |_| Ok(())).await.is_err());
                sqlx::query(&format!("UPDATE memory_states SET {field}=0.1 WHERE tenant_id=$1"))
                    .bind(&p.tenant_id)
                    .execute(repo.pool())
                    .await
                    .unwrap();
            }
        }
        sqlx::query("UPDATE memory_states SET last_review='invalid-timestamp' WHERE tenant_id=$1")
            .bind(&p.tenant_id)
            .execute(repo.pool())
            .await
            .unwrap();
        assert!(repo.visit_feed_metadata(&p.tenant_id, &p.user_id, None, &mut |_| Ok(())).await.is_err());
    }
}

#[cfg(test)]
mod hf13_memory_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tokio::sync::Semaphore;

    tokio::task_local! {
        pub(super) static KEEPER_COMPLETION: std::cell::RefCell<Option<tokio::sync::oneshot::Sender<()>>>;
    }

    async fn observed_repository(
        url: &str,
        max: u32,
        migrate: bool,
    ) -> (SqliteRepository, tokio::sync::oneshot::Receiver<()>) {
        let (completed, completion) = tokio::sync::oneshot::channel();
        let repository = KEEPER_COMPLETION
            .scope(std::cell::RefCell::new(Some(completed)), async {
                if migrate {
                    SqliteRepository::connect_with_max_connections(url, max).await
                } else {
                    SqliteRepository::open_runtime_with_max_connections(url, max).await
                }
            })
            .await
            .expect(url);
        (repository, completion)
    }

    async fn close_business_connections(pool: &SqlitePool, max: u32) {
        // 明确关闭全部业务 worker，使释放断言只观察最后一个 keeper owner。
        let mut connections = Vec::new();
        for _ in 0..max {
            connections.push(pool.acquire().await.unwrap());
        }
        for connection in connections {
            connection.close().await.unwrap();
        }
        assert_eq!(pool.size(), 0);
    }

    fn memdb_urls() -> Vec<(&'static str, bool)> {
        vec![
            ("sqlite:/hf13-vfs?vfs=memdb", true),
            ("sqlite:/hf13-vfs?vfs=memdb&cache=private", true),
            ("sqlite:/hf13-vfs?vfs=memdb&cache=shared", true),
            ("sqlite:%2Fhf13-vfs?vfs=memdb", true),
        ]
    }

    // 矩阵仅覆盖明确支持的已解析字段；其余实际内存组合由拒绝回归验证。
    fn memory_urls() -> Vec<(&'static str, bool)> {
        let mut urls = vec![
            ("sqlite::memory:", false),
            ("sqlite://:memory:", false),
            (":memory:", false),
            ("sqlite:hf13-private?mode=memory&cache=private", false),
            ("sqlite:file:hf13-private?mode=memory&cache=private", false),
            ("sqlite:hf13-shared?mode=memory&cache=shared", true),
            ("sqlite:file:hf13-shared?mode=memory&cache=shared", true),
            ("sqlite:file:hf13-sqlx-in-memory-42?mode=memory&cache=shared", true),
            ("sqlite:hf13-default?mode=memory", true),
            ("sqlite:hf13-decoded?mode=%6demory&cache=shared", true),
        ];
        urls.extend(memdb_urls());
        urls
    }

    async fn assert_database_released(
        options: &SqliteConnectOptions,
        table: &str,
        completions: Vec<tokio::sync::oneshot::Receiver<()>>,
    ) {
        // 等待所有 keeper 的 worker 关闭确认后只探测一次，不让探测连接延续待销毁数据库。
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for completion in completions {
                completion.await.expect("keeper must confirm worker closure");
            }
            let mut fresh = options.connect().await.unwrap();
            let exists: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name=?")
                .bind(table)
                .fetch_one(&mut fresh)
                .await
                .unwrap();
            fresh.close().await.unwrap();
            assert_eq!(exists, 0, "closed keepers must release {table}: {:?}", options.get_filename());
        })
        .await
        .expect("closing or dropping the pool must release the memory database");
    }

    #[tokio::test]
    async fn hf13_memory_survives_all_pool_connections_being_replaced() {
        for (url, shared) in memory_urls() {
            for max in [1, 3] {
                assert_eq!(SqliteRepository::default_max_connections(url).unwrap(), 1, "{url}");
                let (repo, completed) = observed_repository(url, max, true).await;
                let journal: String =
                    sqlx::query_scalar("PRAGMA main.journal_mode").fetch_one(repo.pool()).await.unwrap();
                assert_eq!(journal, "memory", "{url}");
                sqlx::query("CREATE TABLE hf13_marker (value INTEGER NOT NULL)").execute(repo.pool()).await.unwrap();
                sqlx::query("INSERT INTO hf13_marker VALUES (42)").execute(repo.pool()).await.unwrap();
                // 同一个输入的两个仓储必须保留原有的 shared/private 身份。
                let (second, second_completed) = observed_repository(url, max, true).await;
                let exists: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name='hf13_marker'")
                    .fetch_one(second.pool())
                    .await
                    .unwrap();
                assert_eq!(exists, i64::from(shared), "{url}, max={max}");
                if shared {
                    let value: i64 =
                        sqlx::query_scalar("SELECT value FROM hf13_marker").fetch_one(second.pool()).await.unwrap();
                    assert_eq!(value, 42, "{url}, max={max}");
                } else {
                    // 同一私有输入不能借 open_runtime 访问另一个仓储的安装与数据。
                    assert!(SqliteRepository::open_runtime_with_max_connections(url, max).await.is_err(), "{url}");
                }
                close_business_connections(second.pool(), max).await;
                second.pool().close().await;
                let clone = repo.clone();
                drop(repo);
                let mut connections = Vec::new();
                for _ in 0..max {
                    connections.push(clone.pool().acquire().await.unwrap());
                }
                for connection in connections {
                    connection.close().await.unwrap();
                }
                assert_eq!(clone.pool().size(), 0);
                let value: i64 =
                    sqlx::query_scalar("SELECT value FROM hf13_marker").fetch_one(clone.pool()).await.unwrap();
                assert_eq!(value, 42);
                let _: i64 = sqlx::query_scalar("SELECT count(*) FROM cards").fetch_one(clone.pool()).await.unwrap();
                let options = clone.pool().connect_options();
                let pool = clone.pool().clone();
                drop(clone);
                pool.acquire().await.unwrap().close().await.unwrap();
                let value: i64 = sqlx::query_scalar("SELECT value FROM hf13_marker").fetch_one(&pool).await.unwrap();
                assert_eq!(value, 42, "an externally cloned pool must retain the keeper");
                let closed_clone = pool.clone();
                close_business_connections(&pool, max).await;
                pool.close().await;
                // 保留所有已关闭句柄及 second 仓储，证明无需 drop 它们也能释放 keeper。
                assert_database_released(&options, "hf13_marker", vec![completed, second_completed]).await;
                assert!(pool.is_closed());
                assert!(closed_clone.is_closed());
                assert!(second.pool().is_closed());
            }
        }
    }

    #[test]
    fn hf13_sqlx_parsed_memory_fields_are_the_classification_boundary() {
        let default = SqliteRepository::options("sqlite:hf13-default?mode=memory", true).unwrap();
        let explicit = SqliteRepository::options("sqlite:hf13-default?mode=memory&cache=shared", true).unwrap();
        assert_eq!(default.to_url_lossy(), explicit.to_url_lossy());
        assert!(matches!(SqliteRepository::memory_identity(&default), Some(MemoryIdentity::NamedShared)));
        let private = SqliteRepository::options("sqlite:hf13-default?mode=memory&cache=private", true).unwrap();
        assert!(matches!(SqliteRepository::memory_identity(&private), Some(MemoryIdentity::Private)));
    }

    #[tokio::test]
    async fn hf13_reserved_sqlx_names_are_rejected_unless_the_original_url_is_literal_anonymous() {
        for url in [
            "sqlite:file:sqlx-in-memory-hf13?mode=memory&cache=shared",
            "sqlite:file:sqlx-in-memory-42?mode=memory&cache=shared",
            "sqlite:sqlx-in-memory-hf13?mode=memory&cache=shared",
            "sqlite:sqlx-in-memory-42?mode=memory&cache=private",
            "sqlite:sqlx-in-memory-?mode=memory",
            "sqlite:file:sqlx-in-memory-%34%32?mode=memory&cache=shared",
            "sqlite:file:%73qlx-in-memory-hf13?mode=memory&cache=shared",
            "sqlite::memory:?cache=private",
            "sqlite://:memory:?cache=shared",
            ":memory:?mode=memory",
            "sqlite::memory:?immutable=true",
            "sqlite::memory:?",
            "sqlite:sqlite::memory:",
        ] {
            assert!(SqliteRepository::default_max_connections(url).is_err(), "{url}");
            for max in [1, 3] {
                for migrate in [true, false] {
                    let result = if migrate {
                        SqliteRepository::connect_with_max_connections(url, max).await
                    } else {
                        SqliteRepository::open_runtime_with_max_connections(url, max).await
                    };
                    let error = result.err().unwrap_or_else(|| panic!("reserved name accepted: {url}"));
                    assert!(matches!(error, CoreError::Invalid(_)), "{url}: {error}");
                    let message = error.to_string();
                    for guidance in ["reserved name", "sqlx-in-memory-", "choose a different database name", ":memory:"]
                    {
                        assert!(message.contains(guidance), "actionable reserved-name guidance missing: {message}");
                    }
                    assert!(!message.contains(url), "reserved-name error must not echo the input URL");
                }
            }
        }
    }

    #[tokio::test]
    async fn hf13_unsupported_memory_options_are_rejected_before_migration_or_runtime_validation() {
        for url in [
            "sqlite:hf13-immutable?mode=memory&cache=shared&immutable=true",
            "sqlite:file:/hf13-immutable%3Fvfs=memdb%26cache=shared?mode=memory&cache=private&immutable=true",
            "sqlite:file:hf13-immutable-plain%3Fcache=shared?mode=memory&cache=private&immutable=true",
            "sqlite:hf13-readonly?mode=ro&mode=memory&cache=shared",
            "sqlite:/hf13-readonly-vfs?vfs=memdb&mode=ro",
            "sqlite:hf13-other-vfs?mode=memory&vfs=unix",
            "sqlite:/hf13-mixed?vfs=memdb&mode=memory&cache=shared",
            "sqlite:/hf13-mixed?vfs=memdb&mode=memory&cache=private",
            "sqlite:hf13-relative?vfs=memdb",
            "sqlite:%5Chf13-backslash?vfs=memdb",
            "sqlite:/hf13-memdb?vfs=memdb&immutable=true",
            "sqlite:file:/hf13-native%3Fvfs=memdb",
            "sqlite:file:hf13-native%3Fmode=memory%26cache=shared",
            "sqlite:file:hf13-native%3Fmode=memory%26cache=private",
            "sqlite:file::memory:",
            "sqlite:file:%253Amemory%253A?cache=shared",
            "sqlite:hf13%3Fcache=shared?mode=memory&cache=private",
            "sqlite://?mode=memory&cache=shared",
        ] {
            let mut native = SqliteRepository::options(url, true).unwrap().connect().await.unwrap();
            let journal: String = sqlx::query_scalar("PRAGMA main.journal_mode").fetch_one(&mut native).await.unwrap();
            assert_eq!(journal, "memory", "rejection fixture must actually open as memory: {url}");
            native.close().await.unwrap();
            for max in [1, 3] {
                for migrate in [true, false] {
                    let result = if migrate {
                        SqliteRepository::connect_with_max_connections(url, max).await
                    } else {
                        SqliteRepository::open_runtime_with_max_connections(url, max).await
                    };
                    let error = result.err().unwrap_or_else(|| panic!("unsupported memory options accepted: {url}"));
                    assert!(matches!(error, CoreError::Invalid(_)), "{url}: {error}");
                    let message = error.to_string();
                    for form in
                        ["sqlite::memory:", "mode=memory&cache=private", "mode=memory&cache=shared", "vfs=memdb"]
                    {
                        assert!(message.contains(form), "actionable supported form missing: {message}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn hf13_file_paths_remain_file_backed_without_keeper() {
        for url in ["sqlite:./:memory:", "sqlite:file:./:memory:", "sqlite:file:sqlite::memory:"] {
            assert_eq!(SqliteRepository::default_max_connections(url).unwrap(), 8, "{url}");
        }
        let root = std::env::temp_dir().join(memoswish_core::ids::new_id());
        std::fs::create_dir(&root).unwrap();
        let path = root.join(":memory:");
        for url in [
            format!("sqlite://{}", path.display()),
            format!(concat!("sqlite:file:", "//localhost{}"), path.display()),
            format!("sqlite:file:{}%3Fmode=rw?mode=memory", path.display()),
        ] {
            assert_eq!(SqliteRepository::default_max_connections(&url).unwrap(), 8);
            let mut options = SqliteRepository::options(&url, true).unwrap();
            assert!(SqliteRepository::memory_keeper(&mut options).await.unwrap().is_none());
            let repo = SqliteRepository::connect(&url).await.unwrap();
            let journal: String = sqlx::query_scalar("PRAGMA main.journal_mode").fetch_one(repo.pool()).await.unwrap();
            assert_eq!(journal, "wal");
            repo.pool().close().await;
            assert!(path.exists());
        }
        // 同一个既有文件的 immutable/VFS 选项不受内存支持集限制。
        for suffix in ["immutable=true", "vfs=unix", "immutable=true&vfs=unix", "mode=ro"] {
            let url = format!("sqlite://{}?{suffix}", path.display());
            assert_eq!(SqliteRepository::default_max_connections(&url).unwrap(), 8);
            let mut options = SqliteRepository::options(&url, false).unwrap();
            assert!(SqliteRepository::memory_keeper(&mut options).await.unwrap().is_none(), "{suffix}");
            let repo = SqliteRepository::open_runtime(&url).await.unwrap();
            let _: i64 = sqlx::query_scalar("SELECT count(*) FROM cards").fetch_one(repo.pool()).await.unwrap();
            repo.pool().close().await;
            assert!(path.exists());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn hf13_last_pool_drop_releases_keeper_without_explicit_close() {
        for ((url, _), max) in memory_urls().into_iter().flat_map(|url| [1, 3].map(|max| (url, max))) {
            let url = url.replace("hf13-", "hf13-drop-");
            let (repo, completed) = observed_repository(&url, max, true).await;
            sqlx::query("CREATE TABLE hf13_drop (value INTEGER)").execute(repo.pool()).await.unwrap();
            let options = repo.pool().connect_options();
            let external = repo.pool().clone();
            drop(repo);
            let mut connections = Vec::new();
            for _ in 0..max {
                connections.push(external.acquire().await.unwrap());
            }
            for connection in connections {
                connection.close().await.unwrap();
            }
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM hf13_drop").fetch_one(&external).await.unwrap();
            assert_eq!(count, 0);
            close_business_connections(&external, max).await;
            drop(external);
            assert_database_released(&options, "hf13_drop", vec![completed]).await;
        }
    }

    #[tokio::test]
    async fn hf13_anonymous_and_private_memory_repositories_are_isolated() {
        for url in ["sqlite::memory:", "sqlite:hf13-isolation?mode=memory&cache=private"] {
            let first = SqliteRepository::connect(url).await.unwrap();
            let second = SqliteRepository::connect(url).await.unwrap();
            sqlx::query("CREATE TABLE hf13_private (value INTEGER)").execute(first.pool()).await.unwrap();
            let exists: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name='hf13_private'")
                .fetch_one(second.pool())
                .await
                .unwrap();
            assert_eq!(exists, 0);
        }
    }

    #[tokio::test]
    async fn hf13_supported_shared_memory_runtime_keeps_existing_database() {
        for (url, _) in memory_urls().into_iter().filter(|(_, shared)| *shared) {
            for max in [1, 3] {
                let url = url.replace("hf13-", "hf13-runtime-shared-");
                let (migrated, migrated_completed) = observed_repository(&url, max, true).await;
                sqlx::query("CREATE TABLE hf13_shared (value INTEGER)").execute(migrated.pool()).await.unwrap();
                sqlx::query("INSERT INTO hf13_shared VALUES (42)").execute(migrated.pool()).await.unwrap();
                let identity = migrated.pool().connect_options();
                let (runtime, runtime_completed) = observed_repository(&url, max, false).await;
                assert_eq!(runtime.pool().connect_options().get_filename(), identity.get_filename(), "{url}");
                close_business_connections(migrated.pool(), max).await;
                migrated.pool().close().await;
                close_business_connections(runtime.pool(), max).await;
                let value: i64 =
                    sqlx::query_scalar("SELECT value FROM hf13_shared").fetch_one(runtime.pool()).await.unwrap();
                assert_eq!(value, 42, "{url}, max={max}");
                let _: i64 = sqlx::query_scalar("SELECT count(*) FROM cards").fetch_one(runtime.pool()).await.unwrap();
                close_business_connections(runtime.pool(), max).await;
                runtime.pool().close().await;
                assert_database_released(&identity, "hf13_shared", vec![migrated_completed, runtime_completed]).await;
            }
        }
    }

    #[tokio::test]
    async fn hf13_shared_uri_and_memdb_runtime_preserve_exact_native_identity() {
        let mut urls = memdb_urls();
        urls.push(("sqlite:file:hf13-native-shared?mode=memory&cache=shared", true));
        urls.push(("sqlite:file:hf13-sqlx-in-memory-42?mode=memory&cache=shared", true));
        for (url, _) in urls {
            let url = url.replace("hf13-", "hf13-runtime-");
            for max in [1, 3] {
                let original = SqliteRepository::options(&url, true).unwrap();
                let mut native = original.connect().await.unwrap();
                sqlx::query("CREATE TABLE hf13_native_identity (value INTEGER)").execute(&mut native).await.unwrap();
                sqlx::query("INSERT INTO hf13_native_identity VALUES (42)").execute(&mut native).await.unwrap();
                let (migrated, migrated_completed) = observed_repository(&url, max, true).await;
                let (runtime, runtime_completed) = observed_repository(&url, max, false).await;
                assert_eq!(runtime.pool().connect_options().get_filename(), original.get_filename(), "{url}");
                close_business_connections(migrated.pool(), max).await;
                migrated.pool().close().await;
                native.close().await.unwrap();
                let mut connections = Vec::new();
                for _ in 0..max {
                    connections.push(runtime.pool().acquire().await.unwrap());
                }
                for connection in connections {
                    connection.close().await.unwrap();
                }
                assert_eq!(runtime.pool().size(), 0);
                let value: i64 = sqlx::query_scalar("SELECT value FROM hf13_native_identity")
                    .fetch_one(runtime.pool())
                    .await
                    .expect(&url);
                assert_eq!(value, 42, "{url}, max={max}");
                let _: i64 = sqlx::query_scalar("SELECT count(*) FROM cards").fetch_one(runtime.pool()).await.unwrap();
                close_business_connections(runtime.pool(), max).await;
                runtime.pool().close().await;
                assert_database_released(
                    &original,
                    "hf13_native_identity",
                    vec![migrated_completed, runtime_completed],
                )
                .await;
            }
        }
    }

    #[tokio::test]
    async fn hf13_cancelled_acquire_loses_unkept_database_but_preserves_kept_database() {
        for protected in [false, true] {
            let mut options = SqliteRepository::options("sqlite::memory:", true).unwrap();
            let keeper = if protected { SqliteRepository::memory_keeper(&mut options).await.unwrap() } else { None };
            let armed = Arc::new(AtomicBool::new(false));
            let entered = Arc::new(Semaphore::new(0));
            let opened = Arc::new(AtomicUsize::new(0));
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .after_connect({
                    let opened = opened.clone();
                    move |_, _| {
                        opened.fetch_add(1, Ordering::SeqCst);
                        Box::pin(async { Ok(()) })
                    }
                })
                .before_acquire({
                    let armed = armed.clone();
                    let entered = entered.clone();
                    move |_, _| {
                        let block = armed.swap(false, Ordering::SeqCst);
                        let entered = entered.clone();
                        Box::pin(async move {
                            if block {
                                entered.add_permits(1);
                                std::future::pending::<()>().await;
                            }
                            Ok(true)
                        })
                    }
                })
                .connect_with(options)
                .await
                .unwrap();
            let mut connection = pool.acquire().await.unwrap();
            sqlx::query("CREATE TABLE hf13_cancel (value INTEGER)").execute(&mut *connection).await.unwrap();
            // 显式等待归还，保证取消发生于借出的连接检查，而不是等待空闲队列。
            connection.return_to_pool().await;
            armed.store(true, Ordering::SeqCst);
            let waiter = tokio::spawn(pool.acquire());
            entered.acquire().await.unwrap().forget();
            waiter.abort();
            assert!(waiter.await.unwrap_err().is_cancelled());
            let exists: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name='hf13_cancel'")
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(opened.load(Ordering::SeqCst), 2);
            assert_eq!(exists, i64::from(protected));
            pool.close().await;
            drop(keeper);
        }
    }
}
