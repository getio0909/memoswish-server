//! 只读内存数据库与固定旧版模式查询。

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

use memoswish_core::{CoreError, CoreResult};
use serde::Deserialize;
use sqlx::sqlite::{SqliteConnectOptions, SqliteOwnedBuf};
use sqlx::{Connection, Row, SqliteConnection};

use super::archive::MODERN;
use super::{ApkgLimits, invalid};

#[derive(Debug, Deserialize)]
pub struct Field {
    pub name: String,
    pub ord: usize,
}
#[derive(Debug, Deserialize)]
pub struct Template {
    pub ord: u32,
    pub qfmt: String,
    pub afmt: String,
}
#[derive(Debug, Deserialize)]
pub struct Model {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: u8,
    pub flds: Vec<Field>,
    pub tmpls: Vec<Template>,
}
#[derive(Debug, Deserialize)]
pub struct SourceDeck {
    pub name: String,
}
pub struct Note {
    pub id: i64,
    pub mid: i64,
    pub guid: String,
    pub tags: String,
    pub fields: Vec<String>,
}
pub struct SourceCard {
    pub id: i64,
    pub nid: i64,
    pub did: i64,
    pub odid: i64,
    pub ord: u32,
}
pub struct Collection {
    pub models: BTreeMap<String, Model>,
    pub decks: BTreeMap<String, SourceDeck>,
    pub notes: BTreeMap<i64, Note>,
    pub cards: Vec<SourceCard>,
}

pub(super) async fn open_read_only(bytes: &[u8]) -> CoreResult<SqliteConnection> {
    if !bytes.starts_with(b"SQLite format 3\0") || bytes.len() < 100 {
        return Err(CoreError::invalid("collection is not a SQLite database"));
    }
    if bytes[18] != 1 || bytes[19] != 1 {
        return Err(CoreError::invalid("WAL collections are unsupported; re-export with Support older Anki versions"));
    }
    // 只在进程私有内存中读取选定集合，不落盘，因此不存在可被攻击者配对的旁路文件。
    // 连接与反序列化均只读，禁止共享缓存和 WAL；不可变输入由连接独占持有。
    let opts = SqliteConnectOptions::new()
        .in_memory(true)
        .shared_cache(false)
        .read_only(true)
        .immutable(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Memory)
        .pragma("trusted_schema", "OFF")
        .pragma("query_only", "ON")
        .pragma("temp_store", "MEMORY")
        .pragma("cache_size", "-2048");
    let mut conn = SqliteConnection::connect_with(&opts).await.map_err(CoreError::internal)?;
    conn.deserialize(None, SqliteOwnedBuf::try_from(bytes).map_err(invalid)?, true).await.map_err(invalid)?;
    Ok(conn)
}

#[cfg(test)]
pub async fn read(bytes: &[u8]) -> CoreResult<Collection> {
    read_budget(bytes, crate::processing::WorkBudget::default()).await
}

pub async fn read_budget(bytes: &[u8], budget: crate::processing::WorkBudget) -> CoreResult<Collection> {
    budget.charge(0)?;
    let mut conn = open_read_only(bytes).await?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut ticks = 0u32;
    let sql_budget = budget.clone();
    conn.lock_handle().await.map_err(invalid)?.set_progress_handler(1000, move || {
        ticks += 1;
        ticks <= 100_000 && Instant::now() < deadline && sql_budget.charge(1000).is_ok()
    });
    // 直接 PRAGMA 不会被同名用户表遮蔽，必须在读取任何集合值之前验证真实表。
    let tables = sqlx::query("PRAGMA main.table_list").fetch_all(&mut conn).await.map_err(invalid)?;
    for table in ["col", "notes", "cards"] {
        let row = tables
            .iter()
            .find(|row| {
                row.get::<String, _>("schema") == "main" && row.get::<String, _>("name").eq_ignore_ascii_case(table)
            })
            .ok_or_else(|| CoreError::invalid(MODERN))?;
        let kind: String = row.try_get("type").map_err(invalid)?;
        if kind != "table" {
            return Err(CoreError::invalid("collection requires ordinary col, notes and cards tables"));
        }
        let inspect = match table {
            "col" => "PRAGMA main.table_xinfo(col)",
            "notes" => "PRAGMA main.table_xinfo(notes)",
            _ => "PRAGMA main.table_xinfo(cards)",
        };
        let columns = sqlx::query(inspect).fetch_all(&mut conn).await.map_err(invalid)?;
        for column in columns {
            let hidden: i64 = column.try_get("hidden").map_err(invalid)?;
            if hidden != 0 {
                return Err(CoreError::invalid("generated or hidden collection columns are unsupported"));
            }
        }
    }
    let trigger = sqlx::query(
        "SELECT 1 FROM main.sqlite_schema WHERE type = 'trigger' AND lower(tbl_name) IN ('col', 'notes', 'cards') LIMIT 1",
    )
    .fetch_optional(&mut conn)
    .await
    .map_err(invalid)?;
    if trigger.is_some() {
        return Err(CoreError::invalid("triggers on collection tables are unsupported"));
    }
    // SQLx 0.8 没有安全的 sqlite3_limit 接口。只扫描已验证的非生成真实列，
    // 先在 SQL 内检查类型与字节长度，再把有界值交给 SQLx，避免视图表达式与超大值分配。
    let oversized = sqlx::query(
        "SELECT 1 FROM main.col NOT INDEXED WHERE typeof(models) != 'text' OR typeof(decks) != 'text'
         OR length(CAST(models AS BLOB)) + length(CAST(decks AS BLOB)) > ? LIMIT 1",
    )
    .bind(ApkgLimits::MANIFEST as i64)
    .fetch_optional(&mut conn)
    .await
    .map_err(invalid)?;
    if oversized.is_some() {
        return Err(CoreError::invalid("collection metadata must be text within 1 MiB"));
    }
    let rows = sqlx::query("SELECT models, decks FROM main.col NOT INDEXED LIMIT 2")
        .fetch_all(&mut conn)
        .await
        .map_err(invalid)?;
    if rows.len() != 1 {
        return Err(CoreError::invalid("collection must have exactly one col row"));
    }
    let models_json: String = rows[0].try_get("models").map_err(invalid)?;
    let decks_json: String = rows[0].try_get("decks").map_err(invalid)?;
    if models_json.len() + decks_json.len() > ApkgLimits::MANIFEST {
        return Err(CoreError::invalid("collection metadata exceeds 1 MiB"));
    }
    let models: BTreeMap<String, Model> = serde_json::from_str(&models_json).map_err(invalid)?;
    let decks: BTreeMap<String, SourceDeck> = serde_json::from_str(&decks_json).map_err(invalid)?;
    if models.is_empty() || models.len() > 100 || decks.len() > 500 {
        return Err(CoreError::invalid("invalid note type or deck count"));
    }
    for model in models.values() {
        let ords: HashSet<_> = model.flds.iter().map(|f| f.ord).collect();
        let names: HashSet<_> = model.flds.iter().map(|f| &f.name).collect();
        let templates: HashSet<_> = model.tmpls.iter().map(|t| t.ord).collect();
        if model.kind > 1
            || model.flds.is_empty()
            || model.flds.len() > 64
            || ords.len() != model.flds.len()
            || names.len() != model.flds.len()
            || model.flds.iter().any(|f| f.ord >= model.flds.len() || f.name.is_empty())
            || model.tmpls.is_empty()
            || model.tmpls.len() > 64
            || templates.len() != model.tmpls.len()
        {
            return Err(CoreError::invalid(format!("unsupported or malformed note type `{}`", model.name)));
        }
    }
    let oversized = sqlx::query(
        "SELECT 1 FROM main.notes NOT INDEXED WHERE typeof(id) != 'integer' OR typeof(mid) != 'integer'
         OR typeof(guid) != 'text' OR typeof(tags) != 'text' OR typeof(flds) != 'text'
         OR length(CAST(guid AS BLOB)) > ? OR length(CAST(tags AS BLOB)) > ?
         OR length(CAST(flds AS BLOB)) > ? LIMIT 1",
    )
    .bind(ApkgLimits::FIELD as i64)
    .bind(ApkgLimits::FIELD as i64)
    .bind((64 * ApkgLimits::FIELD + 63) as i64)
    .fetch_optional(&mut conn)
    .await
    .map_err(invalid)?;
    if oversized.is_some() {
        return Err(CoreError::invalid("invalid note column type or byte length"));
    }
    let rows = sqlx::query("SELECT id, mid, guid, tags, flds FROM main.notes NOT INDEXED LIMIT 501")
        .fetch_all(&mut conn)
        .await
        .map_err(invalid)?;
    if rows.len() > ApkgLimits::CARDS {
        return Err(CoreError::invalid("APKG exceeds 500 notes"));
    }
    let mut notes = BTreeMap::new();
    for row in rows {
        budget.charge(1)?;
        let id: i64 = row.try_get("id").map_err(invalid)?;
        let mid: i64 = row.try_get("mid").map_err(invalid)?;
        let flds: String = row.try_get("flds").map_err(invalid)?;
        let fields: Vec<String> = flds.split('\x1f').map(str::to_string).collect();
        let model =
            models.get(&mid.to_string()).ok_or_else(|| CoreError::invalid("note references missing note type"))?;
        if id <= 0 || mid <= 0 || fields.len() != model.flds.len() || fields.iter().any(|f| f.len() > ApkgLimits::FIELD)
        {
            return Err(CoreError::invalid("invalid note ID, field count or field size"));
        }
        let note = Note {
            id,
            mid,
            guid: row.try_get("guid").map_err(invalid)?,
            tags: row.try_get("tags").map_err(invalid)?,
            fields,
        };
        if notes.insert(id, note).is_some() {
            return Err(CoreError::invalid("duplicate note ID"));
        }
    }
    let invalid_types = sqlx::query(
        "SELECT 1 FROM main.cards NOT INDEXED WHERE typeof(id) != 'integer' OR typeof(nid) != 'integer'
         OR typeof(did) != 'integer' OR typeof(odid) != 'integer' OR typeof(ord) != 'integer' LIMIT 1",
    )
    .fetch_optional(&mut conn)
    .await
    .map_err(invalid)?;
    if invalid_types.is_some() {
        return Err(CoreError::invalid("card columns must contain integers"));
    }
    let rows = sqlx::query("SELECT id, nid, did, odid, ord FROM main.cards NOT INDEXED LIMIT 501")
        .fetch_all(&mut conn)
        .await
        .map_err(invalid)?;
    if rows.is_empty() || rows.len() > ApkgLimits::CARDS {
        return Err(CoreError::invalid("APKG must contain 1 to 500 cards"));
    }
    let mut ids = HashSet::new();
    let mut cards = Vec::new();
    for row in rows {
        budget.charge(1)?;
        let card = SourceCard {
            id: row.try_get("id").map_err(invalid)?,
            nid: row.try_get("nid").map_err(invalid)?,
            did: row.try_get("did").map_err(invalid)?,
            odid: row.try_get("odid").map_err(invalid)?,
            ord: row.try_get("ord").map_err(invalid)?,
        };
        if card.id <= 0 || card.did <= 0 || card.odid < 0 || !ids.insert(card.id) || !notes.contains_key(&card.nid) {
            return Err(CoreError::invalid("invalid card ID or note reference"));
        }
        cards.push(card);
    }
    Ok(Collection { models, decks, notes, cards })
}
