//! 发页事务的双后端实现；复用注册锁、数据库时钟与 S9 冲突分类。

use memoswish_core::repo::{FeedIssuanceCandidate, FeedIssuanceRequest};
use memoswish_core::{CoreError, CoreResult};

// 会话生命周期的唯一保留期；重放也是活动，过期后不能续期。
pub(crate) const SESSION_LIFETIME_MS: i64 = 24 * 60 * 60 * 1000;

pub(crate) fn db_error(error: sqlx::Error) -> CoreError {
    if crate::learning::retryable(&error) || matches!(error, sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut) {
        CoreError::FeedRetry(database_retry_cause(&error))
    } else {
        CoreError::internal("feed persistence operation failed")
    }
}

// 只读取驱动返回的结构化代码；SQLite 扩展码的低八位为基础错误码。
fn database_retry_cause(error: &sqlx::Error) -> memoswish_core::observability::FeedRetryCause {
    use memoswish_core::observability::FeedRetryCause;
    let busy = error
        .as_database_error()
        .and_then(|e| e.code())
        .and_then(|c| c.parse::<u32>().ok())
        .is_some_and(|code| matches!(code & 255, 5 | 6));
    if busy { FeedRetryCause::DatabaseBusyLocked } else { FeedRetryCause::Other }
}

pub(crate) fn validate_request(request: &FeedIssuanceRequest) -> CoreResult<()> {
    let q = &request.query;
    if q.session_id.as_deref() == Some("preview:non-learning") {
        return Err(CoreError::invalid("preview cannot continue a learner feed"));
    }
    if q.request_id.is_some() && (q.session_id.is_some() || q.cursor.is_some()) {
        return Err(CoreError::invalid("request_id is only valid for a first page"));
    }
    if let Some(id) = &q.request_id
        && (id.is_empty() || id.len() > 128 || !id.bytes().all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)))
    {
        return Err(CoreError::invalid("invalid feed request identity"));
    }
    if q.cursor.as_ref().is_some_and(|c| c.is_empty() || c.len() > 160)
        || (q.cursor.is_some() && q.session_id.as_ref().is_some_and(|id| id.len() > 128))
    {
        return Err(CoreError::SessionExpired);
    }
    if q.cursor.is_some() && q.session_id.is_none() {
        return Err(CoreError::SessionExpired);
    }
    Ok(())
}

pub(crate) fn validate_candidate(candidate: &FeedIssuanceCandidate, deck: Option<&str>) -> CoreResult<()> {
    let before = &candidate.expected.session;
    let after = &candidate.successor;
    let page = &candidate.page;
    let count = page.items.len() as u64;
    let unique: std::collections::HashSet<_> = page.items.iter().map(|item| &item.card.id).collect();
    if unique.len() != page.items.len() {
        return Err(CoreError::invalid("a card may only be delivered once per page"));
    }
    if candidate.policy.is_none()
        || after.id != before.id
        || after.tenant_id != before.tenant_id
        || after.user_id != before.user_id
        || after.created_at != before.created_at
        || page.session_id != before.id
        || before.next_slot.checked_add(count) != Some(after.next_slot)
        || after.next_slot > i64::MAX as u64
        || page.next_cursor.is_empty()
        || page
            .items
            .iter()
            .enumerate()
            .any(|(i, item)| item.slot != before.next_slot + i as u64 || deck.is_some_and(|d| item.card.deck_id != d))
    {
        return Err(CoreError::invalid("invalid feed issuance successor"));
    }
    Ok(())
}

macro_rules! feed_issuance_impl {
    ($repo:ty, $db:ty, $row:ty, $begin:literal, $clock:literal, $auth_lock:literal, $card_lock:literal, $recent:expr, $timestamp:expr, $decode:expr) => {
        impl $repo {
            // 注册锁由调用者持有，学习读写复核捕获的原始凭据与全端注销屏障。
            pub(crate) async fn learning_principal_tx(
                tx: &mut sqlx::Transaction<'_, $db>,
                p: &memoswish_core::Principal,
            ) -> CoreResult<()> {
                if p.via == "jwt" {
                    let iat = p.legacy_issued_at.ok_or_else(|| CoreError::Unauthorized("legacy credential evidence is missing".into()))?;
                    Self::legacy_session_tx(tx, &p.user_id, p.auth_generation, iat).await?;
                }
                Self::session_principal_tx(tx, p).await
            }

            async fn feed_issuance_command(
                &self,
                p: &memoswish_core::Principal,
                request: &memoswish_core::repo::FeedIssuanceRequest,
                candidate: Option<&memoswish_core::repo::FeedIssuanceCandidate>,
            ) -> CoreResult<memoswish_core::repo::FeedIssuanceOutcome> {
                use memoswish_core::repo::{FeedIssuanceOutcome, FeedIssuanceState, FeedSession};
                use memoswish_core::{Permission, Role};
                use memoswish_core::observability::FeedRetryCause;
                use crate::feed_issuance::{db_error, validate_candidate, validate_request, SESSION_LIFETIME_MS};
                p.require(Permission::FeedRead)?;
                validate_request(request)?;
                let q = &request.query;
                let context = serde_json::to_string(&(&q.deck_id, q.limit)).map_err(CoreError::internal)?;
                #[cfg(test)]
                if let Some(gate) = &self.feed_gate { gate.pause(crate::learning::TestPoint::BeforeTransaction).await; }
                let mut tx = self.pool.begin_with($begin).await.map_err(db_error)?;
                // 注册锁先于父作用域和会话锁，与成员移除、撤销及擦除保持相同顺序。
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx).await.map_err(db_error)?;
                // 发新页、推进与重放续期都属于写入，必须核验最初捕获的会话凭据。
                Self::learning_principal_tx(&mut tx, p).await?;
                let role: Option<String> = sqlx::query_scalar(concat!(
                    "SELECT m.role FROM tenants t JOIN tenant_memberships m ON m.tenant_id=t.id JOIN account_auth_epochs a ON a.user_id=m.user_id WHERE t.id=$1 AND m.user_id=$2 AND a.generation=$3 AND m.generation=$4 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id)", $auth_lock))
                    .bind(&p.tenant_id).bind(&p.user_id).bind(p.auth_generation).bind(p.membership_generation)
                    .fetch_optional(&mut *tx).await.map_err(db_error)?;
                let role = role.ok_or_else(|| CoreError::Unauthorized("feed requester is no longer authorized".into()))?;
                if !Role::parse(&role)?.allows(Permission::FeedRead) {
                    return Err(CoreError::Forbidden("current role cannot read feed".into()));
                }
                // 期限使用获得锁之后的数据库时钟，不使用请求开始时间。
                let now: i64 = sqlx::query_scalar($clock).fetch_one(&mut *tx).await.map_err(db_error)?;
                let mut row: Option<$row> = if let Some(first) = &q.request_id {
                    sqlx::query("SELECT id,tenant_id,user_id,next_slot,recent_card_ids,created_at,updated_at,first_request_id,issuance_context,issuance_revision,issuance_cursor,expires_at_ms,expired FROM feed_sessions WHERE tenant_id=$1 AND user_id=$2 AND first_request_id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(first).fetch_optional(&mut *tx).await.map_err(db_error)?
                } else {
                    let session = q.session_id.as_ref().unwrap_or(&request.new_session_id);
                    sqlx::query("SELECT id,tenant_id,user_id,next_slot,recent_card_ids,created_at,updated_at,first_request_id,issuance_context,issuance_revision,issuance_cursor,expires_at_ms,expired FROM feed_sessions WHERE tenant_id=$1 AND user_id=$2 AND id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(session).fetch_optional(&mut *tx).await.map_err(db_error)?
                };
                // 旧客户端无效自选 ID 会回退到本次新 ID，内部重试仍须读取其期限。
                if row.is_none() && q.request_id.is_none() && q.cursor.is_none() {
                    row = sqlx::query("SELECT id,tenant_id,user_id,next_slot,recent_card_ids,created_at,updated_at,first_request_id,issuance_context,issuance_revision,issuance_cursor,expires_at_ms,expired FROM feed_sessions WHERE tenant_id=$1 AND user_id=$2 AND id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(&request.new_session_id)
                        .fetch_optional(&mut *tx).await.map_err(db_error)?;
                }
                let exists = row.is_some();
                let (mut state, cursor, bound_context) = if let Some(row) = row {
                    if row.get::<i64,_>("expired") != 0 || row.get::<i64,_>("expires_at_ms") <= now {
                        return Err(CoreError::SessionExpired);
                    }
                    let replayable = row.get::<Option<String>,_>("first_request_id").is_some();
                    let bound_context: Option<String> = row.get("issuance_context");
                    if replayable && q.request_id.is_none() && q.cursor.is_none() {
                        return Err(CoreError::Conflict("replayable sessions require a cursor".into()));
                    }
                    let cursor: Option<String> = row.get("issuance_cursor");
                    let session = ($decode)(&row)?;
                    (FeedIssuanceState { controls_epoch: 0, desired_retention: None, session, revision: row.get("issuance_revision"), replayable }, cursor, bound_context)
                } else {
                    if q.cursor.is_some() { return Err(CoreError::SessionExpired); }
                    (FeedIssuanceState {
                        session: FeedSession {
                            id: q.session_id.clone().filter(|s| !s.is_empty() && s.len() <= 64).unwrap_or_else(|| request.new_session_id.clone()),
                            tenant_id: p.tenant_id.clone(), user_id: p.user_id.clone(), next_slot: 0,
                            recent_card_ids: vec![], created_at: request.now, updated_at: request.now,
                        }, controls_epoch: 0, desired_retention: None, revision: 0, replayable: q.request_id.is_some(),
                    }, None, None)
                };
                let session = &state.session;
                let key = if let Some(first) = &q.request_id { format!("r:{first}") }
                    else if state.replayable { format!("c:{}", q.cursor.as_deref().unwrap_or_default()) }
                    else { format!("l:{}", request.legacy_request_id) };
                if let Some(receipt) = sqlx::query("SELECT context,page FROM feed_page_receipts WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND issuance_key=$4")
                    .bind(&p.tenant_id).bind(&p.user_id).bind(&session.id).bind(&key)
                    .fetch_optional(&mut *tx).await.map_err(db_error)? {
                    if receipt.get::<String,_>("context") != context {
                        return Err(CoreError::Conflict("feed query differs from the issued context".into()));
                    }
                    let page = serde_json::from_str(&receipt.get::<String,_>("page")).map_err(CoreError::internal)?;
                    sqlx::query("UPDATE feed_sessions SET expires_at_ms=$1 WHERE tenant_id=$2 AND user_id=$3 AND id=$4")
                        .bind(now + SESSION_LIFETIME_MS).bind(&p.tenant_id).bind(&p.user_id).bind(&session.id)
                        .execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    return Ok(FeedIssuanceOutcome::Committed(page));
                }
                if let Some(request_cursor) = &q.cursor {
                    if state.replayable {
                        if cursor.as_ref() != Some(request_cursor) { return Err(CoreError::SessionExpired); }
                    } else if !request_cursor.strip_prefix("s:").is_some_and(|s| s.parse::<u64>().is_ok()) {
                        return Err(CoreError::SessionExpired);
                    }
                }
                if exists && state.replayable && bound_context.as_deref() != Some(&context) {
                    return Err(CoreError::Conflict("feed query differs from the issued context".into()));
                }
                let preferences = sqlx::query("SELECT epoch,desired_retention,issuance_seq FROM learner_preferences WHERE tenant_id=$1 AND user_id=$2")
                    .bind(&p.tenant_id).bind(&p.user_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                let sequence = preferences.as_ref().map_or(0, |r| r.get::<i64,_>("issuance_seq"));
                state.controls_epoch = preferences.as_ref().map_or(0, |r| r.get("epoch"));
                state.desired_retention = preferences.as_ref().and_then(|r| r.get("desired_retention"));
                let Some(candidate) = candidate else { return Ok(FeedIssuanceOutcome::Ready(state)); };
                if candidate.expected != state {
                    let cause = if candidate.expected.revision != state.revision || candidate.expected.session != state.session {
                        FeedRetryCause::SessionRevision
                    } else { FeedRetryCause::StateMismatch };
                    return Ok(FeedIssuanceOutcome::Retry(cause));
                }
                validate_candidate(candidate, q.deck_id.as_deref())?;
                let revision = state.revision.checked_add(1).ok_or_else(|| CoreError::Conflict("feed revision exhausted".into()))?;
                for item in &candidate.page.items {
                    let revision: Option<i64> = sqlx::query_scalar(concat!("SELECT revision FROM cards WHERE publication='published' AND tenant_id=$1 AND id=$2", $card_lock))
                        .bind(&p.tenant_id).bind(&item.card.id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    if revision != Some(i64::from(item.card.revision)) { return Ok(FeedIssuanceOutcome::Retry(FeedRetryCause::StateMismatch)); }
                }
                // 回执恢复先于本检查；新发卡必须在持有注册锁时复核个人控制。
                let mut new_count = 0;
                for item in &candidate.page.items {
                    let reps: Option<i64> = sqlx::query_scalar("SELECT reps FROM memory_states WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(&item.card.id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    new_count += i32::from(reps.is_none_or(|v| v==0));
                    if new_count > 4 { return Err(CoreError::invalid("at most four new cards may be issued per page")); }
                    let hidden: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM learner_card_controls WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3 AND (suspended=1 OR buried_until_ms>$4)")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(&item.card.id).bind(now).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if hidden != 0 { return Ok(FeedIssuanceOutcome::Retry(FeedRetryCause::StateMismatch)); }
                }
                if !exists {
                    sqlx::query("INSERT INTO feed_sessions(id,tenant_id,user_id,next_slot,recent_card_ids,created_at,updated_at,first_request_id,issuance_context,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
                        .bind(&session.id).bind(&p.tenant_id).bind(&p.user_id).bind(session.next_slot as i64)
                        .bind(($recent)(&session.recent_card_ids)?).bind(($timestamp)(&session.created_at)).bind(($timestamp)(&session.updated_at))
                        .bind(&q.request_id).bind(&context).bind(now + SESSION_LIFETIME_MS).execute(&mut *tx).await.map_err(db_error)?;
                }
                let sequence = sequence.checked_add(i64::from(!candidate.page.items.is_empty())).ok_or_else(|| CoreError::Conflict("issuance sequence exhausted".into()))?;
                sqlx::query("INSERT INTO learner_preferences(tenant_id,user_id,epoch,issuance_seq) VALUES($1,$2,1,$3) ON CONFLICT(tenant_id,user_id) DO UPDATE SET epoch=learner_preferences.epoch+1,issuance_seq=excluded.issuance_seq")
                    .bind(&p.tenant_id).bind(&p.user_id).bind(sequence).execute(&mut *tx).await.map_err(db_error)?;
                for item in &candidate.page.items {
                    sqlx::query("INSERT INTO learner_card_controls(tenant_id,user_id,card_id,last_issued_seq) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,user_id,card_id) DO UPDATE SET last_issued_seq=excluded.last_issued_seq")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(&item.card.id).bind(sequence).execute(&mut *tx).await.map_err(db_error)?;
                }
                if let Some(policy) = &candidate.policy {
                    if candidate.page.policy_version.as_ref() != Some(&policy.version) || candidate.page.mode.as_deref() != Some("learning") {
                        return Err(CoreError::invalid("invalid delivery policy"));
                    }
                    sqlx::query("UPDATE feed_sessions SET attribution_start_slot=COALESCE(attribution_start_slot,$1) WHERE tenant_id=$2 AND user_id=$3 AND id=$4")
                        .bind(session.next_slot as i64).bind(&p.tenant_id).bind(&p.user_id).bind(&session.id)
                        .execute(&mut *tx).await.map_err(db_error)?;
                    for item in &candidate.page.items {
                        let id = item.delivery_id.as_ref().filter(|id| !id.is_empty()).ok_or_else(|| CoreError::invalid("missing delivery identity"))?;
                        let record = memoswish_core::repo::DeliveryRecord {
                            attribution: memoswish_core::repo::DeliveryAttribution {
                                delivery_id: id.clone(), policy_version: policy.version.clone(),
                                revision_at_issuance: item.card.revision, issued_at: candidate.page.generated_at,
                            }, card_id: item.card.id.clone(), policy: policy.clone(),
                        };
                        sqlx::query("INSERT INTO feed_deliveries(tenant_id,user_id,session_id,slot,delivery_id,body) VALUES($1,$2,$3,$4,$5,$6)")
                            .bind(&p.tenant_id).bind(&p.user_id).bind(&session.id).bind(item.slot as i64).bind(id)
                            .bind(serde_json::to_string(&record).map_err(CoreError::internal)?)
                            .execute(&mut *tx).await.map_err(db_error)?;
                    }
                }
                sqlx::query("INSERT INTO feed_page_receipts(tenant_id,user_id,session_id,issuance_key,revision,context,page) VALUES($1,$2,$3,$4,$5,$6,$7)")
                    .bind(&p.tenant_id).bind(&p.user_id).bind(&session.id).bind(key).bind(revision).bind(&context)
                    .bind(serde_json::to_string(&candidate.page).map_err(CoreError::internal)?)
                    .execute(&mut *tx).await.map_err(db_error)?;
                #[cfg(test)]
                if let Some(gate) = &self.feed_gate { gate.pause(crate::learning::TestPoint::AfterInsert).await; }
                let successor = &candidate.successor;
                let changed = sqlx::query("UPDATE feed_sessions SET next_slot=$1,recent_card_ids=$2,updated_at=$3,issuance_revision=$4,issuance_cursor=$5,expires_at_ms=$6 WHERE tenant_id=$7 AND user_id=$8 AND id=$9 AND issuance_revision=$10 AND expired=0")
                    .bind(successor.next_slot as i64).bind(($recent)(&successor.recent_card_ids)?).bind(($timestamp)(&successor.updated_at))
                    .bind(revision).bind(&candidate.page.next_cursor).bind(now + SESSION_LIFETIME_MS)
                    .bind(&p.tenant_id).bind(&p.user_id).bind(&session.id).bind(state.revision)
                    .execute(&mut *tx).await.map_err(db_error)?;
                if changed.rows_affected() != 1 {
                    tx.rollback().await.map_err(db_error)?;
                    return Ok(FeedIssuanceOutcome::Retry(FeedRetryCause::SessionRevision));
                }
                #[cfg(test)]
                if let Some(gate) = &self.feed_gate { gate.pause(crate::learning::TestPoint::BeforeCommit).await; }
                tx.commit().await.map_err(db_error)?;
                Ok(FeedIssuanceOutcome::Committed(candidate.page.clone()))
            }

            async fn expire_feed_sessions_command(&self, limit: u32) -> CoreResult<u64> {
                use crate::feed_issuance::db_error;
                let mut tx = self.pool.begin_with($begin).await.map_err(db_error)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_error)?;
                let count = Self::maintenance_feed_tx(&mut tx, limit).await?;
                tx.commit().await.map_err(db_error)?;
                Ok(count)
            }
        }
        impl $repo {
            pub(crate) async fn maintenance_feed_tx(tx: &mut sqlx::Transaction<'_, $db>, limit: u32) -> CoreResult<u64> {
                use crate::feed_issuance::db_error;
                let now: i64 = sqlx::query_scalar($clock).fetch_one(&mut **tx).await.map_err(db_error)?;
                let rows = sqlx::query(&format!("SELECT tenant_id,user_id,id FROM ({}) candidates ORDER BY expires_at_ms,tenant_id,user_id,id LIMIT $2",crate::recovery::FEED_EXPIRY.at("$1")))
                    .bind(now).bind(i64::from(limit.min(100))).fetch_all(&mut **tx).await.map_err(db_error)?;
                for row in &rows {
                    let tenant: String = row.get("tenant_id");
                    let user: String = row.get("user_id");
                    let id: String = row.get("id");
                    sqlx::query("DELETE FROM feed_page_receipts WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3")
                        .bind(&tenant).bind(&user).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                    // 升级前成员已移除时只剩旧会话，清理不能触发要求活成员的 UPDATE。
                    sqlx::query("DELETE FROM feed_sessions WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND NOT EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2)")
                        .bind(&tenant).bind(&user).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                    // 首次身份和截止时间保留，阻止已过期请求静默创建新会话。
                    sqlx::query("UPDATE feed_sessions SET expired=1,recent_card_ids='[]' WHERE tenant_id=$1 AND user_id=$2 AND id=$3")
                        .bind(&tenant).bind(&user).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                }
                Ok(rows.len() as u64)
            }
        }
    };
}
pub(crate) use feed_issuance_impl;

#[cfg(all(test, feature = "sqlite"))]
mod hf12_tests {
    use super::*;
    use memoswish_core::observability::FeedRetryCause;
    use sqlx::{Connection, sqlite::SqliteConnectOptions};
    use std::str::FromStr;

    #[tokio::test]
    async fn hf12_sql_errors_classified_before_sanitization() {
        let root = std::env::temp_dir().join(format!("hf12-errors-{}", memoswish_core::ids::new_id()));
        std::fs::create_dir(&root).unwrap();
        let url = format!("sqlite://{}", root.join("busy.db").display());
        let options = SqliteConnectOptions::from_str(&url)
            .unwrap()
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_millis(10));
        let mut holder = sqlx::SqliteConnection::connect_with(&options).await.unwrap();
        let mut waiter = sqlx::SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("BEGIN IMMEDIATE").execute(&mut holder).await.unwrap();
        let error = sqlx::query("BEGIN IMMEDIATE").execute(&mut waiter).await.unwrap_err();
        assert_eq!(error.as_database_error().unwrap().code().as_deref(), Some("5"));
        assert!(matches!(db_error(error), CoreError::FeedRetry(FeedRetryCause::DatabaseBusyLocked)));
        sqlx::query("ROLLBACK").execute(&mut holder).await.unwrap();
        // 非数据库的暂态错误归 other，永久协议错误继续为 Internal。
        for error in [sqlx::Error::PoolTimedOut, sqlx::Error::Io(std::io::Error::other("SQLITE_BUSY tenant secret"))] {
            assert!(matches!(db_error(error), CoreError::FeedRetry(FeedRetryCause::Other)));
        }
        assert!(matches!(db_error(sqlx::Error::Protocol("database is locked".into())), CoreError::Internal(_)));
        holder.close().await.unwrap();
        waiter.close().await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod hf12_classification_tests {
    use super::*;
    use memoswish_core::observability::FeedRetryCause;
    use std::{borrow::Cow, error::Error};

    #[derive(Debug)]
    struct CodedError(&'static str);
    impl std::fmt::Display for CodedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("private SQL tenant request database is locked")
        }
    }
    impl Error for CodedError {}
    impl sqlx::error::DatabaseError for CodedError {
        fn message(&self) -> &str {
            "private SQL tenant request database is locked"
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            Some(self.0.into())
        }
        fn as_error(&self) -> &(dyn Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    #[test]
    fn hf12_structured_codes_not_error_text_determine_retry_cause() {
        for code in ["5", "6", "261", "262", "517", "773"] {
            assert!(matches!(
                db_error(sqlx::Error::Database(Box::new(CodedError(code)))),
                CoreError::FeedRetry(FeedRetryCause::DatabaseBusyLocked)
            ));
            assert!(matches!(
                crate::feed_candidates::query_error(sqlx::Error::Database(Box::new(CodedError(code)))),
                CoreError::FeedRetry(FeedRetryCause::DatabaseBusyLocked)
            ));
        }
        for code in ["40001", "40P01"] {
            assert!(matches!(
                db_error(sqlx::Error::Database(Box::new(CodedError(code)))),
                CoreError::FeedRetry(FeedRetryCause::Other)
            ));
            assert!(matches!(
                crate::feed_candidates::query_error(sqlx::Error::Database(Box::new(CodedError(code)))),
                CoreError::FeedRetry(FeedRetryCause::Other)
            ));
        }
        assert!(matches!(db_error(sqlx::Error::Database(Box::new(CodedError("23505")))), CoreError::Internal(_)));
        // 候选查询仍只重试原有数据库代码，连接池、IO 与永久错误不扩展为重试。
        for error in [
            sqlx::Error::PoolTimedOut,
            sqlx::Error::Io(std::io::Error::other("database is locked")),
            sqlx::Error::Protocol("database is locked".into()),
            sqlx::Error::Database(Box::new(CodedError("23505"))),
        ] {
            assert!(matches!(crate::feed_candidates::query_error(error), CoreError::Internal(_)));
        }
    }
}
