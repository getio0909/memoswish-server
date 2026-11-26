//! 个人库共用事务：所有命令和读取均在原凭据复核及生命周期锁内执行。
use memoswish_core::{CoreError, CoreResult, Principal};
use memoswish_protocol::LibraryQuery;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct Cursor {
    binding: String,
    pub key: String,
    pub id: String,
}
pub(crate) fn binding(p: &Principal, q: &LibraryQuery, kind: &str) -> CoreResult<String> {
    serde_json::to_vec(&(1, kind, &p.tenant_id, &p.user_id, q.query.as_deref().unwrap_or(""), q.starred, &q.card_id))
        .map(|b| memoswish_core::ids::sha256_hex(&b))
        .map_err(CoreError::internal)
}
pub(crate) fn validate(p: &Principal, q: &LibraryQuery, kind: &str) -> CoreResult<(u32, Option<Cursor>)> {
    let limit = q.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) || q.query.as_ref().is_some_and(|s| s.len() > 256) {
        return Err(CoreError::invalid("library limit must be 1..100 and query at most 256 UTF-8 bytes"));
    }
    if kind.starts_with("history:")
        && (q.card_id.is_some() || q.starred.is_some() || q.query.as_ref().is_some_and(|s| !s.is_empty()))
    {
        return Err(CoreError::invalid("history does not support library filters"));
    }
    let cursor = q
        .cursor
        .as_ref()
        .map(|s| -> CoreResult<Cursor> {
            if s.len() > 4096 {
                return Err(CoreError::invalid("invalid library cursor"));
            }
            let c: Cursor = hex::decode(s)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .ok_or_else(|| CoreError::invalid("invalid library cursor"))?;
            if c.binding != binding(p, q, kind)? {
                return Err(CoreError::invalid("library cursor scope or query mismatch"));
            }
            Ok(c)
        })
        .transpose()?;
    Ok((limit, cursor))
}
pub(crate) fn cursor(p: &Principal, q: &LibraryQuery, kind: &str, key: String, id: String) -> CoreResult<String> {
    serde_json::to_vec(&Cursor { binding: binding(p, q, kind)?, key, id }).map(hex::encode).map_err(CoreError::internal)
}

macro_rules! library_impl {
    ($repo:ty, $db:ty, $visible:expr, $contains:literal, $time:expr, $history_key:literal) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, Principal, Permission, library::LibraryRepo};
            use memoswish_protocol::*;
            use sqlx::Row;
            use crate::assets::db_error;
            impl $repo {
                async fn library_authorize(tx: &mut sqlx::Transaction<'_, $db>, p:&Principal, write:bool) -> CoreResult<()> {
                    p.require(Permission::ContentRead)?;
                    if write {p.require(Permission::FeedbackWrite)?;}
                    let authority=Self::explanation_authority(p);
                    Self::content_authorize(tx,&authority,Permission::ContentRead,false).await?;
                    if write {Self::content_authorize(tx,&authority,Permission::FeedbackWrite,false).await?;}
                    Ok(())
                }
            }
            #[async_trait::async_trait]
            impl LibraryRepo for $repo {
                async fn set_favorite(&self,p:&Principal,card:&str,c:&FavoriteCommand)->CoreResult<FavoriteState> {
                    if c.operation_id.is_empty() || c.operation_id.len()>64 || card.is_empty() || card.len()>128 || c.expected_revision==u32::MAX {
                        return Err(CoreError::invalid("invalid favorite command"));
                    }
                    let command=serde_json::to_string(&(card,c)).map_err(CoreError::internal)?;
                    let mut tx=self.lifecycle_tx(std::slice::from_ref(&p.tenant_id)).await?;
                    Self::library_authorize(&mut tx,p,true).await?;
                    if let Some(row)=sqlx::query("SELECT command,receipt FROM favorite_operations WHERE tenant_id=$1 AND user_id=$2 AND operation_id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(&c.operation_id).fetch_optional(&mut *tx).await.map_err(db_error)? {
                        if row.get::<String,_>("command")!=command {return Err(CoreError::Conflict("favorite operation payload conflict".into()));}
                        return serde_json::from_str(&row.get::<String,_>("receipt")).map_err(CoreError::internal);
                    }
                    // 收藏只接受当前可学习卡片；已提交命令仍从前面的回执恢复。
                    let live:i64=sqlx::query_scalar("SELECT COUNT(*) FROM cards WHERE tenant_id=$1 AND id=$2 AND publication='published'")
                        .bind(&p.tenant_id).bind(card).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if live!=1 {return Err(CoreError::NotFound("card not found".into()));}
                    let revision:Option<i64>=sqlx::query_scalar("SELECT revision FROM personal_favorites WHERE tenant_id=$1 AND user_id=$2 AND card_id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(card).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    if revision.unwrap_or(0)!=i64::from(c.expected_revision) {return Err(CoreError::Conflict("favorite revision conflict".into()));}
                    let next=i64::from(c.expected_revision)+1;
                    sqlx::query("INSERT INTO personal_favorites(tenant_id,user_id,card_id,starred,revision) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,user_id,card_id) DO UPDATE SET starred=excluded.starred,revision=excluded.revision")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(card).bind(c.desired_state).bind(next).execute(&mut *tx).await.map_err(db_error)?;
                    // 显式收藏不制造曝光；递增投影版本使并发复习重新读取。
                    sqlx::query("INSERT INTO memory_states(tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures,starred,projection_version) VALUES($1,$2,$3,0,0,0,0,0,$4,1) ON CONFLICT(tenant_id,user_id,card_id) DO UPDATE SET starred=excluded.starred,projection_version=memory_states.projection_version+1")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(card).bind(c.desired_state).execute(&mut *tx).await.map_err(db_error)?;
                    let result=FavoriteState{card_id:card.into(),starred:c.desired_state,revision:c.expected_revision+1};
                    sqlx::query("INSERT INTO favorite_operations(tenant_id,user_id,operation_id,command,receipt) VALUES($1,$2,$3,$4,$5)")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(&c.operation_id).bind(command).bind(serde_json::to_string(&result).map_err(CoreError::internal)?)
                        .execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(result)
                }
                async fn library_page(&self,p:&Principal,q:&LibraryQuery)->CoreResult<LibraryPage> {

                    let mut tx=self.lifecycle_tx(std::slice::from_ref(&p.tenant_id)).await?;
                    Self::library_authorize(&mut tx,p,false).await?;
                    let namespace:String=sqlx::query_scalar("SELECT value FROM personal_library_namespace WHERE id=1").fetch_one(&mut *tx).await.map_err(db_error)?;
                    let kind=format!("library:{namespace}");
                    let (limit,after)=crate::library::validate(p,q,&kind)?;
                    let mut sql=sqlx::QueryBuilder::<$db>::new("SELECT CAST(c.body AS TEXT) AS body,c.id,COALESCE(f.revision,0) AS revision,COALESCE(m.starred,FALSE) AS starred FROM cards c LEFT JOIN personal_favorites f ON f.tenant_id=c.tenant_id AND f.card_id=c.id AND f.user_id=");
                    sql.push_bind(&p.user_id).push(" LEFT JOIN memory_states m ON m.tenant_id=c.tenant_id AND m.card_id=c.id AND m.user_id=").push_bind(&p.user_id)
                        .push(" WHERE c.publication='published' AND c.tenant_id=").push_bind(&p.tenant_id);
                    if let Some(card)=&q.card_id {sql.push(" AND c.id=").push_bind(card);}
                    if let Some(starred)=q.starred {sql.push(" AND COALESCE(m.starred,FALSE)=").push_bind(starred);}
                    if let Some(after)=&after {sql.push(" AND c.id>").push_bind(&after.id);}
                    if let Some(query)=q.query.as_ref().filter(|s|!s.is_empty()) {
                        sql.push(" AND ").push($contains).push("(").push($visible).push(",").push_bind(query).push(")>0");
                    }
                    sql.push(" ORDER BY c.id LIMIT ").push_bind(i64::from(limit)+1);
                    let rows=sql.build().fetch_all(&mut *tx).await.map_err(db_error)?;
                    let more=rows.len()>limit as usize;
                    let mut items=Vec::new();
                    for row in rows.iter().take(limit as usize) {
                        let card:Card=serde_json::from_str(&row.get::<String,_>("body")).map_err(CoreError::internal)?;
                        let control=Some(Self::controls_card_tx(&mut tx,&p.tenant_id,&p.user_id,&card.id).await?);
                        items.push(LibraryEntry{control,favorite:FavoriteState{card_id:card.id.clone(),starred:row.get("starred"),revision:u32::try_from(row.get::<i64,_>("revision")).map_err(CoreError::internal)?},card});
                    }
                    let next_cursor=if more {items.last().map(|e|crate::library::cursor(p,q,&kind,String::new(),e.card.id.clone())).transpose()?}else{None};
                    tx.commit().await.map_err(db_error)?;
                    Ok(LibraryPage{items,next_cursor})
                }
                async fn review_history(&self,p:&Principal,q:&LibraryQuery)->CoreResult<ReviewHistoryPage> {

                    let mut tx=self.lifecycle_tx(std::slice::from_ref(&p.tenant_id)).await?;
                    Self::library_authorize(&mut tx,p,false).await?;
                    let namespace:String=sqlx::query_scalar("SELECT value FROM personal_library_namespace WHERE id=1").fetch_one(&mut *tx).await.map_err(db_error)?;
                    let kind=format!("history:{namespace}");
                    let (limit,after)=crate::library::validate(p,q,&kind)?;
                    let mut sql=sqlx::QueryBuilder::<$db>::new("SELECT h.event_id,h.card_id,h.received_at,");
                    sql.push($history_key).push(" AS accepted_key,CAST(h.application_provenance AS TEXT) AS application_provenance,c.id AS live_id FROM feedback_events h LEFT JOIN cards c ON c.tenant_id=h.tenant_id AND c.id=h.card_id WHERE h.tenant_id=");
                    sql.push_bind(&p.tenant_id).push(" AND h.user_id=").push_bind(&p.user_id);
                    // 删除后的事件保留归档身份，现存草稿及未知发布状态不进入学习历史。
                    sql.push(" AND (c.id IS NULL OR c.publication='published')");
                    if let Some(c)=&after {sql.push(" AND (").push($history_key).push(",h.event_id)<(").push_bind(&c.key).push(",").push_bind(&c.id).push(")");}
                    sql.push(" ORDER BY ").push($history_key).push(" DESC,h.event_id DESC LIMIT ").push_bind(i64::from(limit)+1);
                    let rows=sql.build().fetch_all(&mut *tx).await.map_err(db_error)?;
                    let more=rows.len()>limit as usize;
                    let mut items=Vec::new();
                    for row in rows.iter().take(limit as usize) {
                        let provenance:Option<memoswish_core::repo::LearningEventProvenance>=row.get::<Option<String>,_>("application_provenance").map(|s|serde_json::from_str(&s).map_err(CoreError::internal)).transpose()?;
                        let disposition=provenance.as_ref().map(|p|serde_json::to_value(p.application.disposition).unwrap().as_str().unwrap().to_string()).unwrap_or_else(||"legacy_unknown".into());
                        let control=if row.get::<Option<String>,_>("live_id").is_some() {Some(Self::controls_card_tx(&mut tx,&p.tenant_id,&p.user_id,&row.get::<String,_>("card_id")).await?)}else{None};
                        items.push(ReviewHistoryEntry{control,event_id:row.get("event_id"),card_id:row.get("card_id"),received_at:($time)(row)?,disposition,rating:provenance.and_then(|p|p.inferred_rating),archived:row.get::<Option<String>,_>("live_id").is_none()});
                    }
                    let next_cursor=if more {let row=&rows[limit as usize-1];Some(crate::library::cursor(p,q,&kind,row.get("accepted_key"),row.get("event_id"))?)}else{None};
                    tx.commit().await.map_err(db_error)?;
                    Ok(ReviewHistoryPage{items,next_cursor})
                }
                async fn feedback_receipts(&self,p:&Principal,ids:&[String])->CoreResult<Vec<FeedbackReceipt>> {
                    if ids.len()>MAX_FEEDBACK_BATCH {return Err(CoreError::invalid("too many receipt IDs"));}
                    let mut tx=self.lifecycle_tx(std::slice::from_ref(&p.tenant_id)).await?;
                    // 回执沿用反馈权限；事务内继续复核原凭据、双世代和当前主体。
                    Self::content_authorize(&mut tx,&Self::explanation_authority(p),Permission::FeedbackWrite,false).await?;
                    let mut result=Vec::new();
                    for id in ids {
                        let row=sqlx::query("SELECT CAST(application_provenance AS TEXT) AS application_provenance FROM feedback_events WHERE tenant_id=$1 AND user_id=$2 AND event_id=$3").bind(&p.tenant_id).bind(&p.user_id).bind(id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                        if let Some(row)=row {
                            let provenance:Option<memoswish_core::repo::LearningEventProvenance>=row.get::<Option<String>,_>("application_provenance").map(|s|serde_json::from_str(&s).map_err(CoreError::internal)).transpose()?;
                            result.push(FeedbackReceipt{event_id:id.clone(),outcome:"delivered".into(),disposition:provenance.map(|p|serde_json::to_value(p.application.disposition).unwrap().as_str().unwrap().into())});
                        }
                    }
                    tx.commit().await.map_err(db_error)?;
                    Ok(result)
                }
            }
        };
    };
}
pub(crate) use library_impl;

// 只检索可见文字，不让资产键、摘要、块类型或 JSON 结构成为命中来源。
pub(crate) fn visible_sql(postgres: bool) -> String {
    let mut paths = vec!["$.tags[*]".to_string()];
    for face in ["front", "back"] {
        for field in ["title", "subtitle"] {
            paths.push(format!("$.{face}.{field}"));
        }
        for field in ["text", "code", "latex", "source", "alt", "title", "items[*]", "header[*]", "rows[*][*]"] {
            paths.push(format!("$.{face}.blocks[*].{field}"));
        }
    }
    if postgres {
        let parts: Vec<_> = paths.iter().map(|p| format!("SELECT jsonb_path_query(c.body, '{p}') AS v")).collect();
        format!("COALESCE((SELECT string_agg(v #>> '{{}}', chr(10)) FROM ({}) visible),'')", parts.join(" UNION ALL "))
    } else {
        let tests: Vec<_> = paths.iter().map(|p| format!("fullkey LIKE '{}'", p.replace("[*]", "[%]"))).collect();
        format!(
            "COALESCE((SELECT group_concat(value,char(10)) FROM json_tree(c.body) WHERE type='text' AND ({})),'')",
            tests.join(" OR ")
        )
    }
}
