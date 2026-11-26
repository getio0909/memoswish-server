//! 两个后端共享严格内容事务、历史和报告；无外部调用或新租约。
macro_rules! content_lifecycle_impl {
    ($repo:ty, $db:ty) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, Permission, Principal};
            use memoswish_core::content::CardMutation;
            use memoswish_core::content_lifecycle_repo::ContentLifecycleRepo;
            use memoswish_protocol::*;
            use sqlx::{Row, types::Json};
            use crate::assets::db_error;
            impl $repo {
                async fn author_authorize(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, p: &Principal, permissions: &[Permission]) -> CoreResult<Principal> {
                    if tenant != p.tenant_id { return Err(CoreError::Forbidden("content tenant mismatch".into())); }
                    let mut current = p.clone();
                    current.role = Self::authorize_tx(tx, tenant, &p.user_id, p.credential_generations()?).await?;
                    for permission in permissions { p.require(*permission)?; current.require(*permission)?; }
                    if !Self::credential_current(tx, p, permissions).await? { return Err(CoreError::Unauthorized("content credential was revoked".into())); }
                    Self::privacy_collection_tx(tx, tenant, &p.user_id).await?;
                    Ok(current)
                }
                async fn author_current(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, id: &str) -> CoreResult<Option<Card>> {
                    let body: Option<String> = sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(id).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    body.map(|b| serde_json::from_str(&b).map_err(CoreError::internal)).transpose()
                }
                async fn author_mutation_tx(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str,mutation:&CardMutation,report_id:Option<&str>)->CoreResult<Card> {
                    let current = Self::author_current(tx, tenant, mutation.id()).await?;
                    let deck_id = match mutation {
                        CardMutation::Author { save, .. } => save.card.deck_id.as_str(),
                        CardMutation::Publication { .. } => current.as_ref().ok_or_else(|| CoreError::NotFound("card".into()))?.deck_id.as_str(),
                        _ => return Err(CoreError::invalid("strict content mutation required")),
                    };
                    let row = sqlx::query("SELECT title,description,language,CAST(tags AS TEXT) AS tags,revision FROM decks WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(deck_id).fetch_optional(&mut **tx).await.map_err(db_error)?
                        .ok_or_else(|| CoreError::NotFound("deck".into()))?;
                    let deck = Deck { revision: Some(row.get::<i64,_>("revision") as u32), id: deck_id.into(), title:row.get("title"), description:row.get("description"), language:row.get("language"), tags:serde_json::from_str(&row.get::<String,_>("tags")).map_err(CoreError::internal)?, card_count:0, created_at:chrono::Utc::now() };
                    let previous_assets=current.as_ref().map(memoswish_core::assets::card_assets).unwrap_or_default().into_iter().cloned().collect::<Vec<_>>();
                    let card = mutation.apply(current, Some(&deck), chrono::Utc::now())?;
                    for asset in memoswish_core::assets::card_assets(&card) {
                        if !previous_assets.iter().any(|old|old.key==asset.key && old.sha256==asset.sha256 && old.bytes==asset.bytes && old.mime==asset.mime) {return Err(CoreError::invalid("strict editor cannot introduce media; use portable import"));}
                    }
                    if let Some(report_id) = report_id {
                        let body: Option<String> = sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM content_reports WHERE tenant_id=$1 AND id=$2 AND card_id=$3 AND corrected_revision IS NULL")
                            .bind(tenant).bind(report_id).bind(&card.id).fetch_optional(&mut **tx).await.map_err(db_error)?;
                        let mut report: ContentReport = serde_json::from_str(&body.ok_or_else(|| CoreError::Conflict("report is missing or already resolved".into()))?).map_err(CoreError::internal)?;
                        report.corrected_revision = Some(card.revision);
                        sqlx::query("UPDATE content_reports SET corrected_revision=$3,body=$4 WHERE tenant_id=$1 AND id=$2")
                            .bind(tenant).bind(report_id).bind(i64::from(card.revision)).bind(Json(report)).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    sqlx::query("INSERT INTO cards(id,tenant_id,deck_id,template,revision,body,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,id) DO UPDATE SET deck_id=excluded.deck_id,template=excluded.template,revision=excluded.revision,body=excluded.body,updated_at=excluded.updated_at")
                        .bind(&card.id).bind(tenant).bind(&card.deck_id).bind(&card.template).bind(i64::from(card.revision)).bind(Json(&card)).bind(card.created_at).bind(card.updated_at)
                        .execute(&mut **tx).await.map_err(db_error)?;
                    Ok(card)
                }
            }
            #[async_trait::async_trait]
            impl ContentLifecycleRepo for $repo {
                async fn insert_authored_deck(&self,tenant:&str,p:&Principal,deck:&Deck)->CoreResult<()> {
                    let mut tx=self.lifecycle_tx(&[tenant.into()]).await?;
                    Self::author_authorize(&mut tx,tenant,p,&[Permission::ContentWrite]).await?;
                    sqlx::query("INSERT INTO decks(id,tenant_id,title,description,language,tags,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&deck.id).bind(tenant).bind(&deck.title).bind(&deck.description).bind(&deck.language).bind(Json(&deck.tags)).bind(deck.created_at).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn author_cards(&self,tenant:&str,p:&Principal,mutations:&[CardMutation])->CoreResult<Vec<Card>> {
                    let mut ids=std::collections::HashSet::new();
                    if mutations.is_empty() || mutations.len()>200 || mutations.iter().any(|m|!ids.insert(m.id())) {return Err(CoreError::invalid("provide 1..=200 unique strict card targets"));}
                    let mut tx=self.lifecycle_tx(&[tenant.into()]).await?;
                    Self::author_authorize(&mut tx,tenant,p,&[Permission::ContentWrite]).await?;
                    let mut cards=Vec::with_capacity(mutations.len());
                    for mutation in mutations {let report=match mutation {CardMutation::Author {save,..}=>save.report_id.as_deref(),_=>None};cards.push(Self::author_mutation_tx(&mut tx,tenant,mutation,report).await?);}
                    #[cfg(test)]
                    if let Some(gate)=&self.content_gate {gate.pause(crate::learning::TestPoint::BeforeCommit).await;}
                    tx.commit().await.map_err(db_error)?;Ok(cards)
                }
                async fn author_card(&self, tenant: &str, p: &Principal, mutation: &CardMutation, report_id: Option<&str>) -> CoreResult<Card> {
                    let mut tx = self.lifecycle_tx(&[tenant.into()]).await?;
                    Self::author_authorize(&mut tx, tenant, p, &[Permission::ContentWrite]).await?;
                    let card=Self::author_mutation_tx(&mut tx,tenant,mutation,report_id).await?;
                    #[cfg(test)]
                    if let Some(gate) = &self.content_gate { gate.pause(crate::learning::TestPoint::BeforeCommit).await; }
                    tx.commit().await.map_err(db_error)?;
                    Ok(card)
                }
                async fn edit_deck(&self, tenant: &str, p: &Principal, id: &str, edit: &DeckEdit) -> CoreResult<Deck> {
                    if edit.title.trim().is_empty() || edit.title.chars().count()>200 || edit.description.len()>16384 || edit.language.trim().is_empty() || edit.language.len()>64 {
                        return Err(CoreError::invalid("invalid deck metadata"));
                    }
                    let mut tx = self.lifecycle_tx(&[tenant.into()]).await?;
                    Self::author_authorize(&mut tx, tenant, p, &[Permission::ContentWrite]).await?;
                    let revision: Option<i64> = sqlx::query_scalar("SELECT revision FROM decks WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    let revision = revision.ok_or_else(|| CoreError::NotFound("deck".into()))?;
                    let next = memoswish_core::content::next_revision(Some(edit.expected_revision), revision as u32)?;
                    sqlx::query("UPDATE decks SET title=$3,description=$4,language=$5,revision=$6 WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(id).bind(edit.title.trim()).bind(&edit.description).bind(&edit.language).bind(i64::from(next)).execute(&mut *tx).await.map_err(db_error)?;
                    let row=sqlx::query("SELECT CAST(tags AS TEXT) AS tags,created_at,(SELECT COUNT(*) FROM cards WHERE tenant_id=$1 AND deck_id=$2) AS card_count FROM decks WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let deck=Deck {id:id.into(),revision:Some(next),title:edit.title.trim().into(),description:edit.description.clone(),language:edit.language.clone(),tags:serde_json::from_str(&row.get::<String,_>("tags")).map_err(CoreError::internal)?,created_at:row.get("created_at"),card_count:row.get::<i64,_>("card_count") as u32};
                    tx.commit().await.map_err(db_error)?;
                    Ok(deck)
                }
                async fn content_revisions(&self, tenant: &str, p: &Principal, card: &str, before: u64, limit: u32) -> CoreResult<Vec<CardRevision>> {
                    let mut tx = self.lifecycle_tx(&[tenant.into()]).await?;
                    Self::author_authorize(&mut tx, tenant, p, &[Permission::ContentWrite,Permission::ContentRead]).await?;
                    let rows: Vec<String> = sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM content_revisions WHERE tenant_id=$1 AND card_id=$2 AND revision<$3 ORDER BY revision DESC LIMIT $4")
                        .bind(tenant).bind(card).bind(i64::try_from(before).map_err(|_| CoreError::invalid("invalid revision cursor"))?).bind(i64::from(limit.clamp(1,100))).fetch_all(&mut *tx).await.map_err(db_error)?;
                    rows.into_iter().map(|b| { let card:Card=serde_json::from_str(&b).map_err(CoreError::internal)?; Ok(CardRevision {revision:card.revision,card}) }).collect()
                }
                async fn create_content_report(&self, tenant: &str, p: &Principal, card_id: &str, input: &ReportCreate) -> CoreResult<ContentReport> {
                    memoswish_core::content_lifecycle::validate_report(input)?;
                    let mut tx = self.lifecycle_tx(&[tenant.into()]).await?;
                    let current = Self::author_authorize(&mut tx, tenant, p, &[Permission::ContentRead,Permission::FeedbackWrite]).await?;
                    let card = Self::author_current(&mut tx, tenant, card_id).await?.ok_or_else(|| CoreError::NotFound("card".into()))?;
                    if input.observed_revision > card.revision { return Err(CoreError::invalid("observed_revision is in the future")); }
                    let historical:Option<String>=sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM content_revisions WHERE tenant_id=$1 AND card_id=$2 AND revision=$3").bind(tenant).bind(card_id).bind(i64::from(input.observed_revision)).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    if !(p.can(Permission::ContentWrite) && current.can(Permission::ContentWrite)) {
                        let was_published=historical.as_ref().map(|body|serde_json::from_str::<serde_json::Value>(body).map(|v|v.pointer("/content/publication").is_none_or(|v|v=="published"))).transpose().map_err(CoreError::internal)?;
                        if was_published==Some(false) || (!memoswish_core::content_lifecycle::published(&card) && input.observed_revision>=card.revision) {return Err(CoreError::NotFound("card".into()));}
                    }
                    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_reports WHERE tenant_id=$1 AND card_id=$2").bind(tenant).bind(card_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let open: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_reports WHERE tenant_id=$1 AND card_id=$2 AND corrected_revision IS NULL").bind(tenant).bind(card_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if count>=1000 || open>=100 { return Err(CoreError::Conflict("content report capacity reached".into())); }
                    let evidence=historical.is_some();
                    let report = ContentReport { id: memoswish_core::ids::new_id(), card_id:card_id.into(), user_id:p.user_id.clone(), observed_revision:input.observed_revision, evidence_available:evidence, text:input.text.clone(), sources:input.sources.clone(), created_at:chrono::Utc::now(), corrected_revision:None };
                    sqlx::query("INSERT INTO content_reports(tenant_id,id,card_id,user_id,body) VALUES($1,$2,$3,$4,$5)").bind(tenant).bind(&report.id).bind(card_id).bind(&p.user_id).bind(Json(&report)).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?; Ok(report)
                }
                async fn content_reports(&self, tenant: &str, p: &Principal, card: &str, offset: u32, limit: u32) -> CoreResult<Vec<ContentReport>> {
                    let mut tx = self.lifecycle_tx(&[tenant.into()]).await?;
                    let current = Self::author_authorize(&mut tx, tenant, p, &[Permission::ContentRead]).await?;
                    let editor=p.can(Permission::ContentWrite) && current.can(Permission::ContentWrite);
                    let rows:Vec<String> = sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM content_reports WHERE tenant_id=$1 AND card_id=$2 AND ($3='' OR user_id=$3) ORDER BY id LIMIT $4 OFFSET $5")
                        .bind(tenant).bind(card).bind(if editor {""}else{&p.user_id}).bind(i64::from(limit.clamp(1,100))).bind(i64::from(offset)).fetch_all(&mut *tx).await.map_err(db_error)?;
                    rows.into_iter().map(|b|serde_json::from_str(&b).map_err(CoreError::internal)).collect()
                }
                async fn visible_cards(&self, tenant: &str, deck: Option<&str>, drafts: bool, limit: u32, offset: u32) -> CoreResult<Vec<Card>> {
                    let rows:Vec<String> = sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id=$1 AND ($2='' OR deck_id=$2) AND ($3 OR publication='published') ORDER BY created_at,id LIMIT $4 OFFSET $5")
                        .bind(tenant).bind(deck.unwrap_or("")).bind(drafts).bind(i64::from(limit.clamp(1,5000))).bind(i64::from(offset)).fetch_all(&self.pool).await.map_err(db_error)?;
                    rows.into_iter().map(|b|serde_json::from_str(&b).map_err(CoreError::internal)).collect()
                }
            }
        };
    }
}
pub(crate) use content_lifecycle_impl;
