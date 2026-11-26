//! 两个后端共用导入事务；外部 PUT 永不跨越 SQL 事务。

macro_rules! imports_impl {
    ($repo:ty, $db:ty, $row:ty, $ts:expr) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, Permission, Principal};
            use memoswish_core::imports::*;
            use memoswish_core::assets::*;
            use memoswish_core::jobs::JobClaim;
            use crate::assets::db_error;
            use sqlx::{Row, types::Json};

            impl $repo {
                async fn import_authorize(tx: &mut sqlx::Transaction<'_, $db>, a: &ImportAuthority, media: bool) -> CoreResult<Principal> {
                    Self::content_authorize(tx, a, Permission::ContentWrite, media).await
                }
                pub(crate) async fn content_authorize(tx: &mut sqlx::Transaction<'_, $db>, a: &ImportAuthority, permission: Permission, media: bool) -> CoreResult<Principal> {
                    let mut p = a.principal();
                    p.require(permission)?;
                    let alive:Option<String>=sqlx::query_scalar(if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT id FROM tenants WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=$1) FOR UPDATE"} else {"SELECT id FROM tenants WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=$1)"}).bind(&p.tenant_id).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    if alive.is_none(){return Err(CoreError::Forbidden("import tenant is erased".into()));}
                    let role = Self::authorize_tx(tx, &p.tenant_id, &p.user_id, p.credential_generations()?).await?;
                    Self::privacy_collection_tx(tx, &p.tenant_id, &p.user_id).await?;
                    if let Some(fence) = &a.privacy {
                        Self::privacy_policy_tx(tx, &fence.policy).await?;
                        let state = Self::privacy_read_tx(tx, &p.tenant_id, &p.user_id).await?;
                        if state.revision != fence.revision { return Err(CoreError::Forbidden("privacy changed after import admission".into())); }
                        memoswish_core::privacy::require_purpose(&state, &fence.policy, "external_tts")?;
                    }
                    if !role.allows(permission) { return Err(CoreError::Forbidden("import requester lacks current content permission".into())); }
                    if media { p.require(Permission::MediaWrite)?; if !role.allows(Permission::MediaWrite) { return Err(CoreError::Forbidden("import requester lacks current media permission".into())); } }
                    Self::session_principal_tx(tx, &p).await?;
                    let now = Self::asset_now(tx).await? / 1000;
                    match p.via.as_str() {
                        "session" => {},
                        "jwt" => {
                            Self::legacy_session_tx(tx, &p.user_id, p.auth_generation, p.legacy_issued_at.ok_or_else(|| CoreError::Unauthorized("legacy credential evidence is missing".into()))?).await?;
                            if a.expires_at.is_none_or(|exp|exp<=now) {return Err(CoreError::Unauthorized("original JWT expired".into()));}
                        },
                        "api_token" => {
                            let hash = a.token_hash.as_deref().ok_or_else(||CoreError::Unauthorized("original API token evidence is missing".into()))?;
                            let row = sqlx::query(if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT user_id,account_generation,membership_generation,CAST(scopes AS TEXT) AS scopes,expires_at,revoked FROM api_tokens WHERE tenant_id=$1 AND token_hash=$2 FOR SHARE"}else{"SELECT user_id,account_generation,membership_generation,CAST(scopes AS TEXT) AS scopes,expires_at,revoked FROM api_tokens WHERE tenant_id=$1 AND token_hash=$2"})
                                .bind(&p.tenant_id).bind(hash).fetch_optional(&mut **tx).await.map_err(db_error)?.ok_or_else(||CoreError::Unauthorized("original API token is unavailable".into()))?;
                            let scopes: Vec<String> = serde_json::from_str(&row.get::<String,_>("scopes")).map_err(|_|CoreError::internal("invalid token scopes"))?;
                            let credential_now=Self::asset_now(tx).await?;
                            if row.get::<bool,_>("revoked") || row.get::<Option<chrono::DateTime<chrono::Utc>>,_>("expires_at").is_some_and(|e| e.timestamp_millis()<credential_now) || row.get::<String,_>("user_id")!=p.user_id || Some(row.get("account_generation"))!=p.auth_generation || Some(row.get("membership_generation"))!=p.membership_generation || Some(scopes)!=p.scopes {
                                return Err(CoreError::Unauthorized("original API token is no longer authorized".into()));
                            }
                        },
                        "mcp_oauth" => {
                            let hash = a.token_hash.as_deref().ok_or_else(||CoreError::Unauthorized("original OAuth evidence is missing".into()))?;
                            let body: Option<String> = sqlx::query_scalar(if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT t.body FROM oauth_tokens t JOIN oauth_grants g ON g.tenant_id=t.tenant_id AND g.id=t.grant_id JOIN oauth_clients c ON c.id=g.client_id WHERE t.tenant_id=$1 AND t.hash=$2 AND t.kind='access' AND t.consumed=0 AND t.expires_at>$3 AND g.expires_at>$3 AND c.expires_at>$3 AND g.revoked=0 FOR SHARE OF t,g,c"}else{"SELECT t.body FROM oauth_tokens t JOIN oauth_grants g ON g.tenant_id=t.tenant_id AND g.id=t.grant_id JOIN oauth_clients c ON c.id=g.client_id WHERE t.tenant_id=$1 AND t.hash=$2 AND t.kind='access' AND t.consumed=0 AND t.expires_at>$3 AND g.expires_at>$3 AND c.expires_at>$3 AND g.revoked=0"})
                                .bind(&p.tenant_id).bind(hash).bind(now).fetch_optional(&mut **tx).await.map_err(db_error)?;
                            let token: memoswish_core::oauth::OAuthToken = serde_json::from_str(&body.ok_or_else(||CoreError::Unauthorized("original OAuth token is unavailable".into()))?).map_err(|_|CoreError::internal("invalid OAuth evidence"))?;
                            let credential_now=Self::asset_now(tx).await?/1000;
                            let client_expiry:i64=sqlx::query_scalar("SELECT expires_at FROM oauth_clients WHERE id=$1").bind(&token.grant.client_id).fetch_one(&mut **tx).await.map_err(db_error)?;
                            if token.expires_at<=credential_now || token.grant.expires_at<=credential_now || client_expiry<=credential_now || token.grant.tenant_id!=p.tenant_id || token.grant.user_id!=p.user_id || Some(token.grant.generations.account)!=p.auth_generation || Some(token.grant.generations.membership)!=p.membership_generation || Some(token.scopes)!=p.scopes { return Err(CoreError::Unauthorized("OAuth evidence does not match requester".into())); }
                        },
                        "single_user" | "stdio" | "test" | "cli" if p.tenant_id==memoswish_core::ids::LOCAL_TENANT_ID && p.user_id==memoswish_core::ids::LOCAL_USER_ID => {},
                        _ => return Err(CoreError::Unauthorized("unsupported import credential evidence".into())),
                    }
                    p.role=role;
                    Ok(p)
                }
                fn import_row(r: &$row) -> CoreResult<ImportOperation> {
                    Ok(ImportOperation { id:r.get("id"),outcome:r.get("outcome"),result:r.get::<Option<String>,_>("result").map(|v|serde_json::from_str(&v).map_err(|_|CoreError::internal("invalid import receipt"))).transpose()? })
                }
                async fn import_asset_tx(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal, asset: &memoswish_protocol::AssetRef) -> CoreResult<Option<String>> {
                    validate_asset_ref(asset)?;
                    let denied=||CoreError::Forbidden("DeckPack asset lacks authorized attachment evidence".into());
                    if !asset.key.starts_with(&p.asset_prefix()) {return Err(denied());}
                    let published:Option<String>=sqlx::query_scalar("SELECT i.asset_id FROM asset_upload_intents i JOIN asset_upload_attempts a ON a.tenant_id=i.tenant_id AND a.id=i.published_attempt JOIN asset_records r ON r.tenant_id=i.tenant_id AND r.id=i.asset_id WHERE i.tenant_id=$1 AND a.object_key=$2 AND a.outcome='uploaded' AND r.sha256=$3 AND r.size=$4 AND r.mime=$5 AND EXISTS(SELECT 1 FROM asset_references f WHERE f.tenant_id=i.tenant_id AND f.asset_id=i.asset_id)").bind(&p.tenant_id).bind(&asset.key).bind(&asset.sha256).bind(asset.bytes as i64).bind(&asset.mime).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    if published.is_some() {return Ok(published);}
                    // 沿用 S20 的旧卡片桥接；受管 uploads 永不使用旧引用代替发布证据。
                    if asset.key.starts_with(&format!("{}uploads/",p.asset_prefix())) {return Err(denied());}
                    // 与 legacy_asset_cards 相同的有界候选查询，在当前导入事务内逐字段验证。
                    let bodies:Vec<String>=sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id=$1 AND CAST(body AS TEXT) LIKE $2 LIMIT 1001").bind(&p.tenant_id).bind(format!("%{}%",asset.key)).fetch_all(&mut **tx).await.map_err(db_error)?;
                    if bodies.len()>1000 {return Err(CoreError::Unsupported("legacy asset lookup requires an explicit owner".into()));}
                    for body in bodies {
                        let card:memoswish_protocol::Card=serde_json::from_str(&body).map_err(|_|CoreError::internal("invalid stored card"))?;
                        if card_assets(&card).iter().any(|existing|existing.key==asset.key && existing.sha256==asset.sha256 && existing.bytes==asset.bytes && existing.mime==asset.mime) {
                            // 旧对象只复制业务引用，不伪造资产记录、版本或上传回执。
                            return Ok(None);
                        }
                    }
                    Err(denied())
                }
                async fn import_fence(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, claim: &JobClaim) -> CoreResult<()> {
                    let now = Self::asset_now(tx).await?;
                    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs j JOIN content_imports i ON i.tenant_id=j.tenant_id AND i.id=j.id WHERE j.tenant_id=$1 AND j.id=$2 AND j.token=$3 AND j.kind='content_import' AND j.state='running' AND j.lease_until_ms>$4 AND i.outcome='pending'")
                        .bind(tenant).bind(&claim.job_id).bind(&claim.token).bind(now).fetch_one(&mut **tx).await.map_err(db_error)?;
                    if live!=1 { return Err(CoreError::Conflict("import claim expired or replaced".into())); } Ok(())
                }
                async fn import_execution_tx(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, id: &str) -> CoreResult<ImportExecution> {
                    let r=sqlx::query("SELECT authority,work FROM content_imports WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).fetch_one(&mut **tx).await.map_err(db_error)?;
                    Ok(ImportExecution {authority:serde_json::from_str(&r.get::<String,_>("authority")).map_err(|_|CoreError::internal("invalid import authority"))?,work:serde_json::from_str(&r.get::<String,_>("work")).map_err(|_|CoreError::internal("invalid import work"))?})
                }
                async fn import_fail_tx(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, id: &str) -> CoreResult<()> {
                    sqlx::query("UPDATE content_imports SET outcome='failed',work='{}',authority='{}' WHERE tenant_id=$1 AND id=$2 AND outcome='pending'").bind(tenant).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE quota_operations SET state='released' WHERE tenant_id=$1 AND operation_id=$2 AND state='reserved'").bind(tenant).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE background_jobs SET state='dead',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }
                // 擦除业务输入和回执，保留精确对象及原计量账本所需的最小责任。
                pub(crate) async fn import_erase(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str,user:Option<&str>)->CoreResult<()> {
                    let ids:Vec<String>=sqlx::query_scalar("SELECT id FROM content_imports WHERE tenant_id=$1 AND ($2='' OR user_id=$2)").bind(tenant).bind(user.unwrap_or("")).fetch_all(&mut **tx).await.map_err(db_error)?;
                    for id in ids {
                        Self::import_fail_tx(tx,tenant,&id).await?;
                        sqlx::query("UPDATE content_imports SET outcome='failed',authority='{}',work='{}',result=NULL WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                        sqlx::query("DELETE FROM import_followups WHERE tenant_id=$1 AND import_id=$2").bind(tenant).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                        sqlx::query("UPDATE asset_upload_attempts SET outcome='uncertain' WHERE tenant_id=$1 AND outcome='in_flight' AND intent_id IN(SELECT intent_id FROM import_uploads WHERE tenant_id=$1 AND import_id=$2)").bind(tenant).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                        sqlx::query("UPDATE import_uploads SET source_key='' WHERE tenant_id=$1 AND import_id=$2").bind(tenant).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                        sqlx::query("UPDATE background_jobs SET result=NULL,payload=$3,idempotency_key=$4 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&id).bind(Json(serde_json::json!({}))).bind(memoswish_core::ids::new_id()).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    Ok(())
                }
                pub(crate) async fn import_try_usage(&self, tenant:&str, metric:&str, period:&str, amount:i64, limit:i64) -> CoreResult<Option<i64>> {
                    if amount<0 || limit<0 { return Err(CoreError::invalid("usage amount and limit must be nonnegative")); }
                    let mut tx=self.asset_tx().await?;
                    let used:i64=sqlx::query_scalar("SELECT CAST(COALESCE(SUM(amount),0) AS BIGINT) FROM usage_counters WHERE tenant_id=$1 AND metric=$2 AND period=$3").bind(tenant).bind(metric).bind(period).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let held:i64=sqlx::query_scalar("SELECT CAST(COALESCE(SUM(amount),0) AS BIGINT) FROM quota_operations WHERE tenant_id=$1 AND metric=$2 AND period=$3 AND state='reserved'").bind(tenant).bind(metric).bind(period).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if used>limit || held>limit-used || amount>limit-used-held { return Ok(None); }
                    sqlx::query("INSERT INTO usage_counters(tenant_id,metric,period,amount) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,metric,period) DO UPDATE SET amount=usage_counters.amount+excluded.amount").bind(tenant).bind(metric).bind(period).bind(amount).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;Ok(Some(used+amount))
                }
                async fn import_lookup_tx(tx:&mut sqlx::Transaction<'_, $db>,a:&ImportAuthority,key:&str,fingerprint:&str)->CoreResult<Option<ImportOperation>> {
                    let row=sqlx::query("SELECT i.* FROM content_imports i JOIN background_jobs j ON j.tenant_id=i.tenant_id AND j.id=i.id WHERE i.tenant_id=$1 AND j.kind='content_import' AND j.idempotency_key=$2").bind(&a.principal.tenant_id).bind(key).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    row.map(|r| {
                        if r.get::<String,_>("authority_id")!=a.identity()? || r.get::<String,_>("fingerprint")!=fingerprint {return Err(CoreError::Conflict("import request identity conflict".into()));} Self::import_row(&r)
                    }).transpose()
                }
            }
            #[async_trait::async_trait]
            impl ImportRepo for $repo {
                async fn revalidate_portable_export(&self,a:&ImportAuthority)->CoreResult<()> {
                    let mut tx=self.asset_tx().await?;
                    Self::content_authorize(&mut tx,a,Permission::ContentRead,false).await?;
                    tx.commit().await.map_err(db_error)
                }
                async fn portable_snapshot(&self,a:&ImportAuthority,id:&str)->CoreResult<memoswish_protocol::DeckPack> {
                    let mut tx=self.asset_tx().await?;
                    let p=Self::content_authorize(&mut tx,a,Permission::ContentRead,false).await?;
                    // 先查询字节预算，再读取正文，避免不支持的历史大内容造成无界分配。
                    let size:i64=sqlx::query_scalar(if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT CAST(COALESCE(SUM(octet_length(CAST(body AS TEXT))),0) AS BIGINT) FROM (SELECT body FROM cards WHERE tenant_id=$1 AND deck_id=$2 LIMIT 501) c"}else{"SELECT CAST(COALESCE(SUM(length(CAST(body AS BLOB))),0) AS BIGINT) FROM (SELECT body FROM cards WHERE tenant_id=$1 AND deck_id=$2 LIMIT 501) c"}).bind(&p.tenant_id).bind(id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let deck_size:Option<i64>=sqlx::query_scalar(if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT CAST(octet_length(title||description||language||CAST(tags AS TEXT)) AS BIGINT) FROM decks WHERE tenant_id=$1 AND id=$2"}else{"SELECT length(CAST(title||description||language||CAST(tags AS TEXT) AS BLOB)) FROM decks WHERE tenant_id=$1 AND id=$2"}).bind(&p.tenant_id).bind(id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    // JSONB 文本最多在每个紧凑 JSON 字节旁增加一个分隔空格。
                    // 内部身份扩展与 PG 展示空格不占公开包预算；包内键替换后再验 8 MiB。
                    let snapshot_limit=PORTABLE_SNAPSHOT_BYTES as i64 * if <$db as sqlx::Database>::NAME=="PostgreSQL" {2} else {1};
                    if size>snapshot_limit || deck_size.is_some_and(|n|n>snapshot_limit-size) {return Err(CoreError::Unsupported("portable stored content exceeds bounded snapshot size".into()));}
                    let r=sqlx::query("SELECT id,title,description,language,CAST(tags AS TEXT) AS tags,created_at,revision FROM decks WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(id).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("deck".into()))?;
                    let bodies:Vec<String>=sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id=$1 AND deck_id=$2 ORDER BY created_at,id LIMIT 501").bind(&p.tenant_id).bind(id).fetch_all(&mut *tx).await.map_err(db_error)?;
                    if bodies.len()>500{return Err(CoreError::Unsupported("portable DeckPack exceeds 500 cards".into()));}
                    let cards:Vec<memoswish_protocol::Card>=bodies.into_iter().map(|s|serde_json::from_str(&s).map_err(|_|CoreError::internal("invalid stored card"))).collect::<CoreResult<Vec<_>>>()?.into_iter().filter(|c| p.can(Permission::ContentWrite) || memoswish_core::content_lifecycle::published(c)).collect();
                    let deck=memoswish_protocol::Deck{revision:Some(r.get::<i64,_>("revision") as u32),id:r.get("id"),title:r.get("title"),description:r.get("description"),language:r.get("language"),tags:serde_json::from_str(&r.get::<String,_>("tags")).map_err(|_|CoreError::internal("invalid deck tags"))?,created_at:r.get("created_at"),card_count:cards.len() as u32};
                    tx.commit().await.map_err(db_error)?;
                    Ok(memoswish_protocol::DeckPack{version:if cards.iter().any(memoswish_core::bgm::has_media_metadata) {"1.2"}else if cards.iter().any(|c|c.content.is_some()) {"1.1"}else{"1.0"}.into(),deck,cards,exported_at:chrono::Utc::now()})
                }

                async fn lookup_import(&self,a:&ImportAuthority,key:&str,fingerprint:&str)->CoreResult<Option<ImportOperation>> {
                    validate_request_id(key)?;
                    let mut tx=self.asset_tx().await?;Self::import_authorize(&mut tx,a,false).await?;
                    let result=Self::import_lookup_tx(&mut tx,a,key,fingerprint).await?;tx.commit().await.map_err(db_error)?;Ok(result)
                }
                async fn import_status(&self,a:&ImportAuthority,key:&str)->CoreResult<Option<ImportOperation>> {
                    validate_request_id(key)?;
                    let mut tx=self.asset_tx().await?;
                    Self::import_authorize(&mut tx,a,false).await?;
                    let row=sqlx::query("SELECT i.id,i.outcome FROM content_imports i JOIN background_jobs j ON j.tenant_id=i.tenant_id AND j.id=i.id WHERE i.tenant_id=$1 AND j.kind='content_import' AND j.idempotency_key=$2 AND i.authority_id=$3").bind(&a.principal.tenant_id).bind(key).bind(a.identity()?).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    let result=row.map(|r|ImportOperation{id:r.get("id"),outcome:r.get("outcome"),result:None});
                    tx.commit().await.map_err(db_error)?;
                    Ok(result)
                }
                async fn accept_import(&self,a:&ImportAuthority,key:&str,fingerprint:&str,work:&ImportWork,limit:Option<i64>,staging_limit:i64)->CoreResult<ImportOperation> {
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbWrite);
        let result: CoreResult<_> = async {
                    validate_request_id(key)?;
                    if !(1..=100).contains(&staging_limit) || limit.is_some_and(|l|l<0) || work.cards.len()>500 || work.media.len()>4096 || work.deck.card_count as usize!=work.cards.len() || fingerprint.len()!=64 {return Err(CoreError::invalid("invalid import admission"));}
                    let mut ids=std::collections::HashSet::new();
                    for card in &work.cards { memoswish_core::content_validation::validate_card(card)?;if card.deck_id!=work.deck.id || card.revision!=1 || !ids.insert(&card.id) {return Err(CoreError::invalid("invalid import card identity"));} }
                    json_bytes(&work.cards,work.cards_byte_limit()?)?;
                    if work.media.iter().try_fold(0usize,|n,m|n.checked_add(m.bytes.len())).is_none_or(|n|n>128*1024*1024) {return Err(CoreError::invalid("import normalized input exceeds bounds"));}
                    let serialized=serde_json::to_string(work).map_err(|_|CoreError::invalid("invalid import work"))?;
                    if serialized.len()>600*1024*1024 {return Err(CoreError::invalid("import staging exceeds bound"));}
                    let mut tx=self.asset_tx().await?;
                    let p=Self::import_authorize(&mut tx,a,!work.media.is_empty()).await?;
                    if let Some(existing)=Self::import_lookup_tx(&mut tx,a,key,fingerprint).await? {tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;return Ok(existing);}
                    let staged:std::collections::HashSet<_>=work.media.iter().map(|m|m.asset.key.as_str()).collect();
                    if staged.len()!=work.media.len(){return Err(CoreError::invalid("duplicate staged media identity"));}
                    for c in &work.cards {for asset in card_assets(c){if !staged.contains(asset.key.as_str()){
                        Self::import_asset_tx(&mut tx,&p,asset).await?;
                    }}}
                    let outstanding:i64=sqlx::query_scalar("SELECT COUNT(*) FROM content_imports WHERE tenant_id=$1 AND outcome='pending'").bind(&p.tenant_id).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    if outstanding>=staging_limit {return Err(CoreError::QuotaExceeded("outstanding import staging limit reached; retry later".into()));}
                    let now=Self::asset_now(&mut tx).await?;
                    let period=chrono::DateTime::from_timestamp_millis(now).ok_or_else(||CoreError::internal("invalid database clock"))?.format("%Y-%m").to_string();
                    let used:i64=sqlx::query_scalar("SELECT CAST(COALESCE(SUM(amount),0) AS BIGINT) FROM usage_counters WHERE tenant_id=$1 AND metric='card_writes' AND period=$2").bind(&p.tenant_id).bind(&period).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    let held:i64=sqlx::query_scalar("SELECT CAST(COALESCE(SUM(amount),0) AS BIGINT) FROM quota_operations WHERE tenant_id=$1 AND metric='card_writes' AND period=$2 AND state='reserved'").bind(&p.tenant_id).bind(&period).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    let amount=work.cards.len() as i64;
                    if limit.is_some_and(|l| used>l || held>l-used || amount>l-used-held) {return Err(CoreError::QuotaExceeded("card_writes monthly limit reached".into()));}
                    let id=memoswish_core::ids::new_id();
                    sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES($1,$2,'content_import',$3,$4,$5,$6,5,$7)").bind(&p.tenant_id).bind(&id).bind(key).bind(Json(serde_json::json!({}))).bind(&p.user_id).bind(p.membership_generation).bind(now).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    sqlx::query("INSERT INTO content_imports(tenant_id,id,fingerprint,authority_id,authority,work,user_id) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&p.tenant_id).bind(&id).bind(fingerprint).bind(a.identity()?).bind(serde_json::to_string(a).map_err(|_|CoreError::internal("invalid authority"))?).bind(serialized).bind(&p.user_id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    sqlx::query("INSERT INTO quota_operations(tenant_id,operation_id,metric,period,amount,state) VALUES($1,$2,'card_writes',$3,$4,'reserved')").bind(&p.tenant_id).bind(&id).bind(&period).bind(amount).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    for (ordinal,m) in work.media.iter().enumerate() {
                        let spec=AssetSpec{mime:m.asset.mime.clone(),size:m.bytes.len() as i64,sha256:memoswish_core::ids::sha256_hex(&m.bytes)};spec.validate()?;
                        if spec.sha256!=m.asset.sha256 || spec.size as u64!=m.asset.bytes || !m.asset.key.starts_with(&p.asset_prefix()) {return Err(CoreError::invalid("invalid staged media identity"));}
                        let intent=memoswish_core::ids::new_id();let asset=memoswish_core::ids::new_id();
                        sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES($1,$2,'asset_upload',$2,$3,$4,$5,5,$6)").bind(&p.tenant_id).bind(&intent).bind(Json(serde_json::json!({}))).bind(&p.user_id).bind(p.membership_generation).bind(now).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        sqlx::query("INSERT INTO asset_records(tenant_id,id,mime,size,sha256) VALUES($1,$2,$3,$4,$5)").bind(&p.tenant_id).bind(&asset).bind(&spec.mime).bind(spec.size).bind(&spec.sha256).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        sqlx::query("INSERT INTO asset_upload_intents(tenant_id,id,asset_id,account_generation) VALUES($1,$2,$3,$4)").bind(&p.tenant_id).bind(&intent).bind(&asset).bind(p.auth_generation).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        sqlx::query("INSERT INTO import_uploads(tenant_id,import_id,ordinal,intent_id,source_key) VALUES($1,$2,$3,$4,$5)").bind(&p.tenant_id).bind(&id).bind(ordinal as i64).bind(&intent).bind(&m.asset.key).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    }
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;Ok(ImportOperation{id,outcome:"pending".into(),result:None})

        }.await;
        use memoswish_core::observability::{AdmissionClass,AdmissionOutcome};
        self.observer.admission(AdmissionClass::Import,match &result { Ok(_)=>AdmissionOutcome::Accepted,Err(CoreError::QuotaExceeded(_))=>AdmissionOutcome::Rejected,Err(CoreError::Invalid(_))=>AdmissionOutcome::Invalid,_=>AdmissionOutcome::Unavailable });
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
                async fn import_operation(&self,tenant:&str,id:&str)->CoreResult<ImportOperation>{
                    let r=sqlx::query("SELECT * FROM content_imports WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).fetch_optional(&self.pool).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("import operation".into()))?;Self::import_row(&r)
                }
                async fn claim_import(&self,tenant:&str,id:&str,lease_ms:i64)->CoreResult<Option<JobClaim>> {
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbClaim);
        let result: CoreResult<_> = async {
                    if !(1..=300_000).contains(&lease_ms) {return Err(CoreError::invalid("invalid import lease duration"));}
                    let mut tx=self.asset_tx().await?;let now=Self::asset_now(&mut tx).await?;
                    let r=sqlx::query(&format!("SELECT j.attempts,j.max_attempts FROM ({}) j JOIN content_imports i ON i.tenant_id=j.tenant_id AND i.id=j.id WHERE j.tenant_id=$1 AND j.id=$2 AND j.kind='content_import' AND CAST(j.payload AS TEXT)='{{}}' AND i.outcome='pending' AND ((j.state='queued' AND j.available_at_ms<=$3) OR (j.state='running' AND j.lease_until_ms<=$3))",crate::recovery::JOBS.sql)).bind(tenant).bind(id).bind(now).fetch_optional(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    let Some(r)=r else {return Ok(None);};
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='uncertain' WHERE tenant_id=$1 AND outcome='in_flight' AND intent_id IN(SELECT intent_id FROM import_uploads WHERE tenant_id=$1 AND import_id=$2)").bind(tenant).bind(id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    if r.get::<i64,_>("attempts")>=r.get::<i64,_>("max_attempts") {Self::import_fail_tx(&mut tx,tenant,id).await?;tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;return Ok(None);}
                    let token=memoswish_core::ids::new_id();
                    sqlx::query("UPDATE background_jobs SET state='running',attempts=attempts+1,worker='import',token=$3,lease_until_ms=$4 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).bind(&token).bind(now+lease_ms).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;Ok(Some(JobClaim{job_id:id.into(),token}))

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
                async fn heartbeat_import(&self,tenant:&str,claim:&JobClaim,lease_ms:i64)->CoreResult<()> {
                    if !(1..=300_000).contains(&lease_ms){return Err(CoreError::invalid("invalid import lease duration"));}
                    let mut tx=self.asset_tx().await?;Self::import_fence(&mut tx,tenant,claim).await?;let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=$3 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).bind(now+lease_ms).execute(&mut *tx).await.map_err(db_error)?;tx.commit().await.map_err(db_error)
                }
                async fn import_execution(&self,tenant:&str,claim:&JobClaim)->CoreResult<ImportExecution>{
                    let mut tx=self.asset_tx().await?;Self::import_fence(&mut tx,tenant,claim).await?;let e=Self::import_execution_tx(&mut tx,tenant,&claim.job_id).await?;Self::import_authorize(&mut tx,&e.authority,!e.work.media.is_empty()).await?;tx.commit().await.map_err(db_error)?;Ok(e)
                }
                async fn begin_import_upload(&self,tenant:&str,claim:&JobClaim,ordinal:i64,store:&str)->CoreResult<UploadAttempt>{
                    validate_asset_id(store)?;let mut tx=self.asset_tx().await?;Self::import_fence(&mut tx,tenant,claim).await?;
                    // 每张图片只读取小型授权证据，不重复反序列化整包媒体。
                    let body:String=sqlx::query_scalar("SELECT authority FROM content_imports WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let authority:ImportAuthority=serde_json::from_str(&body).map_err(|_|CoreError::internal("invalid import authority"))?;
                    Self::import_authorize(&mut tx,&authority,true).await?;Self::import_fence(&mut tx,tenant,claim).await?;
                    let r=sqlx::query("SELECT intent_id,selected_attempt FROM import_uploads WHERE tenant_id=$1 AND import_id=$2 AND ordinal=$3").bind(tenant).bind(&claim.job_id).bind(ordinal).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if let Some(id)=r.get::<Option<String>,_>("selected_attempt") {let a=Self::asset_attempt_tx(&mut tx,tenant,&id).await?;tx.commit().await.map_err(db_error)?;return Ok(a);}
                    let intent:String=r.get("intent_id");
                    // 已知回执可在接管后交接，无需重复 PUT；未知写入保持独立责任。
                    let existing:Option<String>=sqlx::query_scalar("SELECT id FROM asset_upload_attempts WHERE tenant_id=$1 AND intent_id=$2 AND store_id=$3 AND outcome='uploaded' AND version_kind<>'unknown' ORDER BY id LIMIT 1").bind(tenant).bind(&intent).bind(store).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    if let Some(id)=existing {let a=Self::asset_attempt_tx(&mut tx,tenant,&id).await?;tx.commit().await.map_err(db_error)?;return Ok(a);}
                    let id=memoswish_core::ids::new_id();let key=format!("tenants/{tenant}/uploads/{intent}/{id}");memoswish_core::store::validate_key(&key)?;
                    sqlx::query("INSERT INTO asset_upload_attempts(tenant_id,id,intent_id,object_key,claim_token,store_id,outcome) VALUES($1,$2,$3,$4,$5,$6,'in_flight')").bind(tenant).bind(&id).bind(&intent).bind(&key).bind(&claim.token).bind(store).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;Ok(UploadAttempt{id,intent_id:intent,key,store_id:store.into(),claim_token:claim.token.clone(),outcome:UploadOutcome::InFlight,version:ObjectVersion::Unknown})
                }
                async fn select_import_upload(&self,tenant:&str,claim:&JobClaim,ordinal:i64,id:&str)->CoreResult<()> {
                    let mut tx=self.asset_tx().await?;Self::import_fence(&mut tx,tenant,claim).await?;
                    let a=Self::asset_attempt_tx(&mut tx,tenant,id).await?;if a.outcome!=UploadOutcome::Uploaded || a.version==ObjectVersion::Unknown {return Err(CoreError::Conflict("import requires known upload evidence".into()));}
                    let changed=sqlx::query("UPDATE import_uploads SET selected_attempt=$4 WHERE tenant_id=$1 AND import_id=$2 AND ordinal=$3 AND intent_id=$5 AND (selected_attempt IS NULL OR selected_attempt=$4)").bind(tenant).bind(&claim.job_id).bind(ordinal).bind(id).bind(&a.intent_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                    if changed!=1 {return Err(CoreError::Conflict("import upload handoff conflict".into()));}tx.commit().await.map_err(db_error)
                }
                async fn commit_import(&self,tenant:&str,claim:&JobClaim)->CoreResult<ImportOperation>{
                    let mut tx=self.asset_tx().await?;Self::import_fence(&mut tx,tenant,claim).await?;
                    let mut e=Self::import_execution_tx(&mut tx,tenant,&claim.job_id).await?;let p=Self::import_authorize(&mut tx,&e.authority,!e.work.media.is_empty()).await?;Self::import_fence(&mut tx,tenant,claim).await?;
                    // 独立的资产回执交接已完成，最终提交只依赖当前导入 claim。
                    let uploads=sqlx::query("SELECT u.source_key,u.selected_attempt,u.intent_id,i.asset_id,r.mime,r.size,r.sha256 FROM import_uploads u JOIN asset_upload_intents i ON i.tenant_id=u.tenant_id AND i.id=u.intent_id JOIN asset_records r ON r.tenant_id=i.tenant_id AND r.id=i.asset_id WHERE u.tenant_id=$1 AND u.import_id=$2 ORDER BY u.ordinal").bind(tenant).bind(&claim.job_id).fetch_all(&mut *tx).await.map_err(db_error)?;
                    let mut resolved=std::collections::BTreeMap::new();
                    for u in &uploads {
                        let id=u.get::<Option<String>,_>("selected_attempt").ok_or_else(||CoreError::Conflict("import upload handoff is pending".into()))?;let a=Self::asset_attempt_tx(&mut tx,tenant,&id).await?;
                        if a.intent_id!=u.get::<String,_>("intent_id") || a.outcome!=UploadOutcome::Uploaded || a.version==ObjectVersion::Unknown {return Err(CoreError::Conflict("import upload is not publishable".into()));}
                        let changed=sqlx::query("UPDATE asset_upload_intents SET published_attempt=$3 WHERE tenant_id=$1 AND id=$2 AND published_attempt IS NULL").bind(tenant).bind(&a.intent_id).bind(&id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();if changed!=1{return Err(CoreError::Conflict("import upload publication conflict".into()));}
                        resolved.insert(u.get::<String,_>("source_key"),(u.get::<String,_>("asset_id"),memoswish_protocol::AssetRef{key:a.key,url:String::new(),mime:u.get("mime"),bytes:u.get::<i64,_>("size") as u64,sha256:u.get("sha256")}));
                    }
                    for card in &mut e.work.cards {
                        let owner=card.id.clone();
                        for (slot,asset) in memoswish_core::assets::card_asset_slots_mut(card) {
                            if let Some((id,published))=resolved.get(&asset.key) {
                                *asset=published.clone();Self::asset_reference_tx(&mut tx,&p,&AssetReference{asset_id:id.clone(),owner_id:owner.clone(),slot}).await?;
                            } else {
                                // 导入包不是授权来源；提交时重查发布或现有旧卡片证据。
                                if let Some(id)=Self::import_asset_tx(&mut tx,&p,asset).await? {
                                    Self::asset_reference_tx(&mut tx,&p,&AssetReference{asset_id:id,owner_id:owner.clone(),slot}).await?;
                                }
                                asset.url.clear();
                            }
                        }
                        memoswish_core::content_validation::validate_card(card)?;
                    }
                    let deck=&e.work.deck;
                    sqlx::query("INSERT INTO decks(id,tenant_id,title,description,language,tags,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(&deck.id).bind(tenant).bind(&deck.title).bind(&deck.description).bind(&deck.language).bind(Json(&deck.tags)).bind(($ts)(&deck.created_at)).execute(&mut *tx).await.map_err(db_error)?;
                    for c in &e.work.cards {
                        sqlx::query("INSERT INTO cards(id,tenant_id,deck_id,template,revision,body,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(&c.id).bind(tenant).bind(&c.deck_id).bind(&c.template).bind(i64::from(c.revision)).bind(Json(c)).bind(($ts)(&c.created_at)).bind(($ts)(&c.updated_at)).execute(&mut *tx).await.map_err(db_error)?;
                        if e.work.auto_tts {sqlx::query("INSERT INTO import_followups(tenant_id,import_id,card_id,revision,outcome) VALUES($1,$2,$3,$4,'pending')").bind(tenant).bind(&claim.job_id).bind(&c.id).bind(i64::from(c.revision)).execute(&mut *tx).await.map_err(db_error)?;}
                    }
                    Self::import_fence(&mut tx,tenant,claim).await?;
                    sqlx::query("INSERT INTO usage_counters(tenant_id,metric,period,amount) SELECT tenant_id,metric,period,amount FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2 AND state='reserved' ON CONFLICT(tenant_id,metric,period) DO UPDATE SET amount=usage_counters.amount+excluded.amount").bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE quota_operations SET state='committed' WHERE tenant_id=$1 AND operation_id=$2 AND state='reserved'").bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    let result=serde_json::to_string(&e.work.result).map_err(|_|CoreError::internal("invalid import result"))?;
                    sqlx::query("UPDATE content_imports SET outcome='committed',result=$3,work='{}',authority=CASE WHEN $4 THEN authority ELSE '{}' END WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).bind(result).bind(e.work.auto_tts && !e.work.cards.is_empty()).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE background_jobs SET state='succeeded',result=$3,token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).bind(Json(&e.work.result)).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;Ok(ImportOperation{id:claim.job_id.clone(),outcome:"committed".into(),result:Some(e.work.result)})
                }
                async fn retry_import(&self,tenant:&str,claim:&JobClaim)->CoreResult<()> {
                    let mut tx=self.asset_tx().await?;Self::import_fence(&mut tx,tenant,claim).await?;
                    let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='uncertain' WHERE tenant_id=$1 AND outcome='in_flight' AND intent_id IN(SELECT intent_id FROM import_uploads WHERE tenant_id=$1 AND import_id=$2)").bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    // 保留次数与输入；下一次到期领取仍负责原有耗尽处置。
                    sqlx::query("UPDATE background_jobs SET state='queued',available_at_ms=$3,token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).bind(now+memoswish_core::maintenance::CADENCE_MS).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn fail_import(&self,tenant:&str,claim:&JobClaim)->CoreResult<()> {
                    let mut tx=self.asset_tx().await?;Self::import_fence(&mut tx,tenant,claim).await?;Self::import_fail_tx(&mut tx,tenant,&claim.job_id).await?;
                    let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE background_jobs SET available_at_ms=$3 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).bind(now+memoswish_core::maintenance::CADENCE_MS).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn pending_imports(&self,after:Option<(&str,&str)>)->CoreResult<Vec<(String,String)>> {
                    let (t,i)=after.unwrap_or(("",""));
                    let rows=sqlx::query(&format!("SELECT tenant_id,id FROM ({}) recovery WHERE tenant_id>$1 OR (tenant_id=$1 AND id>$2) ORDER BY tenant_id,id LIMIT 100",crate::recovery::IMPORTS.sql)).bind(t).bind(i).fetch_all(&self.pool).await.map_err(db_error)?;Ok(rows.iter().map(|r|(r.get("tenant_id"),r.get("id"))).collect())
                }
                async fn import_cleanup(&self,tenant:&str,id:&str,store:&str)->CoreResult<Vec<UploadAttempt>>{
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbCleanup);
        let result: CoreResult<_> = async {
                    let mut tx=self.asset_tx().await?;
                    let now=Self::asset_now(&mut tx).await?;
                    let ids:Vec<String>=sqlx::query_scalar(&format!("SELECT id FROM ({}) recovery WHERE tenant_id=$1 AND import_id=$2 AND store_id=$3 AND EXISTS(SELECT 1 FROM background_jobs j WHERE j.tenant_id=$1 AND j.id=$2 AND j.available_at_ms<=$4)",crate::recovery::IMPORT_CLEANUP.sql)).bind(tenant).bind(id).bind(store).bind(now).fetch_all(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    let mut out=Vec::new();for id in ids {sqlx::query("UPDATE asset_upload_attempts SET outcome='cleanup_pending' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;out.push(Self::asset_attempt_tx(&mut tx,tenant,&id).await?);}tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;Ok(out)

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
                async fn retry_import_cleanup(&self,tenant:&str,id:&str,supplied:&UploadAttempt)->CoreResult<()> {
                    let mut tx=self.asset_tx().await?;
                    let actual=Self::asset_attempt_tx(&mut tx,tenant,&supplied.id).await?;
                    Self::asset_match_attempt(&actual,supplied)?;
                    if actual.version!=supplied.version || actual.outcome!=UploadOutcome::CleanupPending {return Err(CoreError::Conflict("cleanup retry identity mismatch".into()));}
                    let now=Self::asset_now(&mut tx).await?;
                    // 精确未清理证据与终态父任务围栏，不能改写运行中导入或其他导入。
                    let changed=sqlx::query("UPDATE background_jobs SET available_at_ms=$3 WHERE tenant_id=$1 AND id=$2 AND kind='content_import' AND state IN ('succeeded','dead') AND EXISTS(SELECT 1 FROM import_uploads u WHERE u.tenant_id=$1 AND u.import_id=$2 AND u.intent_id=$4)").bind(tenant).bind(id).bind(now+memoswish_core::maintenance::CADENCE_MS).bind(&actual.intent_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                    if changed!=1 {return Err(CoreError::Conflict("cleanup retry parent mismatch".into()));}
                    tx.commit().await.map_err(db_error)
                }
                async fn import_followups(&self,tenant:&str,id:&str)->CoreResult<Vec<ImportFollowup>> {
                    let mut tx=self.asset_tx().await?;let now=Self::asset_now(&mut tx).await?;
                    let rows=sqlx::query(&format!("SELECT i.authority,f.card_id,f.revision FROM content_imports i JOIN ({}) f ON f.tenant_id=i.tenant_id AND f.import_id=i.id WHERE i.tenant_id=$1 AND i.id=$2 AND i.outcome='committed' AND EXISTS(SELECT 1 FROM background_jobs j WHERE j.tenant_id=i.tenant_id AND j.id=i.id AND j.available_at_ms<=$3) ORDER BY f.card_id",crate::recovery::IMPORT_FOLLOWUPS.sql)).bind(tenant).bind(id).bind(now).fetch_all(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    rows.into_iter().map(|r|Ok(ImportFollowup{authority:serde_json::from_str(&r.get::<String,_>("authority")).map_err(|_|CoreError::internal("invalid import authority"))?,card_id:r.get("card_id"),revision:r.get::<i64,_>("revision") as u32})).collect()
                }
                async fn import_followup(&self,tenant:&str,id:&str,card:&str,outcome:&str)->CoreResult<bool> {
                    if !matches!(outcome,"running"|"succeeded"|"failed"|"interrupted"|"retry") {return Err(CoreError::invalid("invalid import followup outcome"));}
                    let mut tx=self.asset_tx().await?;
                    // 挂载回执是不可变事实；原凭据失效不能覆盖成功，也不能丢弃已接受责任。
                    let request=format!("import:{id}:{card}");
                    let canonical:Option<Option<String>>=sqlx::query_scalar("SELECT x.receipt FROM import_followups f JOIN content_imports i ON i.tenant_id=f.tenant_id AND i.id=f.import_id JOIN tts_submission_items x ON x.tenant_id=i.tenant_id AND x.user_id=i.user_id AND x.request_id=$4 JOIN tts_requesters r ON r.tenant_id=x.tenant_id AND r.id=x.item_id AND r.card_id=f.card_id AND r.revision=f.revision WHERE f.tenant_id=$1 AND f.import_id=$2 AND f.card_id=$3").bind(tenant).bind(id).bind(card).bind(request).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    let retry=outcome=="retry";
                    let outcome=match canonical {
                        Some(Some(body))=>{
                            let receipt:memoswish_protocol::TtsAttachmentReceipt=serde_json::from_str(&body).map_err(|_|CoreError::internal("invalid attachment receipt"))?;
                            if receipt.disposition==memoswish_protocol::TtsDisposition::Attached {"succeeded"} else {"failed"}
                        },
                        Some(None)=>"running",
                        None if retry=>"pending",
                        None=>outcome,
                    };
                    let changed=sqlx::query("UPDATE import_followups SET outcome=$4 WHERE tenant_id=$1 AND import_id=$2 AND card_id=$3 AND outcome IN ('pending','running')").bind(tenant).bind(id).bind(card).bind(outcome).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                    if retry && changed==1 && matches!(outcome,"pending"|"running") {
                        let now=Self::asset_now(&mut tx).await?;
                        sqlx::query("UPDATE background_jobs SET available_at_ms=$3 WHERE tenant_id=$1 AND id=$2 AND kind='content_import' AND state='succeeded'").bind(tenant).bind(id).bind(now+memoswish_core::maintenance::CADENCE_MS).execute(&mut *tx).await.map_err(db_error)?;
                    }
                    sqlx::query("UPDATE content_imports SET authority='{}' WHERE tenant_id=$1 AND id=$2 AND NOT EXISTS(SELECT 1 FROM import_followups WHERE tenant_id=$1 AND import_id=$2 AND outcome IN ('pending','running'))").bind(tenant).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;Ok(changed==1)
                }
                async fn held_import_usage(&self,tenant:&str,period:&str)->CoreResult<i64>{
                    sqlx::query_scalar("SELECT CAST(COALESCE(SUM(amount),0) AS BIGINT) FROM quota_operations WHERE tenant_id=$1 AND period=$2 AND metric='card_writes' AND state='reserved'").bind(tenant).bind(period).fetch_one(&self.pool).await.map_err(db_error)
                }
            }
        };
    };
}
pub(crate) use imports_impl;
