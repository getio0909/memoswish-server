//! 合成、预留、上传交接与请求者挂载的双库事务。

macro_rules! speech_impl {
    ($repo:ty, $db:ty, $row:ty, $auth_lock:literal) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, Permission, Principal, Role};
            use memoswish_core::assets::*;
            use memoswish_core::tts::*;
            use memoswish_core::jobs::JobClaim;
            use sqlx::Row;
            use crate::assets::db_error;

            impl $repo {
                async fn speech_credential_current(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal, content: bool) -> CoreResult<bool> {
                    let permissions = [Permission::TtsGenerate, Permission::ContentRead, Permission::ContentWrite];
                    Self::credential_current(tx, p, &permissions[..if content {3} else {1}]).await
                }
                pub(crate) async fn credential_current(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal, permissions: &[Permission]) -> CoreResult<bool> {
                    let allows=|scopes:&[String]| permissions.iter().all(|permission|scopes.iter().any(|s|s=="*" || s==permission.as_scope()));
                    match p.via.as_str() {
                        "api_token"=>{
                            let Some(hash)=p.session_access_hash.as_deref().and_then(|s|s.strip_prefix("api:")) else {return Ok(false)};
                            let q=if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT user_id,account_generation,membership_generation,CAST(scopes AS TEXT) AS scopes,expires_at FROM api_tokens WHERE tenant_id=$1 AND token_hash=$2 AND revoked=FALSE FOR SHARE"}else{"SELECT user_id,account_generation,membership_generation,CAST(scopes AS TEXT) AS scopes,expires_at FROM api_tokens WHERE tenant_id=$1 AND token_hash=$2 AND revoked=FALSE"};
                            let Some(r)=sqlx::query(q).bind(&p.tenant_id).bind(hash).fetch_optional(&mut **tx).await.map_err(db_error)? else {return Ok(false)};
                            let now=Self::asset_now(tx).await?;
                            let expires:Option<chrono::DateTime<chrono::Utc>>=r.get("expires_at");
                            let scopes:Vec<String>=serde_json::from_str(&r.get::<String,_>("scopes")).map_err(|_|CoreError::internal("invalid stored credential scopes"))?;
                            Ok(r.get::<String,_>("user_id")==p.user_id && Some(r.get::<i64,_>("account_generation"))==p.auth_generation && Some(r.get::<i64,_>("membership_generation"))==p.membership_generation && expires.is_none_or(|e|e.timestamp_millis()>now) && allows(&scopes))
                        },
                        "mcp_oauth"=>{
                            let Some(hash)=p.session_access_hash.as_deref().and_then(|s|s.strip_prefix("oauth:")) else {return Ok(false)};
                            let q=if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT t.body,t.expires_at,g.expires_at AS grant_expiry,c.expires_at AS client_expiry FROM oauth_tokens t JOIN oauth_grants g ON g.tenant_id=t.tenant_id AND g.id=t.grant_id JOIN oauth_clients c ON c.id=g.client_id WHERE t.tenant_id=$1 AND t.hash=$2 AND t.kind='access' AND t.consumed=0 AND g.revoked=0 FOR SHARE"}else{"SELECT t.body,t.expires_at,g.expires_at AS grant_expiry,c.expires_at AS client_expiry FROM oauth_tokens t JOIN oauth_grants g ON g.tenant_id=t.tenant_id AND g.id=t.grant_id JOIN oauth_clients c ON c.id=g.client_id WHERE t.tenant_id=$1 AND t.hash=$2 AND t.kind='access' AND t.consumed=0 AND g.revoked=0"};
                            let Some(r)=sqlx::query(q).bind(&p.tenant_id).bind(hash).fetch_optional(&mut **tx).await.map_err(db_error)? else {return Ok(false)};
                            let token:memoswish_core::oauth::OAuthToken=serde_json::from_str(&r.get::<String,_>("body")).map_err(|_|CoreError::internal("invalid stored credential evidence"))?;
                            let now=Self::asset_now(tx).await?/1000;
                            Ok(token.hash==hash && token.grant.tenant_id==p.tenant_id && token.grant.user_id==p.user_id && Some(token.grant.generations.account)==p.auth_generation && Some(token.grant.generations.membership)==p.membership_generation && r.get::<i64,_>("expires_at")>now && r.get::<i64,_>("grant_expiry")>now && r.get::<i64,_>("client_expiry")>now && allows(&token.scopes) && allows(&token.grant.scopes))
                        },
                        "session"=>{
                            // 与 S21b 的生产写入共用原 access、全族注销和成员屏障。
                            match Self::session_principal_tx(tx,p).await {
                                Ok(())=>Ok(true),
                                Err(CoreError::Unauthorized(_) | CoreError::Forbidden(_))=>Ok(false),
                                Err(e)=>Err(e),
                            }
                        },
                        "jwt"=>{
                            if let Some(evidence)=p.session_access_hash.as_deref() {
                                let expiry=evidence.strip_prefix("jwt:").and_then(|s|s.parse::<i64>().ok());
                                let now=Self::asset_now(tx).await?/1000;
                                if expiry.is_none_or(|expiry|expiry<=now){return Ok(false)}
                            }
                            let Some(iat)=p.legacy_issued_at else {return Ok(false)};
                            match Self::legacy_session_tx(tx,&p.user_id,p.auth_generation,iat).await {
                                Ok(())=>Ok(true),Err(CoreError::Unauthorized(_))=>Ok(false),Err(e)=>Err(e),
                            }
                        },
                        "single_user" | "stdio"=>Ok(true),
                        // 历史 S16 行仅保留原有手动挂载语义，不制造自动提交。
                        "legacy"=>Self::speech_session_current(tx,&p.tenant_id,&p.user_id,p.auth_generation,p.membership_generation,p.session_access_hash.as_deref()).await,
                        _=>Self::speech_session_current(tx,&p.tenant_id,&p.user_id,p.auth_generation,p.membership_generation,p.session_access_hash.as_deref()).await,
                    }
                }

                async fn speech_submission_tx(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal, request_id: &str, command: Option<&str>) -> CoreResult<Option<memoswish_protocol::tts::TtsSubmission>> {
                    validate_submission_id(request_id)?;
                    if p.via=="jwt" && p.session_access_hash.as_deref().is_none_or(|s|!s.starts_with("jwt:")) {return Err(CoreError::Forbidden("legacy credential deadline evidence is missing".into()))}
                    Self::speech_authorize(tx,p,true).await?;
                    let row=sqlx::query("SELECT * FROM tts_submissions WHERE tenant_id=$1 AND user_id=$2 AND request_id=$3")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(request_id).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let Some(row)=row else {return Ok(None)};
                    if Some(row.get::<i64,_>("account_generation"))!=p.auth_generation || Some(row.get::<i64,_>("membership_generation"))!=p.membership_generation {
                        return Err(CoreError::Forbidden("submission owner generation changed".into()));
                    }
                    if command.is_some_and(|hash| hash!=row.get::<String,_>("command_hash")) {
                        return Err(CoreError::Conflict("submission request ID has a different command".into()));
                    }
                    let rows=sqlx::query("SELECT i.item_id,i.receipt,r.card_id,r.revision FROM tts_submission_items i JOIN tts_requesters r ON r.tenant_id=i.tenant_id AND r.id=i.item_id WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.request_id=$3 ORDER BY i.position")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(request_id).fetch_all(&mut **tx).await.map_err(db_error)?;
                    let items=rows.iter().map(|r| Ok(memoswish_protocol::tts::TtsSubmissionItem {
                        item_id:r.get("item_id"), card_id:r.get("card_id"), expected_revision:r.get::<i64,_>("revision") as u32,
                        receipt:r.get::<Option<String>,_>("receipt").map(|v|serde_json::from_str(&v).map_err(|_|CoreError::internal("invalid stored attachment receipt"))).transpose()?,
                    })).collect::<CoreResult<Vec<_>>>()?;
                    Ok(Some(memoswish_protocol::tts::TtsSubmission {request_id:request_id.into(),complete:items.iter().all(|i|i.receipt.is_some()),items}))
                }

                async fn attach_speech_tx(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, request: &str) -> CoreResult<memoswish_protocol::Card> {
                    // 内容 writer 也锁租户；在读取卡片前串行化删除、编辑与挂载。
                    let lock=if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT id FROM tenants WHERE id=$1 FOR UPDATE"}else{"SELECT id FROM tenants WHERE id=$1"};
                    sqlx::query(lock).bind(tenant).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let r=sqlx::query("SELECT * FROM tts_requesters WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(request).fetch_optional(&mut **tx).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("synthesis requester".into()))?;
                    if !Self::speech_requester_current(tx,tenant,&r).await? {
                        sqlx::query("UPDATE tts_requesters SET outcome='requester_revoked' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(request).execute(&mut **tx).await.map_err(db_error)?;
                        return Err(CoreError::Forbidden("synthesis requester is no longer authorized".into()));
                    }
                    let card_id:Option<String>=r.get("card_id");let card_id=card_id.ok_or_else(||CoreError::invalid("synthesis has no card target"))?;
                    let row=sqlx::query("SELECT CAST(body AS TEXT) AS body FROM cards WHERE tenant_id=$1 AND id=$2 AND NOT EXISTS(SELECT 1 FROM deleted_card_ids d WHERE d.tenant_id=$1 AND d.card_id=$2)").bind(tenant).bind(&card_id).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let Some(row)=row else {
                        sqlx::query("UPDATE tts_requesters SET outcome='not_found' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(request).execute(&mut **tx).await.map_err(db_error)?;
                        return Err(CoreError::NotFound("synthesis card".into()));
                    };
                    let mut card:memoswish_protocol::Card=serde_json::from_str(&row.get::<String,_>("body")).map_err(|_|CoreError::internal("invalid stored card"))?;
                    let outcome:String=r.get("outcome");
                    if outcome=="attached" {return Ok(card);}
                    if outcome!="published" {return Err(CoreError::Conflict("synthesis requester is not attachable".into()));}
                    if i64::from(card.revision)!=r.get::<i64,_>("revision") {
                        sqlx::query("UPDATE tts_requesters SET outcome='conflict' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(request).execute(&mut **tx).await.map_err(db_error)?;
                        return Err(CoreError::Conflict(format!("card changed; current revision {}",card.revision)));
                    }
                    let synthesis:String=r.get("synthesis_id");
                    let track=Self::speech_track_tx(tx,tenant,&synthesis).await?.ok_or_else(||CoreError::Unavailable("synthesis publication metadata is unavailable".into()))?;
                    card.revision=memoswish_core::content::next_revision(Some(card.revision),card.revision)?;
                    card.tts=Some(track);card.updated_at=chrono::Utc::now();memoswish_core::content_validation::validate_card(&card)?;
                    sqlx::query("UPDATE cards SET body=$3,revision=$4,updated_at=$5 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&card_id).bind(sqlx::types::Json(&card)).bind(i64::from(card.revision)).bind(card.updated_at).execute(&mut **tx).await.map_err(db_error)?;
                    // 卡片槽是租户共享，替换所有旧槽；请求者独立结果引用保持不变。
                    sqlx::query("DELETE FROM asset_references WHERE tenant_id=$1 AND owner_id=$2 AND slot='tts_card'").bind(tenant).bind(&card_id).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("INSERT INTO asset_references(tenant_id,asset_id,user_id,requester_generation,account_generation,owner_id,slot) SELECT $1,i.asset_id,$3,$4,$5,$2,'tts_card' FROM asset_upload_intents i JOIN tts_syntheses s ON s.tenant_id=i.tenant_id AND s.upload_id=i.id WHERE s.tenant_id=$1 AND s.id=$6").bind(tenant).bind(&card_id).bind(r.get::<String,_>("user_id")).bind(r.get::<i64,_>("membership_generation")).bind(r.get::<i64,_>("account_generation")).bind(&synthesis).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE tts_requesters SET outcome='attached' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(request).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(card)
                }

                async fn accept_speech_tx(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal, work: &SpeechWork, target: Option<(&str,u32)>, limit: Option<i64>, request_id: Option<String>) -> CoreResult<SpeechRequest> {
                    work.validate()?; validate_asset_id(&p.tenant_id)?;
                    if let Some(fence)=&work.privacy {
                        if fence.principal!=*p {return Err(CoreError::Forbidden("privacy requester mismatch".into()));}
                        Self::privacy_fence_tx(tx,&p.tenant_id,fence).await?;
                    }
                    if let Some(out)=&work.legacy_output {
                        let spec=AssetSpec{mime:out.mime.clone(),size:out.audio.len() as i64,sha256:memoswish_core::ids::sha256_hex(&out.audio)};spec.validate()?;
                        SpeechMetadata { alignment_quality: out.alignment_quality, audio_kind: out.audio_kind, provenance: out.provenance.clone(),extension:out.extension.clone(),duration_ms:out.duration_ms,words:out.words.clone()}.validate()?;
                        if work.amount!=0 || out.mime!="audio/wav" || out.extension!="wav" || out.audio.is_empty(){return Err(CoreError::invalid("invalid legacy adoption"));}
                    }
                    if let Some((id,revision)) = target { validate_asset_id(id)?; if revision==0 { return Err(CoreError::invalid("invalid card revision")); } }
                    if limit.is_some_and(|v| v<0) { return Err(CoreError::invalid("invalid synthesis quota limit")); }
                    let identity = work.identity()?;
                    Self::speech_authorize(tx,p,target.is_some()).await?;
                    let existing: Option<String> = sqlx::query_scalar("SELECT id FROM background_jobs WHERE tenant_id=$1 AND kind='tts_synthesis' AND idempotency_key=$2")
                        .bind(&p.tenant_id).bind(&identity).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let id = if let Some(id) = existing { id } else {
                        let now = Self::asset_now(tx).await?;
                        let period = chrono::DateTime::from_timestamp_millis(now).ok_or_else(||CoreError::internal("invalid database clock"))?.format("%Y-%m").to_string();
                        let used: i64 = sqlx::query_scalar("SELECT CAST(COALESCE(SUM(amount),0) AS BIGINT) FROM usage_counters WHERE tenant_id=$1 AND metric='tts_chars' AND period=$2")
                            .bind(&p.tenant_id).bind(&period).fetch_one(&mut **tx).await.map_err(db_error)?;
                        let held: i64 = sqlx::query_scalar("SELECT CAST(COALESCE(SUM(amount),0) AS BIGINT) FROM quota_operations WHERE tenant_id=$1 AND metric='tts_chars' AND period=$2 AND state='reserved'")
                            .bind(&p.tenant_id).bind(&period).fetch_one(&mut **tx).await.map_err(db_error)?;
                        if used.checked_add(held).and_then(|v|v.checked_add(work.amount)).is_none_or(|v|limit.is_some_and(|limit|v>limit)) {
                            return Err(CoreError::QuotaExceeded("tts_chars monthly limit reached".into()));
                        }
                        let id = memoswish_core::ids::new_id();
                        sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES($1,$2,'tts_synthesis',$3,$4,5,$5)")
                            .bind(&p.tenant_id).bind(&id).bind(&identity).bind(sqlx::types::Json(serde_json::json!({}))).bind(now).execute(&mut **tx).await.map_err(db_error)?;
                        sqlx::query("INSERT INTO tts_syntheses(tenant_id,id,work) VALUES($1,$2,$3)")
                            .bind(&p.tenant_id).bind(&id).bind(serde_json::to_string(work).map_err(|_|CoreError::internal("invalid synthesis work"))?).execute(&mut **tx).await.map_err(db_error)?;
                        if let Some(out)=&work.legacy_output {
                            let meta=SpeechMetadata { alignment_quality: out.alignment_quality, audio_kind: out.audio_kind, provenance: out.provenance.clone(),extension:out.extension.clone(),duration_ms:out.duration_ms,words:out.words.clone()};
                            sqlx::query("UPDATE tts_syntheses SET audio=$3,metadata=$4,legacy=1 WHERE tenant_id=$1 AND id=$2").bind(&p.tenant_id).bind(&id).bind(&out.audio).bind(serde_json::to_string(&meta).map_err(|_|CoreError::internal("invalid legacy metadata"))?).execute(&mut **tx).await.map_err(db_error)?;
                        }
                        sqlx::query("INSERT INTO quota_operations(tenant_id,operation_id,metric,period,amount,state) VALUES($1,$2,'tts_chars',$3,$4,'reserved')")
                            .bind(&p.tenant_id).bind(&id).bind(period).bind(work.amount).execute(&mut **tx).await.map_err(db_error)?;
                        id
                    };
                    // 同一请求者、世代、目标和版本复用终态；S17 再扩展外部提交回执。
                    let identity = (&id,&p.user_id,p.auth_generation,p.membership_generation,&p.session_access_hash,target);
                    // 保留现有 opaque/API/MCP 回执身份，旧 JWT 另外绑定原始签发时间。
                    let request_identity = match p.legacy_issued_at {
                        Some(iat) => serde_json::to_string(&(identity,iat)),
                        None => serde_json::to_string(&identity),
                    }.map_err(|_|CoreError::internal("invalid synthesis requester"))?;
                    let request_id = request_id.unwrap_or_else(|| memoswish_core::ids::sha256_hex(request_identity.as_bytes()));
                    let published = Self::speech_track_tx(tx,&p.tenant_id,&id).await?.is_some();
                    // 交接后的失败取决于上传阶段，已发布结果优先于遗留清理任务的耗尽。
                    let state: String = sqlx::query_scalar("SELECT j.state FROM tts_syntheses s JOIN background_jobs j ON j.tenant_id=s.tenant_id AND j.id=COALESCE(s.upload_id,s.id) WHERE s.tenant_id=$1 AND s.id=$2")
                        .bind(&p.tenant_id).bind(&id).fetch_one(&mut **tx).await.map_err(db_error)?;
                    let outcome = if published { "published" } else if state=="dead" { "failed" } else { "pending" };
                    if outcome=="failed" {
                        // 重放同时收敛旧版本在耗尽后误建的 pending 请求者。
                        sqlx::query("UPDATE tts_requesters SET outcome='failed' WHERE tenant_id=$1 AND synthesis_id=$2 AND outcome='pending'")
                            .bind(&p.tenant_id).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    let rows = sqlx::query("SELECT r.*,j.error AS failure FROM tts_requesters r JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.synthesis_id WHERE r.tenant_id=$1 AND r.id=$2")
                        .bind(&p.tenant_id).bind(&request_id).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    if let Some(r) = rows { return Ok(Self::speech_request_row(&r)); }
                    sqlx::query("INSERT INTO tts_requesters(tenant_id,id,synthesis_id,user_id,account_generation,membership_generation,content_permission,card_id,revision,outcome,session_access_hash,legacy_issued_at,credential_via) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
                        .bind(&p.tenant_id).bind(&request_id).bind(&id).bind(&p.user_id).bind(p.auth_generation).bind(p.membership_generation).bind(if target.is_some(){1_i64}else{0_i64}).bind(target.map(|v|v.0)).bind(target.map(|v|i64::from(v.1))).bind(outcome).bind(&p.session_access_hash).bind(p.legacy_issued_at).bind(&p.via).execute(&mut **tx).await.map_err(db_error)?;
                    if published {
                        let asset: String = sqlx::query_scalar("SELECT i.asset_id FROM asset_upload_intents i JOIN tts_syntheses s ON s.tenant_id=i.tenant_id AND s.upload_id=i.id WHERE s.tenant_id=$1 AND s.id=$2")
                            .bind(&p.tenant_id).bind(&id).fetch_one(&mut **tx).await.map_err(db_error)?;
                        Self::asset_reference_tx(tx,p,&AssetReference{asset_id:asset,owner_id:request_id.clone(),slot:"tts_result".into()}).await?;
                    }
                    let failure:Option<String>=sqlx::query_scalar("SELECT error FROM background_jobs WHERE tenant_id=$1 AND id=$2")
                        .bind(&p.tenant_id).bind(&id).fetch_one(&mut **tx).await.map_err(db_error)?;
                    Ok(SpeechRequest{id:request_id,synthesis_id:id,outcome:outcome.into(),failure:failure.as_deref().and_then(SpeechFailure::from_code)})
                }

                pub(crate) async fn speech_revoke_member(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, user: &str) -> CoreResult<()> {
                    sqlx::query("UPDATE background_jobs SET state='dead',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id IN (SELECT id FROM bgm_publications WHERE tenant_id=$1 AND user_id=$2 AND outcome='pending')")
                        .bind(tenant).bind(user).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("DELETE FROM bgm_publications WHERE tenant_id=$1 AND user_id=$2")
                        .bind(tenant).bind(user).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE tts_requesters SET outcome='requester_revoked' WHERE tenant_id=$1 AND user_id=$2")
                        .bind(tenant).bind(user).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }

                pub(crate) async fn speech_erase_tenant(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str) -> CoreResult<()> {
                    sqlx::query("DELETE FROM bgm_publications WHERE tenant_id=$1").bind(tenant).execute(&mut **tx).await.map_err(db_error)?;
                    // 与生命周期共用注册锁；撤销请求者并终止两个阶段，晚到结果不能重新发布。
                    sqlx::query("UPDATE tts_requesters SET outcome='requester_revoked' WHERE tenant_id=$1")
                        .bind(tenant).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE background_jobs SET state='dead',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND (id IN (SELECT id FROM tts_syntheses WHERE tenant_id=$1) OR id IN (SELECT upload_id FROM tts_syntheses WHERE tenant_id=$1))")
                        .bind(tenant).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='uncertain' WHERE tenant_id=$1 AND outcome='in_flight' AND intent_id IN (SELECT upload_id FROM tts_syntheses WHERE tenant_id=$1)")
                        .bind(tenant).execute(&mut **tx).await.map_err(db_error)?;
                    // 未调用 provider 才能释放；已知及未知外部调用的账本和精确对象证据留待核对。
                    sqlx::query("UPDATE quota_operations SET state='released' WHERE tenant_id=$1 AND state='reserved' AND operation_id IN (SELECT id FROM tts_syntheses WHERE tenant_id=$1) AND NOT EXISTS(SELECT 1 FROM tts_provider_attempts p WHERE p.tenant_id=$1 AND p.synthesis_id=quota_operations.operation_id)")
                        .bind(tenant).execute(&mut **tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE tts_syntheses SET audio=NULL,metadata=NULL,work='{}' WHERE tenant_id=$1")
                        .bind(tenant).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }

                async fn speech_authorize(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal, content: bool) -> CoreResult<()> {
                    p.require(Permission::TtsGenerate)?;
                    if content { p.require(Permission::ContentRead)?; p.require(Permission::ContentWrite)?; }
                    let role: Option<String> = sqlx::query_scalar(concat!("SELECT m.role FROM tenants t JOIN tenant_memberships m ON m.tenant_id=t.id JOIN account_auth_epochs a ON a.user_id=m.user_id WHERE t.id=$1 AND m.user_id=$2 AND a.generation=$3 AND m.generation=$4 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id)", $auth_lock))
                        .bind(&p.tenant_id).bind(&p.user_id).bind(p.auth_generation).bind(p.membership_generation)
                        .fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let allowed = role.map(|r| Role::parse(&r).map(|r| r.allows(Permission::TtsGenerate) && (!content || (r.allows(Permission::ContentWrite) && r.allows(Permission::ContentRead))))).transpose()?.unwrap_or(false);
                    if !allowed { return Err(CoreError::Forbidden("synthesis requester is no longer authorized".into())); }
                    if !Self::speech_credential_current(tx,p,content).await? {
                        return Err(CoreError::Forbidden("synthesis requester credential is no longer authorized".into()));
                    }

                    Ok(())
                }
                async fn speech_tenant(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str)->CoreResult<()> {
                    let query=if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT t.id FROM tenants t WHERE t.id=$1 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id) FOR SHARE"} else {"SELECT t.id FROM tenants t WHERE t.id=$1 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id)"};
                    let alive:Option<String>=sqlx::query_scalar(query).bind(tenant).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    if alive.is_none(){return Err(CoreError::Forbidden("synthesis tenant is erased".into()));} Ok(())
                }
                async fn speech_fence(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, claim: &JobClaim) -> CoreResult<()> {
                    let now = Self::asset_now(tx).await?;
                    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs j WHERE tenant_id=$1 AND id=$2 AND token=$3 AND state='running' AND lease_until_ms>$4 AND ((j.kind='tts_synthesis' AND EXISTS(SELECT 1 FROM tts_syntheses s WHERE s.tenant_id=j.tenant_id AND s.id=j.id)) OR (j.kind='asset_upload' AND (EXISTS(SELECT 1 FROM tts_syntheses s WHERE s.tenant_id=j.tenant_id AND s.upload_id=j.id) OR EXISTS(SELECT 1 FROM bgm_publications b WHERE b.tenant_id=j.tenant_id AND b.id=j.id AND b.outcome='pending'))))")
                        .bind(tenant).bind(&claim.job_id).bind(&claim.token).bind(now).fetch_one(&mut **tx).await.map_err(db_error)?;
                    if live != 1 { return Err(CoreError::Conflict("synthesis claim expired or replaced".into())); }
                    Ok(())
                }
                fn speech_request_row(r: &$row) -> SpeechRequest {
                    SpeechRequest { id:r.get("id"), synthesis_id:r.get("synthesis_id"), outcome:r.get("outcome"), failure:r.get::<Option<String>,_>("failure").as_deref().and_then(SpeechFailure::from_code) }
                }
                async fn speech_track_tx(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, id: &str) -> CoreResult<Option<memoswish_protocol::TtsTrack>> {
                    let row = sqlx::query("SELECT s.work,s.metadata,r.mime,r.size,r.sha256,a.object_key FROM tts_syntheses s JOIN asset_upload_intents i ON i.tenant_id=s.tenant_id AND i.id=s.upload_id JOIN asset_records r ON r.tenant_id=i.tenant_id AND r.id=i.asset_id JOIN asset_upload_attempts a ON a.tenant_id=i.tenant_id AND a.id=i.published_attempt WHERE s.tenant_id=$1 AND s.id=$2 AND a.outcome='uploaded' AND a.version_kind<>'unknown'")
                        .bind(tenant).bind(id).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    if let Some(row)=&row {
                        let work:SpeechWork=serde_json::from_str(&row.get::<String,_>("work")).map_err(CoreError::internal)?;
                        if let Some(fence)=&work.privacy {Self::privacy_fence_tx(tx,tenant,fence).await?;}
                    }
                    row.map(|r| {
                        let work: SpeechWork = serde_json::from_str(&r.get::<String,_>("work")).map_err(|_| CoreError::internal("invalid stored synthesis"))?;
                        let meta: SpeechMetadata = serde_json::from_str(&r.get::<String,_>("metadata")).map_err(|_| CoreError::internal("invalid stored synthesis metadata"))?;
                        Ok(memoswish_protocol::TtsTrack { alignment_quality: meta.alignment_quality, audio_kind: meta.audio_kind, provenance: meta.provenance, audio: memoswish_protocol::AssetRef {key:r.get("object_key"),url:String::new(),mime:r.get("mime"),bytes:r.get::<i64,_>("size") as u64,sha256:r.get("sha256")},text:work.request.text,language:work.request.language,voice:work.request.voice,engine:work.engine,duration_ms:meta.duration_ms,words:meta.words })
                    }).transpose()
                }
                // 注册锁已由 asset_tx 持有，旋转、撤销和世代变化不能穿过本次检查。
                async fn speech_session_current(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, user: &str, account: Option<i64>, membership: Option<i64>, hash: Option<&str>) -> CoreResult<bool> {
                    let Some(hash) = hash else { return Ok(true); };
                    let (a, consumed) = match Self::session_read(tx, hash, false).await {
                        Ok(a) => a,
                        Err(CoreError::Unauthorized(_)) => return Ok(false),
                        Err(e) => return Err(e),
                    };
                    if consumed || a.family.user_id != user || Some(a.family.generation) != account || a.credential.tenant_id.as_deref() != Some(tenant) || a.credential.membership_generation != membership { return Ok(false); }
                    let now = Self::session_clock(tx).await?;
                    match Self::session_validate(tx, &a, now).await {
                        Ok(()) => Ok(true),
                        Err(CoreError::Unauthorized(_) | CoreError::Forbidden(_)) => Ok(false),
                        Err(e) => Err(e),
                    }
                }
                async fn speech_requester_current(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, r: &$row) -> CoreResult<bool> {
                    let role: Option<String> = sqlx::query_scalar(concat!("SELECT m.role FROM tenant_memberships m JOIN account_auth_epochs a ON a.user_id=m.user_id JOIN tenants t ON t.id=m.tenant_id WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.generation=$3 AND a.generation=$4 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id)", $auth_lock))
                        .bind(tenant).bind(r.get::<String,_>("user_id")).bind(r.get::<i64,_>("membership_generation")).bind(r.get::<i64,_>("account_generation")).fetch_optional(&mut **tx).await.map_err(db_error)?;
                    let content = r.get::<i64,_>("content_permission") == 1;
                    let principal=Principal{tenant_id:tenant.into(),user_id:r.get("user_id"),role:Role::Owner,scopes:None,via:if r.get::<String,_>("credential_via")=="legacy" && r.get::<Option<i64>,_>("legacy_issued_at").is_some(){"jwt".into()}else{r.get("credential_via")},session_access_hash:r.get("session_access_hash"),auth_generation:Some(r.get("account_generation")),membership_generation:Some(r.get("membership_generation")),legacy_issued_at:r.get("legacy_issued_at")};
                    if !Self::speech_credential_current(tx,&principal,content).await? {return Ok(false)}
                    Ok(role.map(|v| Role::parse(&v).map(|r| r.allows(Permission::TtsGenerate) && (!content || (r.allows(Permission::ContentRead) && r.allows(Permission::ContentWrite))))).transpose()?.unwrap_or(false))
                }
            }

            #[async_trait::async_trait]
            impl SpeechRepo for $repo {
                async fn speech_submission(&self,p:&Principal,request_id:&str,command:Option<&str>)->CoreResult<Option<memoswish_protocol::tts::TtsSubmission>> {
                    let mut tx=self.asset_tx().await?;
                    let result=Self::speech_submission_tx(&mut tx,p,request_id,command).await?;
                    tx.commit().await.map_err(db_error)?;Ok(result)
                }
                async fn submit_speech(&self,p:&Principal,request_id:&str,command_hash:&str,targets:&[SpeechSubmissionTarget],limit:Option<i64>)->CoreResult<memoswish_protocol::tts::TtsSubmission> {
                    validate_submission_id(request_id)?;
                    if command_hash.len()!=64 || !command_hash.bytes().all(|b|b.is_ascii_hexdigit()) {return Err(CoreError::invalid("invalid submission command hash"));}
                    let mut tx=self.asset_tx().await?;
                    // 在任何凭据行锁之前取得内容父锁，避免与 API Token 撤销反向等待。
                    let lock=if <$db as sqlx::Database>::NAME=="PostgreSQL" {"SELECT id FROM tenants WHERE id=$1 FOR UPDATE"}else{"SELECT id FROM tenants WHERE id=$1"};
                    sqlx::query(lock).bind(&p.tenant_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    if let Some(replay)=Self::speech_submission_tx(&mut tx,p,request_id,Some(command_hash)).await? {tx.commit().await.map_err(db_error)?;return Ok(replay)}
                    let mut ids=std::collections::HashSet::new();
                    if targets.is_empty() || targets.len()>100 || targets.iter().any(|t|(t.revision==0 || t.revision==u32::MAX) || !ids.insert(&t.card_id)) {return Err(CoreError::invalid("provide 1..=100 unique card targets with positive revisions"));}
                    // 捕获的文本来自该版本，绝不把旧快照合成为新版本的附件。
                    for target in targets {
                        validate_asset_id(&target.card_id)?;
                        let current:Option<i64>=sqlx::query_scalar("SELECT revision FROM cards WHERE tenant_id=$1 AND id=$2 AND NOT EXISTS(SELECT 1 FROM deleted_card_ids d WHERE d.tenant_id=$1 AND d.card_id=$2)").bind(&p.tenant_id).bind(&target.card_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                        match current {
                            None=>return Err(CoreError::NotFound("submission card".into())),
                            Some(v) if v!=i64::from(target.revision)=>return Err(CoreError::Conflict("submission card changed before admission".into())),
                            _=>{},
                        }
                    }
                    sqlx::query("INSERT INTO tts_submissions(tenant_id,user_id,request_id,command_hash,account_generation,membership_generation) VALUES($1,$2,$3,$4,$5,$6)")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(request_id).bind(command_hash).bind(p.auth_generation).bind(p.membership_generation).execute(&mut *tx).await.map_err(db_error)?;
                    for (position,target) in targets.iter().enumerate() {
                        let item=memoswish_core::ids::new_id();
                        Self::accept_speech_tx(&mut tx,p,&target.work,Some((&target.card_id,target.revision)),limit,Some(item.clone())).await?;
                        sqlx::query("INSERT INTO tts_submission_items(tenant_id,user_id,request_id,position,item_id) VALUES($1,$2,$3,$4,$5)")
                            .bind(&p.tenant_id).bind(&p.user_id).bind(request_id).bind(position as i64).bind(&item).execute(&mut *tx).await.map_err(db_error)?;
                    }
                    let result=Self::speech_submission_tx(&mut tx,p,request_id,Some(command_hash)).await?.ok_or_else(||CoreError::internal("submission admission missing"))?;
                    tx.commit().await.map_err(db_error)?;Ok(result)
                }
                async fn pending_speech_attachments(&self,after:Option<(&str,&str)>,limit:i64)->CoreResult<Vec<(String,String)>> {
                    if !(1..=100).contains(&limit){return Err(CoreError::invalid("invalid attachment recovery page size"));}
                    let (tenant,item)=after.unwrap_or(("",""));
                    let rows=sqlx::query(&format!("SELECT tenant_id,item_id FROM ({}) recovery WHERE tenant_id>$1 OR (tenant_id=$1 AND item_id>$2) ORDER BY tenant_id,item_id LIMIT $3",crate::recovery::ATTACHMENTS.sql))
                        .bind(tenant).bind(item).bind(limit).fetch_all(&self.pool).await.map_err(db_error)?;
                    Ok(rows.iter().map(|r|(r.get("tenant_id"),r.get("item_id"))).collect())
                }
                async fn resolve_speech_attachment(&self,tenant:&str,item:&str)->CoreResult<()> {
                    use memoswish_protocol::tts::{TtsAttachmentReceipt,TtsDisposition};
                    let mut tx=self.asset_tx().await?;
                    let row=sqlx::query("SELECT r.*,i.receipt FROM tts_submission_items i JOIN tts_requesters r ON r.tenant_id=i.tenant_id AND r.id=i.item_id WHERE i.tenant_id=$1 AND i.item_id=$2")
                        .bind(tenant).bind(item).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("submission item".into()))?;
                    if row.get::<Option<String>,_>("receipt").is_some(){tx.commit().await.map_err(db_error)?;return Ok(())}
                    let outcome:String=row.get("outcome");
                    let mut resulting_revision=None;
                    let disposition=match outcome.as_str() {
                        "pending"=>{
                            if Self::speech_requester_current(&mut tx,tenant,&row).await? {tx.commit().await.map_err(db_error)?;return Ok(())}
                            sqlx::query("UPDATE tts_requesters SET outcome='requester_revoked' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(item).execute(&mut *tx).await.map_err(db_error)?;
                            TtsDisposition::RequesterRevoked
                        },
                        "failed"=>TtsDisposition::Failed,
                        "requester_revoked"=>TtsDisposition::RequesterRevoked,
                        "conflict"=>TtsDisposition::Conflict,
                        "not_found"=>TtsDisposition::NotFound,
                        "published"=>match Self::attach_speech_tx(&mut tx,tenant,item).await {
                            Ok(card)=>{resulting_revision=Some(card.revision);TtsDisposition::Attached},
                            Err(CoreError::Forbidden(_))=>TtsDisposition::RequesterRevoked,
                            Err(CoreError::NotFound(_))=>TtsDisposition::NotFound,
                            Err(CoreError::Conflict(_))=>TtsDisposition::Conflict,
                            Err(e)=>return Err(e),
                        },
                        _=>return Err(CoreError::internal("invalid submission item state")),
                    };
                    let asset_id:Option<String>=sqlx::query_scalar("SELECT i.asset_id FROM tts_syntheses s JOIN asset_upload_intents i ON i.tenant_id=s.tenant_id AND i.id=s.upload_id WHERE s.tenant_id=$1 AND s.id=$2 AND i.published_attempt IS NOT NULL")
                        .bind(tenant).bind(row.get::<String,_>("synthesis_id")).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    let receipt=TtsAttachmentReceipt{item_id:item.into(),card_id:row.get("card_id"),expected_revision:row.get::<i64,_>("revision") as u32,disposition,resulting_revision,asset_id};
                    sqlx::query("UPDATE tts_submission_items SET receipt=$3 WHERE tenant_id=$1 AND item_id=$2 AND receipt IS NULL")
                        .bind(tenant).bind(item).bind(serde_json::to_string(&receipt).map_err(|_|CoreError::internal("invalid attachment receipt"))?).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }

                async fn accept_speech(&self, p: &Principal, work: &SpeechWork, target: Option<(&str,u32)>, limit: Option<i64>) -> CoreResult<SpeechRequest> {
                    let mut tx = self.asset_tx().await?;
                    let r = Self::accept_speech_tx(&mut tx,p,work,target,limit,None).await?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(r)
                }
                async fn speech_request(&self, tenant:&str,id:&str)->CoreResult<SpeechRequest>{
                    let r=sqlx::query("SELECT r.*,j.error AS failure FROM tts_requesters r JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.synthesis_id WHERE r.tenant_id=$1 AND r.id=$2").bind(tenant).bind(id).fetch_optional(&self.pool).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("synthesis requester".into()))?;
                    Ok(Self::speech_request_row(&r))
                }
                async fn speech_work(&self, tenant:&str,id:&str)->CoreResult<SpeechWork>{
                    let work: String=sqlx::query_scalar("SELECT work FROM tts_syntheses WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).fetch_optional(&self.pool).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("synthesis".into()))?;
                    serde_json::from_str(&work).map_err(|_|CoreError::internal("invalid stored synthesis work"))
                }
                async fn retire_invalid_speech(&self,tenant:&str,id:&str,policy:&memoswish_protocol::PrivacyPolicy,external:bool)->CoreResult<bool>{
                    use memoswish_protocol::tts::{TtsAttachmentReceipt,TtsDisposition};
                    let mut tx=self.asset_tx().await?;
                    let row=sqlx::query("SELECT work,upload_id FROM tts_syntheses WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let work:SpeechWork=serde_json::from_str(&row.get::<String,_>("work")).map_err(CoreError::internal)?;
                    let upload:Option<String>=row.get("upload_id");
                    let published:i64=sqlx::query_scalar("SELECT COUNT(*) FROM asset_upload_intents WHERE tenant_id=$1 AND id=$2 AND published_attempt IS NOT NULL")
                        .bind(tenant).bind(&upload).fetch_one(&mut *tx).await.map_err(db_error)?;
                    // 本切片只终结未发布工作，已发布数据由分类保留切片处理。
                    if published!=0 {tx.commit().await.map_err(db_error)?;return Ok(false)}
                    let valid=match &work.privacy {
                        Some(fence) if fence.policy!=*policy=>Err(CoreError::Forbidden("speech privacy policy changed".into())),
                        Some(fence)=>Self::privacy_fence_tx(&mut tx,tenant,fence).await,
                        None if external=>Err(CoreError::Forbidden("external speech has no privacy evidence".into())),
                        None=>Ok(()),
                    };
                    match valid {
                        Ok(())=>{tx.commit().await.map_err(db_error)?;return Ok(false)},
                        Err(CoreError::Forbidden(_) | CoreError::Unauthorized(_) | CoreError::NotFound(_))=>{},
                        Err(e)=>return Err(e),
                    }
                    // 撤销旧 claim，晚到 provider/PUT 不能发布；精确对象回执仍可持久化。
                    sqlx::query("UPDATE background_jobs SET state='dead',error=NULL,token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND (id=$2 OR id=$3)")
                        .bind(tenant).bind(id).bind(&upload).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE tts_syntheses SET audio=NULL,metadata=NULL WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    // uncertain/returned attempt 与对象清理责任不因请求终态被删除或结清。
                    sqlx::query("UPDATE quota_operations SET state='released' WHERE tenant_id=$1 AND operation_id=$2 AND state='reserved' AND NOT EXISTS(SELECT 1 FROM tts_provider_attempts WHERE tenant_id=$1 AND synthesis_id=$2)")
                        .bind(tenant).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE tts_requesters SET outcome='failed' WHERE tenant_id=$1 AND synthesis_id=$2 AND outcome='pending'")
                        .bind(tenant).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    let items=sqlx::query("SELECT r.* FROM tts_requesters r JOIN tts_submission_items i ON i.tenant_id=r.tenant_id AND i.item_id=r.id WHERE r.tenant_id=$1 AND r.synthesis_id=$2 AND r.outcome='failed' AND i.receipt IS NULL")
                        .bind(tenant).bind(id).fetch_all(&mut *tx).await.map_err(db_error)?;
                    for item in items {
                        let receipt=TtsAttachmentReceipt{item_id:item.get("id"),card_id:item.get("card_id"),expected_revision:item.get::<i64,_>("revision") as u32,disposition:TtsDisposition::Failed,resulting_revision:None,asset_id:None};
                        sqlx::query("UPDATE tts_submission_items SET receipt=$3 WHERE tenant_id=$1 AND item_id=$2 AND receipt IS NULL")
                            .bind(tenant).bind(&receipt.item_id).bind(serde_json::to_string(&receipt).map_err(CoreError::internal)?).execute(&mut *tx).await.map_err(db_error)?;
                    }
                    tx.commit().await.map_err(db_error)?;Ok(true)
                }
                async fn claim_speech(&self,tenant:&str,id:&str,lease_ms:i64)->CoreResult<Option<JobClaim>>{
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbClaim);
        let result: CoreResult<_> = async {
                    if !(1..=300_000).contains(&lease_ms){return Err(CoreError::invalid("invalid synthesis lease"));}
                    let mut tx=self.asset_tx().await?;
                    let now=Self::asset_now(&mut tx).await?;
                    let r=sqlx::query(&format!("SELECT j.* FROM ({}) j WHERE j.tenant_id=$1 AND j.id=$2 AND j.kind IN ('tts_synthesis','asset_upload') AND CAST(j.payload AS TEXT)='{{}}' AND ((j.state='queued' AND j.available_at_ms<=$3) OR (j.state='running' AND j.lease_until_ms<=$3)) AND (EXISTS(SELECT 1 FROM tts_syntheses s WHERE s.tenant_id=j.tenant_id AND s.id=j.id) OR EXISTS(SELECT 1 FROM tts_syntheses s WHERE s.tenant_id=j.tenant_id AND s.upload_id=j.id))",crate::recovery::JOBS.sql))
                        .bind(tenant).bind(id).bind(now).fetch_optional(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    let Some(r)=r else {tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;return Ok(None)};
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='uncertain' WHERE tenant_id=$1 AND intent_id=$2 AND outcome='in_flight'").bind(tenant).bind(id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    if r.get::<i64,_>("attempts")>=r.get::<i64,_>("max_attempts") {
                        sqlx::query("UPDATE background_jobs SET state='dead',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        sqlx::query("UPDATE tts_requesters SET outcome='failed' WHERE tenant_id=$1 AND outcome='pending' AND synthesis_id IN (SELECT s.id FROM tts_syntheses s WHERE s.tenant_id=$1 AND (s.id=$2 OR s.upload_id=$2))").bind(tenant).bind(id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        sqlx::query("UPDATE quota_operations SET state='released' WHERE tenant_id=$1 AND operation_id=$2 AND state='reserved' AND NOT EXISTS(SELECT 1 FROM tts_provider_attempts p WHERE p.tenant_id=$1 AND p.synthesis_id=$2)").bind(tenant).bind(id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;return Ok(None);
                    }
                    let token=memoswish_core::ids::new_id();
                    sqlx::query("UPDATE background_jobs SET state='running',attempts=attempts+1,token=$3,worker='tts',lease_until_ms=$4 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).bind(&token).bind(now+lease_ms).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    Ok(Some(JobClaim{job_id:id.into(),token}))

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
                async fn heartbeat_speech(&self,tenant:&str,claim:&JobClaim,lease_ms:i64)->CoreResult<()>{
                    if !(1..=300_000).contains(&lease_ms){return Err(CoreError::invalid("invalid synthesis lease"));}
                    let mut tx=self.asset_tx().await?;Self::speech_fence(&mut tx,tenant,claim).await?;
                    let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=$4 WHERE tenant_id=$1 AND id=$2 AND token=$3").bind(tenant).bind(&claim.job_id).bind(&claim.token).bind(now+lease_ms).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn begin_provider(&self,tenant:&str,claim:&JobClaim)->CoreResult<()>{
                    let mut tx=self.asset_tx().await?;Self::speech_tenant(&mut tx,tenant).await?;Self::speech_fence(&mut tx,tenant,claim).await?;
                    let work:SpeechWork = serde_json::from_str(&sqlx::query_scalar::<_,String>("SELECT work FROM tts_syntheses WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(db_error)?).map_err(CoreError::internal)?;
                    if let Some(fence)=&work.privacy {Self::privacy_fence_tx(&mut tx,tenant,fence).await?;}
                    // 开始外部尝试后，先前的本地预检分类不再描述本次失败。
                    sqlx::query("UPDATE background_jobs SET error=NULL WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("INSERT INTO tts_provider_attempts(tenant_id,synthesis_id,claim_token,outcome) VALUES($1,$2,$3,'uncertain')").bind(tenant).bind(&claim.job_id).bind(&claim.token).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn fail_speech(&self,tenant:&str,claim:&JobClaim,failure:Option<SpeechFailure>)->CoreResult<()>{
                    let mut tx=self.asset_tx().await?;Self::speech_fence(&mut tx,tenant,claim).await?;
                    // 业务记录约束已接纳的其他执行者；崩溃过期路径不写入此节流。
                    let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE background_jobs SET error=$3,state=CASE WHEN attempts>=max_attempts THEN 'dead' ELSE 'queued' END,available_at_ms=$4,token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).bind(failure.map(|f|f.error().code())).bind(now+memoswish_core::maintenance::CADENCE_MS).execute(&mut *tx).await.map_err(db_error)?;
                    // 没有 provider 调用证据的终态才可释放；uncertain 不因耗尽消失。
                    sqlx::query("UPDATE quota_operations SET state='released' WHERE tenant_id=$1 AND operation_id=$2 AND state='reserved' AND EXISTS(SELECT 1 FROM background_jobs j WHERE j.tenant_id=$1 AND j.id=$2 AND j.state='dead') AND NOT EXISTS(SELECT 1 FROM tts_provider_attempts p WHERE p.tenant_id=$1 AND p.synthesis_id=$2)").bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE tts_requesters SET outcome='failed' WHERE tenant_id=$1 AND outcome='pending' AND synthesis_id IN (SELECT s.id FROM tts_syntheses s JOIN background_jobs j ON j.tenant_id=s.tenant_id AND (j.id=s.id OR j.id=s.upload_id) WHERE s.tenant_id=$1 AND j.id=$2 AND j.state='dead')").bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn materialize_speech(&self,tenant:&str,claim:&JobClaim,bytes:&[u8],spec:&AssetSpec,metadata:&SpeechMetadata,legacy:bool)->CoreResult<()>{
                    spec.validate()?;metadata.validate()?;
                    if bytes.is_empty() || bytes.len() as i64!=spec.size || memoswish_core::ids::sha256_hex(bytes)!=spec.sha256 || !spec.mime.starts_with("audio/"){return Err(CoreError::invalid("invalid synthesis output"));}
                    let mut tx=self.asset_tx().await?;Self::speech_tenant(&mut tx,tenant).await?;Self::speech_fence(&mut tx,tenant,claim).await?;
                    let calls:i64=sqlx::query_scalar("SELECT COUNT(*) FROM tts_provider_attempts WHERE tenant_id=$1 AND synthesis_id=$2").bind(tenant).bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if legacy && calls!=0{return Err(CoreError::Conflict("provider work cannot be adopted without charge".into()));}
                    if !legacy {
                        let changed=sqlx::query("UPDATE tts_provider_attempts SET outcome='returned' WHERE tenant_id=$1 AND synthesis_id=$2 AND claim_token=$3 AND outcome='uncertain'").bind(tenant).bind(&claim.job_id).bind(&claim.token).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                        if changed!=1{return Err(CoreError::Conflict("provider attempt evidence missing".into()));}
                    }
                    let stored:String=sqlx::query_scalar("SELECT work FROM tts_syntheses WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let work:SpeechWork=serde_json::from_str(&stored).map_err(|_|CoreError::internal("invalid stored synthesis"))?;
                    if let Some(fence)=&work.privacy {Self::privacy_fence_tx(&mut tx,tenant,fence).await?;}
                    let chars=work.request.text.chars().count() as u32;
                    if metadata.words.iter().any(|w|w.char_end>chars){return Err(CoreError::invalid("synthesis timing exceeds text"));}
                    let upload=memoswish_core::ids::new_id();let asset=memoswish_core::ids::new_id();let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES($1,$2,'asset_upload',$3,$4,5,$5)").bind(tenant).bind(&upload).bind(&claim.job_id).bind(sqlx::types::Json(serde_json::json!({}))).bind(now).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("INSERT INTO asset_records(tenant_id,id,mime,size,sha256) VALUES($1,$2,$3,$4,$5)").bind(tenant).bind(&asset).bind(&spec.mime).bind(spec.size).bind(&spec.sha256).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("INSERT INTO asset_upload_intents(tenant_id,id,asset_id,account_generation) VALUES($1,$2,$3,0)").bind(tenant).bind(&upload).bind(&asset).execute(&mut *tx).await.map_err(db_error)?;
                    let changed=sqlx::query("UPDATE tts_syntheses SET upload_id=$3,metadata=$4,audio=$5,legacy=$6 WHERE tenant_id=$1 AND id=$2 AND upload_id IS NULL").bind(tenant).bind(&claim.job_id).bind(&upload).bind(serde_json::to_string(metadata).map_err(|_|CoreError::internal("invalid output metadata"))?).bind(bytes).bind(if legacy{1_i64}else{0_i64}).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                    if changed!=1{return Err(CoreError::Conflict("synthesis already materialized".into()));}
                    sqlx::query("UPDATE background_jobs SET state='succeeded',error=NULL,token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn legacy_speech_output(&self,tenant:&str,id:&str)->CoreResult<Option<TtsOutput>> {
                    let r=sqlx::query("SELECT audio,metadata FROM tts_syntheses WHERE tenant_id=$1 AND id=$2 AND legacy=1 AND upload_id IS NULL AND audio IS NOT NULL").bind(tenant).bind(id).fetch_optional(&self.pool).await.map_err(db_error)?;
                    r.map(|r|{let m:SpeechMetadata=serde_json::from_str(&r.get::<String,_>("metadata")).map_err(|_|CoreError::internal("invalid legacy metadata"))?;Ok(TtsOutput{ alignment_quality: m.alignment_quality, audio_kind: m.audio_kind, provenance: m.provenance,audio:r.get("audio"),mime:"audio/wav".into(),extension:m.extension,duration_ms:m.duration_ms,words:m.words})}).transpose()
                }
                async fn speech_upload(&self,tenant:&str,id:&str)->CoreResult<Option<(String,Vec<u8>)>>{
                    let row=sqlx::query("SELECT upload_id,audio FROM tts_syntheses WHERE tenant_id=$1 AND id=$2 AND upload_id IS NOT NULL AND audio IS NOT NULL").bind(tenant).bind(id).fetch_optional(&self.pool).await.map_err(db_error)?;
                    Ok(row.map(|r|(r.get("upload_id"),r.get("audio"))))
                }
                async fn publish_speech(&self,tenant:&str,claim:&JobClaim,attempt_id:&str)->CoreResult<()>{
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbWrite);
        let result: CoreResult<_> = async {
                    let mut tx=self.asset_tx().await?;Self::speech_tenant(&mut tx,tenant).await?;Self::speech_fence(&mut tx,tenant,claim).await?;Self::asset_fence(&mut tx,tenant,claim).await?;
                    let a=Self::asset_attempt_tx(&mut tx,tenant,attempt_id).await?;
                    if a.intent_id!=claim.job_id || a.claim_token!=claim.token || a.outcome!=UploadOutcome::Uploaded || a.version==ObjectVersion::Unknown {return Err(CoreError::Conflict("synthesis upload is not publishable".into()));}
                    let alive:i64=sqlx::query_scalar("SELECT COUNT(*) FROM tenants t WHERE t.id=$1 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id)").bind(tenant).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    if alive!=1{return Err(CoreError::Forbidden("synthesis tenant is erased".into()));}
                    let s=sqlx::query("SELECT id,legacy,work FROM tts_syntheses WHERE tenant_id=$1 AND upload_id=$2").bind(tenant).bind(&claim.job_id).fetch_optional(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?.ok_or_else(||CoreError::NotFound("synthesis upload".into()))?;
                    let synthesis:String=s.get("id");
                    let work:SpeechWork=serde_json::from_str(&s.get::<String,_>("work")).map_err(CoreError::internal)?;
                    if let Some(fence)=&work.privacy {Self::privacy_fence_tx(&mut tx,tenant,fence).await?;}
                    let changed=sqlx::query("UPDATE asset_upload_intents SET published_attempt=$3 WHERE tenant_id=$1 AND id=$2 AND published_attempt IS NULL").bind(tenant).bind(&claim.job_id).bind(attempt_id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?.rows_affected();
                    if changed!=1{return Err(CoreError::Conflict("synthesis already published".into()));}
                    let q=sqlx::query("SELECT amount,period,state FROM quota_operations WHERE tenant_id=$1 AND operation_id=$2").bind(tenant).bind(&synthesis).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    if q.get::<String,_>("state")!="reserved"{return Err(CoreError::Conflict("synthesis reservation is not held".into()));}
                    let legacy=s.get::<i64,_>("legacy")==1;
                    if !legacy {
                        sqlx::query("INSERT INTO usage_counters(tenant_id,metric,period,amount) VALUES($1,'tts_chars',$2,$3) ON CONFLICT(tenant_id,metric,period) DO UPDATE SET amount=usage_counters.amount+excluded.amount").bind(tenant).bind(q.get::<String,_>("period")).bind(q.get::<i64,_>("amount")).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    }
                    sqlx::query("UPDATE quota_operations SET state=$3 WHERE tenant_id=$1 AND operation_id=$2").bind(tenant).bind(&synthesis).bind(if legacy{"released"}else{"committed"}).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    let asset:String=sqlx::query_scalar("SELECT asset_id FROM asset_upload_intents WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    let requesters=sqlx::query("SELECT * FROM tts_requesters WHERE tenant_id=$1 AND synthesis_id=$2 AND outcome='pending'").bind(tenant).bind(&synthesis).fetch_all(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    for r in requesters {
                        let current=Self::speech_requester_current(&mut tx,tenant,&r).await?;
                        let id:String=r.get("id");
                        sqlx::query("UPDATE tts_requesters SET outcome=$3 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&id).bind(if current{"published"}else{"requester_revoked"}).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        if current {
                            sqlx::query("INSERT INTO asset_references(tenant_id,asset_id,user_id,requester_generation,account_generation,owner_id,slot) VALUES($1,$2,$3,$4,$5,$6,'tts_result')").bind(tenant).bind(&asset).bind(r.get::<String,_>("user_id")).bind(r.get::<i64,_>("membership_generation")).bind(r.get::<i64,_>("account_generation")).bind(&id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        }
                    }
                    // 保留旧未知 attempt；成功发布不等于清理责任已经完成。
                    sqlx::query("UPDATE background_jobs SET state=CASE WHEN EXISTS(SELECT 1 FROM asset_upload_attempts u WHERE u.tenant_id=$1 AND u.intent_id=$2 AND u.id<>$3 AND u.outcome<>'cleaned') THEN CASE WHEN attempts>=max_attempts THEN 'dead' ELSE 'queued' END ELSE 'succeeded' END,token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).bind(attempt_id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    sqlx::query("UPDATE tts_syntheses SET audio=NULL WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&synthesis).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
                async fn speech_track(&self,tenant:&str,id:&str)->CoreResult<Option<memoswish_protocol::TtsTrack>>{
                    let mut tx=self.asset_tx().await?;let track=Self::speech_track_tx(&mut tx,tenant,id).await?;tx.commit().await.map_err(db_error)?;Ok(track)
                }
                async fn attach_speech(&self,tenant:&str,request:&str)->CoreResult<memoswish_protocol::Card>{
                    let mut tx=self.asset_tx().await?;
                    let result = Self::attach_speech_tx(&mut tx,tenant,request).await;
                    match &result {
                        Ok(_) | Err(CoreError::Forbidden(_) | CoreError::NotFound(_) | CoreError::Conflict(_)) => tx.commit().await.map_err(db_error)?,
                        _ => {},
                    }
                    result
                }
                async fn pending_speech(&self,after:Option<(&str,&str)>,limit:i64)->CoreResult<Vec<(String,String)>>{
                    if !(1..=100).contains(&limit){return Err(CoreError::invalid("invalid synthesis recovery page size"));}
                    let (tenant,id)=after.unwrap_or(("",""));
                    let rows=sqlx::query(&format!("SELECT tenant_id,id FROM ({}) recovery WHERE tenant_id>$1 OR (tenant_id=$1 AND id>$2) ORDER BY tenant_id,id LIMIT $3",crate::recovery::SPEECH.sql)).bind(tenant).bind(id).bind(limit).fetch_all(&self.pool).await.map_err(db_error)?;
                    Ok(rows.iter().map(|r|(r.get("tenant_id"),r.get("id"))).collect())
                }
                async fn held_speech_usage(&self,tenant:&str,period:&str)->CoreResult<(i64,i64)>{
                    let held:i64=sqlx::query_scalar("SELECT CAST(COALESCE(SUM(amount),0) AS BIGINT) FROM quota_operations WHERE tenant_id=$1 AND metric='tts_chars' AND period=$2 AND state='reserved'").bind(tenant).bind(period).fetch_one(&self.pool).await.map_err(db_error)?;
                    let uncertain:i64=sqlx::query_scalar("SELECT CAST(COALESCE(SUM(q.amount),0) AS BIGINT) FROM quota_operations q WHERE q.tenant_id=$1 AND q.metric='tts_chars' AND q.period=$2 AND q.state='reserved' AND EXISTS(SELECT 1 FROM tts_provider_attempts p WHERE p.tenant_id=q.tenant_id AND p.synthesis_id=q.operation_id AND p.outcome='uncertain')").bind(tenant).bind(period).fetch_one(&self.pool).await.map_err(db_error)?;
                    Ok((held,uncertain))
                }
            }
        };
    };
}
pub(crate) use speech_impl;
