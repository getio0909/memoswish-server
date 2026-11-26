//! 暂存、原授权、目录 CAS、精确资产引用与结果均在共用事务边界内。
macro_rules! bgm_impl {
    ($repo:ty, $db:ty, $row:ty) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, Permission, Principal};
            use memoswish_core::{assets::*, bgm::*, imports::ImportAuthority, jobs::JobClaim};
            use memoswish_protocol::{AssetRef, BgmTrack};
            use sqlx::Row;
            use crate::assets::db_error;
            impl $repo {
                async fn bgm_authorize(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal, read: bool) -> CoreResult<()> {
                    Self::asset_authorize(tx, p).await?;
                    let permissions = if read { vec![Permission::MediaWrite, Permission::MediaRead] } else { vec![Permission::MediaWrite] };
                    for permission in &permissions { p.require(*permission)?; }
                    if !Self::credential_current(tx, p, &permissions).await? {
                        return Err(CoreError::Forbidden("BGM original credential is no longer authorized".into()));
                    }
                    Ok(())
                }
            }
            #[async_trait::async_trait]
            impl BgmPublicationRepo for $repo {
                async fn bgm_request(&self, p: &Principal, request: &str, command: &str) -> CoreResult<Option<String>> {
                    validate_asset_id(request)?; validate_asset_id(command)?;
                    let mut tx=self.asset_tx().await?; Self::bgm_authorize(&mut tx,p,false).await?;
                    let row=sqlx::query("SELECT id,command_hash FROM bgm_publications WHERE tenant_id=$1 AND user_id=$2 AND request_id=$3").bind(&p.tenant_id).bind(&p.user_id).bind(request).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    if row.as_ref().is_some_and(|r|r.get::<String,_>("command_hash")!=command) {return Err(CoreError::Conflict("BGM request identity conflict".into()));}
                    tx.commit().await.map_err(db_error)?;Ok(row.map(|r|r.get("id")))
                }
                async fn accept_bgm(&self, p: &Principal, request: &str, track: &BgmTrack, bytes: &[u8], expected: Option<u32>, command: &str, read_source: bool) -> CoreResult<String> {
                    validate_track(track)?; validate_asset_id(request)?;
                    if expected == Some(0) || bytes.is_empty() || bytes.len() > 10*1024*1024 || track.asset.bytes != bytes.len() as u64 || track.asset.sha256 != memoswish_core::ids::sha256_hex(bytes) {
                        return Err(CoreError::invalid("invalid BGM publication input"));
                    }
                    validate_asset_id(command)?;
                    let mut tx=self.asset_tx().await?;
                    Self::bgm_authorize(&mut tx,p,read_source).await?;
                    let old=sqlx::query("SELECT id,command_hash FROM bgm_publications WHERE tenant_id=$1 AND user_id=$2 AND request_id=$3").bind(&p.tenant_id).bind(&p.user_id).bind(request).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    if let Some(row)=old {
                        if row.get::<String,_>("command_hash")!=command {return Err(CoreError::Conflict("BGM request identity conflict".into()));}
                        let id=row.get("id");tx.commit().await.map_err(db_error)?;return Ok(id);
                    }
                    let id=memoswish_core::ids::new_id(); let asset=memoswish_core::ids::new_id(); let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES($1,$2,'asset_upload',$2,$3,$4,$5,5,$6)")
                        .bind(&p.tenant_id).bind(&id).bind(sqlx::types::Json(serde_json::json!({}))).bind(&p.user_id).bind(p.membership_generation).bind(now).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("INSERT INTO asset_records(tenant_id,id,mime,size,sha256) VALUES($1,$2,$3,$4,$5)").bind(&p.tenant_id).bind(&asset).bind(&track.asset.mime).bind(bytes.len() as i64).bind(&track.asset.sha256).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("INSERT INTO asset_upload_intents(tenant_id,id,asset_id,account_generation) VALUES($1,$2,$3,$4)").bind(&p.tenant_id).bind(&id).bind(&asset).bind(p.auth_generation).execute(&mut *tx).await.map_err(db_error)?;
                    let authority=BgmAuthority { original: ImportAuthority::capture(p,None), read_source };
                    sqlx::query("INSERT INTO bgm_publications(tenant_id,id,user_id,request_id,command_hash,authority,track,expected_revision,audio) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                        .bind(&p.tenant_id).bind(&id).bind(&p.user_id).bind(request).bind(command).bind(serde_json::to_string(&authority).map_err(CoreError::internal)?).bind(serde_json::to_string(track).map_err(CoreError::internal)?).bind(expected.map(i64::from)).bind(bytes).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?; Ok(id)
                }
                async fn bgm_result(&self, tenant: &str, id: &str) -> CoreResult<Option<BgmTrack>> {
                    let row=sqlx::query("SELECT outcome,result FROM bgm_publications WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).fetch_optional(&self.pool).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("BGM publication".into()))?;
                    match row.get::<String,_>("outcome").as_str() {
                        "published" => Ok(Some(serde_json::from_str(&row.get::<String,_>("result")).map_err(CoreError::internal)?)),
                        "rejected" => {
                            let failure=row.get::<Option<String>,_>("result").map(|s|serde_json::from_str::<BgmFailure>(&s).map_err(CoreError::internal)).transpose()?.unwrap_or(BgmFailure::Exhausted);
                            Err(failure.error())
                        },
                        _ => Ok(None),
                    }
                }
                async fn bgm_stage(&self, tenant: &str, id: &str) -> CoreResult<Option<Vec<u8>>> {
                    sqlx::query_scalar("SELECT audio FROM bgm_publications WHERE tenant_id=$1 AND id=$2 AND outcome='pending'").bind(tenant).bind(id).fetch_optional(&self.pool).await.map_err(db_error).map(Option::flatten)
                }
                async fn claim_bgm(&self, tenant: &str, id: &str, lease_ms: i64) -> CoreResult<Option<JobClaim>> {
                    if !(1..=300_000).contains(&lease_ms) {return Err(CoreError::invalid("invalid BGM lease duration"));}
                    let mut tx=self.asset_tx().await?;let now=Self::asset_now(&mut tx).await?;
                    let row=sqlx::query("SELECT j.attempts,j.max_attempts,b.authority FROM background_jobs j JOIN bgm_publications b ON b.tenant_id=j.tenant_id AND b.id=j.id WHERE j.tenant_id=$1 AND j.id=$2 AND b.outcome='pending' AND j.kind='asset_upload' AND ((j.state='queued' AND j.available_at_ms<=$3) OR (j.state='running' AND j.lease_until_ms<=$3) OR (j.state='dead' AND j.attempts>=j.max_attempts))")
                        .bind(tenant).bind(id).bind(now).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    let Some(row)=row else {tx.commit().await.map_err(db_error)?;return Ok(None)};
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='uncertain' WHERE tenant_id=$1 AND intent_id=$2 AND outcome='in_flight'").bind(tenant).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    if row.get::<i64,_>("attempts")>=row.get::<i64,_>("max_attempts") {
                        sqlx::query("UPDATE bgm_publications SET outcome='rejected',audio=NULL,authority='{}' WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                        sqlx::query("UPDATE background_jobs SET state='dead',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                        tx.commit().await.map_err(db_error)?;return Ok(None);
                    }
                    let authority:BgmAuthority=serde_json::from_str(&row.get::<String,_>("authority")).map_err(CoreError::internal)?;
                    match Self::bgm_authorize(&mut tx,&authority.original.principal(),authority.read_source).await {
                        Ok(())=>{},
                        Err(CoreError::Forbidden(_) | CoreError::Unauthorized(_))=>{
                            sqlx::query("UPDATE bgm_publications SET outcome='rejected',audio=NULL,authority='{}',result=$3 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).bind(serde_json::to_string(&BgmFailure::RequesterRevoked).map_err(CoreError::internal)?).execute(&mut *tx).await.map_err(db_error)?;
                            sqlx::query("UPDATE background_jobs SET state='dead',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                            tx.commit().await.map_err(db_error)?;return Ok(None);
                        },
                        Err(e)=>return Err(e),
                    }
                    let token=memoswish_core::ids::new_id();
                    sqlx::query("UPDATE background_jobs SET state='running',attempts=attempts+1,token=$3,worker='bgm',lease_until_ms=$4 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(id).bind(&token).bind(now+lease_ms).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;Ok(Some(JobClaim{job_id:id.into(),token}))
                }
                async fn publish_bgm(&self, tenant: &str, claim: &JobClaim, attempt: &str) -> CoreResult<()> {
                    let mut tx=self.asset_tx().await?;Self::asset_fence(&mut tx,tenant,claim).await?;
                    let row=sqlx::query("SELECT * FROM bgm_publications WHERE tenant_id=$1 AND id=$2 AND outcome='pending'").bind(tenant).bind(&claim.job_id).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or_else(||CoreError::Conflict("BGM publication is terminal".into()))?;
                    let a=Self::asset_attempt_tx(&mut tx,tenant,attempt).await?;
                    if a.intent_id!=claim.job_id || a.claim_token!=claim.token || a.outcome!=UploadOutcome::Uploaded || a.version==ObjectVersion::Unknown {return Err(CoreError::Conflict("BGM upload is not publishable".into()));}
                    let authority:BgmAuthority=serde_json::from_str(&row.get::<String,_>("authority")).map_err(CoreError::internal)?;
                    let p=authority.original.principal();
                    let mut track:BgmTrack=serde_json::from_str(&row.get::<String,_>("track")).map_err(CoreError::internal)?;
                    let current:Option<i64>=sqlx::query_scalar("SELECT revision FROM bgm_tracks WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&track.id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    let expected:Option<i64>=row.get("expected_revision");
                    let authority_result=Self::bgm_authorize(&mut tx,&p,authority.read_source).await;
                    let authorized=match authority_result {Ok(())=>true, Err(CoreError::Forbidden(_) | CoreError::Unauthorized(_))=>false, Err(e)=>return Err(e)};
                    if !authorized || (expected.is_some() && expected!=current) {
                        let failure=if !authorized { BgmFailure::RequesterRevoked } else { current.map(|r| BgmFailure::Revision(r as u32)).unwrap_or(BgmFailure::NotFound) };
                        sqlx::query("UPDATE bgm_publications SET outcome='rejected',audio=NULL,authority='{}',result=$3 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).bind(serde_json::to_string(&failure).map_err(CoreError::internal)?).execute(&mut *tx).await.map_err(db_error)?;
                        sqlx::query("UPDATE background_jobs SET state='dead',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                        tx.commit().await.map_err(db_error)?;return Err(failure.error());
                    }
                    track.revision=memoswish_core::content::next_revision(expected.map(|v|v as u32),current.unwrap_or(0) as u32)?;
                    let asset:String=sqlx::query_scalar("SELECT asset_id FROM asset_upload_intents WHERE tenant_id=$1 AND id=$2 AND published_attempt IS NULL").bind(tenant).bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    track.asset=AssetRef{key:a.key,url:String::new(),mime:track.asset.mime,bytes:track.asset.bytes,sha256:track.asset.sha256};
                    let body=serde_json::to_string(&track).map_err(CoreError::internal)?;
                    sqlx::query("INSERT INTO bgm_tracks(tenant_id,id,revision,body) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=excluded.revision,body=excluded.body")
                        .bind(tenant).bind(&track.id).bind(i64::from(track.revision)).bind(sqlx::types::Json(&track)).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE asset_upload_intents SET published_attempt=$3 WHERE tenant_id=$1 AND id=$2 AND published_attempt IS NULL").bind(tenant).bind(&claim.job_id).bind(attempt).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("DELETE FROM asset_references WHERE tenant_id=$1 AND owner_id=$2 AND slot='bgm_catalog'").bind(tenant).bind(&track.id).execute(&mut *tx).await.map_err(db_error)?;
                    Self::asset_reference_tx(&mut tx,&p,&AssetReference{asset_id:asset.clone(),owner_id:track.id.clone(),slot:"bgm_catalog".into()}).await?;
                    // 目录替换后，旧请求的不可变结果仍保留其精确资产引用。
                    Self::asset_reference_tx(&mut tx,&p,&AssetReference{asset_id:asset,owner_id:claim.job_id.clone(),slot:"bgm_result".into()}).await?;
                    sqlx::query("UPDATE bgm_publications SET outcome='published',result=$3,audio=NULL,authority='{}' WHERE tenant_id=$1 AND id=$2 AND outcome='pending'").bind(tenant).bind(&claim.job_id).bind(body).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE background_jobs SET state=CASE WHEN EXISTS(SELECT 1 FROM asset_upload_attempts a JOIN asset_upload_intents i ON i.tenant_id=a.tenant_id AND i.id=a.intent_id WHERE a.tenant_id=$1 AND a.intent_id=$2 AND a.id<>i.published_attempt AND a.outcome<>'cleaned') THEN CASE WHEN attempts>=max_attempts THEN 'dead' ELSE 'queued' END ELSE 'succeeded' END,token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn pending_bgm(&self, after: Option<(&str,&str)>, limit: i64) -> CoreResult<Vec<(String,String)>> {
                    if !(1..=100).contains(&limit) {return Err(CoreError::invalid("invalid BGM recovery page size"));}
                    let (tenant,id)=after.unwrap_or(("",""));
                    let candidates=crate::recovery::BGM.at("0");
                    let query=format!("SELECT tenant_id,id FROM ({candidates}) recovery WHERE (tenant_id>$1 OR (tenant_id=$1 AND id>$2)) ORDER BY tenant_id,id LIMIT $3");
                    let rows=sqlx::query(&query).bind(tenant).bind(id).bind(limit).fetch_all(&self.pool).await.map_err(db_error)?;
                    Ok(rows.iter().map(|r|(r.get("tenant_id"),r.get("id"))).collect())
                }
            }
        };
    };
}
pub(crate) use bgm_impl;
