//! 双库共用资产事务；沿用既有撤销锁顺序，锁内读取数据库时钟。

pub(crate) fn db_error(_: sqlx::Error) -> memoswish_core::CoreError {
    // SQL/provider 原文可能携带敏感输入，不保存到任务或错误链。
    memoswish_core::CoreError::internal("asset persistence operation failed")
}

#[path = "tts_publication.rs"]
pub(crate) mod tts_publication;

#[path = "bgm_publication.rs"]
pub(crate) mod bgm_publication;

macro_rules! asset_impl {
    ($repo:ty, $db:ty, $row:ty, $clock:literal, $auth_lock:literal) => {
        crate::assets::bgm_publication::bgm_impl!($repo, $db, $row);
        crate::assets::tts_publication::speech_impl!($repo, $db, $row, $auth_lock);
        const _: () = {
            use memoswish_core::assets::*;
            use memoswish_core::jobs::*;
            use memoswish_core::{CoreError, CoreResult, Permission, Principal, Role};
            use sqlx::Row;
            use crate::assets::db_error;

            impl $repo {
                pub(crate) async fn asset_tx(&self) -> CoreResult<sqlx::Transaction<'_, $db>> {
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbWrite);
        let result: CoreResult<_> = async {
                    let mut tx = self.pool.begin().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    // 与账户撤销、成员变更和擦除使用同一锁；SQLite 首条写入避免读锁升级。
                    sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                        .execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    Ok(tx)

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }

                async fn asset_authorize(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal) -> CoreResult<()> {
                    p.require(Permission::MediaWrite)?;
                    validate_asset_id(&p.tenant_id)?;
                    let row = sqlx::query(concat!("SELECT m.role FROM tenants t JOIN tenant_memberships m ON m.tenant_id=t.id JOIN account_auth_epochs a ON a.user_id=m.user_id WHERE t.id=$1 AND m.user_id=$2 AND a.generation=$3 AND m.generation=$4 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id)", $auth_lock))
                        .bind(&p.tenant_id).bind(&p.user_id).bind(p.auth_generation).bind(p.membership_generation)
                        .fetch_optional(&mut **tx).await.map_err(db_error)?
                        .ok_or_else(|| CoreError::Forbidden("asset requester is no longer authorized".into()))?;
                    if !Role::parse(&row.get::<String,_>("role"))?.allows(Permission::MediaWrite) {
                        return Err(CoreError::Forbidden("asset requester lacks current media permission".into()));
                    }
                    Ok(())
                }

                pub(crate) async fn asset_now(tx: &mut sqlx::Transaction<'_, $db>) -> CoreResult<i64> {
                    sqlx::query_scalar($clock).fetch_one(&mut **tx).await.map_err(db_error)
                }

                async fn asset_fence(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, claim: &JobClaim) -> CoreResult<()> {
                    let now = Self::asset_now(tx).await?;
                    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE tenant_id=$1 AND id=$2 AND kind='asset_upload' AND state='running' AND token=$3 AND lease_until_ms>$4")
                        .bind(tenant).bind(&claim.job_id).bind(&claim.token).bind(now)
                        .fetch_one(&mut **tx).await.map_err(db_error)?;
                    if live != 1 { return Err(CoreError::Conflict("asset job claim expired or replaced".into())); }
                    Ok(())
                }

                fn asset_intent_row(r: &$row) -> AssetIntent {
                    AssetIntent { id:r.get("id"), asset_id:r.get("asset_id"), spec:AssetSpec {mime:r.get("mime"),size:r.get("size"),sha256:r.get("sha256")}, published_attempt:r.get("published_attempt") }
                }

                fn asset_attempt_row(r: &$row) -> CoreResult<UploadAttempt> {
                    let kind: String = r.get("version_kind");
                    let version = match kind.as_str() {
                        "unknown" => ObjectVersion::Unknown,
                        "unversioned" => ObjectVersion::Unversioned,
                        "version" => ObjectVersion::VersionId(r.get("version_id")),
                        _ => return Err(CoreError::internal("invalid stored version kind")),
                    };
                    let outcome: String = r.get("outcome");
                    let outcome = match outcome.as_str() {
                        "in_flight" => UploadOutcome::InFlight,
                        "uploaded" => UploadOutcome::Uploaded,
                        "uncertain" => UploadOutcome::Uncertain,
                        "cleanup_pending" => UploadOutcome::CleanupPending,
                        "cleaned" => UploadOutcome::Cleaned,
                        _ => return Err(CoreError::internal("invalid stored upload outcome")),
                    };
                    Ok(UploadAttempt {id:r.get("id"),intent_id:r.get("intent_id"),key:r.get("object_key"),store_id:r.get("store_id"),claim_token:r.get("claim_token"),outcome,version})
                }

                pub(crate) async fn asset_attempt_tx(tx:&mut sqlx::Transaction<'_, $db>, tenant:&str, id:&str) -> CoreResult<UploadAttempt> {
                    let row = sqlx::query("SELECT * FROM asset_upload_attempts WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(id).fetch_optional(&mut **tx).await.map_err(db_error)?
                        .ok_or_else(||CoreError::NotFound("upload attempt".into()))?;
                    Self::asset_attempt_row(&row)
                }

                fn asset_match_attempt(actual:&UploadAttempt, supplied:&UploadAttempt) -> CoreResult<()> {
                    if actual.intent_id != supplied.intent_id || actual.store_id != supplied.store_id || actual.key != supplied.key || actual.claim_token != supplied.claim_token {
                        return Err(CoreError::Conflict("upload receipt identity mismatch".into()));
                    }
                    Ok(())
                }

                pub(crate) async fn asset_reference_tx(tx:&mut sqlx::Transaction<'_, $db>, p:&Principal, reference:&AssetReference) -> CoreResult<()> {
                    validate_asset_id(&reference.asset_id)?;
                    validate_asset_id(&reference.owner_id)?;
                    validate_asset_id(&reference.slot)?;
                    let existing = sqlx::query("SELECT asset_id,requester_generation,account_generation FROM asset_references WHERE tenant_id=$1 AND user_id=$2 AND owner_id=$3 AND slot=$4")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(&reference.owner_id).bind(&reference.slot)
                        .fetch_optional(&mut **tx).await.map_err(db_error)?;
                    if let Some(row) = existing {
                        if row.get::<String,_>("asset_id") == reference.asset_id && Some(row.get::<i64,_>("requester_generation")) == p.membership_generation && Some(row.get::<i64,_>("account_generation")) == p.auth_generation { return Ok(()); }
                        return Err(CoreError::Conflict("asset reference slot already occupied".into()));
                    }
                    sqlx::query("INSERT INTO asset_references(tenant_id,asset_id,user_id,requester_generation,account_generation,owner_id,slot) VALUES($1,$2,$3,$4,$5,$6,$7)")
                        .bind(&p.tenant_id).bind(&reference.asset_id).bind(&p.user_id).bind(p.membership_generation).bind(p.auth_generation).bind(&reference.owner_id).bind(&reference.slot)
                        .execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }
            }

            #[async_trait::async_trait]
            impl AssetJobRepo for $repo {
                async fn asset_job(&self, tenant:&str, job:&str) -> CoreResult<Option<DurableJob>> {
                    let row = sqlx::query("SELECT id,state,attempts,max_attempts FROM background_jobs WHERE tenant_id=$1 AND id=$2 AND kind='asset_upload'")
                        .bind(tenant).bind(job).fetch_optional(&self.pool).await.map_err(db_error)?;
                    Ok(row.map(|r|DurableJob{id:r.get("id"),state:r.get("state"),attempts:r.get("attempts"),max_attempts:r.get("max_attempts")}))
                }

                async fn claim_asset_job(&self, tenant:&str, worker:&str, lease_ms:i64) -> CoreResult<Option<JobClaim>> {
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbClaim);
        let result: CoreResult<_> = async {
                    validate_asset_id(tenant)?; validate_asset_id(worker)?;
                    if !(1..=300_000).contains(&lease_ms) { return Err(CoreError::invalid("invalid asset lease duration")); }
                    let mut tx = self.asset_tx().await?;
                    let now = Self::asset_now(&mut tx).await?;
                    let row = sqlx::query(&format!("SELECT j.id,j.attempts,j.max_attempts FROM ({}) j JOIN asset_upload_intents i ON i.tenant_id=j.tenant_id AND i.id=j.id WHERE j.tenant_id=$1 AND j.kind='asset_upload' AND ((j.state='queued' AND j.available_at_ms<=$2) OR (j.state='running' AND j.lease_until_ms<=$2)) ORDER BY j.available_at_ms,j.id LIMIT 1",crate::recovery::JOBS.sql))
                        .bind(tenant).bind(now).fetch_optional(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    let Some(row) = row else { tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?; return Ok(None) };
                    let id:String = row.get("id");
                    // 接管只改变旧写入的认知状态，绝不重用其对象键或释放账本。
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='uncertain' WHERE tenant_id=$1 AND intent_id=$2 AND outcome='in_flight'")
                        .bind(tenant).bind(&id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    if row.get::<i64,_>("attempts") >= row.get::<i64,_>("max_attempts") {
                        sqlx::query("UPDATE background_jobs SET state='dead',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2")
                            .bind(tenant).bind(&id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        sqlx::query("UPDATE bgm_publications SET outcome='rejected',audio=NULL,authority='{}' WHERE tenant_id=$1 AND id=$2 AND outcome='pending'")
                            .bind(tenant).bind(&id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        return Ok(None);
                    }
                    let token = memoswish_core::ids::new_id();
                    sqlx::query("UPDATE background_jobs SET state='running',attempts=attempts+1,token=$3,worker=$4,lease_until_ms=$5 WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(&id).bind(&token).bind(worker).bind(now+lease_ms).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    Ok(Some(JobClaim{job_id:id,token}))

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }

                async fn heartbeat_asset_job(&self, tenant:&str, claim:&JobClaim, lease_ms:i64) -> CoreResult<()> {
                    if !(1..=300_000).contains(&lease_ms) { return Err(CoreError::invalid("invalid asset lease duration")); }
                    let mut tx = self.asset_tx().await?;
                    Self::asset_fence(&mut tx, tenant, claim).await?;
                    let now = Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=$4 WHERE tenant_id=$1 AND id=$2 AND token=$3")
                        .bind(tenant).bind(&claim.job_id).bind(&claim.token).bind(now+lease_ms).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }

                async fn retry_asset_job(&self, tenant:&str, claim:&JobClaim, delay_ms:i64) -> CoreResult<()> {
                    if !(0..=300_000).contains(&delay_ms) { return Err(CoreError::invalid("invalid asset retry delay")); }
                    let mut tx = self.asset_tx().await?;
                    Self::asset_fence(&mut tx, tenant, claim).await?;
                    let now = Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='uncertain' WHERE tenant_id=$1 AND intent_id=$2 AND outcome='in_flight'")
                        .bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE background_jobs SET state=CASE WHEN attempts>=max_attempts THEN 'dead' ELSE 'queued' END,available_at_ms=$3,lease_until_ms=0,token=NULL,worker=NULL WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(&claim.job_id).bind(now+delay_ms.max(memoswish_core::maintenance::CADENCE_MS)).execute(&mut *tx).await.map_err(db_error)?;
                    // 耗尽与发布终态原子同步，保留上传账本中的未决对象责任。
                    sqlx::query("UPDATE bgm_publications SET outcome='rejected',audio=NULL,authority='{}' WHERE tenant_id=$1 AND id=$2 AND outcome='pending' AND EXISTS(SELECT 1 FROM background_jobs j WHERE j.tenant_id=$1 AND j.id=$2 AND j.state='dead')")
                        .bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }

                async fn finish_asset_job(&self, tenant:&str, claim:&JobClaim) -> CoreResult<()> {
                    let mut tx = self.asset_tx().await?;
                    Self::asset_fence(&mut tx,tenant,claim).await?;
                    let unresolved:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asset_upload_intents i WHERE i.tenant_id=$1 AND i.id=$2 AND (NOT EXISTS(SELECT 1 FROM asset_upload_attempts u WHERE u.tenant_id=i.tenant_id AND u.intent_id=i.id) OR EXISTS(SELECT 1 FROM asset_upload_attempts u WHERE u.tenant_id=i.tenant_id AND u.intent_id=i.id AND u.outcome<>'cleaned' AND (i.published_attempt IS NULL OR u.id<>i.published_attempt)))")
                        .bind(tenant).bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if unresolved != 0 { return Err(CoreError::Conflict("asset responsibility remains unresolved".into())); }
                    sqlx::query("UPDATE background_jobs SET state='succeeded',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
            }

            #[async_trait::async_trait]
            impl AssetRepo for $repo {
                async fn asset_read_manifest(&self, tenant: &str, key: &str) -> CoreResult<Option<memoswish_core::asset_read::ReadManifest>> {
                    validate_asset_id(tenant)?;
                    memoswish_core::store::validate_key(key)?;
                    let text: Option<String> = sqlx::query_scalar("SELECT manifest FROM asset_read_metadata WHERE tenant_id=$1 AND object_key=$2")
                        .bind(tenant).bind(key).fetch_optional(&self.pool).await.map_err(db_error)?;
                    text.map(|text| {
                        let manifest: memoswish_core::asset_read::ReadManifest = serde_json::from_str(&text).map_err(CoreError::internal)?;
                        manifest.validate()?;
                        Ok(manifest)
                    }).transpose()
                }
                async fn save_asset_read_manifest(&self, tenant: &str, key: &str, manifest: &memoswish_core::asset_read::ReadManifest) -> CoreResult<()> {
                    validate_asset_id(tenant)?;
                    memoswish_core::store::validate_key(key)?;
                    if !key.starts_with(&format!("tenants/{tenant}/")) && !key.starts_with("shared/bgm/") {
                        return Err(CoreError::Forbidden("asset metadata belongs to another tenant".into()));
                    }
                    manifest.validate()?;
                    let text = serde_json::to_string(manifest).map_err(CoreError::internal)?;
                    let mut tx = self.asset_tx().await?;
                    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants t WHERE t.id=$1 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id)")
                        .bind(tenant).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if live != 1 { return Err(CoreError::Forbidden("asset metadata tenant is unavailable".into())); }
                    sqlx::query("INSERT INTO asset_read_metadata(tenant_id,object_key,binding,verified,progress,manifest) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,object_key) DO UPDATE SET binding=excluded.binding,verified=excluded.verified,progress=excluded.progress,manifest=excluded.manifest WHERE asset_read_metadata.binding<>excluded.binding OR asset_read_metadata.verified<excluded.verified OR (asset_read_metadata.verified=excluded.verified AND asset_read_metadata.progress<=excluded.progress)")
                        .bind(tenant).bind(key).bind(&manifest.binding).bind(i32::from(manifest.verified)).bind(manifest.blocks.len() as i32).bind(text)
                        .execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn asset_delivery(&self, p: &Principal, key: &str, permission: Permission) -> CoreResult<Option<AssetDelivery>> {
                    p.require(permission)?;
                    memoswish_core::store::validate_key(key)?;
                    let mut tx = self.asset_tx().await?;
                    let role: Option<String> = sqlx::query_scalar("SELECT m.role FROM tenants t JOIN tenant_memberships m ON m.tenant_id=t.id JOIN account_auth_epochs a ON a.user_id=m.user_id WHERE t.id=$1 AND m.user_id=$2 AND a.generation=$3 AND m.generation=$4 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id)")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(p.auth_generation).bind(p.membership_generation)
                        .fetch_optional(&mut *tx).await.map_err(db_error)?;
                    if !role.map(|r| Role::parse(&r).map(|r| r.allows(permission))).transpose()?.unwrap_or(false) {
                        return Err(CoreError::Forbidden("asset reader is no longer authorized".into()));
                    }
                    let row = sqlx::query("SELECT r.id AS asset_id,r.mime,r.size,r.sha256,a.* FROM asset_records r JOIN asset_upload_intents i ON i.tenant_id=r.tenant_id AND i.asset_id=r.id JOIN asset_upload_attempts a ON a.tenant_id=i.tenant_id AND a.intent_id=i.id AND a.id=i.published_attempt WHERE r.tenant_id=$1 AND a.object_key=$2 AND a.outcome='uploaded' AND a.version_kind<>'unknown' AND EXISTS(SELECT 1 FROM asset_references f WHERE f.tenant_id=r.tenant_id AND f.asset_id=r.id)")
                        .bind(&p.tenant_id).bind(key).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    let result = row.map(|r| {
                        let attempt = Self::asset_attempt_row(&r)?;
                        Ok(AssetDelivery { asset_id:r.get("asset_id"), spec:AssetSpec {mime:r.get("mime"),size:r.get("size"),sha256:r.get("sha256")}, key:attempt.key, store_id:attempt.store_id, version:attempt.version })
                    }).transpose();
                    tx.commit().await.map_err(db_error)?;
                    result
                }

                async fn legacy_asset_cards(&self, tenant: &str, key: &str) -> CoreResult<Vec<memoswish_protocol::Card>> {
                    memoswish_core::store::validate_key(key)?;
                    // LIKE 只选择候选；下游按完整 key 和类型检查，通配符不产生授权。
                    let bodies: Vec<String> = sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id=$1 AND CAST(body AS TEXT) LIKE $2 LIMIT 1001")
                        .bind(tenant).bind(format!("%{key}%")).fetch_all(&self.pool).await.map_err(db_error)?;
                    if bodies.len() > 1000 { return Err(CoreError::Unsupported("legacy asset lookup requires an explicit owner".into())); }
                    bodies.iter().map(|body| serde_json::from_str(body).map_err(|_| CoreError::internal("invalid stored card"))).collect()
                }
                async fn prepare_asset(&self, p:&Principal, request:&str, spec:&AssetSpec, max_attempts:i64) -> CoreResult<AssetIntent> {
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbWrite);
        let result: CoreResult<_> = async {
                    validate_asset_id(request)?; spec.validate()?;
                    if !(1..=100).contains(&max_attempts) { return Err(CoreError::invalid("invalid asset retry budget")); }
                    let mut tx = self.asset_tx().await?;
                    Self::asset_authorize(&mut tx,p).await?;
                    let existing = sqlx::query("SELECT i.*,a.mime,a.size,a.sha256,j.user_id,j.requester_generation,j.max_attempts FROM background_jobs j JOIN asset_upload_intents i ON i.tenant_id=j.tenant_id AND i.id=j.id JOIN asset_records a ON a.tenant_id=i.tenant_id AND a.id=i.asset_id WHERE j.tenant_id=$1 AND j.kind='asset_upload' AND j.idempotency_key=$2")
                        .bind(&p.tenant_id).bind(request).fetch_optional(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    if let Some(row) = existing {
                        let intent = Self::asset_intent_row(&row);
                        if intent.spec != *spec || row.get::<String,_>("user_id") != p.user_id || Some(row.get::<i64,_>("requester_generation")) != p.membership_generation || Some(row.get::<i64,_>("account_generation")) != p.auth_generation || row.get::<i64,_>("max_attempts") != max_attempts {
                            return Err(CoreError::Conflict("asset request identity conflict".into()));
                        }
                        tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        return Ok(intent);
                    }
                    let id = memoswish_core::ids::new_id();
                    let asset_id = memoswish_core::ids::new_id();
                    let now = Self::asset_now(&mut tx).await?;
                    sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES($1,$2,'asset_upload',$3,$4,$5,$6,$7,$8)")
                        .bind(&p.tenant_id).bind(&id).bind(request).bind(sqlx::types::Json(serde_json::json!({}))).bind(&p.user_id).bind(p.membership_generation).bind(max_attempts).bind(now)
                        .execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    sqlx::query("INSERT INTO asset_records(tenant_id,id,mime,size,sha256) VALUES($1,$2,$3,$4,$5)")
                        .bind(&p.tenant_id).bind(&asset_id).bind(&spec.mime).bind(spec.size).bind(&spec.sha256).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    sqlx::query("INSERT INTO asset_upload_intents(tenant_id,id,asset_id,account_generation) VALUES($1,$2,$3,$4)")
                        .bind(&p.tenant_id).bind(&id).bind(&asset_id).bind(p.auth_generation).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    Ok(AssetIntent{id,asset_id,spec:spec.clone(),published_attempt:None})

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }

                async fn asset_intent(&self, tenant:&str, id:&str) -> CoreResult<Option<AssetIntent>> {
                    let row = sqlx::query("SELECT i.*,a.mime,a.size,a.sha256 FROM asset_upload_intents i JOIN asset_records a ON a.tenant_id=i.tenant_id AND a.id=i.asset_id WHERE i.tenant_id=$1 AND i.id=$2")
                        .bind(tenant).bind(id).fetch_optional(&self.pool).await.map_err(db_error)?;
                    Ok(row.as_ref().map(Self::asset_intent_row))
                }

                async fn begin_upload(&self, tenant:&str, claim:&JobClaim, store_id:&str) -> CoreResult<UploadAttempt> {
                    validate_asset_id(store_id)?;
                    let mut tx = self.asset_tx().await?;
                    Self::asset_fence(&mut tx,tenant,claim).await?;
                    let row = sqlx::query("SELECT j.user_id,j.requester_generation,i.account_generation,i.published_attempt FROM background_jobs j JOIN asset_upload_intents i ON i.tenant_id=j.tenant_id AND i.id=j.id WHERE j.tenant_id=$1 AND j.id=$2")
                        .bind(tenant).bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if row.get::<Option<String>,_>("published_attempt").is_some() { return Err(CoreError::Conflict("asset already published".into())); }
                    let speech: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tts_syntheses s JOIN tenants t ON t.id=s.tenant_id WHERE s.tenant_id=$1 AND s.upload_id=$2 AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=t.id)").bind(tenant).bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if speech == 0 {
                        let user: Option<String> = row.get("user_id");
                        let p = Principal {tenant_id:tenant.into(),user_id:user.ok_or_else(||CoreError::Forbidden("upload capability missing".into()))?,role:Role::Owner,scopes:None,via:"asset-intent".into(),session_access_hash:None,legacy_issued_at:None,auth_generation:Some(row.get("account_generation")),membership_generation:Some(row.get("requester_generation"))};
                        Self::asset_authorize(&mut tx,&p).await?;
                    }
                    Self::asset_fence(&mut tx,tenant,claim).await?;
                    // 一个 claim 只授权一次 PUT；调用者不得重放同一 attempt 的外部写入。
                    let used:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asset_upload_attempts WHERE tenant_id=$1 AND intent_id=$2 AND claim_token=$3")
                        .bind(tenant).bind(&claim.job_id).bind(&claim.token).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if used != 0 { return Err(CoreError::Conflict("upload claim already used".into())); }
                    let id = memoswish_core::ids::new_id();
                    let key = format!("tenants/{tenant}/uploads/{}/{id}",claim.job_id);
                    memoswish_core::store::validate_key(&key)?;
                    sqlx::query("INSERT INTO asset_upload_attempts(tenant_id,id,intent_id,object_key,claim_token,store_id,outcome) VALUES($1,$2,$3,$4,$5,$6,'in_flight')")
                        .bind(tenant).bind(&id).bind(&claim.job_id).bind(&key).bind(&claim.token).bind(store_id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(UploadAttempt{id,intent_id:claim.job_id.clone(),key,store_id:store_id.into(),claim_token:claim.token.clone(),outcome:UploadOutcome::InFlight,version:ObjectVersion::Unknown})
                }

                async fn record_upload(&self, tenant:&str, supplied:&UploadAttempt, version:&ObjectVersion) -> CoreResult<()> {
                    version.validate()?;
                    let (kind,id) = match version { ObjectVersion::Unknown => return Err(CoreError::invalid("upload receipt requires known version semantics")), ObjectVersion::Unversioned => ("unversioned",None), ObjectVersion::VersionId(id) => ("version",Some(id.as_str())) };
                    let mut tx = self.asset_tx().await?;
                    let actual = Self::asset_attempt_tx(&mut tx,tenant,&supplied.id).await?;
                    Self::asset_match_attempt(&actual,supplied)?;
                    if actual.version != ObjectVersion::Unknown && actual.version != *version { return Err(CoreError::Conflict("upload version evidence is immutable".into())); }
                    sqlx::query("UPDATE asset_upload_attempts SET version_kind=$3,version_id=$4,outcome=CASE WHEN outcome IN ('in_flight','uncertain') THEN 'uploaded' ELSE outcome END WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(&supplied.id).bind(kind).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    // 发布后才返回的旧 PUT 仍重新进入同一工作责任；耗尽时明确保留 dead。
                    sqlx::query("UPDATE background_jobs SET state=CASE WHEN attempts>=max_attempts THEN 'dead' ELSE 'queued' END WHERE tenant_id=$1 AND id=$2 AND state='succeeded' AND EXISTS(SELECT 1 FROM asset_upload_intents i WHERE i.tenant_id=$1 AND i.id=$2 AND i.published_attempt IS NOT NULL AND i.published_attempt<>$3) AND EXISTS(SELECT 1 FROM asset_upload_attempts u WHERE u.tenant_id=$1 AND u.id=$3 AND u.outcome<>'cleaned')")
                        .bind(tenant).bind(&supplied.intent_id).bind(&supplied.id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }

                async fn mark_upload_uncertain(&self, tenant:&str, supplied:&UploadAttempt) -> CoreResult<()> {
                    let mut tx = self.asset_tx().await?;
                    let actual = Self::asset_attempt_tx(&mut tx,tenant,&supplied.id).await?;
                    Self::asset_match_attempt(&actual,supplied)?;
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='uncertain' WHERE tenant_id=$1 AND id=$2 AND outcome='in_flight'")
                        .bind(tenant).bind(&supplied.id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }

                async fn upload_attempts(&self, tenant:&str, intent:&str) -> CoreResult<Vec<UploadAttempt>> {
                    let rows = sqlx::query("SELECT * FROM asset_upload_attempts WHERE tenant_id=$1 AND intent_id=$2 ORDER BY id")
                        .bind(tenant).bind(intent).fetch_all(&self.pool).await.map_err(db_error)?;
                    rows.iter().map(Self::asset_attempt_row).collect()
                }

                async fn publish_asset(&self, p:&Principal, claim:&JobClaim, attempt_id:&str, reference:&AssetReference) -> CoreResult<()> {
                    let mut tx = self.asset_tx().await?;
                    Self::asset_authorize(&mut tx,p).await?;
                    Self::asset_fence(&mut tx,&p.tenant_id,claim).await?;
                    let attempt = Self::asset_attempt_tx(&mut tx,&p.tenant_id,attempt_id).await?;
                    if attempt.intent_id != claim.job_id || attempt.claim_token != claim.token || attempt.outcome != UploadOutcome::Uploaded { return Err(CoreError::Conflict("upload is not publishable by this claim".into())); }
                    let changed = sqlx::query("UPDATE asset_upload_intents SET published_attempt=$3 WHERE tenant_id=$1 AND id=$2 AND asset_id=$4 AND published_attempt IS NULL AND account_generation=$5 AND EXISTS(SELECT 1 FROM background_jobs j WHERE j.tenant_id=$1 AND j.id=$2 AND j.user_id=$6 AND j.requester_generation=$7)")
                        .bind(&p.tenant_id).bind(&claim.job_id).bind(attempt_id).bind(&reference.asset_id).bind(p.auth_generation).bind(&p.user_id).bind(p.membership_generation).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                    if changed != 1 { return Err(CoreError::Conflict("asset publication owner mismatch".into())); }
                    Self::asset_reference_tx(&mut tx,p,reference).await?;
                    sqlx::query("UPDATE background_jobs SET state=CASE WHEN EXISTS(SELECT 1 FROM asset_upload_attempts u WHERE u.tenant_id=$1 AND u.intent_id=$2 AND u.id<>$3 AND u.outcome<>'cleaned') THEN CASE WHEN attempts>=max_attempts THEN 'dead' ELSE 'queued' END ELSE 'succeeded' END,token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2")
                        .bind(&p.tenant_id).bind(&claim.job_id).bind(attempt_id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }

                async fn add_asset_reference(&self, p:&Principal, reference:&AssetReference) -> CoreResult<()> {
                    let mut tx = self.asset_tx().await?;
                    Self::asset_authorize(&mut tx,p).await?;
                    Self::asset_reference_tx(&mut tx,p,reference).await?;
                    tx.commit().await.map_err(db_error)
                }

                async fn remove_asset_reference(&self, p:&Principal, owner:&str, slot:&str) -> CoreResult<()> {
                    let mut tx = self.asset_tx().await?;
                    Self::asset_authorize(&mut tx,p).await?;
                    sqlx::query("DELETE FROM asset_references WHERE tenant_id=$1 AND user_id=$2 AND owner_id=$3 AND slot=$4")
                        .bind(&p.tenant_id).bind(&p.user_id).bind(owner).bind(slot).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }

                async fn asset_reference_count(&self, tenant:&str, asset:&str) -> CoreResult<i64> {
                    sqlx::query_scalar("SELECT COUNT(*) FROM asset_references WHERE tenant_id=$1 AND asset_id=$2")
                        .bind(tenant).bind(asset).fetch_one(&self.pool).await.map_err(db_error)
                }

                async fn begin_asset_cleanup(&self, tenant:&str, claim:&JobClaim, id:&str, store_id:&str) -> CoreResult<UploadAttempt> {
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbCleanup);
        let result: CoreResult<_> = async {
                    validate_asset_id(store_id)?;
                    let mut tx = self.asset_tx().await?;
                    Self::asset_fence(&mut tx,tenant,claim).await?;
                    let mut attempt = Self::asset_attempt_tx(&mut tx,tenant,id).await?;
                    if attempt.store_id != store_id || attempt.intent_id != claim.job_id || attempt.version == ObjectVersion::Unknown || !matches!(attempt.outcome,UploadOutcome::Uploaded|UploadOutcome::CleanupPending) { return Err(CoreError::Conflict("upload cleanup requires known owned evidence".into())); }
                    let published:i64 = sqlx::query_scalar("SELECT COUNT(*) FROM asset_upload_intents WHERE tenant_id=$1 AND published_attempt=$2")
                        .bind(tenant).bind(id).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    if published != 0 { return Err(CoreError::Conflict("published assets cannot be orphan collected".into())); }
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='cleanup_pending' WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    attempt.outcome = UploadOutcome::CleanupPending;
                    Ok(attempt)

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }

                async fn record_asset_cleaned(&self, tenant:&str, supplied:&UploadAttempt) -> CoreResult<()> {
                    let mut tx = self.asset_tx().await?;
                    let actual = Self::asset_attempt_tx(&mut tx,tenant,&supplied.id).await?;
                    Self::asset_match_attempt(&actual,supplied)?;
                    if actual.version != supplied.version || !matches!(actual.outcome,UploadOutcome::CleanupPending|UploadOutcome::Cleaned) { return Err(CoreError::Conflict("cleanup receipt identity mismatch".into())); }
                    sqlx::query("UPDATE asset_upload_attempts SET outcome='cleaned' WHERE tenant_id=$1 AND id=$2")
                        .bind(tenant).bind(&supplied.id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }

                async fn unresolved_assets(&self, after:Option<(&str,&str)>, limit:i64) -> CoreResult<Vec<(String,AssetIntent)>> {
                    if !(1..=100).contains(&limit) { return Err(CoreError::invalid("invalid asset recovery page size")); }
                    let (tenant,id) = after.unwrap_or(("",""));
                    let rows = sqlx::query(&format!("SELECT i.*,a.mime,a.size,a.sha256 FROM ({}) recovery JOIN asset_upload_intents i ON i.tenant_id=recovery.tenant_id AND i.id=recovery.id JOIN asset_records a ON a.tenant_id=i.tenant_id AND a.id=i.asset_id WHERE i.tenant_id>$1 OR (i.tenant_id=$1 AND i.id>$2) ORDER BY i.tenant_id,i.id LIMIT $3",crate::recovery::ASSETS.sql))
                        .bind(tenant).bind(id).bind(limit).fetch_all(&self.pool).await.map_err(db_error)?;
                    Ok(rows.iter().map(|r|(r.get("tenant_id"),Self::asset_intent_row(r))).collect())
                }
            }
        };
    };
}
pub(crate) use asset_impl;

#[cfg(test)]
#[path = "tts_conformance.rs"]
mod tts_conformance;
