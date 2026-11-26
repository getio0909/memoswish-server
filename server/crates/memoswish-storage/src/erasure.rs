//! 双库共用擦除状态机；序列化后才观察数据库时钟，外部 I/O 不进入事务。

macro_rules! erasure_impl {
    ($repo:ty, $db:ty, $row:ty, $purge_query:literal) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, erasure::*, identity::ErasureJob, jobs::JobClaim, assets::ObjectVersion};
            use crate::assets::db_error;
            use sqlx::Row;
            impl $repo {
                pub(crate) async fn maintenance_tombstones_tx(tx: &mut sqlx::Transaction<'_, $db>, limit: i64) -> CoreResult<()> {
                    let after:String=sqlx::query_scalar("SELECT after_tenant FROM erasure_sweep_cursor WHERE id=1").fetch_one(&mut **tx).await.map_err(db_error)?;
                    let mut tenants:Vec<String>=sqlx::query_scalar(&format!("SELECT tenant_id FROM ({}) candidates WHERE tenant_id>$1 ORDER BY tenant_id LIMIT $2",crate::recovery::TOMBSTONES.sql)).bind(&after).bind(limit).fetch_all(&mut **tx).await.map_err(db_error)?;
                    if tenants.is_empty() && !after.is_empty() {
                        tenants=sqlx::query_scalar(&format!("SELECT tenant_id FROM ({}) candidates ORDER BY tenant_id LIMIT $1",crate::recovery::TOMBSTONES.sql)).bind(limit).fetch_all(&mut **tx).await.map_err(db_error)?;
                    }
                    for tenant in &tenants {
                        let existing:Option<String>=sqlx::query_scalar("SELECT job_id FROM erasure_tombstone_work WHERE tenant_id=$1").bind(tenant).fetch_optional(&mut **tx).await.map_err(db_error)?;
                        let id=if let Some(id)=existing{id}else{
                            // 直接查询首个原 purge 操作；dead 仍保有原预算与责任。
                            let old:Option<String>=sqlx::query_scalar($purge_query).bind(tenant).fetch_optional(&mut **tx).await.map_err(db_error)?;
                            let id=if let Some(id)=old{id}else{
                                let job=ErasureJob{id:memoswish_core::ids::new_id(),tenant_id:Some(tenant.clone()),purge_assets:true,credentials:Vec::new()};
                                sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)").bind(&job.id).bind(crate::oauth::encode(&job)?).execute(&mut **tx).await.map_err(db_error)?;job.id
                            };
                            sqlx::query("INSERT INTO erasure_tombstone_work(tenant_id,job_id) VALUES($1,$2)").bind(tenant).bind(&id).execute(&mut **tx).await.map_err(db_error)?;id
                        };
                        let work=Self::erasure_read(tx,&id).await?;
                        if work.progress=="complete" && work.state=="succeeded" {
                            sqlx::query("UPDATE account_erasure_jobs SET progress='pending',revision=revision+1,assets_ack=0 WHERE id=$1").bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                            sqlx::query("UPDATE background_jobs SET state='queued',attempts=0,available_at_ms=0 WHERE tenant_id=$1 AND id=$2 AND state='succeeded'").bind(tenant).bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                        }
                    }
                    sqlx::query("UPDATE erasure_sweep_cursor SET after_tenant=$1 WHERE id=1").bind(tenants.last().map(String::as_str).unwrap_or("")).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }

                async fn erasure_read(tx: &mut sqlx::Transaction<'_, $db>, id: &str) -> CoreResult<ErasureWork> {
                    let r=sqlx::query("SELECT e.body,e.progress,e.revision,e.total_attempts,j.state,j.attempts,j.max_attempts FROM account_erasure_jobs e JOIN background_jobs j ON j.tenant_id=e.partition_id AND j.id=e.id AND j.kind='erasure' WHERE e.id=$1")
                        .bind(id).fetch_optional(&mut **tx).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("erasure operation".into()))?;
                    Self::erasure_row(&r)
                }
                fn erasure_row(r:&$row)->CoreResult<ErasureWork>{
                    Ok(ErasureWork{job:serde_json::from_str(&r.get::<String,_>("body")).map_err(|_|CoreError::internal("invalid erasure operation"))?,progress:r.get("progress"),state:r.get("state"),attempts:r.get("attempts"),max_attempts:r.get("max_attempts"),revision:r.get("revision"),total_attempts:r.get("total_attempts")})
                }
                async fn erasure_fence(tx:&mut sqlx::Transaction<'_, $db>,claim:&JobClaim)->CoreResult<ErasureWork>{
                    let work=Self::erasure_read(tx,&claim.job_id).await?;
                    let now=Self::asset_now(tx).await?;
                    let live:i64=sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE tenant_id=$1 AND id=$2 AND kind='erasure' AND state='running' AND token=$3 AND lease_until_ms>$4")
                        .bind(work.job.tenant_id.as_deref().unwrap_or("")).bind(&claim.job_id).bind(&claim.token).bind(now).fetch_one(&mut **tx).await.map_err(db_error)?;
                    if live!=1{return Err(CoreError::Conflict("erasure claim expired or replaced".into()));}
                    Ok(work)
                }
                async fn erasure_pending_objects(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str)->CoreResult<i64>{
                    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM ({}) objects WHERE tenant_id=$1",crate::recovery::OBJECTS.sql))
                        .bind(tenant).fetch_one(&mut **tx).await.map_err(db_error)
                }
                async fn erasure_authority(tx:&mut sqlx::Transaction<'_, $db>,work:&ErasureWork)->CoreResult<String>{
                    let tenant=work.job.tenant_id.as_deref().filter(|_|work.job.purge_assets).ok_or_else(||CoreError::Forbidden("erasure has no asset authority".into()))?;
                    let n:i64=sqlx::query_scalar("SELECT COUNT(*) FROM erased_tenants WHERE tenant_id=$1").bind(tenant).fetch_one(&mut **tx).await.map_err(db_error)?;
                    if n!=1{return Err(CoreError::Forbidden("committed tenant tombstone required".into()));}
                    Ok(tenant.into())
                }
                fn erasure_version(kind:&str,id:Option<String>)->CoreResult<ObjectVersion>{
                    match kind {"unknown"=>Ok(ObjectVersion::Unknown),"unversioned"=>Ok(ObjectVersion::Unversioned),"version"=>Ok(ObjectVersion::VersionId(id.ok_or_else(||CoreError::internal("missing version evidence"))?)),_=>Err(CoreError::internal("invalid version evidence"))}
                }
                fn erasure_version_fields(version:&ObjectVersion)->CoreResult<(&'static str,Option<&str>)>{
                    version.validate()?;
                    match version {ObjectVersion::Unknown=>Err(CoreError::Conflict("precise object receipt required".into())),ObjectVersion::Unversioned=>Ok(("unversioned",None)),ObjectVersion::VersionId(id)=>Ok(("version",Some(id)))}
                }
                fn erasure_object_row(r:&$row)->CoreResult<ErasureObject>{
                    Ok(ErasureObject{source:r.get("source"),tenant_id:r.get("tenant_id"),id:r.get("id"),store_id:r.get("store_id"),key:r.get("object_key"),version:Self::erasure_version(&r.get::<String,_>("version_kind"),r.get("version_id"))?})
                }
                fn erasure_table(object:&ErasureObject)->CoreResult<&'static str>{
                    match object.source.as_str(){"managed"=>Ok("managed_object_writes"),"asset"=>Ok("asset_upload_attempts"),_=>Err(CoreError::invalid("invalid cleanup source"))}
                }
                async fn erasure_upload_receipt(tx:&mut sqlx::Transaction<'_, $db>,object:&ErasureObject,version:&ObjectVersion)->CoreResult<()>{
                    let (kind,id)=Self::erasure_version_fields(version)?;
                    // 只有墓碑后的清理可以消费 guard 回执；活跃租户仍由原调用者验证完整元数据。
                    let erased:i64=sqlx::query_scalar("SELECT COUNT(*) FROM erased_tenants WHERE tenant_id=$1").bind(&object.tenant_id).fetch_one(&mut **tx).await.map_err(db_error)?;
                    if erased==0{return Ok(());}
                    let mismatch:i64=sqlx::query_scalar("SELECT COUNT(*) FROM asset_upload_attempts WHERE tenant_id=$1 AND object_key=$2 AND store_id=$3 AND version_kind<>'unknown' AND (version_kind<>$4 OR COALESCE(version_id,'')<>COALESCE($5,''))").bind(&object.tenant_id).bind(&object.key).bind(&object.store_id).bind(kind).bind(id).fetch_one(&mut **tx).await.map_err(db_error)?;
                    if mismatch!=0{return Err(CoreError::Conflict("managed asset receipt identity mismatch".into()));}
                    sqlx::query("UPDATE asset_upload_attempts SET version_kind=$4,version_id=$5,outcome=CASE WHEN outcome IN ('in_flight','uncertain') THEN 'uploaded' ELSE outcome END WHERE tenant_id=$1 AND object_key=$2 AND store_id=$3").bind(&object.tenant_id).bind(&object.key).bind(&object.store_id).bind(kind).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }
                async fn erasure_match_object(tx:&mut sqlx::Transaction<'_, $db>,object:&ErasureObject)->CoreResult<String>{
                    memoswish_core::assets::validate_asset_id(&object.tenant_id)?;
                    memoswish_core::store::validate_key(&object.key)?;
                    if !object.key.starts_with(&format!("tenants/{}/",object.tenant_id)){return Err(CoreError::Forbidden("cleanup tenant prefix mismatch".into()));}
                    let table=Self::erasure_table(object)?;
                    let query=format!("SELECT store_id,object_key,version_kind,version_id,outcome FROM {table} WHERE tenant_id=$1 AND id=$2");
                    let r=sqlx::query(&query).bind(&object.tenant_id).bind(&object.id).fetch_optional(&mut **tx).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("cleanup evidence".into()))?;
                    if r.get::<String,_>("store_id")!=object.store_id || r.get::<String,_>("object_key")!=object.key || Self::erasure_version(&r.get::<String,_>("version_kind"),r.get("version_id"))?!=object.version {
                        return Err(CoreError::Conflict("cleanup identity mismatch".into()));
                    }
                    Ok(r.get("outcome"))
                }
            }
            #[async_trait::async_trait]
            impl ErasureRepo for $repo {
                async fn erasure_work(&self,id:&str)->CoreResult<Option<ErasureWork>>{
                    let mut tx=self.asset_tx().await?;
                    let result=Self::erasure_read(&mut tx,id).await;
                    tx.commit().await.map_err(db_error)?;
                    match result {Ok(w)=>Ok(Some(w)),Err(CoreError::NotFound(_))=>Ok(None),Err(e)=>Err(e)}
                }
                async fn erasure_page(&self,after:&str,limit:i64)->CoreResult<Vec<ErasureWork>>{
                    if !(1..=100).contains(&limit){return Err(CoreError::invalid("invalid erasure page size"));}
                    let rows=sqlx::query(&format!("SELECT e.body,e.progress,e.revision,e.total_attempts,j.state,j.attempts,j.max_attempts FROM ({}) e JOIN background_jobs j ON j.tenant_id=e.partition_id AND j.id=e.id WHERE e.id>$1 ORDER BY e.id LIMIT $2",crate::recovery::ERASURES.sql))
                        .bind(after).bind(limit).fetch_all(&self.pool).await.map_err(db_error)?;
                    rows.iter().map(Self::erasure_row).collect()
                }
                async fn claim_erasure(&self,id:&str,worker:&str,lease_ms:i64)->CoreResult<Option<JobClaim>>{
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbClaim);
        let result: CoreResult<_> = async {
                    memoswish_core::assets::validate_asset_id(worker)?;
                    if !(1..=300_000).contains(&lease_ms){return Err(CoreError::invalid("invalid erasure lease"));}
                    let mut tx=self.asset_tx().await?;
                    let work=Self::erasure_read(&mut tx,id).await?;
                    let now=Self::asset_now(&mut tx).await?;
                    let due:i64=sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE tenant_id=$1 AND id=$2 AND ((state='queued' AND available_at_ms<=$3) OR (state='running' AND lease_until_ms<=$3))")
                        .bind(work.job.tenant_id.as_deref().unwrap_or("")).bind(id).bind(now).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    if due==0 || work.progress=="complete" {tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;return Ok(None);}
                    if work.attempts>=work.max_attempts {
                        sqlx::query("UPDATE background_jobs SET state='dead',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(work.job.tenant_id.as_deref().unwrap_or("")).bind(id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        sqlx::query("UPDATE account_erasure_jobs SET progress='blocked',revision=revision+1 WHERE id=$1").bind(id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;return Ok(None);
                    }
                    let token=memoswish_core::ids::new_id();
                    sqlx::query("UPDATE background_jobs SET state='running',attempts=attempts+1,token=$3,worker=$4,lease_until_ms=$5 WHERE tenant_id=$1 AND id=$2").bind(work.job.tenant_id.as_deref().unwrap_or("")).bind(id).bind(&token).bind(worker).bind(now+lease_ms).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    sqlx::query("UPDATE account_erasure_jobs SET progress='reconciling',revision=revision+1,total_attempts=total_attempts+1 WHERE id=$1").bind(id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    Ok(Some(JobClaim{job_id:id.into(),token}))

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
                async fn heartbeat_erasure(&self,claim:&JobClaim,lease_ms:i64)->CoreResult<()>{
                    if !(1..=300_000).contains(&lease_ms){return Err(CoreError::invalid("invalid erasure lease"));}
                    let mut tx=self.asset_tx().await?;
                    let work=Self::erasure_fence(&mut tx,claim).await?;
                    let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=$3 WHERE tenant_id=$1 AND id=$2").bind(work.job.tenant_id.as_deref().unwrap_or("")).bind(&claim.job_id).bind(now+lease_ms).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn retry_erasure(&self,claim:&JobClaim)->CoreResult<()>{
                    let mut tx=self.asset_tx().await?;
                    let work=Self::erasure_fence(&mut tx,claim).await?;
                    let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE background_jobs SET state=CASE WHEN attempts>=max_attempts THEN 'dead' ELSE 'queued' END,available_at_ms=$3,token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(work.job.tenant_id.as_deref().unwrap_or("")).bind(&claim.job_id).bind(now+memoswish_core::maintenance::CADENCE_MS).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE account_erasure_jobs SET progress='blocked',revision=revision+1 WHERE id=$1").bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn complete_erasure(&self,claim:&JobClaim)->CoreResult<()>{
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbCleanup);
        let result: CoreResult<_> = async {
                    let mut tx=self.asset_tx().await?;
                    let mut work=Self::erasure_fence(&mut tx,claim).await?;
                    if work.job.credentials.iter().any(|(_,cipher)|!cipher.is_empty()){return Err(CoreError::Conflict("upstream revocations remain unresolved".into()));}
                    if work.job.purge_assets {
                        let tenant=Self::erasure_authority(&mut tx,&work).await?;
                        let ack:i64=sqlx::query_scalar("SELECT assets_ack FROM account_erasure_jobs WHERE id=$1").bind(&claim.job_id).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        let uncertain:i64=sqlx::query_scalar(&format!("SELECT COUNT(*) FROM ({}) unresolved WHERE tenant_id=$1",crate::recovery::PROVIDERS.sql)).bind(&tenant).fetch_one(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                        if ack!=1 || uncertain!=0 || Self::erasure_pending_objects(&mut tx,&tenant).await?!=0 {return Err(CoreError::Conflict("erasure external evidence remains unresolved".into()));}
                    }
                    // 留下最小身份和完成状态，不保留已撤销密文。
                    work.job.credentials.clear();
                    Self::erasure_fence(&mut tx,claim).await?;
                    sqlx::query("UPDATE account_erasure_jobs SET progress='complete',revision=revision+1,body=$2 WHERE id=$1").bind(&claim.job_id).bind(crate::oauth::encode(&work.job)?).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    sqlx::query("UPDATE background_jobs SET state='succeeded',token=NULL,worker=NULL,lease_until_ms=0 WHERE tenant_id=$1 AND id=$2").bind(work.job.tenant_id.as_deref().unwrap_or("")).bind(&claim.job_id).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })?;
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
                async fn requeue_erasure(&self,id:&str,expected:i64)->CoreResult<()>{
                    let mut tx=self.asset_tx().await?;
                    let work=Self::erasure_read(&mut tx,id).await?;
                    if work.state!="dead" || work.progress=="complete" || work.revision!=expected {return Err(CoreError::Conflict("erasure requeue observation is stale or work is not dead".into()));}
                    sqlx::query("UPDATE background_jobs SET state='queued',attempts=0,token=NULL,worker=NULL,lease_until_ms=0,available_at_ms=0 WHERE tenant_id=$1 AND id=$2").bind(work.job.tenant_id.as_deref().unwrap_or("")).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("UPDATE account_erasure_jobs SET progress='pending',revision=revision+1 WHERE id=$1").bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn reconcile_erasure_tombstones(&self,limit:i64)->CoreResult<()>{
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::DbCleanup);
        let result: CoreResult<_> = async {
                    if !(1..=100).contains(&limit){return Err(CoreError::invalid("invalid tombstone page size"));}
                    let mut tx=self.asset_tx().await?;
                    Self::maintenance_tombstones_tx(&mut tx,limit).await?;
                    tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_error(error) })
        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
                async fn erasure_objects(&self,claim:&JobClaim,after:(&str,&str),limit:i64)->CoreResult<Vec<ErasureObject>>{
                    if !(1..=100).contains(&limit){return Err(CoreError::invalid("invalid cleanup page size"));}
                    let mut tx=self.asset_tx().await?;
                    let work=Self::erasure_fence(&mut tx,claim).await?;
                    let tenant=Self::erasure_authority(&mut tx,&work).await?;
                    let rows=sqlx::query(&format!("SELECT * FROM ({}) objects WHERE tenant_id=$1 AND (source>$2 OR (source=$2 AND id>$3)) ORDER BY source,id LIMIT $4",crate::recovery::OBJECTS.sql))
                        .bind(&tenant).bind(after.0).bind(after.1).bind(limit).fetch_all(&mut *tx).await.map_err(db_error)?;
                    let result=rows.iter().map(Self::erasure_object_row).collect();
                    tx.commit().await.map_err(db_error)?;result
                }
                async fn begin_erasure_object(&self,claim:&JobClaim,object:&ErasureObject,store:&str)->CoreResult<()>{
                    let mut tx=self.asset_tx().await?;
                    let work=Self::erasure_fence(&mut tx,claim).await?;
                    let tenant=Self::erasure_authority(&mut tx,&work).await?;
                    if tenant!=object.tenant_id || store!=object.store_id || object.version==ObjectVersion::Unknown {return Err(CoreError::Forbidden("erasure cleanup requires matching known owned evidence".into()));}
                    let outcome=Self::erasure_match_object(&mut tx,object).await?;
                    if !matches!(outcome.as_str(),"uploaded"|"cleanup_pending"){return Err(CoreError::Conflict("object not ready for cleanup".into()));}
                    let query=format!("UPDATE {} SET outcome='cleanup_pending' WHERE tenant_id=$1 AND id=$2",Self::erasure_table(object)?);
                    sqlx::query(&query).bind(&tenant).bind(&object.id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn record_erasure_object(&self,object:&ErasureObject)->CoreResult<()>{
                    let mut tx=self.asset_tx().await?;
                    let outcome=Self::erasure_match_object(&mut tx,object).await?;
                    if object.version==ObjectVersion::Unknown || !matches!(outcome.as_str(),"cleanup_pending"|"cleaned"){return Err(CoreError::Conflict("cleanup acknowledgement requires prepared exact evidence".into()));}
                    let query=format!("UPDATE {} SET outcome='cleaned' WHERE tenant_id=$1 AND id=$2",Self::erasure_table(object)?);
                    sqlx::query(&query).bind(&object.tenant_id).bind(&object.id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn erasure_assets_ready(&self,claim:&JobClaim)->CoreResult<bool>{
                    let mut tx=self.asset_tx().await?;
                    let work=Self::erasure_fence(&mut tx,claim).await?;
                    let tenant=Self::erasure_authority(&mut tx,&work).await?;
                    let ready=Self::erasure_pending_objects(&mut tx,&tenant).await?==0;
                    tx.commit().await.map_err(db_error)?;Ok(ready)
                }
                async fn acknowledge_erasure_assets(&self,claim:&JobClaim)->CoreResult<()>{
                    let mut tx=self.asset_tx().await?;
                    let work=Self::erasure_fence(&mut tx,claim).await?;
                    let tenant=Self::erasure_authority(&mut tx,&work).await?;
                    if Self::erasure_pending_objects(&mut tx,&tenant).await?!=0{return Err(CoreError::Conflict("managed writes remain unresolved".into()));}
                    sqlx::query("UPDATE account_erasure_jobs SET assets_ack=1 WHERE id=$1").bind(&claim.job_id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn acknowledge_revocation(&self,claim:&JobClaim,ordinal:usize,provider:&str,cipher:&str)->CoreResult<()>{
                    let mut tx=self.asset_tx().await?;
                    let mut work=Self::erasure_fence(&mut tx,claim).await?;
                    let item=work.job.credentials.get_mut(ordinal).ok_or_else(||CoreError::Conflict("revocation identity mismatch".into()))?;
                    if item.0!=provider || (!item.1.is_empty() && item.1!=cipher){return Err(CoreError::Conflict("revocation identity mismatch".into()));}
                    item.1.clear();
                    sqlx::query("UPDATE account_erasure_jobs SET body=$2 WHERE id=$1").bind(&claim.job_id).bind(crate::oauth::encode(&work.job)?).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn register_managed_put(&self,tenant:&str,store:&str,key:&str)->CoreResult<ErasureObject>{
                    memoswish_core::assets::validate_asset_id(tenant)?;memoswish_core::assets::validate_asset_id(store)?;memoswish_core::store::validate_key(key)?;
                    if !key.starts_with(&format!("tenants/{tenant}/")){return Err(CoreError::Forbidden("managed PUT tenant prefix mismatch".into()));}
                    let mut tx=self.asset_tx().await?;
                    let id=memoswish_core::ids::new_id();let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES($1,$2,'managed_put',$2,$3,1,$4)").bind(tenant).bind(&id).bind(sqlx::types::Json(serde_json::json!({}))).bind(now).execute(&mut *tx).await.map_err(db_error)?;
                    sqlx::query("INSERT INTO managed_object_writes(tenant_id,id,store_id,object_key) VALUES($1,$2,$3,$4)").bind(tenant).bind(&id).bind(store).bind(key).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(ErasureObject{source:"managed".into(),tenant_id:tenant.into(),id,store_id:store.into(),key:key.into(),version:ObjectVersion::Unknown})
                }
                async fn prepare_managed_compensation(&self,object:&ErasureObject)->CoreResult<()>{
                    if object.source!="managed" || object.version==ObjectVersion::Unknown {return Err(CoreError::invalid("compensation requires a managed receipt"));}
                    let mut tx=self.asset_tx().await?;
                    let outcome=Self::erasure_match_object(&mut tx,object).await?;
                    let erased:i64=sqlx::query_scalar("SELECT COUNT(*) FROM erased_tenants WHERE tenant_id=$1").bind(&object.tenant_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if erased!=1 || !matches!(outcome.as_str(),"uploaded"|"cleanup_pending"|"cleaned"){return Err(CoreError::Forbidden("compensation requires a committed tombstone".into()));}
                    Self::erasure_upload_receipt(&mut tx,object,&object.version).await?;
                    sqlx::query("UPDATE managed_object_writes SET outcome=CASE WHEN outcome='cleaned' THEN outcome ELSE 'cleanup_pending' END WHERE tenant_id=$1 AND id=$2").bind(&object.tenant_id).bind(&object.id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
                async fn record_managed_put(&self,object:&ErasureObject,version:&ObjectVersion)->CoreResult<()>{
                    if object.source!="managed" {return Err(CoreError::invalid("invalid managed PUT source"));}
                    let (kind,id)=Self::erasure_version_fields(version)?;
                    let mut tx=self.asset_tx().await?;
                    // 不把调用时的 Unknown 与已存回执比较；重放必须匹配同一物理版本。
                    let r=sqlx::query("SELECT store_id,object_key,version_kind,version_id FROM managed_object_writes WHERE tenant_id=$1 AND id=$2").bind(&object.tenant_id).bind(&object.id).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or_else(||CoreError::NotFound("managed PUT".into()))?;
                    let actual=Self::erasure_version(&r.get::<String,_>("version_kind"),r.get("version_id"))?;
                    if object.store_id!=r.get::<String,_>("store_id") || object.key!=r.get::<String,_>("object_key") || (actual!=ObjectVersion::Unknown && actual!=*version){return Err(CoreError::Conflict("managed PUT receipt identity mismatch".into()));}
                    sqlx::query("UPDATE managed_object_writes SET version_kind=$3,version_id=$4,outcome=CASE WHEN outcome='uncertain' THEN 'uploaded' ELSE outcome END WHERE tenant_id=$1 AND id=$2").bind(&object.tenant_id).bind(&object.id).bind(kind).bind(id).execute(&mut *tx).await.map_err(db_error)?;
                    Self::erasure_upload_receipt(&mut tx,object,version).await?;
                    sqlx::query("UPDATE background_jobs SET state='succeeded' WHERE tenant_id=$1 AND id=$2 AND kind='managed_put'").bind(&object.tenant_id).bind(&object.id).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }
            }
        };
    };
}
pub(crate) use erasure_impl;
