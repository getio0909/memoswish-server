//! 单一 background_jobs 权威；detail 仅保存目录、策略与延续，接纳回执没有执行租约。

use memoswish_core::{CoreError, CoreResult, maintenance::*};

pub(crate) fn policy_json(task: &TaskRegistration) -> CoreResult<String> {
    task.validate()?;
    task.policy
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(CoreError::internal)
        .map(|v| v.unwrap_or("{}".into()))
}

macro_rules! maintenance_impl {
    ($repo:ty, $db:ty) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, maintenance::*};
            use crate::assets::db_error;
            use sqlx::Row;

            impl $repo {
                pub(crate) async fn maintenance_fence(tx: &mut sqlx::Transaction<'_, $db>, claim: &MaintenanceClaim) -> CoreResult<()> {
                    // 所有入口先持有既有注册写锁，然后观察实际数据库时间。
                    let now = Self::asset_now(tx).await?;
                    let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs j JOIN maintenance_tasks m ON m.id=j.id AND m.partition_id=j.tenant_id WHERE j.tenant_id='' AND j.id=$1 AND j.work_scope='maintenance' AND j.kind='maintenance' AND j.state='running' AND j.token=$2 AND j.worker=$3 AND j.lease_until_ms>$4 AND m.task_kind=$5 AND m.payload_version=1")
                        .bind(&claim.task_id).bind(&claim.token).bind(&claim.worker).bind(now).bind(claim.kind.as_str()).fetch_one(&mut **tx).await.map_err(db_error)?;
                    if live != 1 { return Err(CoreError::Conflict("maintenance claim expired or replaced".into())); }
                    Ok(())
                }

                pub(crate) async fn maintenance_finish_tx(tx: &mut sqlx::Transaction<'_, $db>, claim: &MaintenanceClaim, cycle: bool, failed: bool) -> CoreResult<bool> {
                    // 最后一次 fence 与修改同事务；失败使本页及游标整体回滚。
                    Self::maintenance_fence(tx, claim).await?;
                    let now=Self::asset_now(tx).await?;
                    let mut continuation = !cycle && !failed && claim.kind.discovery();
                    if cycle {
                        sqlx::query("UPDATE maintenance_tasks SET cursor='[]',cycle=cycle+1 WHERE id=$1").bind(&claim.task_id).execute(&mut **tx).await.map_err(db_error)?;
                        if claim.kind.discovery() {
                            continuation = !Self::maintenance_discover_tx(tx, claim, 1).await?.is_empty();
                        }
                    }
                    sqlx::query("UPDATE background_jobs SET state='queued',token=NULL,worker=NULL,lease_until_ms=0,available_at_ms=$2,attempts=0,error=$3 WHERE tenant_id='' AND id=$1 AND work_scope='maintenance'")
                        .bind(&claim.task_id).bind(if continuation { now } else { now+CADENCE_MS }).bind(if failed {Some("maintenance page failed")} else {None}).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(continuation)
                }

                async fn maintenance_discover_tx(tx: &mut sqlx::Transaction<'_, $db>, claim: &MaintenanceClaim, limit: i64) -> CoreResult<Vec<DiscoveryItem>> {
                    if !claim.kind.discovery() {return Err(CoreError::invalid("task is not recovery discovery"));}
                    Self::maintenance_fence(tx,claim).await?;
                    let cursor: String=sqlx::query_scalar("SELECT cursor FROM maintenance_tasks WHERE id=$1").bind(&claim.task_id).fetch_one(&mut **tx).await.map_err(db_error)?;
                    let cursor: Vec<String>=serde_json::from_str(&cursor).map_err(|_|CoreError::internal("invalid maintenance cursor"))?;
                    let (tenant,id)=match cursor.as_slice() {[] => ("",""), [t,i] => (t.as_str(),i.as_str()), _ => return Err(CoreError::internal("invalid maintenance cursor"))};
                    let now = Self::asset_now(tx).await?;
                    let (authority, key, extra) = match claim.kind {
                        TaskKind::ErasureRecovery => (&crate::recovery::ERASURES,"id"," AND state<>'dead'"),
                        TaskKind::DiagnosticRecovery => (&crate::recovery::DIAGNOSTICS,"id",""),
                        TaskKind::ImportRecovery => (&crate::recovery::IMPORTS,"id",""),
                        TaskKind::SpeechRecovery => (&crate::recovery::SPEECH,"id",""),
                        TaskKind::AttachmentRecovery => (&crate::recovery::ATTACHMENTS,"item_id",""),
                        _ => unreachable!(),
                    };
                    let mut candidates=authority.at(&now.to_string());
                    if claim.kind==TaskKind::SpeechRecovery {
                        candidates.push_str(" UNION ");
                        candidates.push_str(&crate::recovery::BGM.at(&now.to_string()));
                    }
                    let sql=format!("SELECT tenant_id,{key} FROM ({candidates}) recovery WHERE (tenant_id>$1 OR (tenant_id=$1 AND {key}>$2)){extra} ORDER BY tenant_id,{key} LIMIT $3");
                    let rows = sqlx::query(&sql).bind(tenant).bind(id).bind(limit).fetch_all(&mut **tx).await.map_err(db_error)?;
                    Ok(rows.iter().map(|r|DiscoveryItem{tenant:r.get("tenant_id"),id:r.get(if claim.kind==TaskKind::AttachmentRecovery {"item_id"} else {"id"})}).collect())
                }

                async fn maintenance_identity_tx(tx: &mut sqlx::Transaction<'_, $db>) -> CoreResult<()> {
                    let now=Self::asset_now(tx).await?/1000;
                    for expiry in &crate::recovery::IDENTITY_EXPIRY[..3] {
                        let (table,key)=(expiry.table,expiry.key);
                        let predicate=expiry.predicate("$1");
                        let sql=format!("DELETE FROM {table} WHERE {key} IN (SELECT {key} FROM {table} WHERE {predicate} ORDER BY expires_at,{key} LIMIT $2)");
                        sqlx::query(&sql).bind(now).bind(PAGE_SIZE).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    sqlx::query("DELETE FROM identity_events WHERE (issuer,event_hash) IN (SELECT issuer,event_hash FROM identity_events WHERE expires_at<=$1 ORDER BY expires_at,issuer,event_hash LIMIT $2)").bind(now).bind(PAGE_SIZE).execute(&mut **tx).await.map_err(db_error)?;
                    let sessions:Vec<String>=sqlx::query_scalar("SELECT id FROM app_sessions WHERE expires_at<=$1 ORDER BY expires_at,id LIMIT $2").bind(now).bind(PAGE_SIZE).fetch_all(&mut **tx).await.map_err(db_error)?;
                    for id in sessions {
                        // refresh 族证据仍按族绝对期限删除，不使用 access 的较短期限。
                        sqlx::query("DELETE FROM recent_authentication WHERE hash IN (SELECT assurance_hash FROM app_session_credentials WHERE session_id=$1)").bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                        sqlx::query("DELETE FROM app_sessions WHERE id=$1").bind(&id).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    sqlx::query(&format!("DELETE FROM identity_unlink_fences WHERE identity_hash IN (SELECT identity_hash FROM ({}) candidates ORDER BY identity_hash LIMIT $1)",crate::recovery::FENCES.sql)).bind(PAGE_SIZE).execute(&mut **tx).await.map_err(db_error)?;
                    Ok(())
                }

                async fn maintenance_oauth_tx(tx: &mut sqlx::Transaction<'_, $db>) -> CoreResult<()> {
                    let now=Self::asset_now(tx).await?/1000;
                    for expiry in crate::recovery::OAUTH_EXPIRY {
                        let (table,key)=(expiry.table,expiry.key);
                        let predicate=expiry.predicate("$1");
                        let sql=format!("DELETE FROM {table} WHERE {key} IN (SELECT {key} FROM {table} WHERE {predicate} ORDER BY expires_at,{key} LIMIT $2)");
                        sqlx::query(&sql).bind(now).bind(PAGE_SIZE).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    Ok(())
                }
            }

            #[async_trait::async_trait]
            impl MaintenanceRepo for $repo {
                async fn register_maintenance(&self,task:&TaskRegistration)->CoreResult<String> {
                    let id=task.id()?;
                    let policy=crate::maintenance::policy_json(task)?;
                    let tenants=if task.tenant.is_empty(){vec![]}else{vec![task.tenant.clone()]};
                    let mut tx=self.lifecycle_tx(&tenants).await?;
                    if !task.tenant.is_empty() {
                        let live:i64=sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM erased_tenants WHERE tenant_id=$1)").bind(&task.tenant).fetch_one(&mut *tx).await.map_err(db_error)?;
                        if live!=1 {return Err(CoreError::NotFound("retention tenant".into()));}
                    }
                    sqlx::query("INSERT INTO maintenance_tasks(id,task_kind,payload_version,target_tenant,policy) VALUES($1,$2,1,$3,$4) ON CONFLICT(id) DO NOTHING").bind(&id).bind(task.kind.as_str()).bind(&task.tenant).bind(&policy).execute(&mut *tx).await.map_err(db_error)?;
                    let actual:(String,i64,String,String)=sqlx::query_as("SELECT task_kind,payload_version,target_tenant,policy FROM maintenance_tasks WHERE id=$1").bind(&id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    if actual!=(task.kind.as_str().into(),1,task.tenant.clone(),policy) {return Err(CoreError::Conflict("maintenance registration differs from durable policy".into()));}
                    sqlx::query("UPDATE maintenance_tasks SET enabled=1 WHERE id=$1").bind(&id).execute(&mut *tx).await.map_err(db_error)?;
                    let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope) VALUES('',$1,'maintenance',$1,'{}',1,$2,'maintenance') ON CONFLICT(tenant_id,id) DO NOTHING").bind(&id).bind(now).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(id)
                }

                async fn maintenance_tasks(&self,kind:TaskKind,after:&str)->CoreResult<Vec<String>> {
                    let mut tx=self.asset_tx().await?;
                    let now=Self::asset_now(&mut tx).await?;
                    let tasks=sqlx::query_scalar("SELECT m.id FROM maintenance_tasks m JOIN background_jobs j ON j.tenant_id=m.partition_id AND j.id=m.id WHERE m.task_kind=$1 AND m.payload_version=1 AND m.enabled=1 AND m.id>$2 AND ((j.state='queued' AND j.available_at_ms<=$3) OR (j.state='running' AND j.lease_until_ms<=$3)) ORDER BY j.available_at_ms,m.id LIMIT $4")
                        .bind(kind.as_str()).bind(after).bind(now).bind(PAGE_SIZE).fetch_all(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(tasks)
                }

                async fn claim_maintenance(&self,task:&str,worker:&str)->CoreResult<Option<MaintenanceClaim>> {
                    memoswish_core::assets::validate_asset_id(worker)?;
                    let mut tx=self.asset_tx().await?;
                    let now=Self::asset_now(&mut tx).await?;
                    let row=sqlx::query("SELECT m.task_kind,m.payload_version FROM background_jobs j JOIN maintenance_tasks m ON m.id=j.id AND m.partition_id=j.tenant_id WHERE j.tenant_id='' AND j.id=$1 AND j.work_scope='maintenance' AND j.kind='maintenance' AND ((j.state='queued' AND j.available_at_ms<=$2) OR (j.state='running' AND j.lease_until_ms<=$2))").bind(task).bind(now).fetch_optional(&mut *tx).await.map_err(db_error)?;
                    let Some(row)=row else {return Ok(None);};
                    let kind:TaskKind=serde_json::from_value(serde_json::Value::String(row.get("task_kind"))).map_err(|_|CoreError::Unsupported("unknown maintenance task".into()))?;
                    if row.get::<i64,_>("payload_version")!=1 {return Err(CoreError::Unsupported("unknown maintenance payload version".into()));}
                    let token=memoswish_core::ids::new_id();
                    sqlx::query("UPDATE background_jobs SET state='running',token=$2,worker=$3,lease_until_ms=$4 WHERE tenant_id='' AND id=$1 AND work_scope='maintenance'").bind(task).bind(&token).bind(worker).bind(now+LEASE_MS).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(Some(MaintenanceClaim{task_id:task.into(),token,worker:worker.into(),kind}))
                }

                async fn renew_maintenance(&self,claim:&MaintenanceClaim)->CoreResult<()> {
                    let mut tx=self.asset_tx().await?;
                    Self::maintenance_fence(&mut tx,claim).await?;
                    let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("UPDATE background_jobs SET lease_until_ms=$2 WHERE tenant_id='' AND id=$1 AND work_scope='maintenance'").bind(&claim.task_id).bind(now+LEASE_MS).execute(&mut *tx).await.map_err(db_error)?;
                    tx.commit().await.map_err(db_error)
                }

                async fn release_maintenance(&self,claim:&MaintenanceClaim,failed:bool)->CoreResult<()> {
                    let mut tx=self.asset_tx().await?;
                    Self::maintenance_finish_tx(&mut tx,claim,false,failed).await?;
                    tx.commit().await.map_err(db_error)
                }

                async fn maintenance_sql_page(&self,claim:&MaintenanceClaim)->CoreResult<()> {
                    if claim.kind.discovery(){return Err(CoreError::invalid("recovery requires durable admission"));}
                    // 与原保留入口沿用注册锁→租户锁的顺序。
                    let target:Option<String>=sqlx::query_scalar("SELECT target_tenant FROM maintenance_tasks WHERE id=$1").bind(&claim.task_id).fetch_optional(&self.pool).await.map_err(db_error)?;
                    let tenants=target.filter(|t|!t.is_empty()).into_iter().collect::<Vec<_>>();
                    let mut tx=self.lifecycle_tx(&tenants).await?;
                    Self::maintenance_fence(&mut tx,claim).await?;
                    let mut cycle = true;
                    match claim.kind {
                        TaskKind::ExplanationRecovery => {
                            let cursor: String = sqlx::query_scalar("SELECT cursor FROM maintenance_tasks WHERE id=$1")
                                .bind(&claim.task_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                            let cursor: Vec<String> = serde_json::from_str(&cursor)
                                .map_err(|_| CoreError::internal("invalid maintenance cursor"))?;
                            let after = match cursor.as_slice() {
                                [] => None,
                                [tenant, id] => Some((tenant.as_str(), id.as_str())),
                                _ => return Err(CoreError::internal("invalid maintenance cursor")),
                            };
                            let page = Self::maintain_explanations_tx(&mut tx, after).await?;
                            if let Some(last) = page.last() {
                                let cursor = serde_json::to_string(&[&last.0, &last.1]).map_err(CoreError::internal)?;
                                sqlx::query("UPDATE maintenance_tasks SET cursor=$2 WHERE id=$1")
                                    .bind(&claim.task_id).bind(cursor).execute(&mut *tx).await.map_err(db_error)?;
                                cycle = false;
                            }
                        },
                        TaskKind::PasswordExpiry => {
                            let now = Self::asset_now(&mut tx).await? / 1000;
                            sqlx::query(&format!("DELETE FROM password_challenges WHERE (user_id,purpose) IN (SELECT user_id,purpose FROM ({}) candidates ORDER BY expires_at,user_id,purpose LIMIT $2)",crate::recovery::PASSWORD_EXPIRY.at("(CAST($1 AS BIGINT)*1000)")))
                                .bind(now).bind(PAGE_SIZE).execute(&mut *tx).await.map_err(db_error)?;
                        },
                        TaskKind::FeedExpiry => {Self::maintenance_feed_tx(&mut tx,PAGE_SIZE as u32).await?;},
                        TaskKind::IdentityExpiry => Self::maintenance_identity_tx(&mut tx).await?,
                        TaskKind::OAuthExpiry => Self::maintenance_oauth_tx(&mut tx).await?,
                        TaskKind::TombstoneReconcile => Self::maintenance_tombstones_tx(&mut tx,PAGE_SIZE).await?,
                        TaskKind::Retention => {
                            let (tenant,body):(String,String)=sqlx::query_as("SELECT target_tenant,policy FROM maintenance_tasks WHERE id=$1").bind(&claim.task_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                            let policy:RetentionPolicy=serde_json::from_str(&body).map_err(|_|CoreError::invalid("invalid durable retention policy"))?;
                            policy.validate()?;
                            Self::maintenance_retention_tx(&mut tx,&tenant,&policy,PAGE_SIZE,true).await?;
                        },
                        _=>unreachable!(),
                    }
                    Self::maintenance_finish_tx(&mut tx,claim,cycle,false).await?;
                    tx.commit().await.map_err(db_error)
                }

                async fn maintenance_discover(&self,claim:&MaintenanceClaim)->CoreResult<Vec<DiscoveryItem>> {
                    let mut tx=self.asset_tx().await?;
                    let page=Self::maintenance_discover_tx(&mut tx,claim,PAGE_SIZE).await?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(page)
                }

                async fn admit_maintenance_item(&self,claim:&MaintenanceClaim,item:&DiscoveryItem)->CoreResult<MaintenanceAdmission> {
                    let mut tx=self.asset_tx().await?;
                    // 使用有序游标拒绝任意目标、重放旧页及跨租户伪造。
                    let next=Self::maintenance_discover_tx(&mut tx,claim,1).await?;
                    if next.first()!=Some(item){return Err(CoreError::Conflict("maintenance discovery item changed".into()));}
                    let cycle:i64=sqlx::query_scalar("SELECT cycle FROM maintenance_tasks WHERE id=$1").bind(&claim.task_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                    let admission_id=memoswish_core::ids::new_id();
                    let now=Self::asset_now(&mut tx).await?;
                    Self::maintenance_fence(&mut tx,claim).await?;
                    sqlx::query("INSERT INTO maintenance_admissions(task_id,cycle,tenant_id,item_id,admission_id,admitted_at_ms) VALUES($1,$2,$3,$4,$5,$6)").bind(&claim.task_id).bind(cycle).bind(&item.tenant).bind(&item.id).bind(&admission_id).bind(now).execute(&mut *tx).await.map_err(db_error)?;
                    let cursor=serde_json::to_string(&[&item.tenant,&item.id]).map_err(CoreError::internal)?;
                    sqlx::query("UPDATE maintenance_tasks SET cursor=$2 WHERE id=$1").bind(&claim.task_id).bind(cursor).execute(&mut *tx).await.map_err(db_error)?;
                    Self::maintenance_fence(&mut tx,claim).await?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(MaintenanceAdmission{admission_id,item:item.clone(),kind:claim.kind})
                }

                async fn complete_maintenance_cycle(&self,claim:&MaintenanceClaim)->CoreResult<bool> {
                    let mut tx=self.asset_tx().await?;
                    if !Self::maintenance_discover_tx(&mut tx,claim,1).await?.is_empty(){return Err(CoreError::Conflict("maintenance cycle has remaining discovery work".into()));}
                    // 在同一注册锁下重置游标、复用原权威观察 wrapped head 并释放旧凭据。
                    let remaining = Self::maintenance_finish_tx(&mut tx,claim,true,false).await?;
                    tx.commit().await.map_err(db_error)?;
                    Ok(remaining)
                }
            }
        };
    };
}
pub(crate) use maintenance_impl;
