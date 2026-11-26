//! 分类保留的窄维护入口；不向业务服务暴露跨租户权限。

use memoswish_core::{CoreError, CoreResult};
use serde::Serialize;

pub use memoswish_core::maintenance::RetentionPolicy;

/// 只输出分类计数和数据库观察点；不输出正文、凭据或对象位置。
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct RetentionReport {
    pub observed_at_ms: i64,
    pub expired_api_metadata: u64,
    pub failed_tts_payloads: u64,
    pub expired_explanation_results: u64,
    pub expired_diagnostics: u64,
}

/// 维护者显式选择租户；每类最多处理 limit 行，重复调用排空积压。
pub async fn sweep(
    url: &str,
    tenant: &str,
    policy: &RetentionPolicy,
    limit: i64,
    apply: bool,
) -> CoreResult<RetentionReport> {
    policy.validate()?;
    memoswish_core::assets::validate_asset_id(tenant)?;
    if !(1..=100).contains(&limit) {
        return Err(CoreError::invalid("invalid retention batch size"));
    }
    match crate::DatabaseKind::from_url(url)? {
        #[cfg(feature = "sqlite")]
        crate::DatabaseKind::Sqlite => {
            crate::sqlite::SqliteRepository::open_runtime(url)
                .await?
                .retention_sweep(tenant, policy, limit, apply)
                .await
        }
        #[cfg(feature = "postgres")]
        crate::DatabaseKind::Postgres => {
            crate::postgres::PostgresRepository::open_runtime(url, 1)
                .await?
                .retention_sweep(tenant, policy, limit, apply)
                .await
        }
        #[allow(unreachable_patterns)]
        _ => Err(CoreError::Unsupported("retention backend is not compiled in".into())),
    }
}

macro_rules! retention_impl {
    ($repo:ty, $db:ty, $expired:literal) => {
        impl $repo {
            pub(crate) async fn maintenance_retention_tx(
                tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, policy: &crate::retention::RetentionPolicy, limit: i64, apply: bool,
            ) -> memoswish_core::CoreResult<crate::retention::RetentionReport> {
                use crate::{assets::db_error, retention::RetentionReport};
                use memoswish_core::CoreError;
                let now = Self::asset_now(tx).await?;
                let cutoff = chrono::DateTime::from_timestamp_millis(
                    now - policy.api_metadata_after_expiry_seconds * 1000,
                ).ok_or_else(|| CoreError::internal("invalid retention clock"))?;
                let tokens: Vec<String> = sqlx::query_scalar(concat!(
                    "SELECT id FROM (", crate::recovery::retained_api_sql!(), ") candidates WHERE tenant_id=$1 AND ", $expired,
                    " ORDER BY expires_at,id LIMIT $3"
                )).bind(tenant).bind(cutoff).bind(limit).fetch_all(&mut **tx).await.map_err(db_error)?;
                // 只清除没有上传交接、没有待处理请求者且已结算的失败合成。
                // 活跃/已发布结果仍有交付目的；不按失败正文期限回收。
                let syntheses: Vec<String> = sqlx::query_scalar(&format!(
                    "SELECT id FROM ({}) candidates WHERE tenant_id=$1 AND available_at_ms<=$2 ORDER BY available_at_ms,id LIMIT $3",crate::recovery::RETAINED_SPEECH.sql
                )).bind(tenant).bind(now - policy.failed_tts_payload_after_schedule_seconds * 1000)
                    .bind(limit).fetch_all(&mut **tx).await.map_err(db_error)?;
                // 正文沿用准入时捕获的期限；请求身份、attempt、账本和结算证据继续保留。
                let explanations: Vec<String> = sqlx::query_scalar(&format!("SELECT id FROM ({}) candidates WHERE tenant_id=$1 ORDER BY id LIMIT $3",crate::recovery::EXPLANATION_RESULTS.at("$2"))).bind(tenant).bind(now).bind(limit).fetch_all(&mut **tx).await.map_err(db_error)?;
                let diagnostics: Vec<String> = sqlx::query_scalar(&format!("SELECT report_id FROM ({}) candidates WHERE tenant_id=$1 ORDER BY expires_at_ms,report_id LIMIT $3",crate::recovery::DIAGNOSTIC_EXPIRY.at("$2")))
                    .bind(tenant).bind(now).bind(limit).fetch_all(&mut **tx).await.map_err(db_error)?;
                let report = RetentionReport {
                    observed_at_ms: now,
                    expired_diagnostics: diagnostics.len() as u64,
                    expired_api_metadata: tokens.len() as u64,
                    failed_tts_payloads: syntheses.len() as u64,
                    expired_explanation_results: explanations.len() as u64,
                };
                if apply {
                    sqlx::query("DELETE FROM diagnostic_reports WHERE tenant_id=$1 AND expires_at_ms<=$2 AND (user_id,report_id) IN (SELECT user_id,report_id FROM diagnostic_reports WHERE tenant_id=$1 AND expires_at_ms<=$2 ORDER BY expires_at_ms,report_id LIMIT $3)")
                        .bind(tenant).bind(now).bind(limit).execute(&mut **tx).await.map_err(db_error)?;
                    for id in tokens {
                        sqlx::query("DELETE FROM api_tokens WHERE tenant_id=$1 AND id=$2")
                            .bind(tenant).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    for id in syntheses {
                        // 只删除正文，不删除原任务、幂等键、请求者、结算和 provider 证据。
                        sqlx::query("UPDATE tts_syntheses SET work='{}',audio=NULL,metadata=NULL WHERE tenant_id=$1 AND id=$2")
                            .bind(tenant).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    for id in explanations {
                        sqlx::query("UPDATE explanation_operations SET result=NULL,result_bytes=0,cache_key=NULL,authority='{}',privacy=NULL,state=CASE WHEN state='settled' THEN 'expired' ELSE state END WHERE tenant_id=$1 AND id=$2")
                            .bind(tenant).bind(id).execute(&mut **tx).await.map_err(db_error)?;
                    }
                }
                Ok(report)
            }

            pub(crate) async fn retention_sweep(
                &self,
                tenant: &str,
                policy: &crate::retention::RetentionPolicy,
                limit: i64,
                apply: bool,
            ) -> memoswish_core::CoreResult<crate::retention::RetentionReport> {
                use crate::assets::db_error;
                use memoswish_core::CoreError;
                policy.validate()?;
                memoswish_core::assets::validate_asset_id(tenant)?;
                if !(1..=100).contains(&limit) {
                    return Err(CoreError::invalid("invalid retention batch size"));
                }
                let mut tx = self.lifecycle_tx(&[tenant.to_string()]).await?;
                let claim=if apply {
                    use memoswish_core::maintenance::*;
                    let task=TaskRegistration{kind:TaskKind::Retention,tenant:tenant.into(),policy:Some(policy.clone())};
                    let id=task.id()?;
                    let body=crate::maintenance::policy_json(&task)?;
                    sqlx::query("INSERT INTO maintenance_tasks(id,task_kind,payload_version,target_tenant,policy,enabled) VALUES($1,'retention',1,$2,$3,0) ON CONFLICT(id) DO NOTHING").bind(&id).bind(tenant).bind(body).execute(&mut *tx).await.map_err(db_error)?;
                    let now=Self::asset_now(&mut tx).await?;
                    sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms,work_scope) VALUES('',$1,'maintenance',$1,'{}',1,$2,'maintenance') ON CONFLICT(tenant_id,id) DO NOTHING").bind(&id).bind(now).execute(&mut *tx).await.map_err(db_error)?;
                    let token=memoswish_core::ids::new_id();
                    let changed=sqlx::query("UPDATE background_jobs SET state='running',token=$2,worker='retention-cli',lease_until_ms=$3 WHERE tenant_id='' AND id=$1 AND work_scope='maintenance' AND (state='queued' OR (state='running' AND lease_until_ms<=$4))")
                        .bind(&id).bind(&token).bind(now+LEASE_MS).bind(now).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                    if changed!=1 {return Err(CoreError::Conflict("retention task already has a current owner".into()));}
                    let claim=MaintenanceClaim{task_id:id,token,worker:"retention-cli".into(),kind:TaskKind::Retention};
                    Self::maintenance_fence(&mut tx,&claim).await?;
                    Some(claim)
                } else {None};
                let report = Self::maintenance_retention_tx(&mut tx, tenant, policy, limit, apply).await?;
                if let Some(claim)=claim {
                    Self::maintenance_finish_tx(&mut tx,&claim,true,false).await?;
                    tx.commit().await.map_err(db_error)?;
                } else { tx.rollback().await.map_err(db_error)?; }
                Ok(report)
            }
        }
    };
}
pub(crate) use retention_impl;
