//! 账户证据为全局窄例外，用途记录始终显式限定工作区与本人。
macro_rules! privacy_impl {
    ($repo:ty, $db:ty) => {
        const _: () = {
            use memoswish_core::{CoreError, CoreResult, Principal};
            use memoswish_protocol::{PrivacyPolicy, PrivacyState, PrivacyUpdate};
            use sqlx::Row;
            impl $repo {
                // 正常更新和恢复撤回共用修订、暂存输出失效及持久化边界。
                pub(crate) async fn privacy_write_tx(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str,user:&str,state:&PrivacyState)->CoreResult<()> {
                    // 全局账户修订使该用户所有工作区的旧解释失效，财务证据独立保留。
                    let tenants: Vec<String> = sqlx::query_scalar("SELECT DISTINCT tenant_id FROM explanation_operations WHERE user_id=$1 AND policy IS NOT NULL")
                        .bind(user).fetch_all(&mut **tx).await.map_err(db_err)?;
                    for tenant in tenants {
                        Self::explanation_erase(tx, &tenant, Some(user)).await?;
                    }
                    // 隐私修订保守清除该账户所有旧诊断，不允许撤回后恢复或再授权复活。
                    sqlx::query("DELETE FROM diagnostic_reports WHERE user_id=$1").bind(user).execute(&mut **tx).await.map_err(db_err)?;
                    // 账户修订对该用户的所有在途外部合成生效，保留 provider 和精确对象清理证据。
                    let clear = if <$db as sqlx::Database>::NAME=="PostgreSQL" {
                        "UPDATE tts_syntheses SET audio=NULL,metadata=NULL WHERE audio IS NOT NULL AND EXISTS(SELECT 1 FROM tts_requesters r WHERE r.tenant_id=tts_syntheses.tenant_id AND r.synthesis_id=tts_syntheses.id AND r.user_id=$1) AND (CAST(work AS JSONB)->'privacy'->'principal'->>'user_id')=$1"
                    } else {
                        "UPDATE tts_syntheses SET audio=NULL,metadata=NULL WHERE audio IS NOT NULL AND EXISTS(SELECT 1 FROM tts_requesters r WHERE r.tenant_id=tts_syntheses.tenant_id AND r.synthesis_id=tts_syntheses.id AND r.user_id=$1) AND json_extract(work,'$.privacy.principal.user_id')=$1"
                    };
                    sqlx::query(clear).bind(user).execute(&mut **tx).await.map_err(db_err)?;
                    sqlx::query("INSERT INTO privacy_accounts(user_id,revision,body) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET revision=excluded.revision,body=excluded.body")
                        .bind(user).bind(state.revision).bind(serde_json::to_string(&state.account_records).map_err(CoreError::internal)?).execute(&mut **tx).await.map_err(db_err)?;
                    sqlx::query("INSERT INTO privacy_purposes(tenant_id,user_id,body) VALUES($1,$2,$3) ON CONFLICT(tenant_id,user_id) DO UPDATE SET body=excluded.body")
                        .bind(tenant).bind(user).bind(serde_json::to_string(&state.purpose_records).map_err(CoreError::internal)?).execute(&mut **tx).await.map_err(db_err)?;
                    Ok(())
                }
                pub(crate) async fn privacy_restore_withdrawal_tx(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str,user:&str,purpose:&str,version:&str,recorded_at:i64)->CoreResult<()> {
                    // 已删除账户/成员不重建；重新加入仍须显式授予，缺记录默认拒绝。
                    let member:i64=sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2")
                        .bind(tenant).bind(user).fetch_one(&mut **tx).await.map_err(db_err)?;
                    if member==0 {return Ok(());}
                    // 即使重复撤回不增加修订，也清除快照里的旧诊断。
                    sqlx::query("DELETE FROM diagnostic_reports WHERE tenant_id=$1 AND user_id=$2").bind(tenant).bind(user).execute(&mut **tx).await.map_err(db_err)?;
                    let mut state=Self::privacy_read_tx(tx,tenant,user).await?;
                    let before=state.revision;
                    let update=PrivacyUpdate {expected_revision:before,kind:purpose.into(),version:version.into(),decision:false,value:String::new()};
                    // 撤回不依赖当前部署政策，也不把日志里的旧修订写回快照。
                    memoswish_core::privacy::transition(&mut state,&PrivacyPolicy::default(),&update,recorded_at)?;
                    if state.revision!=before {
                        for record in &mut state.purpose_records {
                            if record.kind==purpose {record.evidence="restore_suppression".into();}
                        }
                        Self::privacy_write_tx(tx,tenant,user,&state).await?;
                    }
                    Ok(())
                }
                pub(crate) async fn privacy_collection_tx(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str,user:&str)->CoreResult<()> {
                    let body:Option<String>=sqlx::query_scalar("SELECT body FROM privacy_deployment_policy WHERE id=1").fetch_optional(&mut **tx).await.map_err(db_err)?;
                    if let Some(body)=body {
                        let policy:PrivacyPolicy=serde_json::from_str(&body).map_err(CoreError::internal)?;
                        if policy.hosted {
                            let state=Self::privacy_read_tx(tx,tenant,user).await?;
                            memoswish_core::privacy::require_collection(&state,&policy)?;
                        }
                    }
                    Ok(())
                }
                pub(crate) async fn privacy_policy_tx(tx:&mut sqlx::Transaction<'_, $db>,policy:&PrivacyPolicy)->CoreResult<()> {
                    let body:Option<String>=sqlx::query_scalar("SELECT body FROM privacy_deployment_policy WHERE id=1").fetch_optional(&mut **tx).await.map_err(db_err)?;
                    let active:Option<PrivacyPolicy>=body.map(|body|serde_json::from_str(&body).map_err(CoreError::internal)).transpose()?;
                    if active.as_ref()!=Some(policy) {return Err(CoreError::Forbidden("privacy deployment policy changed or is missing".into()));} Ok(())
                }
                pub(crate) async fn privacy_read_tx(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, user: &str) -> CoreResult<PrivacyState> {
                    let row=sqlx::query("SELECT revision,body FROM privacy_accounts WHERE user_id=$1").bind(user).fetch_optional(&mut **tx).await.map_err(db_err)?;
                    let mut state=PrivacyState::default();
                    if let Some(row)=row {
                        state.revision=row.get("revision");
                        state.account_records=serde_json::from_str(&row.get::<String,_>("body")).map_err(CoreError::internal)?;
                    }
                    let body:Option<String>=sqlx::query_scalar("SELECT body FROM privacy_purposes WHERE tenant_id=$1 AND user_id=$2").bind(tenant).bind(user).fetch_optional(&mut **tx).await.map_err(db_err)?;
                    if let Some(body)=body {state.purpose_records=serde_json::from_str(&body).map_err(CoreError::internal)?;}
                    Ok(state)
                }
                pub(crate) async fn privacy_authorize_tx(tx:&mut sqlx::Transaction<'_, $db>, tenant:&str, p:&Principal) -> CoreResult<()> {
                    if tenant!=p.tenant_id {return Err(CoreError::Forbidden("privacy tenant mismatch".into()));}
                    // 使用 TTS 已有的原始委托凭据、注销及成员代际复核。
                    Self::authorize_tx(tx,tenant,&p.user_id,p.credential_generations()?).await?;
                    if !Self::credential_current(tx,p,&[]).await? {return Err(CoreError::Unauthorized("privacy credential was revoked".into()));}
                    Ok(())
                }
            }
            impl $repo {
                pub(crate) async fn privacy_fence_tx(tx:&mut sqlx::Transaction<'_, $db>,tenant:&str,fence:&memoswish_core::privacy::PrivacyFence)->CoreResult<()> {
                    let mut principal=fence.principal.clone();principal.session_access_hash=fence.credential_hash.clone();
                    Self::privacy_authorize_tx(tx,tenant,&principal).await?;
                    Self::privacy_policy_tx(tx,&fence.policy).await?;
                    let state=Self::privacy_read_tx(tx,tenant,&fence.principal.user_id).await?;
                    if state.revision!=fence.revision {return Err(CoreError::Forbidden("privacy changed after admission".into()));}
                    memoswish_core::privacy::require_purpose(&state,&fence.policy,"external_tts")
                }
            }
            #[async_trait::async_trait]
            impl memoswish_core::privacy::PrivacyRepo for $repo {
                async fn privacy_install_policy(&self,policy:&PrivacyPolicy)->CoreResult<()> {
                    memoswish_core::privacy::validate_policy(policy)?;
                    let mut tx=self.pool.begin().await.map_err(db_err)?;Self::session_lock(&mut tx).await?;
                    sqlx::query("INSERT INTO privacy_deployment_policy(id,body) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET body=excluded.body")
                        .bind(serde_json::to_string(policy).map_err(CoreError::internal)?).execute(&mut *tx).await.map_err(db_err)?;
                    tx.commit().await.map_err(db_err)
                }
                async fn privacy_state(&self,tenant:&str,p:&Principal)->CoreResult<PrivacyState>{
                    let mut tx=self.pool.begin().await.map_err(db_err)?;
                    Self::session_lock(&mut tx).await?;
                    Self::privacy_authorize_tx(&mut tx,tenant,p).await?;
                    let state=Self::privacy_read_tx(&mut tx,tenant,&p.user_id).await?;
                    tx.commit().await.map_err(db_err)?;Ok(state)
                }
                async fn privacy_update(&self,tenant:&str,p:&Principal,policy:&PrivacyPolicy,update:&PrivacyUpdate)->CoreResult<PrivacyState>{
                    memoswish_core::lifecycle::require_first_party(p)?;
                    let mut tx=self.pool.begin().await.map_err(db_err)?;
                    let now=Self::session_lock(&mut tx).await?;
                    Self::privacy_policy_tx(&mut tx,policy).await?;
                    Self::privacy_authorize_tx(&mut tx,tenant,p).await?;
                    let mut state=Self::privacy_read_tx(&mut tx,tenant,&p.user_id).await?;
                    let before=state.revision;
                    memoswish_core::privacy::transition(&mut state,policy,update,now)?;
                    if state.revision!=before {
                        Self::privacy_write_tx(&mut tx,tenant,&p.user_id,&state).await?;
                    }
                    tx.commit().await.map_err(db_err)?;Ok(state)
                }
                async fn privacy_admit(&self,tenant:&str,p:&Principal,policy:&PrivacyPolicy,purpose:Option<&str>,revision:Option<i64>)->CoreResult<i64>{
                    let mut tx=self.pool.begin().await.map_err(db_err)?;Self::session_lock(&mut tx).await?;
                    Self::privacy_authorize_tx(&mut tx,tenant,p).await?;
                    Self::privacy_policy_tx(&mut tx,policy).await?;
                    let state=Self::privacy_read_tx(&mut tx,tenant,&p.user_id).await?;
                    if let Some(revision)=revision && revision!=state.revision {return Err(CoreError::Forbidden("privacy changed after admission".into()));}
                    match purpose {Some(purpose)=>memoswish_core::privacy::require_purpose(&state,policy,purpose)?,None=>memoswish_core::privacy::require_collection(&state,policy)?};
                    tx.commit().await.map_err(db_err)?;Ok(state.revision)
                }
            }
        };
    };
}
pub(crate) use privacy_impl;
