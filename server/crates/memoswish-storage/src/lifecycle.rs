//! 双数据库共用的生命周期事务；复用注册锁、历史世代和持久擦除任务。

macro_rules! lifecycle_impl {
    ($repo:ty, $db:ty, $tenant_lock:literal) => {
        const _: () = {
            use memoswish_core::identity::ErasureJob;
            use memoswish_core::lifecycle::*;
            use memoswish_core::{AccountPrincipal, CoreError, CoreResult, Principal, Role};
            use sqlx::Row;

            impl $repo {
                pub(crate) async fn lifecycle_tx(&self, tenants: &[String]) -> CoreResult<sqlx::Transaction<'_, $db>> {
                    let mut tx = self.pool.begin().await.map_err(db_err)?;
                    // 首条写入同时避免 SQLite 的延迟事务升级，并与签发、OIDC 完成及成员变更串行。
                    sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    Self::lifecycle_lock_tenants(&mut tx, tenants).await?;
                    Ok(tx)
                }


                pub(crate) async fn lifecycle_account_authorize(tx: &mut sqlx::Transaction<'_, $db>, authority: &AccountAuthority) -> CoreResult<()> {
                    let p = match authority {
                        AccountAuthority::Workspace(p) => {
                            Self::lifecycle_authorize(tx, p).await?;
                            return Ok(());
                        }
                        AccountAuthority::Account(p) => p,
                    };
                    match (&p.session_id, &p.session_access_hash) {
                        (Some(id), Some(hash)) => {
                            let a = Self::session_access_tx(tx, hash).await?;
                            if a.family.id != *id
                                || a.family.user_id != p.user_id
                                || a.family.generation != p.generation
                                || a.credential.tenant_id.is_some()
                            {
                                return Err(CoreError::Unauthorized(
                                    "account session authority does not match principal".into(),
                                ));
                            }
                        }
                        (None, None) => {
                            if let Some(iat) = p.legacy_issued_at {
                                Self::legacy_session_tx(tx, &p.user_id, Some(p.generation), iat).await?;
                            } else if p.user_id != memoswish_core::ids::LOCAL_USER_ID {
                                return Err(CoreError::Unauthorized("legacy credential evidence is missing".into()));
                            }
                        }
                        _ => {
                            return Err(CoreError::Unauthorized(
                                "account session credential identity is missing".into(),
                            ));
                        }
                    }
                    let valid: i64 =
                        sqlx::query_scalar("SELECT COUNT(*) FROM account_auth_epochs WHERE user_id=$1 AND generation=$2")
                            .bind(&p.user_id)
                            .bind(p.generation)
                            .fetch_one(&mut **tx)
                            .await
                            .map_err(db_err)?;
                    if valid != 1 {
                        return Err(CoreError::Unauthorized("account session was revoked".into()));
                    }
                    Ok(())
                }

                pub(crate) async fn lifecycle_commit(&self, tx: sqlx::Transaction<'_, $db>) -> CoreResult<()> {
                    #[cfg(test)]
                    if let Some(gate) = &self.lifecycle_gate {
                        gate.pause(crate::learning::TestPoint::BeforeCommit).await;
                    }
                    tx.commit().await.map_err(db_err)
                }

                pub(crate) async fn lifecycle_lock_tenants(
                    tx: &mut sqlx::Transaction<'_, $db>,
                    tenants: &[String],
                ) -> CoreResult<()> {
                    // 调用者传入已排序的工作区集合，父锁先于成员、学习及授权记录。
                    for tenant in tenants {
                        sqlx::query($tenant_lock)
                            .bind(tenant)
                            .fetch_optional(&mut **tx)
                            .await
                            .map_err(db_err)?;
                    }
                    Ok(())
                }

                pub(crate) async fn lifecycle_authorize(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal) -> CoreResult<Role> {
                    let generations = require_first_party(p)?;
                    if p.via == "jwt" {
                        let iat = p.legacy_issued_at.ok_or_else(|| CoreError::Unauthorized("legacy credential evidence is missing".into()))?;
                        Self::legacy_session_tx(tx, &p.user_id, p.auth_generation, iat).await?;
                    }
                    Self::session_principal_tx(tx, p).await?;
                    Self::authorize_tx(tx, &p.tenant_id, &p.user_id, generations).await
                }

                async fn lifecycle_owner(tx: &mut sqlx::Transaction<'_, $db>, p: &Principal) -> CoreResult<()> {
                    let role = Self::lifecycle_authorize(tx, p).await?;
                    if role != Role::Owner {
                        return Err(CoreError::Forbidden(
                            "workspace lifecycle command requires current owner".into(),
                        ));
                    }
                    Ok(())
                }

                async fn lifecycle_owner_count(tx: &mut sqlx::Transaction<'_, $db>, tenant: &str) -> CoreResult<i64> {
                    sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id=$1 AND role='owner'")
                        .bind(tenant)
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(db_err)
                }

                async fn lifecycle_clear_authorization(
                    tx: &mut sqlx::Transaction<'_, $db>,
                    tenant: &str,
                    user: &str,
                ) -> CoreResult<()> {
                    // 外部身份和账户会话属于全局账户，不随成员关系撤销。
                    for table in ["api_tokens", "oauth_grants", "auth_browser_sessions"] {
                        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id=$1 AND user_id=$2"))
                            .bind(tenant)
                            .bind(user)
                            .execute(&mut **tx)
                            .await
                            .map_err(db_err)?;
                    }
                    Ok(())
                }

                pub(crate) async fn lifecycle_leave_tx(
                    tx: &mut sqlx::Transaction<'_, $db>,
                    tenant: &str,
                    user: &str,
                ) -> CoreResult<()> {
                    Self::speech_revoke_member(tx, tenant, user).await?;
                    Self::import_erase(tx, tenant, Some(user)).await?;
                    Self::explanation_erase(tx, tenant, Some(user)).await?;
                    // 只移除个人提交回执；provider、上传与计量责任由原持久表继续承担。
                    for table in ["tts_submission_items", "tts_submissions"] {
                        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id=$1 AND user_id=$2"))
                            .bind(tenant)
                            .bind(user)
                            .execute(&mut **tx)
                            .await
                            .map_err(db_err)?;
                    }
                    Self::lifecycle_clear_authorization(tx, tenant, user).await?;
                    for table in [
                        "personal_favorites",
                        "favorite_operations",
                        "memory_states",
                        "feedback_events",
                        "feed_sessions",
                        "tenant_memberships",
                    ] {
                        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id=$1 AND user_id=$2"))
                            .bind(tenant)
                            .bind(user)
                            .execute(&mut **tx)
                            .await
                            .map_err(db_err)?;
                    }
                    // 不创建 erased_users；历史世代和引用它的持久任务、配额预留继续保留。
                    Ok(())
                }

                pub(crate) async fn lifecycle_delete_tx(
                    tx: &mut sqlx::Transaction<'_, $db>,
                    tenant: &str,
                ) -> CoreResult<ErasureJob> {
                    Self::speech_erase_tenant(tx, tenant).await?;
                    Self::import_erase(tx, tenant, None).await?;
                    Self::explanation_erase(tx, tenant, None).await?;
                    // 先删子项再删提交，不触碰外部副作用及账本证据。
                    for table in ["tts_submission_items", "tts_submissions"] {
                        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id=$1"))
                            .bind(tenant)
                            .execute(&mut **tx)
                            .await
                            .map_err(db_err)?;
                    }
                    let job = ErasureJob {
                        id: memoswish_core::ids::new_id(),
                        tenant_id: Some(tenant.into()),
                        purge_assets: true,
                        credentials: Vec::new(),
                    };
                    sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
                        .bind(&job.id)
                        .bind(crate::oauth::encode(&job)?)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_err)?;
                    sqlx::query("INSERT INTO erased_tenants(tenant_id) VALUES($1) ON CONFLICT DO NOTHING")
                        .bind(tenant)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_err)?;
                    for table in [
                        "asset_references",
                        "usage_counters",
                        "memory_states",
                        "feedback_events",
                        "feed_sessions",
                        "api_tokens",
                        "cards",
                        "decks",
                        "bgm_tracks",
                        "erased_users",
                    ] {
                        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id=$1"))
                            .bind(tenant)
                            .execute(&mut **tx)
                            .await
                            .map_err(db_err)?;
                    }
                    // 成员及其 OAuth 授权级联删除；全局账户、身份及客户端注册没有该级联。
                    sqlx::query("DELETE FROM tenants WHERE id=$1")
                        .bind(tenant)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_err)?;
                    Ok(job)
                }

                async fn lifecycle_change_role(
                    tx: &mut sqlx::Transaction<'_, $db>,
                    tenant: &str,
                    user: &str,
                    role: Role,
                ) -> CoreResult<()> {
                    let previous: i64 = sqlx::query_scalar(
                        "SELECT MAX(generation) FROM membership_generations WHERE tenant_id=$1 AND user_id=$2",
                    )
                    .bind(tenant)
                    .bind(user)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(db_err)?;
                    let generation = previous
                        .checked_add(1)
                        .ok_or_else(|| CoreError::Conflict("membership generation exhausted".into()))?;
                    Self::speech_revoke_member(tx, tenant, user).await?;
                    Self::lifecycle_clear_authorization(tx, tenant, user).await?;
                    sqlx::query("INSERT INTO membership_generations(tenant_id,user_id,generation) VALUES($1,$2,$3)")
                        .bind(tenant)
                        .bind(user)
                        .bind(generation)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_err)?;
                    sqlx::query("UPDATE tenant_memberships SET role=$3,generation=$4,revision=revision+1 WHERE tenant_id=$1 AND user_id=$2")
                                        .bind(tenant).bind(user).bind(role.as_str()).bind(generation).execute(&mut **tx).await.map_err(db_err)?;
                    Ok(())
                }
            }

            #[async_trait::async_trait]
            impl LifecycleRepo for $repo {
                async fn export_personal(&self, p: &AccountAuthority) -> CoreResult<memoswish_protocol::PersonalAccountExport> {
                    self.personal_export(p).await
                }
                async fn export_workspace(&self, p: &Principal) -> CoreResult<memoswish_protocol::WorkspaceExport> {
                    self.workspace_export(p).await
                }
                async fn revalidate_account_export(&self, p: &AccountAuthority) -> CoreResult<()> {
                    let tenants = match p {AccountAuthority::Workspace(p) => vec![p.tenant_id.clone()], _ => vec![]};
                    let mut tx = self.lifecycle_tx(&tenants).await?;
                    Self::lifecycle_account_authorize(&mut tx, p).await?;
                    self.lifecycle_commit(tx).await
                }
                async fn revalidate_workspace_export(&self, p: &Principal, api_token_hash: Option<&str>) -> CoreResult<()> {
                    let mut tx = self.lifecycle_tx(std::slice::from_ref(&p.tenant_id)).await?;
                    Self::export_workspace_authorize(&mut tx, p, p.can(memoswish_core::Permission::AccountExport)).await?;
                    if p.via == "api_token" {
                        let hash = api_token_hash.ok_or_else(|| CoreError::Unauthorized("export token identity missing".into()))?;
                        let row = sqlx::query("UPDATE api_tokens SET revoked=revoked WHERE tenant_id=$1 AND user_id=$2 AND token_hash=$3 AND revoked=FALSE AND account_generation=$4 AND membership_generation=$5 RETURNING CAST(scopes AS TEXT) AS scopes,expires_at")
                            .bind(&p.tenant_id).bind(&p.user_id).bind(hash).bind(p.auth_generation).bind(p.membership_generation).fetch_optional(&mut *tx).await.map_err(db_err)?
                            .ok_or_else(|| CoreError::Unauthorized("export token was revoked".into()))?;
                        let scopes: Vec<String> = serde_json::from_str(&row.try_get::<String,_>("scopes").map_err(db_err)?).map_err(CoreError::internal)?;
                        let expires: Option<chrono::DateTime<chrono::Utc>> = row.try_get("expires_at").map_err(db_err)?;
                        if p.scopes.as_ref() != Some(&scopes) || expires.is_some_and(|t| t < chrono::Utc::now()) {
                            return Err(CoreError::Unauthorized("export token authority changed".into()));
                        }
                    }
                    self.lifecycle_commit(tx).await
                }
                async fn legacy_close_account(&self, p: &Principal) -> CoreResult<Vec<ErasureJob>> {
                    require_first_party(p)?;
                    let mut tx = self.lifecycle_tx(&[]).await?;
                    let rows = sqlx::query("SELECT tenant_id FROM tenant_memberships WHERE user_id=$1 ORDER BY tenant_id")
                        .bind(&p.user_id).fetch_all(&mut *tx).await.map_err(db_err)?;
                    let tenants: Vec<String> = rows.iter().map(|r| r.get("tenant_id")).collect();
                    Self::lifecycle_lock_tenants(&mut tx, &tenants).await?;
                    let role = Self::lifecycle_authorize(&mut tx, p).await?;
                    if tenants.len() != 1 {
                        return Err(CoreError::UseExplicitCommand);
                    }
                    let mut jobs = Vec::new();
                    if role == Role::Owner {
                        jobs.push(Self::lifecycle_delete_tx(&mut tx, &p.tenant_id).await?);
                    } else {
                        Self::lifecycle_leave_tx(&mut tx, &p.tenant_id, &p.user_id).await?;
                    }
                    jobs.push(Self::close_account_tx(&mut tx, &p.user_id, p.credential_generations()?.account).await?);
                    self.lifecycle_commit(tx).await?;
                    Ok(jobs)
                }
                async fn leave_workspace(&self, p: &Principal) -> CoreResult<()> {
                    require_first_party(p)?;
                    if p.via == "single_user" && p.tenant_id == memoswish_core::ids::LOCAL_TENANT_ID {
                        return Err(CoreError::Conflict("local workspace departure requires CloseAccount".into()));
                    }
                    let mut tx = self.lifecycle_tx(std::slice::from_ref(&p.tenant_id)).await?;
                    let role = Self::lifecycle_authorize(&mut tx, p).await?;
                    if role == Role::Owner && Self::lifecycle_owner_count(&mut tx, &p.tenant_id).await? <= 1 {
                        return Err(CoreError::Conflict(
                            "sole owner must transfer ownership or delete workspace".into(),
                        ));
                    }
                    Self::lifecycle_leave_tx(&mut tx, &p.tenant_id, &p.user_id).await?;
                    self.lifecycle_commit(tx).await
                }

                async fn delete_workspace(&self, p: &Principal, command: &DeleteWorkspace) -> CoreResult<ErasureJob> {
                    require_first_party(p)?;
                    if command.confirmed_tenant_id != p.tenant_id {
                        return Err(CoreError::invalid(
                            "workspace deletion confirmation does not match target",
                        ));
                    }
                    // 单用户主体不能独立删除 local，部署模式的完整校验由认证服务补充。
                    if p.via == "single_user" && p.tenant_id == memoswish_core::ids::LOCAL_TENANT_ID {
                        return Err(CoreError::Conflict(
                            "local workspace deletion requires CloseAccount".into(),
                        ));
                    }
                    let mut tx = self.lifecycle_tx(std::slice::from_ref(&p.tenant_id)).await?;
                    Self::lifecycle_owner(&mut tx, p).await?;
                    let job = Self::lifecycle_delete_tx(&mut tx, &p.tenant_id).await?;
                    self.lifecycle_commit(tx).await?;
                    Ok(job)
                }

                async fn transfer_ownership(&self, p: &Principal, command: &TransferOwnership) -> CoreResult<()> {
                    require_first_party(p)?;
                    if command.successor_user_id == p.user_id {
                        return Err(CoreError::invalid("ownership successor must be another active member"));
                    }
                    let mut tx = self.lifecycle_tx(std::slice::from_ref(&p.tenant_id)).await?;
                    Self::lifecycle_owner(&mut tx, p).await?;
                    let successor_role: Option<String> = sqlx::query_scalar("SELECT m.role FROM tenant_memberships m JOIN account_auth_epochs a ON a.user_id=m.user_id WHERE m.tenant_id=$1 AND m.user_id=$2")
                                        .bind(&p.tenant_id).bind(&command.successor_user_id).fetch_optional(&mut *tx).await.map_err(db_err)?;
                    let Some(successor_role) = successor_role else {
                        return Err(CoreError::Conflict(
                            "ownership successor is no longer an active member".into(),
                        ));
                    };
                    if successor_role == Role::Owner.as_str() {
                        return Err(CoreError::Conflict("ownership successor is already an owner".into()));
                    }
                    // 先提升接任者再降级原 owner，两个成员世代同时更新，旧权限不跨角色变化复活。
                    Self::lifecycle_change_role(&mut tx, &p.tenant_id, &command.successor_user_id, Role::Owner).await?;
                    Self::lifecycle_change_role(&mut tx, &p.tenant_id, &p.user_id, Role::Admin).await?;
                    self.lifecycle_commit(tx).await
                }

                async fn close_account(&self, p: &AccountPrincipal, command: &CloseAccount) -> CoreResult<Vec<ErasureJob>> {
                    self.close_account_authorized(&AccountAuthority::Account(p.clone()), command).await
                }

                async fn close_account_authorized(&self, p: &AccountAuthority, command: &CloseAccount) -> CoreResult<Vec<ErasureJob>> {
                    let user_id = p.user_id();
                    let generation = p.generation()?;
                    let mut tx = self.lifecycle_tx(&[]).await?;
                    let rows = sqlx::query("SELECT tenant_id,role FROM tenant_memberships WHERE user_id=$1 ORDER BY tenant_id")
                        .bind(user_id)
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    let tenants: Vec<String> = rows.iter().map(|r| r.get("tenant_id")).collect();
                    Self::lifecycle_lock_tenants(&mut tx, &tenants).await?;
                    Self::lifecycle_account_authorize(&mut tx, p).await?;
                    let mut exclusive = std::collections::BTreeSet::new();
                    // 在任何删除或任务插入前检查完整集合，禁止先删除可行工作区再拒绝后续工作区。
                    for row in &rows {
                        let tenant: String = row.get("tenant_id");
                        if row.get::<String, _>("role") == "owner" && Self::lifecycle_owner_count(&mut tx, &tenant).await? == 1
                        {
                            let members: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id=$1")
                                .bind(&tenant)
                                .fetch_one(&mut *tx)
                                .await
                                .map_err(db_err)?;
                            if members != 1 {
                                return Err(CoreError::Conflict(
                                    "sole owner of shared workspace must transfer ownership or delete workspace".into(),
                                ));
                            }
                            exclusive.insert(tenant);
                        }
                    }
                    let confirmed: std::collections::BTreeSet<_> =
                        command.confirmed_exclusive_workspaces.iter().cloned().collect();
                    if confirmed.len() != command.confirmed_exclusive_workspaces.len() || confirmed != exclusive {
                        return Err(CoreError::invalid(
                            "account closure requires exact exclusive workspace confirmations",
                        ));
                    }
                    let mut jobs = Vec::new();
                    for tenant in &tenants {
                        if exclusive.contains(tenant) {
                            jobs.push(Self::lifecycle_delete_tx(&mut tx, tenant).await?);
                        } else {
                            Self::lifecycle_leave_tx(&mut tx, tenant, user_id).await?;
                        }
                    }
                    // 复用 S4 的规范身份屏障与全局 user_id 凭据收集，仍在同一事务中。
                    jobs.push(Self::close_account_tx(&mut tx, user_id, generation).await?);
                    self.lifecycle_commit(tx).await?;
                    Ok(jobs)
                }
            }
        };
    };
}
pub(crate) use lifecycle_impl;
