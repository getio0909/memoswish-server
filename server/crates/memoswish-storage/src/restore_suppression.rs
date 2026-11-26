//! 隔离恢复的有序抑制输入；调用者负责独立日志的完整性与快照覆盖证明。

use memoswish_core::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionBatch {
    pub version: u32,
    pub snapshot_sha256: String,
    pub after_sequence: u64,
    pub through_sequence: u64,
    pub entries: Vec<SuppressionEntry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionEntry {
    pub sequence: u64,
    pub action: Suppression,
}

/// 销户时的规范身份来自独立日志，不能只依赖旧快照里的关联列表。
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressedIdentity {
    pub issuer: String,
    pub subject: String,
}

/// 不接收原始凭据、提示或 SQL；未知类别由反序列化拒绝。
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Suppression {
    DeleteWorkspace { tenant_id: String },
    LeaveWorkspace { tenant_id: String, user_id: String },
    CloseAccount { user_id: String, identities: Vec<SuppressedIdentity> },
    DeleteCard { tenant_id: String, card_id: String },
    RevokeSessions { user_id: String, through_auth_time: i64 },
    PasswordSecurity { user_id: String, minimum_generation: i64 },
    RevokeApiToken { tenant_id: String, user_id: String, token_id: String },
    RevokeOauthGrant { tenant_id: String, user_id: String, grant_id: String },
    UnlinkIdentity { user_id: String, issuer: String, subject: String },
    WithdrawPurpose { tenant_id: String, user_id: String, purpose: String, version: String, recorded_at: i64 },
}

impl SuppressionBatch {
    /// 调用者从恢复记录提供边界，不接受文件自行声明覆盖完整。
    pub fn validate(&self, snapshot: &str, after: u64, through: u64) -> CoreResult<()> {
        if self.version != 1
            || snapshot.len() != 64
            || !snapshot.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self.snapshot_sha256 != snapshot
            || self.after_sequence != after
            || self.through_sequence != through
            || self.entries.len() > 100
            || through.checked_sub(after) != Some(self.entries.len() as u64)
            || self.entries.iter().enumerate().any(|(i, e)| after.checked_add(i as u64 + 1) != Some(e.sequence))
        {
            return Err(CoreError::invalid("suppression snapshot binding or sequence coverage is invalid"));
        }
        for entry in &self.entries {
            let ids = match &entry.action {
                Suppression::DeleteWorkspace { tenant_id } => vec![tenant_id],
                Suppression::LeaveWorkspace { tenant_id, user_id } => vec![tenant_id, user_id],
                Suppression::CloseAccount { user_id, identities } => {
                    if identities.len() > 100 || identities.iter().any(|i| !valid_identity(&i.issuer, &i.subject)) {
                        return Err(CoreError::invalid("invalid suppression account identities"));
                    }
                    vec![user_id]
                }
                Suppression::DeleteCard { tenant_id, card_id } => vec![tenant_id, card_id],
                Suppression::PasswordSecurity { user_id, minimum_generation } => {
                    if !(1..i64::MAX).contains(minimum_generation) {
                        return Err(CoreError::invalid("invalid password restore generation"));
                    }
                    vec![user_id]
                }
                Suppression::RevokeSessions { user_id, through_auth_time } => {
                    if !(0..=253_402_300_799).contains(through_auth_time) {
                        return Err(CoreError::invalid("invalid suppression session cutoff"));
                    }
                    vec![user_id]
                }
                Suppression::RevokeApiToken { tenant_id, user_id, token_id } => vec![tenant_id, user_id, token_id],
                Suppression::RevokeOauthGrant { tenant_id, user_id, grant_id } => vec![tenant_id, user_id, grant_id],
                Suppression::WithdrawPurpose { tenant_id, user_id, purpose, version, recorded_at } => {
                    if !memoswish_core::privacy::PURPOSES.contains(&purpose.as_str())
                        || version.is_empty()
                        || version.len() > 128
                        || !(0..=253_402_300_799).contains(recorded_at)
                    {
                        return Err(CoreError::invalid("invalid suppression privacy withdrawal"));
                    }
                    vec![tenant_id, user_id]
                }
                Suppression::UnlinkIdentity { user_id, issuer, subject } => {
                    if !valid_identity(issuer, subject) {
                        return Err(CoreError::invalid("invalid suppression identity"));
                    }
                    vec![user_id]
                }
            };
            for id in ids {
                memoswish_core::assets::validate_asset_id(id)?;
            }
        }
        Ok(())
    }
}

fn valid_identity(issuer: &str, subject: &str) -> bool {
    !issuer.is_empty()
        && issuer.len() <= 2048
        && !issuer.contains('\0')
        && !subject.is_empty()
        && subject.len() <= 1024
        && !subject.contains('\0')
}

/// 只有停止 writer 的隔离安装可调用；本入口不启动 provider 或对象清理。
pub async fn replay(url: &str, batch: &SuppressionBatch, snapshot: &str, after: u64, through: u64) -> CoreResult<()> {
    batch.validate(snapshot, after, through)?;
    match crate::DatabaseKind::from_url(url)? {
        #[cfg(feature = "sqlite")]
        crate::DatabaseKind::Sqlite => {
            crate::sqlite::SqliteRepository::open_runtime(url).await?.replay_suppressions(batch).await
        }
        #[cfg(feature = "postgres")]
        crate::DatabaseKind::Postgres => {
            crate::postgres::PostgresRepository::open_runtime(url, 1).await?.replay_suppressions(batch).await
        }
        #[allow(unreachable_patterns)]
        _ => Err(CoreError::Unsupported("suppression backend is not compiled in".into())),
    }
}

macro_rules! restore_suppression_impl {
    ($repo:ty, $db:ty) => {
        impl $repo {
            async fn suppression_leave(
                tx: &mut sqlx::Transaction<'_, $db>, tenant: &str, user: &str,
            ) -> memoswish_core::CoreResult<()> {
                use crate::assets::db_error;
                let sole_owner: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships m WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.role='owner' AND NOT EXISTS(SELECT 1 FROM tenant_memberships o WHERE o.tenant_id=m.tenant_id AND o.role='owner' AND o.user_id<>m.user_id)")
                    .bind(tenant).bind(user).fetch_one(&mut **tx).await.map_err(db_error)?;
                if sole_owner != 0 {
                    return Err(memoswish_core::CoreError::Conflict("restore requires prior workspace deletion or ownership reconciliation".into()));
                }
                Self::lifecycle_leave_tx(tx, tenant, user).await
            }

            async fn suppression_unlink(
                tx: &mut sqlx::Transaction<'_, $db>, user: &str, issuer: &str, subject: &str,
            ) -> memoswish_core::CoreResult<()> {
                use crate::assets::db_error;
                use sqlx::Row;
                let row = sqlx::query("SELECT user_id,tenant_id,body,credential FROM federated_identities WHERE issuer=$1 AND subject=$2")
                    .bind(issuer).bind(subject).fetch_optional(&mut **tx).await.map_err(db_error)?;
                if row.as_ref().is_some_and(|r| r.get::<String,_>("user_id") != user) {
                    return Err(memoswish_core::CoreError::Conflict("restored identity belongs to another account".into()));
                }
                let sequence: i64 = sqlx::query_scalar("UPDATE oidc_sequence SET value=value+1 WHERE id=1 RETURNING value")
                    .fetch_one(&mut **tx).await.map_err(db_error)?;
                let hash = memoswish_core::ids::sha256_hex(format!("{issuer}\0{subject}").as_bytes());
                sqlx::query("INSERT INTO identity_unlink_fences(identity_hash,sequence) VALUES($1,$2) ON CONFLICT(identity_hash) DO UPDATE SET sequence=excluded.sequence")
                    .bind(hash).bind(sequence).execute(&mut **tx).await.map_err(db_error)?;
                sqlx::query("DELETE FROM oidc_handoffs WHERE attempt_id IN (SELECT id FROM oidc_attempts WHERE identity_issuer=$1 AND identity_subject=$2)")
                    .bind(issuer).bind(subject).execute(&mut **tx).await.map_err(db_error)?;
                sqlx::query("DELETE FROM oidc_attempts WHERE identity_issuer=$1 AND identity_subject=$2")
                    .bind(issuer).bind(subject).execute(&mut **tx).await.map_err(db_error)?;
                if let Some(row) = row {
                    if let Some(credential) = row.get::<Option<String>,_>("credential") {
                        let identity: memoswish_core::identity::FederatedIdentity = serde_json::from_str(&row.get::<String,_>("body"))
                            .map_err(|_| memoswish_core::CoreError::internal("invalid restored identity"))?;
                        let job = memoswish_core::identity::ErasureJob {
                            id: memoswish_core::ids::new_id(), tenant_id: Some(row.get("tenant_id")), purge_assets: false,
                            credentials: vec![(identity.provider, credential)],
                        };
                        sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
                            .bind(&job.id).bind(crate::oauth::encode(&job)?).execute(&mut **tx).await.map_err(db_error)?;
                    }
                    sqlx::query("DELETE FROM federated_identities WHERE issuer=$1 AND subject=$2 AND user_id=$3")
                        .bind(issuer).bind(subject).bind(user).execute(&mut **tx).await.map_err(db_error)?;
                }
                Ok(())
            }

            pub(crate) async fn replay_suppressions(
                &self,
                batch: &crate::restore_suppression::SuppressionBatch,
            ) -> memoswish_core::CoreResult<()> {
                use crate::{assets::db_error, restore_suppression::Suppression};
                batch.validate(&batch.snapshot_sha256, batch.after_sequence, batch.through_sequence)?;
                let mut tx = self.lifecycle_tx(&[]).await?;
                let now = Self::asset_now(&mut tx).await? / 1000;
                // 隔离恢复不运行任何外部调用；整个批次失败时不留下部分抑制。
                for entry in &batch.entries {
                    match &entry.action {
                        Suppression::DeleteWorkspace { tenant_id } => {
                            Self::lifecycle_lock_tenants(&mut tx, std::slice::from_ref(tenant_id)).await?;
                            let erased: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM erased_tenants WHERE tenant_id=$1")
                                .bind(tenant_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                            if erased == 0 {
                                Self::lifecycle_delete_tx(&mut tx, tenant_id).await?;
                            }
                        }
                        Suppression::LeaveWorkspace { tenant_id, user_id } => {
                            Self::lifecycle_lock_tenants(&mut tx, std::slice::from_ref(tenant_id)).await?;
                            Self::suppression_leave(&mut tx, tenant_id, user_id).await?;
                        }
                        Suppression::CloseAccount { user_id, identities } => {
                            // 快照可能早于账户注册；仍须封锁那时已在途的规范身份回调。
                            for identity in identities {
                                Self::suppression_unlink(&mut tx, user_id, &identity.issuer, &identity.subject).await?;
                            }
                            let generation: Option<i64> = sqlx::query_scalar("SELECT a.generation FROM account_auth_epochs a JOIN users u ON u.id=a.user_id WHERE u.id=$1")
                                .bind(user_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                            if let Some(generation) = generation {
                                let tenants: Vec<String> = sqlx::query_scalar("SELECT tenant_id FROM tenant_memberships WHERE user_id=$1 ORDER BY tenant_id")
                                    .bind(user_id).fetch_all(&mut *tx).await.map_err(db_error)?;
                                Self::lifecycle_lock_tenants(&mut tx, &tenants).await?;
                                for tenant in tenants {
                                    Self::suppression_leave(&mut tx, &tenant, user_id).await?;
                                }
                                Self::close_account_tx(&mut tx, user_id, generation).await?;
                            }
                        }
                        Suppression::DeleteCard { tenant_id, card_id } => {
                            Self::lifecycle_lock_tenants(&mut tx, std::slice::from_ref(tenant_id)).await?;
                            Self::explanation_erase_card(&mut tx, tenant_id, card_id).await?;
                            // 原触发器保存最小 ID；旧快照中尚无该卡时也建立同一屏障。
                            sqlx::query("DELETE FROM cards WHERE tenant_id=$1 AND id=$2")
                                .bind(tenant_id).bind(card_id).execute(&mut *tx).await.map_err(db_error)?;
                            sqlx::query("INSERT INTO deleted_card_ids(tenant_id,card_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
                                .bind(tenant_id).bind(card_id).execute(&mut *tx).await.map_err(db_error)?;
                        }
                        Suppression::PasswordSecurity { user_id, minimum_generation } => {
                            sqlx::query("UPDATE account_auth_epochs SET generation=CASE WHEN generation<$2 THEN $2 ELSE generation END WHERE user_id=$1")
                                .bind(user_id).bind(minimum_generation).execute(&mut *tx).await.map_err(db_error)?;
                            sqlx::query("UPDATE users SET password_hash='' WHERE id=$1").bind(user_id).execute(&mut *tx).await.map_err(db_error)?;
                            sqlx::query("UPDATE password_credentials SET verified_email=NULL WHERE user_id=$1").bind(user_id).execute(&mut *tx).await.map_err(db_error)?;
                            for table in ["password_challenges","recent_authentication"] {
                                sqlx::query(&format!("DELETE FROM {table} WHERE user_id=$1")).bind(user_id).execute(&mut *tx).await.map_err(db_error)?;
                            }
                            sqlx::query("UPDATE api_tokens SET revoked=TRUE WHERE user_id=$1").bind(user_id).execute(&mut *tx).await.map_err(db_error)?;
                            for table in ["app_sessions","oauth_grants"] {
                                sqlx::query(&format!("UPDATE {table} SET revoked=1 WHERE user_id=$1")).bind(user_id).execute(&mut *tx).await.map_err(db_error)?;
                            }
                        }
                        Suppression::RevokeSessions { user_id, through_auth_time } => {
                            if *through_auth_time > now {
                                return Err(memoswish_core::CoreError::invalid("suppression session cutoff is in the future"));
                            }
                            sqlx::query("UPDATE app_sessions SET revoked=1 WHERE user_id=$1 AND auth_time<=$2")
                                .bind(user_id).bind(through_auth_time).execute(&mut *tx).await.map_err(db_error)?;
                            // 销户重放或注册前快照没有账户；旧凭据已由账户校验拒绝，无需重建 fence。
                            sqlx::query("INSERT INTO app_session_fences(user_id,revoked_through) SELECT id,$2 FROM users WHERE id=$1 ON CONFLICT(user_id) DO UPDATE SET revoked_through=CASE WHEN excluded.revoked_through>app_session_fences.revoked_through THEN excluded.revoked_through ELSE app_session_fences.revoked_through END")
                                .bind(user_id).bind(through_auth_time).execute(&mut *tx).await.map_err(db_error)?;
                        }
                        Suppression::RevokeApiToken { tenant_id, user_id, token_id } => {
                            let mismatch: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_tokens WHERE id=$3 AND (tenant_id<>$1 OR user_id<>$2)")
                                .bind(tenant_id).bind(user_id).bind(token_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                            if mismatch != 0 { return Err(memoswish_core::CoreError::Conflict("restored token scope mismatch".into())); }
                            sqlx::query("UPDATE api_tokens SET revoked=TRUE WHERE tenant_id=$1 AND user_id=$2 AND id=$3")
                                .bind(tenant_id).bind(user_id).bind(token_id).execute(&mut *tx).await.map_err(db_error)?;
                        }
                        Suppression::RevokeOauthGrant { tenant_id, user_id, grant_id } => {
                            let mismatch: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_grants WHERE id=$3 AND (tenant_id<>$1 OR user_id<>$2)")
                                .bind(tenant_id).bind(user_id).bind(grant_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                            if mismatch != 0 { return Err(memoswish_core::CoreError::Conflict("restored grant scope mismatch".into())); }
                            sqlx::query("UPDATE oauth_grants SET revoked=1 WHERE tenant_id=$1 AND user_id=$2 AND id=$3")
                                .bind(tenant_id).bind(user_id).bind(grant_id).execute(&mut *tx).await.map_err(db_error)?;
                        }
                        Suppression::WithdrawPurpose { tenant_id, user_id, purpose, version, recorded_at } => {
                            if *recorded_at > now {
                                return Err(memoswish_core::CoreError::invalid("suppression withdrawal time is in the future"));
                            }
                            Self::lifecycle_lock_tenants(&mut tx, std::slice::from_ref(tenant_id)).await?;
                            Self::privacy_restore_withdrawal_tx(&mut tx, tenant_id, user_id, purpose, version, *recorded_at).await?;
                        }
                        Suppression::UnlinkIdentity { user_id, issuer, subject } => {
                            Self::suppression_unlink(&mut tx, user_id, issuer, subject).await?;
                        }
                    }
                }
                tx.commit().await.map_err(db_error)
            }
        }
    };
}
pub(crate) use restore_suppression_impl;
