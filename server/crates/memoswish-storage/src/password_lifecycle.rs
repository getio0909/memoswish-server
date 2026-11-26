//! 复用注册锁和锁后数据库时钟；证明消费、口令与撤销在同一事务提交。
macro_rules! password_lifecycle_impl {
    ($repo:ty, $db:ty) => {
        impl $repo {
            async fn password_snapshot_tx(tx: &mut sqlx::Transaction<'_, $db>, email: &str) -> CoreResult<Option<memoswish_core::password_lifecycle::PasswordSnapshot>> {
                let row = sqlx::query("SELECT u.id,u.email,u.password_hash,a.generation,COALESCE(p.version,0) AS version,p.verified_email FROM users u JOIN account_auth_epochs a ON a.user_id=u.id LEFT JOIN password_credentials p ON p.user_id=u.id WHERE lower(u.email)=lower($1)")
                    .bind(email).fetch_optional(&mut **tx).await.map_err(db_err)?;
                Ok(row.map(|r| {
                    let email: String = r.get("email");
                    let verified: Option<String> = r.get("verified_email");
                    memoswish_core::password_lifecycle::PasswordSnapshot {
                        user_id: r.get("id"), verified: verified.as_deref()==Some(email.as_str()), email,
                        password_hash:r.get("password_hash"), generation:r.get("generation"), version:r.get("version"),
                    }
                }))
            }
            async fn password_check_tx(tx: &mut sqlx::Transaction<'_, $db>, proof: &memoswish_core::password_lifecycle::PasswordSnapshot) -> CoreResult<memoswish_core::password_lifecycle::PasswordSnapshot> {
                let current = Self::password_snapshot_tx(tx, &proof.email).await?
                    .ok_or_else(|| CoreError::Unauthorized("invalid password proof".into()))?;
                if current.user_id!=proof.user_id || current.password_hash!=proof.password_hash || current.generation!=proof.generation || current.version!=proof.version || current.password_hash.is_empty() {
                    return Err(CoreError::Unauthorized("invalid password proof".into()));
                }
                Ok(current)
            }
        }
        #[async_trait::async_trait]
        impl memoswish_core::password_lifecycle::PasswordLifecycleRepo for $repo {
            async fn password_snapshot(&self, email: &str) -> CoreResult<Option<memoswish_core::password_lifecycle::PasswordSnapshot>> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let result=Self::password_snapshot_tx(&mut tx,email).await?;
                tx.commit().await.map_err(db_err)?;
                Ok(result)
            }
            async fn password_proof(&self, proof: &memoswish_core::password_lifecycle::PasswordSnapshot) -> CoreResult<()> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                Self::session_lock(&mut tx).await?;
                Self::password_check_tx(&mut tx,proof).await?;
                tx.commit().await.map_err(db_err)
            }
            async fn password_challenge(&self, proof: &memoswish_core::password_lifecycle::PasswordSnapshot, purpose: memoswish_core::password_lifecycle::ChallengePurpose, digest: &str, ttl: i64) -> CoreResult<()> {
                if !(1..=3600).contains(&ttl) || digest.len()!=64 || !digest.bytes().all(|b|b.is_ascii_hexdigit()) {
                    return Err(CoreError::invalid("invalid password challenge"));
                }
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let now=Self::session_lock(&mut tx).await?;
                Self::password_check_tx(&mut tx,proof).await?;
                let current=Self::password_snapshot_tx(&mut tx,&proof.email).await?.expect("checked account");
                if purpose==memoswish_core::password_lifecycle::ChallengePurpose::Reset && !current.verified {
                    return Err(CoreError::Unauthorized("invalid password proof".into()));
                }
                sqlx::query("INSERT INTO password_challenges(user_id,purpose,digest,destination,credential_version,generation,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_id,purpose) DO UPDATE SET digest=excluded.digest,destination=excluded.destination,credential_version=excluded.credential_version,generation=excluded.generation,expires_at=excluded.expires_at")
                    .bind(&proof.user_id).bind(purpose.as_str()).bind(digest).bind(&proof.email).bind(proof.version).bind(proof.generation).bind(now+ttl)
                    .execute(&mut *tx).await.map_err(db_err)?;
                tx.commit().await.map_err(db_err)
            }
            async fn password_reset_challenge(&self, email: &str, digest: &str, ttl: i64) -> CoreResult<Option<String>> {
                if !(1..=3600).contains(&ttl) || digest.len()!=64 || !digest.bytes().all(|b|b.is_ascii_hexdigit()) {
                    return Err(CoreError::invalid("invalid password challenge"));
                }
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let now=Self::session_lock(&mut tx).await?;
                let proof=Self::password_snapshot_tx(&mut tx,email).await?;
                // 未知、未验证、无口令和有效账户均执行同一条件写入，不暴露锁等待差异。
                let changed=sqlx::query("INSERT INTO password_challenges(user_id,purpose,digest,destination,credential_version,generation,expires_at) SELECT u.id,'reset',$2,u.email,p.version,a.generation,$3 FROM users u JOIN password_credentials p ON p.user_id=u.id JOIN account_auth_epochs a ON a.user_id=u.id WHERE lower(u.email)=lower($1) AND u.password_hash<>'' AND p.verified_email=u.email ON CONFLICT(user_id,purpose) DO UPDATE SET digest=excluded.digest,destination=excluded.destination,credential_version=excluded.credential_version,generation=excluded.generation,expires_at=excluded.expires_at")
                    .bind(email).bind(digest).bind(now+ttl).execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                tx.commit().await.map_err(db_err)?;
                Ok(proof.filter(|_|changed==1).map(|p|p.email))
            }
            async fn password_mutate(&self, mutation: memoswish_core::password_lifecycle::PasswordMutation<'_>) -> CoreResult<()> {
                use memoswish_core::password_lifecycle::{PasswordMutation,ChallengePurpose};
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let now=Self::session_lock(&mut tx).await?;
                let (proof,new_hash,operator)=match mutation {
                    PasswordMutation::Verify{email,digest} | PasswordMutation::Reset{email,digest,..} => {
                        let purpose=if matches!(mutation,PasswordMutation::Verify{..}) {ChallengePurpose::Verify} else {ChallengePurpose::Reset};
                        let proof=Self::password_snapshot_tx(&mut tx,email).await?.ok_or_else(||CoreError::Unauthorized("invalid or expired password challenge".into()))?;
                        if proof.password_hash.is_empty() || (purpose==ChallengePurpose::Reset && !proof.verified) {
                            return Err(CoreError::Unauthorized("invalid or expired password challenge".into()));
                        }
                        let n=sqlx::query("DELETE FROM password_challenges WHERE user_id=$1 AND purpose=$2 AND digest=$3 AND destination=$4 AND credential_version=$5 AND generation=$6 AND expires_at>$7")
                            .bind(&proof.user_id).bind(purpose.as_str()).bind(digest).bind(&proof.email).bind(proof.version).bind(proof.generation).bind(now)
                            .execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                        if n!=1 {return Err(CoreError::Unauthorized("invalid or expired password challenge".into()));}
                        if purpose==ChallengePurpose::Verify {
                            sqlx::query("INSERT INTO password_credentials(user_id,version,verified_email) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET verified_email=excluded.verified_email")
                                .bind(&proof.user_id).bind(proof.version).bind(&proof.email).execute(&mut *tx).await.map_err(db_err)?;
                            return tx.commit().await.map_err(db_err);
                        }
                        let PasswordMutation::Reset{new_hash,..}=mutation else {unreachable!()};
                        (proof,new_hash,false)
                    }
                    PasswordMutation::Change{proof,access_hash,new_hash} => {
                        // 哈希期间可能已完成邮箱验证；保留锁内当前状态，仍核验原始身份、口令和世代。
                        let current=Self::password_check_tx(&mut tx,proof).await?;
                        let a=Self::session_access_tx(&mut tx,access_hash).await?;
                        if a.family.user_id!=proof.user_id || a.family.generation!=proof.generation || a.credential.tenant_id.is_some() {
                            return Err(CoreError::Unauthorized("account session required".into()));
                        }
                        (current,new_hash,false)
                    }
                    PasswordMutation::Operator{proof,new_hash} => {
                        // 维护入口允许无口令账户修复，但仍保留原快照条件与世代。
                        let current=Self::password_snapshot_tx(&mut tx,&proof.email).await?.ok_or_else(||CoreError::Unauthorized("account no longer exists".into()))?;
                        if current.user_id!=proof.user_id || current.version!=proof.version || current.generation!=proof.generation || current.password_hash!=proof.password_hash {
                            return Err(CoreError::Conflict("account changed during local recovery".into()));
                        }
                        (proof.clone(),new_hash,true)
                    }
                };
                if new_hash.is_empty() {return Err(CoreError::invalid("password hash is required"));}
                let version=proof.version.checked_add(1).ok_or_else(||CoreError::Conflict("credential version exhausted".into()))?;
                let generation=proof.generation.checked_add(1).ok_or_else(||CoreError::Conflict("account generation exhausted".into()))?;
                sqlx::query("UPDATE users SET password_hash=$1 WHERE id=$2").bind(new_hash).bind(&proof.user_id).execute(&mut *tx).await.map_err(db_err)?;
                let verified=if operator || !proof.verified {None} else {Some(proof.email.clone())};
                sqlx::query("INSERT INTO password_credentials(user_id,version,verified_email) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,verified_email=excluded.verified_email")
                    .bind(&proof.user_id).bind(version).bind(verified).execute(&mut *tx).await.map_err(db_err)?;
                sqlx::query("UPDATE account_auth_epochs SET generation=$1 WHERE user_id=$2").bind(generation).bind(&proof.user_id).execute(&mut *tx).await.map_err(db_err)?;
                sqlx::query("DELETE FROM password_challenges WHERE user_id=$1").bind(&proof.user_id).execute(&mut *tx).await.map_err(db_err)?;
                // 世代屏障涵盖 App、API 和 OAuth；显式标记族不改变其他注销入口的窄域。
                sqlx::query("UPDATE app_sessions SET revoked=1 WHERE user_id=$1").bind(&proof.user_id).execute(&mut *tx).await.map_err(db_err)?;
                sqlx::query("UPDATE api_tokens SET revoked=TRUE WHERE user_id=$1").bind(&proof.user_id).execute(&mut *tx).await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_grants SET revoked=1 WHERE user_id=$1").bind(&proof.user_id).execute(&mut *tx).await.map_err(db_err)?;
                sqlx::query("DELETE FROM recent_authentication WHERE user_id=$1").bind(&proof.user_id).execute(&mut *tx).await.map_err(db_err)?;
                tx.commit().await.map_err(db_err)
            }
            async fn password_cleanup(&self) -> CoreResult<()> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let now=Self::session_lock(&mut tx).await?;
                sqlx::query("DELETE FROM password_challenges WHERE expires_at<=$1").bind(now).execute(&mut *tx).await.map_err(db_err)?;
                tx.commit().await.map_err(db_err)
            }
        }
    }
}
pub(crate) use password_lifecycle_impl;
