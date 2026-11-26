//! 兼容写入在同一事务创建全局账户、成员历史与初始成员关系。
macro_rules! membership_impl {
    ($repo:ty, $db:ty, $timestamp:expr) => {

        #[async_trait::async_trait]
        impl MembershipRepo for $repo {
            async fn issue_api_token(&self, t: &ApiTokenRecord) -> CoreResult<()> {
                self.insert_api_token_bound(t, true).await
            }
            async fn account_by_email(&self, email: &str) -> CoreResult<Option<AccountRecord>> {
                let row = sqlx::query("SELECT id,email,display_name,password_hash FROM users WHERE lower(email)=lower($1)")
                    .bind(email)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db_err)?;
                Ok(row.map(|r| AccountRecord {
                    id: r.get("id"),
                    email: r.get("email"),
                    display_name: r.get("display_name"),
                    password_hash: r.get("password_hash"),
                }))
            }
            async fn account_by_id(&self, user_id: &str) -> CoreResult<Option<AccountRecord>> {
                let row = sqlx::query("SELECT id,email,display_name,password_hash FROM users WHERE id=$1")
                    .bind(user_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db_err)?;
                Ok(row.map(|r| AccountRecord {
                    id: r.get("id"),
                    email: r.get("email"),
                    display_name: r.get("display_name"),
                    password_hash: r.get("password_hash"),
                }))
            }
            async fn account_generation(&self, user_id: &str) -> CoreResult<i64> {
                sqlx::query_scalar("SELECT generation FROM account_auth_epochs WHERE user_id=$1")
                    .bind(user_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db_err)?
                    .ok_or_else(|| CoreError::Unauthorized("account no longer exists".into()))
            }
            async fn memberships(&self, user_id: &str) -> CoreResult<Vec<MembershipRecord>> {
                sqlx::query("SELECT tenant_id,role,generation FROM tenant_memberships WHERE user_id=$1 ORDER BY tenant_id")
                    .bind(user_id)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(db_err)?
                    .into_iter()
                    .map(|r| {
                        Ok(MembershipRecord {
                            tenant_id: r.get("tenant_id"),
                            role: Role::parse(r.get::<String, _>("role").as_str())?,
                            generation: r.get("generation"),
                        })
                    })
                    .collect()
            }
            async fn membership_authorize(
                &self,
                tenant_id: &str,
                user_id: &str,
                generations: memoswish_core::CredentialGenerations,
            ) -> CoreResult<Role> {
                let row = sqlx::query("SELECT m.role FROM tenant_memberships m JOIN account_auth_epochs a ON a.user_id=m.user_id WHERE m.tenant_id=$1 AND m.user_id=$2 AND a.generation=$3 AND m.generation=$4")
                                                                    .bind(tenant_id).bind(user_id).bind(generations.account).bind(generations.membership)
                                                                    .fetch_optional(&self.pool).await.map_err(db_err)?
                                                                    .ok_or_else(|| CoreError::Unauthorized("credential authorization was revoked".into()))?;
                Role::parse(row.get::<String, _>("role").as_str())
            }
            async fn membership_remove(&self, tenant_id: &str, user_id: &str) -> CoreResult<bool> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let changed = sqlx::query("DELETE FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2")
                    .bind(tenant_id)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .rows_affected()
                    == 1;
                // 历史世代永远保留，普通移除不创建账户擦除墓碑。
                tx.commit().await.map_err(db_err)?;
                Ok(changed)
            }
            async fn membership_join(&self, tenant_id: &str, user_id: &str, role: Role) -> CoreResult<i64> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let current: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2")
                        .bind(tenant_id)
                        .bind(user_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_err)?;
                if current != 0 {
                    return Err(CoreError::Conflict("membership already exists".into()));
                }
                let previous: Option<i64> =
                    sqlx::query_scalar("SELECT MAX(generation) FROM membership_generations WHERE tenant_id=$1 AND user_id=$2")
                        .bind(tenant_id)
                        .bind(user_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_err)?;
                let generation = previous
                    .unwrap_or(-1)
                    .checked_add(1)
                    .ok_or_else(|| CoreError::Conflict("membership generation exhausted".into()))?;
                sqlx::query("INSERT INTO membership_generations(tenant_id,user_id,generation) VALUES($1,$2,$3)")
                    .bind(tenant_id)
                    .bind(user_id)
                    .bind(generation)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let n = sqlx::query("INSERT INTO tenant_memberships(tenant_id,user_id,role,joined_at,generation) SELECT $1,$2,$3,$4,$5 FROM users WHERE id=$2")
                                                                    .bind(tenant_id).bind(user_id).bind(role.as_str()).bind(($timestamp)(&chrono::Utc::now())).bind(generation).execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                if n != 1 {
                    return Err(CoreError::Unauthorized("account no longer exists".into()));
                }
                tx.commit().await.map_err(db_err)?;
                Ok(generation)
            }
            async fn account_export_empty(
                &self,
                user_id: &str,
                generation: i64,
            ) -> CoreResult<memoswish_protocol::AccountExport> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let account = Self::empty_account_tx(&mut tx, user_id, generation).await?;
                let rows: Vec<String> =
                    sqlx::query_scalar("SELECT body FROM federated_identities WHERE user_id=$1 ORDER BY issuer,subject")
                        .bind(user_id)
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db_err)?;
                let identities = rows
                    .into_iter()
                    .map(|body| {
                        let i: memoswish_core::identity::FederatedIdentity =
                            serde_json::from_str(&body).map_err(CoreError::internal)?;
                        Ok(memoswish_protocol::LinkedIdentity {
                            provider: i.provider,
                            issuer: i.issuer,
                            subject: i.subject,
                            email: i.email,
                        })
                    })
                    .collect::<CoreResult<Vec<_>>>()?;
                tx.commit().await.map_err(db_err)?;
                Ok(memoswish_protocol::AccountExport { account, identities })
            }
            async fn account_close_empty(
                &self,
                user_id: &str,
                generation: i64,
            ) -> CoreResult<memoswish_core::identity::ErasureJob> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let job = Self::close_account_tx(&mut tx, user_id, generation).await?;
                tx.commit().await.map_err(db_err)?;
                Ok(job)
            }
        }
        impl $repo {
            pub(crate) async fn close_account_tx(tx: &mut sqlx::Transaction<'_, $db>, user_id: &str, generation: i64) -> CoreResult<memoswish_core::identity::ErasureJob> {
                Self::empty_account_tx(tx, user_id, generation).await?;
                // 无成员账户也可能保留旧合成请求；销户时一并撤销，保留共享任务与计量证据。
                sqlx::query("UPDATE tts_requesters SET outcome='requester_revoked' WHERE user_id=$1")
                    .bind(user_id).execute(&mut **tx).await.map_err(db_err)?;
                let sequence: i64 = sqlx::query_scalar("UPDATE oidc_sequence SET value=value+1 WHERE id=1 RETURNING value")
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(db_err)?;
                let identities = sqlx::query("SELECT issuer,subject FROM federated_identities WHERE user_id=$1")
                    .bind(user_id)
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(db_err)?;
                for identity in identities {
                    let hash = memoswish_core::ids::sha256_hex(
                        format!(
                            "{}\0{}",
                            identity.get::<String, _>("issuer"),
                            identity.get::<String, _>("subject")
                        )
                        .as_bytes(),
                    );
                    sqlx::query("INSERT INTO identity_unlink_fences(identity_hash,sequence) VALUES($1,$2) ON CONFLICT(identity_hash) DO UPDATE SET sequence=excluded.sequence").bind(hash).bind(sequence).execute(&mut **tx).await.map_err(db_err)?;
                }
                let rows =
                    sqlx::query("SELECT body,credential FROM federated_identities WHERE user_id=$1 AND credential IS NOT NULL")
                        .bind(user_id)
                        .fetch_all(&mut **tx)
                        .await
                        .map_err(db_err)?;
                let mut credentials = Vec::new();
                for row in rows {
                    let i: memoswish_core::identity::FederatedIdentity =
                        serde_json::from_str(&row.get::<String, _>("body")).map_err(CoreError::internal)?;
                    credentials.push((i.provider, row.get::<String, _>("credential")));
                }
                let job = memoswish_core::identity::ErasureJob {
                    id: memoswish_core::ids::new_id(),
                    tenant_id: None,
                    purge_assets: false,
                    credentials,
                };
                // 独立于租户及账户的持久任务在删除后继续负责上游撤销。
                sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
                    .bind(&job.id)
                    .bind(crate::oauth::encode(&job)?)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_err)?;
                // 收尾旧成员移除留下的学习与提交数据；保留已撤销 requester 及外部责任证据。
                for table in ["tts_submission_items", "tts_submissions", "api_tokens", "memory_states", "feedback_events", "feed_sessions"] {
                    sqlx::query(&format!("DELETE FROM {table} WHERE user_id=$1"))
                        .bind(user_id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_err)?;
                }
                sqlx::query("DELETE FROM users WHERE id=$1")
                    .bind(user_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_err)?;
                Ok(job)
            }

            async fn empty_account_tx(
                tx: &mut sqlx::Transaction<'_, $db>,
                user_id: &str,
                generation: i64,
            ) -> CoreResult<memoswish_protocol::AccountProfile> {
                let row=sqlx::query("SELECT u.email,u.display_name FROM users u JOIN account_auth_epochs a ON a.user_id=u.id WHERE u.id=$1 AND a.generation=$2")
                                                                    .bind(user_id).bind(generation).fetch_optional(&mut **tx).await.map_err(db_err)?
                                                                    .ok_or_else(|| CoreError::Unauthorized("account session was revoked".into()))?;
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_memberships WHERE user_id=$1")
                    .bind(user_id)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(db_err)?;
                if count != 0 {
                    return Err(CoreError::Conflict("account still has memberships".into()));
                }
                Ok(memoswish_protocol::AccountProfile {
                    user_id: user_id.into(),
                    email: row.get("email"),
                    display_name: row.get("display_name"),
                })
            }
            pub(crate) async fn authorize_tx(
                tx: &mut sqlx::Transaction<'_, $db>,
                tenant_id: &str,
                user_id: &str,
                g: memoswish_core::CredentialGenerations,
            ) -> CoreResult<Role> {
                // 调用者先持有注册锁；成员行锁使角色变更与敏感签发串行。
                let row=sqlx::query("UPDATE tenant_memberships SET revision=revision WHERE tenant_id=$1 AND user_id=$2 AND generation=$3 AND EXISTS(SELECT 1 FROM account_auth_epochs WHERE user_id=$2 AND generation=$4) RETURNING role")
                                                                    .bind(tenant_id).bind(user_id).bind(g.membership).bind(g.account)
                                                                    .fetch_optional(&mut **tx).await.map_err(db_err)?
                                                                    .ok_or_else(|| CoreError::Unauthorized("credential authorization was revoked".into()))?;
                Role::parse(row.get::<String, _>("role").as_str())
            }

            pub(crate) async fn insert_identity(tx: &mut sqlx::Transaction<'_, $db>, u: &UserRecord) -> CoreResult<()> {
                sqlx::query("INSERT INTO users(id,default_tenant_id,email,display_name,password_hash,created_at) VALUES($1,$2,$3,$4,$5,$6)")
                                                                    .bind(&u.id)
                                                                    .bind(&u.tenant_id)
                                                                    .bind(u.email.to_lowercase())
                                                                    .bind(&u.display_name)
                                                                    .bind(&u.password_hash)
                                                                    .bind(($timestamp)(&u.created_at))
                                                                    .execute(&mut **tx)
                                                                    .await
                                                                    .map_err(|e| match &e {
                                                                        sqlx::Error::Database(d) if d.is_unique_violation() => {
                                                                            CoreError::Conflict("email already registered".into())
                                                                        }
                                                                        _ => db_err(e),
                                                                    })?;
                sqlx::query("INSERT INTO account_auth_epochs(user_id,generation) VALUES($1,0)")
                    .bind(&u.id)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_err)?;
                sqlx::query("INSERT INTO membership_generations(tenant_id,user_id,generation) VALUES($1,$2,0)")
                    .bind(&u.tenant_id)
                    .bind(&u.id)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_err)?;
                sqlx::query(
                    "INSERT INTO tenant_memberships(tenant_id,user_id,role,joined_at,generation) VALUES($1,$2,$3,$4,0)",
                )
                .bind(&u.tenant_id)
                .bind(&u.id)
                .bind(u.role.as_str())
                .bind(($timestamp)(&u.created_at))
                .execute(&mut **tx)
                .await
                .map_err(db_err)?;
                Ok(())
            }
        }
    };
}
pub(crate) use membership_impl;
