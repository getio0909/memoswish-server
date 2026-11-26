//! 注册锁先于账户、成员及会话行；两库使用同一转换与条件消费。
macro_rules! sessions_impl {
    ($repo:ty, $db:ty, $clock:expr, $timestamp:expr) => {
        impl $repo {
            async fn session_commit(&self, tx: sqlx::Transaction<'_, $db>) -> CoreResult<()> {
                #[cfg(test)]
                if let Some(gate) = &self.lifecycle_gate {
                    gate.pause(crate::learning::TestPoint::BeforeCommit).await;
                }
                tx.commit().await.map_err(db_err)
            }
            pub(crate) async fn session_clock(tx: &mut sqlx::Transaction<'_, $db>) -> CoreResult<i64> {
                sqlx::query_scalar($clock).fetch_one(&mut **tx).await.map_err(db_err)
            }
            pub(crate) async fn session_lock(tx: &mut sqlx::Transaction<'_, $db>) -> CoreResult<i64> {
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut **tx).await.map_err(db_err)?;
                Self::session_clock(tx).await
            }
            pub(crate) async fn session_validate(tx: &mut sqlx::Transaction<'_, $db>, a: &memoswish_core::session::SessionAccess, now: i64) -> CoreResult<()> {
                let f = &a.family;
                if f.revoked || f.expires_at <= now || a.credential.expires_at <= now {
                    return Err(CoreError::Unauthorized("invalid app session".into()));
                }
                let valid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_auth_epochs WHERE user_id=$1 AND generation=$2")
                    .bind(&f.user_id).bind(f.generation).fetch_one(&mut **tx).await.map_err(db_err)?;
                if valid != 1 { return Err(CoreError::Unauthorized("invalid app session".into())); }
                match (&a.credential.tenant_id, a.credential.membership_generation) {
                    (Some(t), Some(m)) => { Self::authorize_tx(tx,t,&f.user_id,memoswish_core::CredentialGenerations {account:f.generation,membership:m}).await?; }
                    (None, None) => {}
                    _ => return Err(CoreError::Unauthorized("invalid app session".into())),
                }
                Ok(())
            }
            pub(crate) async fn session_read(tx: &mut sqlx::Transaction<'_, $db>, hash: &str, refresh: bool) -> CoreResult<(memoswish_core::session::SessionAccess, bool)> {
                let column = if refresh { "refresh_hash" } else { "access_hash" };
                let r = sqlx::query(&format!("SELECT s.id,s.user_id,s.generation,s.provenance,s.auth_time,s.expires_at AS family_expires,s.revoked,c.access_hash,c.refresh_hash,c.assurance_hash,c.tenant_id,c.membership_generation,c.expires_at,c.consumed FROM app_session_credentials c JOIN app_sessions s ON s.id=c.session_id WHERE c.{column}=$1"))
                    .bind(hash).fetch_optional(&mut **tx).await.map_err(db_err)?
                    .ok_or_else(||CoreError::Unauthorized("invalid app session".into()))?;
                Ok((memoswish_core::session::SessionAccess {
                    family: memoswish_core::session::SessionFamily {
                        id:r.get("id"),user_id:r.get("user_id"),generation:r.get("generation"),provenance:r.get("provenance"),
                        auth_time:r.get("auth_time"),expires_at:r.get("family_expires"),revoked:r.get::<i64,_>("revoked")!=0,
                    },
                    credential: memoswish_core::session::SessionCredential {
                        access_hash:r.get("access_hash"),refresh_hash:r.get("refresh_hash"),assurance_hash:r.get("assurance_hash"),session_id:r.get("id"),
                        tenant_id:r.get("tenant_id"),membership_generation:r.get("membership_generation"),expires_at:r.get("expires_at"),
                    }
                },r.get::<i64,_>("consumed")!=0))
            }
            // 调用者必须先取得注册锁；读取和校验共用当前事务与数据库时钟。
            pub(crate) async fn session_access_tx(
                tx: &mut sqlx::Transaction<'_, $db>,
                hash: &str,
            ) -> CoreResult<memoswish_core::session::SessionAccess> {
                let now = Self::session_clock(tx).await?;
                let (a, consumed) = Self::session_read(tx, hash, false).await?;
                if consumed {
                    return Err(CoreError::Unauthorized("invalid app session".into()));
                }
                Self::session_validate(tx, &a, now).await?;
                Ok(a)
            }
            pub(crate) async fn session_revoke_all_tx(tx: &mut sqlx::Transaction<'_, $db>, hash: &str, now: i64) -> CoreResult<()> {
                let a = Self::session_account_access(tx, hash, now).await?;
                sqlx::query("UPDATE app_sessions SET revoked=1 WHERE user_id=$1")
                    .bind(&a.family.user_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_err)?;
                sqlx::query("INSERT INTO app_session_fences(user_id,revoked_through) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET revoked_through=CASE WHEN excluded.revoked_through>app_session_fences.revoked_through THEN excluded.revoked_through ELSE app_session_fences.revoked_through END")
                            .bind(&a.family.user_id).bind(now).execute(&mut **tx).await.map_err(db_err)?;
                Ok(())
            }
            pub(crate) async fn session_account_access(
                tx: &mut sqlx::Transaction<'_, $db>,
                hash: &str,
                now: i64,
            ) -> CoreResult<memoswish_core::session::SessionAccess> {
                let (a, consumed) = Self::session_read(tx, hash, false).await?;
                if consumed || a.credential.tenant_id.is_some() {
                    return Err(CoreError::Unauthorized("account session required".into()));
                }
                Self::session_validate(tx, &a, now).await?;
                Ok(a)
            }
            // 已持注册锁的生产写入复用原始凭据检查，不将新会话权限补给旧请求。
            pub(crate) async fn session_principal_tx(tx: &mut sqlx::Transaction<'_, $db>, p: &memoswish_core::Principal) -> CoreResult<()> {
                if p.via != "session" { return Ok(()); }
                let hash = p.session_access_hash.as_deref()
                    .ok_or_else(|| CoreError::Unauthorized("session credential identity is missing".into()))?;
                let a = Self::session_access_tx(tx, hash).await?;
                if a.family.user_id != p.user_id
                    || Some(a.family.generation) != p.auth_generation
                    || a.credential.tenant_id.as_deref() != Some(p.tenant_id.as_str())
                    || a.credential.membership_generation != p.membership_generation {
                    return Err(CoreError::Unauthorized("session authority does not match principal".into()));
                }
                Ok(())
            }
            // 注册锁由调用者持有，旧 JWT 的原始证据与注销提交串行复核。
            pub(crate) async fn legacy_session_tx(tx: &mut sqlx::Transaction<'_, $db>, user: &str, generation: Option<i64>, iat: i64) -> CoreResult<()> {
                let valid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_auth_epochs a WHERE a.user_id=$1 AND a.generation=$2 AND NOT EXISTS(SELECT 1 FROM app_session_fences f WHERE f.user_id=a.user_id AND f.revoked_through>=$3)")
                    .bind(user).bind(generation).bind(iat).fetch_one(&mut **tx).await.map_err(db_err)?;
                if valid != 1 { return Err(CoreError::Unauthorized("legacy app session was revoked".into())); }
                Ok(())
            }
            async fn session_insert_family(
                tx: &mut sqlx::Transaction<'_, $db>,
                f: &memoswish_core::session::SessionFamily,
                c: &memoswish_core::session::SessionCredential,
            ) -> CoreResult<()> {
                sqlx::query("INSERT INTO app_sessions(id,user_id,generation,provenance,auth_time,expires_at,revoked) VALUES($1,$2,$3,$4,$5,$6,0)")
                            .bind(&f.id).bind(&f.user_id).bind(f.generation).bind(&f.provenance).bind(f.auth_time).bind(f.expires_at).execute(&mut **tx).await.map_err(db_err)?;
                Self::session_insert_credential(tx, f, c).await
            }
            async fn session_insert_credential(tx: &mut sqlx::Transaction<'_, $db>, f: &memoswish_core::session::SessionFamily, c: &memoswish_core::session::SessionCredential) -> CoreResult<()> {
                if c.session_id != f.id || c.expires_at > f.expires_at {return Err(CoreError::invalid("invalid session credential"));}
                sqlx::query("INSERT INTO app_session_credentials(access_hash,refresh_hash,assurance_hash,session_id,tenant_id,membership_generation,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
                    .bind(&c.access_hash).bind(&c.refresh_hash).bind(&c.assurance_hash).bind(&c.session_id).bind(&c.tenant_id).bind(c.membership_generation).bind(c.expires_at)
                    .execute(&mut **tx).await.map_err(db_err)?;
                if let Some(tenant) = &c.tenant_id {
                    // 刷新/工作区选择只搬运原始交互认证期限。
                    sqlx::query("INSERT INTO recent_authentication(hash,tenant_id,user_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(hash) DO NOTHING")
                        .bind(&c.assurance_hash).bind(tenant).bind(&f.user_id).bind(f.auth_time+300).execute(&mut **tx).await.map_err(db_err)?;
                }
                Ok(())
            }
        }
        #[async_trait::async_trait]
        impl memoswish_core::session::SessionRepo for $repo {
            async fn access_authorize(&self, tenant: &str, p: &memoswish_core::Principal) -> CoreResult<()> {
                if tenant!=p.tenant_id {return Err(CoreError::Forbidden("credential tenant mismatch".into()));}
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                Self::session_lock(&mut tx).await?;
                Self::authorize_tx(&mut tx,tenant,&p.user_id,p.credential_generations()?).await?;
                if !Self::credential_current(&mut tx,p,&[]).await? {
                    return Err(CoreError::Unauthorized("credential was revoked or expired".into()));
                }
                tx.commit().await.map_err(db_err)
            }

            async fn access_page(&self, hash: &str, kind: memoswish_core::session::AccessKind, after: &str, limit: u32) -> CoreResult<memoswish_protocol::AccessPage> {
                self.access_page_impl(hash,kind,after,limit).await
            }
            async fn access_revoke(&self, hash: &str, kind: memoswish_core::session::AccessKind, tenant: Option<&str>, id: &str) -> CoreResult<bool> {
                self.access_revoke_impl(hash,kind,tenant,id).await
            }

            async fn session_register(
                &self,
                tenant: &TenantRecord,
                user: &UserRecord,
                f: &memoswish_core::session::SessionFamily,
                c: &memoswish_core::session::SessionCredential,
            ) -> CoreResult<()> {
                if user.tenant_id != tenant.id
                    || f.user_id != user.id
                    || f.generation != 0
                    || c.tenant_id.is_some()
                    || c.membership_generation.is_some()
                    || user.role != Role::Owner
                {
                    return Err(CoreError::invalid("invalid registration session"));
                }
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let now = Self::session_lock(&mut tx).await?;
                sqlx::query("INSERT INTO tenants(id,name,plan,created_at) VALUES($1,$2,$3,$4)")
                    .bind(&tenant.id)
                    .bind(&tenant.name)
                    .bind(&tenant.plan)
                    .bind(($timestamp)(&tenant.created_at))
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                Self::insert_identity(&mut tx, user).await?;
                let a = memoswish_core::session::SessionAccess {
                    family: f.clone(),
                    credential: c.clone(),
                };
                Self::session_validate(&mut tx, &a, now).await?;
                if f.auth_time > now || f.revoked {
                    return Err(CoreError::invalid("invalid session family"));
                }
                Self::session_insert_family(&mut tx, f, c).await?;
                tx.commit().await.map_err(db_err)
            }
            async fn session_memberships(&self, hash: &str) -> CoreResult<Vec<memoswish_protocol::MembershipSummary>> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let now = Self::session_lock(&mut tx).await?;
                let a = Self::session_account_access(&mut tx, hash, now).await?;
                let rows = sqlx::query("SELECT m.tenant_id,t.name,m.role FROM tenant_memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.user_id=$1 ORDER BY m.tenant_id")
                            .bind(&a.family.user_id).fetch_all(&mut *tx).await.map_err(db_err)?;
                let result = rows
                    .into_iter()
                    .map(|r| memoswish_protocol::MembershipSummary {
                        tenant_id: r.get("tenant_id"),
                        name: r.get("name"),
                        role: r.get("role"),
                    })
                    .collect();
                tx.commit().await.map_err(db_err)?;
                Ok(result)
            }
            async fn session_revoke_all(&self, hash: &str) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let now = Self::session_lock(&mut tx).await?;
                Self::session_revoke_all_tx(&mut tx, hash, now).await?;
                self.session_commit(tx).await
            }
            async fn legacy_session_authorize(
                &self,
                user: &str,
                generation: i64,
                iat: i64,
                successor_iat: Option<i64>,
                workspace: Option<(&str, i64)>,
            ) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let now = Self::session_lock(&mut tx).await?;
                Self::legacy_session_tx(&mut tx, user, Some(generation), iat).await?;
                if successor_iat.is_some_and(|iat| iat > now) {
                    return Err(CoreError::Unauthorized("legacy app session was revoked".into()));
                }
                if let Some((tenant, membership)) = workspace {
                    Self::authorize_tx(
                        &mut tx,
                        tenant,
                        user,
                        memoswish_core::CredentialGenerations {
                            account: generation,
                            membership,
                        },
                    )
                    .await?;
                }
                tx.commit().await.map_err(db_err)
            }
            async fn session_link_ack(&self, hash: &str, attempt_id: &str) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let now = Self::session_lock(&mut tx).await?;
                let (a, consumed) = Self::session_read(&mut tx, hash, false).await?;
                if consumed {
                    return Err(CoreError::Unauthorized("original session was retired".into()));
                }
                Self::session_validate(&mut tx, &a, now).await?;
                let body: String = sqlx::query_scalar("SELECT body FROM oidc_attempts WHERE id=$1")
                    .bind(attempt_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .ok_or_else(|| CoreError::Unauthorized("invalid link attempt".into()))?;
                let attempt: memoswish_core::identity::LoginAttempt =
                    serde_json::from_str(&body).map_err(CoreError::internal)?;
                if attempt.link_access_hash.as_deref() != Some(hash) {
                    return Err(CoreError::Unauthorized("original opaque session required".into()));
                }
                let tenant = a
                    .credential
                    .tenant_id
                    .as_deref()
                    .ok_or_else(|| CoreError::Unauthorized("workspace session required".into()))?;
                let membership = a
                    .credential
                    .membership_generation
                    .ok_or_else(|| CoreError::Unauthorized("workspace session required".into()))?;
                Self::complete_identity_tx(
                    &mut tx,
                    attempt_id,
                    tenant,
                    &a.family.user_id,
                    a.family.generation,
                    &a.credential.assurance_hash,
                    now,
                    Some(memoswish_core::CredentialGenerations {
                        account: a.family.generation,
                        membership,
                    }),
                    false,
                )
                .await?;
                tx.commit().await.map_err(db_err)
            }
            async fn session_access(&self, hash: &str) -> CoreResult<memoswish_core::session::SessionAccess> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                Self::session_lock(&mut tx).await?;
                let a = Self::session_access_tx(&mut tx, hash).await?;
                self.session_commit(tx).await?;
                Ok(a)
            }
            async fn session_issue(&self, f: &memoswish_core::session::SessionFamily, c: &memoswish_core::session::SessionCredential, attempt: Option<&str>) -> CoreResult<()> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let now=Self::session_lock(&mut tx).await?;
                let a=memoswish_core::session::SessionAccess{family:f.clone(),credential:c.clone()};
                Self::session_validate(&mut tx,&a,now).await?;
                if f.auth_time>now || f.revoked {return Err(CoreError::invalid("invalid session family"));}
                if let Some(attempt)=attempt {
                    let row=sqlx::query("SELECT tenant_id FROM oidc_attempts WHERE id=$1").bind(attempt).fetch_optional(&mut *tx).await.map_err(db_err)?
                        .ok_or_else(||CoreError::Unauthorized("invalid identity transaction".into()))?;
                    let tenant:String=row.get("tenant_id");
                    let workspace=c.tenant_id.as_ref().zip(c.membership_generation).map(|(_,membership)|memoswish_core::CredentialGenerations{account:f.generation,membership});
                    Self::complete_identity_tx(&mut tx,attempt,&tenant,&f.user_id,f.generation,&c.assurance_hash,now,workspace,true).await?;
                }
                Self::session_insert_family(&mut tx,f,c).await?;
                self.session_commit(tx).await
            }
            async fn session_select(&self, hash: &str, c: &memoswish_core::session::SessionCredential) -> CoreResult<()> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let now=Self::session_lock(&mut tx).await?;
                let (a,consumed)=Self::session_read(&mut tx,hash,false).await?;
                if consumed || a.credential.tenant_id.is_some() || c.tenant_id.is_none() || c.session_id!=a.family.id {return Err(CoreError::Unauthorized("account session required".into()));}
                Self::session_validate(&mut tx,&a,now).await?;
                Self::session_validate(&mut tx,&memoswish_core::session::SessionAccess{family:a.family.clone(),credential:c.clone()},now).await?;
                Self::session_insert_credential(&mut tx,&a.family,c).await?;
                self.session_commit(tx).await
            }
            async fn session_rotate(&self, hash: &str, access: &str, refresh: &str, assurance: &str, ttl: i64) -> CoreResult<memoswish_core::session::SessionAccess> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let now=Self::session_lock(&mut tx).await?;
                let (mut a,consumed)=Self::session_read(&mut tx,hash,true).await?;
                if consumed {
                    // 只对数据库确认为已消费的父凭据撤销；失败响应前必须提交撤销。
                    sqlx::query("UPDATE app_sessions SET revoked=1 WHERE id=$1").bind(&a.family.id).execute(&mut *tx).await.map_err(db_err)?;
                    self.session_commit(tx).await?;
                    return Err(CoreError::Unauthorized("refresh token reuse revoked the session".into()));
                }
                // refresh 生命周期由族的绝对期限限定，不受旧 access 的较短期限影响。
                a.credential.expires_at=a.family.expires_at;
                Self::session_validate(&mut tx,&a,now).await?;
                if ttl<=0 {return Err(CoreError::invalid("invalid access lifetime"));}
                let n=sqlx::query("UPDATE app_session_credentials SET consumed=1 WHERE refresh_hash=$1 AND consumed=0")
                    .bind(hash).execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                if n!=1 {return Err(CoreError::Unauthorized("invalid app session".into()));}
                a.credential.access_hash=access.into();a.credential.refresh_hash=refresh.into();a.credential.assurance_hash=assurance.into();
                a.credential.expires_at=now.saturating_add(ttl).min(a.family.expires_at);
                Self::session_insert_credential(&mut tx,&a.family,&a.credential).await?;
                self.session_commit(tx).await?;
                Ok(a)
            }
            async fn session_list(&self, hash: &str) -> CoreResult<Vec<memoswish_core::session::SessionFamily>> {
                let a=self.session_access(hash).await?;
                let rows=sqlx::query("SELECT id,user_id,generation,provenance,auth_time,expires_at,revoked FROM app_sessions WHERE user_id=$1 ORDER BY auth_time,id")
                    .bind(&a.family.user_id).fetch_all(&self.pool).await.map_err(db_err)?;
                Ok(rows.into_iter().map(|r|memoswish_core::session::SessionFamily {
                    id:r.get("id"),user_id:r.get("user_id"),generation:r.get("generation"),provenance:r.get("provenance"),auth_time:r.get("auth_time"),expires_at:r.get("expires_at"),revoked:r.get::<i64,_>("revoked")!=0
                }).collect())
            }
            async fn session_revoke(&self, hash: &str, id: &str) -> CoreResult<bool> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let now=Self::session_lock(&mut tx).await?;
                let (a,consumed)=Self::session_read(&mut tx,hash,false).await?;
                if consumed {return Err(CoreError::Unauthorized("invalid app session".into()));}
                Self::session_validate(&mut tx,&a,now).await?;
                let n=sqlx::query("UPDATE app_sessions SET revoked=1 WHERE id=$1 AND user_id=$2").bind(id).bind(&a.family.user_id).execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                self.session_commit(tx).await?;
                Ok(n==1)
            }
        }
    };
}
pub(crate) use sessions_impl;
