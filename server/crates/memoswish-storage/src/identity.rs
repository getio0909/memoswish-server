//! 双数据库共享身份事务与账户生命周期，使用显式列白名单导出，永不导出凭据摘要。
macro_rules! identity_impl {
    ($repo:ty, $db:ty, $erasure_lock:expr, $clock_query:expr) => {
        #[async_trait::async_trait]
        impl memoswish_core::identity::IdentityRepo for $repo {
            async fn identity_reencrypt(&self, transform:&memoswish_core::identity::CipherTransform)->CoreResult<u64> {
                let mut changed=0;
                // 分页各自持有注册锁，断点重跑安全；不在网络事务中调用。
                for table in ["oidc_attempts","oidc_handoffs","account_erasure_jobs"] {
                    let key=if table=="oidc_handoffs" {"hash"} else {"id"};
                    let mut cursor=String::new();
                    loop {
                        let mut tx=self.pool.begin().await.map_err(db_err)?;
                        Self::session_lock(&mut tx).await?;
                        let rows=sqlx::query(&format!("SELECT {key} AS cursor,body FROM {table} WHERE {key}>$1 ORDER BY {key} LIMIT 100"))
                            .bind(&cursor).fetch_all(&mut *tx).await.map_err(db_err)?;
                        let count=rows.len();
                        for row in rows {
                            cursor=row.get("cursor");let old:String=row.get("body");
                            let new=crate::identity::rekey_body(table,&old,transform)?;
                            if old!=new {
                                sqlx::query(&format!("UPDATE {table} SET body=$1 WHERE {key}=$2"))
                                    .bind(new).bind(&cursor).execute(&mut *tx).await.map_err(db_err)?;
                                changed+=1;
                            }
                            if table=="oidc_attempts" {
                                let pending:Option<String>=sqlx::query_scalar("SELECT pending_link FROM oidc_attempts WHERE id=$1").bind(&cursor).fetch_one(&mut *tx).await.map_err(db_err)?;
                                if let Some(body)=pending {
                                    let (identity,credential):(memoswish_core::identity::FederatedIdentity,Option<String>)=serde_json::from_str(&body).map_err(CoreError::internal)?;
                                    let credential=credential.map(|v|crate::identity::rekey_revocation(&v,transform)).transpose()?;
                                    let new=crate::oauth::encode(&(identity,credential))?;
                                    if new!=body {
                                        sqlx::query("UPDATE oidc_attempts SET pending_link=$1 WHERE id=$2").bind(new).bind(&cursor).execute(&mut *tx).await.map_err(db_err)?;changed+=1;
                                    }
                                }
                            }
                        }
                        tx.commit().await.map_err(db_err)?;
                        if count<100 {break;}
                    }
                }
                let (mut issuer,mut subject)=(String::new(),String::new());
                loop {
                    let mut tx=self.pool.begin().await.map_err(db_err)?;Self::session_lock(&mut tx).await?;
                    let rows=sqlx::query("SELECT issuer,subject,credential FROM federated_identities WHERE (issuer,subject)>($1,$2) ORDER BY issuer,subject LIMIT 100")
                        .bind(&issuer).bind(&subject).fetch_all(&mut *tx).await.map_err(db_err)?;
                    let count=rows.len();
                    for r in rows {
                        issuer=r.get("issuer");subject=r.get("subject");
                        if let Some(old)=r.get::<Option<String>,_>("credential") {
                            let new=crate::identity::rekey_revocation(&old,transform)?;
                            if old!=new {sqlx::query("UPDATE federated_identities SET credential=$1 WHERE issuer=$2 AND subject=$3").bind(new).bind(&issuer).bind(&subject).execute(&mut *tx).await.map_err(db_err)?;changed+=1;}
                        }
                    }
                    tx.commit().await.map_err(db_err)?;if count<100 {break;}
                }
                Ok(changed)
            }
            async fn identity_list(&self, tenant_id: &str, user_id: &str) -> CoreResult<Vec<memoswish_core::identity::FederatedIdentity>> {
                let rows: Vec<String> = sqlx::query_scalar("SELECT body FROM federated_identities WHERE tenant_id=$1 AND user_id=$2 ORDER BY issuer,subject")
                    .bind(tenant_id).bind(user_id).fetch_all(&self.pool).await.map_err(db_err)?;
                rows.into_iter().map(|body| serde_json::from_str(&body).map_err(CoreError::internal)).collect()
            }
            async fn identity_unlink(
                &self,
                tenant_id: &str,
                user_id: &str,
                generations: memoswish_core::CredentialGenerations,
                provider: &str,
                session_hash: &str,
                now: i64,
                configured_clients: &[(String, String, Vec<String>)],
            ) -> CoreResult<bool> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_err)?;
                let now=Self::session_clock(&mut tx).await?.max(now);
                Self::authorize_tx(&mut tx, tenant_id, user_id, generations).await?;
                // 已在适配器认证的请求等待锁期间，logout/旋转仍可撤销其原会话。
                let opaque:Option<String>=sqlx::query_scalar("SELECT access_hash FROM app_session_credentials WHERE assurance_hash=$1")
                    .bind(session_hash).fetch_optional(&mut *tx).await.map_err(db_err)?;
                if let Some(hash)=opaque {
                    let (a,used)=Self::session_read(&mut tx,&hash,false).await?;
                    if used {return Err(CoreError::Unauthorized("original session was retired".into()));}
                    Self::session_validate(&mut tx,&a,now).await?;
                }
                let recent: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recent_authentication WHERE tenant_id=$1 AND user_id=$2 AND hash=$3 AND expires_at>$4")
                    .bind(tenant_id).bind(user_id).bind(session_hash).bind(now).fetch_one(&mut *tx).await.map_err(db_err)?;
                if recent != 1 { return Err(CoreError::Forbidden("identity changes require interactive login within five minutes".into())); }
                let password: Option<String> = sqlx::query_scalar("SELECT password_hash FROM user_profiles WHERE tenant_id=$1 AND id=$2")
                    .bind(tenant_id).bind(user_id).fetch_optional(&mut *tx).await.map_err(db_err)?;
                let password = password.ok_or_else(|| CoreError::Unauthorized("account no longer exists".into()))?;
                let rows = sqlx::query("SELECT issuer,subject,body,credential FROM federated_identities WHERE tenant_id=$1 AND user_id=$2")
                    .bind(tenant_id).bind(user_id).fetch_all(&mut *tx).await.map_err(db_err)?;
                let mut targets = Vec::new();
                let mut remaining = 0;
                for row in rows {
                    let body: String = row.get("body");
                    let identity: memoswish_core::identity::FederatedIdentity = serde_json::from_str(&body).map_err(CoreError::internal)?;
                    if identity.provider == provider {
                        targets.push(row);
                    } else if configured_clients.iter().any(|(provider, issuer, clients)| {
                        identity.provider == *provider && identity.issuer == *issuer
                            && clients.contains(&identity.client_id)
                    }) {
                        let revoked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_status WHERE issuer=$1 AND subject=$2 AND (permanently_deleted<>0 OR last_event_kind='consent-revoked')")
                            .bind(&identity.issuer).bind(&identity.subject).fetch_one(&mut *tx).await.map_err(db_err)?;
                        if revoked == 0 { remaining += 1; }
                    }
                }
                if targets.is_empty() { return Err(CoreError::NotFound("linked provider".into())); }
                if password.is_empty() && remaining == 0 { return Err(CoreError::Conflict("cannot remove the last login method".into())); }
                let sequence: i64 = sqlx::query_scalar("UPDATE oidc_sequence SET value=value+1 WHERE id=1 RETURNING value")
                    .fetch_one(&mut *tx).await.map_err(db_err)?;
                let mut credentials = Vec::new();
                for row in targets {
                    sqlx::query("INSERT INTO identity_unlink_fences(identity_hash,sequence) VALUES($1,$2) ON CONFLICT(identity_hash) DO UPDATE SET sequence=excluded.sequence")
                        .bind(memoswish_core::ids::sha256_hex(format!("{}\0{}",row.get::<String,_>("issuer"),row.get::<String,_>("subject")).as_bytes())).bind(sequence)
                        .execute(&mut *tx).await.map_err(db_err)?;
                    // 规范身份覆盖同一 issuer 的全部 provider 别名，包括已消费的 handoff。
                    sqlx::query("DELETE FROM oidc_handoffs WHERE attempt_id IN (SELECT id FROM oidc_attempts WHERE identity_issuer=$1 AND identity_subject=$2)")
                        .bind(row.get::<String,_>("issuer")).bind(row.get::<String,_>("subject"))
                        .execute(&mut *tx).await.map_err(db_err)?;
                    sqlx::query("DELETE FROM oidc_attempts WHERE identity_issuer=$1 AND identity_subject=$2")
                        .bind(row.get::<String,_>("issuer")).bind(row.get::<String,_>("subject"))
                        .execute(&mut *tx).await.map_err(db_err)?;
                    if let Some(credential) = row.get::<Option<String>, _>("credential") { credentials.push((provider.to_string(), credential)); }
                    sqlx::query("DELETE FROM federated_identities WHERE tenant_id=$1 AND user_id=$2 AND issuer=$3 AND subject=$4")
                        .bind(tenant_id).bind(user_id).bind(row.get::<String,_>("issuer")).bind(row.get::<String,_>("subject"))
                        .execute(&mut *tx).await.map_err(db_err)?;
                }
                // 删除已解析登录与显式关联事务；未解析回调由身份序列屏障拒绝。
                sqlx::query("DELETE FROM oidc_attempts WHERE tenant_id=$1 AND user_id=$2 AND provider=$3")
                    .bind(tenant_id).bind(user_id).bind(provider).execute(&mut *tx).await.map_err(db_err)?;
                sqlx::query("DELETE FROM oidc_handoffs WHERE tenant_id=$1 AND user_id=$2 AND provider=$3")
                    .bind(tenant_id).bind(user_id).bind(provider).execute(&mut *tx).await.map_err(db_err)?;
                let pending = !credentials.is_empty();
                if pending {
                    let job = memoswish_core::identity::ErasureJob { id: memoswish_core::ids::new_id(), tenant_id: Some(tenant_id.into()), purge_assets: false, credentials };
                    sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
                        .bind(&job.id).bind(crate::oauth::encode(&job)?).execute(&mut *tx).await.map_err(db_err)?;
                }
                tx.commit().await.map_err(db_err)?;
                Ok(pending)
            }
            async fn identity_attempt_insert(&self, a: &memoswish_core::identity::LoginAttempt) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oidc_attempts")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_err)?;
                if count >= 10000 {
                    return Err(CoreError::QuotaExceeded("login transaction capacity reached".into()));
                }
                if let (Some(tenant),Some(user),Some(account),Some(membership))=(&a.link_tenant,&a.link_user,a.link_generation,a.link_membership_generation) {
                    Self::authorize_tx(&mut tx,tenant,user,memoswish_core::CredentialGenerations {account,membership}).await?;
                } else if a.link_user.is_some() {return Err(CoreError::Unauthorized("missing link authorization".into()));}
                let now=Self::session_clock(&mut tx).await?;
                Self::identity_link_authorize_tx(&mut tx,a,now).await?;
                let sequence: i64 = sqlx::query_scalar("UPDATE oidc_sequence SET value=value+1 WHERE id=1 RETURNING value")
                    .fetch_one(&mut *tx).await.map_err(db_err)?;
                sqlx::query("INSERT INTO oidc_attempts(id,state_hash,launch_hash,browser_hash,provider,expires_at,body,tenant_id,user_id,sequence,membership_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
                            .bind(&a.id).bind(&a.state_hash).bind(&a.launch_hash).bind(&a.browser_hash).bind(&a.provider).bind(a.expires_at)
                            .bind(crate::oauth::encode(a)?).bind(&a.link_tenant).bind(&a.link_user).bind(sequence).bind(a.link_membership_generation).execute(&mut *tx).await.map_err(db_err)?;
                tx.commit().await.map_err(db_err)
            }
            async fn identity_attempt(
                &self,
                id: &str,
                state_lookup: bool,
            ) -> CoreResult<Option<memoswish_core::identity::LoginAttempt>> {
                let sql = if state_lookup {
                    "SELECT body FROM oidc_attempts WHERE state_hash=$1"
                } else {
                    "SELECT body FROM oidc_attempts WHERE id=$1"
                };
                crate::oauth::decode(
                    sqlx::query_scalar(sql)
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(db_err)?,
                )
            }
            async fn identity_launch(&self, id: &str, launch_hash: &str, browser_hash: &str, now: i64) -> CoreResult<bool> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                Self::session_lock(&mut tx).await?;
                let body:Option<String>=sqlx::query_scalar("SELECT body FROM oidc_attempts WHERE id=$1 AND launch_hash=$2 AND phase=0 AND expires_at>$3")
                    .bind(id).bind(launch_hash).bind(now).fetch_optional(&mut *tx).await.map_err(db_err)?;
                let Some(body)=body else {tx.commit().await.map_err(db_err)?;return Ok(false)};
                let attempt:memoswish_core::identity::LoginAttempt=serde_json::from_str(&body).map_err(CoreError::internal)?;
                Self::identity_link_authorize_tx(&mut tx,&attempt,now).await?;
                let changed=sqlx::query("UPDATE oidc_attempts SET phase=1,browser_hash=$1 WHERE id=$2 AND launch_hash=$3 AND phase=0 AND expires_at>$4")
                            .bind(browser_hash).bind(id).bind(launch_hash).bind(now).execute(&mut *tx).await.map_err(db_err)?.rows_affected()==1;
                tx.commit().await.map_err(db_err)?;Ok(changed)
            }
            async fn identity_claim(
                &self,
                id: &str,
                provider: &str,
                binding: &str,
                native: bool,
                now: i64,
            ) -> CoreResult<bool> {
                let sql = if native {
                    "UPDATE oidc_attempts SET phase=2 WHERE id=$1 AND provider=$2 AND launch_hash=$3 AND phase=0 AND expires_at>$4"
                } else {
                    "UPDATE oidc_attempts SET phase=2 WHERE id=$1 AND provider=$2 AND browser_hash=$3 AND phase=1 AND expires_at>$4"
                };
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                Self::session_lock(&mut tx).await?;
                let lookup=if native {
                    "SELECT body FROM oidc_attempts WHERE id=$1 AND provider=$2 AND launch_hash=$3 AND phase=0 AND expires_at>$4"
                } else {
                    "SELECT body FROM oidc_attempts WHERE id=$1 AND provider=$2 AND browser_hash=$3 AND phase=1 AND expires_at>$4"
                };
                let body:Option<String>=sqlx::query_scalar(lookup).bind(id).bind(provider).bind(binding).bind(now).fetch_optional(&mut *tx).await.map_err(db_err)?;
                let Some(body)=body else {tx.commit().await.map_err(db_err)?;return Ok(false)};
                let attempt:memoswish_core::identity::LoginAttempt=serde_json::from_str(&body).map_err(CoreError::internal)?;
                Self::identity_link_authorize_tx(&mut tx,&attempt,now).await?;
                let changed=sqlx::query(sql)
                    .bind(id)
                    .bind(provider)
                    .bind(binding)
                    .bind(now)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .rows_affected()
                    == 1;
                tx.commit().await.map_err(db_err)?;Ok(changed)
            }
            async fn identity_resolve(
                &self,
                i: &memoswish_core::identity::FederatedIdentity,
                new_account: Option<(&TenantRecord, &UserRecord)>,
                link: bool,
                credential: Option<&str>,
                expected_generations: Option<memoswish_core::CredentialGenerations>,
                attempt_id: Option<&str>,
            ) -> CoreResult<(String, String, i64)> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                if let Some(id) = attempt_id {
                    let valid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oidc_attempts a WHERE a.id=$1 AND a.phase=2 AND a.provider=$2 AND a.expires_at>$4 AND a.sequence>COALESCE((SELECT sequence FROM identity_unlink_fences WHERE identity_hash=$3),-1)")
                        .bind(id).bind(&i.provider).bind(memoswish_core::ids::sha256_hex(format!("{}\0{}",i.issuer,i.subject).as_bytes())).bind(Self::session_clock(&mut tx).await?).fetch_one(&mut *tx).await.map_err(db_err)?;
                    if valid != 1 { return Err(CoreError::Unauthorized("identity transaction was invalidated".into())); }
                }
                if link {
                    Self::privacy_collection_tx(&mut tx,&i.tenant_id,&i.user_id).await?;
                    let expected =
                        expected_generations.ok_or_else(|| CoreError::Unauthorized("missing link authorization".into()))?;
                    Self::authorize_tx(&mut tx, &i.tenant_id, &i.user_id, expected).await?;
                    if let Some(id) = attempt_id {
                        let body: String = sqlx::query_scalar("SELECT body FROM oidc_attempts WHERE id=$1")
                            .bind(id)
                            .fetch_one(&mut *tx)
                            .await
                            .map_err(db_err)?;
                        let attempt: memoswish_core::identity::LoginAttempt =
                            serde_json::from_str(&body).map_err(CoreError::internal)?;
                        if attempt.link_tenant.as_deref() != Some(i.tenant_id.as_str())
                            || attempt.link_user.as_deref() != Some(i.user_id.as_str())
                            || attempt.link_generation != Some(expected.account)
                            || attempt.link_membership_generation != Some(expected.membership)
                        {
                            return Err(CoreError::Unauthorized("link authorization does not match the original session".into()));
                        }
                    }
                }
                if link && let Some(id)=attempt_id {
                    let now=Self::session_clock(&mut tx).await?;
                    let body:String=sqlx::query_scalar("SELECT body FROM oidc_attempts WHERE id=$1 AND expires_at>$2")
                        .bind(id).bind(now).fetch_optional(&mut *tx).await.map_err(db_err)?.ok_or_else(||CoreError::Unauthorized("identity transaction expired".into()))?;
                    let attempt:memoswish_core::identity::LoginAttempt=serde_json::from_str(&body).map_err(CoreError::internal)?;
                    Self::identity_link_authorize_tx(&mut tx,&attempt,now).await?;
                    let owner:Option<String>=sqlx::query_scalar("SELECT user_id FROM federated_identities WHERE issuer=$1 AND subject=$2")
                        .bind(&i.issuer).bind(&i.subject).fetch_optional(&mut *tx).await.map_err(db_err)?;
                    if owner.as_deref().is_some_and(|u|u!=i.user_id){return Err(CoreError::Conflict("identity is already linked".into()));}
                    let pending=crate::oauth::encode(&(i,credential))?;
                    sqlx::query("UPDATE oidc_attempts SET pending_link=$1,identity_issuer=$2,identity_subject=$3 WHERE id=$4")
                        .bind(pending).bind(&i.issuer).bind(&i.subject).bind(id).execute(&mut *tx).await.map_err(db_err)?;
                    tx.commit().await.map_err(db_err)?;
                    return Ok((i.tenant_id.clone(),i.user_id.clone(),expected_generations.unwrap().account));
                }
                let existing = sqlx::query("SELECT tenant_id,user_id,body FROM federated_identities WHERE issuer=$1 AND subject=$2")
                    .bind(&i.issuer)
                    .bind(&i.subject)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_err)?;
                if let Some(row) = existing {
                    let t: String = row.get("tenant_id");
                    let u: String = row.get("user_id");
                    if link && (t != i.tenant_id || u != i.user_id) {
                        return Err(CoreError::Conflict("identity is already linked".into()));
                    }
                    if let Some(status)=sqlx::query("SELECT last_event_at,last_event_kind,revoked_before,permanently_deleted FROM identity_status WHERE issuer=$1 AND subject=$2").bind(&i.issuer).bind(&i.subject).fetch_optional(&mut *tx).await.map_err(db_err)? {
                                let kind:String=status.get("last_event_kind");
                                if status.get::<i64,_>("permanently_deleted")!=0 || i.authenticated_at<=status.get::<i64,_>("revoked_before") {return Err(CoreError::Unauthorized("upstream identity is revoked".into()));}
                                if kind=="consent-revoked" {sqlx::query("UPDATE identity_status SET last_event_kind='reauthorized' WHERE issuer=$1 AND subject=$2").bind(&i.issuer).bind(&i.subject).execute(&mut *tx).await.map_err(db_err)?;}
                            }
                    // 重新交互认证补齐旧数据的 client 映射，保留已有资料。
                    let mut stored: memoswish_core::identity::FederatedIdentity = serde_json::from_str(&row.get::<String,_>("body")).map_err(CoreError::internal)?;
                    stored.client_id = i.client_id.clone();
                    stored.authenticated_at = i.authenticated_at;
                    sqlx::query("UPDATE federated_identities SET body=$1 WHERE issuer=$2 AND subject=$3")
                        .bind(crate::oauth::encode(&stored)?).bind(&i.issuer).bind(&i.subject).execute(&mut *tx).await.map_err(db_err)?;
                    if let Some(c) = credential {
                        sqlx::query("UPDATE federated_identities SET credential=$1 WHERE issuer=$2 AND subject=$3")
                            .bind(c)
                            .bind(&i.issuer)
                            .bind(&i.subject)
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    }
                    let generation: i64 = sqlx::query_scalar("SELECT generation FROM account_auth_epochs WHERE user_id=$2 AND $1 IS NOT NULL")
                        .bind(&t).bind(&u).fetch_optional(&mut *tx).await.map_err(db_err)?.ok_or_else(||CoreError::Unauthorized("account no longer exists".into()))?;
                    if let Some(id) = attempt_id {
                        sqlx::query("UPDATE oidc_attempts SET tenant_id=$1,user_id=$2,identity_issuer=$4,identity_subject=$5,membership_generation=(SELECT generation FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2) WHERE id=$3")
                            .bind(&t).bind(&u).bind(id).bind(&i.issuer).bind(&i.subject).execute(&mut *tx).await.map_err(db_err)?;
                    }
                    tx.commit().await.map_err(db_err)?;
                    return Ok((t, u, generation));
                }
                if link {
                    let present: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_profiles WHERE tenant_id=$1 AND id=$2")
                        .bind(&i.tenant_id)
                        .bind(&i.user_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    if present != 1 {
                        return Err(CoreError::Unauthorized("link account no longer exists".into()));
                    }
                } else {
                    let (t, u) = new_account.ok_or_else(|| CoreError::Forbidden("registration is closed".into()))?;
                    if let Some(email) = i.email.as_ref().filter(|_| i.email_verified) {
                        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE lower(email)=lower($1)")
                            .bind(email)
                            .fetch_one(&mut *tx)
                            .await
                            .map_err(db_err)?;
                        if n != 0 {
                            return Err(CoreError::Conflict(
                                "authenticate the existing account before linking this identity".into(),
                            ));
                        }
                    }
                    sqlx::query("INSERT INTO tenants(id,name,plan,created_at) VALUES($1,$2,$3,$4)")
                        .bind(&t.id)
                        .bind(&t.name)
                        .bind(&t.plan)
                        .bind(t.created_at)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    Self::insert_identity(&mut tx,u).await?;
                }
                sqlx::query("INSERT INTO federated_identities(issuer,subject,tenant_id,user_id,body,credential) VALUES($1,$2,$3,$4,$5,$6)")
                            .bind(&i.issuer).bind(&i.subject).bind(&i.tenant_id).bind(&i.user_id).bind(crate::oauth::encode(i)?).bind(credential).execute(&mut *tx).await.map_err(db_err)?;
                let generation: i64 = sqlx::query_scalar("SELECT generation FROM account_auth_epochs WHERE user_id=$2 AND $1 IS NOT NULL")
                    .bind(&i.tenant_id).bind(&i.user_id).fetch_optional(&mut *tx).await.map_err(db_err)?.ok_or_else(||CoreError::Unauthorized("account no longer exists".into()))?;
                if let Some(id) = attempt_id {
                    sqlx::query("UPDATE oidc_attempts SET tenant_id=$1,user_id=$2,identity_issuer=$4,identity_subject=$5,membership_generation=(SELECT generation FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2) WHERE id=$3")
                        .bind(&i.tenant_id).bind(&i.user_id).bind(id).bind(&i.issuer).bind(&i.subject).execute(&mut *tx).await.map_err(db_err)?;
                }
                tx.commit().await.map_err(db_err)?;
                Ok((i.tenant_id.clone(), i.user_id.clone(), generation))
            }
            async fn identity_handoff_insert(&self, h: &memoswish_core::identity::LoginHandoff) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_err)?;
                if let Some(id) = &h.attempt_id {
                    let valid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oidc_attempts WHERE id=$1 AND phase=2 AND tenant_id=$2 AND user_id=$3")
                        .bind(id).bind(&h.tenant_id).bind(&h.user_id).fetch_one(&mut *tx).await.map_err(db_err)?;
                    if valid != 1 { return Err(CoreError::Unauthorized("identity transaction was invalidated".into())); }
                }
                sqlx::query("INSERT INTO oidc_handoffs(hash,provider,challenge,tenant_id,user_id,expires_at,body,attempt_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                            .bind(&h.hash).bind(&h.provider).bind(&h.challenge).bind(&h.tenant_id).bind(&h.user_id).bind(h.expires_at).bind(crate::oauth::encode(h)?).bind(&h.attempt_id).execute(&mut *tx).await.map_err(db_err)?;
                tx.commit().await.map_err(db_err)
            }
            async fn identity_handoff_consume(
                &self,
                hash: &str,
                provider: &str,
                challenge: &str,
                now: i64,
            ) -> CoreResult<Option<memoswish_core::identity::LoginHandoff>> {
                crate::oauth::decode(sqlx::query_scalar("DELETE FROM oidc_handoffs WHERE hash=$1 AND provider=$2 AND challenge=$3 AND expires_at>$4 RETURNING body")
                            .bind(hash).bind(provider).bind(challenge).bind(now).fetch_optional(&self.pool).await.map_err(db_err)?)
            }
            async fn identity_complete(
                &self,
                attempt_id: &str,
                tenant_id: &str,
                user_id: &str,
                generations: memoswish_core::CredentialGenerations,
                session_hash: &str,
                now: i64,
            ) -> CoreResult<()> {
                self.complete_identity(attempt_id, tenant_id, user_id, generations.account, session_hash, now, Some(generations))
                    .await
            }
            async fn identity_complete_account(
                &self,
                attempt_id: &str,
                tenant_id: &str,
                user_id: &str,
                generation: i64,
                session_hash: &str,
                now: i64,
            ) -> CoreResult<()> {
                self.complete_identity(attempt_id, tenant_id, user_id, generation, session_hash, now, None).await
            }
            async fn identity_recent_auth(
                &self,
                tenant_id: &str,
                user_id: &str,
                generations: memoswish_core::CredentialGenerations,
                hash: &str,
                expires: i64,
            ) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_err)?;
                Self::authorize_tx(&mut tx, tenant_id, user_id, generations).await?;
                sqlx::query("INSERT INTO recent_authentication(hash,tenant_id,user_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(hash) DO NOTHING")
                            .bind(hash).bind(tenant_id).bind(user_id).bind(expires).execute(&mut *tx).await.map_err(db_err)?;
                tx.commit().await.map_err(db_err)
            }
            async fn identity_recent_deadline(&self, tenant_id:&str,user_id:&str,generations:memoswish_core::CredentialGenerations,hash:&str) -> CoreResult<Option<i64>> {
                let mut tx=self.pool.begin().await.map_err(db_err)?;
                let now=Self::session_lock(&mut tx).await?;
                Self::authorize_tx(&mut tx,tenant_id,user_id,generations).await?;
                let expires=sqlx::query_scalar("SELECT expires_at FROM recent_authentication WHERE tenant_id=$1 AND user_id=$2 AND hash=$3 AND expires_at>$4")
                    .bind(tenant_id).bind(user_id).bind(hash).bind(now).fetch_optional(&mut *tx).await.map_err(db_err)?;
                tx.commit().await.map_err(db_err)?;
                Ok(expires)
            }
            async fn identity_check_recent(
                &self,
                tenant_id: &str,
                user_id: &str,
                generations: memoswish_core::CredentialGenerations,
                hash: &str,
                now: i64,
            ) -> CoreResult<bool> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_err)?;
                let n: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM recent_authentication WHERE tenant_id=$1 AND user_id=$2 AND hash=$3 AND expires_at>$4",
                )
                .bind(tenant_id)
                .bind(user_id)
                .bind(hash)
                .bind(now)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
                if n == 1 {
                    Self::authorize_tx(&mut tx, tenant_id, user_id, generations).await?;
                }
                tx.commit().await.map_err(db_err)?;
                Ok(n == 1)
            }
            async fn identity_generation(&self, _tenant_id: &str, user_id: &str) -> CoreResult<i64> {
                <Self as MembershipRepo>::account_generation(self,user_id).await
            }
            async fn identity_event(
                &self,
                issuer: &str,
                subject: &str,
                event_hash: &str,
                kind: &str,
                at: i64,
                now: i64,
            ) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let n = sqlx::query(
                    "INSERT INTO identity_events(issuer,event_hash,expires_at) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
                )
                .bind(issuer)
                .bind(event_hash)
                .bind(now + 86400)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected();
                if n == 0 {
                    return Ok(());
                }
                let row = sqlx::query("SELECT tenant_id,user_id FROM federated_identities WHERE issuer=$1 AND subject=$2")
                    .bind(issuer)
                    .bind(subject)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_err)?;
                if let Some(row) = row {
                    let t: String = row.get("tenant_id");
                    let u: String = row.get("user_id");
                    let forwarding = match kind {
                        "email-enabled" => Some("enabled"),
                        "email-disabled" => Some("disabled"),
                        _ => None,
                    };
                    let n=sqlx::query("INSERT INTO identity_status(issuer,subject,last_event_at,last_event_kind,email_forwarding,revoked_before,permanently_deleted) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(issuer,subject) DO UPDATE SET last_event_at=CASE WHEN excluded.last_event_at>identity_status.last_event_at THEN excluded.last_event_at ELSE identity_status.last_event_at END,last_event_kind=CASE WHEN identity_status.last_event_kind='account-deleted' THEN 'account-deleted' WHEN excluded.last_event_kind IN ('email-enabled','email-disabled') AND identity_status.last_event_kind IN ('consent-revoked','account-deleted') THEN identity_status.last_event_kind ELSE excluded.last_event_kind END,email_forwarding=COALESCE(excluded.email_forwarding,identity_status.email_forwarding),revoked_before=CASE WHEN excluded.revoked_before>identity_status.revoked_before THEN excluded.revoked_before ELSE identity_status.revoked_before END,permanently_deleted=CASE WHEN excluded.permanently_deleted>identity_status.permanently_deleted THEN excluded.permanently_deleted ELSE identity_status.permanently_deleted END WHERE identity_status.last_event_at<=excluded.last_event_at OR excluded.revoked_before>identity_status.revoked_before OR excluded.permanently_deleted>identity_status.permanently_deleted")
                                .bind(issuer).bind(subject).bind(at).bind(kind).bind(forwarding).bind(if ["consent-revoked","account-deleted"].contains(&kind){at}else{0}).bind(if kind=="account-deleted"{1i64}else{0i64}).execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                    if n == 1 && ["consent-revoked", "account-deleted"].contains(&kind) {
                        let advanced=sqlx::query("UPDATE account_auth_epochs SET generation=generation+1 WHERE user_id=$1 AND generation<9223372036854775807").bind(&u).execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                        if advanced!=1 {return Err(CoreError::Conflict("account generation exhausted".into()));}
                        sqlx::query("INSERT INTO user_auth_epochs(tenant_id,user_id,generation) VALUES($1,$2,1) ON CONFLICT(tenant_id,user_id) DO UPDATE SET generation=user_auth_epochs.generation+1").bind(&t).bind(&u).execute(&mut *tx).await.map_err(db_err)?;
                        sqlx::query("DELETE FROM api_tokens WHERE user_id=$2 AND $1 IS NOT NULL")
                            .bind(&t)
                            .bind(&u)
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                        for table in [
                            "oauth_grants",
                            "auth_browser_sessions",
                            "recent_authentication",
                            "oidc_attempts",
                            "oidc_handoffs",
                        ] {
                            sqlx::query(&format!("DELETE FROM {table} WHERE user_id=$2 AND $1 IS NOT NULL"))
                                .bind(&t)
                                .bind(&u)
                                .execute(&mut *tx)
                                .await
                                .map_err(db_err)?;
                        }
                        sqlx::query("UPDATE federated_identities SET credential=NULL WHERE issuer=$1 AND subject=$2")
                            .bind(issuer)
                            .bind(subject)
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    }
                }
                tx.commit().await.map_err(db_err)
            }
            async fn identity_cleanup(&self, now: i64) -> CoreResult<()> {
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::Retention);
        let result: CoreResult<_> = async {
                for expiry in crate::recovery::IDENTITY_EXPIRY {
                    sqlx::query(&format!("DELETE FROM {} WHERE {}",expiry.table,expiry.predicate("$1")))
                        .bind(now)
                        .execute(&self.pool)
                        .await
                        .map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })?;
                }
                let mut tx = self.pool.begin().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })?;
                let clock=Self::session_clock(&mut tx).await?;
                // 先清除过期族的 assurance，防止已回收 opaque 索引被误当作 legacy 认证。
                sqlx::query("DELETE FROM recent_authentication WHERE hash IN (SELECT c.assurance_hash FROM app_session_credentials c JOIN app_sessions s ON s.id=c.session_id WHERE s.expires_at<=$1)")
                    .bind(clock).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })?;
                sqlx::query(&format!("DELETE FROM app_sessions WHERE {}",crate::recovery::SESSIONS.predicate("$1"))).bind(clock).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })?;
                // 没有更早的持久事务后，晚到回调也无法通过事务存在性检查。
                sqlx::query(&format!("DELETE FROM identity_unlink_fences WHERE identity_hash IN (SELECT identity_hash FROM ({}) recovery)",crate::recovery::FENCES.sql))
                    .execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })?;
                tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
            async fn account_export(&self, tenant_id: &str, user_id: &str, owner: bool) -> CoreResult<serde_json::Value> {
                let role:Option<String>=sqlx::query_scalar("SELECT role FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2").bind(tenant_id).bind(user_id).fetch_optional(&self.pool).await.map_err(db_err)?;
                let editor=role.as_deref().is_some_and(|role|matches!(role,"owner"|"admin"|"editor"));
                let mut result = serde_json::Map::new();
                // 列白名单排除密码、令牌摘要、随机状态、上游凭据及授权码。
                let tables: &[(&str, &[&str], bool)] = &[
                    ("privacy_purposes", &["user_id", "body"], true),
                    ("diagnostic_reports", &["report_id", "body", "created_at_ms", "expires_at_ms"], true),
                    (
                        "users",
                        &["id", "tenant_id", "email", "display_name", "role", "created_at"],
                        true,
                    ),
                    (
                        "api_tokens",
                        &[
                            "id",
                            "name",
                            "user_id",
                            "scopes",
                            "created_at",
                            "expires_at",
                            "last_used_at",
                            "revoked",
                        ],
                        true,
                    ),
                    ("usage_counters", &["metric", "period", "amount"], false),
                    (
                        "decks",
                        &["id", "title", "description", "language", "tags", "created_at"],
                        false,
                    ),
                    ("cards", &["body"], false),
                    ("content_revisions", &["body"], false),
                    ("content_reports", &["user_id","body"], true),
                    ("personal_favorites", &["user_id","card_id","starred","revision"], true),
                    ("favorite_operations", &["user_id","operation_id","command","receipt"], true),
                    ("content_imports", &["id", "user_id", "outcome", "result"], true),
                    ("bgm_tracks", &["body"], false),
                    (
                        "memory_states",
                        &[
                            "user_id",
                            "card_id",
                            "stability",
                            "difficulty",
                            "reps",
                            "lapses",
                            "exposures",
                            "last_review",
                            "due",
                            "starred",
                            "last_rating",
                        ],
                        true,
                    ),
                    (
                        "feedback_events",
                        &["user_id", "session_id", "rating", "body", "received_at", "application_provenance"],
                        true,
                    ),
                    (
                        "feed_sessions",
                        &[
                            "id",
                            "user_id",
                            "next_slot",
                            "recent_card_ids",
                            "created_at",
                            "updated_at",
                        ],
                        true,
                    ),
                    ("learner_preferences", &["user_id", "desired_retention", "revision", "epoch", "issuance_seq"], true),
                    ("learner_card_controls", &["user_id", "card_id", "suspended", "buried_until_ms", "revision", "last_issued_seq"], true),
                    ("feed_deliveries", &["user_id", "session_id", "slot", "delivery_id", "body"], true),
                    ("federated_identities", &["body"], true),
                    ("oidc_attempts", &["provider", "user_id", "expires_at"], true),
                    ("oidc_handoffs", &["provider", "user_id", "expires_at"], true),
                    ("recent_authentication", &["user_id", "expires_at"], true),
                    ("auth_browser_sessions", &["user_id", "expires_at", "body"], true),
                    (
                        "oauth_grants",
                        &["id", "user_id", "client_id", "expires_at", "revoked", "metadata"],
                        true,
                    ),
                ];
                for (table, cols, personal) in tables {
                    let projection = cols
                        .iter()
                        .map(|c| format!("CAST({c} AS TEXT) AS {c}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    let filter = if *table=="cards" && !editor {
                        " AND publication='published' AND $2=$2"
                    } else if *table=="content_revisions" && !editor {
                        " AND 1=0 AND $2=$2"
                    } else if matches!(*table,"privacy_purposes" | "diagnostic_reports" | "personal_favorites" | "favorite_operations") {
                        " AND user_id=$2"
                    } else if *personal && !owner {
                        if *table == "users" {
                            " AND id=$2"
                        } else {
                            " AND user_id=$2"
                        }
                    } else {
                        ""
                    };
                    let source = if *table == "users" { "user_profiles" } else { *table };
                    let expiry = if *table=="diagnostic_reports" {format!(" AND expires_at_ms > ({})",$clock_query)} else {String::new()};
                    let sql = format!("SELECT {projection} FROM {source} WHERE tenant_id=$1{filter}{expiry}");
                    let q = sqlx::query(&sql).bind(tenant_id);
                    let rows = if filter.is_empty() {
                        q.fetch_all(&self.pool).await
                    } else {
                        q.bind(user_id).fetch_all(&self.pool).await
                    }
                    .map_err(db_err)?;
                    let mut records = Vec::new();
                    for row in rows {
                        let mut obj = serde_json::Map::new();
                        for c in *cols {
                            let v: Option<String> = row.try_get(*c).map_err(db_err)?;
                            let mut value = match v {
                                None => serde_json::Value::Null,
                                Some(s) => {
                                    if ["body", "tags", "scopes", "recent_card_ids", "metadata", "application_provenance"].contains(c) {
                                        serde_json::from_str(&s).map_err(|_| CoreError::internal("invalid stored JSON"))?
                                    } else if [
                                        "amount",
                                        "rating",
                                        "next_slot",
                                        "reps",
                                        "lapses",
                                        "exposures",
                                        "last_rating",
                                        "stability",
                                        "difficulty",
                                        "expires_at",
                                        "revoked",
                                        "starred",
                                    ]
                                    .contains(c)
                                        && !s.contains(':')
                                    {
                                        serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s))
                                    } else if *c == "email" && s.starts_with("oidc:") {
                                        serde_json::Value::Null
                                    } else {
                                        serde_json::Value::String(s)
                                    }
                                }
                            };
                            if *table=="content_revisions" && *c=="body" {memoswish_core::assets::clear_historical_delivery_urls(&mut value);}
                            obj.insert(c.to_string(), value);
                        }
                        if *table == "auth_browser_sessions" {
                            let body = obj.remove("body").unwrap_or_default();
                            for field in ["auth_time", "auth_method"] {
                                if let Some(v) = body.get(field) {
                                    obj.insert(field.into(), v.clone());
                                }
                            }
                        }
                        if cols.len() == 1 && cols[0] == "body" {
                            records.push(obj.remove("body").unwrap());
                        } else {
                            records.push(serde_json::Value::Object(obj));
                        }
                    }
                    result.insert(table.to_string(), serde_json::Value::Array(records));
                }
                // 所有授权码和令牌只导出绑定元数据，消费状态取真实列而非 JSON 缓存。
                for (table, key) in [
                    ("oauth_tokens", "oauth_token_metadata"),
                    ("oauth_authorization_codes", "oauth_code_metadata"),
                ] {
                    let sql = format!(
                        "SELECT t.body,t.consumed FROM {table} t JOIN oauth_grants g ON g.id=t.grant_id AND g.tenant_id=t.tenant_id WHERE g.tenant_id=$1 AND ($2='' OR g.user_id=$2)"
                    );
                    let rows = sqlx::query(&sql)
                        .bind(tenant_id)
                        .bind(if owner { "" } else { user_id })
                        .fetch_all(&self.pool)
                        .await
                        .map_err(db_err)?;
                    let mut records = Vec::new();
                    for row in rows {
                        let b: serde_json::Value = serde_json::from_str(&row.get::<String, _>("body"))
                            .map_err(|_| CoreError::internal("invalid token metadata"))?;
                        let mut safe = serde_json::Map::new();
                        safe.insert("consumed".into(), serde_json::json!(row.get::<i64, _>("consumed") != 0));
                        for c in ["id", "client_id", "resource", "scopes"] {
                            if let Some(v) = b["grant"].get(c) {
                                safe.insert(if c == "id" { "grant_id".into() } else { c.into() }, v.clone());
                            }
                        }
                        for c in ["scopes", "kind", "expires_at", "redirect_uri"] {
                            if let Some(v) = b.get(c) {
                                safe.insert(c.into(), v.clone());
                            }
                        }
                        records.push(serde_json::Value::Object(safe));
                    }
                    result.insert(key.into(), serde_json::json!(records));
                }
                let rows=sqlx::query("SELECT r.body FROM oauth_authorization_requests r JOIN auth_browser_sessions b ON b.hash=r.browser_hash WHERE b.tenant_id=$1 AND ($2='' OR b.user_id=$2)")
                            .bind(tenant_id).bind(if owner {""}else{user_id}).fetch_all(&self.pool).await.map_err(db_err)?;
                let mut requests = Vec::new();
                for row in rows {
                    let body: serde_json::Value = serde_json::from_str(&row.get::<String, _>("body"))
                        .map_err(|_| CoreError::internal("invalid request metadata"))?;
                    let mut safe = serde_json::Map::new();
                    for c in ["client_id", "redirect_uri", "resource", "scopes", "expires_at"] {
                        if let Some(v) = body.get(c) {
                            safe.insert(c.into(), v.clone());
                        }
                    }
                    requests.push(serde_json::Value::Object(safe));
                }
                let rows=sqlx::query("SELECT s.issuer,s.subject,s.last_event_at,s.last_event_kind,s.email_forwarding FROM identity_status s JOIN federated_identities i ON i.issuer=s.issuer AND i.subject=s.subject WHERE i.tenant_id=$1 AND ($2='' OR i.user_id=$2)").bind(tenant_id).bind(if owner {""}else{user_id}).fetch_all(&self.pool).await.map_err(db_err)?;
                let statuses=rows.into_iter().map(|r|serde_json::json!({"issuer":r.get::<String,_>("issuer"),"subject":r.get::<String,_>("subject"),"last_event_at":r.get::<i64,_>("last_event_at"),"last_event_kind":r.get::<String,_>("last_event_kind"),"email_forwarding":r.get::<Option<String>,_>("email_forwarding")})).collect::<Vec<_>>();
                result.insert("identity_status".into(), serde_json::json!(statuses));
                result.insert("oauth_request_metadata".into(), serde_json::json!(requests));
                Ok(serde_json::Value::Object(result))
            }
            async fn account_erase(
                &self,
                tenant_id: &str,
                user_id: &str,
                owner: bool,
            ) -> CoreResult<memoswish_core::identity::ErasureJob> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                sqlx::query($erasure_lock).bind(tenant_id).fetch_optional(&mut *tx).await.map_err(db_err)?;
                let role: Option<String> = sqlx::query_scalar("SELECT role FROM user_profiles WHERE tenant_id=$1 AND id=$2")
                    .bind(tenant_id)
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_err)?;
                if role.as_deref().map(|r| r == "owner") != Some(owner) {
                    return Err(CoreError::Forbidden(
                        "account role changed or account no longer exists".into(),
                    ));
                }
                let creds=sqlx::query("SELECT body,credential FROM federated_identities WHERE tenant_id=$1 AND ($2='' OR user_id=$2) AND credential IS NOT NULL")
                            .bind(tenant_id).bind(if owner {""} else {user_id}).fetch_all(&mut *tx).await.map_err(db_err)?;
                let mut credentials = Vec::new();
                for row in creds {
                    let i: memoswish_core::identity::FederatedIdentity = serde_json::from_str(&row.get::<String, _>("body"))
                        .map_err(|_| CoreError::internal("invalid identity"))?;
                    credentials.push((i.provider, row.get("credential")));
                }
                let job = memoswish_core::identity::ErasureJob {
                    id: memoswish_core::ids::new_id(),
                    tenant_id: Some(tenant_id.into()),
                    purge_assets: owner,
                    credentials,
                };
                sqlx::query("INSERT INTO account_erasure_jobs(id,body) VALUES($1,$2)")
                    .bind(&job.id)
                    .bind(crate::oauth::encode(&job)?)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                if owner {
                    Self::speech_erase_tenant(&mut tx, tenant_id).await?;
                    Self::import_erase(&mut tx, tenant_id, None).await?;
                    Self::explanation_erase(&mut tx, tenant_id, None).await?;
                    sqlx::query("INSERT INTO erased_tenants(tenant_id) VALUES($1) ON CONFLICT DO NOTHING")
                        .bind(tenant_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    for table in [
                        "tts_submission_items",
                        "tts_submissions",
                        "asset_references",
                        "usage_counters",
                        "decks",
                        "cards",
                        "bgm_tracks",
                        "personal_favorites",
                        "favorite_operations",
                        "memory_states",
                        "feedback_events",
                        "feed_sessions",
                        "api_tokens",
                        "erased_users",
                    ] {
                        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id=$1"))
                            .bind(tenant_id)
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    }
                    sqlx::query("DELETE FROM users WHERE id IN (SELECT user_id FROM tenant_memberships WHERE tenant_id=$1)")
                        .bind(tenant_id).execute(&mut *tx).await.map_err(db_err)?;
                    sqlx::query("DELETE FROM tenants WHERE id=$1")
                        .bind(tenant_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                } else {
                    Self::speech_revoke_member(&mut tx, tenant_id, user_id).await?;
                    Self::import_erase(&mut tx, tenant_id, Some(user_id)).await?;
                    Self::explanation_erase(&mut tx, tenant_id, Some(user_id)).await?;
                    sqlx::query("INSERT INTO erased_users(tenant_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
                        .bind(tenant_id)
                        .bind(user_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    for table in ["tts_submission_items", "tts_submissions", "personal_favorites", "favorite_operations", "memory_states", "feedback_events", "feed_sessions", "api_tokens"] {
                        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id=$1 AND user_id=$2"))
                            .bind(tenant_id)
                            .bind(user_id)
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    }
                    sqlx::query("DELETE FROM users WHERE id=$2 AND EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2)")
                        .bind(tenant_id)
                        .bind(user_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                }
                tx.commit().await.map_err(db_err)?;
                Ok(job)
            }
            async fn account_erasure_jobs(&self) -> CoreResult<Vec<memoswish_core::identity::ErasureJob>> {
                let rows: Vec<String> = sqlx::query_scalar("SELECT body FROM account_erasure_jobs WHERE progress<>'complete' ORDER BY id")
                    .fetch_all(&self.pool)
                    .await
                    .map_err(db_err)?;
                rows.into_iter()
                    .map(|b| serde_json::from_str(&b).map_err(|_| CoreError::internal("invalid erasure job")))
                    .collect()
            }
            async fn account_erasure_finish(&self, _id: &str) -> CoreResult<()> {
                Err(CoreError::Conflict("erasure completion requires a current job claim and external receipts".into()))
            }
            async fn account_erased_tenant(&self, tenant_id: &str) -> CoreResult<bool> {
                let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM erased_tenants WHERE tenant_id=$1")
                    .bind(tenant_id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(db_err)?;
                Ok(n != 0)
            }
        }
        impl $repo {
            // 调用者已持有注册锁；创建、暂存和完成统一重验原始关联凭据。
            async fn identity_link_authorize_tx(
                tx: &mut sqlx::Transaction<'_, $db>,
                attempt: &memoswish_core::identity::LoginAttempt,
                now: i64,
            ) -> CoreResult<()> {
                if let Some(user)=&attempt.link_user {
                    // 注册锁串行化资格更新与关联的创建、暂存及最终提交；登录不走此分支。
                    let tenant=attempt.link_tenant.as_deref().ok_or_else(||CoreError::Unauthorized("missing link workspace".into()))?;
                    Self::privacy_collection_tx(tx,tenant,user).await?;
                    if let Some(hash)=&attempt.link_access_hash {
                        let (a,used)=Self::session_read(tx,hash,false).await?;
                        if used {return Err(CoreError::Unauthorized("original session was retired".into()));}
                        Self::session_validate(tx,&a,now).await?;
                    } else {
                        let iat=attempt.link_legacy_issued_at.ok_or_else(||CoreError::Unauthorized("missing legacy link authorization".into()))?;
                        let fenced:i64=sqlx::query_scalar("SELECT COUNT(*) FROM app_session_fences WHERE user_id=$1 AND revoked_through>=$2")
                            .bind(user).bind(iat).fetch_one(&mut **tx).await.map_err(db_err)?;
                        if fenced!=0 {return Err(CoreError::Unauthorized("legacy app session was revoked".into()));}
                    }
                }
                Ok(())
            }
            #[allow(clippy::too_many_arguments)]
            async fn complete_identity(
                &self,
                attempt_id: &str,
                tenant_id: &str,
                user_id: &str,
                generation: i64,
                session_hash: &str,
                now: i64,
                workspace: Option<memoswish_core::CredentialGenerations>,
            ) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx).await.map_err(db_err)?;
                let now=Self::session_clock(&mut tx).await?.max(now);
                Self::complete_identity_tx(&mut tx,attempt_id,tenant_id,user_id,generation,session_hash,now,workspace,true).await?;
                tx.commit().await.map_err(db_err)
            }
            #[allow(clippy::too_many_arguments)]
            pub(crate) async fn complete_identity_tx(
                tx: &mut sqlx::Transaction<'_, $db>,
                attempt_id:&str,tenant_id:&str,user_id:&str,generation:i64,session_hash:&str,now:i64,
                workspace:Option<memoswish_core::CredentialGenerations>, record_recent: bool,
            )->CoreResult<()> {
                let pending=sqlx::query("SELECT pending_link,body FROM oidc_attempts WHERE id=$1 AND phase=2 AND expires_at>$2")
                    .bind(attempt_id).bind(now).fetch_optional(&mut **tx).await.map_err(db_err)?
                    .ok_or_else(||CoreError::Unauthorized("identity transaction expired".into()))?;
                let attempt:memoswish_core::identity::LoginAttempt=serde_json::from_str(&pending.get::<String,_>("body")).map_err(CoreError::internal)?;
                Self::identity_link_authorize_tx(tx,&attempt,now).await?;
                if let Some(body)=pending.get::<Option<String>,_>("pending_link") {
                    let (identity,credential):(memoswish_core::identity::FederatedIdentity,Option<String>)=serde_json::from_str(&body).map_err(CoreError::internal)?;
                    if identity.user_id!=user_id || identity.tenant_id!=tenant_id {return Err(CoreError::Unauthorized("invalid pending identity".into()));}
                    let existing:Option<String>=sqlx::query_scalar("SELECT user_id FROM federated_identities WHERE issuer=$1 AND subject=$2").bind(&identity.issuer).bind(&identity.subject).fetch_optional(&mut **tx).await.map_err(db_err)?;
                    if existing.as_deref().is_some_and(|u|u!=user_id) {return Err(CoreError::Conflict("identity is already linked".into()));}
                    let revoked:i64=sqlx::query_scalar("SELECT COUNT(*) FROM identity_status WHERE issuer=$1 AND subject=$2 AND (permanently_deleted<>0 OR revoked_before>=$3)")
                        .bind(&identity.issuer).bind(&identity.subject).bind(identity.authenticated_at).fetch_one(&mut **tx).await.map_err(db_err)?;
                    if revoked!=0 {return Err(CoreError::Unauthorized("upstream identity is revoked".into()));}
                    sqlx::query("INSERT INTO federated_identities(issuer,subject,tenant_id,user_id,body,credential) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(issuer,subject) DO UPDATE SET body=excluded.body,credential=COALESCE(excluded.credential,federated_identities.credential)")
                        .bind(&identity.issuer).bind(&identity.subject).bind(tenant_id).bind(user_id).bind(crate::oauth::encode(&identity)?).bind(credential).execute(&mut **tx).await.map_err(db_err)?;
                }
                if let Some(generations) = workspace {
                    Self::authorize_tx(tx, tenant_id, user_id, generations).await?;
                }
                let row = sqlx::query(
                    "SELECT a.identity_issuer,a.identity_subject,a.sequence,a.body
                     FROM oidc_attempts a
                     JOIN federated_identities i
                       ON i.issuer=a.identity_issuer AND i.subject=a.identity_subject
                      AND i.tenant_id=a.tenant_id AND i.user_id=a.user_id
                     JOIN users u ON u.id=a.user_id
                     WHERE a.id=$1 AND a.tenant_id=$2 AND a.user_id=$3
                       AND a.phase=2 AND a.expires_at>$4
                       AND (SELECT generation FROM account_auth_epochs WHERE user_id=$3)=$5
                       AND ($6 IS NULL OR a.membership_generation=$6)"
                )
                    .bind(attempt_id)
                    .bind(tenant_id)
                    .bind(user_id)
                    .bind(now)
                    .bind(generation)
                    .bind(workspace.map(|g| g.membership))
                    .fetch_optional(&mut **tx)
                    .await.map_err(db_err)?
                    .ok_or_else(|| CoreError::Unauthorized("identity is no longer linked to this account".into()))?;
                // 账户完成也必须保留显式关联原会话的工作区撤销边界。
                let attempt: memoswish_core::identity::LoginAttempt =
                    serde_json::from_str(&row.get::<String, _>("body")).map_err(CoreError::internal)?;
                if let Some(user) = &attempt.link_user {
                    let account =
                        attempt.link_generation.ok_or_else(|| CoreError::Unauthorized("missing link authorization".into()))?;
                    let membership = attempt
                        .link_membership_generation
                        .ok_or_else(|| CoreError::Unauthorized("missing link authorization".into()))?;
                    let tenant = attempt
                        .link_tenant
                        .as_deref()
                        .ok_or_else(|| CoreError::Unauthorized("missing link authorization".into()))?;
                    if user != user_id || tenant != tenant_id || account != generation {
                        return Err(CoreError::Unauthorized("link authorization does not match the original session".into()));
                    }
                    Self::authorize_tx(tx, tenant, user, memoswish_core::CredentialGenerations { account, membership }).await?;
                }
                let identity_hash = memoswish_core::ids::sha256_hex(
                    format!("{}\0{}", row.get::<String,_>("identity_issuer"), row.get::<String,_>("identity_subject")).as_bytes()
                );
                let fenced: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM identity_unlink_fences WHERE identity_hash=$1 AND sequence>=$2"
                )
                    .bind(identity_hash)
                    .bind(row.get::<i64,_>("sequence"))
                    .fetch_one(&mut **tx).await.map_err(db_err)?;
                if fenced != 0 {
                    return Err(CoreError::Unauthorized("identity transaction was invalidated".into()));
                }
                sqlx::query("UPDATE oidc_attempts SET phase=3 WHERE id=$1")
                    .bind(attempt_id).execute(&mut **tx).await.map_err(db_err)?;
                if record_recent {
                sqlx::query("INSERT INTO recent_authentication(hash,tenant_id,user_id,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(hash) DO NOTHING")
                    .bind(session_hash)
                    .bind(tenant_id)
                    .bind(user_id)
                    .bind(now+300)
                    .execute(&mut **tx).await.map_err(db_err)?;
                }
                Ok(())
            }
        }
    };
}

pub(crate) fn rekey_revocation(
    value: &str,
    transform: &memoswish_core::identity::CipherTransform,
) -> memoswish_core::CoreResult<String> {
    let (aad, cipher) =
        value.split_once('\n').ok_or_else(|| memoswish_core::CoreError::internal("invalid revocation envelope"))?;
    Ok(format!("{aad}\n{}", transform(cipher, aad)?))
}
pub(crate) fn rekey_body(
    table: &str,
    body: &str,
    transform: &memoswish_core::identity::CipherTransform,
) -> memoswish_core::CoreResult<String> {
    use memoswish_core::{CoreError, identity::*};
    match table {
        "oidc_attempts" => {
            let mut a: LoginAttempt = serde_json::from_str(body).map_err(CoreError::internal)?;
            a.verifier_ciphertext = transform(&a.verifier_ciphertext, &a.id)?;
            crate::oauth::encode(&a)
        }
        "oidc_handoffs" => {
            let mut h: LoginHandoff = serde_json::from_str(body).map_err(CoreError::internal)?;
            h.pending_identity = h.pending_identity.map(|p| transform(&p, "pending-link")).transpose()?;
            crate::oauth::encode(&h)
        }
        "account_erasure_jobs" => {
            let mut j: ErasureJob = serde_json::from_str(body).map_err(CoreError::internal)?;
            for (_, cipher) in &mut j.credentials {
                if !cipher.is_empty() {
                    *cipher = rekey_revocation(cipher, transform)?;
                }
            }
            crate::oauth::encode(&j)
        }
        _ => Err(CoreError::internal("invalid ciphertext table")),
    }
}
