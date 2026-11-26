//! 两个 SQL 后端共享 OAuth 事务；只使用两端一致支持的语句与绑定参数。
// 权限字符串复用核心矩阵，未知 scope 在事务边界拒绝。
pub(crate) fn role_allows_scopes(role: memoswish_core::Role, scopes: &[String]) -> bool {
    use memoswish_core::Permission::*;
    let permissions = [
        AccountExport,
        FeedRead,
        FeedbackWrite,
        ContentRead,
        ContentWrite,
        MediaRead,
        MediaWrite,
        TtsGenerate,
        TokenManage,
        MemberManage,
        BillingManage,
    ];
    scopes.iter().all(|s| permissions.iter().any(|p| s == p.as_scope() && role.allows(*p)))
}

pub(crate) fn encode<T: serde::Serialize>(value: &T) -> memoswish_core::CoreResult<String> {
    serde_json::to_string(value).map_err(|e| memoswish_core::CoreError::internal(e.to_string()))
}
pub(crate) fn decode<T: serde::de::DeserializeOwned>(value: Option<String>) -> memoswish_core::CoreResult<Option<T>> {
    value.map(|s| serde_json::from_str(&s)).transpose().map_err(|e| memoswish_core::CoreError::internal(e.to_string()))
}

macro_rules! oauth_impl {
    ($repo:ty) => {
        #[async_trait::async_trait]
        impl memoswish_core::oauth::OAuthIndex for $repo {
            async fn oauth_client(&self, id: &str) -> CoreResult<Option<memoswish_core::oauth::OAuthClient>> {
                crate::oauth::decode(
                    sqlx::query_scalar("SELECT body FROM oauth_clients WHERE id=$1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(db_err)?,
                )
            }
            async fn oauth_register(&self, c: &memoswish_core::oauth::OAuthClient) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_err)?;
                if count >= 10000 {
                    return Err(CoreError::QuotaExceeded("client registry capacity reached".into()));
                }
                sqlx::query("INSERT INTO oauth_clients(id,expires_at,body) VALUES($1,$2,$3)")
                    .bind(&c.id)
                    .bind(c.expires_at)
                    .bind(crate::oauth::encode(c)?)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                tx.commit().await.map_err(db_err)
            }
            async fn oauth_browser(&self, hash: &str) -> CoreResult<Option<memoswish_core::oauth::BrowserSession>> {
                crate::oauth::decode(
                    sqlx::query_scalar("SELECT body FROM auth_browser_sessions WHERE hash=$1")
                        .bind(hash)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(db_err)?,
                )
            }
            async fn oauth_request(&self, id: &str) -> CoreResult<Option<memoswish_core::oauth::AuthorizationRequest>> {
                crate::oauth::decode(
                    sqlx::query_scalar("SELECT body FROM oauth_authorization_requests WHERE id=$1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(db_err)?,
                )
            }
            async fn oauth_begin(
                &self,
                s: &memoswish_core::oauth::BrowserSession,
                r: &memoswish_core::oauth::AuthorizationRequest,
            ) -> CoreResult<()> {
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_browser_sessions")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_err)?;
                if count >= 10000 {
                    return Err(CoreError::QuotaExceeded("browser session capacity reached".into()));
                }
                sqlx::query("INSERT INTO auth_browser_sessions(hash,tenant_id,user_id,expires_at,body) VALUES($1,$2,$3,$4,$5)")
                    .bind(&s.hash)
                    .bind(&s.tenant_id)
                    .bind(&s.user_id)
                    .bind(s.expires_at)
                    .bind(crate::oauth::encode(s)?)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                sqlx::query("INSERT INTO oauth_authorization_requests(id,browser_hash,client_id,expires_at,body) VALUES($1,$2,$3,$4,$5)")
                            .bind(&r.id).bind(&r.browser_hash).bind(&r.client_id).bind(r.expires_at).bind(crate::oauth::encode(r)?).execute(&mut *tx).await.map_err(db_err)?;
                tx.commit().await.map_err(db_err)
            }
            async fn oauth_code(&self, hash: &str) -> CoreResult<Option<memoswish_core::oauth::AuthorizationCode>> {
                crate::oauth::decode(sqlx::query_scalar("SELECT c.body FROM oauth_authorization_codes c JOIN oauth_grants g ON g.id=c.grant_id AND g.tenant_id=c.tenant_id WHERE c.hash=$1 AND g.revoked=0")
                            .bind(hash).fetch_optional(&self.pool).await.map_err(db_err)?)
            }
            async fn oauth_token(&self, hash: &str) -> CoreResult<Option<memoswish_core::oauth::OAuthToken>> {
                crate::oauth::decode(sqlx::query_scalar("SELECT t.body FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id AND g.tenant_id=t.tenant_id WHERE t.hash=$1 AND g.revoked=0")
                            .bind(hash).fetch_optional(&self.pool).await.map_err(db_err)?)
            }
            async fn oauth_cleanup(&self, now: i64) -> CoreResult<()> {
        use memoswish_core::observability::{Operation,Outcome};
        let mut observation=self.observer.start(Operation::Retention);
        let result: CoreResult<_> = async {
                let mut tx = self.pool.begin().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })?;
                for expiry in crate::recovery::OAUTH_EXPIRY {
                    let sql=format!("DELETE FROM {} WHERE {}",expiry.table,expiry.predicate("$1"));
                    sqlx::query(&sql).bind(now).execute(&mut *tx).await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })?;
                }
                tx.commit().await.map_err(|error| { observation.finish(crate::operational_metrics::classify(&error)); db_err(error) })

        }.await;
        observation.finish(if result.is_ok() {Outcome::Returned} else {Outcome::Error});
        result
    }
        }
        #[async_trait::async_trait]
        impl memoswish_core::oauth::OAuthRepo for $repo {
            async fn oauth_login(
                &self,
                tenant_id: &str,
                r: &memoswish_core::oauth::AuthorizationRequest,
                s: &memoswish_core::oauth::BrowserSession,
                now: i64,
            ) -> CoreResult<bool> {
                if s.tenant_id.as_deref() != Some(tenant_id) || s.user_id.is_none() {
                    return Ok(false);
                }
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_err)?;
                Self::authorize_tx(&mut tx,tenant_id,s.user_id.as_deref().unwrap(),s.generations.ok_or_else(||CoreError::Unauthorized("missing browser credential generations".into()))?).await?;
                // 注册锁先取得 SQLite 写锁，避免延迟事务的读后升级竞争。
                let mut next = r.clone();
                next.browser_hash = s.hash.clone();
                sqlx::query("INSERT INTO auth_browser_sessions(hash,tenant_id,user_id,expires_at,body) VALUES($1,$2,$3,$4,$5)")
                    .bind(&s.hash)
                    .bind(tenant_id)
                    .bind(&s.user_id)
                    .bind(s.expires_at)
                    .bind(crate::oauth::encode(s)?)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                let n = sqlx::query("UPDATE oauth_authorization_requests SET browser_hash=$1,body=$2 WHERE id=$3 AND browser_hash=$4 AND expires_at>$5 AND EXISTS(SELECT 1 FROM auth_browser_sessions WHERE hash=$4 AND tenant_id IS NULL AND expires_at>$5)")
                            .bind(&s.hash).bind(crate::oauth::encode(&next)?).bind(&r.id).bind(&r.browser_hash).bind(now).execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                if n != 1 {
                    return Ok(false);
                }
                sqlx::query("DELETE FROM auth_browser_sessions WHERE hash=$1")
                    .bind(&r.browser_hash)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                tx.commit().await.map_err(db_err)?;
                Ok(true)
            }
            async fn oauth_consent(
                &self,
                tenant_id: &str,
                r: &memoswish_core::oauth::AuthorizationRequest,
                c: Option<&memoswish_core::oauth::AuthorizationCode>,
                now: i64,
            ) -> CoreResult<bool> {
                if c.is_some_and(|c| {
                    c.grant.tenant_id != tenant_id
                        || c.grant.client_id != r.client_id
                        || c.grant.resource != r.resource
                        || c.grant.scopes != r.scopes
                        || c.challenge != r.challenge
                        || c.redirect_uri != r.redirect_uri
                }) {
                    return Ok(false);
                }
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_err)?;
                let browser_body:Option<String>=sqlx::query_scalar("SELECT body FROM auth_browser_sessions WHERE hash=$1 AND tenant_id=$2")
                    .bind(&r.browser_hash).bind(tenant_id).fetch_optional(&mut *tx).await.map_err(db_err)?;
                let Some(browser)=crate::oauth::decode::<memoswish_core::oauth::BrowserSession>(browser_body)? else {return Ok(false)};
                let Some(user)=browser.user_id.as_deref() else {return Ok(false)};
                let generations=browser.generations.ok_or_else(||CoreError::Unauthorized("missing browser credential generations".into()))?;
                let role=Self::authorize_tx(&mut tx,tenant_id,user,generations).await?;
                if c.is_some_and(|c|c.grant.generations!=generations || c.grant.user_id!=user || !crate::oauth::role_allows_scopes(role,&c.grant.scopes)) {return Ok(false);}
                let n = sqlx::query("DELETE FROM oauth_authorization_requests WHERE id=$1 AND browser_hash=$2 AND expires_at>$3 AND EXISTS(SELECT 1 FROM auth_browser_sessions s WHERE s.hash=$2 AND s.tenant_id=$4 AND s.expires_at>$3 AND ($5='' OR s.user_id=$5))")
                            .bind(&r.id).bind(&r.browser_hash).bind(now).bind(tenant_id).bind(c.map(|c| c.grant.user_id.as_str()).unwrap_or("")).execute(&mut *tx).await.map_err(db_err)?.rows_affected();
                if n != 1 {
                    return Ok(false);
                }
                if let Some(c) = c {
                    let g = &c.grant;
                    sqlx::query("INSERT INTO oauth_grants(id,tenant_id,user_id,client_id,expires_at,metadata) VALUES($1,$2,$3,$4,$5,$6)")
                        .bind(&g.id)
                        .bind(tenant_id)
                        .bind(&g.user_id)
                        .bind(&g.client_id)
                        .bind(g.expires_at)
                        .bind(crate::oauth::encode(&c.grant)?)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    sqlx::query(
                        "INSERT INTO oauth_authorization_codes(hash,tenant_id,grant_id,expires_at,body) VALUES($1,$2,$3,$4,$5)",
                    )
                    .bind(&c.hash)
                    .bind(tenant_id)
                    .bind(&g.id)
                    .bind(c.expires_at)
                    .bind(crate::oauth::encode(c)?)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                }
                tx.commit().await.map_err(db_err)?;
                Ok(true)
            }
            async fn oauth_redeem(
                &self,
                tenant_id: &str,
                c: &memoswish_core::oauth::AuthorizationCode,
                tokens: &[memoswish_core::oauth::OAuthToken],
                now: i64,
            ) -> CoreResult<bool> {
                self.oauth_exchange(tenant_id, &c.grant, &c.hash, false, tokens, now)
                    .await
            }
            async fn oauth_rotate(
                &self,
                tenant_id: &str,
                p: &memoswish_core::oauth::OAuthToken,
                tokens: &[memoswish_core::oauth::OAuthToken],
                now: i64,
            ) -> CoreResult<bool> {
                self.oauth_exchange(tenant_id, &p.grant, &p.hash, true, tokens, now)
                    .await
            }
            async fn oauth_revoke(&self, tenant_id: &str, id: &str) -> CoreResult<()> {
                sqlx::query("UPDATE oauth_grants SET revoked=1 WHERE tenant_id=$1 AND id=$2")
                    .bind(tenant_id)
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    .map_err(db_err)?;
                Ok(())
            }
        }
        impl $repo {
            async fn oauth_exchange(
                &self,
                tenant_id: &str,
                g: &memoswish_core::oauth::OAuthGrant,
                parent: &str,
                refresh: bool,
                tokens: &[memoswish_core::oauth::OAuthToken],
                now: i64,
            ) -> CoreResult<bool> {
                if g.tenant_id != tenant_id
                    || tokens.is_empty()
                    || tokens.iter().any(|t| t.grant != *g || t.expires_at > g.expires_at)
                {
                    return Ok(false);
                }
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.map_err(db_err)?;
                let role=Self::authorize_tx(&mut tx,tenant_id,&g.user_id,g.generations).await?;
                if tokens.iter().any(|t|t.kind=="access" && !crate::oauth::role_allows_scopes(role,&t.scopes)) {return Ok(false);}
                let stored:Option<String>=sqlx::query_scalar("SELECT metadata FROM oauth_grants WHERE tenant_id=$1 AND id=$2")
                    .bind(tenant_id).bind(&g.id).fetch_optional(&mut *tx).await.map_err(db_err)?;
                if crate::oauth::decode::<memoswish_core::oauth::OAuthGrant>(stored)?.as_ref()!=Some(g) {return Ok(false);}
                let n = sqlx::query(
                    "UPDATE oauth_grants SET revoked=revoked WHERE tenant_id=$1 AND id=$2 AND revoked=0 AND expires_at>$3",
                )
                .bind(tenant_id)
                .bind(&g.id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected();
                if n != 1 {
                    return Ok(false);
                }
                let sql = if refresh {
                    "UPDATE oauth_tokens SET consumed=1 WHERE tenant_id=$1 AND grant_id=$2 AND hash=$3 AND kind='refresh' AND consumed=0 AND expires_at>$4"
                } else {
                    "UPDATE oauth_authorization_codes SET consumed=1 WHERE tenant_id=$1 AND grant_id=$2 AND hash=$3 AND consumed=0 AND expires_at>$4"
                };
                let n = sqlx::query(sql)
                    .bind(tenant_id)
                    .bind(&g.id)
                    .bind(parent)
                    .bind(now)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?
                    .rows_affected();
                if n != 1 {
                    // 只对已消费的真实父凭据撤销；不存在或过期的凭据不会误伤家族。
                    let sql = if refresh {
                        "SELECT COUNT(*) FROM oauth_tokens WHERE tenant_id=$1 AND grant_id=$2 AND hash=$3 AND consumed=1"
                    } else {
                        "SELECT COUNT(*) FROM oauth_authorization_codes WHERE tenant_id=$1 AND grant_id=$2 AND hash=$3 AND consumed=1"
                    };
                    let used: i64 = sqlx::query_scalar(sql)
                        .bind(tenant_id)
                        .bind(&g.id)
                        .bind(parent)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    if used == 1 {
                        sqlx::query("UPDATE oauth_grants SET revoked=1 WHERE tenant_id=$1 AND id=$2")
                            .bind(tenant_id)
                            .bind(&g.id)
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    }
                    tx.commit().await.map_err(db_err)?;
                    return Ok(false);
                }
                for t in tokens {
                    sqlx::query(
                        "INSERT INTO oauth_tokens(hash,tenant_id,grant_id,kind,expires_at,body) VALUES($1,$2,$3,$4,$5,$6)",
                    )
                    .bind(&t.hash)
                    .bind(tenant_id)
                    .bind(&g.id)
                    .bind(&t.kind)
                    .bind(t.expires_at)
                    .bind(crate::oauth::encode(t)?)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                }
                tx.commit().await.map_err(db_err)?;
                Ok(true)
            }
        }
    };
}
