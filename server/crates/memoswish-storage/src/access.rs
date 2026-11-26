//! 账户本人摘要与撤销复用注册锁，和刷新、兑换、CP2 安全世代转换串行。
pub(crate) fn validate_page(after: &str, limit: u32) -> memoswish_core::CoreResult<()> {
    if !(1..=100).contains(&limit)
        || after.len() > 128
        || !after.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(memoswish_core::CoreError::invalid("invalid access page"));
    }
    Ok(())
}
pub(crate) fn status(revoked: bool, expired: bool, stale: bool) -> String {
    if revoked {
        "revoked"
    } else if expired {
        "expired"
    } else if stale {
        "inactive"
    } else {
        "active"
    }
    .into()
}
macro_rules! access_impl {
    ($repo:ty, $db:ty) => {
        impl $repo {
            pub(crate) async fn access_page_impl(&self, hash: &str, kind: memoswish_core::session::AccessKind, after: &str, limit: u32) -> CoreResult<memoswish_protocol::AccessPage> {
                use memoswish_core::session::AccessKind;
                use memoswish_protocol::AccessSummary;
                crate::access::validate_page(after, limit)?;
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let now = Self::session_lock(&mut tx).await?;
                let a = Self::session_account_access(&mut tx, hash, now).await?;
                let mut items = Vec::new();
                match kind {
                    AccessKind::Sessions => {
                        let rows = sqlx::query("SELECT id,generation,provenance,auth_time,expires_at,revoked FROM app_sessions WHERE user_id=$1 AND id>$2 ORDER BY id LIMIT $3")
                            .bind(&a.family.user_id).bind(after).bind(i64::from(limit)+1).fetch_all(&mut *tx).await.map_err(db_err)?;
                        for r in rows {
                            let id: String = r.get("id");
                            let expiry: i64 = r.get("expires_at");
                            items.push(AccessSummary {
                                current: Some(id==a.family.id), id, kind:kind.as_str().into(),
                                status: crate::access::status(r.get::<i64,_>("revoked")!=0, expiry<=now, r.get::<i64,_>("generation")!=a.family.generation),
                                tenant_id:None, label:Some(r.get("provenance")), scopes:None, scopes_limited:None, expires_at:Some(expiry), auth_time:Some(r.get("auth_time")),
                            });
                        }
                    }
                    AccessKind::ApiTokens => {
                        let token_now = Self::asset_now(&mut tx).await?;
                        // 不读取 token_hash；准入只核验撤销、过期、成员存在及捕获世代，权限另取交集。
                        let rows = sqlx::query("SELECT t.id,t.tenant_id,t.name,CAST(t.scopes AS TEXT) AS scopes,t.expires_at,CASE WHEN t.revoked THEN CAST(1 AS BIGINT) ELSE CAST(0 AS BIGINT) END AS revoked,t.account_generation,t.membership_generation,m.generation,m.role FROM api_tokens t LEFT JOIN tenant_memberships m ON m.tenant_id=t.tenant_id AND m.user_id=t.user_id WHERE t.user_id=$1 AND t.id>$2 ORDER BY t.id LIMIT $3")
                            .bind(&a.family.user_id).bind(after).bind(i64::from(limit)+1).fetch_all(&mut *tx).await.map_err(db_err)?;
                        for r in rows {
                            let scopes:Vec<String> = serde_json::from_str(&r.get::<String,_>("scopes")).map_err(|_|CoreError::internal("invalid stored token scopes"))?;
                            let role = r.get::<Option<String>,_>("role").and_then(|s| memoswish_core::Role::parse(&s).ok());
                            let stale = r.get::<i64,_>("account_generation")!=a.family.generation
                                || Some(r.get::<i64,_>("membership_generation"))!=r.get::<Option<i64>,_>("generation")
                                || role.is_none();
                            let projection = memoswish_core::Principal {
                                role: role.unwrap_or(memoswish_core::Role::Learner), scopes:Some(scopes.clone()),
                                ..memoswish_core::Principal::local_owner("api_token")
                            };
                            let effective:Vec<String> = memoswish_core::Permission::ALL.into_iter()
                                .filter(|p|role.is_some() && projection.can(*p)).map(|p|p.as_scope().into()).collect();
                            let limited = scopes.iter().any(|s| s!="*" && !effective.contains(s)) || role.is_none();
                            let expiry:Option<chrono::DateTime<chrono::Utc>> = r.get("expires_at");
                            items.push(AccessSummary {
                                id:r.get("id"), kind:kind.as_str().into(), status:crate::access::status(r.get::<i64,_>("revoked")!=0,expiry.is_some_and(|t|t.timestamp_millis()<=token_now),stale),
                                tenant_id:Some(r.get("tenant_id")),label:Some(r.get("name")),scopes:Some(effective),scopes_limited:Some(limited),expires_at:expiry.map(|t|t.timestamp()),auth_time:None,current:None,
                            });
                        }
                    }
                    AccessKind::Grants => {
                        // 授权摘要不读取授权码、access/refresh 哈希或客户端密钥。
                        let rows = sqlx::query("SELECT g.id,g.tenant_id,g.client_id,CAST(g.metadata AS TEXT) AS metadata,g.expires_at,g.revoked,m.generation,m.role,c.expires_at AS client_expiry FROM oauth_grants g LEFT JOIN tenant_memberships m ON m.tenant_id=g.tenant_id AND m.user_id=g.user_id LEFT JOIN oauth_clients c ON c.id=g.client_id WHERE g.user_id=$1 AND g.id>$2 ORDER BY g.id LIMIT $3")
                            .bind(&a.family.user_id).bind(after).bind(i64::from(limit)+1).fetch_all(&mut *tx).await.map_err(db_err)?;
                        for r in rows {
                            let grant:memoswish_core::oauth::OAuthGrant = serde_json::from_str(&r.get::<String,_>("metadata")).map_err(|_|CoreError::internal("invalid stored grant metadata"))?;
                            let role = r.get::<Option<String>,_>("role").and_then(|s|memoswish_core::Role::parse(&s).ok());
                            let expiry:i64 = r.get("expires_at");
                            let stale = grant.generations.account!=a.family.generation
                                || Some(grant.generations.membership)!=r.get::<Option<i64>,_>("generation")
                                || !role.is_some_and(|role|crate::oauth::role_allows_scopes(role,&grant.scopes));
                            let client_expiry:Option<i64> = r.get("client_expiry");
                            items.push(AccessSummary {
                                id:r.get("id"),kind:kind.as_str().into(),status:crate::access::status(r.get::<i64,_>("revoked")!=0,expiry<=now || client_expiry.is_none_or(|t|t<=now),stale),
                                tenant_id:Some(r.get("tenant_id")),label:Some(r.get("client_id")),scopes:Some(grant.scopes),scopes_limited:None,expires_at:Some(expiry),auth_time:None,current:None,
                            });
                        }
                    }
                }
                let more = items.len()>limit as usize;
                items.truncate(limit as usize);
                let next_cursor = if more {items.last().map(|r|r.id.clone())} else {None};
                tx.commit().await.map_err(db_err)?;
                Ok(memoswish_protocol::AccessPage {items,next_cursor})
            }
            pub(crate) async fn access_revoke_impl(&self, hash: &str, kind: memoswish_core::session::AccessKind, tenant: Option<&str>, id: &str) -> CoreResult<bool> {
                use memoswish_core::session::AccessKind;
                if (kind==AccessKind::Sessions) != tenant.is_none() || tenant.is_some_and(str::is_empty) || id.is_empty() {
                    return Err(CoreError::invalid("invalid access revocation target"));
                }
                let mut tx = self.pool.begin().await.map_err(db_err)?;
                let now = Self::session_lock(&mut tx).await?;
                let a = Self::session_account_access(&mut tx,hash,now).await?;
                // 不推进账户世代；同族的所有工作区凭据随会话撤销而失效。
                let n = match kind {
                    AccessKind::Sessions => sqlx::query("UPDATE app_sessions SET revoked=1 WHERE user_id=$1 AND id=$2")
                        .bind(&a.family.user_id).bind(id).execute(&mut *tx).await.map_err(db_err)?.rows_affected(),
                    AccessKind::ApiTokens => sqlx::query("UPDATE api_tokens SET revoked=TRUE WHERE user_id=$1 AND id=$2 AND tenant_id=$3")
                        .bind(&a.family.user_id).bind(id).bind(tenant).execute(&mut *tx).await.map_err(db_err)?.rows_affected(),
                    AccessKind::Grants => sqlx::query("UPDATE oauth_grants SET revoked=1 WHERE user_id=$1 AND id=$2 AND tenant_id=$3")
                        .bind(&a.family.user_id).bind(id).bind(tenant).execute(&mut *tx).await.map_err(db_err)?.rows_affected(),
                };
                self.session_commit(tx).await?;
                Ok(n==1)
            }
        }
    };
}
pub(crate) use access_impl;
