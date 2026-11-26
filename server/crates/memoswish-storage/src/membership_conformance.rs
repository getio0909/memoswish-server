//! S4 双数据库共用成员世代、签发边界与迁移回归。
macro_rules! membership_tests {
    ($repo:ident, $pool:ty, $migrations:literal) => {

        use memoswish_core::{CredentialGenerations, oauth::*};

        async fn membership_suite(repo: &$repo) {
            let tenant = TenantRecord {
                id: memoswish_core::ids::new_id(),
                name: "S4".into(),
                plan: "free".into(),
                created_at: chrono::Utc::now(),
            };
            let other = TenantRecord {
                id: memoswish_core::ids::new_id(),
                ..tenant.clone()
            };
            repo.upsert_tenant(&tenant).await.unwrap();
            repo.upsert_tenant(&other).await.unwrap();
            let user = UserRecord {
                id: memoswish_core::ids::new_id(),
                tenant_id: tenant.id.clone(),
                email: format!("{}@example.com", memoswish_core::ids::new_id()),
                display_name: "S4".into(),
                password_hash: "not-exported".into(),
                role: Role::Owner,
                created_at: chrono::Utc::now(),
            };
            repo.insert_user(&user).await.unwrap();
            assert_eq!(
                repo.membership_join(&other.id, &user.id, Role::Learner).await.unwrap(),
                0
            );
            let old = CredentialGenerations {
                account: 0,
                membership: 0,
            };
            assert_eq!(
                repo.membership_authorize(&tenant.id, &user.id, old).await.unwrap(),
                Role::Owner
            );
            assert_eq!(
                repo.membership_authorize(&other.id, &user.id, old).await.unwrap(),
                Role::Learner
            );
            let api = ApiTokenRecord {
                id: memoswish_core::ids::new_id(),
                tenant_id: tenant.id.clone(),
                user_id: user.id.clone(),
                name: "S4".into(),
                token_hash: memoswish_core::ids::new_id(),
                generations: old,
                scopes: vec!["content:read".into()],
                created_at: chrono::Utc::now(),
                expires_at: None,
                last_used_at: None,
                revoked: false,
            };
            repo.issue_api_token(&api).await.unwrap();
            let client = OAuthClient {
                id: memoswish_core::ids::new_id(),
                name: "S4".into(),
                redirect_uris: vec!["https://client.example/callback".into()],
                grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                scopes: vec!["content:read".into()],
                auth_method: "none".into(),
                secret_hash: None,
                created_at: 0,
                expires_at: i64::MAX,
            };
            repo.oauth_register(&client).await.unwrap();
            let code = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 1).await;
            let parent = crate::oauth_conformance::token(&code, "refresh");
            let access = crate::oauth_conformance::token(&code, "access");
            repo.oauth_redeem(&tenant.id, &code, &[parent.clone(), access.clone()], 10)
                .await
                .unwrap();
            let pending = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 1).await;
            assert!(repo.account_close_empty(&user.id, 0).await.is_err());
            assert!(repo.membership_remove(&tenant.id, &user.id).await.unwrap());
            assert!(!repo.membership_remove(&tenant.id, &user.id).await.unwrap());
            assert!(repo.membership_authorize(&tenant.id, &user.id, old).await.is_err());
            assert!(repo.membership_authorize(&other.id, &user.id, old).await.is_ok());
            assert_eq!(repo.account_generation(&user.id).await.unwrap(), 0);
            assert_eq!(repo.account_by_email(&user.email).await.unwrap().unwrap().id, user.id);
            assert!(
                repo.issue_api_token(&ApiTokenRecord {
                    id: memoswish_core::ids::new_id(),
                    token_hash: memoswish_core::ids::new_id(),
                    ..api.clone()
                })
                .await
                .is_err()
            );
            assert!(
                !repo
                    .oauth_rotate(
                        &tenant.id,
                        &parent,
                        &[crate::oauth_conformance::token(&code, "refresh")],
                        10
                    )
                    .await
                    .is_ok_and(|v| v)
            );
            assert!(
                !repo
                    .oauth_redeem(
                        &tenant.id,
                        &pending,
                        &[crate::oauth_conformance::token(&pending, "access")],
                        10
                    )
                    .await
                    .is_ok_and(|v| v)
            );
            let (a, b) = tokio::join!(
                repo.membership_join(&tenant.id, &user.id, Role::Owner),
                repo.membership_join(&tenant.id, &user.id, Role::Owner)
            );
            assert_ne!(a.is_ok(), b.is_ok());
            assert_eq!(a.or(b).unwrap(), 1);
            assert!(repo.membership_authorize(&tenant.id, &user.id, old).await.is_err());
            let fresh = CredentialGenerations {
                account: 0,
                membership: 1,
            };
            assert!(repo.membership_authorize(&tenant.id, &user.id, fresh).await.is_ok());
            assert!(
                !repo
                    .oauth_rotate(
                        &tenant.id,
                        &parent,
                        &[crate::oauth_conformance::token(&code, "refresh")],
                        10
                    )
                    .await
                    .is_ok_and(|v| v)
            );
            let fresh_code = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 1).await;
            assert!(
                repo.oauth_redeem(
                    &tenant.id,
                    &fresh_code,
                    &[crate::oauth_conformance::token(&fresh_code, "access")],
                    10
                )
                .await
                .unwrap()
            );
            // 认证之后降权，签发事务必须读取当前角色。
            sqlx::query("UPDATE tenant_memberships SET role='learner' WHERE tenant_id=$1 AND user_id=$2")
                .bind(&tenant.id)
                .bind(&user.id)
                .execute(repo.pool())
                .await
                .unwrap();
            assert_eq!(
                repo.membership_authorize(&tenant.id, &user.id, fresh).await.unwrap(),
                Role::Learner
            );
            assert!(
                repo.issue_api_token(&ApiTokenRecord {
                    id: memoswish_core::ids::new_id(),
                    token_hash: memoswish_core::ids::new_id(),
                    generations: fresh,
                    ..api.clone()
                })
                .await
                .is_err()
            );
            // 账户世代改变使全部成员授权失效。
            sqlx::query("UPDATE account_auth_epochs SET generation=1 WHERE user_id=$1")
                .bind(&user.id)
                .execute(repo.pool())
                .await
                .unwrap();
            assert!(repo.membership_authorize(&tenant.id, &user.id, fresh).await.is_err());
            assert!(repo.membership_authorize(&other.id, &user.id, old).await.is_err());
            repo.membership_remove(&tenant.id, &user.id).await.unwrap();
            repo.membership_remove(&other.id, &user.id).await.unwrap();
            assert!(repo.account_export_empty(&user.id, 0).await.is_err());
            let export = repo.account_export_empty(&user.id, 1).await.unwrap();
            assert_eq!(export.account.user_id, user.id);
            assert!(!serde_json::to_string(&export).unwrap().contains("not-exported"));
            // 并发加入和销户只允许一个结果，不能删除新成员。
            let (join, close) = tokio::join!(
                repo.membership_join(&tenant.id, &user.id, Role::Learner),
                repo.account_close_empty(&user.id, 1)
            );
            assert_ne!(join.is_ok(), close.is_ok());
            if join.is_ok() {
                assert!(repo.account_by_id(&user.id).await.unwrap().is_some());
                assert!(repo.get_user(&tenant.id, &user.id).await.unwrap().is_some());
                repo.membership_remove(&tenant.id, &user.id).await.unwrap();
                repo.account_close_empty(&user.id, 1).await.unwrap();
            }
            assert!(repo.account_by_id(&user.id).await.unwrap().is_none());
            assert!(repo.account_generation(&user.id).await.is_err());
            let history: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM membership_generations WHERE user_id=$1")
                .bind(&user.id)
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert!(history >= 3);
            // 不存在的父账户使插入历史后的失败整体回滚。
            assert!(repo.membership_join(&tenant.id, "missing", Role::Owner).await.is_err());
            let partial: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM membership_generations WHERE user_id='missing'")
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(partial, 0);
        }

        async fn identity_authorization_snapshot(repo: &$repo) -> Vec<Vec<String>> {
            let mut snapshot = Vec::new();
            for query in [
                "SELECT body || COALESCE(credential,'') FROM federated_identities ORDER BY issuer,subject",
                "SELECT identity_hash || ':' || CAST(sequence AS TEXT) FROM identity_unlink_fences ORDER BY identity_hash",
                "SELECT body FROM account_erasure_jobs ORDER BY id",
                "SELECT body || ':' || CAST(phase AS TEXT) FROM oidc_attempts ORDER BY id",
                "SELECT body FROM oidc_handoffs ORDER BY hash",
                "SELECT hash || ':' || CAST(expires_at AS TEXT) FROM recent_authentication ORDER BY hash",
                "SELECT CAST(value AS TEXT) FROM oidc_sequence WHERE id=1",
            ] {
                snapshot.push(sqlx::query_scalar(query).fetch_all(repo.pool()).await.unwrap());
            }
            snapshot
        }

        async fn membership_identity_races(repo: &$repo) {
            use memoswish_core::identity::*;
            let old = CredentialGenerations { account: 0, membership: 0 };
            for boundary in ["rejoin", "account-revocation"] {
                for operation in [
                    "unlink",
                    "link",
                    "recent-write",
                    "recent-check",
                    "link-start",
                    "workspace-complete",
                    "account-link-complete",
                ] {
                    let (user, identity) = crate::identity_conformance::unlink_fixture(repo, true).await;
                    let now = chrono::Utc::now().timestamp();
                    let recent = memoswish_core::ids::new_id();
                    repo.identity_resolve(&identity, None, true, Some("sealed-revocation"), Some(old), None).await.unwrap();
                    repo.identity_recent_auth(&user.tenant_id, &user.id, old, &recent, now + 300).await.unwrap();
                    let attempt = crate::identity_conformance::claimed_attempt(repo, &identity, true).await;
                    repo.identity_resolve(&identity, None, true, None, Some(old), Some(&attempt.id)).await.unwrap();
                    let snapshot = identity_authorization_snapshot(repo).await;
                    // 真实移除和重入各自提交，旧请求随后在另一个连接等待注册锁。
                    if boundary == "rejoin" {
                        assert!(repo.membership_remove(&user.tenant_id, &user.id).await.unwrap());
                        assert_eq!(repo.membership_join(&user.tenant_id, &user.id, Role::Owner).await.unwrap(), 1);
                    }
                    let mut tx = repo.pool().begin().await.unwrap();
                    sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1").execute(&mut *tx).await.unwrap();
                    if boundary == "account-revocation" {
                        // 保留近期认证行，单独证明账户世代校验不能依赖清理副作用。
                        sqlx::query("UPDATE account_auth_epochs SET generation=1 WHERE user_id=$1")
                            .bind(&user.id)
                            .execute(&mut *tx)
                            .await
                            .unwrap();
                    }
                    let gate = std::sync::Arc::new(tokio::sync::Barrier::new(2));
                    let worker_gate = gate.clone();
                    let contender = repo.clone();
                    let tid = user.tenant_id.clone();
                    let uid = user.id.clone();
                    let original_attempt_id = attempt.id.clone();
                    let worker_identity = identity.clone();
                    let worker = tokio::spawn(async move {
                        worker_gate.wait().await;
                        match operation {
                            "unlink" => {
                                contender.identity_unlink(&tid, &uid, old, "google", &recent, now, &[]).await.map(|_| ())
                            }
                            "link" => {
                                let pending = FederatedIdentity { subject: memoswish_core::ids::new_id(), ..worker_identity };
                                contender
                                    .identity_resolve(
                                        &pending,
                                        None,
                                        true,
                                        Some("new-sealed-credential"),
                                        Some(old),
                                        Some(&attempt.id),
                                    )
                                    .await
                                    .map(|_| ())
                            }
                            "recent-write" => contender.identity_recent_auth(&tid, &uid, old, "new-session", now + 300).await,
                            "recent-check" => contender.identity_check_recent(&tid, &uid, old, &recent, now).await.map(|_| ()),
                            "link-start" => {
                                let start = LoginAttempt {
        link_access_hash: None,
                                    id: memoswish_core::ids::new_id(),
                                    state_hash: memoswish_core::ids::new_id(),
                                    ..attempt
                                };
                                contender.identity_attempt_insert(&start).await
                            }
                            "workspace-complete" => {
                                contender.identity_complete(&attempt.id, &tid, &uid, old, "new-session", now).await
                            }
                            "account-link-complete" => {
                                contender
                                    .identity_complete_account(&attempt.id, &tid, &uid, old.account, "new-session", now)
                                    .await
                            }
                            _ => unreachable!(),
                        }
                    });
                    gate.wait().await;
                    observe_membership_wait(repo).await;
                    assert!(!worker.is_finished());
                    tx.commit().await.unwrap();
                    assert!(matches!(worker.await.unwrap(), Err(CoreError::Unauthorized(_))), "{boundary}-first {operation}");
                    assert_eq!(
                        identity_authorization_snapshot(repo).await,
                        snapshot,
                        "rejected {boundary} {operation} must preserve identities, fences, jobs, attempts and recent auth"
                    );
                    let fresh = if boundary == "rejoin" {
                        CredentialGenerations { account: 0, membership: 1 }
                    } else {
                        CredentialGenerations { account: 1, membership: 0 }
                    };
                    assert!(
                        matches!(
                            repo.identity_resolve(&identity, None, true, None, Some(fresh), Some(&original_attempt_id)).await,
                            Err(CoreError::Unauthorized(_))
                        ),
                        "a fresh principal cannot replace the original link authorization"
                    );
                    assert_eq!(identity_authorization_snapshot(repo).await, snapshot);
                    let fresh_session = memoswish_core::ids::new_id();
                    repo.identity_recent_auth(&user.tenant_id, &user.id, fresh, &fresh_session, now + 300).await.unwrap();
                    assert!(
                        repo.identity_unlink(&user.tenant_id, &user.id, fresh, "google", &fresh_session, now, &[])
                            .await
                            .unwrap()
                    );
                    let jobs = repo.account_erasure_jobs().await.unwrap();
                    assert_eq!(jobs.iter().filter(|j| j.tenant_id.as_deref() == Some(user.tenant_id.as_str())).count(), 1);
                }
            }
            // 解绑先提交时保留已签发会话语义，后续移除与重入不能恢复身份。
            let (user, identity) = crate::identity_conformance::unlink_fixture(repo, true).await;
            let now = chrono::Utc::now().timestamp();
            repo.identity_resolve(&identity, None, true, Some("sealed-revocation"), Some(old), None).await.unwrap();
            repo.identity_recent_auth(&user.tenant_id, &user.id, old, "unlink-first", now + 300).await.unwrap();
            let gate = std::sync::Arc::new(tokio::sync::Barrier::new(2));
            let worker_gate = gate.clone();
            let contender = repo.clone();
            let tid = user.tenant_id.clone();
            let uid = user.id.clone();
            let removal = tokio::spawn(async move {
                worker_gate.wait().await;
                assert!(contender.membership_remove(&tid, &uid).await.unwrap());
                assert_eq!(contender.membership_join(&tid, &uid, Role::Owner).await.unwrap(), 1);
            });
            assert!(repo.identity_unlink(&user.tenant_id, &user.id, old, "google", "unlink-first", now, &[]).await.unwrap());
            assert_eq!(repo.membership_authorize(&user.tenant_id, &user.id, old).await.unwrap(), Role::Owner);
            let snapshot = identity_authorization_snapshot(repo).await;
            gate.wait().await;
            removal.await.unwrap();
            assert_eq!(identity_authorization_snapshot(repo).await, snapshot);
            assert!(repo.identity_list(&user.tenant_id, &user.id).await.unwrap().is_empty());
            let fence: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identity_unlink_fences WHERE identity_hash=$1")
                .bind(memoswish_core::ids::sha256_hex(format!("{}\0{}", identity.issuer, identity.subject).as_bytes()))
                .fetch_one(repo.pool())
                .await
                .unwrap();
            assert_eq!(fence, 1);

            // 匿名 OIDC 交互证明账户身份，移除工作区后仍可完成账户登录。
            let (user, identity) = crate::identity_conformance::unlink_fixture(repo, true).await;
            let attempt = crate::identity_conformance::claimed_attempt(repo, &identity, false).await;
            repo.identity_resolve(&identity, None, false, None, None, Some(&attempt.id)).await.unwrap();
            repo.membership_remove(&user.tenant_id, &user.id).await.unwrap();
            repo.membership_join(&user.tenant_id, &user.id, Role::Owner).await.unwrap();
            assert!(repo.identity_complete(&attempt.id, &user.tenant_id, &user.id, old, "stale-workspace", now).await.is_err());
            assert!(
                repo.identity_complete(
                    &attempt.id,
                    &user.tenant_id,
                    &user.id,
                    CredentialGenerations { account: 0, membership: 1 },
                    "upgraded-workspace",
                    now
                )
                .await
                .is_err()
            );
            repo.identity_complete_account(&attempt.id, &user.tenant_id, &user.id, 0, "account-only", now).await.unwrap();
        }

        async fn membership_issuance_races(repo: &$repo) {
            let tenant = TenantRecord {
                id: memoswish_core::ids::new_id(),
                name: "Races".into(),
                plan: "free".into(),
                created_at: chrono::Utc::now(),
            };
            repo.upsert_tenant(&tenant).await.unwrap();
            let user = UserRecord {
                id: memoswish_core::ids::new_id(),
                tenant_id: tenant.id.clone(),
                email: format!("{}@example.com", memoswish_core::ids::new_id()),
                display_name: "Races".into(),
                password_hash: "private".into(),
                role: Role::Owner,
                created_at: chrono::Utc::now(),
            };
            repo.insert_user(&user).await.unwrap();
            let client = OAuthClient {
                id: memoswish_core::ids::new_id(),
                name: "Races".into(),
                redirect_uris: vec!["https://client.example/callback".into()],
                grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                scopes: vec!["content:read".into()],
                auth_method: "none".into(),
                secret_hash: None,
                created_at: 0,
                expires_at: i64::MAX,
            };
            repo.oauth_register(&client).await.unwrap();
            for operation in ["api", "login", "consent", "redeem", "refresh"] {
                let generation = repo.memberships(&user.id).await.unwrap()[0].generation;
                let generations = CredentialGenerations {
                    account: 0,
                    membership: generation,
                };
                let code = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 1).await;
                let parent = crate::oauth_conformance::token(&code, "refresh");
                assert!(
                    repo.oauth_redeem(&tenant.id, &code, std::slice::from_ref(&parent), 10)
                        .await
                        .unwrap()
                );
                let redeem = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 1).await;
                let (request, session) =
                    crate::oauth_conformance::pending_authorization(repo, &user, &client, i64::MAX - 1).await;
                let consent = AuthorizationCode {
                    hash: memoswish_core::ids::new_id(),
                    grant: OAuthGrant {
                        id: memoswish_core::ids::new_id(),
                        tenant_id: tenant.id.clone(),
                        user_id: user.id.clone(),
                        client_id: client.id.clone(),
                        resource: request.resource.clone(),
                        scopes: request.scopes.clone(),
                        expires_at: i64::MAX - 1,
                        generations,
                    },
                    redirect_uri: request.redirect_uri.clone(),
                    challenge: request.challenge.clone(),
                    expires_at: i64::MAX - 1,
                };
                let anonymous = BrowserSession {
                    hash: memoswish_core::ids::new_id(),
                    tenant_id: None,
                    user_id: None,
                    auth_time: 0,
                    auth_method: "anonymous".into(),
                    generations: None,
                    expires_at: i64::MAX - 1,
                };
                let login_request = AuthorizationRequest {
                    id: memoswish_core::ids::new_id(),
                    browser_hash: anonymous.hash.clone(),
                    ..request.clone()
                };
                repo.oauth_begin(&anonymous, &login_request).await.unwrap();
                let session = BrowserSession {
                    hash: memoswish_core::ids::new_id(),
                    ..session
                };
                let api = ApiTokenRecord {
                    id: memoswish_core::ids::new_id(),
                    tenant_id: tenant.id.clone(),
                    user_id: user.id.clone(),
                    name: "Race".into(),
                    token_hash: memoswish_core::ids::new_id(),
                    generations,
                    scopes: vec!["content:read".into()],
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                    last_used_at: None,
                    revoked: false,
                };
                // 先锁住删除事务，再启动另一个连接的敏感签发。
                let mut tx = repo.pool().begin().await.unwrap();
                sqlx::query("UPDATE oauth_registry SET value=value WHERE id=1")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                sqlx::query("DELETE FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2")
                    .bind(&tenant.id)
                    .bind(&user.id)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                let gate = std::sync::Arc::new(tokio::sync::Barrier::new(2));
                let worker_gate = gate.clone();
                let contender = repo.clone();
                let tid = tenant.id.clone();
                let worker = tokio::spawn(async move {
                    worker_gate.wait().await;
                    match operation {
                        "api" => contender.issue_api_token(&api).await.map(|_| true),
                        "login" => contender.oauth_login(&tid, &login_request, &session, 10).await,
                        "consent" => contender.oauth_consent(&tid, &request, Some(&consent), 10).await,
                        "redeem" => {
                            contender
                                .oauth_redeem(&tid, &redeem, &[crate::oauth_conformance::token(&redeem, "access")], 10)
                                .await
                        }
                        "refresh" => {
                            contender
                                .oauth_rotate(&tid, &parent, &[crate::oauth_conformance::token(&code, "refresh")], 10)
                                .await
                        }
                        _ => unreachable!(),
                    }
                });
                gate.wait().await;
                observe_membership_wait(repo).await;
                assert!(!worker.is_finished());
                tx.commit().await.unwrap();
                assert!(!worker.await.unwrap().is_ok_and(|ok| ok), "removal-first {operation}");
                repo.membership_join(&tenant.id, &user.id, Role::Owner).await.unwrap();
            }
            // 同意请求在认证后被降权，锁内权限检查必须拒绝写权限。
            let (mut request, _) = crate::oauth_conformance::pending_authorization(repo, &user, &client, i64::MAX - 1).await;
            request.scopes = vec!["content:write".into()];
            sqlx::query("UPDATE oauth_authorization_requests SET body=$1 WHERE id=$2")
                .bind(crate::oauth::encode(&request).unwrap())
                .bind(&request.id)
                .execute(repo.pool())
                .await
                .unwrap();
            let generations = CredentialGenerations {
                account: 0,
                membership: repo.memberships(&user.id).await.unwrap()[0].generation,
            };
            let consent = AuthorizationCode {
                hash: memoswish_core::ids::new_id(),
                grant: OAuthGrant {
                    id: memoswish_core::ids::new_id(),
                    tenant_id: tenant.id.clone(),
                    user_id: user.id.clone(),
                    client_id: client.id.clone(),
                    resource: request.resource.clone(),
                    scopes: request.scopes.clone(),
                    expires_at: i64::MAX - 1,
                    generations,
                },
                redirect_uri: request.redirect_uri.clone(),
                challenge: request.challenge.clone(),
                expires_at: i64::MAX - 1,
            };
            sqlx::query("UPDATE tenant_memberships SET role='learner' WHERE tenant_id=$1 AND user_id=$2")
                .bind(&tenant.id)
                .bind(&user.id)
                .execute(repo.pool())
                .await
                .unwrap();
            assert!(
                !repo
                    .oauth_consent(&tenant.id, &request, Some(&consent), 10)
                    .await
                    .unwrap()
            );
            assert!(repo.oauth_code(&consent.hash).await.unwrap().is_none());
        }

        async fn persistent_member_setup(repo: &$repo) -> UserRecord {
            let tenant = TenantRecord {
                id: memoswish_core::ids::new_id(),
                name: "Restart".into(),
                plan: "free".into(),
                created_at: chrono::Utc::now(),
            };
            repo.upsert_tenant(&tenant).await.unwrap();
            let user = UserRecord {
                id: memoswish_core::ids::new_id(),
                tenant_id: tenant.id,
                email: format!("{}@example.com", memoswish_core::ids::new_id()),
                display_name: "Restart".into(),
                password_hash: "private".into(),
                role: Role::Owner,
                created_at: chrono::Utc::now(),
            };
            repo.insert_user(&user).await.unwrap();
            repo.membership_remove(&user.tenant_id, &user.id).await.unwrap();
            user
        }
        async fn persistent_member_resume(repo: &$repo, user: &UserRecord) {
            assert_eq!(
                repo.membership_join(&user.tenant_id, &user.id, Role::Owner)
                    .await
                    .unwrap(),
                1
            );
            assert!(
                repo.membership_authorize(
                    &user.tenant_id,
                    &user.id,
                    CredentialGenerations {
                        account: 0,
                        membership: 0
                    }
                )
                .await
                .is_err()
            );
            assert!(
                repo.membership_authorize(
                    &user.tenant_id,
                    &user.id,
                    CredentialGenerations {
                        account: 0,
                        membership: 1
                    }
                )
                .await
                .is_ok()
            );
            repo.membership_remove(&user.tenant_id, &user.id).await.unwrap();
            sqlx::query("INSERT INTO membership_generations(tenant_id,user_id,generation) VALUES($1,$2,9223372036854775807)")
                .bind(&user.tenant_id)
                .bind(&user.id)
                .execute(repo.pool())
                .await
                .unwrap();
            assert!(
                repo.membership_join(&user.tenant_id, &user.id, Role::Owner)
                    .await
                    .is_err()
            );
        }

        async fn zero_account_cleanup_responsibility(repo: &$repo) {
            use memoswish_core::identity::{FederatedIdentity, IdentityRepo};
            let tenant = TenantRecord {
                id: memoswish_core::ids::new_id(),
                name: "Cleanup".into(),
                plan: "free".into(),
                created_at: chrono::Utc::now(),
            };
            repo.upsert_tenant(&tenant).await.unwrap();
            let user = UserRecord {
                id: memoswish_core::ids::new_id(),
                tenant_id: tenant.id.clone(),
                email: format!("{}@example.com", memoswish_core::ids::new_id()),
                display_name: "Cleanup".into(),
                password_hash: "private".into(),
                role: Role::Owner,
                created_at: chrono::Utc::now(),
            };
            repo.insert_user(&user).await.unwrap();
            let identity = FederatedIdentity {
                client_id: "client".into(),
                issuer: format!("https://{}.example", memoswish_core::ids::new_id()),
                subject: "subject".into(),
                provider: "provider".into(),
                tenant_id: tenant.id.clone(),
                user_id: user.id.clone(),
                email: None,
                email_verified: false,
                display_name: None,
                created_at: 1,
                authenticated_at: 1,
            };
            repo.identity_resolve(
                &identity,
                None,
                true,
                Some("encrypted-revocation-responsibility"),
                Some(CredentialGenerations { account: 0, membership: 0 }),
                None,
            )
            .await
            .unwrap();
            repo.membership_remove(&tenant.id, &user.id).await.unwrap();
            let job = repo.account_close_empty(&user.id, 0).await.unwrap();
            assert!(job.tenant_id.is_none());
            assert!(!job.purge_assets);
            assert_eq!(
                job.credentials,
                vec![("provider".into(), "encrypted-revocation-responsibility".into())]
            );
            assert!(repo.identity_list(&tenant.id, &user.id).await.unwrap().is_empty());
            let persisted = repo
                .account_erasure_jobs()
                .await
                .unwrap()
                .into_iter()
                .find(|j| j.id == job.id)
                .unwrap();
            assert_eq!(persisted.credentials, job.credentials);
            assert!(repo.get_tenant(&tenant.id).await.unwrap().is_some());
            assert!(repo.account_erasure_finish(&job.id).await.is_err());
        }

        async fn membership_upgrade(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            crate::foundation_conformance::through(&full, 8)
                .run(pool)
                .await
                .unwrap();
            sqlx::raw_sql(crate::foundation_conformance::LEGACY_DATA)
                .execute(pool)
                .await
                .unwrap();
            crate::foundation_conformance::through(&full, 11)
                .run(pool)
                .await
                .unwrap();
            sqlx::raw_sql("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES('foundation','s4-job','tts','s4','{}','account',7,3,0); INSERT INTO quota_operations VALUES('foundation','s4-job','tts_chars','2026-11',9,'reserved');").execute(pool).await.unwrap();
            // 构造真实旧版 OAuth JSON，验证有效授权的非零世代升级。
            let grant = OAuthGrant {
                id: "grant".into(),
                tenant_id: "foundation".into(),
                user_id: "account".into(),
                client_id: "client".into(),
                resource: "https://learn.example/mcp".into(),
                scopes: vec!["content:read".into()],
                expires_at: 2_000_000_000,
                generations: CredentialGenerations {
                    account: 7,
                    membership: 7,
                },
            };
            let mut legacy = serde_json::to_value(&grant).unwrap();
            legacy.as_object_mut().unwrap().remove("generations");
            sqlx::query("UPDATE oauth_grants SET metadata=$1 WHERE id='grant'")
                .bind(legacy.to_string())
                .execute(pool)
                .await
                .unwrap();
            let code = AuthorizationCode {
                hash: "code".into(),
                grant: grant.clone(),
                redirect_uri: "https://client.example/callback".into(),
                challenge: "s256".into(),
                expires_at: 2_000_000_000,
            };
            let mut legacy = serde_json::to_value(&code).unwrap();
            legacy["grant"].as_object_mut().unwrap().remove("generations");
            sqlx::query("UPDATE oauth_authorization_codes SET body=$1 WHERE hash='code'")
                .bind(legacy.to_string())
                .execute(pool)
                .await
                .unwrap();
            for (hash, kind) in [("access", "access"), ("refresh", "refresh")] {
                let token = OAuthToken {
                    hash: hash.into(),
                    grant: grant.clone(),
                    scopes: grant.scopes.clone(),
                    kind: kind.into(),
                    expires_at: 2_000_000_000,
                };
                let mut legacy = serde_json::to_value(&token).unwrap();
                legacy["grant"].as_object_mut().unwrap().remove("generations");
                sqlx::query("UPDATE oauth_tokens SET body=$1 WHERE hash=$2")
                    .bind(legacy.to_string())
                    .bind(hash)
                    .execute(pool)
                    .await
                    .unwrap();
            }
            sqlx::query("INSERT INTO oauth_grants(id,tenant_id,user_id,client_id,expires_at,metadata) VALUES('ambiguous','foundation','account','client',2000000000,'{}')").execute(pool).await.unwrap();

            // 迁移失败必须回滚结构、数据与迁移历史。
            let mut broken = crate::foundation_conformance::through(&full, 12);
            let last = broken.migrations.to_mut().last_mut().unwrap();
            *last = sqlx::migrate::Migration::new(
                12,
                "injected failure".into(),
                sqlx::migrate::MigrationType::Simple,
                format!("{}\nSELECT * FROM s4_injected_missing;", last.sql).into(),
                false,
            );
            assert!(broken.run(pool).await.is_err());
            let latest: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(latest, 11);
            let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oidc_attempts")
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(attempts, 1);
            full.run(pool).await.unwrap();
            full.run(pool).await.unwrap();
            let api = sqlx::query(
                "SELECT account_generation,membership_generation,token_hash,revoked FROM api_tokens WHERE id='api'",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            assert_eq!(api.get::<i64, _>("account_generation"), 7);
            assert_eq!(api.get::<i64, _>("membership_generation"), 7);
            assert_eq!(api.get::<String, _>("token_hash"), "preserved-hash");
            let grant: String = sqlx::query_scalar("SELECT metadata FROM oauth_grants WHERE id='grant'")
                .fetch_one(pool)
                .await
                .unwrap();
            let grant: serde_json::Value = serde_json::from_str(&grant).unwrap();
            assert_eq!(grant["generations"], serde_json::json!({"account":7,"membership":7}));
            for table in ["oauth_authorization_codes", "oauth_tokens"] {
                let rows = sqlx::query(&format!("SELECT body,consumed FROM {table} ORDER BY hash"))
                    .fetch_all(pool)
                    .await
                    .unwrap();
                for row in rows {
                    let body: serde_json::Value = serde_json::from_str(&row.get::<String, _>("body")).unwrap();
                    assert_eq!(body["grant"]["generations"], grant["generations"]);
                }
            }
            let repo = $repo {
                observer: memoswish_core::observability::noop(), pool: pool.clone(),
                learning_gate: None,
                feed_gate: None, content_gate: None, lifecycle_gate: None,
            };
            let persisted = repo.oauth_token("refresh").await.unwrap().unwrap();
            assert_eq!(
                persisted.grant.generations,
                CredentialGenerations {
                    account: 7,
                    membership: 7
                }
            );
            assert_eq!(persisted.scopes, vec!["content:read"]);
            assert!(repo.oauth_code("code").await.unwrap().is_some());
            let ambiguous: i64 = sqlx::query_scalar("SELECT revoked FROM oauth_grants WHERE id='ambiguous'")
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(ambiguous, 1);
            let used: i64 = sqlx::query_scalar("SELECT consumed FROM oauth_tokens WHERE hash='refresh'")
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(used, 1);
            for table in ["background_jobs", "quota_operations", "federated_identities"] {
                // S19 导入的擦除工作另有共享验收，此处继续保护原成员任务与账本。
                let scope=if table=="background_jobs" {" WHERE kind<>'erasure'"}else{""};
                let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}{scope}"))
                    .fetch_one(pool)
                    .await
                    .unwrap();
                assert_eq!(count, 1);
            }
            let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oidc_attempts")
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(pending, 0);
        }
    };
}
pub(crate) use membership_tests;
