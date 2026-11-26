//! 两库共用旋转、回滚、撤销与成员世代负例。
use chrono::Utc;
use memoswish_core::ids::new_id;
use memoswish_core::{
    Role,
    repo::{Repository, TenantRecord, UserRecord},
    session::*,
};

pub(crate) async fn setup(repo: &dyn Repository) -> (SessionFamily, SessionCredential) {
    let t = TenantRecord { id: new_id(), name: "Sessions".into(), plan: "free".into(), created_at: Utc::now() };
    repo.upsert_tenant(&t).await.unwrap();
    let u = UserRecord {
        id: new_id(),
        tenant_id: t.id.clone(),
        email: format!("{}@test.invalid", new_id()),
        display_name: "Owner".into(),
        password_hash: "hash".into(),
        role: Role::Owner,
        created_at: Utc::now(),
    };
    repo.insert_user(&u).await.unwrap();
    let now = Utc::now().timestamp();
    let f = SessionFamily {
        id: new_id(),
        user_id: u.id,
        generation: 0,
        provenance: "password".into(),
        auth_time: now,
        expires_at: now + 3600,
        revoked: false,
    };
    let c = credential(&f, Some((t.id, 0)));
    (f, c)
}
pub(crate) fn credential(f: &SessionFamily, t: Option<(String, i64)>) -> SessionCredential {
    SessionCredential {
        access_hash: new_id(),
        refresh_hash: new_id(),
        assurance_hash: new_id(),
        session_id: f.id.clone(),
        tenant_id: t.as_ref().map(|t| t.0.clone()),
        membership_generation: t.map(|t| t.1),
        expires_at: f.auth_time + 600,
    }
}
pub(crate) async fn run<R: Repository>(repo: &R) {
    let (f, c) = setup(repo).await;
    repo.session_issue(&f, &c, None).await.unwrap();
    assert_eq!(repo.session_access(&c.access_hash).await.unwrap().family, f);
    // 插入冲突发生在消费之后，必须整体回滚，父凭据仍能刷新。
    let other = credential(&f, None);
    let mut f2 = f.clone();
    f2.id = new_id();
    let mut other = other;
    other.session_id = f2.id.clone();
    repo.session_issue(&f2, &other, None).await.unwrap();
    assert!(repo.session_rotate(&c.refresh_hash, &new_id(), &other.refresh_hash, &new_id(), 600).await.is_err());
    assert!(repo.session_access(&c.access_hash).await.is_ok());
    let next = repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.unwrap();
    assert_eq!(next.family.auth_time, f.auth_time);
    assert!(repo.session_access(&c.access_hash).await.is_err());
    assert!(repo.session_access(&next.credential.access_hash).await.is_ok());
    assert!(repo.session_rotate("unknown", &new_id(), &new_id(), &new_id(), 600).await.is_err());
    assert!(repo.session_access(&next.credential.access_hash).await.is_ok());
    assert!(repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.is_err());
    assert!(repo.session_access(&next.credential.access_hash).await.is_err());
    assert!(repo.session_rotate(&next.credential.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.is_err());
    assert!(repo.session_access(&other.access_hash).await.is_ok());
    // 同父并发最多一个成功；重复请求可使成功请求的后继立即失效。
    let (f, c) = setup(repo).await;
    repo.session_issue(&f, &c, None).await.unwrap();
    let (a1, r1, h1, a2, r2, h2) = (new_id(), new_id(), new_id(), new_id(), new_id(), new_id());
    let (one, two) = tokio::join!(
        repo.session_rotate(&c.refresh_hash, &a1, &r1, &h1, 600),
        repo.session_rotate(&c.refresh_hash, &a2, &r2, &h2, 600)
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    assert!(repo.session_access(&a1).await.is_err());
    assert!(repo.session_access(&a2).await.is_err());
    // 显式选择才可获得当前成员世代；旧工作区 refresh 永不升级。
    let (f, c) = setup(repo).await;
    let account = credential(&f, None);
    repo.session_issue(&f, &account, None).await.unwrap();
    repo.session_select(&account.access_hash, &c).await.unwrap();
    let tenant = c.tenant_id.as_deref().unwrap();
    repo.membership_remove(tenant, &f.user_id).await.unwrap();
    assert!(repo.session_access(&c.access_hash).await.is_err());
    assert!(repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.is_err());
    assert!(repo.session_access(&account.access_hash).await.is_ok());
    repo.membership_join(tenant, &f.user_id, Role::Learner).await.unwrap();
    assert!(repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.is_err());
    let mut fresh = credential(&f, Some((tenant.into(), 1)));
    repo.session_select(&account.access_hash, &fresh).await.unwrap();
    assert!(repo.session_access(&fresh.access_hash).await.is_ok());
    // 外部账户无法探测或撤销目标；本账户 logout 撤销全部同族权限。
    let (foreign, fc) = setup(repo).await;
    repo.session_issue(&foreign, &fc, None).await.unwrap();
    assert!(!repo.session_revoke(&fc.access_hash, &f.id).await.unwrap());
    assert!(repo.session_access(&account.access_hash).await.is_ok());
    // 第一方族撤销不影响独立 MCP grant，仍可执行自己的旋转。
    let user = repo.get_user(tenant, &f.user_id).await.unwrap().unwrap();
    let client = memoswish_core::oauth::OAuthClient {
        id: new_id(),
        name: "Independent MCP".into(),
        redirect_uris: vec!["https://client.example/callback".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        scopes: vec!["content:read".into()],
        auth_method: "none".into(),
        secret_hash: None,
        created_at: 10,
        expires_at: i64::MAX - 1,
    };
    repo.oauth_register(&client).await.unwrap();
    let code = crate::oauth_conformance::code(repo, &user, &client, f.expires_at).await;
    let mcp = crate::oauth_conformance::token(&code, "access");
    let parent = crate::oauth_conformance::token(&code, "refresh");
    assert!(repo.oauth_redeem(tenant, &code, &[mcp.clone(), parent.clone()], 10).await.unwrap());
    assert!(repo.session_revoke(&account.access_hash, &f.id).await.unwrap());
    assert!(repo.oauth_token(&mcp.hash).await.unwrap().is_some());
    let next = crate::oauth_conformance::token(&code, "refresh");
    assert!(repo.oauth_rotate(tenant, &parent, std::slice::from_ref(&next), 10).await.unwrap());
    assert!(repo.session_access(&fresh.access_hash).await.is_err());
    fresh.session_id = foreign.id;
    assert!(repo.session_select(&fc.access_hash, &fresh).await.is_err());
}
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_sessions_conformance() {
    let repo = crate::sqlite::SqliteRepository::in_memory().await.unwrap();
    run(&repo).await;
    links(&repo).await;
    revoked_unlink(&repo).await;
    prerequisites(&repo).await;
    link_ack(&repo).await;
    logout_interleavings(&repo).await;
}
#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_sessions_conformance() {
    crate::pg_test_support::run_pg_test(|owner| async move {
        let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").expect("PostgreSQL URL required");
        let fixture = owner.fixture(&url).await;
        let repo = fixture.repository(4).await.unwrap();
        run(&repo).await;
        links(&repo).await;
        revoked_unlink(&repo).await;
        prerequisites(&repo).await;
        link_ack(&repo).await;
        fixture.cleanup().await;
    });
}

pub(crate) async fn staged_link(
    repo: &dyn Repository,
) -> (
    SessionFamily,
    SessionCredential,
    memoswish_core::identity::FederatedIdentity,
    memoswish_core::identity::LoginAttempt,
) {
    staged_link_with_legacy(repo, false).await
}

pub(crate) async fn staged_link_with_legacy(
    repo: &dyn Repository,
    legacy: bool,
) -> (
    SessionFamily,
    SessionCredential,
    memoswish_core::identity::FederatedIdentity,
    memoswish_core::identity::LoginAttempt,
) {
    use memoswish_core::identity::*;
    let (f, c) = setup(repo).await;
    repo.session_issue(&f, &c, None).await.unwrap();
    let now = Utc::now().timestamp();
    let a = LoginAttempt {
        link_legacy_issued_at: legacy.then_some(now),
        link_access_hash: (!legacy).then(|| c.access_hash.clone()),
        id: new_id(),
        provider: "test".into(),
        state_hash: new_id(),
        launch_hash: new_id(),
        browser_hash: String::new(),
        nonce: new_id(),
        verifier_ciphertext: "encrypted".into(),
        client_id: "client".into(),
        return_uri: "dev.learntok:/callback".into(),
        app_state: "state".into(),
        challenge: "challenge".into(),
        native: true,
        link_tenant: c.tenant_id.clone(),
        link_user: Some(f.user_id.clone()),
        link_generation: Some(0),
        link_membership_generation: Some(0),
        link_session_hash: Some("binding".into()),
        expires_at: now + 300,
    };
    repo.identity_attempt_insert(&a).await.unwrap();
    assert!(repo.identity_claim(&a.id, "test", &a.launch_hash, true, now).await.unwrap());
    let i = FederatedIdentity {
        issuer: "https://issuer.invalid".into(),
        subject: new_id(),
        provider: "test".into(),
        client_id: "client".into(),
        tenant_id: c.tenant_id.clone().unwrap(),
        user_id: f.user_id.clone(),
        email: None,
        email_verified: false,
        display_name: None,
        created_at: now,
        authenticated_at: now,
    };
    repo.identity_resolve(
        &i,
        None,
        true,
        None,
        Some(memoswish_core::CredentialGenerations { account: 0, membership: 0 }),
        Some(&a.id),
    )
    .await
    .unwrap();
    assert!(repo.identity_list(&i.tenant_id, &i.user_id).await.unwrap().is_empty());
    (f, c, i, a)
}
pub(crate) async fn links(repo: &dyn Repository) {
    use memoswish_core::CredentialGenerations;
    let g = CredentialGenerations { account: 0, membership: 0 };
    let (f, c, i, a) = staged_link(repo).await;
    // 完成时等于 deadline 必须拒绝，暂存关联不能残留。
    assert!(
        repo.identity_complete(&a.id, &i.tenant_id, &f.user_id, g, "expired-assurance", a.expires_at).await.is_err()
    );
    assert!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().is_empty());
    assert!(
        !repo
            .identity_check_recent(&i.tenant_id, &f.user_id, g, "expired-assurance", Utc::now().timestamp())
            .await
            .unwrap()
    );
    // 后继插入冲突回滚关联、attempt 消费与会话行。
    let mut successor = f.clone();
    successor.id = new_id();
    let mut next = credential(&successor, None);
    next.refresh_hash = c.refresh_hash.clone();
    assert!(repo.session_issue(&successor, &next, Some(&a.id)).await.is_err());
    assert!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().is_empty());
    assert!(repo.session_access(&next.access_hash).await.is_err());
    next.refresh_hash = new_id();
    repo.session_issue(&successor, &next, Some(&a.id)).await.unwrap();
    assert_eq!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().len(), 1);
    assert!(repo.session_access(&next.access_hash).await.is_ok());
    // 安全事件提升账户世代，原工作区及账户族均失效。
    repo.identity_event(
        &i.issuer,
        &i.subject,
        &new_id(),
        "consent-revoked",
        Utc::now().timestamp(),
        Utc::now().timestamp(),
    )
    .await
    .unwrap();
    assert!(repo.session_access(&next.access_hash).await.is_err());
    assert!(repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.is_err());
    let (f, c, i, a) = staged_link(repo).await;
    repo.session_revoke(&c.access_hash, &f.id).await.unwrap();
    assert!(
        repo.identity_complete(&a.id, &i.tenant_id, &f.user_id, g, "revoked-assurance", Utc::now().timestamp())
            .await
            .is_err()
    );
    assert!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().is_empty());
}

async fn revoked_unlink(repo: &dyn Repository) {
    let (f, c, i, a) = staged_link(repo).await;
    let g = memoswish_core::CredentialGenerations { account: 0, membership: 0 };
    repo.identity_complete(&a.id, &i.tenant_id, &f.user_id, g, "unlink-completion", Utc::now().timestamp())
        .await
        .unwrap();
    repo.session_revoke(&c.access_hash, &f.id).await.unwrap();
    assert!(
        repo.identity_unlink(&i.tenant_id, &f.user_id, g, "test", &c.assurance_hash, Utc::now().timestamp(), &[])
            .await
            .is_err()
    );
    assert_eq!(
        repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().len(),
        1,
        "logout before the transaction must prevent unlink"
    );
}

// 复用规范迁移裁剪与两库同场景，真实旧 JSON 不包含 opaque 绑定字段。
macro_rules! upgrade_tests {
    ($repo:ident, $pool:ty, $migrations:literal) => {
        async fn pre_s21_snapshot(pool: &$pool, table: &str) -> Vec<Vec<Option<String>>> {
            use sqlx::{Column, Row};
            let Some(row) = sqlx::query(&format!("SELECT * FROM {table} LIMIT 1")).persistent(false).fetch_optional(pool).await.unwrap() else { return Vec::new(); };
            // S19 scope 与 S26d 时间列单独验证，升级快照继续逐列比较全部既有字段。
            let projection = row.columns().iter().filter(|column| !(table == "background_jobs" && matches!(column.name(), "work_scope" | "work_scope_guard")) && !matches!(column.name(),"enqueued_at_ms"|"responsibility_at_ms")).map(|column| format!("CAST({} AS TEXT)", column.name()))
                .collect::<Vec<_>>().join(",");
            sqlx::query(&format!("SELECT {projection} FROM {table} ORDER BY {projection}"))
                .fetch_all(pool).await.unwrap().iter()
                .map(|row| (0..row.len()).map(|index| row.get(index)).collect()).collect()
        }

        async fn pre_s21_links_upgrade(pool: &$pool) {
            use memoswish_core::{CredentialGenerations, ids::new_id, identity::*, oauth::{OAuthRepo, OAuthIndex}, session::*};

            let full = sqlx::migrate!($migrations);
            crate::foundation_conformance::through(&full, 16).run(pool).await.unwrap();
            let repo = $repo { observer: memoswish_core::observability::noop(), pool: pool.clone(), learning_gate: None, content_gate: None, feed_gate: None, lifecycle_gate: None };
            let (mut family, mut credential) = crate::session_conformance::setup(&repo).await;
            let tenant = credential.tenant_id.clone().unwrap();
            let user = family.user_id.clone();
            sqlx::query("UPDATE account_auth_epochs SET generation=7 WHERE user_id=$1")
                .bind(&user).execute(pool).await.unwrap();
            sqlx::query("INSERT INTO membership_generations(tenant_id,user_id,generation) VALUES($1,$2,7)")
                .bind(&tenant).bind(&user).execute(pool).await.unwrap();
            sqlx::query("UPDATE tenant_memberships SET generation=7 WHERE tenant_id=$1 AND user_id=$2")
                .bind(&tenant).bind(&user).execute(pool).await.unwrap();
            family.generation = 7;
            credential.membership_generation = Some(7);
            let generations = CredentialGenerations { account: 7, membership: 7 };
            let now = Utc::now().timestamp();
            let established = FederatedIdentity {
                issuer: "https://upgrade.invalid".into(), subject: "established".into(),
                provider: "test".into(), client_id: "client".into(), tenant_id: tenant.clone(),
                user_id: user.clone(), email: None, email_verified: false, display_name: None,
                created_at: now - 300, authenticated_at: now - 300,
            };
            // 旧库夹具直接构造历史行，不在隐私迁移之前调用当前关联准入。
            sqlx::query("INSERT INTO federated_identities(issuer,subject,tenant_id,user_id,body,credential) VALUES($1,$2,$3,$4,$5,$6)")
                .bind(&established.issuer).bind(&established.subject).bind(&tenant).bind(&user)
                .bind(serde_json::to_string(&established).unwrap()).bind("retained-ciphertext")
                .execute(pool).await.unwrap();
            let client = memoswish_core::oauth::OAuthClient {
                id: new_id(), name: "Upgrade MCP".into(), redirect_uris: vec!["https://client.example/callback".into()],
                grant_types: vec!["authorization_code".into(), "refresh_token".into()], scopes: vec!["content:read".into()],
                auth_method: "none".into(), secret_hash: None, created_at: now, expires_at: now + 3600,
            };
            repo.oauth_register(&client).await.unwrap();
            let owner = repo.get_user(&tenant, &user).await.unwrap().unwrap();
            let code = crate::oauth_conformance::code(&repo, &owner, &client, now + 3600).await;
            let access = crate::oauth_conformance::token(&code, "access");
            let refresh = crate::oauth_conformance::token(&code, "refresh");
            assert!(repo.oauth_redeem(&tenant, &code, &[access.clone(), refresh.clone()], now).await.unwrap());

            // t=0 认证，t=299 发起，旧版错误地允许到 t=599；完成覆盖 t=300 与 t=400。
            let mut attempts = Vec::new();
            for native in [false, true] {
                for phase in 0..=2_i64 {
                    for completion in [now, now + 100] {
                        let attempt = LoginAttempt {
                            link_legacy_issued_at: None,
                            link_access_hash: None, id: new_id(), provider: "test".into(), state_hash: new_id(),
                            launch_hash: new_id(), browser_hash: new_id(), nonce: new_id(), verifier_ciphertext: "encrypted".into(),
                            client_id: "client".into(), return_uri: "dev.learntok:/callback".into(), app_state: "state".into(),
                            challenge: new_id(), native, link_tenant: Some(tenant.clone()), link_user: Some(user.clone()),
                            link_generation: Some(7), link_membership_generation: Some(7),
                            link_session_hash: Some("legacy-binding".into()), expires_at: now + 299,
                        };
                        let mut body = serde_json::to_value(&attempt).unwrap();
                        body.as_object_mut().unwrap().remove("link_access_hash");
                        sqlx::query("INSERT INTO oidc_attempts(id,state_hash,launch_hash,browser_hash,provider,phase,expires_at,body,tenant_id,user_id,sequence,membership_generation,identity_issuer,identity_subject) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,7,$11,$12)")
                            .bind(&attempt.id).bind(&attempt.state_hash).bind(&attempt.launch_hash).bind(&attempt.browser_hash)
                            .bind(&attempt.provider).bind(phase).bind(attempt.expires_at).bind(body.to_string())
                            .bind(&tenant).bind(&user).bind(&established.issuer).bind(&attempt.id)
                            .execute(pool).await.unwrap();
                        let identity = FederatedIdentity { subject: attempt.id.clone(), ..established.clone() };
                        let handoff = LoginHandoff {
                            attempt_id: Some(attempt.id.clone()), generation: 7, pending_identity: Some("encrypted-pending-link".into()),
                            link_session_hash: attempt.link_session_hash.clone(), hash: new_id(), provider: "test".into(),
                            tenant_id: tenant.clone(), user_id: user.clone(), challenge: attempt.challenge.clone(), expires_at: attempt.expires_at,
                        };
                        if phase == 2 {
                            repo.identity_handoff_insert(&handoff).await.unwrap();
                        }
                        assert!(repo.identity_attempt(&attempt.id, false).await.unwrap().is_some());
                        attempts.push((attempt, identity, handoff, completion));
                    }
                }
            }
            repo.identity_recent_auth(&tenant, &user, generations, "legacy-binding", now).await.unwrap();

            // 比较受保护行的全部列，保留已建立身份、授权、凭据、认证证据及非零世代。
            let protected = ["users", "user_profiles", "federated_identities", "oauth_clients", "oauth_grants",
                "oauth_authorization_codes", "oauth_tokens", "account_auth_epochs", "membership_generations",
                "tenant_memberships", "recent_authentication"];
            let mut before = Vec::new();
            for table in protected {
                before.push(pre_s21_snapshot(pool, table).await);
            }
            full.run(pool).await.unwrap();
            full.run(pool).await.unwrap();
            // 新时间列保留历史 unknown，不能用升级时刻冒充入队或清理起点。
            let known:i64=sqlx::query_scalar("SELECT COUNT(*) FROM background_jobs WHERE enqueued_at_ms IS NOT NULL").fetch_one(pool).await.unwrap();
            assert_eq!(known,0,"historical enqueue times must remain unknown");
            for (table, expected) in protected.iter().zip(&before) {
                assert_eq!(&pre_s21_snapshot(pool, table).await, expected, "upgrade changed {table}");
            }
            for (attempt, identity, handoff, completion) in attempts {
                assert!(completion >= now && completion < attempt.expires_at);
                assert!(repo.identity_attempt(&attempt.id, false).await.unwrap().is_none());
                assert!(repo.identity_attempt(&attempt.state_hash, true).await.unwrap().is_none());
                assert!(!repo.identity_launch(&attempt.id, &attempt.launch_hash, &attempt.browser_hash, completion).await.unwrap());
                let binding = if attempt.native { &attempt.launch_hash } else { &attempt.browser_hash };
                assert!(!repo.identity_claim(&attempt.id, "test", binding, attempt.native, completion).await.unwrap());
                assert!(repo.identity_handoff_consume(&handoff.hash, "test", &handoff.challenge, completion).await.unwrap().is_none());
                assert!(repo.identity_resolve(&identity, None, true, None, Some(generations), Some(&attempt.id)).await.is_err());
                assert!(repo.identity_complete(&attempt.id, &tenant, &user, generations, "upgrade-assurance", completion).await.is_err());
                assert!(repo.identity_complete_account(&attempt.id, &tenant, &user, 7, "upgrade-assurance", completion).await.is_err());
                assert!(repo.session_issue(&family, &credential, Some(&attempt.id)).await.is_err());
            }
            for table in ["oidc_attempts", "oidc_handoffs", "app_sessions", "app_session_credentials"] {
                let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}")).fetch_one(pool).await.unwrap();
                assert_eq!(count, 0, "pending link repair left rows in {table}");
            }
            let assurance: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recent_authentication WHERE hash='upgrade-assurance'")
                .fetch_one(pool).await.unwrap();
            assert_eq!(assurance, 0);
            let identities = repo.identity_list(&tenant, &user).await.unwrap();
            assert_eq!(identities.len(), 1);
            assert_eq!(identities[0].subject, established.subject);
            assert!(repo.membership_authorize(&tenant, &user, generations).await.is_ok());
            assert!(repo.oauth_token(&access.hash).await.unwrap().is_some());
            assert!(repo.oauth_token(&refresh.hash).await.unwrap().is_some());
            for (table, expected) in protected.iter().zip(&before) {
                assert_eq!(&pre_s21_snapshot(pool, table).await, expected, "rejected completion changed {table}");
            }
        }
    };
}
pub(crate) use upgrade_tests;

async fn prerequisites<R: Repository>(repo: &R) {
    let (f, workspace) = setup(repo).await;
    let root = credential(&f, None);
    repo.session_issue(&f, &root, None).await.unwrap();
    repo.session_select(&root.access_hash, &workspace).await.unwrap();
    let mut second = f.clone();
    second.id = new_id();
    let second_credential = credential(&second, None);
    repo.session_issue(&second, &second_credential, None).await.unwrap();
    let (foreign, foreign_credential) = setup(repo).await;
    repo.session_issue(&foreign, &foreign_credential, None).await.unwrap();
    let memberships = repo.session_memberships(&root.access_hash).await.unwrap();
    assert_eq!(memberships.len(), 1);
    assert_eq!(memberships[0].tenant_id, workspace.tenant_id.clone().unwrap());
    assert_eq!(memberships[0].role, "owner");
    assert!(repo.session_memberships(&workspace.access_hash).await.is_err());
    assert!(repo.session_revoke_all(&workspace.access_hash).await.is_err());
    assert!(repo.session_revoke_all("unknown").await.is_err());
    assert!(repo.session_access(&root.access_hash).await.is_ok());
    let api = memoswish_core::repo::ApiTokenRecord {
        id: new_id(),
        tenant_id: workspace.tenant_id.clone().unwrap(),
        user_id: f.user_id.clone(),
        name: "Preserved API".into(),
        token_hash: new_id(),
        generations: memoswish_core::CredentialGenerations { account: 0, membership: 0 },
        scopes: vec!["*".into()],
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    };
    repo.issue_api_token(&api).await.unwrap();
    let persisted_api = repo.find_api_token(&api.token_hash).await.unwrap().unwrap();
    let client = memoswish_core::oauth::OAuthClient {
        id: new_id(),
        name: "Independent MCP".into(),
        redirect_uris: vec!["https://client.example/callback".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        scopes: vec!["content:read".into()],
        auth_method: "none".into(),
        secret_hash: None,
        created_at: 10,
        expires_at: i64::MAX - 1,
    };
    repo.oauth_register(&client).await.unwrap();
    let user = repo.get_user(workspace.tenant_id.as_deref().unwrap(), &f.user_id).await.unwrap().unwrap();
    let code = crate::oauth_conformance::code(repo, &user, &client, f.expires_at).await;
    let mcp_access = crate::oauth_conformance::token(&code, "access");
    let mcp_refresh = crate::oauth_conformance::token(&code, "refresh");
    assert!(repo.oauth_redeem(&user.tenant_id, &code, &[mcp_access.clone(), mcp_refresh.clone()], 10).await.unwrap());
    // 两个先提交的族以及工作区凭据都受同一次账户撤销覆盖。
    repo.session_revoke_all(&root.access_hash).await.unwrap();
    for c in [&root, &workspace, &second_credential] {
        assert!(repo.session_access(&c.access_hash).await.is_err());
        assert!(repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.is_err());
    }
    assert!(
        repo.session_select(&root.access_hash, &credential(&f, workspace.tenant_id.clone().map(|t| (t, 0))))
            .await
            .is_err()
    );
    assert!(repo.session_access(&foreign_credential.access_hash).await.is_ok());
    assert_eq!(repo.account_generation(&f.user_id).await.unwrap(), 0);
    assert!(repo.oauth_token(&mcp_access.hash).await.unwrap().is_some());
    let next = crate::oauth_conformance::token(&code, "refresh");
    assert!(repo.oauth_rotate(&user.tenant_id, &mcp_refresh, &[next], 10).await.unwrap());
    assert_eq!(repo.find_api_token(&api.token_hash).await.unwrap().unwrap(), persisted_api);
    // 撤销后重新交互登录可以签发全新族，无需等待时间窗口。
    let mut fresh = f.clone();
    fresh.id = new_id();
    let fresh_credential = credential(&fresh, None);
    repo.session_issue(&fresh, &fresh_credential, None).await.unwrap();
    assert!(repo.session_access(&fresh_credential.access_hash).await.is_ok());
    repo.session_revoke_all(&fresh_credential.access_hash).await.unwrap();
    assert!(repo.session_access(&fresh_credential.access_hash).await.is_err());

    // 工作区发现允许零成员，不把已删除的成员摘要变成权限。
    let (f, c) = setup(repo).await;
    let root = credential(&f, None);
    repo.session_issue(&f, &root, None).await.unwrap();
    let tenant = c.tenant_id.as_deref().unwrap();
    repo.membership_remove(tenant, &f.user_id).await.unwrap();
    assert!(repo.session_memberships(&root.access_hash).await.unwrap().is_empty());
    repo.membership_join(tenant, &f.user_id, Role::Learner).await.unwrap();
    assert!(repo.session_select(&root.access_hash, &c).await.is_err());
    let current = repo.session_memberships(&root.access_hash).await.unwrap();
    assert_eq!(current[0].role, "learner");
    let extra =
        TenantRecord { id: new_id(), name: "Second workspace".into(), plan: "free".into(), created_at: Utc::now() };
    repo.upsert_tenant(&extra).await.unwrap();
    repo.membership_join(&extra.id, &f.user_id, Role::Editor).await.unwrap();
    let summaries = repo.session_memberships(&root.access_hash).await.unwrap();
    assert_eq!(summaries.len(), 2);
    assert!(summaries[0].tenant_id < summaries[1].tenant_id);
    assert!(summaries.iter().all(|s| s.tenant_id == tenant || s.tenant_id == extra.id));
}

async fn link_ack(repo: &dyn Repository) {
    let (f, c, i, a) = staged_link(repo).await;
    let before = repo.session_list(&c.access_hash).await.unwrap();
    let original = repo.session_access(&c.access_hash).await.unwrap();
    // ACK 保留原凭据和认证时刻，不创建额外会话族。
    repo.session_link_ack(&c.access_hash, &a.id).await.unwrap();
    assert_eq!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().len(), 1);
    assert_eq!(repo.session_list(&c.access_hash).await.unwrap(), before);
    let after = repo.session_access(&c.access_hash).await.unwrap();
    assert_eq!(after.family, original.family);
    assert_eq!(after.credential, original.credential);
    assert!(repo.session_link_ack(&c.access_hash, &a.id).await.is_err());
    assert!(repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.is_ok());
    for action in ["rotate", "logout", "remove", "wrong-session"] {
        let (f, c, i, a) = staged_link(repo).await;
        let mut hash = c.access_hash.clone();
        match action {
            "rotate" => {
                repo.session_rotate(&c.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.unwrap();
            }
            "logout" => {
                repo.session_revoke(&c.access_hash, &f.id).await.unwrap();
            }
            "remove" => {
                repo.membership_remove(&i.tenant_id, &f.user_id).await.unwrap();
            }
            _ => {
                let (other, c) = setup(repo).await;
                repo.session_issue(&other, &c, None).await.unwrap();
                hash = c.access_hash;
            }
        }
        assert!(repo.session_link_ack(&hash, &a.id).await.is_err(), "{action}");
        assert!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().is_empty());
    }
}

macro_rules! prerequisites_tests {
    ($repo:ident, $pool:ty, $migrations:literal, $reject_fence:expr, $drop_fence:expr) => {
        async fn s21b_pending_links_recheck_logout(pool: &$pool) {
            use memoswish_core::ids::new_id;
            use memoswish_core::{
                CredentialGenerations,
                identity::IdentityRepo,
                oauth::{OAuthIndex, OAuthRepo},
                repo::AuthRepo,
                session::SessionRepo,
            };
            let repo = $repo {
                observer: memoswish_core::observability::noop(), pool: pool.clone(),
                learning_gate: None,
                content_gate: None,
                feed_gate: None,
                lifecycle_gate: None,
            };
            for legacy in [true, false] {
                for operation in ["opaque", "workspace", "account", "stage", "insert", "ack", "missing-evidence"] {
                    let (f, c, i, mut a) = crate::session_conformance::staged_link_with_legacy(&repo, legacy).await;
                    let mut root_family = f.clone();
                    root_family.id = new_id();
                    let root = crate::session_conformance::credential(&root_family, None);
                    repo.session_issue(&root_family, &root, None).await.unwrap();
                    let api = memoswish_core::repo::ApiTokenRecord {
                        id: new_id(),
                        tenant_id: i.tenant_id.clone(),
                        user_id: f.user_id.clone(),
                        name: "Independent API".into(),
                        token_hash: new_id(),
                        generations: CredentialGenerations { account: 0, membership: 0 },
                        scopes: vec!["*".into()],
                        created_at: Utc::now(),
                        expires_at: None,
                        last_used_at: None,
                        revoked: false,
                    };
                    repo.issue_api_token(&api).await.unwrap();
                    let client = memoswish_core::oauth::OAuthClient {
                        id: new_id(),
                        name: "Independent MCP".into(),
                        redirect_uris: vec!["https://client.example/callback".into()],
                        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                        scopes: vec!["content:read".into()],
                        auth_method: "none".into(),
                        secret_hash: None,
                        created_at: 10,
                        expires_at: i64::MAX - 1,
                    };
                    repo.oauth_register(&client).await.unwrap();
                    let user = repo.get_user(&i.tenant_id, &f.user_id).await.unwrap().unwrap();
                    let code = crate::oauth_conformance::code(&repo, &user, &client, f.expires_at).await;
                    let access = crate::oauth_conformance::token(&code, "access");
                    let refresh = crate::oauth_conformance::token(&code, "refresh");
                    assert!(
                        repo.oauth_redeem(&i.tenant_id, &code, &[access.clone(), refresh.clone()], 10).await.unwrap()
                    );
                    let protected = [
                        "api_tokens",
                        "oauth_tokens",
                        "oauth_grants",
                        "account_auth_epochs",
                        "tenant_memberships",
                        "recent_authentication",
                        "federated_identities",
                        "oidc_attempts",
                        "oidc_handoffs",
                    ];
                    let families: i64 =
                        sqlx::query_scalar("SELECT COUNT(*) FROM app_sessions").fetch_one(pool).await.unwrap();
                    let credentials: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_session_credentials")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                    if operation == "insert" {
                        a.id = new_id();
                        a.state_hash = new_id();
                        a.launch_hash = new_id();
                    }
                    if operation == "missing-evidence" {
                        // 模拟升级前 JSON，缺少时间证据不能在屏障后恢复关联权限。
                        let mut body = serde_json::to_value(&a).unwrap();
                        body.as_object_mut().unwrap().remove("link_legacy_issued_at");
                        body.as_object_mut().unwrap().remove("link_access_hash");
                        sqlx::query("UPDATE oidc_attempts SET body=$1 WHERE id=$2")
                            .bind(body.to_string())
                            .bind(&a.id)
                            .execute(pool)
                            .await
                            .unwrap();
                    }
                    let mut snapshots = Vec::new();
                    for table in protected {
                        snapshots.push(pre_s21_snapshot(pool, table).await);
                    }
                    let mut fresh = f.clone();
                    fresh.id = new_id();
                    let fresh_c = crate::session_conformance::credential(&fresh, None);
                    let generations = CredentialGenerations { account: 0, membership: 0 };
                    let (staged, waiting) = tokio::sync::oneshot::channel();
                    let (resume, paused) = tokio::sync::oneshot::channel();
                    let completion = async {
                        staged.send(()).unwrap();
                        paused.await.unwrap();
                        match operation {
                            "insert" => repo.identity_attempt_insert(&a).await,
                            "stage" => repo
                                .identity_resolve(&i, None, true, None, Some(generations), Some(&a.id))
                                .await
                                .map(|_| ()),
                            "workspace" => {
                                repo.identity_complete(
                                    &a.id,
                                    &i.tenant_id,
                                    &f.user_id,
                                    generations,
                                    "rejected-assurance",
                                    f.auth_time,
                                )
                                .await
                            }
                            "account" => {
                                repo.identity_complete_account(
                                    &a.id,
                                    &i.tenant_id,
                                    &f.user_id,
                                    0,
                                    "rejected-assurance",
                                    f.auth_time,
                                )
                                .await
                            }
                            "ack" => repo.session_link_ack(&c.access_hash, &a.id).await,
                            _ => repo.session_issue(&fresh, &fresh_c, Some(&a.id)).await,
                        }
                    };
                    let logout = async {
                        waiting.await.unwrap();
                        repo.session_revoke_all(&root.access_hash).await.unwrap();
                        resume.send(()).unwrap();
                    };
                    let (result, ()) = tokio::join!(completion, logout);
                    assert!(
                        matches!(result, Err(memoswish_core::CoreError::Unauthorized(_))),
                        "legacy={legacy} operation={operation}"
                    );
                    assert!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().is_empty());
                    assert_eq!(
                        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM app_sessions")
                            .fetch_one(pool)
                            .await
                            .unwrap(),
                        families
                    );
                    assert_eq!(
                        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM app_session_credentials")
                            .fetch_one(pool)
                            .await
                            .unwrap(),
                        credentials
                    );
                    assert!(repo.session_access(&fresh_c.access_hash).await.is_err());
                    for (table, snapshot) in protected.iter().zip(snapshots) {
                        assert_eq!(
                            pre_s21_snapshot(pool, table).await,
                            snapshot,
                            "{table}: legacy={legacy} operation={operation}"
                        );
                    }
                    assert!(repo.find_api_token(&api.token_hash).await.unwrap().is_some());
                    assert!(repo.oauth_token(&access.hash).await.unwrap().is_some());
                    assert!(repo.oauth_token(&refresh.hash).await.unwrap().is_some());
                    let next = crate::oauth_conformance::token(&code, "refresh");
                    assert!(repo.oauth_rotate(&i.tenant_id, &refresh, &[next], 10).await.unwrap());
                }
                // 完成先提交时保留关联结果；随后注销仍覆盖完成中新签发的族。
                for profile in ["workspace", "account", "opaque", "ack"] {
                    if legacy && profile == "ack" {
                        continue;
                    }
                    let (f, c, i, a) = crate::session_conformance::staged_link_with_legacy(&repo, legacy).await;
                    let mut root_family = f.clone();
                    root_family.id = new_id();
                    let root = crate::session_conformance::credential(&root_family, None);
                    repo.session_issue(&root_family, &root, None).await.unwrap();
                    let mut fresh = f.clone();
                    fresh.id = new_id();
                    let fresh_c = crate::session_conformance::credential(&fresh, None);
                    match profile {
                        "workspace" => repo
                            .identity_complete(
                                &a.id,
                                &i.tenant_id,
                                &f.user_id,
                                CredentialGenerations { account: 0, membership: 0 },
                                "success-assurance",
                                f.auth_time,
                            )
                            .await
                            .unwrap(),
                        "account" => repo
                            .identity_complete_account(
                                &a.id,
                                &i.tenant_id,
                                &f.user_id,
                                0,
                                "success-assurance",
                                f.auth_time,
                            )
                            .await
                            .unwrap(),
                        "opaque" => repo.session_issue(&fresh, &fresh_c, Some(&a.id)).await.unwrap(),
                        _ => repo.session_link_ack(&c.access_hash, &a.id).await.unwrap(),
                    }
                    assert_eq!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().len(), 1);
                    repo.session_revoke_all(&root.access_hash).await.unwrap();
                    assert!(repo.session_access(&c.access_hash).await.is_err());
                    assert!(repo.session_access(&fresh_c.access_hash).await.is_err());
                    assert_eq!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().len(), 1);
                }
            }
        }

        async fn s21b_atomicity(pool: &$pool) {
            use memoswish_core::{identity::IdentityRepo, lifecycle::LifecycleRepo, session::SessionRepo};
            let repo = $repo {
                observer: memoswish_core::observability::noop(), pool: pool.clone(),
                learning_gate: None,
                content_gate: None,
                feed_gate: None,
                lifecycle_gate: None,
            };
            let (family, mut workspace) = crate::session_conformance::setup(&repo).await;
            workspace.tenant_id = None;
            workspace.membership_generation = None;
            repo.session_issue(&family, &workspace, None).await.unwrap();
            // 触发器在族撤销之后拒绝屏障写入，整个操作必须回滚。
            sqlx::raw_sql($reject_fence).execute(pool).await.unwrap();
            assert!(repo.session_revoke_all(&workspace.access_hash).await.is_err());
            assert!(repo.session_access(&workspace.access_hash).await.is_ok());
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM app_session_fences WHERE user_id=$1")
                    .bind(&family.user_id)
                    .fetch_one(pool)
                    .await
                    .unwrap(),
                0
            );
            sqlx::query($drop_fence).execute(pool).await.unwrap();
            repo.session_revoke_all(&workspace.access_hash).await.unwrap();
            let fence: i64 = sqlx::query_scalar("SELECT revoked_through FROM app_session_fences WHERE user_id=$1")
                .bind(&family.user_id)
                .fetch_one(pool)
                .await
                .unwrap();
            for (iat, valid) in [(fence - 1, false), (fence, false), (fence + 1, true)] {
                for profile in [None, Some((repo.memberships(&family.user_id).await.unwrap()[0].tenant_id.clone(), 0))]
                {
                    assert_eq!(
                        repo.legacy_session_authorize(
                            &family.user_id,
                            0,
                            iat,
                            Some(fence),
                            profile.as_ref().map(|(t, m)| (t.as_str(), *m))
                        )
                        .await
                        .is_ok(),
                        valid
                    );
                }
            }
            // 模拟时钟倒退，已有更高屏障不能被较低数据库时间覆盖。
            sqlx::query("UPDATE app_session_fences SET revoked_through=$1 WHERE user_id=$2")
                .bind(fence + 100)
                .bind(&family.user_id)
                .execute(pool)
                .await
                .unwrap();
            let mut fresh = family.clone();
            fresh.id = memoswish_core::ids::new_id();
            let fresh_c = crate::session_conformance::credential(&fresh, None);
            repo.session_issue(&fresh, &fresh_c, None).await.unwrap();
            repo.session_revoke_all(&fresh_c.access_hash).await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT revoked_through FROM app_session_fences WHERE user_id=$1")
                    .bind(&family.user_id)
                    .fetch_one(pool)
                    .await
                    .unwrap(),
                fence + 100
            );
            // 凭据唯一键失败发生在租户/账户/成员/族写入之后，必须整体撤销注册。
            let (template, c) = crate::session_conformance::setup(&repo).await;
            let mut user = repo.get_user(c.tenant_id.as_deref().unwrap(), &template.user_id).await.unwrap().unwrap();
            let mut tenant = repo.get_tenant(&user.tenant_id).await.unwrap().unwrap();
            tenant.id = memoswish_core::ids::new_id();
            user.tenant_id = tenant.id.clone();
            user.id = memoswish_core::ids::new_id();
            user.email = format!("{}@test.invalid", user.id);
            let mut registration = template.clone();
            registration.id = memoswish_core::ids::new_id();
            registration.user_id = user.id.clone();
            let mut collision = crate::session_conformance::credential(&registration, None);
            collision.refresh_hash = workspace.refresh_hash.clone();
            assert!(repo.session_register(&tenant, &user, &registration, &collision).await.is_err());
            assert!(repo.get_tenant(&tenant.id).await.unwrap().is_none());
            assert!(repo.account_by_id(&user.id).await.unwrap().is_none());
            assert!(repo.memberships(&user.id).await.unwrap().is_empty());
            assert!(repo.account_generation(&user.id).await.is_err());
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM app_sessions WHERE id=$1")
                    .bind(&registration.id)
                    .fetch_one(pool)
                    .await
                    .unwrap(),
                0
            );
            collision.refresh_hash = memoswish_core::ids::new_id();
            repo.session_register(&tenant, &user, &registration, &collision).await.unwrap();
            assert!(repo.session_access(&collision.access_hash).await.is_ok());
            assert_eq!(repo.account_generation(&user.id).await.unwrap(), 0);
            assert_eq!(repo.memberships(&user.id).await.unwrap()[0].generation, 0);
            assert_eq!(repo.memberships(&user.id).await.unwrap()[0].role, memoswish_core::Role::Owner);
            let workspace = crate::session_conformance::credential(&registration, Some((tenant.id.clone(), 0)));
            repo.session_select(&collision.access_hash, &workspace).await.unwrap();
            let principal = memoswish_core::Principal {
                tenant_id: tenant.id.clone(),
                user_id: user.id.clone(),
                role: memoswish_core::Role::Owner,
                session_access_hash: Some(workspace.access_hash.clone()),
                ..memoswish_core::Principal::local_owner("session")
            };
            let deck = memoswish_protocol::examples::sample_deck();
            let card = memoswish_protocol::examples::sample_card();
            repo.insert_deck_with_cards(&tenant.id, &deck, std::slice::from_ref(&card)).await.unwrap();
            repo.delete_card_if_revision(&tenant.id, &card.id, Some(card.revision)).await.unwrap();
            assert!(repo.insert_deck_with_cards(&tenant.id, &deck, std::slice::from_ref(&card)).await.is_err());
            let mut duplicate_tenant = tenant.clone();
            duplicate_tenant.id = memoswish_core::ids::new_id();
            let mut duplicate_user = user.clone();
            duplicate_user.id = memoswish_core::ids::new_id();
            duplicate_user.tenant_id = duplicate_tenant.id.clone();
            let mut duplicate_family = registration.clone();
            duplicate_family.id = memoswish_core::ids::new_id();
            duplicate_family.user_id = duplicate_user.id.clone();
            let duplicate_c = crate::session_conformance::credential(&duplicate_family, None);
            assert!(
                repo.session_register(&duplicate_tenant, &duplicate_user, &duplicate_family, &duplicate_c)
                    .await
                    .is_err()
            );
            assert!(repo.get_tenant(&duplicate_tenant.id).await.unwrap().is_none());
            assert_eq!(repo.session_memberships(&collision.access_hash).await.unwrap().len(), 1);
            // 新注册的初始所有者可走正常生命周期入口，删除工作区后账户根仍保留。
            repo.delete_workspace(
                &principal,
                &memoswish_core::lifecycle::DeleteWorkspace { confirmed_tenant_id: tenant.id.clone() },
            )
            .await
            .unwrap();
            assert!(repo.get_tenant(&tenant.id).await.unwrap().is_none());
            assert!(repo.account_by_id(&user.id).await.unwrap().is_some());
            assert!(repo.session_memberships(&collision.access_hash).await.unwrap().is_empty());
            sqlx::query("UPDATE app_session_credentials SET expires_at=0 WHERE access_hash=$1")
                .bind(&collision.access_hash)
                .execute(pool)
                .await
                .unwrap();
            assert!(repo.session_revoke_all(&collision.access_hash).await.is_err());
            assert!(repo.session_memberships(&collision.access_hash).await.is_err());
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM app_session_fences WHERE user_id=$1")
                    .bind(&user.id)
                    .fetch_one(pool)
                    .await
                    .unwrap(),
                0
            );
            let (f, c, i, a) = crate::session_conformance::staged_link(&repo).await;
            let count_before: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM app_session_credentials WHERE session_id=$1")
                    .bind(&f.id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            // 证据缺失时 ACK 也不能补发五分钟关联权限。
            sqlx::query("DELETE FROM recent_authentication WHERE hash=$1")
                .bind(&c.assurance_hash)
                .execute(pool)
                .await
                .unwrap();
            let recent_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recent_authentication WHERE user_id=$1")
                .bind(&f.user_id)
                .fetch_one(pool)
                .await
                .unwrap();
            repo.session_link_ack(&c.access_hash, &a.id).await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM app_session_credentials WHERE session_id=$1")
                    .bind(&f.id)
                    .fetch_one(pool)
                    .await
                    .unwrap(),
                count_before
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM recent_authentication WHERE user_id=$1")
                    .bind(&f.user_id)
                    .fetch_one(pool)
                    .await
                    .unwrap(),
                recent_before
            );
            assert_eq!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().len(), 1);
            let (f, c, i, a) = crate::session_conformance::staged_link(&repo).await;
            sqlx::query("UPDATE oidc_attempts SET expires_at=0 WHERE id=$1").bind(&a.id).execute(pool).await.unwrap();
            assert!(repo.session_link_ack(&c.access_hash, &a.id).await.is_err());
            assert!(repo.identity_list(&i.tenant_id, &f.user_id).await.unwrap().is_empty());
            assert!(repo.session_access(&c.access_hash).await.is_ok());
        }

        async fn s21b_populated_upgrade(pool: &$pool) {
            use memoswish_core::session::SessionRepo;
            let full = sqlx::migrate!($migrations);
            crate::foundation_conformance::through(&full, 20).run(pool).await.unwrap();
            let repo = $repo {
                observer: memoswish_core::observability::noop(), pool: pool.clone(),
                learning_gate: None,
                content_gate: None,
                feed_gate: None,
                lifecycle_gate: None,
            };
            crate::session_conformance::run(&repo).await;
            let (api_owner, api_workspace) = crate::session_conformance::setup(&repo).await;
            let api = memoswish_core::repo::ApiTokenRecord {
                id: memoswish_core::ids::new_id(),
                tenant_id: api_workspace.tenant_id.unwrap(),
                user_id: api_owner.user_id,
                name: "Upgrade API".into(),
                token_hash: memoswish_core::ids::new_id(),
                generations: memoswish_core::CredentialGenerations { account: 0, membership: 0 },
                scopes: vec!["content:read".into()],
                created_at: Utc::now(),
                expires_at: None,
                last_used_at: None,
                revoked: false,
            };
            repo.issue_api_token(&api).await.unwrap();
            // 保留升级前已有身份的全列快照；当前关联流程在完整迁移后执行原有断言。
            let historical = memoswish_core::identity::FederatedIdentity {
                client_id:"client".into(),issuer:"https://s21b-upgrade.invalid".into(),subject:memoswish_core::ids::new_id(),
                provider:"test".into(),tenant_id:api.tenant_id.clone(),user_id:api.user_id.clone(),
                email:None,email_verified:false,display_name:None,created_at:Utc::now().timestamp(),authenticated_at:Utc::now().timestamp(),
            };
            sqlx::query("INSERT INTO federated_identities(issuer,subject,tenant_id,user_id,body,credential) VALUES($1,$2,$3,$4,$5,$6)")
                .bind(&historical.issuer).bind(&historical.subject).bind(&historical.tenant_id).bind(&historical.user_id)
                .bind(serde_json::to_string(&historical).unwrap()).bind("historical-ciphertext")
                .execute(pool).await.unwrap();
            let synthesis = memoswish_core::ids::new_id();
            sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES($1,$2,'tts_synthesis',$2,'{}',5,0)")
                .bind(&api.tenant_id).bind(&synthesis).execute(pool).await.unwrap();
            sqlx::query("INSERT INTO tts_syntheses(tenant_id,id,work) VALUES($1,$2,'{}')")
                .bind(&api.tenant_id).bind(&synthesis).execute(pool).await.unwrap();
            sqlx::query("INSERT INTO tts_requesters(tenant_id,id,synthesis_id,user_id,account_generation,membership_generation,content_permission) VALUES($1,$2,$2,$3,0,0,0)")
                .bind(&api.tenant_id).bind(&synthesis).bind(&api.user_id).execute(pool).await.unwrap();
            let protected = [
                "tenants",
                "users",
                "user_profiles",
                "account_auth_epochs",
                "tenant_memberships",
                "membership_generations",
                "app_sessions",
                "app_session_credentials",
                "federated_identities",
                "oauth_clients",
                "oauth_grants",
                "oauth_tokens",
                "api_tokens",
                "recent_authentication",
                "background_jobs",
                "tts_syntheses",
            ];
            let mut before = Vec::new();
            for table in protected {
                before.push(pre_s21_snapshot(pool, table).await);
            }
            full.run(pool).await.unwrap();
            let scope: String = sqlx::query_scalar("SELECT work_scope FROM background_jobs WHERE tenant_id=$1 AND id=$2").bind(&api.tenant_id).bind(&synthesis).fetch_one(pool).await.unwrap();
            assert_eq!(scope,"tenant");
            let historical_iat: Option<i64> = sqlx::query_scalar("SELECT legacy_issued_at FROM tts_requesters WHERE tenant_id=$1 AND id=$2 AND user_id=$3 AND outcome='pending'")
                .bind(&api.tenant_id).bind(&synthesis).bind(&api.user_id).fetch_one(pool).await.unwrap();
            assert_eq!(historical_iat, None);
            for (table, expected) in protected.iter().zip(before) {
                assert_eq!(pre_s21_snapshot(pool, table).await, expected, "upgrade changed {table}");
            }
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM app_session_fences").fetch_one(pool).await.unwrap(),
                0
            );
            let (f, _) = crate::session_conformance::setup(&repo).await;
            let root = crate::session_conformance::credential(&f, None);
            repo.session_issue(&f, &root, None).await.unwrap();
            repo.session_revoke_all(&root.access_hash).await.unwrap();
            let restarted = $repo {
                observer: memoswish_core::observability::noop(), pool: pool.clone(),
                learning_gate: None,
                content_gate: None,
                feed_gate: None,
                lifecycle_gate: None,
            };
            assert!(restarted.session_access(&root.access_hash).await.is_err());
            assert!(restarted.legacy_session_authorize(&f.user_id, 0, 0, None, None).await.is_err());
            crate::session_conformance::links(&repo).await;
        }
    };
}
pub(crate) use prerequisites_tests;

async fn logout_interleavings<R: Repository>(repo: &R) {
    // 旋转或选择即使先成功，也不能在注销提交后留下可用后继。
    for rotate in [true, false] {
        let (f, workspace) = setup(repo).await;
        let root = credential(&f, None);
        repo.session_issue(&f, &root, None).await.unwrap();
        let (access, refresh, assurance) = (new_id(), new_id(), new_id());
        if rotate {
            let (logout, _) = tokio::join!(
                repo.session_revoke_all(&root.access_hash),
                repo.session_rotate(&root.refresh_hash, &access, &refresh, &assurance, 600)
            );
            logout.unwrap();
            assert!(repo.session_access(&access).await.is_err());
        } else {
            let (logout, _) = tokio::join!(
                repo.session_revoke_all(&root.access_hash),
                repo.session_select(&root.access_hash, &workspace)
            );
            logout.unwrap();
            assert!(repo.session_access(&workspace.access_hash).await.is_err());
        }
    }
    let (f, _) = setup(repo).await;
    let root = credential(&f, None);
    repo.session_issue(&f, &root, None).await.unwrap();
    let mut fresh = f.clone();
    fresh.id = new_id();
    let c = credential(&fresh, None);
    let (logout, issue) =
        tokio::join!(repo.session_revoke_all(&root.access_hash), repo.session_issue(&fresh, &c, None));
    logout.unwrap();
    issue.unwrap();
    // 两种提交次序的结果均持久化，凭据和族的撤销状态保持一致。
    let listed = repo.session_access(&c.access_hash).await;
    if listed.is_ok() {
        repo.session_revoke_all(&c.access_hash).await.unwrap();
    }
    assert!(repo.session_access(&root.access_hash).await.is_err());
    assert!(repo.session_access(&c.access_hash).await.is_err());
}
