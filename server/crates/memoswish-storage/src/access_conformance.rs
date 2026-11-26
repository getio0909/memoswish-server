//! 两库执行相同的所有权、世代、分页与撤销竞态断言。
use chrono::Utc;
use memoswish_core::{Role, ids::new_id, oauth::*, repo::*, session::*};

pub(crate) async fn run<R: Repository>(repo: &R) -> (SessionCredential, SessionCredential, String, String) {
    let (family, workspace) = crate::session_conformance::setup(repo).await;
    let tenant = workspace.tenant_id.clone().unwrap();
    let root = crate::session_conformance::credential(&family, None);
    repo.session_issue(&family, &root, None).await.unwrap();
    repo.session_select(&root.access_hash, &workspace).await.unwrap();
    let user = repo.get_user(&tenant, &family.user_id).await.unwrap().unwrap();
    mixed_scope_admission(repo).await;
    let other =
        UserRecord { id: new_id(), email: format!("{}@test.invalid", new_id()), role: Role::Admin, ..user.clone() };
    repo.insert_user(&other).await.unwrap();
    let mut foreign = family.clone();
    foreign.id = new_id();
    foreign.user_id = other.id.clone();
    let foreign_root = crate::session_conformance::credential(&foreign, None);
    repo.session_issue(&foreign, &foreign_root, None).await.unwrap();
    let (cross, cross_workspace) = crate::session_conformance::setup(repo).await;
    let cross_root = crate::session_conformance::credential(&cross, None);
    repo.session_issue(&cross, &cross_root, None).await.unwrap();
    assert!(repo.access_page(&workspace.access_hash, AccessKind::Sessions, "", 50).await.is_err());
    for (after, limit) in [("", 0), ("", 101), ("../other", 50)] {
        assert!(repo.access_page(&root.access_hash, AccessKind::Sessions, after, limit).await.is_err());
    }
    let page = repo.access_page(&root.access_hash, AccessKind::Sessions, "", 1).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, family.id);
    assert_eq!(page.items[0].current, Some(true));
    assert!(!repo.access_revoke(&root.access_hash, AccessKind::Sessions, None, &foreign.id).await.unwrap());
    assert!(!repo.access_revoke(&foreign_root.access_hash, AccessKind::Sessions, None, &family.id).await.unwrap());
    let token = ApiTokenRecord {
        id: new_id(),
        tenant_id: tenant.clone(),
        user_id: family.user_id.clone(),
        name: "Owner integration".into(),
        token_hash: "hash-sentinel-never-list".into(),
        generations: memoswish_core::CredentialGenerations { account: 0, membership: 0 },
        scopes: vec!["content:read".into()],
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    };
    repo.issue_api_token(&token).await.unwrap();
    let other_token = ApiTokenRecord { id: new_id(), user_id: other.id.clone(), token_hash: new_id(), ..token.clone() };
    repo.issue_api_token(&other_token).await.unwrap();
    let cross_token = ApiTokenRecord {
        id: new_id(),
        tenant_id: cross_workspace.tenant_id.clone().unwrap(),
        user_id: cross.user_id.clone(),
        token_hash: new_id(),
        ..token.clone()
    };
    repo.issue_api_token(&cross_token).await.unwrap();
    let page = repo.access_page(&root.access_hash, AccessKind::ApiTokens, "", 50).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, token.id);
    assert_eq!(page.items[0].status, "active");
    assert!(!serde_json::to_string(&page).unwrap().contains(&token.token_hash));
    assert!(repo.access_page(&token.token_hash, AccessKind::Sessions, "", 50).await.is_err());
    assert!(repo.access_revoke(&root.access_hash, AccessKind::ApiTokens, None, &token.id).await.is_err());
    assert!(!repo.access_revoke(&root.access_hash, AccessKind::ApiTokens, Some("wrong"), &token.id).await.unwrap());
    assert!(
        !repo.access_revoke(&root.access_hash, AccessKind::ApiTokens, Some(&tenant), &other_token.id).await.unwrap()
    );
    assert!(
        !repo
            .access_revoke(&root.access_hash, AccessKind::ApiTokens, Some(&cross_token.tenant_id), &cross_token.id)
            .await
            .unwrap()
    );
    repo.membership_join(&cross_token.tenant_id, &user.id, Role::Owner).await.unwrap();
    let own_cross =
        ApiTokenRecord { id: new_id(), user_id: user.id.clone(), token_hash: new_id(), ..cross_token.clone() };
    repo.issue_api_token(&own_cross).await.unwrap();
    let rows = repo.access_page(&root.access_hash, AccessKind::ApiTokens, "", 50).await.unwrap();
    assert_eq!(rows.items.len(), 2);
    assert!(
        rows.items.iter().any(|r| r.id == own_cross.id && r.tenant_id.as_deref() == Some(own_cross.tenant_id.as_str()))
    );
    assert!(!repo.access_revoke(&root.access_hash, AccessKind::ApiTokens, Some(&tenant), &own_cross.id).await.unwrap());
    assert!(!repo.find_api_token(&own_cross.token_hash).await.unwrap().unwrap().revoked);
    let client = OAuthClient {
        id: new_id(),
        name: "Agent".into(),
        redirect_uris: vec!["https://agent.invalid/cb".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        scopes: vec!["content:read".into()],
        auth_method: "none".into(),
        secret_hash: None,
        created_at: 10,
        expires_at: i64::MAX - 1,
    };
    repo.oauth_register(&client).await.unwrap();
    let code = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 2).await;
    let other_code = crate::oauth_conformance::code(repo, &other, &client, i64::MAX - 2).await;
    let untouched = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 2).await;
    assert_eq!(repo.access_page(&root.access_hash, AccessKind::Grants, "", 50).await.unwrap().items.len(), 2);
    assert!(
        !repo.access_revoke(&root.access_hash, AccessKind::Grants, Some(&tenant), &other_code.grant.id).await.unwrap()
    );
    assert!(!repo.access_revoke(&root.access_hash, AccessKind::Grants, Some("wrong"), &code.grant.id).await.unwrap());
    // 两种锁顺序都必须收敛；撤销提交后，已兑换的后继也不可用。
    let issued = crate::oauth_conformance::token(&code, "access");
    let rows = [issued.clone()];
    let (revoked, exchange) = tokio::join!(
        repo.access_revoke(&root.access_hash, AccessKind::Grants, Some(&tenant), &code.grant.id),
        repo.oauth_redeem(&tenant, &code, &rows, Utc::now().timestamp())
    );
    assert!(revoked.unwrap());
    assert!(exchange.is_ok());
    assert!(repo.oauth_token(&issued.hash).await.unwrap().is_none());
    assert!(!repo.oauth_redeem(&tenant, &code, &rows, Utc::now().timestamp()).await.unwrap());
    let parent = crate::oauth_conformance::token(&untouched, "refresh");
    repo.oauth_redeem(&tenant, &untouched, std::slice::from_ref(&parent), Utc::now().timestamp()).await.unwrap();
    let held_access = crate::oauth_conformance::token(&untouched, "access");
    // 已签发 access 和保留主体在 refresh 竞态前有效，撤销后不能继续使用。
    let held = memoswish_core::Principal {
        tenant_id: tenant.clone(),
        user_id: user.id.clone(),
        role: Role::Owner,
        scopes: Some(held_access.scopes.clone()),
        via: "mcp_oauth".into(),
        session_access_hash: Some(format!("oauth:{}", held_access.hash)),
        auth_generation: Some(0),
        membership_generation: Some(0),
        legacy_issued_at: None,
    };
    let another = crate::oauth_conformance::code(repo, &user, &client, i64::MAX - 2).await;
    let held_access = OAuthToken { grant: another.grant.clone(), ..held_access };
    let held = memoswish_core::Principal { session_access_hash: Some(format!("oauth:{}", held_access.hash)), ..held };
    repo.oauth_redeem(&tenant, &another, std::slice::from_ref(&held_access), Utc::now().timestamp()).await.unwrap();
    repo.access_authorize(&tenant, &held).await.unwrap();
    repo.library_page(&held, &memoswish_protocol::LibraryQuery::default()).await.unwrap();
    repo.review_history(&held, &memoswish_protocol::LibraryQuery::default()).await.unwrap();
    repo.access_revoke(&root.access_hash, AccessKind::Grants, Some(&tenant), &another.grant.id).await.unwrap();
    assert!(repo.access_authorize(&tenant, &held).await.is_err());
    for error in [
        repo.library_page(&held, &memoswish_protocol::LibraryQuery::default()).await.unwrap_err(),
        repo.review_history(&held, &memoswish_protocol::LibraryQuery::default()).await.unwrap_err(),
    ] {
        assert_eq!(error.http_status(), 401);
    }
    let child = crate::oauth_conformance::token(&untouched, "access");
    let children = [child.clone()];
    let (revoke, rotate) = tokio::join!(
        repo.access_revoke(&root.access_hash, AccessKind::Grants, Some(&tenant), &untouched.grant.id),
        repo.oauth_rotate(&tenant, &parent, &children, Utc::now().timestamp())
    );
    assert!(revoke.unwrap());
    assert!(rotate.is_ok());
    assert!(repo.oauth_token(&child.hash).await.unwrap().is_none());
    // 独立 App 族在并发刷新后仍整体撤销，当前族及其他用户不受影响。
    let mut target = family.clone();
    target.id = new_id();
    let target_credential = crate::session_conformance::credential(&target, None);
    repo.session_issue(&target, &target_credential, None).await.unwrap();
    let next_access = new_id();
    let next_refresh = new_id();
    let assurance = new_id();
    let (revoke, _rotate) = tokio::join!(
        repo.access_revoke(&root.access_hash, AccessKind::Sessions, None, &target.id),
        repo.session_rotate(&target_credential.refresh_hash, &next_access, &next_refresh, &assurance, 600)
    );
    assert!(revoke.unwrap());
    assert!(repo.session_access(&next_access).await.is_err());
    assert!(repo.session_rotate(&target_credential.refresh_hash, &new_id(), &new_id(), &new_id(), 600).await.is_err());
    assert!(repo.session_access(&root.access_hash).await.is_ok());
    assert!(repo.session_access(&foreign_root.access_hash).await.is_ok());
    assert!(repo.session_access(&cross_root.access_hash).await.is_ok());
    assert!(!repo.find_api_token(&token.token_hash).await.unwrap().unwrap().revoked);
    assert!(repo.access_revoke(&root.access_hash, AccessKind::ApiTokens, Some(&tenant), &token.id).await.unwrap());
    assert!(repo.access_revoke(&root.access_hash, AccessKind::ApiTokens, Some(&tenant), &token.id).await.unwrap());
    assert!(repo.find_api_token(&token.token_hash).await.unwrap().unwrap().revoked);
    assert!(!repo.find_api_token(&other_token.token_hash).await.unwrap().unwrap().revoked);
    assert_eq!(repo.account_generation(&user.id).await.unwrap(), 0);
    repo.membership_remove(&tenant, &user.id).await.unwrap();
    repo.membership_join(&tenant, &user.id, Role::Owner).await.unwrap();
    assert_eq!(
        repo.access_page(&root.access_hash, AccessKind::ApiTokens, "", 50).await.unwrap().items[0].status,
        "revoked"
    );
    assert!(repo.access_revoke(&root.access_hash, AccessKind::Sessions, None, &family.id).await.unwrap());
    assert!(repo.session_access(&workspace.access_hash).await.is_err());
    assert!(repo.access_page(&root.access_hash, AccessKind::Sessions, "", 50).await.is_err());
    (root, foreign_root, token.token_hash, issued.hash)
}

macro_rules! bulk_test {
    ($repo:ty, $db:ty) => {
        async fn access_bulk_pages(repo: &$repo) {
            use memoswish_core::session::*;
            let (f,_)=crate::session_conformance::setup(repo).await;
            let c=crate::session_conformance::credential(&f,None);
            repo.session_issue(&f,&c,None).await.unwrap();
            sqlx::query("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<2001) INSERT INTO app_sessions(id,user_id,generation,provenance,auth_time,expires_at,revoked) SELECT 'bulk-' || CAST(x AS TEXT),$1,0,'password',0,1,0 FROM n")
                .bind(&f.user_id).execute(repo.pool()).await.unwrap();
            let mut after=String::new();let mut ids=std::collections::BTreeSet::new();
            loop {
                let page=repo.access_page(&c.access_hash,AccessKind::Sessions,&after,100).await.unwrap();
                assert!(page.items.len()<=100);
                for row in &page.items {assert!(ids.insert(row.id.clone()));if row.id.starts_with("bulk-"){assert_eq!(row.status,"expired");}}
                match page.next_cursor {Some(cursor)=>{assert!(cursor>after);after=cursor;},None=>break}
            }
            assert_eq!(ids.len(),2002);
            let tenant=repo.memberships(&f.user_id).await.unwrap()[0].tenant_id.clone();
            sqlx::query("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<2001) INSERT INTO api_tokens(id,tenant_id,user_id,name,token_hash,scopes,created_at,revoked,account_generation,membership_generation) SELECT 'bulk-token-' || CAST(x AS TEXT),$1,$2,'Inventory','secret-sentinel-' || CAST(x AS TEXT),'[\"content:read\"]',$3,FALSE,0,0 FROM n")
                .bind(&tenant).bind(&f.user_id).bind(chrono::Utc::now()).execute(repo.pool()).await.unwrap();
            let client=memoswish_core::oauth::OAuthClient{id:memoswish_core::ids::new_id(),name:"Bulk Agent".into(),redirect_uris:vec!["https://agent.invalid/cb".into()],grant_types:vec![],scopes:vec!["content:read".into()],auth_method:"none".into(),secret_hash:None,created_at:0,expires_at:i64::MAX-1};
            repo.oauth_register(&client).await.unwrap();
            let grant=memoswish_core::oauth::OAuthGrant{id:"bulk-grant-id".into(),tenant_id:tenant.clone(),user_id:f.user_id.clone(),client_id:client.id.clone(),resource:"https://learn.invalid/mcp".into(),scopes:vec!["content:read".into()],generations:memoswish_core::CredentialGenerations{account:0,membership:0},expires_at:i64::MAX-2};
            let grant_sql=if <$db as sqlx::Database>::NAME=="PostgreSQL" {"WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<2001) INSERT INTO oauth_grants(id,tenant_id,user_id,client_id,expires_at,revoked,metadata) SELECT 'bulk-grant-' || CAST(x AS TEXT),$1,$2,$3,$4,0,CAST(replace($5,'bulk-grant-id','bulk-grant-' || CAST(x AS TEXT)) AS JSONB) FROM n"} else {"WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<2001) INSERT INTO oauth_grants(id,tenant_id,user_id,client_id,expires_at,revoked,metadata) SELECT 'bulk-grant-' || CAST(x AS TEXT),$1,$2,$3,$4,0,replace($5,'bulk-grant-id','bulk-grant-' || CAST(x AS TEXT)) FROM n"};
            sqlx::query(grant_sql)
                .bind(&tenant).bind(&f.user_id).bind(&client.id).bind(grant.expires_at).bind(serde_json::to_string(&grant).unwrap()).execute(repo.pool()).await.unwrap();
            for kind in [AccessKind::ApiTokens,AccessKind::Grants] {
                let mut after=String::new();let mut ids=std::collections::BTreeSet::new();
                loop {
                    let page=repo.access_page(&c.access_hash,kind,&after,100).await.unwrap();
                    assert!(page.items.len()<=100);
                    assert!(!serde_json::to_string(&page).unwrap().contains("secret-sentinel"));
                    for row in &page.items {assert!(ids.insert(row.id.clone()));assert_eq!(row.status,"active");}
                    match page.next_cursor {Some(cursor)=>{assert!(cursor>after);after=cursor;},None=>break}
                }
                assert_eq!(ids.len(),2001);
            }
            sqlx::query("UPDATE api_tokens SET account_generation=1 WHERE user_id=$1").bind(&f.user_id).execute(repo.pool()).await.unwrap();
            assert_eq!(repo.access_page(&c.access_hash,AccessKind::ApiTokens,"",1).await.unwrap().items[0].status,"inactive");
            // 错误世代不会把已捕获凭据升级成当前权限。
            sqlx::query("UPDATE app_sessions SET generation=1 WHERE id LIKE 'bulk-%'").execute(repo.pool()).await.unwrap();
            sqlx::query("UPDATE account_auth_epochs SET generation=generation+1 WHERE user_id=$1").bind(&f.user_id).execute(repo.pool()).await.unwrap();
            assert!(repo.access_page(&c.access_hash,AccessKind::Sessions,"",100).await.is_err());
            assert!(repo.access_revoke(&c.access_hash,AccessKind::Sessions,None,&f.id).await.is_err());
        }
    };
}
pub(crate) use bulk_test;

// 两库复用真实成员授权与保留凭据准入，权限交集不能使整枚令牌失效。
async fn mixed_scope_admission<R: Repository>(repo: &R) {
    use memoswish_core::{CoreError, Permission, Principal};
    let (family, workspace) = crate::session_conformance::setup(repo).await;
    let tenant = workspace.tenant_id.unwrap();
    let owner = repo.get_user(&tenant, &family.user_id).await.unwrap().unwrap();
    let admin = UserRecord { id: new_id(), email: format!("{}@test.invalid", new_id()), role: Role::Admin, ..owner };
    repo.insert_user(&admin).await.unwrap();
    let family = SessionFamily { id: new_id(), user_id: admin.id.clone(), ..family };
    let root = crate::session_conformance::credential(&family, None);
    repo.session_issue(&family, &root, None).await.unwrap();
    let token = ApiTokenRecord {
        id: new_id(),
        tenant_id: tenant.clone(),
        user_id: admin.id.clone(),
        name: "Mixed scopes".into(),
        token_hash: new_id(),
        generations: memoswish_core::CredentialGenerations { account: 0, membership: 0 },
        scopes: vec!["content:read".into(), "billing:manage".into()],
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    };
    repo.issue_api_token(&token).await.unwrap();
    let stored = repo.find_api_token(&token.token_hash).await.unwrap().unwrap();
    let principal = Principal {
        tenant_id: tenant.clone(),
        user_id: admin.id.clone(),
        role: repo.membership_authorize(&tenant, &admin.id, stored.generations).await.unwrap(),
        scopes: Some(stored.scopes.clone()),
        via: "api_token".into(),
        session_access_hash: Some(format!("api:{}", stored.token_hash)),
        auth_generation: Some(0),
        membership_generation: Some(0),
        legacy_issued_at: None,
    };
    repo.access_authorize(&tenant, &principal).await.unwrap();
    principal.require(Permission::ContentRead).unwrap();
    assert!(matches!(principal.require(Permission::BillingManage), Err(CoreError::Forbidden(_))));
    let page = repo.access_page(&root.access_hash, AccessKind::ApiTokens, "", 50).await.unwrap();
    assert_eq!(page.items[0].status, "active");
    assert_eq!(page.items[0].scopes, Some(vec!["content:read".into()]));
    assert_eq!(page.items[0].scopes_limited, Some(true));
    let wildcard = ApiTokenRecord { id: new_id(), token_hash: new_id(), scopes: vec!["*".into()], ..token.clone() };
    let blocked =
        ApiTokenRecord { id: new_id(), token_hash: new_id(), scopes: vec!["billing:manage".into()], ..token.clone() };
    let expired = ApiTokenRecord {
        id: new_id(),
        token_hash: new_id(),
        expires_at: Some(Utc::now() - chrono::Duration::seconds(60)),
        ..token.clone()
    };
    for t in [&wildcard, &blocked, &expired] {
        repo.issue_api_token(t).await.unwrap();
    }
    let page = repo.access_page(&root.access_hash, AccessKind::ApiTokens, "", 50).await.unwrap();
    let row = page.items.iter().find(|r| r.id == wildcard.id).unwrap();
    assert_eq!(row.status, "active");
    assert_eq!(row.scopes_limited, Some(false));
    let expected: Vec<String> = memoswish_core::Permission::ALL
        .into_iter()
        .filter(|p| principal.role.allows(*p))
        .map(|p| p.as_scope().into())
        .collect();
    assert_eq!(row.scopes, Some(expected));
    let row = page.items.iter().find(|r| r.id == blocked.id).unwrap();
    assert_eq!(row.status, "active");
    assert_eq!(row.scopes, Some(vec![]));
    assert_eq!(row.scopes_limited, Some(true));
    assert_eq!(page.items.iter().find(|r| r.id == expired.id).unwrap().status, "expired");
    let expired_principal =
        Principal { session_access_hash: Some(format!("api:{}", expired.token_hash)), ..principal.clone() };
    assert!(repo.access_authorize(&tenant, &expired_principal).await.is_err());
    for t in [&token, &expired] {
        repo.access_revoke(&root.access_hash, AccessKind::ApiTokens, Some(&tenant), &t.id).await.unwrap();
    }
    let page = repo.access_page(&root.access_hash, AccessKind::ApiTokens, "", 50).await.unwrap();
    for t in [&token, &expired] {
        assert_eq!(page.items.iter().find(|r| r.id == t.id).unwrap().status, "revoked");
    }
    assert!(repo.access_authorize(&tenant, &principal).await.is_err());
    repo.membership_remove(&tenant, &admin.id).await.unwrap();
    let page = repo.access_page(&root.access_hash, AccessKind::ApiTokens, "", 50).await.unwrap();
    let row = page.items.iter().find(|r| r.id == wildcard.id).unwrap();
    assert_eq!(row.status, "inactive");
    assert_eq!(row.scopes, Some(vec![]));
    assert!(repo.membership_authorize(&tenant, &admin.id, token.generations).await.is_err());
    repo.membership_join(&tenant, &admin.id, Role::Admin).await.unwrap();
    assert!(repo.membership_authorize(&tenant, &admin.id, token.generations).await.is_err());
    let page = repo.access_page(&root.access_hash, AccessKind::ApiTokens, "", 50).await.unwrap();
    assert_eq!(page.items.iter().find(|r| r.id == wildcard.id).unwrap().status, "inactive");
}
