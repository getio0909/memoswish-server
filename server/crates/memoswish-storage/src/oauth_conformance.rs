//! OAuth 同一测试逻辑在 SQLite 和真实 PostgreSQL 上执行。
use memoswish_core::ids::new_id;
use memoswish_core::{
    oauth::*,
    repo::{Repository, UserRecord},
};

pub(crate) async fn pending_authorization<R: Repository>(
    repo: &R,
    user: &UserRecord,
    client: &OAuthClient,
    expires: i64,
) -> (AuthorizationRequest, BrowserSession) {
    let generations = memoswish_core::CredentialGenerations {
        account: repo.account_generation(&user.id).await.unwrap(),
        membership: repo
            .memberships(&user.id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| m.tenant_id == user.tenant_id)
            .unwrap()
            .generation,
    };
    let browser = BrowserSession {
        hash: new_id(),
        tenant_id: None,
        user_id: None,
        auth_time: 0,
        auth_method: "anonymous".into(),
        generations: None,
        expires_at: expires,
    };
    let mut request = AuthorizationRequest {
        id: new_id(),
        browser_hash: browser.hash.clone(),
        csrf_hash: new_id(),
        client_id: client.id.clone(),
        redirect_uri: client.redirect_uris[0].clone(),
        resource: "https://learn.example/mcp".into(),
        scopes: vec!["content:read".into()],
        challenge: new_id(),
        state: None,
        expires_at: expires,
    };
    repo.oauth_begin(&browser, &request).await.unwrap();
    let session = BrowserSession {
        hash: new_id(),
        tenant_id: Some(user.tenant_id.clone()),
        user_id: Some(user.id.clone()),
        auth_time: 10,
        auth_method: "password".into(),
        generations: Some(generations),
        expires_at: expires,
    };
    assert!(!repo.oauth_login("other", &request, &session, 10).await.unwrap());
    assert!(repo.oauth_login(&user.tenant_id, &request, &session, 10).await.unwrap());
    assert!(!repo.oauth_login(&user.tenant_id, &request, &session, 10).await.is_ok_and(|b| b));
    assert!(repo.oauth_browser(&browser.hash).await.unwrap().is_none());
    request.browser_hash = session.hash.clone();
    (request, session)
}

pub(crate) async fn code<R: Repository>(
    repo: &R,
    user: &UserRecord,
    client: &OAuthClient,
    expires: i64,
) -> AuthorizationCode {
    let (request, session) = pending_authorization(repo, user, client, expires).await;
    let generations = session.generations.unwrap();
    let c = AuthorizationCode {
        hash: new_id(),
        grant: OAuthGrant {
            generations,
            id: new_id(),
            tenant_id: user.tenant_id.clone(),
            user_id: user.id.clone(),
            client_id: client.id.clone(),
            resource: request.resource.clone(),
            scopes: request.scopes.clone(),
            expires_at: expires,
        },
        redirect_uri: request.redirect_uri.clone(),
        challenge: request.challenge.clone(),
        expires_at: expires,
    };
    assert!(!repo.oauth_consent("other", &request, Some(&c), 10).await.unwrap());
    assert!(repo.oauth_consent(&user.tenant_id, &request, Some(&c), 10).await.unwrap());
    assert!(!repo.oauth_consent(&user.tenant_id, &request, Some(&c), 10).await.unwrap());
    c
}
pub(crate) fn token(c: &AuthorizationCode, kind: &str) -> OAuthToken {
    OAuthToken {
        hash: new_id(),
        grant: c.grant.clone(),
        scopes: c.grant.scopes.clone(),
        kind: kind.into(),
        expires_at: c.grant.expires_at,
    }
}
pub async fn run<R: Repository>(repo: &R, user: &UserRecord) {
    let client = OAuthClient {
        id: new_id(),
        name: "Conformance".into(),
        redirect_uris: vec!["https://client.example/callback".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        scopes: vec!["content:read".into()],
        auth_method: "none".into(),
        secret_hash: None,
        created_at: 10,
        expires_at: i64::MAX - 1,
    };
    repo.oauth_register(&client).await.unwrap();
    assert_eq!(repo.oauth_client(&client.id).await.unwrap().unwrap(), client);
    let c = code(repo, user, &client, i64::MAX - 2).await;
    let access = token(&c, "access");
    let parent = token(&c, "refresh");
    assert!(!repo.oauth_redeem("other", &c, &[access.clone(), parent.clone()], 10).await.unwrap());
    // 第二个插入冲突时，整个消费和第一个令牌插入一起回滚。
    assert!(repo.oauth_redeem(&user.tenant_id, &c, &[access.clone(), access.clone()], 10).await.is_err());
    assert!(repo.oauth_token(&access.hash).await.unwrap().is_none());
    assert!(repo.oauth_redeem(&user.tenant_id, &c, &[access.clone(), parent.clone()], 10).await.unwrap());
    assert!(repo.oauth_token(&access.hash).await.unwrap().is_some());
    let next = token(&c, "refresh");
    let next_access = token(&c, "access");
    let rows = [next.clone(), next_access.clone()];
    let (a, b) = tokio::join!(
        repo.oauth_rotate(&user.tenant_id, &parent, &rows, 10),
        repo.oauth_rotate(&user.tenant_id, &parent, &rows, 10)
    );
    assert_ne!(a.unwrap(), b.unwrap(), "exactly one concurrent refresh wins");
    assert!(repo.oauth_token(&next.hash).await.unwrap().is_none(), "reuse revokes successor");
    assert!(repo.oauth_token(&access.hash).await.unwrap().is_none(), "reuse revokes access family");
    let c = code(repo, user, &client, i64::MAX - 2).await;
    let rows = [token(&c, "access")];
    let (a, b) = tokio::join!(
        repo.oauth_redeem(&user.tenant_id, &c, &rows, 10),
        repo.oauth_redeem(&user.tenant_id, &c, &rows, 10)
    );
    assert_ne!(a.unwrap(), b.unwrap(), "exactly one concurrent code redemption wins");
    assert!(repo.oauth_token(&rows[0].hash).await.unwrap().is_none(), "code reuse revokes grant");
    let c = code(repo, user, &client, 100).await;
    let t = token(&c, "access");
    assert!(
        !repo.oauth_redeem(&user.tenant_id, &c, std::slice::from_ref(&t), 100).await.unwrap(),
        "expiry is exclusive"
    );
    assert!(repo.oauth_redeem(&user.tenant_id, &c, std::slice::from_ref(&t), 10).await.unwrap());
    repo.oauth_revoke("other", &c.grant.id).await.unwrap();
    assert!(repo.oauth_token(&t.hash).await.unwrap().is_some());
    repo.oauth_cleanup(100).await.unwrap();
    assert!(repo.oauth_token(&t.hash).await.unwrap().is_none());
    assert!(repo.oauth_code(&c.hash).await.unwrap().is_none());
    assert!(repo.get_user(&user.tenant_id, &user.id).await.unwrap().is_some(), "migration/cleanup preserve user");
    let c = code(repo, user, &client, i64::MAX - 2).await;
    let t = token(&c, "access");
    assert!(repo.oauth_redeem(&user.tenant_id, &c, std::slice::from_ref(&t), 10).await.unwrap());
    repo.oauth_revoke(&user.tenant_id, &c.grant.id).await.unwrap();
    assert!(repo.oauth_token(&t.hash).await.unwrap().is_none());
}
