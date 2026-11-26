//! OAuth HTTP 流程与凭据边界的集成回归测试。
use crate::{app::AppState, config::Config};
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use memoswish_auth::oauth::{OAuthConfig, OAuthService, challenge, digest, now};
use memoswish_protocol::{DeploymentMode, RegisterRequest};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

struct Fixture {
    app: Router,
    st: AppState,
    oauth: Arc<OAuthService>,
    dir: std::path::PathBuf,
    jwt: String,
    tenant: String,
    user: String,
}
impl Fixture {
    async fn cleanup(self) {
        crate::runtime::cleanup_test_app(&self.dir, &[&self.st]).await;
    }
}
async fn fixture() -> Fixture {
    fixture_with_database(None).await
}
async fn fixture_with_database(database_url: Option<String>) -> Fixture {
    let dir = std::env::temp_dir().join(format!("memoswish-oauth-{}", memoswish_core::ids::new_id()));
    let config = Config {
        data_dir: dir.clone(),
        database_url,
        mode: DeploymentMode::MultiTenant,
        registration_open: true,
        seed_demo: false,
        oauth: OAuthConfig {
            enabled: true,
            issuer: "https://learn.example".into(),
            public_base_url: "https://learn.example".into(),
            mcp_resource: "https://learn.example/mcp".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let st = AppState::build(config).await.unwrap();
    let auth = st
        .services
        .auth
        .register(&RegisterRequest {
            email: "ada@example.com".into(),
            password: "password123".into(),
            display_name: "Ada <script>alert(1)</script>".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    Fixture {
        app: crate::auth_defenses::test_router(st.clone()),
        oauth: st.oauth.clone().unwrap(),
        st,
        dir,
        jwt: auth.access_token,
        tenant: auth.user.tenant_id,
        user: auth.user.user_id,
    }
}
async fn send(f: &Fixture, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let r = f.app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let body = r.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}
fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}
fn json_req(uri: &str, v: Value, bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
    if uri == "/mcp" {
        b = b.header(header::HOST, "localhost");
    }
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(v.to_string())).unwrap()
}
fn encode(p: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new()).extend_pairs(p.iter().copied()).finish()
}
fn post(uri: &str, p: &[(&str, &str)], cookie: Option<&str>, basic: Option<&str>) -> Request<Body> {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if let Some(basic) = basic {
        b = b.header(header::AUTHORIZATION, format!("Basic {basic}"));
    }
    b.body(Body::from(encode(p))).unwrap()
}
fn registration() -> Value {
    json!({"client_name":"Test <img src=x onerror=alert(1)>","redirect_uris":["https://client.example/cb?existing=1"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"]})
}
async fn client(f: &Fixture) -> String {
    let (s, _, b) = send(f, json_req("/oauth/register", registration(), None)).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    serde_json::from_str::<Value>(&b).unwrap()["client_id"].as_str().unwrap().into()
}
struct Browser {
    id: String,
    csrf: String,
    cookie: String,
    html: String,
}
fn browser(headers: &HeaderMap, body: String) -> Browser {
    let value = |name: &str| {
        body.split(&format!("name=\"{name}\" value=\"")).nth(1).unwrap().split('"').next().unwrap().to_string()
    };
    Browser {
        id: value("request_id"),
        csrf: value("csrf"),
        cookie: headers[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().into(),
        html: body,
    }
}
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
fn auth_params(client: &str, scope: &str) -> Vec<(String, String)> {
    vec![
        ("client_id".into(), client.into()),
        ("redirect_uri".into(), "https://client.example/cb?existing=1".into()),
        ("response_type".into(), "code".into()),
        ("resource".into(), "https://learn.example/mcp".into()),
        ("scope".into(), scope.into()),
        ("code_challenge_method".into(), "S256".into()),
        ("code_challenge".into(), challenge(VERIFIER)),
        ("state".into(), "state & + / 中文".into()),
    ]
}
async fn start(f: &Fixture, client: &str, scope: &str) -> Browser {
    let query = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(auth_params(client, scope)).finish();
    let (s, h, b) = send(f, get(&format!("/oauth/authorize?{query}"))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    assert!(h[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("frame-ancestors 'none'"));
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
    let cookie = h[header::SET_COOKIE].to_str().unwrap();
    for flag in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(flag));
    }
    browser(&h, b)
}
async fn login(f: &Fixture, b: &Browser) -> Browser {
    let (s, h, body) = send(
        f,
        post(
            "/oauth/login",
            &[("request_id", &b.id), ("csrf", &b.csrf), ("email", "ada@example.com"), ("password", "password123")],
            Some(&b.cookie),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let next = browser(&h, body);
    assert_ne!(next.cookie, b.cookie);
    next
}

async fn password_login_rejects_replacement_account(database_url: Option<String>) {
    for oauth in [false, true] {
        let mut f = fixture_with_database(database_url.clone()).await;
        let gate = Arc::new(memoswish_auth::password_lifecycle::LoginProofGate::default());
        f.st.services.auth = f.st.services.auth.clone().with_login_proof_gate(gate.clone());
        f.st.oauth = Some(Arc::new(
            OAuthService::new(f.st.repo.clone(), f.st.services.auth.clone(), f.st.config.oauth.clone()).unwrap(),
        ));
        f.app = crate::auth_defenses::test_router(f.st.clone());
        let (request, browser_hash) = if oauth {
            let client = client(&f).await;
            let b = start(&f, &client, "content:read").await;
            let cookie = b.cookie.split_once('=').unwrap().1;
            (
                post(
                    "/oauth/login",
                    &[
                        ("request_id", &b.id),
                        ("csrf", &b.csrf),
                        ("email", "ada@example.com"),
                        ("password", "password123"),
                    ],
                    Some(&b.cookie),
                    None,
                ),
                Some(digest(cookie)),
            )
        } else {
            (json_req("/v1/auth/login", json!({"email":"ada@example.com","password":"password123"}), None), None)
        };
        let app = f.app.clone();
        let pending = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
        // 屏障在密码验证及 password_proof 提交后、邮箱资料读取前触发。
        gate.entered().await;
        let account =
            f.st.services
                .auth
                .login_session(&memoswish_protocol::LoginRequest {
                    email: "ada@example.com".into(),
                    password: "password123".into(),
                })
                .await
                .unwrap();
        let principal = f.st.services.auth.authenticate_account(&account.access_token).await.unwrap();
        assert_eq!(principal.user_id, f.user);
        f.st.services
            .auth
            .close_account(
                &principal,
                &memoswish_core::lifecycle::CloseAccount { confirmed_exclusive_workspaces: vec![f.tenant.clone()] },
            )
            .await
            .unwrap();
        let replacement =
            f.st.services
                .auth
                .register(&RegisterRequest {
                    email: "ada@example.com".into(),
                    password: "replacement-password-456".into(),
                    display_name: "Replacement".into(),
                    tenant_name: None,
                })
                .await
                .unwrap();
        assert_ne!(replacement.user.user_id, f.user);
        assert_eq!(f.st.repo.account_generation(&replacement.user.user_id).await.unwrap(), 0);
        gate.release();
        let response = pending.await.unwrap();
        assert_eq!(response.status(), if oauth { StatusCode::BAD_REQUEST } else { StatusCode::UNAUTHORIZED });
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        if oauth {
            assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["error"], "access_denied");
        }
        for secret in [&replacement.user.user_id, &replacement.access_token, "access_token", "lto_bs_"] {
            assert!(!body.contains(secret), "{body}");
        }
        if let Some(hash) = browser_hash {
            let browser = f.st.repo.oauth_browser(&hash).await.unwrap().unwrap();
            assert!(browser.user_id.is_none());
            assert!(browser.tenant_id.is_none());
        }
        assert!(
            f.st.services
                .auth
                .login(&memoswish_protocol::LoginRequest {
                    email: "ada@example.com".into(),
                    password: "password123".into(),
                })
                .await
                .is_err()
        );
        let login =
            f.st.services
                .auth
                .login(&memoswish_protocol::LoginRequest {
                    email: "ada@example.com".into(),
                    password: "replacement-password-456".into(),
                })
                .await
                .unwrap();
        assert_eq!(login.user.user_id, replacement.user.user_id);
        // PostgreSQL 两个子场景共用 schema，通过正式销户入口释放本场景的邮箱。
        let authority = f.st.services.auth.authenticate_lifecycle_account(Some(&login.access_token)).await.unwrap();
        f.st.services
            .auth
            .close_account_authorized(
                &authority,
                &memoswish_core::lifecycle::CloseAccount {
                    confirmed_exclusive_workspaces: vec![replacement.user.tenant_id],
                },
            )
            .await
            .unwrap();
        f.cleanup().await;
    }
}

#[tokio::test]
async fn sqlite_password_login_rejects_close_reregister_interleaving() {
    password_login_rejects_replacement_account(None).await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn postgres_password_login_rejects_close_reregister_interleaving() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let (database, url) = crate::feature_tests::postgres_database(&owner).await;
        password_login_rejects_replacement_account(Some(url)).await;
        database.cleanup().await;
    });
}

async fn approve(f: &Fixture, b: &Browser) -> String {
    let (s, h, body) = send(
        f,
        post(
            "/oauth/authorize",
            &[("request_id", &b.id), ("csrf", &b.csrf), ("decision", "approve")],
            Some(&b.cookie),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{body}");
    let u = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
    let q = u.query_pairs().collect::<std::collections::HashMap<_, _>>();
    assert_eq!(q["iss"], "https://learn.example");
    assert_eq!(q["state"], "state & + / 中文");
    assert_eq!(q["existing"], "1");
    q["code"].to_string()
}
async fn code(f: &Fixture, c: &str, scope: &str) -> String {
    let b = start(f, c, scope).await;
    let b = login(f, &b).await;
    approve(f, &b).await
}
fn redeem<'a>(c: &'a str, code: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", "authorization_code"),
        ("client_id", c),
        ("code", code),
        ("redirect_uri", "https://client.example/cb?existing=1"),
        ("resource", "https://learn.example/mcp"),
        ("code_verifier", VERIFIER),
    ]
}
async fn tokens(f: &Fixture, c: &str, scope: &str) -> Value {
    let code = code(f, c, scope).await;
    let (s, h, b) = send(f, post("/oauth/token", &redeem(c, &code), None, None)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    serde_json::from_str(&b).unwrap()
}
async fn mcp(f: &Fixture, t: &str, name: &str, args: Value) -> (StatusCode, HeaderMap, String) {
    send(
        f,
        json_req(
            "/mcp",
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}),
            Some(t),
        ),
    )
    .await
}
async fn assert_error(f: &Fixture, req: Request<Body>, code: &str) {
    let (s, h, b) = send(f, req).await;
    assert!(s.is_client_error(), "{s}: {b}");
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["error"], code, "{b}");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
}

async fn assert_authorization_error(f: &Fixture, req: Request<Body>, error: &str, state: Option<&str>) {
    let (s, h, b) = send(f, req).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{b}");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    assert!(!h.contains_key(header::SET_COOKIE));
    let u = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(u.origin().ascii_serialization(), "https://client.example");
    assert_eq!(u.path(), "/cb");
    assert!(u.fragment().is_none());
    let q = u.query_pairs().collect::<std::collections::HashMap<_, _>>();
    assert_eq!(q["error"], error);
    assert_eq!(q["iss"], "https://learn.example");
    assert_eq!(q["existing"], "1");
    assert_eq!(q.get("state").map(|s| s.as_ref()), state);
    assert!(!q.contains_key("code"));
}

#[tokio::test]
async fn discovery_registration_login_consent_token_mcp_and_legacy_lanes() {
    full_flow_case(fixture().await).await;
}
async fn full_flow_case(f: Fixture) {
    for path in ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"] {
        let (s, _, b) = send(&f, get(path)).await;
        assert_eq!(s, StatusCode::OK);
        let v: Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["resource"], "https://learn.example/mcp");
        assert_eq!(v["authorization_servers"][0], "https://learn.example");
    }
    let (_, _, b) = send(&f, get("/.well-known/oauth-authorization-server")).await;
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(v["response_modes_supported"], json!(["query"]));
    for key in ["token_endpoint_auth_methods_supported", "revocation_endpoint_auth_methods_supported"] {
        assert_eq!(v[key], json!(["none", "client_secret_basic", "client_secret_post"]));
    }
    assert_eq!(v["client_id_metadata_document_supported"], false);
    assert!(v.get("jwks_uri").is_none());
    for method in ["GET", "POST", "DELETE", "PUT"] {
        let (s, h, _) = send(&f, Request::builder().method(method).uri("/mcp").body(Body::empty()).unwrap()).await;
        if method == "PUT" {
            assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
        } else {
            assert_eq!(s, StatusCode::UNAUTHORIZED);
            assert!(
                h[header::WWW_AUTHENTICATE]
                    .to_str()
                    .unwrap()
                    .contains("resource_metadata=\"https://learn.example/.well-known/oauth-protected-resource/mcp\"")
            );
        }
    }
    let c = client(&f).await;
    let b = start(&f, &c, "content:read").await;
    assert!(!b.html.contains("<img"));
    assert!(b.html.contains("&lt;img"));
    assert!(b.html.contains("client.example"));
    let b = login(&f, &b).await;
    assert!(!b.html.contains("<script>"));
    assert!(b.html.contains("&lt;script&gt;"));
    assert!(b.html.contains(&f.tenant));
    let code = approve(&f, &b).await;
    let stored = f.st.repo.oauth_code(&digest(&code)).await.unwrap().unwrap();
    assert_eq!(stored.hash, digest(&code));
    assert!(!serde_json::to_string(&stored).unwrap().contains(&code));
    let (s, _, body) = send(&f, post("/oauth/token", &redeem(&c, &code), None, None)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let t: Value = serde_json::from_str(&body).unwrap();
    let access = t["access_token"].as_str().unwrap();
    let (s, _, b) = mcp(&f, access, "deck_list", json!({})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(serde_json::from_str::<Value>(&b).unwrap()["result"]["isError"], false);
    for (path, method) in [("/v1/me", "GET"), ("/v1/auth/refresh", "POST"), ("/v1/decks", "GET")] {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {access}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&f, req).await.0, StatusCode::UNAUTHORIZED);
    }
    assert!(f.oauth.authenticate(access, "https://other.example/mcp").await.is_err());
    let p = f.st.services.auth.authenticate(Some(&f.jwt)).await.unwrap();
    let api = f.st.services.auth.create_api_token(&p, "legacy", vec!["content:read".into()], None).await.unwrap();
    for t in [&f.jwt, &api.plaintext] {
        assert_eq!(mcp(&f, t, "deck_list", json!({})).await.0, StatusCode::OK);
    }
    let (s, _, _) = send(
        &f,
        Request::post("/v1/auth/refresh")
            .header(header::AUTHORIZATION, format!("Bearer {}", api.plaintext))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = send(
        &f,
        Request::post("/v1/auth/refresh")
            .header(header::AUTHORIZATION, format!("Bearer {}", f.jwt))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_error(&f, post("/oauth/token", &redeem(&c, &code), None, None), "invalid_grant").await;
    assert_eq!(mcp(&f, access, "deck_list", json!({})).await.0, StatusCode::UNAUTHORIZED);
    f.cleanup().await;
}

#[tokio::test]
async fn registration_rejects_redirects_metadata_and_bounds() {
    let f = fixture().await;
    for redirect in [
        "http://evil.example/cb",
        "javascript:alert(1)",
        concat!("file:", "///cb"),
        "com.example:/cb",
        "https://client.example/*",
        "https://u:p@client.example/cb",
        "https://client.example/cb#fragment",
        "http://localhost/cb",
        "https://client.example/cb\n",
    ] {
        let mut r = registration();
        r["redirect_uris"] = json!([redirect]);
        assert_error(&f, json_req("/oauth/register", r, None), "invalid_redirect_uri").await;
    }
    for redirect in
        ["https://client.example/cb", "https://localhost/cb", "http://127.0.0.1:4857/cb", "http://[::1]:4857/cb"]
    {
        let mut r = registration();
        r["redirect_uris"] = json!([redirect]);
        assert_eq!(send(&f, json_req("/oauth/register", r, None)).await.0, StatusCode::CREATED);
    }
    for (key, value) in [
        ("client_name", json!("x".repeat(129))),
        ("redirect_uris", json!([])),
        ("redirect_uris", json!(vec!["https://example.com/cb"; 9])),
        ("grant_types", json!(["implicit"])),
        ("response_types", json!(["token"])),
        ("token_endpoint_auth_method", json!("private_key_jwt")),
    ] {
        let mut r = registration();
        r[key] = value;
        assert_error(&f, json_req("/oauth/register", r, None), "invalid_client_metadata").await;
    }
    let mut r = registration();
    r["scope"] = json!("*");
    assert_error(&f, json_req("/oauth/register", r, None), "invalid_client_metadata").await;
    let mut r = registration();
    r["logo_uri"] = json!("x".repeat(17000));
    assert_error(&f, json_req("/oauth/register", r, None), "invalid_client_metadata").await;
    f.cleanup().await;
}

#[tokio::test]
async fn authorization_bindings_pkce_and_resource_are_strict() {
    let f = fixture().await;
    let c = client(&f).await;
    for (key, value, err) in [
        ("redirect_uri", "https://evil.example/cb", "invalid_redirect_uri"),
        ("resource", "https://other.example/mcp", "invalid_target"),
        ("code_challenge_method", "plain", "invalid_request"),
        ("code_challenge", "too-short", "invalid_request"),
        ("response_type", "token", "unsupported_response_type"),
        ("scope", "token:manage", "invalid_scope"),
        ("scope", "content:read *", "invalid_scope"),
    ] {
        let mut params = auth_params(&c, "content:read");
        params.iter_mut().find(|(k, _)| k == key).unwrap().1 = value.into();
        let q = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(params).finish();
        let req = get(&format!("/oauth/authorize?{q}"));
        if key == "redirect_uri" {
            let (s, h, b) = send(&f, req).await;
            assert_eq!(s, StatusCode::BAD_REQUEST);
            assert!(!h.contains_key(header::LOCATION));
            assert_eq!(serde_json::from_str::<Value>(&b).unwrap()["error"], err);
        } else {
            assert_authorization_error(&f, req, err, Some("state & + / 中文")).await;
        }
    }
    let q = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(auth_params(&c, "content:read")).finish();
    assert_error(
        &f,
        get(&format!("/oauth/authorize?{q}&resource=https%3A%2F%2Flearn.example%2Fmcp")),
        "invalid_target",
    )
    .await;
    let mut params = auth_params(&c, "content:read");
    params.retain(|(k, _)| k != "resource");
    let q = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(params).finish();
    assert_authorization_error(&f, get(&format!("/oauth/authorize?{q}")), "invalid_target", Some("state & + / 中文"))
        .await;
    f.cleanup().await;
}

#[tokio::test]
async fn login_and_consent_require_csrf_browser_and_interactive_authentication() {
    let f = fixture().await;
    let c = client(&f).await;
    let b = start(&f, &c, "content:read").await;
    let other = start(&f, &c, "content:read").await;
    for (cookie, csrf) in
        [(Some(b.cookie.as_str()), "wrong"), (None, b.csrf.as_str()), (Some(other.cookie.as_str()), b.csrf.as_str())]
    {
        assert_error(
            &f,
            post(
                "/oauth/login",
                &[("request_id", &b.id), ("csrf", csrf), ("email", "ada@example.com"), ("password", "password123")],
                cookie,
                None,
            ),
            "access_denied",
        )
        .await;
    }
    assert_error(
        &f,
        post(
            "/oauth/authorize",
            &[("request_id", &b.id), ("csrf", &b.csrf), ("decision", "approve")],
            Some(&b.cookie),
            None,
        ),
        "access_denied",
    )
    .await;
    let next = login(&f, &b).await;
    assert_error(
        &f,
        post(
            "/oauth/authorize",
            &[("request_id", &next.id), ("csrf", &next.csrf), ("decision", "approve")],
            Some(&b.cookie),
            None,
        ),
        "access_denied",
    )
    .await;
    assert_error(
        &f,
        post(
            "/oauth/authorize",
            &[("request_id", &next.id), ("csrf", "bad"), ("decision", "approve")],
            Some(&next.cookie),
            None,
        ),
        "access_denied",
    )
    .await;
    let _ = approve(&f, &next).await;
    assert_error(
        &f,
        post(
            "/oauth/authorize",
            &[("request_id", &next.id), ("csrf", &next.csrf), ("decision", "approve")],
            Some(&next.cookie),
            None,
        ),
        "access_denied",
    )
    .await;
    f.cleanup().await;
}

#[tokio::test]
async fn consent_denial_preserves_state_and_issues_no_code() {
    let f = fixture().await;
    let c = client(&f).await;
    let b = login(&f, &start(&f, &c, "content:read").await).await;
    let (s, h, _) = send(
        &f,
        post(
            "/oauth/authorize",
            &[("request_id", &b.id), ("csrf", &b.csrf), ("decision", "deny")],
            Some(&b.cookie),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let u = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
    let q = u.query_pairs().collect::<std::collections::HashMap<_, _>>();
    assert_eq!(q["error"], "access_denied");
    assert_eq!(q["state"], "state & + / 中文");
    assert_eq!(q["iss"], "https://learn.example");
    assert!(!q.contains_key("code"));
    assert!(f.st.repo.oauth_request(&b.id).await.unwrap().is_none());
    f.cleanup().await;
}

#[tokio::test]
async fn code_binding_errors_do_not_consume_and_scope_cannot_expand() {
    let f = fixture().await;
    let c = client(&f).await;
    let other = client(&f).await;
    let code = code(&f, &c, "content:read").await;
    assert_error(
        &f,
        post(
            "/oauth/token",
            &[("client_id", &c), ("grant_type", "password"), ("resource", "https://learn.example/mcp")],
            None,
            None,
        ),
        "unsupported_grant_type",
    )
    .await;
    for (key, value, err) in [
        ("client_id", other.as_str(), "invalid_grant"),
        ("redirect_uri", "https://client.example/other", "invalid_grant"),
        ("resource", "https://other.example/mcp", "invalid_target"),
        ("code_verifier", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFX", "invalid_grant"),
    ] {
        let mut p = redeem(&c, &code);
        p.iter_mut().find(|(k, _)| k == &key).unwrap().1 = value;
        assert_error(&f, post("/oauth/token", &p, None, None), err).await;
    }
    let mut p = redeem(&c, &code);
    p.push(("scope", "content:read content:write"));
    assert_error(&f, post("/oauth/token", &p, None, None), "invalid_scope").await;
    let mut p = redeem(&c, &code);
    p.retain(|(k, _)| *k != "resource");
    assert_error(&f, post("/oauth/token", &p, None, None), "invalid_target").await;
    let mut p = redeem(&c, &code);
    p.push(("resource", "https://learn.example/mcp"));
    assert_error(&f, post("/oauth/token", &p, None, None), "invalid_target").await;
    assert_eq!(send(&f, post("/oauth/token", &redeem(&c, &code), None, None)).await.0, StatusCode::OK);
    f.cleanup().await;
}

#[tokio::test]
async fn refresh_rotates_preserves_refresh_scope_and_reuse_revokes_family() {
    refresh_replay_case(fixture().await).await;
}
async fn refresh_replay_case(mut f: Fixture) {
    let c = client(&f).await;
    let other = client(&f).await;
    let t = tokens(&f, &c, "content:read content:write").await;
    crate::runtime::drain_test_state(&f.st).await;
    f.st = AppState::build(f.st.config.as_ref().clone()).await.unwrap();
    f.oauth = f.st.oauth.clone().unwrap();
    f.app = crate::auth_defenses::test_router(f.st.clone());
    let rt = t["refresh_token"].as_str().unwrap();
    let access = t["access_token"].as_str().unwrap();
    let base = |client| {
        vec![
            ("grant_type", "refresh_token"),
            ("client_id", client),
            ("refresh_token", rt),
            ("resource", "https://learn.example/mcp"),
        ]
    };
    assert_error(&f, post("/oauth/token", &base(&other), None, None), "invalid_grant").await;
    let mut p = base(&c);
    p.push(("scope", "content:read media:write"));
    assert_error(&f, post("/oauth/token", &p, None, None), "invalid_scope").await;
    let mut p = base(&c);
    p.push(("scope", "content:read"));
    let (s, _, b) = send(&f, post("/oauth/token", &p, None, None)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let next: Value = serde_json::from_str(&b).unwrap();
    assert_ne!(next["refresh_token"], rt);
    assert_eq!(next["scope"], "content:read");
    let mut p = vec![
        ("grant_type", "refresh_token"),
        ("client_id", c.as_str()),
        ("refresh_token", next["refresh_token"].as_str().unwrap()),
        ("resource", "https://learn.example/mcp"),
        ("scope", "content:write"),
    ];
    assert_eq!(
        mcp(&f, next["access_token"].as_str().unwrap(), "deck_create", json!({"title":"Denied"})).await.0,
        StatusCode::FORBIDDEN
    );
    let (s, _, b) = send(&f, post("/oauth/token", &p, None, None)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let write: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(write["scope"], "content:write");
    p.pop();
    p.iter_mut().find(|(k, _)| *k == "refresh_token").unwrap().1 = write["refresh_token"].as_str().unwrap();
    let (s, _, b) = send(&f, post("/oauth/token", &p, None, None)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let full: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(full["scope"], "content:read content:write");
    for t in [&next, &write, &full] {
        let stored = f.st.repo.oauth_token(&digest(t["refresh_token"].as_str().unwrap())).await.unwrap().unwrap();
        assert_eq!(stored.scopes, ["content:read", "content:write"]);
    }
    assert_error(&f, post("/oauth/token", &base(&c), None, None), "invalid_grant").await;
    for a in [
        access,
        next["access_token"].as_str().unwrap(),
        write["access_token"].as_str().unwrap(),
        full["access_token"].as_str().unwrap(),
        rt,
        "lto_at_invalid",
    ] {
        assert_eq!(mcp(&f, a, "deck_list", json!({})).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_error(&f, post("/oauth/token", &p, None, None), "invalid_grant").await;
    f.cleanup().await;
}

#[tokio::test]
async fn confidential_client_requires_basic_auth_and_revoke_is_client_bound() {
    use base64::Engine;
    let f = fixture().await;
    let mut r = registration();
    r["token_endpoint_auth_method"] = json!("client_secret_basic");
    let (s, _, b) = send(&f, json_req("/oauth/register", r, None)).await;
    assert_eq!(s, StatusCode::CREATED);
    let r: Value = serde_json::from_str(&b).unwrap();
    let c = r["client_id"].as_str().unwrap();
    let secret = r["client_secret"].as_str().unwrap();
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{c}:{secret}"));
    let stored = f.st.repo.oauth_client(c).await.unwrap().unwrap();
    assert_eq!(stored.secret_hash, Some(digest(secret)));
    assert!(!serde_json::to_string(&stored).unwrap().contains(secret));
    let code = code(&f, c, "content:read").await;
    assert_error(&f, post("/oauth/token", &redeem(c, &code), None, None), "invalid_client").await;
    let (s, _, b) = send(&f, post("/oauth/token", &redeem(c, &code), None, Some(&basic))).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let t: Value = serde_json::from_str(&b).unwrap();
    let at = t["access_token"].as_str().unwrap();
    let rt = t["refresh_token"].as_str().unwrap();
    let other = client(&f).await;
    assert_eq!(
        send(&f, post("/oauth/revoke", &[("client_id", &other), ("token", rt)], None, None)).await.0,
        StatusCode::OK
    );
    assert_eq!(mcp(&f, at, "deck_list", json!({})).await.0, StatusCode::OK);
    assert_eq!(
        send(&f, post("/oauth/revoke", &[("client_id", c), ("token", rt)], None, Some(&basic))).await.0,
        StatusCode::OK
    );
    assert_eq!(mcp(&f, at, "deck_list", json!({})).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        send(&f, post("/oauth/revoke", &[("client_id", c), ("token", "unknown")], None, Some(&basic))).await.0,
        StatusCode::OK
    );
    f.cleanup().await;
}

#[tokio::test]
async fn scopes_preflight_all_requirements_before_side_effects() {
    let f = fixture().await;
    let c = client(&f).await;
    let t = tokens(&f, &c, "content:write").await;
    let access = t["access_token"].as_str().unwrap();
    let sample = memoswish_protocol::examples::sample_card();
    let (s, h, _) = mcp(&f, access, "card_upsert", json!({"cards":[sample]})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let challenge = h[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert_eq!(
        challenge,
        concat!(
            r#"Bearer realm="learntok", resource_metadata="https://learn.example/.well-known/oauth-protected-resource/mcp", "#,
            r#"error="insufficient_scope", scope="content:write tts:generate content:read""#
        )
    );
    let (s, h, _) = mcp(
        &f,
        access,
        "bgm_assign",
        json!({
            "card_ids":[sample.id], "assignment":{"track_id":"bgm_focus_pad"}
        }),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let challenge = h[header::WWW_AUTHENTICATE].to_str().unwrap();
    for required in ["content:write", "content:read", "insufficient_scope", "resource_metadata"] {
        assert!(challenge.contains(required), "{challenge}");
    }
    let (status, headers, _) = mcp(
        &f,
        access,
        "explanation_reconcile",
        json!({"request_id":"denied","evidence":{"input_tokens":1,"output_tokens":1}}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let challenge = headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    for scope in ["content:read", "billing:manage", "insufficient_scope"] {
        assert!(challenge.contains(scope), "{challenge}");
    }
    assert_eq!(
        f.st.repo.get_usage(&f.tenant, "mcp_calls", &chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),
        0
    );
    assert!(f.st.repo.list_cards(&f.tenant, None, 10, 0).await.unwrap().is_empty());
    let (s, _, _) = mcp(&f, access, "deck_create", json!({"title":"Allowed","language":"en"})).await;
    assert_eq!(s, StatusCode::OK);
    f.cleanup().await;
}

#[tokio::test]
async fn tenant_isolation_and_current_role_downgrade() {
    let f = fixture().await;
    let other =
        f.st.services
            .auth
            .register(&RegisterRequest {
                email: "other@example.com".into(),
                password: "password123".into(),
                display_name: "Other".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
    let other_p = f.st.services.auth.authenticate(Some(&other.access_token)).await.unwrap();
    let deck =
        f.st.services
            .content
            .create_deck(
                &other_p,
                memoswish_content::NewDeck {
                    title: "Private".into(),
                    description: String::new(),
                    language: "en".into(),
                    tags: vec![],
                },
            )
            .await
            .unwrap();
    let c = client(&f).await;
    let t = tokens(&f, &c, "content:read content:write").await;
    let at = t["access_token"].as_str().unwrap();
    let (s, _, body) = mcp(&f, at, "deck_list", json!({})).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!body.contains(&deck.id));
    let (s, _, body) = mcp(&f, at, "deck_export", json!({"deck_id":deck.id})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["result"]["isError"], true);
    let pool = sqlx::SqlitePool::connect(&f.st.config.database_url()).await.unwrap();
    sqlx::query("UPDATE tenant_memberships SET role='learner' WHERE tenant_id=? AND user_id=?")
        .bind(&f.tenant)
        .bind(&f.user)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(mcp(&f, at, "deck_create", json!({"title":"Blocked","language":"en"})).await.0, StatusCode::FORBIDDEN);
    assert_eq!(mcp(&f, at, "deck_list", json!({})).await.0, StatusCode::OK);
    assert_error(
        &f,
        post(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &c),
                ("refresh_token", t["refresh_token"].as_str().unwrap()),
                ("resource", "https://learn.example/mcp"),
            ],
            None,
            None,
        ),
        "invalid_scope",
    )
    .await;
    sqlx::query(
        "DELETE FROM users WHERE id=?2 AND EXISTS(SELECT 1 FROM tenant_memberships WHERE tenant_id=?1 AND user_id=?2)",
    )
    .bind(&f.tenant)
    .bind(&f.user)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(mcp(&f, at, "deck_list", json!({})).await.0, StatusCode::UNAUTHORIZED);
    assert!(f.st.repo.oauth_token(&digest(at)).await.unwrap().is_none(), "user deletion cascades grants and tokens");
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM auth_browser_sessions WHERE tenant_id=? AND user_id=?")
            .bind(&f.tenant)
            .bind(&f.user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "user deletion cascades browser sessions");
    assert!(f.st.repo.get_user(&other.user.tenant_id, &other.user.user_id).await.unwrap().is_some());
    pool.close().await;
    f.cleanup().await;
}

#[tokio::test]
async fn token_expiry_cleanup_and_auth_session_expiry() {
    let f = fixture().await;
    let c = client(&f).await;
    let b = start(&f, &c, "content:read").await;
    f.st.repo.oauth_cleanup(now() + 601).await.unwrap();
    assert_error(
        &f,
        post(
            "/oauth/login",
            &[("request_id", &b.id), ("csrf", &b.csrf), ("email", "ada@example.com"), ("password", "password123")],
            Some(&b.cookie),
            None,
        ),
        "access_denied",
    )
    .await;
    let t = tokens(&f, &c, "content:read").await;
    let at = t["access_token"].as_str().unwrap();
    let pool = sqlx::SqlitePool::connect(&f.st.config.database_url()).await.unwrap();
    let mut rec = f.st.repo.oauth_token(&digest(at)).await.unwrap().unwrap();
    rec.expires_at = now();
    sqlx::query("UPDATE oauth_tokens SET body=? WHERE hash=?")
        .bind(serde_json::to_string(&rec).unwrap())
        .bind(digest(at))
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(mcp(&f, at, "deck_list", json!({})).await.0, StatusCode::UNAUTHORIZED);
    f.st.repo.oauth_cleanup(now() + f.oauth.config.refresh_token_ttl_secs + 1).await.unwrap();
    assert!(f.st.repo.oauth_token(&digest(t["refresh_token"].as_str().unwrap())).await.unwrap().is_none());
    pool.close().await;
    f.cleanup().await;
}

#[tokio::test]
async fn registration_rate_limit_is_bounded_and_oauth_errors_are_standard() {
    let f = fixture().await;
    for _ in 0..60 {
        let (s, _, b) = send(&f, json_req("/oauth/register", json!({}), None)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
    }
    let (s, _, b) = send(&f, json_req("/oauth/register", registration(), None)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(serde_json::from_str::<Value>(&b).unwrap()["error"], "temporarily_unavailable");
    f.cleanup().await;
}

#[tokio::test]
async fn cors_exposes_oauth_challenge_for_explicit_origins() {
    let f = fixture().await;
    let mut st = f.st.clone();
    let mut config = (*st.config).clone();
    config.cors_origins = vec!["https://client.example".into()];
    config.mcp.allowed_origins = vec!["https://client.example".into()];
    st.config = Arc::new(config);
    let app = crate::auth_defenses::test_router(st);
    let r = app
        .oneshot(Request::get("/mcp").header(header::ORIGIN, "https://client.example").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(r.headers()[header::WWW_AUTHENTICATE].to_str().unwrap().contains("resource_metadata"));
    assert!(r.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS].to_str().unwrap().contains("www-authenticate"));
    f.cleanup().await;
}

#[tokio::test]
async fn pre_registered_public_client_works_with_dynamic_registration_disabled() {
    let f = fixture().await;
    let mut cfg = f.oauth.config.clone();
    cfg.dynamic_registration = false;
    cfg.pre_registered_clients = vec![memoswish_auth::oauth_config::PreRegisteredClient {
        client_id: "desktop-client".into(),
        client_name: "Trusted Desktop".into(),
        redirect_uris: vec!["https://client.example/cb?existing=1".into()],
        scope: "content:read".into(),
    }];
    let oauth = Arc::new(OAuthService::new(f.st.repo.clone(), f.st.services.auth.clone(), cfg).unwrap());
    oauth.install_clients().await.unwrap();
    oauth.install_clients().await.unwrap();
    let mut st = f.st.clone();
    st.oauth = Some(oauth);
    let app = crate::auth_defenses::test_router(st);
    let mut f = f;
    f.app = app;
    assert_error(&f, json_req("/oauth/register", registration(), None), "access_denied").await;
    let (_, _, b) = send(&f, get("/.well-known/oauth-authorization-server")).await;
    let v: Value = serde_json::from_str(&b).unwrap();
    assert!(v.get("registration_endpoint").is_none());
    let t = tokens(&f, "desktop-client", "content:read").await;
    assert_eq!(mcp(&f, t["access_token"].as_str().unwrap(), "deck_list", json!({})).await.0, StatusCode::OK);
    f.cleanup().await;
}

#[tokio::test]
async fn loopback_port_exception_is_narrow_and_code_uses_exact_redirect() {
    let f = fixture().await;
    let mut r = registration();
    r["redirect_uris"] = json!(["http://127.0.0.1:1234/callback"]);
    let (_, _, body) = send(&f, json_req("/oauth/register", r, None)).await;
    let c: Value = serde_json::from_str(&body).unwrap();
    let c = c["client_id"].as_str().unwrap();
    let mut p = auth_params(c, "content:read");
    p.iter_mut().find(|(k, _)| k == "redirect_uri").unwrap().1 = "http://127.0.0.1:5678/callback".into();
    let q = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(p.clone()).finish();
    let (s, h, b) = send(&f, get(&format!("/oauth/authorize?{q}"))).await;
    assert_eq!(s, StatusCode::OK);
    let b = login(&f, &browser(&h, b)).await;
    let (s, h, _) = send(
        &f,
        post(
            "/oauth/authorize",
            &[("request_id", &b.id), ("csrf", &b.csrf), ("decision", "approve")],
            Some(&b.cookie),
            None,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let u = url::Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(u.port(), Some(5678));
    let code = u.query_pairs().find(|(k, _)| k == "code").unwrap().1.into_owned();
    let mut request = redeem(c, &code);
    request.iter_mut().find(|(k, _)| *k == "redirect_uri").unwrap().1 = "http://127.0.0.1:1234/callback";
    assert_error(&f, post("/oauth/token", &request, None, None), "invalid_grant").await;
    request.iter_mut().find(|(k, _)| *k == "redirect_uri").unwrap().1 = "http://127.0.0.1:5678/callback";
    assert_eq!(send(&f, post("/oauth/token", &request, None, None)).await.0, StatusCode::OK);
    for redirect in
        ["http://127.0.0.2:5678/callback", "http://127.0.0.1:5678/other", "http://127.0.0.1:5678/path/../callback"]
    {
        p.iter_mut().find(|(k, _)| k == "redirect_uri").unwrap().1 = redirect.into();
        let q = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(p.clone()).finish();
        assert_error(&f, get(&format!("/oauth/authorize?{q}")), "invalid_redirect_uri").await;
    }
    f.cleanup().await;
}

#[tokio::test]
async fn expired_codes_cannot_redeem_and_expired_consumed_codes_still_revoke_on_replay() {
    let f = fixture().await;
    let c = client(&f).await;
    let pool = sqlx::SqlitePool::connect(&f.st.config.database_url()).await.unwrap();
    let raw = code(&f, &c, "content:read").await;
    let mut stored = f.st.repo.oauth_code(&digest(&raw)).await.unwrap().unwrap();
    stored.expires_at = now();
    sqlx::query("UPDATE oauth_authorization_codes SET expires_at=?, body=? WHERE hash=?")
        .bind(stored.expires_at)
        .bind(serde_json::to_string(&stored).unwrap())
        .bind(&stored.hash)
        .execute(&pool)
        .await
        .unwrap();
    assert_error(&f, post("/oauth/token", &redeem(&c, &raw), None, None), "invalid_grant").await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_tokens WHERE tenant_id=? AND grant_id=?")
        .bind(&f.tenant)
        .bind(&stored.grant.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let raw = code(&f, &c, "content:read").await;
    let (s, _, body) = send(&f, post("/oauth/token", &redeem(&c, &raw), None, None)).await;
    assert_eq!(s, StatusCode::OK);
    let t: Value = serde_json::from_str(&body).unwrap();
    let mut stored = f.st.repo.oauth_code(&digest(&raw)).await.unwrap().unwrap();
    stored.expires_at = now();
    sqlx::query("UPDATE oauth_authorization_codes SET expires_at=?, body=? WHERE hash=?")
        .bind(stored.expires_at)
        .bind(serde_json::to_string(&stored).unwrap())
        .bind(&stored.hash)
        .execute(&pool)
        .await
        .unwrap();
    assert_error(&f, post("/oauth/token", &redeem(&c, &raw), None, None), "invalid_grant").await;
    assert_eq!(mcp(&f, t["access_token"].as_str().unwrap(), "deck_list", json!({})).await.0, StatusCode::UNAUTHORIZED);
    pool.close().await;
    f.cleanup().await;
}

#[tokio::test]
async fn token_redirect_is_optional_for_single_and_multiple_registered_callbacks() {
    let f = fixture().await;
    for redirects in [
        json!(["https://client.example/cb?existing=1"]),
        json!(["https://client.example/cb?existing=1", "https://client.example/second"]),
    ] {
        let mut r = registration();
        r["redirect_uris"] = redirects;
        let (s, _, b) = send(&f, json_req("/oauth/register", r, None)).await;
        assert_eq!(s, StatusCode::CREATED);
        let registered: Value = serde_json::from_str(&b).unwrap();
        let c = registered["client_id"].as_str().unwrap();
        let code = code(&f, c, "content:read").await;
        let mut p = redeem(c, &code);
        p.iter_mut().find(|(k, _)| *k == "redirect_uri").unwrap().1 = "";
        assert_error(&f, post("/oauth/token", &p, None, None), "invalid_grant").await;
        p.retain(|(k, _)| *k != "redirect_uri");
        p.iter_mut().find(|(k, _)| *k == "code_verifier").unwrap().1 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFX";
        assert_error(&f, post("/oauth/token", &p, None, None), "invalid_grant").await;
        p.iter_mut().find(|(k, _)| *k == "code_verifier").unwrap().1 = VERIFIER;
        let (s, _, b) = send(&f, post("/oauth/token", &p, None, None)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let t: Value = serde_json::from_str(&b).unwrap();
        assert_eq!(mcp(&f, t["access_token"].as_str().unwrap(), "deck_list", json!({})).await.0, StatusCode::OK);
    }
    f.cleanup().await;
}

#[tokio::test]
async fn authorization_errors_only_redirect_to_validated_clients_and_query_mode() {
    let f = fixture().await;
    let c = client(&f).await;
    for key in ["client_id", "redirect_uri"] {
        for value in [None, Some(""), Some("https://evil.example/cb")] {
            let mut p = auth_params(&c, "invalid");
            p.retain(|(k, _)| k != key);
            if let Some(value) = value {
                p.push((key.into(), value.into()));
            }
            let q = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(p).finish();
            let (s, h, _) = send(&f, get(&format!("/oauth/authorize?{q}"))).await;
            assert_eq!(s, StatusCode::BAD_REQUEST);
            assert!(!h.contains_key(header::LOCATION));
        }
    }
    for key in ["response_type", "scope", "code_challenge", "code_challenge_method"] {
        let mut p = auth_params(&c, "content:read");
        p.retain(|(k, _)| k != key);
        let q = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(p).finish();
        assert_authorization_error(
            &f,
            get(&format!("/oauth/authorize?{q}")),
            "invalid_request",
            Some("state & + / 中文"),
        )
        .await;
    }
    for (mode, status) in
        [("query", StatusCode::OK), ("fragment", StatusCode::SEE_OTHER), ("form_post", StatusCode::SEE_OTHER)]
    {
        let mut p = auth_params(&c, "content:read");
        p.retain(|(k, _)| k != "state");
        p.push(("response_mode".into(), mode.into()));
        let q = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(p).finish();
        let req = get(&format!("/oauth/authorize?{q}"));
        if status == StatusCode::OK {
            assert_eq!(send(&f, req).await.0, status);
        } else {
            assert_authorization_error(&f, req, "invalid_request", None).await;
        }
    }
    f.cleanup().await;
}

#[tokio::test]
async fn token_missing_or_empty_required_parameters_return_invalid_request() {
    let f = fixture().await;
    let c = client(&f).await;
    let code = code(&f, &c, "content:read").await;
    for key in ["grant_type", "code", "code_verifier"] {
        for value in [None, Some("")] {
            let mut p = redeem(&c, &code);
            p.retain(|(k, _)| *k != key);
            if let Some(value) = value {
                p.push((key, value));
            }
            let (s, _, b) = send(&f, post("/oauth/token", &p, None, None)).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{key}: {b}");
            assert_eq!(serde_json::from_str::<Value>(&b).unwrap()["error"], "invalid_request");
        }
    }
    assert_eq!(send(&f, post("/oauth/token", &redeem(&c, &code), None, None)).await.0, StatusCode::OK);
    for value in [None, Some("")] {
        let mut p =
            vec![("client_id", c.as_str()), ("grant_type", "refresh_token"), ("resource", "https://learn.example/mcp")];
        if let Some(value) = value {
            p.push(("refresh_token", value));
        }
        let (s, _, b) = send(&f, post("/oauth/token", &p, None, None)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(serde_json::from_str::<Value>(&b).unwrap()["error"], "invalid_request");
    }
    f.cleanup().await;
}

#[tokio::test]
async fn registered_client_authentication_methods_are_enforced_for_token_and_revoke() {
    use base64::Engine;
    let f = fixture().await;
    for method in ["none", "client_secret_basic", "client_secret_post"] {
        let mut r = registration();
        r["token_endpoint_auth_method"] = json!(method);
        let (s, _, b) = send(&f, json_req("/oauth/register", r, None)).await;
        assert_eq!(s, StatusCode::CREATED, "{b}");
        let r: Value = serde_json::from_str(&b).unwrap();
        let c = r["client_id"].as_str().unwrap();
        let secret = r["client_secret"].as_str().unwrap_or("unregistered-secret");
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("{c}:{secret}"));
        let stored = f.st.repo.oauth_client(c).await.unwrap().unwrap();
        if method != "none" {
            assert_eq!(stored.secret_hash, Some(digest(secret)));
            assert!(!serde_json::to_string(&stored).unwrap().contains(secret));
        }
        let code = code(&f, c, "content:read").await;
        for endpoint in ["/oauth/token", "/oauth/revoke"] {
            let base = if endpoint == "/oauth/token" {
                redeem(c, &code)
            } else {
                vec![("client_id", c), ("token", "unknown")]
            };
            let mut mixed = base.clone();
            mixed.push(("client_secret", secret));
            let (s, _, b) = send(&f, post(endpoint, &mixed, None, Some(&basic))).await;
            assert_eq!(s, StatusCode::BAD_REQUEST);
            assert_eq!(serde_json::from_str::<Value>(&b).unwrap()["error"], "invalid_request");
            for attempted in ["none", "client_secret_basic", "client_secret_post"] {
                if attempted == method {
                    continue;
                }
                let mut p = base.clone();
                if attempted == "client_secret_post" {
                    p.push(("client_secret", secret));
                }
                let (s, _, b) =
                    send(&f, post(endpoint, &p, None, (attempted == "client_secret_basic").then_some(basic.as_str())))
                        .await;
                assert_eq!(s, StatusCode::UNAUTHORIZED, "{method}/{attempted}: {b}");
                assert_eq!(serde_json::from_str::<Value>(&b).unwrap()["error"], "invalid_client");
            }
            if method == "client_secret_post" {
                let mut wrong = base;
                wrong.push(("client_secret", "wrong"));
                assert_error(&f, post(endpoint, &wrong, None, None), "invalid_client").await;
            }
        }
        let mut p = redeem(c, &code);
        if method == "client_secret_post" {
            p.push(("client_secret", secret));
        }
        let basic = (method == "client_secret_basic").then_some(basic.as_str());
        let (s, _, b) = send(&f, post("/oauth/token", &p, None, basic)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let t: Value = serde_json::from_str(&b).unwrap();
        let mut p = vec![
            ("client_id", c),
            ("grant_type", "refresh_token"),
            ("refresh_token", t["refresh_token"].as_str().unwrap()),
            ("resource", "https://learn.example/mcp"),
        ];
        if method == "client_secret_post" {
            p.push(("client_secret", secret));
        }
        let (s, _, b) = send(&f, post("/oauth/token", &p, None, basic)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let rotated: Value = serde_json::from_str(&b).unwrap();
        let mut p = vec![("client_id", c), ("token", rotated["refresh_token"].as_str().unwrap())];
        if method == "client_secret_post" {
            p.push(("client_secret", secret));
        }
        assert_eq!(send(&f, post("/oauth/revoke", &p, None, basic)).await.0, StatusCode::OK);
        assert_eq!(
            mcp(&f, rotated["access_token"].as_str().unwrap(), "deck_list", json!({})).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    f.cleanup().await;
}

#[tokio::test]
async fn authorization_login_and_consent_never_enable_cors() {
    let f = fixture().await;
    let c = client(&f).await;
    let query =
        url::form_urlencoded::Serializer::new(String::new()).extend_pairs(auth_params(&c, "content:read")).finish();
    for origins in [vec!["https://client.example".into()], vec!["*".into()]] {
        let mut st = f.st.clone();
        let mut cfg = (*st.config).clone();
        cfg.cors_origins = origins;
        st.config = Arc::new(cfg);
        let app = crate::auth_defenses::test_router(st);
        for (method, path) in [
            ("GET", format!("/oauth/authorize?{query}")),
            ("POST", "/oauth/authorize".into()),
            ("POST", "/oauth/login".into()),
        ] {
            for preflight in [false, true] {
                let mut req = Request::builder()
                    .method(if preflight { "OPTIONS" } else { method })
                    .uri(&path)
                    .header(header::ORIGIN, "https://client.example");
                if preflight {
                    req = req.header(header::ACCESS_CONTROL_REQUEST_METHOD, method);
                }
                let r = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
                assert!(
                    !r.headers().keys().any(|name| name.as_str().starts_with("access-control-")),
                    "{method} {path}: {:?}",
                    r.headers()
                );
            }
        }
        for (method, path) in
            [("GET", "/.well-known/oauth-authorization-server"), ("POST", "/oauth/token"), ("GET", "/v1/server-info")]
        {
            for preflight in [false, true] {
                let mut req = Request::builder()
                    .method(if preflight { "OPTIONS" } else { method })
                    .uri(path)
                    .header(header::ORIGIN, "https://client.example");
                if preflight {
                    req = req.header(header::ACCESS_CONTROL_REQUEST_METHOD, method);
                }
                let r = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
                assert!(r.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN), "{method} {path}");
            }
        }
    }
    f.cleanup().await;
}

#[tokio::test]
async fn rotation_preserves_preexisting_narrow_refresh_scopes() {
    let f = fixture().await;
    let c = client(&f).await;
    let t = tokens(&f, &c, "content:read content:write").await;
    let rt = t["refresh_token"].as_str().unwrap();
    let mut stored = f.st.repo.oauth_token(&digest(rt)).await.unwrap().unwrap();
    stored.scopes = vec!["content:read".into()];
    let pool = sqlx::SqlitePool::connect(&f.st.config.database_url()).await.unwrap();
    sqlx::query("UPDATE oauth_tokens SET body=? WHERE hash=?")
        .bind(serde_json::to_string(&stored).unwrap())
        .bind(digest(rt))
        .execute(&pool)
        .await
        .unwrap();
    let mut p = vec![
        ("client_id", c.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", rt),
        ("resource", "https://learn.example/mcp"),
        ("scope", "content:write"),
    ];
    assert_error(&f, post("/oauth/token", &p, None, None), "invalid_scope").await;
    p.pop();
    let (s, _, b) = send(&f, post("/oauth/token", &p, None, None)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let next: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(next["scope"], "content:read");
    let stored = f.st.repo.oauth_token(&digest(next["refresh_token"].as_str().unwrap())).await.unwrap().unwrap();
    assert_eq!(stored.scopes, ["content:read"]);
    pool.close().await;
    f.cleanup().await;
}

#[tokio::test]
async fn batch_and_apkg_preflight_reject_before_application_admission() {
    let f = fixture().await;
    let c = client(&f).await;
    let token = tokens(&f, &c, "content:write content:read").await;
    let access = token["access_token"].as_str().unwrap();
    let calls = json!([
        {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_create","arguments":{"title":"Must not exist","language":"en"}}},
        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"card_upsert","arguments":{"cards":[]}}}
    ]);
    let (status, headers, _) = send(&f, json_req("/mcp", calls, Some(access))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(headers[header::WWW_AUTHENTICATE].to_str().unwrap().contains("tts:generate"));
    // 即使无图片或参数尚未解码，APKG OAuth 预检仍要求媒体写权限。
    let (status, headers, _) = mcp(&f, access, "deck_import_apkg", json!({"apkg_base64":"invalid"})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(headers[header::WWW_AUTHENTICATE].to_str().unwrap().contains("media:write"));
    let p = f.st.services.auth.authenticate(Some(&f.jwt)).await.unwrap();
    assert!(f.st.services.list_decks(&p).await.unwrap().is_empty());
    assert!(f.st.services.usage(&p).await.unwrap().metrics.iter().all(|metric| metric.used == 0));
    f.cleanup().await;
}

#[tokio::test]
async fn admission_unavailable_preserves_oauth_503_security_headers_and_rest_envelope() {
    struct Unavailable;
    #[async_trait::async_trait]
    impl memoswish_core::rate_limit::RateLimiter for Unavailable {
        async fn check(&self, _: &str, _: f64) -> memoswish_core::CoreResult<()> {
            Err(memoswish_core::CoreError::Unavailable("rate limiter unavailable".into()))
        }
    }
    let f = fixture().await;
    let mut st = f.st.clone();
    let mut service = OAuthService::new(st.repo.clone(), st.services.auth.clone(), f.oauth.config.clone()).unwrap();
    service.limiter = Arc::new(Unavailable);
    st.oauth = Some(Arc::new(service));
    st.auth_admission = Arc::new(crate::auth_defenses::AuthAdmission::test_backend(Arc::new(Unavailable)));
    let app = crate::auth_defenses::test_router(st);
    let response = app.clone().oneshot(json_req("/oauth/register", registration(), None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    let body: Value = serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"], "temporarily_unavailable");
    let response = app
        .oneshot(json_req("/v1/auth/login", json!({"email":"ada@example.com","password":"password123"}), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["code"], "temporarily_unavailable");
    f.cleanup().await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires PostgreSQL"]
fn feature_matrix_postgres_http_authorization_and_restart() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        for replay in [false, true] {
            let (database, url) = crate::feature_tests::postgres_database(&owner).await;
            let f = fixture_with_database(Some(url)).await;
            if replay {
                refresh_replay_case(f).await;
            } else {
                full_flow_case(f).await;
            }
            database.cleanup().await;
        }
    });
}
