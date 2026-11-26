//! 真实路由验证旧账户默认拒绝、第一方分离更新及委托继承。
use crate::{app::AppState, config::Config};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
async fn send(st: &AppState, method: &str, path: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = crate::auth_defenses::test_router(st.clone())
        .oneshot(req.body(if body.is_null() { Body::empty() } else { Body::from(body.to_string()) }).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}
#[tokio::test]
async fn privacy_routes_and_delegated_enforcement() {
    let dir = std::env::temp_dir().join(format!("memoswish-privacy-{}", memoswish_core::ids::new_id()));
    let st = AppState::build(Config {
        data_dir: dir.clone(),
        mode: memoswish_protocol::DeploymentMode::MultiTenant,
        registration_open: true,
        privacy: memoswish_protocol::examples::sample_privacy_policy(),
        ..Default::default()
    })
    .await
    .unwrap();
    // 已有账户由测试运营方预置；公开托管开户仍被关闭。
    let provisioner = memoswish_auth::AuthService::new(
        st.repo.clone(),
        memoswish_auth::AuthConfig {
            mode: memoswish_protocol::DeploymentMode::MultiTenant,
            jwt_secret: "privacy-fixture-signing-key-32-bytes".into(),
            jwt_ttl_secs: 3600,
            registration_open: true,
            default_plan: "free".into(),
        },
    )
    .unwrap();
    provisioner
        .register(&memoswish_protocol::RegisterRequest {
            email: "privacy@example.invalid".into(),
            password: "privacy-password123".into(),
            display_name: "Privacy".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let jwt = st
        .services
        .auth
        .login(&memoswish_protocol::LoginRequest {
            email: "privacy@example.invalid".into(),
            password: "privacy-password123".into(),
        })
        .await
        .unwrap()
        .access_token;
    assert_eq!(send(&st, "GET", "/v1/privacy/policy", None, Value::Null).await.0, StatusCode::OK);
    assert_eq!(send(&st, "GET", "/v1/privacy/state", None, Value::Null).await.0, StatusCode::UNAUTHORIZED);
    let (status, initial) = send(&st, "GET", "/v1/privacy/state", Some(&jwt), Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(initial["revision"], 0);
    assert_eq!(send(&st, "GET", "/v1/feed", Some(&jwt), Value::Null).await.0, StatusCode::FORBIDDEN);
    let mut state = initial;
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_ai", "provider-policy-v1", ""),
    ] {
        let (status, next) = send(
            &st,
            "POST",
            "/v1/privacy/state",
            Some(&jwt),
            json!({"expected_revision":state["revision"],"kind":kind,"version":version,"decision":true,"value":value}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{next}");
        state = next;
    }
    assert_eq!(send(&st, "GET", "/v1/feed", Some(&jwt), Value::Null).await.0, StatusCode::OK);
    assert_eq!(send(&st,"POST","/v1/privacy/state",Some(&jwt),json!({"expected_revision":state["revision"],"kind":"notice","version":"notice-v1","decision":true,"user_id":"someone-else"})).await.0,StatusCode::BAD_REQUEST);
    assert!(!st.services.auth.registration_open());
    let p = st.services.auth.authenticate(Some(&jwt)).await.unwrap();
    let token = st.services.auth.create_api_token(&p, "privacy test", vec!["*".into()], None).await.unwrap();
    assert_eq!(send(&st,"POST","/v1/privacy/state",Some(&token.plaintext),json!({"expected_revision":state["revision"],"kind":"external_ai","version":"provider-policy-v1","decision":true})).await.0,StatusCode::FORBIDDEN);
    let (status,withdrawn)=send(&st,"POST","/v1/privacy/state",Some(&jwt),json!({"expected_revision":state["revision"],"kind":"external_ai","version":"provider-policy-v1","decision":false})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(withdrawn["purpose_records"].as_array().unwrap().iter().all(|r| r["decision"] == false));
    let delegated = st.services.auth.authenticate(Some(&token.plaintext)).await.unwrap();
    assert!(st.services.auth.admit_privacy_purpose(&delegated, "external_ai", None).await.is_err());
    let mcp = memoswish_mcp::tools::call(&st.services, &delegated, "deck_list", json!({})).await;
    assert!(mcp.is_ok());
    let denied=send(&st,"POST","/v1/privacy/state",Some(&jwt),json!({"expected_revision":withdrawn["revision"],"kind":"age","version":"notice-v1","decision":false,"value":"underage"})).await;
    assert_eq!(denied.0, StatusCode::OK);
    assert_eq!(send(&st, "GET", "/v1/decks", Some(&token.plaintext), Value::Null).await.0, StatusCode::FORBIDDEN);
    let mcp = memoswish_mcp::tools::call(&st.services, &delegated, "deck_list", json!({})).await;
    assert!(matches!(mcp, Err(memoswish_mcp::tools::CallError::Domain(memoswish_core::CoreError::Forbidden(_)))));
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn hosted_signup_cannot_persist_identity_before_eligibility() {
    let dir = std::env::temp_dir().join(format!("memoswish-privacy-signup-{}", memoswish_core::ids::new_id()));
    let st = AppState::build(Config {
        data_dir: dir.clone(),
        mode: memoswish_protocol::DeploymentMode::MultiTenant,
        registration_open: true,
        seed_demo: false,
        privacy: memoswish_protocol::examples::sample_privacy_policy(),
        ..Default::default()
    })
    .await
    .unwrap();
    let invalid = AppState::build(Config {
        data_dir: dir.join("invalid-hosted"),
        privacy: memoswish_protocol::examples::sample_privacy_policy(),
        ..Default::default()
    })
    .await
    .err()
    .unwrap();
    assert!(invalid.to_string().contains("hosted privacy enforcement requires authenticated multi-tenant mode"));
    let body = json!({"email":"unknown-age@example.invalid","password":"password123","display_name":"Unknown"});
    for uri in ["/v1/auth/register", "/v1/auth/sessions/register"] {
        assert_eq!(send(&st, "POST", uri, None, body.clone()).await.0, StatusCode::FORBIDDEN);
    }
    // OIDC 账户自动创建也调用同一个 registration_open 判定。
    assert!(!st.services.auth.registration_open());
    assert!(st.repo.account_by_email("unknown-age@example.invalid").await.unwrap().is_none());
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}
