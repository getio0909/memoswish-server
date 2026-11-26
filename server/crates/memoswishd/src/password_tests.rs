//! 真实路由的账户权限、匿名确认、缓存及 CP1 准入回归。
use crate::{Config, app::AppState};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use memoswish_core::{CoreResult, password_lifecycle::ChallengePurpose};
use memoswish_protocol::*;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
#[derive(Default)]
struct Mail(Mutex<Vec<String>>);
impl memoswish_auth::password_lifecycle::PasswordMail for Mail {
    fn deliver(&self, _: &str, _: ChallengePurpose, token: String) -> CoreResult<()> {
        self.0.lock().unwrap().push(token);
        Ok(())
    }
}
async fn send(st: &AppState, path: &str, value: Value, access: Option<&str>, ip: usize) -> (StatusCode, Value) {
    let mut b = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = access {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let request = b.body(Body::from(value.to_string())).unwrap();
    let router = crate::api::router(st.clone()).layer(axum::Extension(axum::extract::ConnectInfo(
        format!("192.0.2.{ip}:1234").parse::<std::net::SocketAddr>().unwrap(),
    )));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() };
    assert!(!body.to_string().contains("sentinel"));
    (status, body)
}
#[tokio::test]
async fn password_routes_use_first_party_root_and_preserve_generic_requests() {
    let directory = std::env::temp_dir().join(format!("memoswish-password-{}", memoswish_core::ids::new_id()));
    let mut st = AppState::build(Config {
        mode: DeploymentMode::MultiTenant,
        data_dir: directory.clone(),
        registration_open: true,
        seed_demo: false,
        ..Default::default()
    })
    .await
    .unwrap();
    let mail = Arc::new(Mail::default());
    st.services.auth = st.services.auth.clone().with_password_lifecycle(true, Some(mail.clone()));
    let root = st
        .services
        .auth
        .register_session(&RegisterRequest {
            email: "user@test.invalid".into(),
            password: "password-sentinel".into(),
            display_name: "User".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    for email in ["unknown@test.invalid", "user@test.invalid"] {
        let (status, body) = send(&st, "/v1/auth/password/reset", json!({"email":email}), None, 1).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"accepted":true}));
    }
    assert!(mail.0.lock().unwrap().is_empty());
    let (status, _) = send(
        &st,
        "/v1/auth/password/verification",
        json!({"email":"user@test.invalid","password":"password-sentinel"}),
        None,
        1,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &st,
        "/v1/auth/password/verification/resend",
        json!({"email":"user@test.invalid","password":"password-sentinel"}),
        None,
        6,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = mail.0.lock().unwrap().last().unwrap().clone();
    let (status, _) = send(
        &st,
        "/v1/auth/password/verification/confirm",
        json!({"email":"user@test.invalid","token":token}),
        None,
        1,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let memberships = st.services.auth.session_memberships(&root.access_token).await.unwrap();
    let workspace =
        st.services.auth.select_session_workspace(&root.access_token, &memberships[0].tenant_id).await.unwrap();
    let p = st.services.auth.authenticate(Some(&workspace.access_token)).await.unwrap();
    let api = st.services.auth.create_api_token(&p, "Agent", vec!["*".into()], None).await.unwrap();
    let body = json!({"current_password":"password-sentinel","new_password":"changed-sentinel"});
    for (i, access) in [api.plaintext.as_str(), workspace.access_token.as_str()].into_iter().enumerate() {
        let (status, _) = send(&st, "/v1/account/password", body.clone(), Some(access), i + 2).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = send(&st, "/v1/account/password", body, Some(&root.access_token), 4).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(st.services.auth.authenticate(Some(&api.plaintext)).await.is_err());
    assert!(st.services.auth.authenticate(Some(&workspace.access_token)).await.is_err());
    assert!(st.services.auth.authenticate_account(&root.access_token).await.is_err());
    assert!(
        st.services
            .auth
            .login_session(&LoginRequest { email: "user@test.invalid".into(), password: "changed-sentinel".into() })
            .await
            .is_ok()
    );
    let (status, _) = send(&st, "/v1/auth/password/reset", json!({"email":"user@test.invalid"}), None, 7).await;
    assert_eq!(status, StatusCode::OK);
    let token = mail.0.lock().unwrap().last().unwrap().clone();
    let (status, _) = send(
        &st,
        "/v1/auth/password/reset/confirm",
        json!({"email":"user@test.invalid","token":token,"new_password":"reset-sentinel"}),
        None,
        8,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(
        &st,
        "/v1/auth/password/reset/confirm",
        json!({"email":"missing@test.invalid","token":"bad-sentinel","new_password":"changed-sentinel"}),
        None,
        5,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    crate::runtime::cleanup_test_app(directory, &[&st]).await;
}

#[tokio::test]
async fn password_status_route_uses_account_authority() {
    let directory = std::env::temp_dir().join(format!("memoswish-password-status-{}", memoswish_core::ids::new_id()));
    let st = AppState::build(Config {
        mode: DeploymentMode::MultiTenant,
        data_dir: directory.clone(),
        registration_open: true,
        seed_demo: false,
        ..Default::default()
    })
    .await
    .unwrap();
    let root = st
        .services
        .auth
        .register_session(&RegisterRequest {
            email: "status@test.invalid".into(),
            password: "password-sentinel".into(),
            display_name: "Status".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let request = Request::builder()
        .method("GET")
        .uri("/v1/account/password")
        .header(header::AUTHORIZATION, format!("Bearer {}", root.access_token))
        .body(Body::empty())
        .unwrap();
    let response = crate::auth_defenses::test_router(st.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body: PasswordStatus =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(body.password_enabled);
    assert!(!body.email_verified);
    assert!(!body.mail_available);
    crate::runtime::cleanup_test_app(directory, &[&st]).await;
}
