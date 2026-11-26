//! 真实路由验证预算、未知字段、本人用途、撤回和错误脱敏。
use crate::{app::AppState, config::Config};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn send(st: &AppState, body: String) -> (StatusCode, String) {
    let response = crate::api::router(st.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/diagnostics/reports")
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}
#[tokio::test]
async fn diagnostics_http_opt_in_redaction_budget_and_operation_capture() {
    let dir = std::env::temp_dir().join(format!("memoswish-diagnostics-{}", memoswish_core::ids::new_id()));
    let mut policy = memoswish_protocol::examples::sample_privacy_policy();
    policy.hosted = false;
    policy.purpose_versions.insert("diagnostics".into(), "diagnostics-v1".into());
    let mut config = Config { data_dir: dir.clone(), privacy: policy.clone(), ..Default::default() };
    config.tts.auto_detect_espeak = false;
    let st = AppState::build(config).await.unwrap();
    let p = st.services.auth.authenticate(None).await.unwrap();
    let mut report = memoswish_protocol::examples::sample_diagnostic_report();
    report.captured_at_ms = chrono::Utc::now().timestamp_millis() - 1000;
    assert_eq!(send(&st, serde_json::to_string(&report).unwrap()).await.0, StatusCode::FORBIDDEN);
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("diagnostics", "diagnostics-v1", ""),
    ] {
        let state = st.services.privacy_state(&p).await.unwrap();
        st.services
            .update_privacy(
                &p,
                &memoswish_protocol::PrivacyUpdate {
                    expected_revision: state.revision,
                    kind: kind.into(),
                    version: version.into(),
                    value: value.into(),
                    decision: true,
                },
            )
            .await
            .unwrap();
    }
    report.privacy_revision = st.services.privacy_state(&p).await.unwrap().revision;
    let body = serde_json::to_string(&report).unwrap();
    assert_eq!(send(&st, body.clone()).await.0, StatusCode::OK);
    let (_, duplicate) = send(&st, body.clone()).await;
    assert_eq!(serde_json::from_str::<Value>(&duplicate).unwrap()["duplicate"], true);
    let mut forged = serde_json::to_value(&report).unwrap();
    forged["user_id"] = json!("secret@example.invalid");
    let denied = send(&st, forged.to_string()).await;
    assert_eq!(denied.0, StatusCode::BAD_REQUEST);
    assert!(!denied.1.contains("secret"));
    for value in [
        json!({"frames":["secret"]}),
        json!({"build":"https://secret@example.invalid/?token=secret"}),
        json!({"frames":vec!["data";33]}),
    ] {
        let mut altered = serde_json::to_value(&report).unwrap();
        for (k, v) in value.as_object().unwrap() {
            altered[k] = v.clone();
        }
        let denied = send(&st, altered.to_string()).await;
        assert_eq!(denied.0, StatusCode::BAD_REQUEST);
        assert!(!denied.1.contains("secret"));
    }
    let denied = send(&st, format!("{}{}", body, " ".repeat(16 * 1024))).await;
    assert_eq!(denied.0, StatusCode::BAD_REQUEST);
    let denied = send(&st, "[".repeat(2000)).await;
    assert_eq!(denied.0, StatusCode::BAD_REQUEST);
    // 已授权服务器操作失败只记录固定 code，不记录业务 ID 或错误消息。
    let failed =
        st.services.explain_card(&p, "secret-missing-card", &memoswish_protocol::ExplainRequest::default()).await;
    assert!(failed.is_err());
    let export = st.repo.account_export(&p.tenant_id, &p.user_id, true).await.unwrap();
    assert_eq!(export["diagnostic_reports"].as_array().unwrap().len(), 2);
    assert!(!export["diagnostic_reports"].to_string().contains("secret-missing-card"));
    // 持久解释请求同样经过诊断包装，不能绕过 身份校验与预算限制。
    let failed = st
        .services
        .explain_card(
            &p,
            "secret-missing-card",
            &memoswish_protocol::ExplainRequest {
                request_id: Some("diagnostic-owned-explanation".into()),
                ..Default::default()
            },
        )
        .await;
    assert!(failed.is_err());
    let export = st.repo.account_export(&p.tenant_id, &p.user_id, true).await.unwrap();
    assert_eq!(export["diagnostic_reports"].as_array().unwrap().len(), 3);
    assert!(!export["diagnostic_reports"].to_string().contains("secret-missing-card"));
    st.services
        .update_privacy(
            &p,
            &memoswish_protocol::PrivacyUpdate {
                expected_revision: report.privacy_revision,
                kind: "diagnostics".into(),
                version: "diagnostics-v1".into(),
                decision: false,
                value: String::new(),
            },
        )
        .await
        .unwrap();
    assert_eq!(send(&st, body).await.0, StatusCode::FORBIDDEN);
    assert!(
        st.repo.account_export(&p.tenant_id, &p.user_id, true).await.unwrap()["diagnostic_reports"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}
