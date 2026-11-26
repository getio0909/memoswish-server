//! 私有资产在读取前与释放响应前都执行托管资格边界。
use super::*;

#[tokio::test]
async fn privacy_assets_enforce_eligibility_for_sessions_tokens_and_late_reads() {
    let (mut st, dir, tenant, url) = opaque_asset_fixture().await;
    let session = opaque_asset_session(&st, &tenant).await;
    let p = st.services.auth.authenticate(Some(&session.access_token)).await.unwrap();
    let token = st.services.auth.create_api_token(&p, "privacy asset", vec!["*".into()], None).await.unwrap().plaintext;
    let mut policy = memoswish_protocol::examples::sample_privacy_policy();
    st.repo.privacy_install_policy(&policy).await.unwrap();
    st.services.auth = st.services.auth.clone().with_privacy_policy(policy.clone()).unwrap();
    let etag = format!("\"{}\"", memoswish_core::ids::sha256_hex(b"abc"));
    let request = |token: &str, condition: Option<(&str, &str)>| {
        let mut req = Request::get(&url).header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some((name, value)) = condition {
            req = req.header(name, value);
        }
        req.body(Body::empty()).unwrap()
    };
    let conditions = [None, Some(("range", "bytes=0-1")), Some(("if-none-match", etag.as_str()))];
    for phase in ["unknown", "underage", "eligible", "stale-notice", "stale-terms"] {
        let mut state = st.services.auth.privacy_state(&p).await.unwrap();
        let updates = match phase {
            "underage" => vec![("age", "notice-v1", false, "underage")],
            "eligible" => vec![
                ("notice", "notice-v1", true, ""),
                ("terms", "terms-v1", true, ""),
                ("age", "notice-v1", true, "example-region"),
            ],
            _ => vec![],
        };
        for (kind, version, decision, value) in updates {
            state = st
                .services
                .auth
                .update_privacy(
                    &p,
                    &memoswish_protocol::PrivacyUpdate {
                        expected_revision: state.revision,
                        kind: kind.into(),
                        version: version.into(),
                        decision,
                        value: value.into(),
                    },
                )
                .await
                .unwrap();
        }
        if phase == "stale-notice" {
            policy.notice_version = "notice-v2".into();
        }
        if phase == "stale-terms" {
            policy.notice_version = "notice-v1".into();
            policy.terms_version = "terms-v2".into();
        }
        st.repo.privacy_install_policy(&policy).await.unwrap();
        st.services.auth = st.services.auth.clone().with_privacy_policy(policy.clone()).unwrap();
        let app = crate::auth_defenses::test_router(st.clone());
        for bearer in [&session.access_token, &token] {
            for (index, condition) in conditions.iter().enumerate() {
                let status = send(&app, request(bearer, *condition)).await.0;
                let expected = if phase == "eligible" {
                    [StatusCode::OK, StatusCode::PARTIAL_CONTENT, StatusCode::NOT_MODIFIED][index]
                } else {
                    StatusCode::FORBIDDEN
                };
                assert_eq!(status, expected, "{phase}");
            }
        }
        assert_eq!(send(&app, get("/assets/shared/bgm/bgm_calm_pad.wav")).await.0, StatusCode::OK);
        assert_eq!(
            send(
                &app,
                Request::get("/v1/privacy/state")
                    .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token))
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    // 对象读取已开始时撤回资格，200/206/304 都不能释放旧响应。
    policy = memoswish_protocol::examples::sample_privacy_policy();
    st.repo.privacy_install_policy(&policy).await.unwrap();
    st.services.auth = st.services.auth.clone().with_privacy_policy(policy).unwrap();
    for bearer in [&session.access_token, &token] {
        for condition in conditions {
            let state = st.services.auth.privacy_state(&p).await.unwrap();
            st.services
                .auth
                .update_privacy(
                    &p,
                    &memoswish_protocol::PrivacyUpdate {
                        expected_revision: state.revision,
                        kind: "age".into(),
                        version: "notice-v1".into(),
                        decision: true,
                        value: "example-region".into(),
                    },
                )
                .await
                .unwrap();
            let entered = std::sync::Arc::new(tokio::sync::Notify::new());
            let release = std::sync::Arc::new(tokio::sync::Notify::new());
            let mut paused = st.clone();
            paused.store = std::sync::Arc::new(DeliveryBarrier {
                inner: st.store.clone(),
                entered: entered.clone(),
                release: release.clone(),
            });
            let app = crate::auth_defenses::test_router(paused);
            let req = request(bearer, condition);
            let waiting = tokio::spawn(async move { send(&app, req).await });
            entered.notified().await;
            assert!(!waiting.is_finished());
            let state = st.services.auth.privacy_state(&p).await.unwrap();
            st.services
                .auth
                .update_privacy(
                    &p,
                    &memoswish_protocol::PrivacyUpdate {
                        expected_revision: state.revision,
                        kind: "age".into(),
                        version: "notice-v1".into(),
                        decision: false,
                        value: "underage".into(),
                    },
                )
                .await
                .unwrap();
            release.notify_one();
            assert_eq!(waiting.await.unwrap().0, StatusCode::FORBIDDEN);
        }
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}
