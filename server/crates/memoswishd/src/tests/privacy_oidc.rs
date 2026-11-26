//! OIDC 绑定不能借用登录 bootstrap 例外采集额外身份。
use super::*;

#[tokio::test]
async fn oidc_privacy_link_start_and_completion_enforce_hosted_eligibility() {
    let mut f = fixture("generic").await;
    let account =
        f.st.services
            .auth
            .register(&RegisterRequest {
                email: "privacy-link@example.invalid".into(),
                password: "password123".into(),
                display_name: "Privacy".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
    let jwt = &account.access_token;
    let p = f.st.services.auth.authenticate(Some(jwt)).await.unwrap();
    let policy = examples::sample_privacy_policy();
    f.st.repo.privacy_install_policy(&policy).await.unwrap();
    f.st.services.auth = f.st.services.auth.clone().with_privacy_policy(policy).unwrap();
    f.st.oidc = Some(Arc::new(
        OidcService::new(f.st.config.oidc.clone(), f.st.repo.clone(), f.st.services.auth.clone(), "free".into())
            .unwrap(),
    ));
    f.app = super::super::api::router(f.st.clone());
    for age in ["unknown", "underage"] {
        let state = f.st.services.auth.privacy_state(&p).await.unwrap();
        f.st.services
            .auth
            .update_privacy(
                &p,
                &PrivacyUpdate {
                    expected_revision: state.revision,
                    kind: "age".into(),
                    version: "notice-v1".into(),
                    decision: false,
                    value: age.into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            send(&f.app, "POST", "/v1/auth/oidc/test/link/start", Some(jwt), None, Some(start_request(false))).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(f.m.tokens.load(Ordering::SeqCst), 0);
        assert_eq!(
            send(&f.app, "POST", "/v1/auth/oidc/test/start", None, None, Some(start_request(false))).await.0,
            StatusCode::OK
        );
    }
    for (kind, version, value) in
        [("notice", "notice-v1", ""), ("terms", "terms-v1", ""), ("age", "notice-v1", "example-region")]
    {
        let state = f.st.services.auth.privacy_state(&p).await.unwrap();
        f.st.services
            .auth
            .update_privacy(
                &p,
                &PrivacyUpdate {
                    expected_revision: state.revision,
                    kind: kind.into(),
                    version: version.into(),
                    decision: true,
                    value: value.into(),
                },
            )
            .await
            .unwrap();
    }
    let b = begin(&f, Some(jwt)).await;
    let code = upstream(&f, &b, "privacy-new-identity", json!({"email":null}));
    let (status, headers, _) = callback(&f, &b, &code, None, Some(&b.cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let target = url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    let code = target.query_pairs().find(|(key, _)| key == "code").unwrap().1.to_string();
    let state = f.st.services.auth.privacy_state(&p).await.unwrap();
    f.st.services
        .auth
        .update_privacy(
            &p,
            &PrivacyUpdate {
                expected_revision: state.revision,
                kind: "age".into(),
                version: "notice-v1".into(),
                decision: false,
                value: "underage".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        send(
            &f.app,
            "POST",
            "/v1/auth/oidc/test/complete",
            Some(jwt),
            None,
            Some(json!({"code":code,"code_verifier":VERIFIER}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(f.st.repo.identity_list(&p.tenant_id, &p.user_id).await.unwrap().is_empty());
    // 身份查看、登录与注销仍可用；解绑和擦除由双库回归覆盖。
    assert_eq!(send(&f.app, "GET", "/v1/account/identities", Some(jwt), None, None).await.0, StatusCode::OK);
    assert!(
        f.st.services
            .auth
            .login(&LoginRequest { email: "privacy-link@example.invalid".into(), password: "password123".into() })
            .await
            .is_ok()
    );
    f.cleanup().await;
}
