//! 复用 OIDC 本地提供者夹具验证此前未命中的公开生产者。
use super::*;

#[tokio::test]
async fn compatibility_oidc_native_opaque_exchange_contract_and_replay() {
    let f = fixture("google").await;
    let (status, _, attempt) =
        send(&f.app, "POST", "/v1/auth/oidc/test/start", None, None, Some(start_request(true))).await;
    assert_eq!(status, StatusCode::OK);
    let mut c = claims(&f.m.issuer, attempt["nonce"].as_str().unwrap(), "opaque-native");
    c["aud"] = json!("native-client");
    let request = json!({"attempt_id":attempt["attempt_id"],"id_token":signed(&c,&KEYS,false),"nonce":attempt["nonce"],"code_verifier":VERIFIER});
    let (status, headers, body) =
        send(&f.app, "POST", "/v1/auth/sessions/oidc/test/exchange", None, None, Some(request.clone())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let session: SessionResponse = serde_json::from_value(body).unwrap();
    assert!(session.access_token.starts_with("lts_at_"));
    assert!(session.refresh_token.starts_with("lts_rt_"));
    assert!(session.workspace.is_none());
    assert!(f.st.services.auth.authenticate_account(&session.access_token).await.is_ok());
    assert_eq!(
        send(&f.app, "POST", "/v1/auth/sessions/oidc/test/exchange", None, None, Some(request)).await.0,
        StatusCode::UNAUTHORIZED
    );
    f.task.abort();
    f.cleanup().await;
}

#[tokio::test]
async fn compatibility_oidc_browser_launch_and_get_callback_contract() {
    let f = fixture("generic").await;
    let (status, _, attempt) =
        send(&f.app, "POST", "/v1/auth/oidc/test/start", None, None, Some(start_request(false))).await;
    assert_eq!(status, StatusCode::OK);
    let launch = url::Url::parse(attempt["launch_url"].as_str().unwrap()).unwrap();
    assert_eq!(launch.path(), "/v1/auth/oidc/test/start");
    let (status, headers, _) =
        send(&f.app, "GET", &format!("{}?{}", launch.path(), launch.query().unwrap()), None, None, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let b = Browser {
        provider: "test".into(),
        upstream: url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap(),
        cookie: headers[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().into(),
        link_jwt: None,
    };
    let code = upstream(&f, &b, "compat-browser", json!({}));
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", &query(&b, "state"))
        .append_pair("code", &code)
        .finish();
    let path = format!("/v1/auth/oidc/test/callback?{query}");
    let (status, headers, _) = send(&f.app, "GET", &path, None, Some(&b.cookie), None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let redirect = url::Url::parse(headers[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(redirect.scheme(), "com.memoswish.app");
    let handoff = redirect.query_pairs().find(|(key, _)| key == "code").unwrap().1.into_owned();
    let (status, headers, auth) = send(
        &f.app,
        "POST",
        "/v1/auth/oidc/test/complete",
        None,
        None,
        Some(json!({"code":handoff,"code_verifier":VERIFIER})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{auth}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    serde_json::from_value::<AuthResponse>(auth).unwrap();
    assert_eq!(send(&f.app, "GET", &path, None, Some(&b.cookie), None).await.0, StatusCode::UNAUTHORIZED);
    f.task.abort();
    f.cleanup().await;
}
