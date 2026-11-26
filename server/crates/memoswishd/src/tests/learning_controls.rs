//! 真实 HTTP 验证控制错误包络、持久化、回执与学习统计边界。
use super::*;
async fn get(app: &Router, path: &str) -> (StatusCode, Value) {
    let (status, headers, body) = send(app, Request::get(path).body(Body::empty()).unwrap()).await;
    if path.starts_with("/v1/learning/") {
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }
    (status, serde_json::from_slice(&body).unwrap())
}
async fn command(app: &Router, path: &str, input: Value, expected: StatusCode) -> Value {
    let (status, headers, body) = send(app, post_json(path, &input, None)).await;
    assert_eq!(status, expected, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    serde_json::from_slice(&body).unwrap()
}
#[tokio::test]
async fn p33_learning_controls_http_replay_restart_and_negative_commands() {
    let dir = std::env::temp_dir().join(format!("memoswish-p33-http-{}", memoswish_core::ids::new_id()));
    let cfg = Config { data_dir: dir.clone(), ..Config::default() };
    let state = AppState::build(cfg.clone()).await.unwrap();
    let app = crate::auth_defenses::test_router(state.clone());
    let prefs = get(&app, "/v1/learning/preferences").await.1;
    assert_eq!(prefs, json!({"revision":0,"effective_retention":0.9}));
    let malformed = "/v1/learning/cards/%FF/control";
    let (status, error) = get(&app, malformed).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "bad_request");
    assert!(error["message"].is_string());
    let error = command(&app, malformed, json!({"expected_revision":0,"action":"bury"}), StatusCode::BAD_REQUEST).await;
    assert_eq!(error["code"], "bad_request");
    assert!(error["message"].is_string());
    for input in [
        json!({"expected_revision":0,"desired_retention":0.49}),
        json!({"expected_revision":0,"desired_retention":1.0}),
        json!({"expected_revision":0,"desired_retention":"NaN"}),
        json!({"desired_retention":0.8}),
        json!({"expected_revision":0,"desired_retention":0.8,"toggle":true}),
    ] {
        let error = command(&app, "/v1/learning/preferences", input, StatusCode::BAD_REQUEST).await;
        assert!(error.get("code").is_some());
    }
    let prefs = command(
        &app,
        "/v1/learning/preferences",
        json!({"expected_revision":0,"desired_retention":0.82}),
        StatusCode::OK,
    )
    .await;
    assert_eq!(prefs["effective_retention"], 0.82);
    assert_eq!(command(&app, "/v1/learning/preferences", json!({"expected_revision":1}), StatusCode::OK).await, prefs);
    command(
        &app,
        "/v1/learning/preferences",
        json!({"expected_revision":0,"desired_retention":0.82}),
        StatusCode::CONFLICT,
    )
    .await;
    let issued = get(&app, "/v1/feed?request_id=p33-original&limit=10").await.1;
    let items = issued["items"].as_array().unwrap();
    assert!(!items.is_empty());
    assert!(items.len() <= 4);
    let id = items[0]["card"]["id"].as_str().unwrap();
    let path = format!("/v1/learning/cards/{id}/control");
    let before = get(&app, "/v1/stats").await.1;
    let control = command(&app, &path, json!({"expected_revision":0,"action":"bury"}), StatusCode::OK).await;
    assert!(control["buried_until"].is_string());
    command(&app, &path, json!({"expected_revision":0,"action":"bury"}), StatusCode::CONFLICT).await;
    assert_eq!(get(&app, &path).await.1, control);
    assert_eq!(get(&app, "/v1/stats").await.1, before);
    assert_eq!(get(&app, "/v1/feed?request_id=p33-original&limit=10").await.1, issued);
    assert_eq!(get(&app, "/v1/learning/hidden?limit=1").await.1["items"][0]["card_id"], id);
    assert_eq!(get(&app, "/v1/learning/cards/foreign-id/control").await.0, StatusCode::NOT_FOUND);
    command(
        &app,
        "/v1/learning/cards/foreign-id/control",
        json!({"expected_revision":0,"action":"suspend"}),
        StatusCode::NOT_FOUND,
    )
    .await;
    command(&app, &path, json!({"expected_revision":1,"action":"toggle"}), StatusCode::BAD_REQUEST).await;
    state.services.operations.close();
    state.services.operations.wait().await;
    drop(app);
    drop(state);
    let state = AppState::build(cfg).await.unwrap();
    let app = crate::auth_defenses::test_router(state.clone());
    assert_eq!(get(&app, &path).await.1, control);
    assert_eq!(get(&app, "/v1/learning/preferences").await.1, prefs);
    let resumed = command(&app, &path, json!({"expected_revision":1,"action":"resume"}), StatusCode::OK).await;
    assert_eq!(resumed["suspended"], false);
    assert!(resumed.get("buried_until").is_none());
    assert!(before["total_cards"].as_u64().unwrap() > 4);
    let after_restart = get(&app, "/v1/feed?request_id=p33-after-restart&limit=1").await.1;
    assert!(
        items.iter().all(|item| item["card"]["id"] != after_restart["items"][0]["card"]["id"]),
        "issuance fairness must survive database restart"
    );
    let reset = command(
        &app,
        "/v1/learning/preferences",
        json!({"expected_revision":1,"desired_retention":null}),
        StatusCode::OK,
    )
    .await;
    assert_eq!(reset, json!({"revision":2,"effective_retention":0.9}));
    state.services.operations.close();
    state.services.operations.wait().await;
    drop(app);
    drop(state);
    tokio::fs::remove_dir_all(dir).await.unwrap();
}
