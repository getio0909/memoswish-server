//! 端到端 HTTP 测试：真实组装 AppState（SQLite + 临时目录），通过 tower `oneshot` 调用路由。

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use memoswish_protocol::{
    Card, CardExplanation, Deck, DeckPack, DeploymentMode, FeedPage, FeedbackAck, FeedbackBatch, ImplicitFeedback,
    LearningStats, ServerInfo, SwipeDirection,
};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::app::AppState;
use crate::config::Config;

async fn app(mode: DeploymentMode) -> (Router, AppState, std::path::PathBuf) {
    let (st, dir) = app_state(mode).await;
    (crate::auth_defenses::test_router(st.clone()), st, dir)
}

async fn app_state(mode: DeploymentMode) -> (AppState, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("memoswishd-test-{}", memoswish_core::ids::new_id()));
    let cfg = Config {
        mode,
        data_dir: dir.clone(),
        registration_open: true,
        default_plan: "free".into(),
        seed_demo: true,
        tts: crate::config::TtsConfig { default_engine: "placeholder".into(), ..Default::default() },
        ..Config::default()
    };
    let st = AppState::build(cfg).await.unwrap();
    (st, dir)
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, body)
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

fn post_json(uri: &str, v: &Value, token: Option<&str>) -> Request<Body> {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
    if uri == "/mcp" {
        b = b.header(header::HOST, "localhost");
    }
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(v.to_string())).unwrap()
}

pub(crate) fn explanation_test_policy() -> memoswish_core::explanations::ExplanationPolicy {
    serde_json::from_value(json!({
        "deployment_id":"generation-test", "provider_account":"generation-test", "pricing_version":"v1",
        "currency":"USD", "valid_until_ms":i64::MAX, "input_rate":1, "output_rate":1, "rate_denominator":1000,
        "tenant_limit":10000, "deployment_limit":10000, "provider_limit":10000, "unresolved_limit":10000,
        "cache_entry_bytes":16384, "cache_tenant_bytes":32768, "cache_deployment_bytes":65536, "cache_ttl_ms":60000
    }))
    .unwrap()
}

#[tokio::test]
async fn embedded_rest_and_mcp_still_execute_configured_explanation_provider() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = Router::new()
        .route(
            "/v1/chat/completions",
            axum::routing::post(|axum::extract::State(calls): axum::extract::State<Arc<AtomicUsize>>| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let explanation = json!({
                    "summary":"External explanation", "key_points":["Key idea"],
                    "analogy":"An example", "follow_up_questions":["Why?"]
                });
                axum::Json(json!({
                    "id":"chatcmpl-routes", "model":"gpt-4o-mini-2024-07-18", "service_tier":"default",
                    "usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12},
                    "choices":[{"finish_reason":"stop","message":{"content":explanation.to_string()}}]
                }))
            }),
        )
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let mock = tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
    let dir = std::env::temp_dir().join(format!("memoswish-explanation-{}", memoswish_core::ids::new_id()));
    let cfg = Config {
        data_dir: dir.clone(),
        seed_demo: false,
        privacy: memoswish_protocol::PrivacyPolicy {
            hosted: false,
            ..memoswish_protocol::examples::sample_privacy_policy()
        },
        ai: memoswish_content::AiExplainConfig {
            base_url: Some(endpoint),
            api_key: Some("synthetic-explanation-key".into()),
            budget: Some(explanation_test_policy()),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut state = AppState::build(cfg).await.unwrap();
    struct LoginBudget(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl memoswish_core::rate_limit::RateLimiter for LoginBudget {
        async fn check(&self, _: &str, _: f64) -> memoswish_core::CoreResult<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(memoswish_core::CoreError::QuotaExceeded("login budget exhausted".into()))
        }
    }
    let login_budget = Arc::new(LoginBudget(AtomicUsize::new(0)));
    state.auth_admission = Arc::new(crate::auth_defenses::AuthAdmission::test_backend(login_budget.clone()));
    state.services.operations.close();
    state.services.operations.wait().await;
    state.services.operations = Default::default();
    state.mcp = std::sync::Arc::new(memoswish_mcp::McpServer::new(state.services.clone()));
    let p = memoswish_core::Principal::local_owner("single_user");
    let pack = memoswish_protocol::examples::sample_deck_pack();
    let deck = state.services.import_deck_pack(&p, pack).await.unwrap();
    let card_id = state.services.list_cards(&p, Some(&deck.id), 1, 0).await.unwrap()[0].id.clone();
    let app = crate::auth_defenses::test_router(state.clone());
    let (status, _, body) =
        send(&app, post_json(&format!("/v1/cards/{card_id}/explain"), &json!({"request_id":"absent-purpose"}), None))
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "forbidden");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        state.services.explanation_operation(&p, "absent-purpose").await,
        Err(memoswish_core::CoreError::NotFound(_))
    ));
    // 付费入口与普通认证路由一致拒绝无效凭据，且不写入付费责任。
    for path in ["/v1/me".to_owned(), format!("/v1/cards/{card_id}/explain")] {
        let req = if path == "/v1/me" {
            Request::get(&path).header(header::AUTHORIZATION, "Bearer ltk_invalid").body(Body::empty()).unwrap()
        } else {
            post_json(&path, &json!({"request_id":"invalid-credential"}), Some("ltk_invalid"))
        };
        assert_eq!(send(&app, req).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        state.services.explanation_operation(&p, "invalid-credential").await,
        Err(memoswish_core::CoreError::NotFound(_))
    ));
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_ai", "provider-policy-v1", ""),
    ] {
        let current = state.services.auth.privacy_state(&p).await.unwrap();
        state
            .services
            .auth
            .update_privacy(
                &p,
                &memoswish_protocol::PrivacyUpdate {
                    expected_revision: current.revision,
                    kind: kind.into(),
                    version: version.into(),
                    decision: true,
                    value: value.into(),
                },
            )
            .await
            .unwrap();
    }
    let (status, _, body) =
        send(&app, post_json(&format!("/v1/cards/{card_id}/explain"), &json!({"request_id":"rest-explanation"}), None))
            .await;
    assert_eq!(status, StatusCode::OK);
    let rest: CardExplanation = serde_json::from_slice(&body).unwrap();
    assert_eq!(rest.provider, "openai:gpt-4o-mini");
    assert_eq!(rest.summary, "External explanation");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"card_explain","arguments":{"card_id":card_id,"request_id":"mcp-explanation","question":"MCP follow-up"}}});
    let (status, _, body) = send(&app, post_json("/mcp", &request, None)).await;
    assert_eq!(status, StatusCode::OK);
    let mcp: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(mcp["result"]["isError"], false, "{mcp}");
    assert_eq!(mcp["result"]["structuredContent"]["summary"], rest.summary);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    // REST 与 MCP 的付费解释均不消耗密码准入，实际登录仍经过同一关闭预算。
    assert_eq!(login_budget.0.load(Ordering::SeqCst), 0);
    let (status, headers, _) =
        send(&app, post_json("/v1/auth/login", &json!({"email":"budget@example.com","password":"password123"}), None))
            .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(headers[header::RETRY_AFTER], "10");
    assert_eq!(login_budget.0.load(Ordering::SeqCst), 1);
    let current = state.services.auth.privacy_state(&p).await.unwrap();
    state
        .services
        .auth
        .update_privacy(
            &p,
            &memoswish_protocol::PrivacyUpdate {
                expected_revision: current.revision,
                kind: "external_ai".into(),
                version: "provider-policy-v1".into(),
                decision: false,
                value: String::new(),
            },
        )
        .await
        .unwrap();
    for key in ["rest-explanation", "withdrawn-purpose"] {
        let (status, _, body) =
            send(&app, post_json(&format!("/v1/cards/{card_id}/explain"), &json!({"request_id":key}), None)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "forbidden");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let receipt = state.services.explanation_operation(&p, "rest-explanation").await.unwrap();
    let accounting = receipt.accounting.unwrap();
    assert_eq!((accounting.attempts, accounting.held_microcurrency, accounting.committed_microcurrency), (1, 0, 2));
    crate::runtime::drain_background(&state).await;
    mock.abort();
    let _ = mock.await;
    crate::runtime::cleanup_test_app(dir, &[&state]).await;
}

#[tokio::test]
async fn feed_receipts_replay_and_reject_conflicting_or_unknown_cursors() {
    let (app, st, dir) = app(DeploymentMode::SingleUser).await;
    let first_uri = "/v1/feed?request_id=http-retry&limit=2";
    let (status, _, body) = send(&app, get(first_uri)).await;
    assert_eq!(status, StatusCode::OK);
    let first: FeedPage = serde_json::from_slice(&body).unwrap();
    assert_eq!(send(&app, get(first_uri)).await.2, body);
    let uri = format!("/v1/feed?session_id={}&cursor={}&limit=2", first.session_id, first.next_cursor);
    let (left, right) = tokio::join!(send(&app, get(&uri)), send(&app, get(&uri)));
    assert_eq!(left.0, StatusCode::OK);
    assert_eq!(left.2, right.2);
    let second: FeedPage = serde_json::from_slice(&left.2).unwrap();
    assert_eq!(second.items[0].slot, 2);
    assert_eq!(send(&app, get(first_uri)).await.2, body);
    let conflict = uri.replace("limit=2", "limit=3");
    let (status, _, body) = send(&app, get(&conflict)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "conflict");
    for uri in [
        format!("/v1/feed?session_id={}&cursor=fp_unknown&limit=2", first.session_id),
        "/v1/feed?session_id=unknown&cursor=fp_unknown&limit=2".into(),
        "/v1/feed?cursor=fp_unknown".into(),
    ] {
        let (status, _, body) = send(&app, get(&uri)).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"code":"session_expired","message":"feed session expired"})
        );
    }
    // REST 与 MCP 共用显式非学习预览，保留页封套但没有可用续页身份。
    let (status, _, body) = send(&app, get("/v1/feed?mode=preview&limit=1")).await;
    assert_eq!(status, StatusCode::OK);
    let page: FeedPage = serde_json::from_slice(&body).unwrap();
    assert_eq!(page.mode.as_deref(), Some("preview"));
    assert!(page.next_cursor.is_empty());
    assert!(page.items[0].delivery_id.is_none());
    let mut batch = memoswish_protocol::examples::sample_feedback_batch();
    batch.session_id = page.session_id.clone();
    batch.events.truncate(1);
    batch.events[0].card_id = page.items[0].card.id.clone();
    batch.events[0].slot = page.items[0].slot;
    let (_, _, body) = send(&app, post_json("/v1/feedback", &serde_json::to_value(batch).unwrap(), None)).await;
    assert_eq!(serde_json::from_slice::<FeedbackAck>(&body).unwrap().rejected[0].reason, "invalid delivery binding");
    let preview =
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"feed_preview","arguments":{"limit":1}}});
    let (status, _, body) = send(&app, post_json("/mcp", &preview, None)).await;
    assert_eq!(status, StatusCode::OK);
    let response: Value = serde_json::from_slice(&body).unwrap();
    assert!(response.get("error").is_none(), "{response}");
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn single_user_feed_loop() {
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let app = crate::auth_defenses::test_router(st.clone());

    let (s, _, body) = send(&app, get("/v1/server-info")).await;
    assert_eq!(s, StatusCode::OK);
    let info: ServerInfo = serde_json::from_slice(&body).unwrap();
    assert_eq!(info.mode, DeploymentMode::SingleUser);
    assert!(info.tts_engines.contains(&"placeholder".to_string()));

    let (s, _, body) = send(&app, get("/v1/decks")).await;
    assert_eq!(s, StatusCode::OK);
    let decks: Vec<Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(decks.len(), 4, "demo decks seeded");

    let (s, _, body) = send(&app, get("/v1/feed?limit=6")).await;
    assert_eq!(s, StatusCode::OK);
    let page: FeedPage = serde_json::from_slice(&body).unwrap();
    assert_eq!(page.items.len(), 4);
    // 六条反馈来自两个真实短页，保留批次幂等、后缀失败和统计断言。
    let (status, _, body) =
        send(&app, get(&format!("/v1/feed?limit=2&session_id={}&cursor={}", page.session_id, page.next_cursor))).await;
    assert_eq!(status, StatusCode::OK);
    let continuation: FeedPage = serde_json::from_slice(&body).unwrap();
    assert_eq!(continuation.session_id, page.session_id);
    assert_eq!(continuation.items.len(), 2);
    assert_eq!(continuation.items[0].slot, 4);
    let first = &page.items[0].card;
    let tts = first.tts.as_ref().expect("seeded cards have tts");
    assert!(!tts.words.is_empty());
    assert!(first.bgm.is_some());
    assert!(!page.prefetch.entries[0].assets.is_empty());

    // 资产：完整下载、Range、ETag。
    let (s, h, bytes) = send(&app, get(&tts.audio.url)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "audio/wav");
    assert_eq!(bytes.len() as u64, tts.audio.bytes);
    let etag = h[header::ETAG].to_str().unwrap().to_string();
    let (s, h, part) =
        send(&app, Request::get(&tts.audio.url).header(header::RANGE, "bytes=0-43").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.len(), 44);
    assert!(h[header::CONTENT_RANGE].to_str().unwrap().starts_with("bytes 0-43/"));
    let (s, _, _) =
        send(&app, Request::get(&tts.audio.url).header(header::IF_NONE_MATCH, etag).body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::NOT_MODIFIED);
    let (s, _, _) = send(&app, get("/assets/../../etc/passwd")).await;
    assert_ne!(s, StatusCode::OK);

    // 埋点：接收 + 幂等。
    let batch = FeedbackBatch {
        session_id: page.session_id.clone(),
        client_id: "test".into(),
        sent_at: chrono::Utc::now(),
        events: page
            .items
            .iter()
            .chain(continuation.items.iter())
            .map(|it| ImplicitFeedback {
                delivery_id: None,
                event_id: format!("ev-{}", it.slot),
                card_id: it.card.id.clone(),
                slot: it.slot,
                shown_at: chrono::Utc::now(),
                dwell_time_ms: 3_000,
                loop_count: 1,
                swipe_velocity: 1.2,
                swipe_direction: SwipeDirection::Next,
                flipped: false,
                double_tapped: it.slot == 0,
                long_pressed: false,
                muted: false,
            })
            .collect(),
    };
    let v = serde_json::to_value(&batch).unwrap();
    let (s, _, body) = send(&app, post_json("/v1/feedback", &v, None)).await;
    assert_eq!(s, StatusCode::OK);
    let ack: FeedbackAck = serde_json::from_slice(&body).unwrap();
    assert_eq!(ack.accepted, 6);
    let (_, _, body) = send(&app, post_json("/v1/feedback", &v, None)).await;
    let ack: FeedbackAck = serde_json::from_slice(&body).unwrap();
    assert_eq!((ack.accepted, ack.duplicates), (0, 6));

    // 同一事件 ID 的载荷更改是逐事件冲突，已提交投影不再次应用。
    let mut changed = batch.clone();
    changed.events.truncate(1);
    changed.events[0].loop_count += 1;
    let (status, _, body) = send(&app, post_json("/v1/feedback", &serde_json::to_value(changed).unwrap(), None)).await;
    assert_eq!(status, StatusCode::OK);
    let conflict: FeedbackAck = serde_json::from_slice(&body).unwrap();
    assert_eq!((conflict.accepted, conflict.duplicates), (0, 0));
    assert_eq!(conflict.rejected.len(), 1);
    assert_eq!(conflict.rejected[0].reason, "conflict");

    // HTTP 批次后缀失败后重传：已提交前缀保持一次，失败事件重新应用。
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", dir.join("learntok.db").display())).await.unwrap();
    let mut partial = batch.clone();
    partial.events.truncate(2);
    for event in &mut partial.events {
        event.event_id.push_str("-partial");
    }
    partial.events[1].shown_at = partial.events[0].shown_at + chrono::Duration::seconds(1);
    sqlx::query("CREATE TRIGGER s9_suffix_fail BEFORE INSERT ON feedback_events WHEN NEW.event_id LIKE '%partial' AND NEW.event_id <> 'ev-0-partial' BEGIN SELECT RAISE(ABORT, 'injected batch suffix failure'); END")
        .execute(&pool).await.unwrap();
    let (status, _, body) = send(&app, post_json("/v1/feedback", &serde_json::to_value(&partial).unwrap(), None)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "internal");
    let committed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feedback_events WHERE event_id LIKE '%partial'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(committed, 1);
    sqlx::query("DROP TRIGGER s9_suffix_fail").execute(&pool).await.unwrap();
    let (status, _, body) = send(&app, post_json("/v1/feedback", &serde_json::to_value(&partial).unwrap(), None)).await;
    assert_eq!(status, StatusCode::OK);
    let retry: FeedbackAck = serde_json::from_slice(&body).unwrap();
    assert_eq!((retry.accepted, retry.duplicates), (1, 1));
    pool.close().await;

    // 下一页延续 slot 编号。
    let (_, _, body) = send(
        &app,
        get(&format!("/v1/feed?limit=3&session_id={}&cursor={}", page.session_id, continuation.next_cursor)),
    )
    .await;
    let next: FeedPage = serde_json::from_slice(&body).unwrap();
    assert_eq!(next.items[0].slot, 6);

    let (s, _, body) = send(&app, get("/v1/cards/does-not-exist")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let err: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err["code"], "not_found");

    // MCP over HTTP 与 REST 共用同一服务。
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "learning_stats", "arguments": {}}});
    let (s, _, body) = send(&app, post_json("/mcp", &init, None)).await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["result"]["structuredContent"]["seen_cards"], 6);

    // REST 学习统计与双击收藏列表。
    let (s, _, body) = send(&app, get("/v1/stats")).await;
    assert_eq!(s, StatusCode::OK);
    let stats: LearningStats = serde_json::from_slice(&body).unwrap();
    assert_eq!(stats.seen_cards, 6);
    assert_eq!(stats.starred_cards, 1);

    let (s, _, body) = send(&app, get("/v1/starred")).await;
    assert_eq!(s, StatusCode::OK);
    let starred: Vec<Card> = serde_json::from_slice(&body).unwrap();
    assert_eq!(starred.len(), 1);
    assert_eq!(starred[0].id, first.id);

    // AI 卡片深度解析。
    let (s, _, body) = send(
        &app,
        post_json(&format!("/v1/cards/{}/explain", first.id), &json!({"question": "What is the key idea?"}), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let exp: CardExplanation = serde_json::from_slice(&body).unwrap();
    assert_eq!(exp.card_id, first.id);
    assert!(!exp.summary.is_empty());
    assert!(!exp.key_points.is_empty());

    // 卡组导出与重新导入。
    let first_deck_id = decks[0]["id"].as_str().unwrap();
    let (s, _, body) = send(&app, get(&format!("/v1/decks/{first_deck_id}/export"))).await;
    assert_eq!(s, StatusCode::OK);
    let pack: DeckPack = serde_json::from_slice(&body).unwrap();
    assert_eq!(pack.version, "1.2");
    assert!(!pack.cards.is_empty());

    let pack_val = serde_json::to_value(&pack).unwrap();
    let (s, _, body) = send(&app, post_json("/v1/decks/import", &pack_val, None)).await;
    assert_eq!(s, StatusCode::CREATED);
    let imported: Deck = serde_json::from_slice(&body).unwrap();
    assert_ne!(imported.id, first_deck_id);
    assert_eq!(imported.card_count as usize, pack.cards.len());

    // 内置 Web Admin 控制台。
    let (s, h, body) = send(&app, get("/admin")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(h[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/html"));
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Memoswish"));

    // Prometheus 监控指标。
    let (s, h, body) = send(&app, get("/metrics")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "text/plain; version=0.0.4; charset=utf-8");
    let prom = String::from_utf8_lossy(&body);
    assert!(prom.contains("learntok_build_info{"));
    assert!(prom.contains("mode=\"single_user\""));
    assert!(prom.contains("learntok_http_requests_total"));
    assert!(prom.contains("learntok_tts_engines_registered"));

    // 配额快照查询。
    let (s, _, body) = send(&app, get("/v1/usage")).await;
    assert_eq!(s, StatusCode::OK);
    let usage: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(usage["tenant_id"], "local");
    assert_eq!(usage["metrics"].as_array().unwrap().len(), 3);

    // GDPR 全量账户数据导出与删除。
    let (s, _, body) = send(&app, get("/v1/account/export")).await;
    assert_eq!(s, StatusCode::OK);
    let exported: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(exported["tenant_id"], "local");
    assert_eq!(exported["decks"].as_array().unwrap().len(), 5);
    assert_eq!(exported["stats"]["seen_cards"], 6);

    let (s, _, _) = send(&app, Request::delete("/v1/account").body(Body::empty()).unwrap()).await;
    crate::account_tests::assert_erasure_response(&st, s).await;
    let (s, _, _) = send(&app, get("/v1/decks")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "true erasure invalidates the local account");
    let cfg = Config {
        data_dir: dir.clone(),
        seed_demo: true,
        tts: crate::config::TtsConfig { default_engine: "placeholder".into(), ..Default::default() },
        ..Default::default()
    };
    let reopened = AppState::build(cfg).await.unwrap();
    assert!(reopened.repo.get_user("local", memoswish_core::ids::LOCAL_USER_ID).await.unwrap().is_none());
    assert!(reopened.repo.list_decks("local").await.unwrap().is_empty());
    assert!(reopened.repo.list_memory("local", memoswish_core::ids::LOCAL_USER_ID).await.unwrap().is_empty());

    crate::runtime::cleanup_test_app(dir, &[&st, &reopened]).await;
}

#[tokio::test]
async fn multi_tenant_requires_auth_and_isolates() {
    let (app, st, dir) = app(DeploymentMode::MultiTenant).await;
    let (s, _, _) = send(&app, get("/v1/feed")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, _) = send(&app, post_json("/mcp", &json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}), None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let reg = json!({"email": "ada@example.com", "password": "password123", "display_name": "Ada"});
    let (s, _, body) = send(&app, post_json("/v1/auth/register", &reg, None)).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let auth: Value = serde_json::from_slice(&body).unwrap();
    let token = auth["access_token"].as_str().unwrap().to_string();

    let (s, _, body) = send(
        &app,
        Request::get("/v1/decks").header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let decks: Vec<Value> = serde_json::from_slice(&body).unwrap();
    assert!(decks.is_empty(), "new tenant sees no demo/local data");

    let login = json!({"email": "ada@example.com", "password": "wrong-password"});
    let (s, _, _) = send(&app, post_json("/v1/auth/login", &login, None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // JWT 令牌刷新。
    let (s, _, body) = send(
        &app,
        Request::post("/v1/auth/refresh")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let refreshed: Value = serde_json::from_slice(&body).unwrap();
    let new_token = refreshed["access_token"].as_str().unwrap().to_string();
    assert!(!new_token.is_empty());
    assert_eq!(refreshed["user"]["user_id"], auth["user"]["user_id"]);

    // 共享 BGM 可访问，其它租户资产不可访问。
    let (s, _, _) = send(
        &app,
        Request::get("/assets/shared/bgm/bgm_calm_pad.wav")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = send(&app, get("/assets/shared/bgm/bgm_calm_pad.wav")).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = send(
        &app,
        Request::get("/assets/tenants/local/tts/x.wav")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[path = "../../memoswish-content/tests/support/mod.rs"]
pub(crate) mod apkg_support;

// HTTP 与 stdio 测试共享进程级的两个 APKG 许可，必须持有同一测试隔离锁。
pub(crate) static APKG_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn apkg_raw_upload_report_limits_and_error_envelope() {
    let _guard = APKG_TEST.lock().await;
    let (app, st, dir) = app(DeploymentMode::SingleUser).await;
    let bytes = apkg_support::basic().await;
    let (status, _, body) = send(
        &app,
        Request::post("/v1/decks/import/apkg?title=Imported&language=en")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(bytes))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let report: memoswish_content::apkg::ApkgReport = serde_json::from_slice(&body).unwrap();
    assert_eq!(report.cards_imported, 1);
    assert_eq!(report.deck.title, "Imported");
    let (_, _, body) = send(&app, get("/v1/usage")).await;
    let usage: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(usage["metrics"].as_array().unwrap().iter().find(|v| v["metric"] == "card_writes").unwrap()["used"], 1);
    for bytes in [b"not a ZIP".to_vec(), vec![0; memoswish_content::apkg::ApkgLimits::ARCHIVE + 1]] {
        let (status, _, body) =
            send(&app, Request::post("/v1/decks/import/apkg").body(Body::from(bytes)).unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["code"], "bad_request");
    }
    let (_, _, body) = send(&app, get("/v1/usage")).await;
    let usage: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(usage["metrics"].as_array().unwrap().iter().find(|v| v["metric"] == "card_writes").unwrap()["used"], 1);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn apkg_upload_above_default_body_limit_and_private_image_download() {
    let _guard = APKG_TEST.lock().await;
    let (app, st, dir) = app(DeploymentMode::MultiTenant).await;
    let (_, _, body) = send(
        &app,
        post_json(
            "/v1/auth/register",
            &json!({"email":"apkg@example.com","password":"strong-password-123","display_name":"Importer"}),
            None,
        ),
    )
    .await;
    let auth: Value = serde_json::from_slice(&body).unwrap();
    let token = auth["access_token"].as_str().unwrap();
    let db = apkg_support::database("basic", "<img src='x.png'>\x1fBack", &[0]).await;
    let mut image = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut state = 123456789u32;
    for _ in 0..(3 * 1024 * 1024) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        image.push(state as u8);
    }
    let bytes =
        apkg_support::zip(vec![("collection.anki2", db), ("media", br#"{"0":"x.png"}"#.to_vec()), ("0", image)]);
    assert!(bytes.len() > 2 * 1024 * 1024);
    let (status, _, body) = send(
        &app,
        Request::post("/v1/decks/import/apkg")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(bytes))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    let report: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(report["media_imported"], 1);
    let (status, _, body) = send(
        &app,
        Request::get(format!("/v1/decks/{}/cards", report["deck"]["id"].as_str().unwrap()))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cards: Vec<Card> = serde_json::from_slice(&body).unwrap();
    let url = &cards[0].front.blocks.iter().find_map(memoswish_protocol::ContentBlock::asset).unwrap().url;
    let (status, _, _) = send(
        &app,
        Request::get(url).header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, _, body) = send(
        &app,
        post_json(
            "/v1/auth/register",
            &json!({"email":"other-apkg@example.com","password":"strong-password-123","display_name":"Other"}),
            None,
        ),
    )
    .await;
    let other: Value = serde_json::from_slice(&body).unwrap();
    let (status, _, body) = send(
        &app,
        Request::get(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", other["access_token"].as_str().unwrap()))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["code"], "not_found");
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn oauth_routes_are_absent_without_runtime_activation() {
    let (app, st, dir) = app(DeploymentMode::SingleUser).await;
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-authorization-server",
        "/oauth/register",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/revoke",
    ] {
        for method in ["GET", "POST"] {
            let req = Request::builder().method(method).uri(path).body(Body::empty()).unwrap();
            assert_eq!(send(&app, req).await.0, StatusCode::NOT_FOUND, "{method} {path}");
        }
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[cfg(not(feature = "mcp-oauth"))]
#[tokio::test]
async fn self_hosted_build_rejects_enabled_oauth_configuration() {
    let mut cfg = Config::default();
    cfg.oauth.enabled = true;
    let error = AppState::build(cfg).await.err().expect("OAuth must require mcp-oauth feature");
    assert!(error.to_string().contains("mcp-oauth"));
}

#[tokio::test]
async fn rest_and_mcp_deckpack_import_share_accounting_and_preserve_tts_defaults() {
    let dir = std::env::temp_dir().join(format!("memoswish-s2-deckpack-{}", memoswish_core::ids::new_id()));
    let mut state = AppState::build(Config {
        data_dir: dir.clone(),
        seed_demo: false,
        tts: crate::config::TtsConfig { default_engine: "placeholder".into(), ..Default::default() },
        ..Config::default()
    })
    .await
    .unwrap();
    let app = crate::auth_defenses::test_router(state.clone());
    let p = memoswish_core::Principal::local_owner("test");
    let mut pack = memoswish_protocol::examples::sample_deck_pack();
    pack.cards[0].tts = None;
    pack.cards[0].bgm = None;
    let pack = serde_json::to_value(pack).unwrap();
    let (status, _, body) = send(&app, post_json("/v1/decks/import", &pack, None)).await;
    assert_eq!(status, StatusCode::CREATED);
    let rest: Deck = serde_json::from_slice(&body).unwrap();
    let rest_cards = state.services.list_cards(&p, Some(&rest.id), 10, 0).await.unwrap();
    assert_eq!(rest_cards.len(), 1);
    assert!(rest_cards[0].tts.is_none());
    assert_eq!(
        state.services.usage(&p).await.unwrap().metrics.iter().find(|m| m.metric == "card_writes").unwrap().used,
        1
    );
    let (status, _, body) = send(
        &app,
        post_json(
            "/mcp",
            &json!({
                "jsonrpc":"2.0", "id":1, "method":"tools/call",
                "params":{"name":"deck_import", "arguments":{"pack":pack}}
            }),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mcp: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(mcp["result"]["isError"], false, "{mcp}");
    let id = mcp["result"]["structuredContent"]["id"].as_str().unwrap();
    // 先排空原后台拥有者，再以新准入域恢复，避免与已持有 claim 的 worker 竞争观察结果。
    state.services.operations.close();
    state.services.operations.wait().await;
    state.services.operations = Default::default();
    // 启动扫描会推迟下一轮挂载；显式设置本轮到期资格，再验证持久回执。
    crate::maintenance_scheduler::due_for_test(&state.config).await.unwrap();
    state.services.recover_speech().unwrap().await.unwrap().unwrap();
    let cards = state.services.list_cards(&p, Some(id), 10, 0).await.unwrap();
    assert_eq!(cards.len(), 1);
    assert!(cards[0].tts.is_some());
    let usage = state.services.usage(&p).await.unwrap();
    assert_eq!(usage.metrics.iter().find(|metric| metric.metric == "card_writes").unwrap().used, 2);
    assert_eq!(usage.metrics.iter().find(|metric| metric.metric == "mcp_calls").unwrap().used, 1);
    assert!(usage.metrics.iter().find(|metric| metric.metric == "tts_chars").unwrap().used > 0);
    state.services.operations.close();
    state.services.operations.wait().await;
    assert!(state.put_tasks.shutdown().await);
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&state]).await;
}

#[tokio::test]
async fn rest_public_errors_never_include_synthetic_provider_sql_or_validation_details() {
    use axum::response::IntoResponse;
    use memoswish_core::CoreError;
    for error in [
        CoreError::internal("SQL/provider S28_SECRET_SENTINEL"),
        CoreError::Invalid("S28_SECRET_SENTINEL".into()),
        CoreError::Forbidden("S28_SECRET_SENTINEL".into()),
        CoreError::Conflict("revision mismatch; current revision 4; S28_SECRET_SENTINEL".into()),
        CoreError::Unavailable("S28_SECRET_SENTINEL".into()),
        memoswish_core::tts::SpeechFailure::from_code("speech_engine_unavailable").unwrap().error(),
        memoswish_core::tts::SpeechFailure::from_code("speech_voice_unavailable").unwrap().error(),
    ] {
        let code = error.code();
        let status = error.http_status();
        let response = crate::api::ApiErr(error).into_response();
        assert_eq!(response.status().as_u16(), status);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], code);
        assert!(!body.to_string().contains("S28_SECRET_SENTINEL"));
    }
}

#[tokio::test]
async fn mcp_preflight_allows_protocol_header_and_runtime_switch_closes_route() {
    let dir = std::env::temp_dir().join(format!("memoswish-s28-{}", memoswish_core::ids::new_id()));
    let mut config = Config {
        data_dir: dir.clone(),
        cors_origins: vec!["https://client.example".into()],
        seed_demo: false,
        ..Config::default()
    };
    let st = AppState::build(config.clone()).await.unwrap();
    let app = crate::auth_defenses::test_router(st.clone());
    let (status, headers, _) = send(
        &app,
        Request::builder()
            .method("OPTIONS")
            .uri("/mcp")
            .header(header::ORIGIN, "https://client.example")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization,content-type,mcp-protocol-version,mcp-session-id",
            )
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(status.is_success());
    let allowed = headers[header::ACCESS_CONTROL_ALLOW_HEADERS].to_str().unwrap();
    assert!(allowed.contains("mcp-protocol-version"));
    assert!(allowed.contains("mcp-session-id"));
    for (origin, permitted) in [("https://client.example", true), ("https://untrusted.example", false)] {
        let (_, headers, _) = send(
            &app,
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/decks/import")
                .header(header::ORIGIN, origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization,content-type,idempotency-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN), permitted);
        if permitted {
            assert!(headers[header::ACCESS_CONTROL_ALLOW_HEADERS].to_str().unwrap().contains("idempotency-key"));
        }
    }
    crate::runtime::drain_test_state(&st).await;
    config.mcp.http_enabled = false;
    let st = AppState::build(config).await.unwrap();
    assert_eq!(
        send(
            &crate::auth_defenses::test_router(st.clone()),
            post_json("/mcp", &json!({"jsonrpc":"2.0","id":1,"method":"ping"}), None)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn conditional_content_delete_preserves_rest_envelopes_and_legacy_requests() {
    let (app, st, dir) = app(DeploymentMode::SingleUser).await;
    let (_, _, body) = send(&app, get("/v1/feed?limit=2")).await;
    let page: FeedPage = serde_json::from_slice(&body).unwrap();
    let card = &page.items[0].card;
    for revision in ["0".to_string(), "-1".into(), "invalid".into()] {
        let (status, _, body) = send(
            &app,
            Request::delete(format!("/v1/cards/{}?expected_revision={revision}", card.id)).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "bad_request");
    }
    let (status, _, body) = send(
        &app,
        Request::delete(format!("/v1/cards/{}?expected_revision={}", card.id, card.revision + 1))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let error: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["code"], "conflict");
    assert!(error["message"].as_str().unwrap().contains(&format!("current revision {}", card.revision)));
    assert_eq!(send(&app, get(&format!("/v1/cards/{}", card.id))).await.0, StatusCode::OK);
    let uri = format!("/v1/cards/{}?expected_revision={}", card.id, card.revision);
    assert_eq!(send(&app, Request::delete(&uri).body(Body::empty()).unwrap()).await.0, StatusCode::NO_CONTENT);
    assert_eq!(send(&app, Request::delete(&uri).body(Body::empty()).unwrap()).await.0, StatusCode::NOT_FOUND);
    let legacy_uri = format!("/v1/cards/{}", page.items[1].card.id);
    assert_eq!(send(&app, Request::delete(&legacy_uri).body(Body::empty()).unwrap()).await.0, StatusCode::NO_CONTENT);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn asset_delivery_publication_scopes_integrity_and_response_copies() {
    use memoswish_core::assets::{AssetReference, AssetSpec, ObjectVersion, card_assets};
    let dir = std::env::temp_dir().join(format!("s20-delivery-{}", memoswish_core::ids::new_id()));
    let st = AppState::build(Config { data_dir: dir.clone(), seed_demo: false, ..Config::default() }).await.unwrap();
    let p = st.services.auth.authenticate(None).await.unwrap();
    // 交付夹具只创建所需内容，不让演示数据的持久 TTS 任务参与上传领取。
    let deck = memoswish_protocol::examples::sample_deck();
    let mut fixture_card = memoswish_protocol::examples::sample_card();
    fixture_card.deck_id = deck.id.clone();
    fixture_card.tts = None;
    fixture_card.bgm = None;
    st.repo.insert_deck_with_cards(&p.tenant_id, &deck, &[fixture_card]).await.unwrap();
    let app = crate::auth_defenses::test_router(st.clone());
    let cards = st.repo.list_cards(&p.tenant_id, None, 1, 0).await.unwrap();
    let original = cards[0].clone();
    let mut card = original.clone();
    card.id = memoswish_core::ids::new_id();
    card.tts = None;
    card.bgm = None;
    let legacy = st.store.put("tenants/local/imports/security.png", b"abc".to_vec(), "image/png").await.unwrap();
    let mut image = legacy.clone();
    image.url = "https://expired.invalid/private?signature=SECRET_SENTINEL".into();
    card.front.blocks = vec![memoswish_protocol::ContentBlock::Image { asset: image.clone(), alt: String::new() }];
    card.back.blocks = card.front.blocks.clone();
    card.visual.image = Some(image);
    st.repo.insert_card(&p.tenant_id, &card).await.unwrap();
    let result = st.services.get_card(&p, &card.id).await.unwrap();
    assert_eq!(result.revision, card.revision);
    for asset in card_assets(&result) {
        assert!(asset.url.starts_with("/assets/"));
        assert!(!asset.url.contains("SECRET_SENTINEL"));
        let (s, headers, body) = send(&app, get(&asset.url)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(body, b"abc");
        assert_eq!(headers[header::CACHE_CONTROL], "private, no-cache");
    }
    assert_eq!(st.repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap(), card);
    let (status, _, rpc) = send(&app, post_json("/mcp", &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"card_get","arguments":{"card_id":card.id}}}),None)).await;
    assert_eq!(status, StatusCode::OK);
    let json = String::from_utf8(rpc).unwrap();
    assert!(json.contains("delivery=1"));
    assert!(!json.contains("SECRET_SENTINEL"));
    for track in st.services.list_bgm(&p).await.unwrap() {
        assert!(track.asset.url.contains("surface=media"));
    }
    let pack = st.services.export_deck(&p, &card.deck_id).await.unwrap();
    assert!(pack.cards.iter().flat_map(card_assets).all(|a| a.url.starts_with("/assets/")));
    let export = crate::account::export(&st, &p).await.unwrap();
    assert!(!export.to_string().contains("SECRET_SENTINEL"));
    let mut spoof = card.clone();
    spoof.id = memoswish_core::ids::new_id();
    spoof.front.blocks.clear();
    spoof.back.blocks.clear();
    spoof.visual.image.as_mut().unwrap().mime = "text/html".into();
    st.repo.insert_card(&p.tenant_id, &spoof).await.unwrap();
    let spoof = st.services.get_card(&p, &spoof.id).await.unwrap();
    assert_eq!(send(&app, get(&spoof.visual.image.unwrap().url)).await.0, StatusCode::CONFLICT);

    let token = st.services.auth.create_api_token(&p, "content", vec!["content:read".into()], None).await.unwrap();
    let feed_token = st.services.auth.create_api_token(&p, "feed", vec!["feed:read".into()], None).await.unwrap();
    assert_eq!(
        send(&app, get(&format!("/assets/{}?access_token={}", legacy.key, feed_token.plaintext))).await.0,
        StatusCode::OK
    );
    let url = &result.visual.image.as_ref().unwrap().url;
    for delivery in ["invalid", "256", "999999999999999999999999999999999", "", "-1", "1&delivery=1"] {
        let malformed = url.replace("delivery=1", &format!("delivery={delivery}"));
        let (status, headers, body) = send(&app, get(&malformed)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "delivery={delivery}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        let error: memoswish_protocol::ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.code, "bad_request");
        assert!(!error.message.is_empty());
    }
    let with_token = |url: &str, token: &str| {
        Request::get(url).header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap()
    };
    assert_eq!(send(&app, with_token(url, &token.plaintext)).await.0, StatusCode::OK);
    assert_eq!(send(&app, with_token(url, &feed_token.plaintext)).await.0, StatusCode::FORBIDDEN);
    let feed_url = url.replace("surface=content", "surface=feed");
    assert_eq!(send(&app, with_token(&feed_url, &feed_token.plaintext)).await.0, StatusCode::OK);
    st.repo.revoke_api_token(&p.tenant_id, &token.record.id).await.unwrap();
    assert_eq!(send(&app, with_token(url, &token.plaintext)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, get(&format!("{url}&access_token=SECRET_SENTINEL"))).await.0, StatusCode::BAD_REQUEST);
    // 完整性失败必须先于 Range、HEAD 和 304；外部旧地址完全不参与代理读取。
    let (_, h, _) = send(&app, get(url)).await;
    st.store.put(&legacy.key, b"bad".to_vec(), "image/png").await.unwrap();
    for method in ["GET", "HEAD"] {
        let request = Request::builder()
            .method(method)
            .uri(url)
            .header(header::IF_NONE_MATCH, h[header::ETAG].clone())
            .header(header::RANGE, "bytes=0-1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&app, request).await.0, StatusCode::CONFLICT);
    }
    let spec = AssetSpec { mime: "image/png".into(), size: 3, sha256: memoswish_core::ids::sha256_hex(b"abc") };
    let intent = st.repo.prepare_asset(&p, "delivery", &spec, 3).await.unwrap();
    let claim = st.repo.claim_asset_job(&p.tenant_id, "delivery", 30_000).await.unwrap().unwrap();
    assert_eq!(claim.job_id, intent.id);
    let attempt = st.repo.begin_upload(&p.tenant_id, &claim, &st.store.namespace().unwrap()).await.unwrap();
    let receipt = st.store.put(&attempt.key, b"abc".to_vec(), "image/png").await.unwrap();
    let target = format!("/assets/{}?delivery=1&surface=media", attempt.key);
    assert_eq!(send(&app, get(&target)).await.0, StatusCode::NOT_FOUND);
    st.repo.record_upload(&p.tenant_id, &attempt, &ObjectVersion::Unversioned).await.unwrap();
    assert_eq!(send(&app, get(&target)).await.0, StatusCode::NOT_FOUND);
    // 伪造业务引用不能把未发布 uploads 降级到 legacy。
    let mut forged = card.clone();
    forged.id = memoswish_core::ids::new_id();
    forged.visual.image = Some(receipt);
    st.repo.insert_card(&p.tenant_id, &forged).await.unwrap();
    assert_eq!(
        send(&app, get(&format!("/assets/{}?surface=content&owner={}", attempt.key, forged.id))).await.0,
        StatusCode::NOT_FOUND
    );
    st.repo
        .publish_asset(
            &p,
            &claim,
            &attempt.id,
            &AssetReference { asset_id: intent.asset_id, owner_id: forged.id.clone(), slot: "image".into() },
        )
        .await
        .unwrap();
    // LocalDiskStore 无法从 extensionless immutable key 推断 MIME，交付以可信 spec 为准。
    let (status, _, _) = send(&app, get(&target)).await;
    assert_eq!(status, StatusCode::OK);
    for (request, namespace, version, expected) in [
        ("wrong-namespace", "other-store".to_string(), ObjectVersion::Unversioned, StatusCode::CONFLICT),
        (
            "unsupported-version",
            st.store.namespace().unwrap(),
            ObjectVersion::VersionId("v-old".into()),
            StatusCode::NOT_IMPLEMENTED,
        ),
    ] {
        let intent = st.repo.prepare_asset(&p, request, &spec, 3).await.unwrap();
        let claim = st.repo.claim_asset_job(&p.tenant_id, "delivery", 30_000).await.unwrap().unwrap();
        assert_eq!(claim.job_id, intent.id);
        let attempt = st.repo.begin_upload(&p.tenant_id, &claim, &namespace).await.unwrap();
        st.store.put(&attempt.key, b"abc".to_vec(), "image/png").await.unwrap();
        st.repo.record_upload(&p.tenant_id, &attempt, &version).await.unwrap();
        st.repo
            .publish_asset(
                &p,
                &claim,
                &attempt.id,
                &AssetReference { asset_id: intent.asset_id, owner_id: forged.id.clone(), slot: request.into() },
            )
            .await
            .unwrap();
        let url = format!("/assets/{}?delivery=1&surface=media", attempt.key);
        assert_eq!(send(&app, get(&url)).await.0, expected);
    }
    assert_eq!(send(&app, get("/assets/shared/not-a-pad.wav")).await.0, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, get("/assets/tenants/locally/imports/security.png")).await.0, StatusCode::NOT_FOUND);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[derive(Clone)]
struct DeliveryBarrier {
    inner: std::sync::Arc<dyn memoswish_core::store::ObjectStore>,
    entered: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

async fn opaque_asset_fixture() -> (AppState, std::path::PathBuf, String, String) {
    let dir = std::env::temp_dir().join(format!("s21-delivery-{}", memoswish_core::ids::new_id()));
    let st = AppState::build(Config {
        data_dir: dir.clone(),
        mode: DeploymentMode::MultiTenant,
        registration_open: true,
        seed_demo: false,
        tts: crate::config::TtsConfig { default_engine: "placeholder".into(), ..Default::default() },
        ..Config::default()
    })
    .await
    .unwrap();
    let registered = st
        .services
        .auth
        .register(&memoswish_protocol::RegisterRequest {
            email: "asset@example.com".into(),
            password: "password123".into(),
            display_name: "Asset owner".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let tenant = registered.user.tenant_id;
    let deck = memoswish_protocol::examples::sample_deck();
    st.repo.insert_deck(&tenant, &deck).await.unwrap();
    let image =
        st.store.put(&format!("tenants/{tenant}/imports/session.png"), b"abc".to_vec(), "image/png").await.unwrap();
    let mut card = memoswish_protocol::examples::sample_card();
    card.deck_id = deck.id;
    card.tts = None;
    card.bgm = None;
    card.visual.image = Some(image);
    st.repo.insert_card(&tenant, &card).await.unwrap();
    let asset = card.visual.image.as_ref().unwrap();
    memoswish_core::asset_read::register_write(
        st.repo.as_ref(),
        st.store.as_ref(),
        &tenant,
        &asset.key,
        &memoswish_core::assets::ObjectVersion::Unversioned,
        &memoswish_core::assets::AssetSpec {
            mime: asset.mime.clone(),
            size: asset.bytes as i64,
            sha256: asset.sha256.clone(),
        },
        b"abc",
    )
    .await
    .unwrap();
    let rendered = memoswish_application::asset_delivery::render_card(card, "content");
    (st, dir, tenant, rendered.visual.image.unwrap().url)
}

async fn opaque_asset_session(st: &AppState, tenant: &str) -> memoswish_protocol::SessionResponse {
    let account = st
        .services
        .auth
        .login_session(&memoswish_protocol::LoginRequest {
            email: "asset@example.com".into(),
            password: "password123".into(),
        })
        .await
        .unwrap();
    st.services.auth.select_session_workspace(&account.access_token, tenant).await.unwrap()
}

#[tokio::test]
async fn replayable_feed_preserves_snapshots_across_opaque_rotation_and_asset_delivery() {
    let (st, dir, tenant, _) = opaque_asset_fixture().await;
    let session = opaque_asset_session(&st, &tenant).await;
    let app = crate::auth_defenses::test_router(st.clone());
    let request = |uri: &str, token: &str| {
        Request::get(uri).header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap()
    };
    let first_uri = "/v1/feed?request_id=s21-rotation&limit=1";
    let (status, _, body) = send(&app, request(first_uri, &session.access_token)).await;
    assert_eq!(status, StatusCode::OK);
    let page: FeedPage = serde_json::from_slice(&body).unwrap();
    assert_eq!(page.items.len(), 1);
    let card = &page.items[0].card;
    let image = card.visual.image.as_ref().unwrap();
    assert!(image.url.contains("surface=feed"));
    let prefetch = page.prefetch.entries.iter().find(|entry| entry.card_id == card.id).unwrap();
    assert!(prefetch.assets.iter().any(|asset| asset == image));
    assert!(page.prefetch.expires_at.is_none());
    assert_eq!(send(&app, request(&image.url, &session.access_token)).await.2, b"abc");
    // 交付渲染只修改响应副本，内容及不可变回执继续保存原资产引用。
    let p = st.services.auth.authenticate(Some(&session.access_token)).await.unwrap();
    let original = st.repo.get_card(&tenant, &card.id).await.unwrap().unwrap();
    let query =
        memoswish_protocol::FeedQuery { request_id: Some("s21-rotation".into()), limit: Some(1), ..Default::default() };
    let receipt = st.services.feed.next_page(&p, &query).await.unwrap();
    assert_eq!(receipt.items[0].card, original);
    assert_ne!(receipt.items[0].card.visual.image.as_ref().unwrap().url, image.url);
    let rotated = st.services.auth.refresh_session(&session.refresh_token).await.unwrap();
    assert!(st.services.preview_feed(&p, Some(1), None).await.is_err());
    assert_eq!(send(&app, request("/v1/feed?mode=preview", &session.access_token)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, request("/v1/feed?mode=preview", &rotated.access_token)).await.0, StatusCode::OK);
    // 凭据旋转保留学习会话身份，旧 access 无权读取已有回执。
    assert_eq!(send(&app, request(first_uri, &session.access_token)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, request(first_uri, &rotated.access_token)).await.2, body);
    let next_uri = format!("/v1/feed?session_id={}&cursor={}&limit=1", page.session_id, page.next_cursor);
    let (status, _, next_body) = send(&app, request(&next_uri, &rotated.access_token)).await;
    assert_eq!(status, StatusCode::OK);
    let next: FeedPage = serde_json::from_slice(&next_body).unwrap();
    assert_eq!(next.session_id, page.session_id);
    assert_eq!(next.items[0].slot, 1);
    // 历史页仍可重放，资产交付继续检查当前引用，删除后返回 404。
    assert!(st.repo.delete_card(&tenant, &card.id).await.unwrap());
    assert_eq!(send(&app, request(first_uri, &rotated.access_token)).await.2, body);
    assert_eq!(send(&app, request(&image.url, &rotated.access_token)).await.0, StatusCode::NOT_FOUND);
    assert!(st.services.auth.refresh_session(&session.refresh_token).await.is_err());
    for uri in [first_uri, &next_uri, &image.url] {
        assert_eq!(send(&app, request(uri, &rotated.access_token)).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(send(&app, request("/v1/feed?mode=preview", &rotated.access_token)).await.0, StatusCode::UNAUTHORIZED);
    // 新会话族重新认证后仍能恢复同一学习回执。
    let fresh = opaque_asset_session(&st, &tenant).await;
    assert_eq!(send(&app, request(first_uri, &fresh.access_token)).await.2, body);
    assert!(st.services.auth.revoke_session(&fresh.access_token, None).await.unwrap());
    assert_eq!(send(&app, request(first_uri, &fresh.access_token)).await.0, StatusCode::UNAUTHORIZED);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn tts_publication_uses_authenticated_delivery_and_deleted_card_outcome() {
    let (st, dir, tenant, _) = opaque_asset_fixture().await;
    let workspace = opaque_asset_session(&st, &tenant).await;
    let p = st.services.auth.authenticate(Some(&workspace.access_token)).await.unwrap();
    assert!(p.session_access_hash.is_some());
    let card = st.repo.list_cards(&tenant, None, 10, 0).await.unwrap().remove(0);
    let updated =
        st.services.synthesize_cards(&p, std::slice::from_ref(&card.id), &Default::default()).await.unwrap().remove(0);
    let audio = &updated.tts.as_ref().unwrap().audio;
    assert!(audio.key.starts_with(&format!("tenants/{tenant}/uploads/")));
    assert!(audio.url.contains("delivery=1&surface=content&owner="));
    let app = crate::auth_defenses::test_router(st.clone());
    assert_eq!(send(&app, get(&audio.url)).await.0, StatusCode::UNAUTHORIZED);
    let request = |token: &str| {
        Request::get(&audio.url).header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap()
    };
    let (status, headers, bytes) = send(&app, request(&workspace.access_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], audio.mime);
    assert_eq!(bytes.len() as u64, audio.bytes);
    assert_eq!(memoswish_core::ids::sha256_hex(&bytes), audio.sha256);
    let rotated = st.services.auth.refresh_session(&workspace.refresh_token).await.unwrap();
    assert_eq!(send(&app, request(&workspace.access_token)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, request(&rotated.access_token)).await.0, StatusCode::OK);
    st.repo.delete_deck(&tenant, &card.deck_id).await.unwrap();
    assert_eq!(send(&app, request(&rotated.access_token)).await.0, StatusCode::NOT_FOUND);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn opaque_asset_delivery_preserves_credential_domains_and_rotation_revocation() {
    let (st, dir, tenant, url) = opaque_asset_fixture().await;
    let app = crate::auth_defenses::test_router(st.clone());
    let account = st
        .services
        .auth
        .login_session(&memoswish_protocol::LoginRequest {
            email: "asset@example.com".into(),
            password: "password123".into(),
        })
        .await
        .unwrap();
    let workspace = st.services.auth.select_session_workspace(&account.access_token, &tenant).await.unwrap();
    let request = |method: &str, token: &str, condition: Option<(&str, &str)>| {
        let mut builder =
            Request::builder().method(method).uri(&url).header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some((name, value)) = condition {
            builder = builder.header(name, value);
        }
        builder.body(Body::empty()).unwrap()
    };
    for token in [&account.access_token, &account.refresh_token, &workspace.refresh_token] {
        assert_eq!(send(&app, request("GET", token, None)).await.0, StatusCode::UNAUTHORIZED);
    }
    let (status, headers, body) = send(&app, request("GET", &workspace.access_token, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"abc");
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-cache");
    let etag = headers[header::ETAG].to_str().unwrap();
    let conditions = [
        ("GET", None, StatusCode::OK),
        ("HEAD", None, StatusCode::OK),
        ("GET", Some(("range", "bytes=0-1")), StatusCode::PARTIAL_CONTENT),
        ("GET", Some(("if-none-match", etag)), StatusCode::NOT_MODIFIED),
    ];
    for (method, condition, expected) in conditions {
        assert_eq!(send(&app, request(method, &workspace.access_token, condition)).await.0, expected);
    }
    let rotated = st.services.auth.refresh_session(&workspace.refresh_token).await.unwrap();
    assert_eq!(send(&app, request("GET", &workspace.access_token, None)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, request("GET", &rotated.access_token, None)).await.0, StatusCode::OK);
    // 旧 refresh 重放撤销整个族，已旋转的 access 也不能继续交付资产。
    assert!(st.services.auth.refresh_session(&workspace.refresh_token).await.is_err());
    for (method, condition, _) in conditions {
        assert_eq!(send(&app, request(method, &rotated.access_token, condition)).await.0, StatusCode::UNAUTHORIZED);
    }
    let next = opaque_asset_session(&st, &tenant).await;
    assert!(st.services.auth.revoke_session(&next.access_token, None).await.unwrap());
    assert_eq!(send(&app, request("GET", &next.access_token, None)).await.0, StatusCode::UNAUTHORIZED);
    // 另一租户的有效 workspace access 仍不能读取原租户资产。
    let other = st
        .services
        .auth
        .register(&memoswish_protocol::RegisterRequest {
            email: "other@example.com".into(),
            password: "password123".into(),
            display_name: "Other".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let other_account = st
        .services
        .auth
        .login_session(&memoswish_protocol::LoginRequest {
            email: "other@example.com".into(),
            password: "password123".into(),
        })
        .await
        .unwrap();
    let other_workspace =
        st.services.auth.select_session_workspace(&other_account.access_token, &other.user.tenant_id).await.unwrap();
    assert_eq!(send(&app, request("GET", &other_workspace.access_token, None)).await.0, StatusCode::NOT_FOUND);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn opaque_session_revocation_during_asset_read_precedes_all_success_responses() {
    let (mut st, dir, tenant, url) = opaque_asset_fixture().await;
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    st.store = std::sync::Arc::new(DeliveryBarrier {
        inner: st.store.clone(),
        entered: entered.clone(),
        release: release.clone(),
    });
    let app = crate::auth_defenses::test_router(st.clone());
    let etag = format!("\"{}\"", memoswish_core::ids::sha256_hex(b"abc"));
    for (method, condition) in [
        ("GET", None),
        ("HEAD", None),
        ("GET", Some(("range", "bytes=0-1"))),
        ("GET", Some(("if-none-match", etag.as_str()))),
    ] {
        let session = opaque_asset_session(&st, &tenant).await;
        let mut builder = Request::builder()
            .method(method)
            .uri(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token));
        if let Some((name, value)) = condition {
            builder = builder.header(name, value);
        }
        let request = builder.body(Body::empty()).unwrap();
        let app = app.clone();
        let waiting = tokio::spawn(async move { send(&app, request).await });
        entered.notified().await;
        assert!(!waiting.is_finished());
        assert!(st.services.auth.revoke_session(&session.access_token, None).await.unwrap());
        release.notify_one();
        assert_eq!(waiting.await.unwrap().0, StatusCode::UNAUTHORIZED);
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[async_trait::async_trait]
impl memoswish_core::store::ObjectStore for DeliveryBarrier {
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn namespace(&self) -> memoswish_core::CoreResult<String> {
        self.inner.namespace()
    }
    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        mime: &str,
    ) -> memoswish_core::CoreResult<memoswish_protocol::AssetRef> {
        self.inner.put(key, bytes, mime).await
    }
    async fn get(&self, key: &str) -> memoswish_core::CoreResult<Option<memoswish_core::store::StoredObject>> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> memoswish_core::CoreResult<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> memoswish_core::CoreResult<()> {
        self.inner.delete(key).await
    }
    async fn read_delivery(
        &self,
        key: &str,
        version: &memoswish_core::assets::ObjectVersion,
        limit: u64,
    ) -> memoswish_core::CoreResult<Option<memoswish_core::store::StoredObject>> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner.read_delivery(key, version, limit).await
    }
    async fn read_legacy(
        &self,
        key: &str,
        limit: u64,
    ) -> memoswish_core::CoreResult<Option<memoswish_core::store::StoredObject>> {
        // 对象已缓冲后暂停，证明生命周期提交后不会释放旧的成功响应。
        let object = self.inner.read_legacy(key, limit).await?;
        self.entered.notify_one();
        self.release.notified().await;
        Ok(object)
    }
}

#[tokio::test]
async fn revocation_during_buffered_asset_read_precedes_conditional_success() {
    let dir = std::env::temp_dir().join(format!("s20-revocation-{}", memoswish_core::ids::new_id()));
    let mut st = AppState::build(Config {
        data_dir: dir.clone(),
        seed_demo: true,
        tts: crate::config::TtsConfig { default_engine: "placeholder".into(), ..Default::default() },
        ..Config::default()
    })
    .await
    .unwrap();
    let p = st.services.auth.authenticate(None).await.unwrap();
    let card = st.services.list_cards(&p, None, 1, 0).await.unwrap().remove(0);
    let asset = card.tts.unwrap().audio;
    let token = st.services.auth.create_api_token(&p, "revoking", vec!["content:read".into()], None).await.unwrap();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    st.store = std::sync::Arc::new(DeliveryBarrier {
        inner: st.store.clone(),
        entered: entered.clone(),
        release: release.clone(),
    });
    let app = crate::auth_defenses::test_router(st.clone());
    let waiting = tokio::spawn(async move {
        let request = Request::get(asset.url)
            .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
            .header(header::IF_NONE_MATCH, format!("\"{}\"", asset.sha256))
            .body(Body::empty())
            .unwrap();
        send(&app, request).await
    });
    entered.notified().await;
    assert!(!waiting.is_finished());
    st.repo.revoke_api_token(&p.tenant_id, &token.record.id).await.unwrap();
    release.notify_one();
    assert_eq!(waiting.await.unwrap().0, StatusCode::UNAUTHORIZED);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn s5_lifecycle_during_opaque_asset_read_fences_conditional_and_range_responses() {
    use memoswish_core::lifecycle::{CloseAccount, DeleteWorkspace, TransferOwnership};
    for boundary in ["leave", "transfer", "delete", "close"] {
        let (mut st, dir, tenant, url) = opaque_asset_fixture().await;
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        st.store = std::sync::Arc::new(DeliveryBarrier {
            inner: st.store.clone(),
            entered: entered.clone(),
            release: release.clone(),
        });
        let account = st
            .services
            .auth
            .login_session(&memoswish_protocol::LoginRequest {
                email: "asset@example.com".into(),
                password: "password123".into(),
            })
            .await
            .unwrap();
        let session = st.services.auth.select_session_workspace(&account.access_token, &tenant).await.unwrap();
        let p = st.services.auth.authenticate(Some(&session.access_token)).await.unwrap();
        let peer_id = memoswish_core::ids::new_id();
        if matches!(boundary, "leave" | "transfer") {
            st.repo
                .insert_user(&memoswish_core::repo::UserRecord {
                    id: peer_id.clone(),
                    tenant_id: tenant.clone(),
                    email: "peer@example.com".into(),
                    display_name: "Peer".into(),
                    password_hash: String::new(),
                    role: if boundary == "leave" { memoswish_core::Role::Owner } else { memoswish_core::Role::Learner },
                    created_at: chrono::Utc::now(),
                })
                .await
                .unwrap();
        }
        let app = crate::auth_defenses::test_router(st.clone());
        let etag = format!("\"{}\"", memoswish_core::ids::sha256_hex(b"abc"));
        let request = Request::get(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token))
            .header(header::IF_NONE_MATCH, &etag)
            .body(Body::empty())
            .unwrap();
        let waiting = {
            let app = app.clone();
            tokio::spawn(async move { send(&app, request).await })
        };
        entered.notified().await;
        assert!(!waiting.is_finished());
        match boundary {
            "leave" => st.services.leave_workspace(&p).await.unwrap(),
            "transfer" => {
                st.services.transfer_ownership(&p, &TransferOwnership { successor_user_id: peer_id }).await.unwrap()
            }
            "delete" => {
                st.services
                    .delete_workspace(&p, &DeleteWorkspace { confirmed_tenant_id: tenant.clone() })
                    .await
                    .unwrap();
            }
            "close" => {
                let account = st.services.auth.authenticate_account(&account.access_token).await.unwrap();
                st.services
                    .close_account(&account, &CloseAccount { confirmed_exclusive_workspaces: vec![tenant.clone()] })
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        release.notify_one();
        assert_eq!(waiting.await.unwrap().0, StatusCode::UNAUTHORIZED, "{boundary}");
        for (method, condition) in [
            ("GET", None),
            ("HEAD", None),
            ("GET", Some(("range", "bytes=0-1"))),
            ("GET", Some(("if-none-match", etag.as_str()))),
        ] {
            let mut builder = Request::builder()
                .method(method)
                .uri(&url)
                .header(header::AUTHORIZATION, format!("Bearer {}", session.access_token));
            if let Some((name, value)) = condition {
                builder = builder.header(name, value);
            }
            assert_eq!(
                send(&app, builder.body(Body::empty()).unwrap()).await.0,
                StatusCode::UNAUTHORIZED,
                "{boundary} {method}"
            );
        }
        assert!(st.services.auth.refresh_session(&session.refresh_token).await.is_err());
        if boundary == "close" {
            assert!(st.services.auth.authenticate_account(&account.access_token).await.is_err());
            assert!(st.services.auth.refresh_session(&account.refresh_token).await.is_err());
        } else {
            assert!(st.services.auth.authenticate_account(&account.access_token).await.is_ok());
        }
        crate::runtime::cleanup_test_app(dir, &[&st]).await;
    }
}

mod compatibility;

#[tokio::test]
async fn rest_import_idempotency_replay_conflict_and_duplicate_headers() {
    let dir = std::env::temp_dir().join(format!("memoswish-s18-http-{}", memoswish_core::ids::new_id()));
    let st = AppState::build(Config { data_dir: dir.clone(), seed_demo: false, ..Config::default() }).await.unwrap();
    let app = crate::auth_defenses::test_router(st.clone());
    let pack = serde_json::to_value(memoswish_protocol::examples::sample_deck_pack()).unwrap();
    let make = || {
        let mut r = post_json("/v1/decks/import", &pack, None);
        r.headers_mut().insert("idempotency-key", "s18-http".parse().unwrap());
        r
    };
    let (a, b) = tokio::join!(send(&app, make()), send(&app, make()));
    assert_eq!(a.0, StatusCode::CREATED);
    assert_eq!(b.0, StatusCode::CREATED);
    assert_eq!(a.2, b.2);
    let mut changed = pack.clone();
    changed["deck"]["title"] = json!("Changed");
    let mut r = post_json("/v1/decks/import", &changed, None);
    r.headers_mut().insert("idempotency-key", "s18-http".parse().unwrap());
    assert_eq!(send(&app, r).await.0, StatusCode::CONFLICT);
    let mut duplicate = make();
    duplicate.headers_mut().append("idempotency-key", "second".parse().unwrap());
    assert_eq!(send(&app, duplicate).await.0, StatusCode::BAD_REQUEST);
    let p = memoswish_core::Principal::local_owner("test");
    assert_eq!(st.services.list_decks(&p).await.unwrap().len(), 1);
    assert_eq!(
        st.services.usage(&p).await.unwrap().metrics.iter().find(|m| m.metric == "card_writes").unwrap().used,
        1
    );
    st.services.operations.close();
    st.services.operations.wait().await;
    assert!(st.put_tasks.shutdown().await);
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}
#[path = "tests/privacy_assets.rs"]
mod privacy_assets;

#[path = "tests/portable.rs"]
mod portable;
#[tokio::test]
async fn draining_preserves_rest_mcp_and_oauth_error_contracts() {
    let (mut st, root) = app_state(DeploymentMode::SingleUser).await;
    let mut config = (*st.config).clone();
    // 只验证已组装适配器的关闭边界，不联系身份提供者。
    config.oauth.enabled = cfg!(feature = "mcp-oauth");
    st.config = std::sync::Arc::new(config);
    st.health.lifecycle.drain();
    let app = crate::api::router(st.clone());
    for path in ["/v1/server-info", "/mcp", "/oauth/token"] {
        let (status, headers, body) = send(&app, get(path)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(headers[header::RETRY_AFTER], "1");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        let value: Value = serde_json::from_slice(&body).unwrap();
        if path == "/mcp" {
            assert_eq!(value["jsonrpc"], "2.0");
            assert_eq!(value["error"]["code"], -32603);
            assert!(value["id"].is_null());
        } else if path == "/oauth/token" && cfg!(feature = "mcp-oauth") {
            assert_eq!(value["error"], "temporarily_unavailable");
            assert_eq!(headers[header::PRAGMA], "no-cache");
            assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
            assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
        } else {
            assert_eq!(value["code"], "temporarily_unavailable");
        }
    }
    crate::runtime::drain_background(&st).await;
    crate::runtime::cleanup_test_app(root, &[&st]).await;
}

#[tokio::test]
async fn explanation_identity_lookup_and_reconciliation_use_real_routes() {
    let (app, st, dir) = app(DeploymentMode::SingleUser).await;
    let (status, _, bytes) = send(&app, get("/v1/feed?limit=1")).await;
    assert_eq!(status, StatusCode::OK);
    let page: FeedPage = serde_json::from_slice(&bytes).unwrap();
    let id = &page.items[0].card.id;
    let command = json!({"request_id":"route-explain","locale":"en-US"});
    let uri = format!("/v1/cards/{id}/explain");
    let (status, _, bytes) = send(&app, post_json(&uri, &command, None)).await;
    assert_eq!(status, StatusCode::OK);
    let result: CardExplanation = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.provider, "builtin-heuristic");
    assert_eq!(result.operation.unwrap().request_id, "route-explain");
    let (status, _, bytes) = send(&app, get("/v1/explanations/route-explain")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["disposition"], "local");
    let (status, _, bytes) = send(&app, get("/v1/explanations/absent")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["code"], "not_found");
    let (status, _, bytes) = send(
        &app,
        post_json("/v1/explanations/route-explain/reconcile", &json!({"input_tokens":10,"output_tokens":2}), None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["code"], "conflict");
    let (status, _, bytes) =
        send(&app, post_json("/v1/explanations/route-explain/reconcile", &json!({"input_tokens":0.5}), None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["code"], "bad_request");
    let changed = json!({"request_id":"route-explain","question":"changed","locale":"en-US"});
    assert_eq!(send(&app, post_json(&uri, &changed, None)).await.0, StatusCode::CONFLICT);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn explanation_current_billing_authority_reconciles_old_generation_via_rest_and_mcp() {
    use memoswish_core::explanations::*;
    use memoswish_core::{Principal, Role};
    let dir = std::env::temp_dir().join(format!("memoswishd-explanation-generation-{}", memoswish_core::ids::new_id()));
    let mut st = AppState::build(Config {
        mode: DeploymentMode::SingleUser,
        data_dir: dir.clone(),
        default_plan: "self_hosted".into(),
        seed_demo: true,
        tts: crate::config::TtsConfig { default_engine: "placeholder".into(), ..Default::default() },
        privacy: memoswish_protocol::PrivacyPolicy {
            hosted: false,
            ..memoswish_protocol::examples::sample_privacy_policy()
        },
        ..Config::default()
    })
    .await
    .unwrap();
    st.services.operations.close();
    st.services.operations.wait().await;
    st.services.operations = Default::default();
    st.mcp = std::sync::Arc::new(memoswish_mcp::McpServer::new(st.services.clone()));
    let owner = Principal::local_owner("single_user");
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_ai", "provider-policy-v1", ""),
    ] {
        let state = st.services.auth.privacy_state(&owner).await.unwrap();
        st.services
            .auth
            .update_privacy(
                &owner,
                &memoswish_protocol::PrivacyUpdate {
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
    let old = Principal::local_owner("test");
    let card = st.repo.list_cards("local", None, 1, 0).await.unwrap().remove(0);
    let policy = explanation_test_policy();
    for key in ["generation-rest", "generation-mcp"] {
        let a = ExplanationAdmission {
            request_id: key.into(),
            command_hash: "a".repeat(64),
            card_id: card.id.clone(),
            revision: card.revision,
            cache_key: None,
            profile_id: "b".repeat(64),
            policy: Some(policy.clone()),
            context: ExplanationContext {
                locale: "en".into(),
                model_profile: "gpt-4o-mini".into(),
                prompt_version: "v1".into(),
                policy_version: "v1".into(),
            },
        };
        st.repo.admit_explanation(&old, &a).await.unwrap();
        assert!(st.repo.begin_explanation_attempt(&old, key).await.unwrap());
    }
    assert!(st.repo.membership_remove("local", &old.user_id).await.unwrap());
    assert!(
        st.repo.membership_join("local", &old.user_id, Role::Owner).await.unwrap() > old.membership_generation.unwrap()
    );
    let proof = ExplanationEvidence::NotCharged { reference_sha256: "a".repeat(64) };
    assert!(
        st.services
            .reconcile_explanation_request(
                &old,
                "generation-rest",
                &memoswish_protocol::ExplainReconcileRequest {
                    not_charged_reference_sha256: Some("a".repeat(64)),
                    input_tokens: None,
                    output_tokens: None,
                }
            )
            .await
            .is_err()
    );
    assert!(st.repo.reconcile_explanation(&old, "generation-rest", &proof).await.is_err());
    let app = crate::api::router(st.clone());
    let evidence = json!({"not_charged_reference_sha256":"a".repeat(64)});
    let uri = "/v1/explanations/generation-rest/reconcile";
    let (status, _, body) = send(&app, post_json(uri, &evidence, None)).await;
    assert_eq!(status, StatusCode::OK);
    let receipt: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(receipt["disposition"], "settled");
    assert_eq!(receipt["accounting"]["held_microcurrency"], 0);
    assert_eq!(receipt["accounting"]["attempts"], 1);
    assert!(receipt.get("result").is_none());
    assert_eq!(send(&app, post_json(uri, &evidence, None)).await.2, body);
    assert_eq!(
        send(&app, post_json(uri, &json!({"input_tokens":10,"output_tokens":2}), None)).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(send(&app, get("/v1/explanations/generation-rest")).await.0, StatusCode::FORBIDDEN);
    let mcp = |evidence: Value| {
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"explanation_reconcile","arguments":{"request_id":"generation-mcp","evidence":evidence}
        }})
    };
    let (status, _, body) = send(&app, post_json("/mcp", &mcp(evidence.clone()), None)).await;
    assert_eq!(status, StatusCode::OK);
    let response: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(response["result"]["structuredContent"]["accounting"]["held_microcurrency"], 0);
    assert_eq!(response["result"]["structuredContent"]["disposition"], "settled");
    assert_eq!(send(&app, post_json("/mcp", &mcp(evidence), None)).await.2, body);
    let (_, _, body) = send(&app, post_json("/mcp", &mcp(json!({"input_tokens":10,"output_tokens":2})), None)).await;
    let response: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(send(&app, get("/v1/explanations/generation-mcp")).await.0, StatusCode::FORBIDDEN);
    st.services.operations.close();
    st.services.operations.wait().await;
    assert!(st.put_tasks.shutdown().await);
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[path = "tests/content_lifecycle.rs"]
mod content_lifecycle;
mod legacy_import_replay;
mod starter_upgrade;
#[tokio::test]
async fn feedback_only_token_gets_first_and_duplicate_receipts() {
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let p = st.services.auth.authenticate(None).await.unwrap();
    let token =
        st.services.auth.create_api_token(&p, "Feedback only", vec!["feedback:write".into()], None).await.unwrap();
    let app = crate::auth_defenses::test_router(st.clone());
    let (status, _, bytes) = send(&app, get("/v1/feed?limit=1")).await;
    assert_eq!(status, StatusCode::OK);
    let page: FeedPage = serde_json::from_slice(&bytes).unwrap();
    let item = &page.items[0];
    let batch = json!({"session_id":page.session_id,"client_id":"feedback-only","sent_at":page.generated_at,"events":[{"event_id":"feedback-only-event","delivery_id":item.delivery_id,"card_id":item.card.id,"slot":item.slot,"shown_at":page.generated_at,"dwell_time_ms":9000,"loop_count":1,"swipe_velocity":0}]});
    let mut original = None;
    for (accepted, duplicates) in [(1, 0), (0, 1)] {
        let (status, _, bytes) = send(&app, post_json("/v1/feedback", &batch, Some(&token.plaintext))).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&bytes));
        let ack: FeedbackAck = serde_json::from_slice(&bytes).unwrap();
        assert_eq!((ack.accepted, ack.duplicates, ack.rejected.len()), (accepted, duplicates, 0));
        let receipts = ack.receipts.unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].event_id, "feedback-only-event");
        assert_eq!(receipts[0].disposition.as_deref(), Some("scheduled"));
        if let Some(previous) = &original {
            assert_eq!(&receipts, previous);
        }
        original = Some(receipts);
    }
    let memory = st.repo.get_versioned_memory(&p.tenant_id, &p.user_id, &item.card.id).await.unwrap().unwrap();
    assert_eq!((memory.version, memory.state.exposures, memory.state.reps), (1, 1, 1));
    for uri in ["/v1/library", "/v1/history"] {
        let request = Request::get(uri)
            .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&app, request).await.0, StatusCode::FORBIDDEN);
    }
    drop((app, st));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn personal_library_http_commands_and_wire_ack() {
    let (app, st, dir) = app(DeploymentMode::SingleUser).await;
    let (_, _, bytes) = send(&app, get("/v1/server-info")).await;
    let info: ServerInfo = serde_json::from_slice(&bytes).unwrap();
    assert!(info.features.iter().any(|f| f == "personal-library-v1"));
    let (status, _, bytes) = send(&app, get("/v1/library?limit=1")).await;
    assert_eq!(status, StatusCode::OK);
    let page: memoswish_protocol::LibraryPage = serde_json::from_slice(&bytes).unwrap();
    let card = &page.items[0].card.id;
    let uri = format!("/v1/library/{card}/favorite");
    let command = json!({"operation_id":"http-unstar","desired_state":false,"expected_revision":0});
    assert_eq!(send(&app, post_json(&uri, &command, None)).await.0, StatusCode::OK);
    assert_eq!(send(&app, post_json(&uri, &command, None)).await.0, StatusCode::OK);
    assert_eq!(
        send(&app, post_json(&uri, &json!({"operation_id":"stale","desired_state":true,"expected_revision":0}), None))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        send(
            &app,
            post_json(
                "/v1/library/missing/favorite",
                &json!({"operation_id":"missing-card","desired_state":false,"expected_revision":0}),
                None
            )
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (status, _, export) = send(&app, get("/v1/account/export/full")).await;
    assert_eq!(status, StatusCode::OK);
    let export: Value = serde_json::from_slice(&export).unwrap();
    assert_eq!(export["workspaces"][0]["data"]["favorite_operations"][0]["receipt"]["card_id"], card.as_str());
    for path in ["/v1/library?limit=0", "/v1/library?cursor=bad", "/v1/history?query=not-supported"] {
        assert_eq!(send(&app, get(path)).await.0, StatusCode::BAD_REQUEST);
    }
    let (_, _, bytes) = send(&app, get("/v1/feed?limit=1")).await;
    let page: FeedPage = serde_json::from_slice(&bytes).unwrap();
    let item = &page.items[0];
    let batch = json!({"session_id":page.session_id,"client_id":"p3-2","sent_at":page.generated_at,"events":[{"event_id":"library-feedback","delivery_id":item.delivery_id,"card_id":item.card.id,"slot":item.slot,"shown_at":page.generated_at,"dwell_time_ms":9000,"loop_count":1,"swipe_velocity":0}]});
    let (_, _, bytes) = send(&app, post_json("/v1/feedback", &batch, None)).await;
    let ack: FeedbackAck = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ack.accepted, 1);
    assert_eq!(ack.receipts.unwrap().len(), 1);
    let (_, _, bytes) = send(&app, post_json("/v1/feedback", &batch, None)).await;
    let ack: FeedbackAck = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ack.duplicates, 1);
    let (_, _, bytes) = send(&app, get("/v1/history")).await;
    let history: memoswish_protocol::ReviewHistoryPage = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(history.items.len(), 1);
    let favorite_uri = format!("/v1/library/{}/favorite", item.card.id);
    let favorite = json!({"operation_id":"before-unpublish","desired_state":true,"expected_revision":if item.card.id==*card {1}else{0}});
    let original = send(&app, post_json(&favorite_uri, &favorite, None)).await;
    assert_eq!(original.0, StatusCode::OK);
    let publication_uri = format!("/v1/content/cards/{}/publication", item.card.id);
    assert_eq!(
        send(&app, post_json(&publication_uri, &json!({"expected_revision":item.card.revision,"publish":false}), None))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(send(&app, post_json(&favorite_uri, &favorite, None)).await.2, original.2);
    let fresh_favorite = json!({"operation_id":"after-unpublish","desired_state":false,"expected_revision":1});
    let (status, _, bytes) = send(&app, post_json(&favorite_uri, &fresh_favorite, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["code"], "not_found");
    let (_, _, bytes) = send(&app, post_json("/v1/feedback", &batch, None)).await;
    let duplicate: FeedbackAck = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(duplicate.duplicates, 1);
    assert_eq!(duplicate.receipts.unwrap().len(), 1);
    let mut fresh = batch.clone();
    fresh["events"][0]["event_id"] = json!("after-unpublish");
    let (status, _, bytes) = send(&app, post_json("/v1/feedback", &fresh, None)).await;
    assert_eq!(status, StatusCode::OK);
    let rejected: FeedbackAck = serde_json::from_slice(&bytes).unwrap();
    assert_eq!((rejected.accepted, rejected.duplicates), (0, 0));
    assert_eq!(rejected.rejected.len(), 1);
    assert_eq!(rejected.rejected[0].event_id, "after-unpublish");
    assert!(rejected.receipts.unwrap().is_empty());
    let (_, _, bytes) = send(&app, get(&format!("/v1/library?card_id={}", item.card.id))).await;
    assert!(serde_json::from_slice::<memoswish_protocol::LibraryPage>(&bytes).unwrap().items.is_empty());
    let (_, _, bytes) = send(&app, get("/v1/history")).await;
    assert!(serde_json::from_slice::<memoswish_protocol::ReviewHistoryPage>(&bytes).unwrap().items.is_empty());
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[path = "tests/asset_streaming.rs"]
mod asset_streaming;

mod learning_controls;

#[path = "tests/hf12.rs"]
mod hf12;
