//! 两传输共用的安全策略及 HTTP 生命周期回归。

use super::*;
use axum::body::Bytes;
use axum::http::Request;
use http_body_util::BodyExt;
use memoswish_auth::{Metric, Unlimited};
use memoswish_core::Principal;
use serde_json::{Value, json};
use tower::ServiceExt;

fn state(server: McpServer) -> HttpState {
    HttpState {
        server: Arc::new(server),
        allowed_origins: Arc::new(vec!["https://client.example:443".into()]),
        allowed_hosts: Arc::new(vec!["localhost".into(), "127.0.0.1".into(), "::1".into(), "learn.example:443".into()]),
        #[cfg(feature = "mcp-oauth")]
        oauth: None,
    }
}

fn request(value: Value) -> Request<Body> {
    Request::post("/mcp")
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(value.to_string()))
        .unwrap()
}

fn ping() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"ping"})
}

fn init(version: &str) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":version,"capabilities":{},"clientInfo":{"name":"test","version":"0"}
    }})
}

async fn response(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() };
    (status, headers, value)
}

#[tokio::test]
async fn negotiated_versions_headers_and_stateless_lifecycle() {
    let app = router(state(crate::server::tests::test_server().await));
    for (requested, expected) in [
        ("2025-06-18", "2025-06-18"),
        ("2025-11-25", "2025-11-25"),
        ("2025-03-26", "2025-11-25"),
        ("2024-11-05", "2025-11-25"),
        ("1999-01-01", "2025-11-25"),
        ("2026-07-28", "2025-11-25"),
    ] {
        let mut req = request(init(requested));
        req.headers_mut().insert(SESSION_HEADER, HeaderValue::from_static("arbitrary-reused-session"));
        let (status, headers, body) = response(&app, req).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["result"]["protocolVersion"], expected);
        assert!(!headers.contains_key(SESSION_HEADER));
        assert_eq!(body["result"]["capabilities"]["tools"]["listChanged"], false);
    }
    for version in ["2025-06-18", "2025-11-25", "2025-03-26", "2026-07-28", "invalid"] {
        let mut req = request(ping());
        req.headers_mut().insert("mcp-protocol-version", version.parse().unwrap());
        let (status, _, _) = response(&app, req).await;
        assert_eq!(
            status,
            if SUPPORTED_VERSIONS.contains(&version) { StatusCode::OK } else { StatusCode::BAD_REQUEST }
        );
    }
    let mut mismatch = request(init("2025-06-18"));
    mismatch.headers_mut().insert("mcp-protocol-version", HeaderValue::from_static("2025-11-25"));
    assert_eq!(response(&app, mismatch).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(response(&app, request(ping())).await.0, StatusCode::OK);
    for method in [Method::GET, Method::HEAD, Method::DELETE] {
        let req = Request::builder()
            .method(method)
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(SESSION_HEADER, "reused")
            .body(Body::empty())
            .unwrap();
        let result = app.clone().oneshot(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(result.headers()[header::ALLOW], "POST");
        assert!(!result.headers().contains_key(SESSION_HEADER));
    }
}

#[tokio::test]
async fn rejected_envelopes_never_write_or_meter() {
    let mut server = crate::server::tests::test_server().await;
    let repo = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
    server.services.quota = Arc::new(Unlimited::metered(repo));
    let services = server.services.clone();
    let app = router(state(server));
    let call = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_create","arguments":{"title":"must not exist","language":"en"}}});
    let mut cases = vec![
        json!([]),
        json!([call.clone()]),
        json!(null),
        json!({}),
        json!({"jsonrpc":"2.0","id":1}),
        json!({"jsonrpc":"2.0","id":1,"result":{},"error":{}}),
    ];
    for id in [Value::Null, json!({"secret":"sentinel"}), json!([]), json!(0.5), json!(18446744073709551615_u64)] {
        let mut bad = call.clone();
        bad["id"] = id;
        cases.push(bad);
    }
    for (field, value) in [
        ("jsonrpc", json!("1.0")),
        ("method", json!(null)),
        ("result", json!({})),
        ("error", json!({})),
        ("params", json!([])),
        ("params", json!(null)),
    ] {
        let mut bad = call.clone();
        bad[field] = value;
        cases.push(bad);
    }
    let mut notification = call.clone();
    notification.as_object_mut().unwrap().remove("id");
    cases.push(notification);
    let mut bad_arguments = call.clone();
    bad_arguments["params"]["arguments"] = json!([]);
    cases.push(bad_arguments);
    for value in cases {
        let (status, _, body) = response(&app, request(value.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}: {body}");
        assert!(body["error"]["code"].is_number());
    }
    let principal = Principal::local_owner("test");
    assert!(services.list_decks(&principal).await.unwrap().is_empty());
    let used = services.usage(&principal).await.unwrap();
    assert_eq!(used.metrics.iter().find(|metric| metric.metric == Metric::McpCalls.as_str()).unwrap().used, 0);
    // 领域参数错误仍须经过已知工具的计量，不可被 SDK schema 验证提前吞掉。
    let (_, _, body) = response(
        &app,
        request(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_create","arguments":{}}})),
    )
    .await;
    assert_eq!(body["error"]["code"], codes::INVALID_PARAMS);
    let used = services.usage(&principal).await.unwrap();
    assert_eq!(used.metrics.iter().find(|metric| metric.metric == Metric::McpCalls.as_str()).unwrap().used, 1);
}

#[tokio::test]
async fn host_origin_and_media_policy() {
    let app = router(state(crate::server::tests::test_server().await));
    for (origin, allowed) in [
        ("http://localhost:3000", true),
        ("http://[::1]:3000", true),
        ("https://client.example", true),
        ("https://client.example:444", false),
        ("https://evil.example", false),
        ("localhost", false),
        ("http://localhost:invalid", false),
        ("http://localhost:99999", false),
        ("http://localhost:", false),
        ("http://localhost@evil.example", false),
        ("http://localhost/attack", false),
        ("null", false),
    ] {
        let mut req = request(ping());
        req.headers_mut().insert(header::ORIGIN, origin.parse().unwrap());
        assert_eq!(
            response(&app, req).await.0,
            if allowed { StatusCode::OK } else { StatusCode::FORBIDDEN },
            "{origin}"
        );
    }
    for (host, allowed) in [
        ("localhost:8787", true),
        ("[::1]:8787", true),
        ("learn.example:443", true),
        ("evil.example", false),
        ("learn.example:444", false),
    ] {
        let mut req = request(ping());
        req.headers_mut().insert(header::HOST, host.parse().unwrap());
        req.headers_mut().insert("forwarded", HeaderValue::from_static("host=learn.example:443;proto=https"));
        assert_eq!(response(&app, req).await.0, if allowed { StatusCode::OK } else { StatusCode::FORBIDDEN }, "{host}");
    }
    let mut default_hosts = state(crate::server::tests::test_server().await);
    default_hosts.allowed_hosts = Arc::new(vec![]);
    let default_hosts = router(default_hosts);
    let mut forged = request(ping());
    forged.headers_mut().insert(header::HOST, HeaderValue::from_static("evil.example"));
    assert_eq!(response(&default_hosts, forged).await.0, StatusCode::FORBIDDEN);
    assert_eq!(response(&default_hosts, request(ping())).await.0, StatusCode::OK);
    for accept in ["text/html", "application/json;q=0,text/event-stream;q=0", "application/json;q=wat"] {
        let mut req = request(ping());
        req.headers_mut().insert(header::ACCEPT, accept.parse().unwrap());
        assert_eq!(response(&app, req).await.0, StatusCode::NOT_ACCEPTABLE);
    }
    let mut req = request(ping());
    req.headers_mut().remove(header::CONTENT_TYPE);
    assert_eq!(response(&app, req).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let mut req = request(ping());
    req.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    assert_eq!(response(&app, req).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn bounded_bodies_and_safe_parse_read_errors() {
    let app = router(state(crate::server::tests::test_server().await));
    let mut exact = ping().to_string();
    exact.extend(std::iter::repeat_n(' ', MAX_MESSAGE_BYTES - exact.len()));
    let mut req = request(ping());
    *req.body_mut() = Body::from(exact.clone());
    assert_eq!(response(&app, req).await.0, StatusCode::OK);
    exact.push(' ');
    let mut req = request(ping());
    *req.body_mut() = Body::from(exact);
    assert_eq!(response(&app, req).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    let stream = futures::stream::iter([
        Ok::<_, std::io::Error>(Bytes::from(vec![b' '; MAX_MESSAGE_BYTES])),
        Ok(Bytes::from_static(b"overrun")),
    ]);
    let mut req = request(ping());
    *req.body_mut() = Body::from_stream(stream);
    assert_eq!(response(&app, req).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    let stream = futures::stream::iter([Err::<Bytes, _>(std::io::Error::other("S28_SECRET_SENTINEL"))]);
    let mut req = request(ping());
    *req.body_mut() = Body::from_stream(stream);
    let (status, _, body) = response(&app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body.to_string().contains("S28_SECRET_SENTINEL"));
    let mut req = request(ping());
    *req.body_mut() = Body::from("{\"S28_SECRET_SENTINEL\":invalid}");
    let (status, _, body) = response(&app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], codes::PARSE_ERROR);
    assert!(!body.to_string().contains("S28_SECRET_SENTINEL"));
}

#[tokio::test]
async fn concurrent_same_ids_and_session_headers_never_share_identity() {
    let (server, repo) =
        crate::server::tests::test_server_with_repo(memoswish_protocol::DeploymentMode::MultiTenant).await;
    let mut credentials = Vec::new();
    for name in ["alice", "bob"] {
        let registered = server
            .services
            .auth
            .register(&memoswish_protocol::RegisterRequest {
                email: format!("{name}@example.test"),
                password: "password123".into(),
                display_name: name.into(),
                tenant_name: None,
            })
            .await
            .unwrap();
        let principal = server.services.auth.authenticate(Some(&registered.access_token)).await.unwrap();
        let token = server.services.auth.create_api_token(&principal, "test", vec![], None).await.unwrap();
        credentials.push((principal, token));
    }
    let services = server.services.clone();
    let app = router(state(server));
    let make = |name: &str, token: &str| {
        let mut req = request(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_create","arguments":{"title":name,"language":"en"}}}),
        );
        req.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        req.headers_mut().insert(SESSION_HEADER, HeaderValue::from_static("shared-untrusted-session"));
        req
    };
    let (alice, bob) = tokio::join!(
        response(&app, make("alice", &credentials[0].1.plaintext)),
        response(&app, make("bob", &credentials[1].1.plaintext))
    );
    assert_eq!(alice.0, StatusCode::OK);
    assert_eq!(bob.0, StatusCode::OK);
    assert_eq!(alice.2["result"]["structuredContent"]["title"], "alice");
    assert_eq!(bob.2["result"]["structuredContent"]["title"], "bob");
    for (index, name) in ["alice", "bob"].iter().enumerate() {
        let decks = services.list_decks(&credentials[index].0).await.unwrap();
        assert_eq!(decks.len(), 1);
        assert_eq!(decks[0].title, *name);
    }
    // 同一会话头不能把撤销后的下一请求升级为旧主体。
    assert!(repo.revoke_api_token(&credentials[0].0.tenant_id, &credentials[0].1.record.id).await.unwrap());
    let (status, headers, _) = response(&app, make("revoked", &credentials[0].1.plaintext)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers[header::WWW_AUTHENTICATE], r#"Bearer realm="learntok""#);
    assert_eq!(services.list_decks(&credentials[0].0).await.unwrap().len(), 1);
}

#[tokio::test]
async fn real_sdk_http_client_uses_stateless_transport() {
    use rmcp::{ServiceExt, model::CallToolRequestParams, transport::StreamableHttpClientTransport};
    let app = router(state(crate::server::tests::test_server().await));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let client = ().serve(StreamableHttpClientTransport::from_uri(format!("http://{address}/mcp"))).await.unwrap();
    assert_eq!(client.peer_info().unwrap().protocol_version.as_str(), "2025-11-25");
    let tools = client.peer().list_tools(Default::default()).await.unwrap();
    assert_eq!(serde_json::to_value(tools).unwrap(), crate::tools::list_tools_json());
    let result = client.peer().call_tool(CallToolRequestParams::new("deck_list")).await.unwrap();
    assert_eq!(result.is_error, Some(false));
    client.cancel().await.unwrap();
    stop.send(()).unwrap();
    server.await.unwrap();
}

struct Gate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl Gate {
    fn new() -> Self {
        Self { entered: tokio::sync::Semaphore::new(0), release: tokio::sync::Semaphore::new(0) }
    }
    async fn pause(&self) {
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
    }
    async fn reached(&self) {
        self.entered.acquire().await.unwrap().forget();
    }
}

#[async_trait::async_trait]
impl memoswish_core::rate_limit::RateLimiter for Gate {
    async fn check(&self, _: &str, _: f64) -> memoswish_core::CoreResult<()> {
        self.pause().await;
        Ok(())
    }
}

#[tokio::test]
async fn inventory_revocation_blocks_active_and_subsequent_mcp_calls() {
    let (mut server, repo) =
        crate::server::tests::test_server_with_repo(memoswish_protocol::DeploymentMode::MultiTenant).await;
    let registered = server
        .services
        .auth
        .register(&memoswish_protocol::RegisterRequest {
            email: "revocation@example.test".into(),
            password: "password123".into(),
            display_name: "revocation".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let principal = server.services.auth.authenticate(Some(&registered.access_token)).await.unwrap();
    let token = server.services.auth.create_api_token(&principal, "test", vec![], None).await.unwrap();
    let gate = Arc::new(Gate::new());
    server.services.limiter = gate.clone();
    let services = server.services.clone();
    let app = router(state(server));
    let make = || {
        let mut request = request(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_create","arguments":{"title":"in flight","language":"en"}}}),
        );
        request.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {}", token.plaintext).parse().unwrap());
        request.headers_mut().insert(SESSION_HEADER, HeaderValue::from_static("same-session"));
        request
    };
    let request_a = make();
    let app_a = app.clone();
    let first = tokio::spawn(async move { response(&app_a, request_a).await });
    gate.reached().await;
    let root = services
        .auth
        .login_session(&memoswish_protocol::LoginRequest {
            email: "revocation@example.test".into(),
            password: "password123".into(),
        })
        .await
        .unwrap();
    assert!(
        services
            .auth
            .revoke_access(
                &root.access_token,
                memoswish_core::session::AccessKind::ApiTokens,
                Some(&principal.tenant_id),
                &token.record.id
            )
            .await
            .unwrap()
    );
    assert!(repo.find_api_token(&token.record.token_hash).await.unwrap().unwrap().revoked);
    assert_eq!(response(&app, make()).await.0, StatusCode::UNAUTHORIZED);
    gate.release.add_permits(1);
    let (status, _, body) = first.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("error").is_some() || body["result"]["isError"] == true, "{body}");
    assert!(services.list_decks(&principal).await.unwrap().is_empty());
}

struct ImportQuota {
    inner: Unlimited,
    gate: Option<Arc<Gate>>,
}

#[async_trait::async_trait]
impl memoswish_auth::QuotaPolicy for ImportQuota {
    fn name(&self) -> &'static str {
        "s28-import-test"
    }
    async fn consume(&self, p: &Principal, metric: Metric, amount: u64) -> memoswish_core::CoreResult<()> {
        if metric == Metric::CardWrites
            && let Some(gate) = &self.gate
        {
            gate.pause().await;
        }
        self.inner.consume(p, metric, amount).await
    }
    async fn card_write_limit(&self, _tenant: &str) -> memoswish_core::CoreResult<Option<i64>> {
        if let Some(gate) = &self.gate {
            gate.pause().await;
        }
        Ok(None)
    }
    async fn snapshot(&self, p: &Principal) -> memoswish_core::CoreResult<memoswish_auth::UsageSnapshot> {
        self.inner.snapshot(p).await
    }
}

struct ImportStore {
    inner: memoswish_storage::LocalDiskStore,
    gate: Option<Arc<Gate>>,
    fail_put: bool,
}

#[async_trait::async_trait]
impl memoswish_core::store::ObjectStore for ImportStore {
    fn namespace(&self) -> memoswish_core::CoreResult<String> {
        self.inner.namespace()
    }
    fn kind(&self) -> &'static str {
        "s28-import-test"
    }
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        mime: &str,
    ) -> memoswish_core::CoreResult<memoswish_protocol::AssetRef> {
        let asset = self.inner.put(key, bytes, mime).await?;
        if let Some(gate) = &self.gate {
            gate.pause().await;
        }
        if self.fail_put {
            return Err(memoswish_core::CoreError::internal("S28_SECRET_SENTINEL"));
        }
        Ok(asset)
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
}

#[tokio::test]
async fn json_and_sse_disconnect_preserve_import_accounting_publication_and_cleanup() {
    use crate::server::apkg_support as support;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use memoswish_content::{ContentService, apkg::ApkgOptions};
    use memoswish_core::store::ObjectStore;
    let _guard = crate::APKG_TEST.lock().await;
    let bytes = support::zip(vec![
        ("collection.anki2", support::database("basic", "Question<img src='x.png'>\x1fAnswer", &[0]).await),
        ("media", br#"{"0":"x.png"}"#.to_vec()),
        ("0", b"\x89PNG\r\n\x1a\nimage".to_vec()),
    ]);
    for accept in ["application/json", "text/event-stream"] {
        for pause_upload in [false, true] {
            for fail_put in [false, true] {
                let (mut server, repo) =
                    crate::server::tests::test_server_with_repo(memoswish_protocol::DeploymentMode::SingleUser).await;
                let gate = Arc::new(Gate::new());
                let dir = std::env::temp_dir().join(format!("s28-cancel-{}", memoswish_core::ids::new_id()));
                let store = Arc::new(ImportStore {
                    inner: memoswish_storage::LocalDiskStore::new(&dir, "/assets"),
                    gate: pause_upload.then(|| gate.clone()),
                    fail_put,
                });
                store.inner.put("tenants/local/keep.png", vec![1], "image/png").await.unwrap();
                server.services.content = ContentService::new(repo.clone()).with_import_store(store.clone());
                server.services.quota = Arc::new(ImportQuota {
                    inner: Unlimited::metered(repo),
                    gate: (!pause_upload).then(|| gate.clone()),
                });
                let services = server.services.clone();
                let principal = Principal::local_owner("test");
                // 持有另一许可，恢复准备成功即可证明后台任务已归还本次许可。
                let held =
                    services.content.prepare_apkg(&principal, bytes.clone(), ApkgOptions::default()).await.unwrap();
                let app = router(state(server));
                let mut request = request(
                    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_import_apkg","arguments":{"apkg_base64":STANDARD.encode(&bytes)}}}),
                );
                request.headers_mut().insert(header::ACCEPT, accept.parse().unwrap());
                let task = tokio::spawn(async move {
                    let response = app.oneshot(request).await.unwrap();
                    response.into_body().collect().await
                });
                gate.reached().await;
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                gate.release.add_permits(1);
                let recovered = loop {
                    match services.content.prepare_apkg(&principal, bytes.clone(), ApkgOptions::default()).await {
                        Ok(prepared) => break prepared,
                        Err(memoswish_core::CoreError::QuotaExceeded(_)) => tokio::task::yield_now().await,
                        Err(error) => panic!("unexpected preparation failure: {error}"),
                    }
                };
                drop((held, recovered));
                assert_eq!(services.list_decks(&principal).await.unwrap().len(), usize::from(!fail_put));
                assert_eq!(store.inner.list_prefix("tenants/local/").await.unwrap().len(), 2);
                assert!(store.exists("tenants/local/keep.png").await.unwrap());
                let used = services.usage(&principal).await.unwrap();
                for metric in [Metric::McpCalls, Metric::CardWrites] {
                    assert_eq!(
                        used.metrics.iter().find(|entry| entry.metric == metric.as_str()).unwrap().used,
                        if fail_put && metric == Metric::CardWrites { 0 } else { 1 }
                    );
                    if fail_put && metric == Metric::CardWrites {
                        assert_eq!(used.metrics.iter().find(|entry| entry.metric == metric.as_str()).unwrap().held, 1);
                    }
                }
                std::fs::remove_dir_all(dir).unwrap();
            }
        }
    }
}

struct FailingLimiter(std::sync::Mutex<Option<memoswish_core::CoreError>>);

#[async_trait::async_trait]
impl memoswish_core::rate_limit::RateLimiter for FailingLimiter {
    async fn check(&self, _: &str, _: f64) -> memoswish_core::CoreResult<()> {
        Err(self.0.lock().unwrap().take().expect("one injected failure"))
    }
}

#[tokio::test]
async fn domain_errors_keep_tool_envelope_without_exposing_payloads() {
    use memoswish_core::CoreError;
    for error in [
        CoreError::internal("SQL/provider S28_SECRET_SENTINEL"),
        CoreError::Invalid("S28_SECRET_SENTINEL".into()),
        CoreError::Unavailable("S28_SECRET_SENTINEL".into()),
        memoswish_core::tts::SpeechFailure::from_code("speech_engine_unavailable").unwrap().error(),
        memoswish_core::tts::SpeechFailure::from_code("speech_voice_unavailable").unwrap().error(),
    ] {
        let expected = format!("[{}] {}", error.code(), error.public_message());
        let mut server = crate::server::tests::test_server().await;
        server.services.limiter = Arc::new(FailingLimiter(std::sync::Mutex::new(Some(error))));
        let app = router(state(server));
        let (status, _, body) = response(
            &app,
            request(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_list","arguments":{}}})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["isError"], true);
        assert_eq!(body["result"]["content"][0]["text"], expected);
        assert!(!body.to_string().contains("S28_SECRET_SENTINEL"));
    }
}

#[tokio::test]
async fn sdk_http_handler_without_request_principal_fails_closed() {
    let server = crate::server::tests::test_server().await;
    let services = server.services.clone();
    let message = validate(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_create","arguments":{"title":"must not exist"}}})).unwrap();
    let (transport, mut responses) = rmcp::transport::OneshotTransport::<rmcp::RoleServer>::new(message);
    let service = rmcp::service::serve_directly(
        Handler { server, stdio_principal: None, stdio_authority: None },
        transport,
        None,
    );
    let response = serde_json::to_value(responses.recv().await.unwrap()).unwrap();
    service.cancel().await.unwrap();
    assert_eq!(response["error"]["code"], codes::INVALID_REQUEST);
    assert!(services.list_decks(&Principal::local_owner("test")).await.unwrap().is_empty());
}

#[test]
fn strict_content_tools_have_explicit_oauth_permissions_without_implicit_media() {
    use memoswish_core::Permission::*;
    for (name, expected) in [
        ("card_save", vec![ContentWrite]),
        ("card_publish", vec![ContentWrite]),
        ("card_report", vec![ContentRead, FeedbackWrite]),
    ] {
        assert_eq!(
            required_permissions(&json!({"method":"tools/call","params":{"name":name,"arguments":{}}})),
            expected
        );
    }
    assert_eq!(
        required_permissions(
            &json!({"method":"tools/call","params":{"name":"card_upsert","arguments":{"content_lifecycle":true}}})
        ),
        vec![ContentWrite]
    );
    assert!(
        required_permissions(&json!({"method":"tools/call","params":{"name":"card_upsert","arguments":{}}}))
            .contains(&TtsGenerate)
    );
}

#[tokio::test]
async fn explicit_http_cancellation_before_import_acceptance_does_not_create_responsibility() {
    let mut server = crate::server::tests::test_server().await;
    let gate = Arc::new(Gate::new());
    server.services.limiter = gate.clone();
    let services = server.services.clone();
    let app = router(state(server));
    let pack = memoswish_protocol::examples::sample_deck_pack();
    let call = json!({"jsonrpc":"2.0","id":"cancel-import","method":"tools/call","params":{
        "name":"deck_import","arguments":{"pack":pack,"auto_tts":false,"request_id":"cancel-import"}
    }});
    let app_a = app.clone();
    let first = tokio::spawn(async move { response(&app_a, request(call)).await });
    gate.reached().await;
    let duplicate = json!({"jsonrpc":"2.0","id":"cancel-import","method":"tools/call","params":{"name":"deck_list"}});
    assert_eq!(response(&app, request(duplicate)).await.2["error"]["code"], -32600);
    let cancel = json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"cancel-import","reason":"SECRET_SENTINEL"}});
    assert_eq!(response(&app, request(cancel.clone())).await.0, StatusCode::ACCEPTED);
    assert_eq!(response(&app, request(cancel)).await.0, StatusCode::ACCEPTED);
    gate.release.add_permits(1);
    let (_, _, result) = first.await.unwrap();
    assert_eq!(result["result"]["isError"], true, "{result}");
    let principal = Principal::local_owner("single_user");
    assert!(services.list_decks(&principal).await.unwrap().is_empty());
    assert!(matches!(
        services.import_status(&principal, "cancel-import", None).await,
        Err(memoswish_core::CoreError::NotFound(_))
    ));
    services.operations.close();
    services.operations.wait().await;
}

#[tokio::test]
async fn cancellation_bridge_obeys_host_origin_version_and_typed_ids() {
    let server = crate::server::tests::test_server().await;
    let principal = server.services.auth.authenticate(None).await.unwrap();
    let active = server
        .active_calls
        .register(crate::control::http_authority(&principal, None), rmcp::model::RequestId::Number(7))
        .unwrap();
    let app = router(state(server));
    let cancel = |id: Value| json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id}});
    for (header_name, header_value) in
        [("host", "evil.example"), ("origin", "https://evil.example"), ("mcp-protocol-version", "2099-01-01")]
    {
        let mut req = request(cancel(json!(7)));
        req.headers_mut().insert(axum::http::HeaderName::from_static(header_name), header_value.parse().unwrap());
        assert!(response(&app, req).await.0.is_client_error());
        assert!(active.control.checkpoint().is_ok());
    }
    for value in [
        cancel(json!("7")),
        cancel(json!(999)),
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":123}}),
    ] {
        let _ = response(&app, request(value)).await;
        assert!(active.control.checkpoint().is_ok());
    }
    assert_eq!(response(&app, request(cancel(json!(7)))).await.0, StatusCode::ACCEPTED);
    assert!(active.control.checkpoint().is_err());
}

#[tokio::test]
async fn logging_is_truthfully_unsupported_and_progress_metadata_is_validated() {
    let app = router(state(crate::server::tests::test_server().await));
    for (params, code) in [(json!({"level":"debug"}), -32601), (json!({"level":"invalid"}), -32602)] {
        let (_, _, result) =
            response(&app, request(json!({"jsonrpc":"2.0","id":1,"method":"logging/setLevel","params":params}))).await;
        assert_eq!(result["error"]["code"], code);
    }
    for token in [json!(null), json!(false), json!([]), json!({}), json!(1.5), json!("x".repeat(129))] {
        let (status, _, _) = response(&app, request(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deck_list","_meta":{"progressToken":token}}}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn progress_is_request_local_sse_even_with_json_preference_and_empty_token() {
    let mut server = crate::server::tests::test_server().await;
    let gate = Arc::new(Gate::new());
    server.services.limiter = gate.clone();
    let app = router(state(server));
    let call = json!({"jsonrpc":"2.0","id":45,"method":"tools/call","params":{"name":"deck_import","_meta":{"progressToken":""},"arguments":{"pack":memoswish_protocol::examples::sample_deck_pack(),"auto_tts":false,"request_id":"progress"}}});
    let app_a = app.clone();
    let started = tokio::spawn(async move { app_a.oneshot(request(call)).await.unwrap() });
    gate.reached().await;
    let response = started.await.unwrap();
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/event-stream");
    let mut body = response.into_body();
    let mut raw = String::new();
    while !raw.contains("notifications/progress") {
        let frame = body.frame().await.unwrap().unwrap();
        if let Ok(data) = frame.into_data() {
            raw.push_str(std::str::from_utf8(&data).unwrap());
        }
    }
    let progress: Value = raw
        .lines()
        .filter_map(|line| line.strip_prefix("data: ").or_else(|| line.strip_prefix("data:")))
        .find_map(|line| serde_json::from_str::<Value>(line).ok().filter(|v| v["method"] == "notifications/progress"))
        .unwrap();
    assert_eq!(progress["params"]["progressToken"], "");
    assert_eq!(progress["params"]["progress"], 1.0);
    assert!(progress["params"].get("total").is_none());
    assert_eq!(progress["params"]["message"], "preparing");
    assert_eq!(
        super::boundary_tests::response(&app, request(json!({"jsonrpc":"2.0","id":46,"method":"ping"}))).await.0,
        StatusCode::OK
    );
    assert_eq!(
        super::boundary_tests::response(
            &app,
            request(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":45}}))
        )
        .await
        .0,
        StatusCode::ACCEPTED
    );
    gate.release.add_permits(1);
    let tail = body.collect().await.unwrap().to_bytes();
    let tail = std::str::from_utf8(&tail).unwrap();
    assert!(!tail.contains("notifications/progress"));
    assert!(tail.contains("isError"));
}

#[tokio::test]
async fn cancellation_never_transfers_between_api_tokens_and_revocation_is_rechecked() {
    let (server, repo) =
        crate::server::tests::test_server_with_repo(memoswish_protocol::DeploymentMode::MultiTenant).await;
    let account = server
        .services
        .auth
        .register(&memoswish_protocol::RegisterRequest {
            email: "control@example.test".into(),
            password: "password123".into(),
            display_name: "Control".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let owner = server.services.auth.authenticate(Some(&account.access_token)).await.unwrap();
    let first = server.services.auth.create_api_token(&owner, "first", vec![], None).await.unwrap();
    let second = server.services.auth.create_api_token(&owner, "second", vec![], None).await.unwrap();
    let principal = server.services.auth.authenticate(Some(&first.plaintext)).await.unwrap();
    let active = server
        .active_calls
        .register(crate::control::http_authority(&principal, Some(&first.plaintext)), rmcp::model::RequestId::Number(1))
        .unwrap();
    let app = router(state(server));
    let cancel = |token: &str| {
        let mut req = request(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}));
        req.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        req.headers_mut().insert(SESSION_HEADER, HeaderValue::from_static("forged-same-session"));
        req
    };
    assert_eq!(response(&app, cancel(&second.plaintext)).await.0, StatusCode::ACCEPTED);
    assert!(active.control.checkpoint().is_ok());
    repo.revoke_api_token(&owner.tenant_id, &first.record.id).await.unwrap();
    assert_eq!(response(&app, cancel(&first.plaintext)).await.0, StatusCode::UNAUTHORIZED);
    assert!(active.control.checkpoint().is_ok());
}

#[tokio::test]
async fn same_ids_and_progress_tokens_in_two_tenants_keep_cancellation_and_results_isolated() {
    let (mut server, _) =
        crate::server::tests::test_server_with_repo(memoswish_protocol::DeploymentMode::MultiTenant).await;
    let mut accounts = Vec::new();
    let mut principals = Vec::new();
    for email in ["progress-a@example.test", "progress-b@example.test"] {
        let account = server
            .services
            .auth
            .register(&memoswish_protocol::RegisterRequest {
                email: email.into(),
                password: "password123".into(),
                display_name: "Progress".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
        principals.push(server.services.auth.authenticate(Some(&account.access_token)).await.unwrap());
        accounts.push(account);
    }
    let gate = Arc::new(Gate::new());
    server.services.limiter = gate.clone();
    let services = server.services.clone();
    let app = router(state(server));
    let mut streams = Vec::new();
    for (index, account) in accounts.iter().enumerate() {
        let mut pack = memoswish_protocol::examples::sample_deck_pack();
        pack.deck.title = format!("Tenant {index}");
        let mut req = request(
            json!({"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"deck_import","_meta":{"progressToken":"same-token"},"arguments":{"pack":pack,"auto_tts":false,"request_id":"same-business-key"}}}),
        );
        req.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {}", account.access_token).parse().unwrap());
        let app = app.clone();
        streams.push(tokio::spawn(async move { app.oneshot(req).await.unwrap() }));
    }
    gate.reached().await;
    gate.reached().await;
    let mut responses = Vec::new();
    for stream in streams {
        responses.push(stream.await.unwrap());
    }
    let mut cancel = request(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":71}}));
    cancel.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {}", accounts[0].access_token).parse().unwrap());
    assert_eq!(response(&app, cancel).await.0, StatusCode::ACCEPTED);
    gate.release.add_permits(2);
    for (index, response) in responses.into_iter().enumerate() {
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/event-stream");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("same-token"));
        let values: Vec<Value> = body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|line| serde_json::from_str(line.trim()).ok())
            .collect();
        let result = values.iter().find(|v| v["id"] == 71).unwrap();
        assert_eq!(result["result"]["isError"], index == 0, "{body}");
        assert_eq!(services.list_decks(&principals[index]).await.unwrap().len(), index);
    }
}

#[tokio::test]
async fn unsupported_capabilities_never_return_noop_success() {
    let app = router(state(crate::server::tests::test_server().await));
    let (_, _, info) = response(&app, request(init("2025-11-25"))).await;
    for capability in ["logging", "completions", "tasks", "elicitation"] {
        assert!(info["result"]["capabilities"].get(capability).is_none());
    }
    for (method, params) in [
        (
            "completion/complete",
            json!({"ref":{"type":"ref/prompt","name":"slice_article_to_cards"},"argument":{"name":"topic","value":"a"}}),
        ),
        ("resources/subscribe", json!({"uri":"memoswish://stats"})),
        ("resources/unsubscribe", json!({"uri":"memoswish://stats"})),
        ("tasks/list", json!({})),
        ("elicitation/create", json!({"message":"unsupported"})),
        ("server/discover", json!({})),
    ] {
        let (_, _, result) =
            response(&app, request(json!({"jsonrpc":"2.0","id":9,"method":method,"params":params}))).await;
        // 新版 discovery 缺少内联元数据时由 SDK 传输先拒绝，不能当作成功。
        let expected = if method == "server/discover" { -32600 } else { -32601 };
        assert_eq!(result["error"]["code"], expected, "{method}: {result}");
    }
}

#[tokio::test]
async fn cancelled_strict_authoring_during_mcp_admission_never_writes_or_charges_cards() {
    let mut server = crate::server::tests::test_server().await;
    let gate = Arc::new(Gate::new());
    let p = Principal::local_owner("single_user");
    let deck = server
        .services
        .create_authored_deck(
            &p,
            memoswish_content::NewDeck {
                title: "Cancelled authoring".into(),
                description: String::new(),
                language: "en".into(),
                tags: vec![],
            },
        )
        .await
        .unwrap();
    let card =
        serde_json::to_value(memoswish_content::slice_material(&deck.id, "Question :: Answer", 1).remove(0)).unwrap();
    let saved = server
        .services
        .save_card(
            &p,
            memoswish_protocol::CardSave {
                card: serde_json::from_value(card.clone()).unwrap(),
                publish: false,
                provenance: None,
                report_id: None,
            },
        )
        .await
        .unwrap();
    server.services.limiter = gate.clone();
    let services = server.services.clone();
    let app = router(state(server));
    for (name, args) in [
        ("card_save", json!({"card":card,"publish":true})),
        ("card_publish", json!({"card_id":saved.id,"expected_revision":saved.revision,"publish":true})),
        (
            "card_report",
            json!({"card_id":saved.id,"observed_revision":saved.revision,"text":"Check this answer","sources":[]}),
        ),
        ("card_upsert", json!({"cards":[card],"content_lifecycle":true,"publish":true})),
        (
            "material_slice",
            json!({"deck_id":deck.id,"text":"New :: Answer","commit":true,"content_lifecycle":true,"publish":true}),
        ),
    ] {
        let app_a = app.clone();
        let call =
            json!({"jsonrpc":"2.0","id":"authoring","method":"tools/call","params":{"name":name,"arguments":args}});
        let first = tokio::spawn(async move { response(&app_a, request(call)).await });
        gate.reached().await;
        assert_eq!(
            response(
                &app,
                request(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"authoring"}}))
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
        gate.release.add_permits(1);
        let result = first.await.unwrap().2;
        assert_eq!(result["result"]["isError"], true, "{name}: {result}");
        assert_eq!(services.get_card(&p, &saved.id).await.unwrap(), saved);
        assert_eq!(services.list_cards(&p, Some(&deck.id), 10, 0).await.unwrap().len(), 1);
    }
    services.operations.close();
    services.operations.wait().await;
}

#[tokio::test]
async fn inventory_grant_revocation_fences_active_authoring_and_retained_stdio() {
    use memoswish_core::{ids::new_id, oauth::*, session::AccessKind};
    let (mut server, repo) =
        crate::server::tests::test_server_with_repo(memoswish_protocol::DeploymentMode::MultiTenant).await;
    let root = server
        .services
        .auth
        .register_session(&memoswish_protocol::RegisterRequest {
            email: "grant-control@example.test".into(),
            password: "password123".into(),
            display_name: "Owner".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let tenant = server.services.auth.session_memberships(&root.access_token).await.unwrap()[0].tenant_id.clone();
    let workspace = server.services.auth.select_session_workspace(&root.access_token, &tenant).await.unwrap();
    let owner = server.services.auth.authenticate(Some(&workspace.access_token)).await.unwrap();
    let client = OAuthClient {
        id: new_id(),
        name: "Agent".into(),
        redirect_uris: vec!["https://agent.example/cb".into()],
        grant_types: vec!["authorization_code".into()],
        scopes: vec!["content:read".into(), "content:write".into()],
        auth_method: "none".into(),
        secret_hash: None,
        created_at: 10,
        expires_at: i64::MAX,
    };
    repo.oauth_register(&client).await.unwrap();
    let browser = BrowserSession {
        hash: new_id(),
        tenant_id: None,
        user_id: None,
        generations: None,
        auth_time: 10,
        auth_method: "anonymous".into(),
        expires_at: i64::MAX,
    };
    let mut authorization = AuthorizationRequest {
        id: new_id(),
        browser_hash: browser.hash.clone(),
        csrf_hash: new_id(),
        client_id: client.id.clone(),
        redirect_uri: client.redirect_uris[0].clone(),
        resource: "https://learn.example/mcp".into(),
        scopes: client.scopes.clone(),
        challenge: new_id(),
        state: None,
        expires_at: i64::MAX,
    };
    repo.oauth_begin(&browser, &authorization).await.unwrap();
    let authenticated = BrowserSession {
        hash: new_id(),
        tenant_id: Some(tenant.clone()),
        user_id: Some(owner.user_id.clone()),
        generations: Some(owner.credential_generations().unwrap()),
        auth_method: "password".into(),
        ..browser
    };
    assert!(repo.oauth_login(&tenant, &authorization, &authenticated, 10).await.unwrap());
    authorization.browser_hash = authenticated.hash.clone();
    let grant = OAuthGrant {
        generations: owner.credential_generations().unwrap(),
        id: new_id(),
        tenant_id: tenant.clone(),
        user_id: owner.user_id.clone(),
        client_id: client.id.clone(),
        resource: authorization.resource.clone(),
        scopes: client.scopes.clone(),
        expires_at: i64::MAX,
    };
    let code = AuthorizationCode {
        hash: new_id(),
        grant: grant.clone(),
        redirect_uri: authorization.redirect_uri.clone(),
        challenge: authorization.challenge.clone(),
        expires_at: i64::MAX,
    };
    assert!(repo.oauth_consent(&tenant, &authorization, Some(&code), 10).await.unwrap());
    let access = OAuthToken {
        hash: new_id(),
        grant: grant.clone(),
        scopes: grant.scopes.clone(),
        kind: "access".into(),
        expires_at: i64::MAX,
    };
    let refresh = OAuthToken { hash: new_id(), kind: "refresh".into(), ..access.clone() };
    assert!(repo.oauth_redeem(&tenant, &code, &[access.clone(), refresh.clone()], 10).await.unwrap());
    let captured = Principal {
        via: "mcp_oauth".into(),
        scopes: Some(grant.scopes.clone()),
        session_access_hash: Some(format!("oauth:{}", access.hash)),
        ..owner.clone()
    };
    let deck = server
        .services
        .create_authored_deck(
            &captured,
            memoswish_content::NewDeck {
                title: "Grant deck".into(),
                description: String::new(),
                language: "en".into(),
                tags: vec![],
            },
        )
        .await
        .unwrap();
    let save = memoswish_protocol::CardSave {
        card: memoswish_content::slice_material(&deck.id, "Question :: Answer", 1).remove(0),
        publish: true,
        provenance: None,
        report_id: None,
    };
    let gate = Arc::new(Gate::new());
    server.services.limiter = gate.clone();
    let running = server.clone();
    let held = captured.clone();
    let call = json!({"jsonrpc":"2.0","id":81,"method":"tools/call","params":{"name":"card_save","arguments":save}});
    let pending = tokio::spawn(async move { running.handle_value(&held, call).await.unwrap() });
    // 到达限流屏障时，P3.12 已登记活动调用且首次凭据检查已通过。
    gate.reached().await;
    let inventory = server.services.auth.access_page(&root.access_token, AccessKind::Grants, "", 50).await.unwrap();
    assert_eq!(inventory.items[0].id, grant.id);
    assert_eq!(inventory.items[0].status, "active");
    assert!(
        server
            .services
            .auth
            .revoke_access(&root.access_token, AccessKind::Grants, Some(&tenant), &grant.id)
            .await
            .unwrap()
    );
    gate.release.add_permits(1);
    let result = pending.await.unwrap();
    assert!(result.get("error").is_some() || result["result"]["isError"] == true, "{result}");
    assert!(server.services.list_cards(&owner, Some(&deck.id), 10, 0).await.unwrap().is_empty());
    assert!(server.services.save_card(&captured, save).await.is_err());
    assert!(
        server
            .services
            .create_authored_deck(
                &captured,
                memoswish_content::NewDeck {
                    title: "Denied".into(),
                    description: String::new(),
                    language: "en".into(),
                    tags: vec![]
                }
            )
            .await
            .is_err()
    );
    let subsequent = server
        .handle_value(
            &captured,
            json!({"jsonrpc":"2.0","id":82,"method":"tools/call","params":{"name":"deck_list","arguments":{}}}),
        )
        .await
        .unwrap();
    assert!(subsequent.get("error").is_some() || subsequent["result"]["isError"] == true);
    assert!(repo.oauth_token(&access.hash).await.unwrap().is_none());
    assert!(!repo.oauth_rotate(&tenant, &refresh, &[OAuthToken { hash: new_id(), ..access }], 10).await.unwrap());
    assert_eq!(
        server.services.auth.access_page(&root.access_token, AccessKind::Grants, "", 50).await.unwrap().items[0].status,
        "revoked"
    );
    server.services.operations.close();
    server.services.operations.wait().await;
}
