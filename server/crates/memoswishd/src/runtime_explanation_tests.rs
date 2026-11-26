//! 真实传输、解释责任和核账在同一关闭期限内排空，期限后仍保留持久财务责任。
use super::*;
use memoswish_protocol::{ExplainDisposition, ExplainReconcileRequest, ExplainRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn state(endpoint: String, shutdown_secs: u64) -> (AppState, Principal, String, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("p23-drain-{}", memoswish_core::ids::new_id()));
    let cfg = Config {
        data_dir: root.clone(),
        seed_demo: false,
        privacy: memoswish_protocol::PrivacyPolicy {
            hosted: false,
            ..memoswish_protocol::examples::sample_privacy_policy()
        },
        ai: memoswish_content::AiExplainConfig {
            base_url: Some(endpoint),
            api_key: Some("P23_CREDENTIAL_SENTINEL".into()),
            budget: Some(crate::tests::explanation_test_policy()),
            ..Default::default()
        },
        object_store: crate::ObjectStoreConfig { put_shutdown_timeout_secs: shutdown_secs, ..Default::default() },
        ..Default::default()
    };
    let st = AppState::assemble(cfg).await.unwrap();
    let p = Principal::local_owner("single_user");
    let deck = st.services.import_deck_pack(&p, memoswish_protocol::examples::sample_deck_pack()).await.unwrap();
    let card = st.services.list_cards(&p, Some(&deck.id), 1, 0).await.unwrap()[0].id.clone();
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_ai", "provider-policy-v1", ""),
    ] {
        let current = st.services.auth.privacy_state(&p).await.unwrap();
        st.services
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
    (st, p, card, root)
}

async fn accept_request(listener: &tokio::net::TcpListener) -> tokio::net::TcpStream {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut raw = Vec::new();
    // 完整读取请求正文后再发响应，避免关闭 socket 时丢弃未读正文触发 reset。
    loop {
        let mut chunk = [0; 4096];
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        raw.extend_from_slice(&chunk[..n]);
        if let Some(end) = raw.windows(4).position(|v| v == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
            let length: usize =
                header.lines().find_map(|line| line.strip_prefix("content-length: ")).unwrap().parse().unwrap();
            if raw.len() >= end + 4 + length {
                return socket;
            }
        }
    }
}

async fn respond(socket: &mut tokio::net::TcpStream, usage: bool) {
    let body = if usage {
        serde_json::json!({"id":"chatcmpl-drain", "model":"gpt-4o-mini-2024-07-18", "service_tier":"default",
            "usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12},
            "choices":[{"finish_reason":"length","message":{"content":"broken"}}]})
        .to_string()
    } else {
        "{}".into()
    };
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
}

async fn in_flight_attempt(exhaust_deadline: bool) {
    let provider = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let budget = if exhaust_deadline { 1 } else { crate::ObjectStoreConfig::default().put_shutdown_timeout_secs };
    let (st, p, card, root) = state(format!("http://{}", provider.local_addr().unwrap()), budget).await;
    let daemon = Daemon::initialize_with(st.clone(), |_| async { Ok(()) }).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let transport = st.clone();
    // 直接驱动生产连接生命周期和 daemon 排空，隔离会取消尚未尝试请求的周期恢复扫描。
    // serve_http 包装器与扫描本身继续由既有运行时测试覆盖。
    let serving = tokio::spawn(async move {
        let stopping = transport.clone();
        let result = crate::lifecycle::serve(
            listener,
            crate::api::router(transport.clone()),
            async move {
                stopped.await.unwrap();
                stopping.health.lifecycle.drain();
                stopping.services.operations.close();
                stopping.services.auth.close_password_work();
            },
            transport.health.lifecycle.clone(),
        )
        .await;
        daemon.shutdown().await;
        result
    });
    let request = tokio::spawn(async move {
        reqwest::Client::new()
            .post(format!("http://{addr}/v1/cards/{card}/explain"))
            .json(&serde_json::json!({"request_id":"shutdown-attempt"}))
            .send()
            .await
    });
    let mut socket = accept_request(&provider).await;
    assert_eq!(
        st.services.explanation_operation(&p, "shutdown-attempt").await.unwrap().disposition,
        ExplainDisposition::Unresolved
    );
    if exhaust_deadline {
        tokio::time::pause();
    }
    stop.send(()).unwrap();
    st.health.lifecycle.draining().await;
    let deadline = st.health.lifecycle.drain();
    assert!(st.services.recover_explanations().is_err());
    assert!(
        st.services
            .reconcile_explanation_request(
                &p,
                "shutdown-attempt",
                &ExplainReconcileRequest {
                    input_tokens: Some(10),
                    output_tokens: Some(2),
                    not_charged_reference_sha256: None,
                }
            )
            .await
            .is_err(),
        "closed admission must also reject settlement work"
    );
    if exhaust_deadline {
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        serving.await.unwrap().unwrap();
        assert_eq!(st.health.lifecycle.drain(), deadline);
        tokio::time::resume();
        let receipt = st.services.explanation_operation(&p, "shutdown-attempt").await.unwrap();
        assert_eq!(receipt.disposition, ExplainDisposition::Unresolved);
        let accounting = receipt.accounting.unwrap();
        assert_eq!(accounting.attempts, 1);
        assert!(accounting.held_microcurrency > 0);
        assert_eq!(accounting.committed_microcurrency, 0);
        // HTTP 已回收，应用所有者仍可接收可信 usage 并提交结算。
        respond(&mut socket, true).await;
        st.services.operations.wait().await;
    } else {
        assert!(!serving.is_finished());
        respond(&mut socket, true).await;
        serving.await.unwrap().unwrap();
    }
    let _ = request.await;
    let receipt = st.services.explanation_operation(&p, "shutdown-attempt").await.unwrap();
    assert_eq!(receipt.disposition, ExplainDisposition::Settled);
    let accounting = receipt.accounting.unwrap();
    assert_eq!((accounting.attempts, accounting.held_microcurrency, accounting.committed_microcurrency), (1, 0, 2));
    // 新 tracker 模拟重启，原身份只读结算结果且绝不再发一次外部请求。
    let mut services = st.services.clone();
    services.operations = Default::default();
    let card = st.services.list_cards(&p, None, 1, 0).await.unwrap()[0].id.clone();
    let replay = services
        .explain_card(&p, &card, &ExplainRequest { request_id: Some("shutdown-attempt".into()), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(replay.operation.unwrap().disposition, ExplainDisposition::Settled);
    tokio::select! { biased; _ = provider.accept() => panic!("shutdown caused a paid retry"), _ = tokio::task::yield_now() => {} }
    crate::runtime::cleanup_test_app(root, &[&st]).await;
}

#[tokio::test]
async fn explanation_attempt_drains_and_settles_before_shared_deadline() {
    in_flight_attempt(false).await;
}

#[tokio::test]
async fn explanation_attempt_retains_responsibility_after_http_deadline() {
    in_flight_attempt(true).await;
}

#[tokio::test]
async fn detached_manual_settlement_survives_shutdown_and_database_wait() {
    let provider = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (st, p, card, root) = state(format!("http://{}", provider.local_addr().unwrap()), 1).await;
    let daemon = Daemon::initialize_with(st.clone(), |_| async { Ok(()) }).await.unwrap();
    let services = st.services.clone();
    let principal = p.clone();
    let caller = tokio::spawn(async move {
        services
            .explain_card(
                &principal,
                &card,
                &ExplainRequest { request_id: Some("manual-drain".into()), ..Default::default() },
            )
            .await
    });
    respond(&mut accept_request(&provider).await, false).await;
    assert_eq!(caller.await.unwrap().unwrap().operation.unwrap().disposition, ExplainDisposition::Unresolved);
    // 使用真实 SQLite writer 阻塞核账事务，不增加生产 hook。
    let db = sqlx::SqlitePool::connect(&st.config.database_url()).await.unwrap();
    let mut writer = db.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *writer).await.unwrap();
    let services = st.services.clone();
    let principal = p.clone();
    let (entered, observed) = oneshot::channel();
    let caller = tokio::spawn(async move {
        let evidence = ExplainReconcileRequest {
            input_tokens: Some(10),
            output_tokens: Some(2),
            not_charged_reference_sha256: None,
        };
        let reconcile = services.reconcile_explanation_request(&principal, "manual-drain", &evidence);
        tokio::pin!(reconcile);
        let mut entered = Some(entered);
        std::future::poll_fn(|cx| {
            let result = reconcile.as_mut().poll(cx);
            if result.is_pending()
                && let Some(entered) = entered.take()
            {
                entered.send(()).unwrap();
            }
            result
        })
        .await
    });
    observed.await.unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    tokio::time::pause();
    let deadline = st.health.lifecycle.drain();
    daemon.shutdown().await;
    assert!(tokio::time::Instant::now() >= deadline);
    assert_eq!(st.health.lifecycle.drain(), deadline);
    tokio::time::resume();
    // 公开查询也需要 writer fence；锁仍被占用时用只读 SQL 检查持久事实。
    let disposition: String =
        sqlx::query_scalar("SELECT state FROM explanation_operations").fetch_one(&db).await.unwrap();
    assert_eq!(disposition, "unresolved");
    let held: i64 = sqlx::query_scalar("SELECT SUM(held) FROM explanation_accounts").fetch_one(&db).await.unwrap();
    assert!(held > 0);
    sqlx::query("ROLLBACK").execute(&mut *writer).await.unwrap();
    st.services.operations.wait().await;
    let receipt = st.services.explanation_operation(&p, "manual-drain").await.unwrap();
    assert_eq!(receipt.disposition, ExplainDisposition::Settled);
    let accounting = receipt.accounting.unwrap();
    assert_eq!((accounting.held_microcurrency, accounting.committed_microcurrency), (0, 2));
    drop(writer);
    db.close().await;
    crate::runtime::cleanup_test_app(root, &[&st]).await;
}

#[tokio::test]
async fn optional_explanation_provider_failure_does_not_change_readiness() {
    use tower::ServiceExt;
    let provider = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", provider.local_addr().unwrap());
    drop(provider);
    let (st, p, card, root) = state(endpoint, 1).await;
    let daemon = Daemon::initialize_with(st.clone(), |_| async { Ok(()) }).await.unwrap();
    for failed in [false, true] {
        if failed {
            let result = st
                .services
                .explain_card(
                    &p,
                    &card,
                    &ExplainRequest { request_id: Some("optional-provider-failed".into()), ..Default::default() },
                )
                .await
                .unwrap();
            assert_eq!(result.provider, "builtin-heuristic");
            assert_eq!(result.operation.unwrap().disposition, ExplainDisposition::Unresolved);
        }
        let response = st
            .health
            .router()
            .oneshot(axum::http::Request::get("/readyz").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(st.health.lifecycle.phase(), crate::lifecycle::Phase::Running);
    }
    daemon.shutdown().await;
    crate::runtime::cleanup_test_app(root, &[&st]).await;
}
