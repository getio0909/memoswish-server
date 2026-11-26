use super::*;
use memoswish_protocol::examples;

#[tokio::test]
async fn heuristic_explains_rich_and_term_cards() {
    let cfg = AiExplainConfig::default();
    let card = examples::sample_card();
    let exp = explain_transport_test(&card, &ExplainRequest::default(), &cfg).await.unwrap();
    assert_eq!(exp.card_id, card.id);
    assert_eq!(exp.provider, BUILTIN_PROVIDER);
    assert!(exp.summary.contains("serendipity"));
    assert!(exp.key_points.len() >= 2);
    assert!(!exp.analogy.is_empty());
    assert!(exp.follow_up_questions.len() >= 2);

    let rich = examples::sample_rich_card();
    let req =
        ExplainRequest {
            request_id: None, question: Some("为什么光速是平方？".into()), locale: Some("zh-CN".into())
        };
    let exp_rich = explain_transport_test(&rich, &req, &cfg).await.unwrap();
    assert!(exp_rich.summary.contains("为什么光速是平方"));
    assert!(exp_rich.key_points.iter().any(|p| p.contains("E = mc^2")));
    assert!(exp_rich.key_points.iter().any(|p| p.contains("physics")));
}

#[tokio::test]
async fn production_local_explanation_rejects_oversized_fixed_metadata() {
    let mut card = examples::sample_card();
    card.id = "x".repeat(20_000);
    let request = ExplainRequest::default();
    validate_input(&card, &request).unwrap();
    assert!(serde_json::to_vec(&heuristic_explain(&card, &request)).unwrap().len() > MAX_RESULT_BYTES);
    assert!(matches!(explain_card(&card, &request, &AiExplainConfig::default()).await, Err(CoreError::Invalid(_))));
}

#[tokio::test]
async fn falls_back_gracefully_when_external_llm_unreachable() {
    let cfg = AiExplainConfig {
        base_url: Some("http://127.0.0.1:9".into()),
        api_key: Some("test-key".into()),
        model: "gpt-4o-mini".into(),
        reasoning_effort: None,
        budget: None,
    };
    let card = examples::sample_card();
    let exp = explain_transport_test(
        &card,
        &ExplainRequest { request_id: None, question: None, locale: Some("en-US".into()) },
        &cfg,
    )
    .await
    .unwrap();
    assert_eq!(exp.provider, BUILTIN_PROVIDER);
    assert!(exp.summary.contains("serendipity"));
}

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

// 手写最小回环 HTTP 夹具以控制原始报文，不引入额外测试依赖。
struct MockProvider {
    url: String,
    request: oneshot::Receiver<Vec<u8>>,
    response: oneshot::Sender<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
}

async fn mock_provider() -> MockProvider {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (request_tx, request) = oneshot::channel();
    let (response, response_rx) = oneshot::channel::<Vec<u8>>();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut raw = Vec::new();
        let header_end = loop {
            let mut chunk = [0; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            raw.extend_from_slice(&chunk[..n]);
            if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let headers = String::from_utf8_lossy(&raw[..header_end]).to_ascii_lowercase();
        let length: usize =
            headers.lines().find_map(|line| line.strip_prefix("content-length: ")).unwrap().parse().unwrap();
        while raw.len() < header_end + length {
            let mut chunk = [0; 4096];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            raw.extend_from_slice(&chunk[..n]);
        }
        request_tx.send(raw).unwrap();
        if let Ok(response) = response_rx.await {
            // 调用方取消或超时后，关闭连接属于预期路径。
            let _ = stream.write_all(&response).await;
        }
    });
    MockProvider { url, request, response, task }
}

fn external_config(url: &str) -> AiExplainConfig {
    AiExplainConfig { base_url: Some(url.into()), api_key: Some("synthetic-key-sentinel".into()), ..Default::default() }
}

fn payload() -> serde_json::Value {
    json!({"summary": "Intuition", "key_points": ["First", "Second"], "analogy": "Analogy", "follow_up_questions": ["Why?"]})
}

fn envelope(payload: serde_json::Value) -> serde_json::Value {
    json!({"choices": [{"finish_reason": "stop", "message": {"content": payload.to_string()}}]})
}

fn http_response(body: &[u8]) -> Vec<u8> {
    let mut raw =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    raw.extend_from_slice(body);
    raw
}

fn multi_block_card(text: &str) -> Card {
    let mut card: Card = serde_json::from_str(include_str!("../../../../protocol/fixtures/card.json")).unwrap();
    card.front.title = "Topic".into();
    card.front.blocks = vec![ContentBlock::Text { text: text.into() }; 10];
    card.back.title = "Definition".into();
    card.back.blocks.clear();
    crate::validate::validate_card(&card).unwrap();
    validate_input(&card, &ExplainRequest::default()).unwrap();
    card
}

fn assert_bounded_heuristic(card: &Card, result: &CardExplanation) {
    assert_eq!(result.card_id, card.id);
    assert_eq!(result.provider, BUILTIN_PROVIDER);
    assert!(result.summary.contains("Topic"));
    assert!(result.summary.contains("Definition"));
    assert!(result.key_points.len() >= 2);
    assert!(result.key_points.len() <= MAX_KEY_POINTS);
    assert!(result.follow_up_questions.len() >= 2);
    assert!(result.follow_up_questions.len() <= MAX_FOLLOW_UPS);
    for field in
        [&result.summary, &result.analogy].into_iter().chain(&result.key_points).chain(&result.follow_up_questions)
    {
        assert!(!field.trim().is_empty());
        assert!(field.len() <= MAX_FIELD_BYTES);
    }
    let bytes = serde_json::to_vec(result).unwrap();
    assert!(bytes.len() <= MAX_RESULT_BYTES, "{} serialized bytes", bytes.len());
    assert_eq!(serde_json::from_slice::<CardExplanation>(&bytes).unwrap(), *result);
}

#[tokio::test]
async fn multi_block_heuristic_fits_total_budget_without_ai() {
    for text in ["x".repeat(2000), "x".repeat(2048)] {
        let card = multi_block_card(&text);
        let result =
            explain_transport_test(&card, &ExplainRequest::default(), &AiExplainConfig::default()).await.unwrap();
        assert_bounded_heuristic(&card, &result);
        assert!(result.key_points.iter().any(|point| point.contains("xxxxxxxx")));
    }
}

#[tokio::test]
async fn multi_block_heuristic_fits_total_budget_after_provider_failure() {
    let card = multi_block_card(&"x".repeat(2048));
    let mock = mock_provider().await;
    let cfg = external_config(&mock.url);
    let caller_card = card.clone();
    let caller =
        tokio::spawn(async move { explain_transport_test(&caller_card, &ExplainRequest::default(), &cfg).await });
    mock.request.await.unwrap();
    mock.response.send(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec()).unwrap();
    assert_bounded_heuristic(&card, &caller.await.unwrap().unwrap());
    mock.task.await.unwrap();
}

#[tokio::test]
async fn multi_block_heuristic_fits_total_budget_after_capacity_exhaustion() {
    let card = multi_block_card(&"x".repeat(2048));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let cfg = external_config(&format!("http://{}", listener.local_addr().unwrap()));
    // 注入独占的同类传输，避免测试占满全局槽位而干扰并行调用。
    let transport = OnceLock::new();
    assert!(transport.set(Ok(ExplainTransport::new(MAX_CONCURRENT, REQUEST_TIMEOUT).unwrap())).is_ok());
    let slots = &transport.get().unwrap().as_ref().unwrap().slots;
    let permit = slots.try_acquire_many(MAX_CONCURRENT as u32).unwrap();
    assert_eq!(slots.available_permits(), 0);
    let result = explain_with_transport(&card, &ExplainRequest::default(), &cfg, &transport).await.unwrap();
    assert_bounded_heuristic(&card, &result);
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(slots.available_permits(), 0);
    drop(permit);
    assert_eq!(slots.available_permits(), MAX_CONCURRENT);
}

#[tokio::test]
async fn multi_block_heuristic_budget_accounts_for_json_escaping_and_utf8() {
    let card = multi_block_card(&"学😀\"\\\u{0001}\n".repeat(150));
    for locale in ["zh-CN", "en-US"] {
        let req = ExplainRequest {
            request_id: None,
            question: Some("学😀\"\\\u{0001}\n".repeat(4)),
            locale: Some(locale.into()),
        };
        let result = explain_card(&card, &req, &AiExplainConfig::default()).await.unwrap();
        assert_bounded_heuristic(&card, &result);
        assert!(result.key_points.iter().any(|point| point.contains("学😀\"\\\u{0001}\n")));
        let mut repeated = heuristic_explain(&card, &req);
        repeated.generated_at = result.generated_at;
        assert_eq!(repeated, result);
    }
}

#[test]
fn utf8_input_limits_and_serialized_card_boundary() {
    let mut card = examples::sample_card();
    let mut request =
        ExplainRequest { request_id: None, question: Some("学".repeat(MAX_QUESTION_BYTES / 3) + "a"), locale: None };
    assert_eq!(request.question.as_ref().unwrap().len(), MAX_QUESTION_BYTES);
    validate_input(&card, &request).unwrap();
    request.question.as_mut().unwrap().push('a');
    assert!(validate_input(&card, &request).is_err());
    request = ExplainRequest::default();
    request.locale = Some("a".repeat(MAX_LOCALE_BYTES));
    validate_input(&card, &request).unwrap();
    request.locale.as_mut().unwrap().push('a');
    assert!(validate_input(&card, &request).is_err());
    for invalid in ["", "zh_CN", "en\nsecret", "学"] {
        request.locale = Some(invalid.into());
        assert!(validate_input(&card, &request).is_err());
    }
    request = ExplainRequest::default();
    card.front.title.clear();
    let baseline = serde_json::to_vec(&card).unwrap().len();
    card.front.title = "a".repeat(MAX_CARD_BYTES - baseline);
    assert_eq!(serde_json::to_vec(&card).unwrap().len(), MAX_CARD_BYTES);
    validate_input(&card, &request).unwrap();
    card.front.title.push('a');
    assert!(validate_input(&card, &request).is_err());
    assert!(bounded_json(&"\n".repeat(MAX_CARD_BYTES), MAX_CARD_BYTES).is_err());
    assert_eq!(bounded_json(&"a".repeat(8), 10).unwrap().len(), 10);
    assert!(bounded_json(&"a".repeat(9), 10).is_err());
}

#[test]
fn response_fields_arrays_and_total_limits() {
    let card = examples::sample_card();
    let cfg = external_config("http://127.0.0.1:9");
    let mut empty_points = payload();
    empty_points["key_points"] = json!([]);
    let result = parse_response(&card, &cfg, &serde_json::to_vec(&envelope(empty_points)).unwrap()).unwrap();
    assert!(!result.key_points.is_empty());
    let mut valid = payload();
    valid["summary"] = json!("学".repeat(MAX_FIELD_BYTES / 3) + "aa");
    valid["key_points"] = json!(vec!["point"; MAX_KEY_POINTS]);
    valid["follow_up_questions"] = json!(vec!["question"; MAX_FOLLOW_UPS]);
    assert!(parse_response(&card, &cfg, &serde_json::to_vec(&envelope(valid.clone())).unwrap()).is_ok());
    let mut invalid = valid.clone();
    invalid["summary"] = json!(valid["summary"].as_str().unwrap().to_string() + "a");
    assert!(parse_response(&card, &cfg, &serde_json::to_vec(&envelope(invalid)).unwrap()).is_err());
    for (field, value) in [
        ("summary", json!(" ")),
        ("analogy", json!("")),
        ("key_points", json!(vec!["point"; MAX_KEY_POINTS + 1])),
        ("follow_up_questions", json!(vec!["question"; MAX_FOLLOW_UPS + 1])),
        ("key_points", json!([""])),
    ] {
        let mut invalid = payload();
        invalid[field] = value;
        assert!(parse_response(&card, &cfg, &serde_json::to_vec(&envelope(invalid)).unwrap()).is_err(), "{field}");
    }
    let mut oversized = payload();
    oversized["key_points"] = json!(vec!["x".repeat(MAX_FIELD_BYTES); MAX_KEY_POINTS]);
    assert!(parse_response(&card, &cfg, &serde_json::to_vec(&envelope(oversized)).unwrap()).is_err());
    for body in [
        b"{".to_vec(),
        b"{}".to_vec(),
        serde_json::to_vec(
            &json!({"choices": [{"finish_reason": "length", "message": {"content": payload().to_string()}}]}),
        )
        .unwrap(),
        serde_json::to_vec(
            &json!({"choices": [{"finish_reason": "stop", "message": {"content": "synthetic-body-sentinel"}}]}),
        )
        .unwrap(),
    ] {
        let error = parse_response(&card, &cfg, &body).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("synthetic-body-sentinel"));
    }
}

#[test]
fn endpoint_profiles_and_secret_redaction() {
    let mut cfg = external_config("https://example.com");
    for (base, path) in [
        ("https://api.openai.com", "/v1/chat/completions"),
        ("https://api.openai.com/v1/", "/v1/chat/completions"),
        ("http://127.0.0.1:1234/custom/chat/completions", "/custom/chat/completions"),
        ("http://[::1]:1234", "/v1/chat/completions"),
    ] {
        cfg.base_url = Some(base.into());
        assert_eq!(provider_url(&cfg).unwrap().path(), path);
    }
    for base in [
        "https://user:synthetic-url-sentinel@example.com",
        "https://example.com?key=synthetic-query-sentinel",
        "https://example.com#synthetic-fragment-sentinel",
        "http://example.com",
        "ftp://example.com",
        "synthetic-invalid-url",
    ] {
        cfg.base_url = Some(base.into());
        assert_eq!(provider_url(&cfg).unwrap_err(), "invalid explanation endpoint");
        let diagnostic = format!("{cfg:?} {}", serde_json::to_string(&cfg.redacted()).unwrap());
        assert!(!diagnostic.contains("synthetic"));
    }
    cfg.base_url = Some("http://127.0.0.1:9".into());
    for base in ["https://example.com", "https://api.openai.com:444", "https://api.openai.com/custom"] {
        cfg.base_url = Some(base.into());
        assert_eq!(provider_url(&cfg).unwrap_err(), "unsupported explanation provider profile");
    }
    cfg.base_url = Some("https://api.openai.com/v1".into());
    cfg.model = "gpt-4o-mini-2024-07-18".into();
    assert!(provider_url(&cfg).is_ok());
    cfg.model = "synthetic-model-sentinel".into();
    assert!(provider_url(&cfg).is_ok());
    assert!(!format!("{cfg:?} {}", serde_json::to_string(&cfg.redacted()).unwrap()).contains("synthetic"));
    cfg.model = " ".into();
    assert_eq!(provider_url(&cfg).unwrap_err(), "invalid explanation model profile");
    let old: AiExplainConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(old, AiExplainConfig::default());
}

#[tokio::test]
async fn successful_public_call_has_explicit_budgets_and_minimal_prompt() {
    let mock = mock_provider().await;
    let mut card = examples::sample_rich_card();
    card.attributes.insert("synthetic-metadata-sentinel".into(), json!("private"));
    card.front.blocks.push(ContentBlock::Link {
        title: Some("Reference".into()),
        url: "https://example.com/synthetic-link-sentinel".into(),
    });
    card.front.blocks.push(ContentBlock::Image {
        alt: "Diagram".into(),
        asset: memoswish_protocol::AssetRef {
            key: "synthetic-asset-sentinel".into(),
            url: "https://example.com/synthetic-asset-sentinel".into(),
            mime: "image/png".into(),
            bytes: 1,
            sha256: "0".repeat(64),
        },
    });
    let cfg = external_config(&mock.url);
    let task = tokio::spawn(async move { explain_transport_test(&card, &ExplainRequest::default(), &cfg).await });
    let raw = mock.request.await.unwrap();
    let start = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let body: serde_json::Value = serde_json::from_slice(&raw[start..]).unwrap();
    assert_eq!(body["max_completion_tokens"], MAX_COMPLETION_TOKENS);
    assert_eq!(body["store"], false);
    assert_eq!(body["stream"], false);
    assert_eq!(body["n"], 1);
    let prompt = body["messages"][1]["content"].as_str().unwrap();
    assert!(prompt.contains("E = mc^2"));
    assert!(prompt.contains("Diagram"));
    assert!(!prompt.contains("synthetic-"));
    mock.response.send(http_response(&serde_json::to_vec(&envelope(payload())).unwrap())).unwrap();
    let result = task.await.unwrap().unwrap();
    assert_eq!(result.provider, "openai:gpt-4o-mini");
    assert_eq!(result.summary, "Intuition");
    mock.task.await.unwrap();
}

async fn transport_response(raw: Vec<u8>) -> Result<CardExplanation, &'static str> {
    let mock = mock_provider().await;
    let transport = ExplainTransport::new(1, REQUEST_TIMEOUT).unwrap();
    let cfg = external_config(&mock.url);
    let task =
        tokio::spawn(async move { transport.call(&examples::sample_card(), &ExplainRequest::default(), &cfg).await });
    mock.request.await.unwrap();
    mock.response.send(raw).unwrap();
    let result = task.await.unwrap();
    mock.task.await.unwrap();
    result
}

#[tokio::test]
async fn hostile_http_responses_are_bounded_without_retry_or_redirect() {
    let valid = serde_json::to_vec(&envelope(payload())).unwrap();
    let mut exact = valid.clone();
    exact.resize(MAX_RESPONSE_BYTES, b' ');
    assert!(transport_response(http_response(&exact)).await.is_ok());
    exact.push(b' ');
    assert_eq!(transport_response(http_response(&exact)).await.unwrap_err(), "explanation response exceeds byte limit");
    let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_RESPONSE_BYTES + 1).into_bytes();
    assert_eq!(transport_response(raw).await.unwrap_err(), "explanation response exceeds byte limit");
    let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    raw.extend_from_slice(format!("{:x}\r\n", MAX_RESPONSE_BYTES + 1).as_bytes());
    raw.extend_from_slice(&vec![b' '; MAX_RESPONSE_BYTES + 1]);
    raw.extend_from_slice(b"\r\n0\r\n\r\n");
    assert_eq!(transport_response(raw).await.unwrap_err(), "explanation response exceeds byte limit");
    let mut raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
    raw.extend_from_slice(&vec![b' '; MAX_RESPONSE_BYTES + 1]);
    assert_eq!(transport_response(raw).await.unwrap_err(), "explanation response exceeds byte limit");
    let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", valid.len() + 1).into_bytes();
    raw.extend_from_slice(&valid);
    assert_eq!(transport_response(raw).await.unwrap_err(), "explanation response read failed");
    for raw in [
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/synthetic-redirect-sentinel\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
        b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 23\r\n\r\nsynthetic-body-sentinel!".to_vec(),
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ] {
        assert_eq!(transport_response(raw).await.unwrap_err(), "explanation provider returned unsuccessful status");
    }
}

#[tokio::test]
async fn saturated_admission_cancellation_and_timeout_release_slots() {
    let mock = mock_provider().await;
    let transport = Arc::new(ExplainTransport::new(1, REQUEST_TIMEOUT).unwrap());
    let cfg = external_config(&mock.url);
    let first_transport = transport.clone();
    let first_cfg = cfg.clone();
    let task = tokio::spawn(async move {
        first_transport.call(&examples::sample_card(), &ExplainRequest::default(), &first_cfg).await
    });
    mock.request.await.unwrap();
    assert_eq!(transport.slots.available_permits(), 0);
    assert_eq!(
        transport.call(&examples::sample_card(), &ExplainRequest::default(), &cfg).await.unwrap_err(),
        "explanation capacity exhausted"
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(transport.slots.available_permits(), 1);
    drop(mock.response);
    mock.task.await.unwrap();

    let mock = mock_provider().await;
    let transport = Arc::new(ExplainTransport::new(1, Duration::from_millis(100)).unwrap());
    let cfg = external_config(&mock.url);
    let worker_transport = transport.clone();
    let task =
        tokio::spawn(
            async move { worker_transport.call(&examples::sample_card(), &ExplainRequest::default(), &cfg).await },
        );
    mock.request.await.unwrap();
    assert_eq!(task.await.unwrap().unwrap_err(), "explanation request failed");
    assert_eq!(transport.slots.available_permits(), 1);
    drop(mock.response);
    mock.task.await.unwrap();
}

#[tokio::test]
async fn invalid_inputs_prevent_network_and_unknown_profiles_keep_heuristic() {
    let card = examples::sample_card();
    let mut cfg = external_config("http://127.0.0.1:9");
    let req = ExplainRequest { request_id: None, question: Some("x".repeat(MAX_QUESTION_BYTES + 1)), locale: None };
    assert!(explain_transport_test(&card, &req, &cfg).await.is_err());
    cfg.model = "synthetic-model-sentinel".into();
    let result = explain_transport_test(&card, &ExplainRequest::default(), &cfg).await.unwrap();
    assert_eq!(result.provider, BUILTIN_PROVIDER);
    assert!(!serde_json::to_string(&result).unwrap().contains("synthetic"));
    let mut large = card.clone();
    large.back.title = "学".repeat(2000);
    let result = explain_transport_test(&large, &ExplainRequest::default(), &AiExplainConfig::default()).await.unwrap();
    assert!(result.summary.len() <= MAX_FIELD_BYTES);
    assert!(result.analogy.len() <= MAX_FIELD_BYTES);
    assert!(serde_json::to_vec(&result).unwrap().len() <= MAX_RESULT_BYTES);
}

#[derive(Clone, Default)]
struct CapturedDiagnostics(Arc<std::sync::Mutex<String>>);

impl tracing::field::Visit for CapturedDiagnostics {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        write!(self.0.lock().unwrap(), "{}={value:?} ", field.name()).unwrap();
    }
}

impl tracing::Subscriber for CapturedDiagnostics {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "memoswish::content::explain"
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target() == "memoswish::content::explain" {
            event.record(&mut self.clone());
        }
    }
}

#[tokio::test]
async fn public_fallback_and_diagnostics_never_expose_provider_secrets() {
    let captured = CapturedDiagnostics::default();
    tracing::subscriber::set_global_default(captured.clone()).unwrap();
    let mock = mock_provider().await;
    let cfg = external_config(&mock.url);
    let task = tokio::spawn(async move {
        explain_transport_test(&examples::sample_card(), &ExplainRequest::default(), &cfg).await
    });
    mock.request.await.unwrap();
    mock.response
        .send(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 23\r\n\r\nsynthetic-body-sentinel!".to_vec())
        .unwrap();
    let result = task.await.unwrap().unwrap();
    assert_eq!(result.provider, BUILTIN_PROVIDER);
    assert!(!serde_json::to_string(&result).unwrap().contains("synthetic"));
    mock.task.await.unwrap();
    for url in [
        "https://user:synthetic-password-sentinel@api.openai.com",
        "https://api.openai.com?key=synthetic-query-sentinel",
        "synthetic-invalid-url-sentinel",
    ] {
        let result =
            explain_transport_test(&examples::sample_card(), &ExplainRequest::default(), &external_config(url))
                .await
                .unwrap();
        assert_eq!(result.provider, BUILTIN_PROVIDER);
    }
    let logs = captured.0.lock().unwrap();
    assert!(logs.contains("external explanation failed"));
    assert!(logs.contains("explanation provider returned unsuccessful status"), "{logs}");
    assert!(!logs.contains("synthetic"));
    assert!(!logs.contains("127.0.0.1"));
}

#[tokio::test]
async fn content_service_preserves_tenant_lookup_before_external_execution() {
    use memoswish_core::repo::{Repository, TenantRecord};
    let repo: Arc<dyn Repository> = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
    for tenant in ["local", "other"] {
        repo.upsert_tenant(&TenantRecord {
            id: tenant.into(),
            name: tenant.into(),
            plan: "self_hosted".into(),
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    }
    let deck = examples::sample_deck();
    let card = examples::sample_card();
    repo.insert_deck("local", &deck).await.unwrap();
    repo.insert_card("local", &card).await.unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let cfg = external_config(&format!("http://{}", listener.local_addr().unwrap()));
    let service = crate::ContentService::new(repo).with_ai_config(cfg);
    let mut outsider = memoswish_core::Principal::local_owner("test");
    outsider.tenant_id = "other".into();
    let error = service.explain_card(&outsider, &card.id, &ExplainRequest::default()).await.unwrap_err();
    assert!(matches!(error, CoreError::NotFound(_)));
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    let request = ExplainRequest { request_id: None, question: Some("x".repeat(MAX_QUESTION_BYTES + 1)), locale: None };
    let error =
        service.explain_card(&memoswish_core::Principal::local_owner("test"), &card.id, &request).await.unwrap_err();
    assert!(error.to_string().contains("question exceeds byte limit"));
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    let mut restricted = memoswish_core::Principal::local_owner("test");
    restricted.scopes = Some(vec!["content:write".into()]);
    assert!(matches!(
        service.explain_card(&restricted, &card.id, &ExplainRequest::default()).await,
        Err(CoreError::Forbidden(_))
    ));
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    let blocked = service.clone().with_external_ai_execution(false);
    let owner = memoswish_core::Principal::local_owner("test");
    assert!(matches!(
        blocked.explain_card(&owner, &card.id, &ExplainRequest::default()).await,
        Err(CoreError::Unavailable(_))
    ));
    assert!(matches!(
        blocked.explain_card(&outsider, &card.id, &ExplainRequest::default()).await,
        Err(CoreError::NotFound(_))
    ));
    assert!(matches!(
        blocked.explain_card(&restricted, &card.id, &ExplainRequest::default()).await,
        Err(CoreError::Forbidden(_))
    ));
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    let builtin = blocked.with_ai_config(AiExplainConfig::default());
    assert_eq!(
        builtin.explain_card(&owner, &card.id, &ExplainRequest::default()).await.unwrap().provider,
        BUILTIN_PROVIDER
    );
    let mut escaped = card;
    escaped.front.title = "\"".repeat(15_000);
    let req = ExplainRequest { request_id: None, question: Some("\"".repeat(MAX_QUESTION_BYTES)), locale: None };
    validate_input(&escaped, &req).unwrap();
    assert!(request_body(&escaped, &req, &AiExplainConfig::default()).is_err());
}

#[tokio::test]
async fn timeout_includes_body_read_and_releases_capacity() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cfg = external_config(&format!("http://{}", listener.local_addr().unwrap()));
    let (headers_tx, headers_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{").await.unwrap();
        headers_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let transport = Arc::new(ExplainTransport::new(1, Duration::from_millis(100)).unwrap());
    let caller = transport.clone();
    let task =
        tokio::spawn(async move { caller.call(&examples::sample_card(), &ExplainRequest::default(), &cfg).await });
    headers_rx.await.unwrap();
    assert_eq!(task.await.unwrap().unwrap_err(), "explanation response read failed");
    assert_eq!(transport.slots.available_permits(), 1);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn privacy_withdrawal_keeps_unadmitted_content_entry_local() {
    use memoswish_core::{
        Principal, Role,
        repo::{Repository, TenantRecord, UserRecord},
    };
    let repo: Arc<dyn Repository> = Arc::new(memoswish_storage::sqlite::SqliteRepository::in_memory().await.unwrap());
    let p = Principal::local_owner("single_user");
    repo.upsert_tenant(&TenantRecord {
        id: p.tenant_id.clone(),
        name: "Privacy".into(),
        plan: "self_hosted".into(),
        created_at: Utc::now(),
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: p.user_id.clone(),
        tenant_id: p.tenant_id.clone(),
        email: "privacy@example.invalid".into(),
        display_name: "Privacy".into(),
        password_hash: String::new(),
        role: Role::Owner,
        created_at: Utc::now(),
    })
    .await
    .unwrap();
    let policy = examples::sample_privacy_policy();
    repo.privacy_install_policy(&policy).await.unwrap();
    let mut state = repo.privacy_state(&p.tenant_id, &p).await.unwrap();
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_ai", "provider-policy-v1", ""),
    ] {
        state = repo
            .privacy_update(
                &p.tenant_id,
                &p,
                &policy,
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
    repo.insert_deck(&p.tenant_id, &examples::sample_deck()).await.unwrap();
    let card = examples::sample_card();
    repo.insert_card(&p.tenant_id, &card).await.unwrap();
    let mock = mock_provider().await;
    let svc = crate::ContentService::new(repo.clone())
        .with_ai_config(external_config(&mock.url))
        .with_privacy_policy(policy.clone());
    assert_eq!(svc.explain_card(&p, &card.id, &ExplainRequest::default()).await.unwrap().provider, BUILTIN_PROVIDER);
    repo.privacy_update(
        &p.tenant_id,
        &p,
        &policy,
        &memoswish_protocol::PrivacyUpdate {
            expected_revision: state.revision,
            kind: "external_ai".into(),
            version: "provider-policy-v1".into(),
            decision: false,
            value: String::new(),
        },
    )
    .await
    .unwrap();
    assert_eq!(svc.explain_card(&p, &card.id, &ExplainRequest::default()).await.unwrap().provider, BUILTIN_PROVIDER);
    mock.task.abort();
    // 撤回之后的新请求不建立任何提供者连接，本地启发式仍可单独使用。
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let svc = crate::ContentService::new(repo)
        .with_ai_config(external_config(&format!("http://{}", listener.local_addr().unwrap())))
        .with_privacy_policy(policy);
    assert_eq!(svc.explain_card(&p, &card.id, &ExplainRequest::default()).await.unwrap().provider, BUILTIN_PROVIDER);
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(
        explain_card(&card, &ExplainRequest::default(), &AiExplainConfig::default()).await.unwrap().provider,
        BUILTIN_PROVIDER
    );
}

#[test]
fn usage_is_validated_independently_and_never_defaults_missing_values_to_zero() {
    let cfg = AiExplainConfig::default();
    let good = serde_json::json!({"id":"chatcmpl-test","model":"gpt-4o-mini-2024-07-18","service_tier":"default","usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30},"choices":[{"finish_reason":"length","message":{"content":"{broken"}}]});
    let raw = serde_json::to_vec(&good).unwrap();
    assert_eq!(parse_usage(&cfg, &raw).unwrap().input_tokens, 20);
    assert!(parse_response(&examples::sample_card(), &cfg, &raw).is_err());
    for change in ["missing", "negative", "fraction", "inconsistent", "model", "tier", "identifier", "overflow"] {
        let mut value = good.clone();
        match change {
            "missing" => {
                value.as_object_mut().unwrap().remove("usage");
            }
            "negative" => value["usage"]["prompt_tokens"] = (-1).into(),
            "fraction" => value["usage"]["completion_tokens"] = 0.5.into(),
            "inconsistent" => value["usage"]["total_tokens"] = 31.into(),
            "model" => value["model"] = "unknown".into(),
            "tier" => value["service_tier"] = "priority".into(),
            "identifier" => value["id"] = "s".repeat(129).into(),
            _ => {
                value["usage"]["prompt_tokens"] = i64::MAX.into();
                value["usage"]["completion_tokens"] = 1.into();
            }
        }
        assert!(parse_usage(&cfg, &serde_json::to_vec(&value).unwrap()).is_none(), "{change}");
    }
    let mut over = good;
    over["usage"] = serde_json::json!({"prompt_tokens":128001,"completion_tokens":1025,"total_tokens":129026});
    assert!(
        parse_usage(&cfg, &serde_json::to_vec(&over).unwrap()).is_some(),
        "actual overrun must reach accounting, never clamp"
    );
}

#[tokio::test]
async fn configured_models_and_optional_effort_reach_the_fake_provider() {
    for (model, effort) in [
        (DEFAULT_AI_MODEL, None),
        (DEFAULT_AI_MODEL, Some(ReasoningEffort::Low)),
        ("gpt-4o-mini-2024-07-18", None),
        ("gpt-6-luna", None),
        ("gpt-6-luna", Some(ReasoningEffort::None)),
        ("gpt-6-luna", Some(ReasoningEffort::Low)),
        ("operator/custom-model", Some(ReasoningEffort::Minimal)),
        ("operator/custom-model", Some(ReasoningEffort::Medium)),
        ("operator/custom-model", Some(ReasoningEffort::High)),
    ] {
        let mock = mock_provider().await;
        let mut cfg = external_config(&mock.url);
        cfg.model = model.into();
        cfg.reasoning_effort = effort;
        assert!(external_profile_supported(&cfg));
        let task = tokio::spawn(async move {
            execute_admitted_explanation(&examples::sample_card(), &ExplainRequest::default(), &cfg, "ai1-test").await
        });
        let raw = mock.request.await.unwrap();
        let start = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let body: serde_json::Value = serde_json::from_slice(&raw[start..]).unwrap();
        assert_eq!(body["model"], model);
        assert_eq!(body.get("reasoning_effort"), effort.map(|v| json!(v)).as_ref());
        if effort.is_none() && matches!(model, DEFAULT_AI_MODEL | "gpt-4o-mini-2024-07-18") {
            assert_eq!(body["temperature"], 0.3);
        } else {
            assert!(body.get("temperature").is_none());
        }
        assert_eq!(body["max_completion_tokens"], MAX_COMPLETION_TOKENS);
        assert!(body.get("max_tokens").is_none());
        let mut response = envelope(payload());
        response["id"] = json!("chatcmpl-ai1");
        response["model"] = json!(model);
        response["service_tier"] = json!("default");
        response["usage"] = json!({"prompt_tokens":20,"completion_tokens":10,"total_tokens":30});
        mock.response.send(http_response(&serde_json::to_vec(&response).unwrap())).unwrap();
        let paid = task.await.unwrap().unwrap();
        assert_eq!(paid.usage.unwrap().output_tokens, 10);
        assert_eq!(paid.explanation.unwrap().provider, format!("openai:{model}"));
        mock.task.await.unwrap();
    }
}

#[test]
fn usage_preserves_only_legacy_snapshot_equivalence_and_effort_changes_cache_identity() {
    let mut cfg = external_config("http://127.0.0.1:9");
    let legacy_profile = explanation_profile_id(&cfg).unwrap();
    let old_config = json!({"base_url":cfg.base_url,"api_key":cfg.api_key,"model":cfg.model,"budget":null});
    let old_config: AiExplainConfig = serde_json::from_value(old_config).unwrap();
    assert_eq!(cfg, old_config);
    assert!(serde_json::to_value(&cfg).unwrap().get("reasoning_effort").is_none());
    cfg.reasoning_effort = Some(ReasoningEffort::Low);
    assert_ne!(legacy_profile, explanation_profile_id(&cfg).unwrap());
    let mut response = json!({"id":"chatcmpl-ai1","service_tier":"default",
        "usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30}});
    for model in [DEFAULT_AI_MODEL, "gpt-4o-mini-2024-07-18", "gpt-6-luna", "operator/custom-model"] {
        cfg.model = model.into();
        response["model"] = json!(model);
        assert!(parse_usage(&cfg, &serde_json::to_vec(&response).unwrap()).is_some());
        response["model"] = json!(format!("{model}-snapshot"));
        assert!(parse_usage(&cfg, &serde_json::to_vec(&response).unwrap()).is_none());
    }
    for (configured, returned, accepted) in [
        (DEFAULT_AI_MODEL, "gpt-4o-mini-2024-07-18", true),
        (DEFAULT_AI_MODEL, "gpt-4o-mini-evil", false),
        (DEFAULT_AI_MODEL, "gpt-4o", false),
        (DEFAULT_AI_MODEL, "gpt-4o-mini-2024-07-18-evil", false),
        (DEFAULT_AI_MODEL, "gpt-4o-mini-2099-01-01", false),
        ("gpt-4o-mini-2024-07-18", DEFAULT_AI_MODEL, false),
        ("gpt-4o-mini-2024-07-18", "gpt-4o-mini-2099-01-01", false),
        ("gpt-4o-mini-evil", "gpt-4o-mini-2024-07-18", false),
        ("gpt-6-luna", "gpt-4o-mini-2024-07-18", false),
    ] {
        cfg.model = configured.into();
        response["model"] = json!(returned);
        assert_eq!(
            parse_usage(&cfg, &serde_json::to_vec(&response).unwrap()).is_some(),
            accepted,
            "configured={configured}, returned={returned}"
        );
    }
}

#[tokio::test]
async fn unadmitted_library_entry_never_sends_even_with_credentials() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cfg = external_config(&format!("http://{}", listener.local_addr().unwrap()));
    let request = ExplainRequest { request_id: Some("unadmitted".into()), ..Default::default() };
    let text = super::explain_card(&examples::sample_card(), &request, &cfg).await.unwrap();
    assert_eq!(text.provider, BUILTIN_PROVIDER);
    tokio::select! {biased; _=listener.accept()=>panic!("unadmitted entry sent a request"),_=tokio::task::yield_now()=>{}}
}
