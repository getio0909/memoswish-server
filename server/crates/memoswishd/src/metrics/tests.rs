use super::*;
use memoswish_core::repo::LearningDisposition;
use memoswish_protocol::DeploymentMode;
use std::collections::BTreeSet;

fn dump(metrics: &Metrics) -> String {
    String::from_utf8(metrics.encode(false).unwrap()).unwrap()
}
fn value(metrics: &Metrics, name: &str) -> f64 {
    dump(metrics)
        .lines()
        .find(|line| line.starts_with(name))
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn instance_isolation_all_labels_and_worst_case_resource_bounds() {
    let a = Metrics::new(DeploymentMode::SingleUser).unwrap();
    let b = Metrics::new(DeploymentMode::SingleUser).unwrap();
    assert!(routes::ROUTES.len() <= 128);
    for route in routes::ROUTES {
        for code in [100, 200, 300, 400, 500, 999] {
            a.http(route).finish(StatusCode::from_u16(code).unwrap());
        }
        drop(a.http(route));
    }
    for operation in Operation::ALL {
        for outcome in Outcome::ALL {
            a.start(*operation).finish(*outcome);
        }
    }
    for class in AdmissionClass::ALL {
        for outcome in AdmissionOutcome::ALL {
            a.admission(*class, *outcome);
        }
        a.capacity(*class, 1, 2);
    }
    for kind in memoswish_core::maintenance::TaskKind::ALL {
        a.maintenance(*kind, true);
        a.maintenance(*kind, false);
    }
    for cause in FeedRetryCause::ALL {
        a.feed_retry(*cause);
    }
    for outcome in ReviewOutcome::ALL {
        a.review(*outcome);
    }
    for d in [
        LearningDisposition::Scheduled,
        LearningDisposition::LateNotScheduled,
        LearningDisposition::FutureNotScheduled,
        LearningDisposition::NotRated,
    ] {
        a.disposition(d);
    }
    a.set_pool(PoolSnapshot { size: 3, idle: 1, capacity: 8 });
    a.sampled(OperationalSnapshot { observed_at_ms: 20_000, pending: vec![], maintenance: vec![] });
    let text = dump(&a);
    assert!(text.len() < MAX_BYTES);
    assert!(text.lines().filter(|line| !line.starts_with('#')).count() < 16_384);
    assert!(!dump(&b).contains("memoswish_reviews_total{"));
    let mut seen = BTreeSet::new();
    for family in a.registry.gather() {
        assert!(
            family.name().starts_with("memoswish_")
                || ["learntok_build_info", "learntok_http_requests_total", "learntok_tts_engines_registered"]
                    .contains(&family.name())
        );
        for metric in family.get_metric() {
            for label in metric.get_label() {
                let name = label.name();
                let value = label.value();
                seen.insert(name.to_owned());
                assert!(
                    match name {
                        "cause" => FeedRetryCause::ALL.iter().any(|v| v.label() == value),
                        "route" => routes::ROUTES.contains(&value),
                        "status_class" => ["1xx", "2xx", "3xx", "4xx", "5xx", "other"].contains(&value),
                        "operation" => Operation::ALL.iter().any(|v| v.label() == value),
                        "outcome" =>
                            Outcome::ALL.iter().any(|v| v.label() == value)
                                || AdmissionOutcome::ALL.iter().any(|v| v.label() == value)
                                || ReviewOutcome::ALL.iter().any(|v| v.label() == value),
                        "task_kind" => memoswish_core::maintenance::TaskKind::ALL.iter().any(|k| k.as_str() == value),
                        "task_state" => TaskState::ALL.iter().any(|s| s.label() == value),
                        "class" => AdmissionClass::ALL.iter().any(|v| v.label() == value),
                        "kind" => WorkKind::ALL.iter().any(|v| v.label() == value),
                        "state" => ["size", "idle", "capacity", "used_estimate"].contains(&value),
                        "disposition" =>
                            ["scheduled", "late_not_scheduled", "future_not_scheduled", "not_rated"].contains(&value),
                        "version" => value == env!("CARGO_PKG_VERSION"),
                        "mode" => value == "single_user",
                        _ => false,
                    },
                    "unreviewed label: {name}"
                );
            }
        }
    }
    assert_eq!(seen.len(), 13);
    let mut writer = BoundedWriter(vec![0; MAX_BYTES]);
    assert!(writer.write_all(b"overflow").is_err());
    let _encoding = a.encoding.try_acquire().unwrap();
    assert_eq!(a.response(false).status(), StatusCode::SERVICE_UNAVAILABLE);
    b.http_requests.inc();
    assert_eq!(b.response(false).status(), StatusCode::OK);
}

#[test]
fn cancelled_operations_never_fabricate_http_status_and_stale_samples_retain_gauges() {
    let metrics = Metrics::new(DeploymentMode::SingleUser).unwrap();
    drop(metrics.http("/v1/feed"));
    drop(metrics.start(Operation::TtsHttp));
    let text = dump(&metrics);
    assert!(text.contains("memoswish_http_cancellations_total{route=\"/v1/feed\"} 1"));
    assert!(!text.contains("memoswish_http_responses_total{"));
    assert!(text.contains("operation=\"tts_http\",outcome=\"cancelled\""));
    metrics.sampled(OperationalSnapshot {
        observed_at_ms: 20_000,
        maintenance: vec![],
        pending: vec![PendingWork { kind: WorkKind::Erasure, count: 3, unknown: 1, future: 1, oldest_ms: Some(5_000) }],
    });
    assert_eq!(value(&metrics, "memoswish_cleanup_lag_seconds{kind=\"erasure\"}"), 15.0);
    metrics.sample_failed();
    assert_eq!(value(&metrics, "memoswish_operational_sample_success "), 0.0);
    assert_eq!(value(&metrics, "memoswish_operational_sample_timestamp_seconds "), 20.0);
    assert_eq!(value(&metrics, "memoswish_cleanup_lag_seconds{kind=\"erasure\"}"), 15.0);
    assert_eq!(value(&metrics, "memoswish_operational_sample_errors_total "), 1.0);
    metrics.sampled(OperationalSnapshot { observed_at_ms: 21_000, pending: vec![], maintenance: vec![] });
    assert!(value(&metrics, "memoswish_cleanup_lag_seconds{kind=\"erasure\"}").is_nan());
}

async fn state(mode: DeploymentMode) -> (crate::app::AppState, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("s26d-daemon-{}", memoswish_core::ids::new_id()));
    let cfg = crate::Config {
        data_dir: dir.clone(),
        seed_demo: false,
        mode,
        tts: crate::TtsConfig { auto_detect_espeak: false, ..Default::default() },
        ..Default::default()
    };
    let st = crate::app::AppState::assemble(cfg).await.unwrap();
    st.health.attach(&st).unwrap();
    st.health.lifecycle.set(crate::lifecycle::Phase::Running);
    (st, dir)
}

#[tokio::test]
async fn real_http_status_privacy_cors_and_body_are_preserved() {
    use axum::{Router, body::Body, routing::get};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let (st, dir) = state(DeploymentMode::MultiTenant).await;
    let app = crate::api::router(st.clone());
    for (method, path, expected) in [
        ("GET", "/v1/cards/CARD_SECRET_SENTINEL?url=https://PRIVATE_SENTINEL", 401),
        ("GET", "/v1/PRIVATE_SENTINEL", 404),
        ("PUT", "/v1/server-info", 405),
        ("GET", "/PRIVATE_SENTINEL", 404),
        ("OPTIONS", "/v1/server-info", 200),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", "Bearer TOKEN_SECRET_SENTINEL")
            .header("origin", "https://URL_SECRET_SENTINEL")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status().as_u16(), expected);
    }
    for index in 0..80 {
        app.clone()
            .oneshot(Request::get(format!("/v1/random-{index}-PRIVATE_SENTINEL")).body(Body::empty()).unwrap())
            .await
            .unwrap();
    }
    let legacy = app.clone().oneshot(Request::get("/metrics").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(legacy.headers()[axum::http::header::CONTENT_TYPE], CONTENT_TYPE);
    let text = String::from_utf8(legacy.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert_eq!(text.lines().filter(|line| !line.starts_with('#')).count(), 3);
    let full =
        st.health.internal_router().oneshot(Request::get("/metrics").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(full.status(), StatusCode::OK);
    let full = String::from_utf8(full.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    for sentinel in ["CARD_SECRET_SENTINEL", "PRIVATE_SENTINEL", "TOKEN_SECRET_SENTINEL", "URL_SECRET_SENTINEL"] {
        assert!(!full.contains(sentinel));
    }
    assert!(full.contains("route=\"/v1/cards/{card_id}\",status_class=\"4xx\""));
    assert!(full.contains("route=\"unmatched\",status_class=\"4xx\""));
    // 响应体不被观察器消费；未消费/长流仍由原 Body 管理。
    let extension = crate::api::instrument(
        Router::new().route(
            "/stream",
            get(|| async {
                Body::from_stream(futures::stream::pending::<Result<axum::body::Bytes, std::io::Error>>())
            }),
        ),
        st.clone(),
    );
    let response = extension.oneshot(Request::get("/stream").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    st.health.lifecycle.drain();
    let response = app.oneshot(Request::get("/v1/feed").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(dump(&st.metrics).contains("route=\"/v1/feed\",status_class=\"5xx\""));
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn provider_failure_timeout_invalid_response_cancellation_and_command_are_signalled() {
    use axum::{Router, body::Body, extract::Path, routing::post};
    use memoswish_core::tts::{TtsEngine, TtsRequest};
    use memoswish_media::tts::{
        command::{CommandTts, CommandTtsConfig},
        http::{HttpTts, HttpTtsConfig},
    };
    let metrics = Metrics::new(DeploymentMode::SingleUser).unwrap();
    let mock = Router::new().route(
        "/{kind}/{secret}",
        post(|Path((kind, _)): Path<(String, String)>| async move {
            match kind.as_str() {
                "error" => (StatusCode::INTERNAL_SERVER_ERROR, Body::from("PROVIDER_SECRET_SENTINEL")).into_response(),
                "slow" => {
                    std::future::pending::<()>().await;
                    unreachable!()
                }
                "ok" => {
                    (StatusCode::OK, Body::from(memoswish_media::wav::encode_wav(&[0.0; 160], 16000))).into_response()
                }
                _ => (StatusCode::OK, Body::from("{PRIVATE_CONTENT_SENTINEL")).into_response(),
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let request = TtsRequest {
        text: "PRIVATE_CONTENT_SENTINEL".into(),
        voice: "VOICE_SECRET_SENTINEL".into(),
        language: "en".into(),
        speed: 1.0,
    };
    for kind in ["error", "invalid", "slow", "ok"] {
        let engine = HttpTts::new(HttpTtsConfig {
            id: "ID_SECRET_SENTINEL".into(),
            endpoint: format!("http://{address}/{kind}/URL_SECRET_SENTINEL"),
            api_key: Some("API_SECRET_SENTINEL".into()),
            timeout_secs: 1,
            ..Default::default()
        })
        .with_observer(metrics.clone());
        assert_eq!(engine.synthesize(&request).await.is_ok(), kind == "ok");
    }
    let engine = HttpTts::new(HttpTtsConfig {
        endpoint: format!("http://{address}/slow/URL_SECRET_SENTINEL"),
        ..Default::default()
    })
    .with_observer(metrics.clone());
    {
        let pending = engine.synthesize(&request);
        tokio::pin!(pending);
        assert!(futures::poll!(&mut pending).is_pending());
    }
    // 独立 future 的作用域结束后才观察取消。
    let command = CommandTts::new(CommandTtsConfig {
        id: "COMMAND_SECRET_SENTINEL".into(),
        program: "false".into(),
        args: vec![],
        default_voice: "default".into(),
        timeout_secs: 1,
        text_via_stdin: false,
        external_transfer: false,
    })
    .with_observer(metrics.clone());
    let error = command.synthesize(&request).await.expect_err("The false fixture must fail");
    assert!(error.to_string().contains("speech command failed"), "Test requires false on PATH: {error}");
    let text = dump(&metrics);
    assert!(
        text.contains("memoswish_operation_duration_seconds_count{operation=\"tts_http\",outcome=\"cancelled\"} 1")
    );
    for outcome in ["http_error", "invalid_response", "timeout", "returned"] {
        assert!(
            text.contains(&format!(
                "memoswish_operation_duration_seconds_count{{operation=\"tts_http\",outcome=\"{outcome}\"}} 1"
            )),
            "{outcome}"
        );
    }
    assert!(text.contains("operation=\"tts_command\",outcome=\"command_failure\""));
    for secret in [
        "PROVIDER_SECRET_SENTINEL",
        "PRIVATE_CONTENT_SENTINEL",
        "URL_SECRET_SENTINEL",
        "VOICE_SECRET_SENTINEL",
        "ID_SECRET_SENTINEL",
        "API_SECRET_SENTINEL",
        "COMMAND_SECRET_SENTINEL",
    ] {
        assert!(!text.contains(secret));
    }
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn committed_reviews_duplicates_late_rejected_and_partial_failure_are_not_http_ack_counts() {
    use memoswish_core::repo::ContentRepo;
    use memoswish_protocol::{FeedbackBatch, examples};
    let (mut st, dir) = state(DeploymentMode::SingleUser).await;
    let repo = Arc::new(
        memoswish_storage::sqlite::SqliteRepository::open_runtime(&st.config.database_url())
            .await
            .unwrap()
            .with_observer(st.metrics.clone()),
    );
    let p = memoswish_core::Principal::local_owner("single_user");
    let deck = examples::sample_deck();
    repo.insert_deck(&p.tenant_id, &deck).await.unwrap();
    let mut card = examples::sample_card();
    card.deck_id = deck.id;
    repo.insert_card(&p.tenant_id, &card).await.unwrap();
    let now = chrono::Utc::now();
    let feed = memoswish_feed::FeedService::new(repo.clone(), Default::default(), Arc::new(move || now))
        .unwrap()
        .with_observer(st.metrics.clone());
    let mut event = examples::sample_feedback_batch().events[0].clone();
    let page =
        feed.next_page(&p, &memoswish_protocol::FeedQuery { limit: Some(1), ..Default::default() }).await.unwrap();
    event.card_id = card.id;
    event.event_id = "first".into();
    event.delivery_id = page.items[0].delivery_id.clone();
    event.slot = page.items[0].slot;
    event.shown_at = now - chrono::Duration::minutes(2);
    event.dwell_time_ms = 4000;
    event.loop_count = 1;
    let batch =
        FeedbackBatch { session_id: page.session_id, events: vec![event.clone()], ..examples::sample_feedback_batch() };
    let (a, b) = tokio::join!(feed.record_feedback(&p, &batch), feed.record_feedback(&p, &batch));
    assert_eq!(a.unwrap().accepted + b.unwrap().accepted, 1);
    assert_eq!(value(&st.metrics, "memoswish_reviews_total{outcome=\"accepted\"}"), 1.0);
    assert_eq!(value(&st.metrics, "memoswish_reviews_total{outcome=\"duplicate\"}"), 1.0);
    event.event_id = "late".into();
    event.shown_at -= chrono::Duration::days(1);
    let ack = feed.record_feedback(&p, &FeedbackBatch { events: vec![event.clone()], ..batch.clone() }).await.unwrap();
    assert_eq!(ack.accepted, 1);
    assert_eq!(value(&st.metrics, "memoswish_review_dispositions_total{disposition=\"late_not_scheduled\"}"), 1.0);
    event.event_id = String::new();
    let ack = feed.record_feedback(&p, &FeedbackBatch { events: vec![event.clone()], ..batch.clone() }).await.unwrap();
    assert_eq!(ack.rejected.len(), 1);
    assert_eq!(value(&st.metrics, "memoswish_reviews_total{outcome=\"rejected\"}"), 1.0);
    sqlx::raw_sql("CREATE TRIGGER s26d_fail_event BEFORE INSERT ON feedback_events WHEN NEW.event_id='z-system-failure' BEGIN SELECT RAISE(ABORT,'SQL_SECRET_SENTINEL'); END;").execute(repo.pool()).await.unwrap();
    event.event_id = "a-partial".into();
    event.shown_at = now - chrono::Duration::minutes(1);
    let mut fails = event.clone();
    fails.event_id = "z-system-failure".into();
    assert!(feed.record_feedback(&p, &FeedbackBatch { events: vec![event, fails], ..batch }).await.is_err());
    assert_eq!(value(&st.metrics, "memoswish_reviews_total{outcome=\"accepted\"}"), 3.0);
    assert!(dump(&st.metrics).contains("operation=\"db_write\",outcome=\"error\""));
    assert!(!dump(&st.metrics).contains("SQL_SECRET_SENTINEL"));
    // 真正关闭连接池，采样失败保留 last-good 并使错误信号变化。
    st.repo = repo.clone();
    crate::metrics::sample(&st).await;
    let old = value(&st.metrics, "memoswish_operational_sample_timestamp_seconds ");
    repo.pool().close().await;
    assert!(repo.operational_snapshot().await.is_err());
    crate::metrics::sample(&st).await;
    assert_eq!(value(&st.metrics, "memoswish_operational_sample_success "), 0.0);
    assert_eq!(value(&st.metrics, "memoswish_operational_sample_timestamp_seconds "), old);
    assert!(dump(&st.metrics).contains("operation=\"db_sample\",outcome=\"closed\""));
    assert!(old > 0.0);
    drop(feed);
    drop(repo);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn real_admission_rejection_and_backend_failure_preserve_policy_and_signals() {
    use memoswish_core::rate_limit::FailureMode;
    let metrics = Metrics::new(DeploymentMode::SingleUser).unwrap();
    let config = crate::admission::AdmissionConfig::default();
    let limiter =
        crate::admission::build_observed(&config, "work", 1, 0.001, FailureMode::Closed, metrics.clone()).unwrap();
    limiter.check("TENANT_USER_SECRET_SENTINEL", 1.0).await.unwrap();
    assert_eq!(limiter.check("TENANT_USER_SECRET_SENTINEL", 1.0).await.unwrap_err().http_status(), 429);
    assert_eq!(value(&metrics, "memoswish_admissions_total{class=\"work\",outcome=\"rejected\"}"), 1.0);
    #[cfg(feature = "redis")]
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = crate::admission::AdmissionConfig {
            backend: "redis".into(),
            redis_url: Some(format!("redis://{}", listener.local_addr().unwrap())),
            timeout_ms: 20,
            ..Default::default()
        };
        for failure in [FailureMode::Closed, FailureMode::Open] {
            let limiter = crate::admission::build_observed(&config, "work", 1, 1.0, failure, metrics.clone()).unwrap();
            assert_eq!(
                limiter.check("TENANT_USER_SECRET_SENTINEL", 1.0).await.is_ok(),
                matches!(failure, FailureMode::Open)
            );
        }
        assert_eq!(value(&metrics, "memoswish_admissions_total{class=\"work\",outcome=\"unavailable\"}"), 1.0);
        assert_eq!(value(&metrics, "memoswish_admissions_total{class=\"work\",outcome=\"fail_open\"}"), 1.0);
    }
    assert!(!dump(&metrics).contains("TENANT_USER_SECRET_SENTINEL"));
}

#[tokio::test]
async fn durable_tts_cache_does_not_count_another_provider_attempt() {
    use memoswish_media::{
        MediaService, SynthesizeOptions,
        tts::command::{CommandTts, CommandTtsConfig},
    };
    let (st, dir) = state(DeploymentMode::SingleUser).await;
    std::fs::create_dir_all(st.config.assets_dir()).unwrap();
    let wav = dir.join("source.wav");
    std::fs::write(&wav, memoswish_media::wav::encode_wav(&[0.0; 1600], 16000)).unwrap();
    let engine = CommandTts::new(CommandTtsConfig {
        external_transfer: false,
        id: "cache-engine".into(),
        program: "cat".into(),
        args: vec![wav.to_str().unwrap().into()],
        default_voice: "default".into(),
        text_via_stdin: false,
        timeout_secs: 1,
    })
    .with_observer(st.metrics.clone());
    let media = MediaService::new(
        st.repo.clone(),
        st.store.clone(),
        st.services.quota.clone(),
        vec![Arc::new(engine)],
        "cache-engine",
    )
    .unwrap();
    let p = memoswish_core::Principal::local_owner("single_user");
    let one = media
        .synthesize(&p, "CACHE_CONTENT_SENTINEL", "en", &SynthesizeOptions::default())
        .await
        .expect("The cat fixture on PATH must return the WAV");
    let two = media.synthesize(&p, "CACHE_CONTENT_SENTINEL", "en", &SynthesizeOptions::default()).await.unwrap();
    assert_eq!(one.audio.key, two.audio.key);
    assert_eq!(
        value(
            &st.metrics,
            "memoswish_operation_duration_seconds_count{operation=\"tts_command\",outcome=\"returned\"}"
        ),
        1.0
    );
    assert_eq!(value(&st.metrics, "memoswish_admission_in_flight{class=\"put\"}"), 0.0);
    assert!(!dump(&st.metrics).contains("CACHE_CONTENT_SENTINEL"));
    drop(media);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn evidenced_explanation_preserves_usage_and_attempt_header_on_invalid_content() {
    use axum::{Json, Router, routing::post};
    let metrics = Metrics::new(DeploymentMode::SingleUser).unwrap();
    let mock = Router::new().route(
        "/v1/chat/completions",
        post(|headers: axum::http::HeaderMap| async move {
            assert_eq!(headers["X-Client-Request-Id"], "metrics-attempt");
            Json(serde_json::json!({
                "id":"response123", "model":"gpt-4o-mini", "service_tier":"default",
                "usage":{"prompt_tokens":20,"completion_tokens":5,"total_tokens":25},
                "choices":[{"finish_reason":"stop","message":{"content":"PRIVATE_INVALID_SENTINEL"}}]
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let config = memoswish_content::explain::AiExplainConfig {
        base_url: Some(format!("http://{address}")),
        api_key: Some("PRIVATE_API_SENTINEL".into()),
        ..Default::default()
    };
    let paid = memoswish_content::explain::execute_admitted_explanation_observed(
        &memoswish_protocol::examples::sample_card(),
        &Default::default(),
        &config,
        "metrics-attempt",
        metrics.clone(),
    )
    .await
    .unwrap();
    assert_eq!(paid.usage.unwrap().input_tokens, 20);
    assert!(paid.explanation.is_err());
    assert_eq!(
        value(
            &metrics,
            "memoswish_operation_duration_seconds_count{operation=\"explanation_http\",outcome=\"invalid_response\"}"
        ),
        1.0
    );
    assert_eq!(value(&metrics, "memoswish_admission_in_flight{class=\"explanation\"}"), 0.0);
    assert!(!dump(&metrics).contains("PRIVATE_"));
    task.abort();
    let _ = task.await;
}

#[test]
fn hf12_feed_retry_counter_has_exactly_four_bounded_labels() {
    assert_eq!(
        FeedRetryCause::ALL.iter().map(|c| c.label()).collect::<Vec<_>>(),
        ["state_mismatch", "session_revision", "database_busy_locked", "other"]
    );
    let metrics = Metrics::new(DeploymentMode::SingleUser).unwrap();
    let other = Metrics::new(DeploymentMode::SingleUser).unwrap();
    for cause in FeedRetryCause::ALL {
        metrics.feed_retry(*cause);
        metrics.feed_retry(*cause);
    }
    let family = metrics.registry.gather().into_iter().find(|f| f.name() == "memoswish_feed_retries_total").unwrap();
    assert_eq!(family.get_metric().len(), 4);
    for metric in family.get_metric() {
        assert_eq!(metric.get_counter().get_value(), 2.0);
        assert_eq!(metric.get_label().len(), 1);
        assert_eq!(metric.get_label()[0].name(), "cause");
        assert!(FeedRetryCause::ALL.iter().any(|c| c.label() == metric.get_label()[0].value()));
    }
    assert!(!String::from_utf8(metrics.encode(true).unwrap()).unwrap().contains("memoswish_feed_retries_total"));
    assert!(!dump(&other).contains("memoswish_feed_retries_total"));
}
