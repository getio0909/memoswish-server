//! 真实隔离 PG schema 与专属 S3 mock 验证跨角色持久交接；不接触系统 Redis。
use super::*;
use crate::Daemon;
use crate::deployment::{Profile, Role};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
};
use memoswish_core::imports::ImportRepo;
use memoswish_core::repo::ContentRepo;
use memoswish_protocol::DeploymentMode;
use memoswish_storage::pg_test_support::run_pg_test;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tower::ServiceExt;

use crate::tests::apkg_support as import_support;

#[derive(Clone, Default)]
struct Objects {
    objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    mimes: Arc<Mutex<HashMap<String, String>>>,
    puts: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
    providers: Arc<AtomicUsize>,
    explanation_providers: Arc<AtomicUsize>,
    fail_put: Arc<Mutex<Option<String>>>,
}
async fn object(
    State(state): State<Objects>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    bytes: Bytes,
) -> impl IntoResponse {
    let key = uri.path().to_owned();
    if key == "/speech" {
        state.providers.fetch_add(1, Ordering::SeqCst);
        let wav = memoswish_media::wav::encode_wav(&vec![0.0; 22050 * 5], 22050);
        return (StatusCode::OK, [("Content-Type", "audio/wav")], wav).into_response();
    }
    if key == "/v1/chat/completions" {
        state.explanation_providers.fetch_add(1, Ordering::SeqCst);
        let explanation = serde_json::json!({
            "summary":"External explanation", "key_points":["Key idea"],
            "analogy":"An example", "follow_up_questions":["Why?"]
        });
        return axum::Json(serde_json::json!({
            "choices":[{"finish_reason":"stop","message":{"content":explanation.to_string()}}]
        }))
        .into_response();
    }
    if method == Method::GET && uri.query().is_some_and(|q| q.split('&').any(|p| p == "versions=")) {
        let url = reqwest::Url::parse(&format!("http://localhost{uri}")).unwrap();
        let prefix = url.query_pairs().find(|(k, _)| k == "prefix").unwrap().1.into_owned();
        let entries = state
            .objects
            .lock()
            .unwrap()
            .keys()
            .filter_map(|k| k.strip_prefix("/learntok/"))
            .filter(|k| k.starts_with(&prefix))
            .map(|k| format!("<Version><Key>{k}</Key><VersionId>null</VersionId></Version>"))
            .collect::<String>();
        return (
            StatusCode::OK,
            [("Content-Type", "application/xml")],
            format!("<ListVersionsResult><IsTruncated>false</IsTruncated>{entries}</ListVersionsResult>"),
        )
            .into_response();
    }
    (match method {
        Method::PUT => {
            if state.fail_put.lock().unwrap().as_deref() == Some(&key) {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            let mut objects = state.objects.lock().unwrap();
            if headers.get("if-none-match").is_some_and(|h| h == "*") && objects.contains_key(&key) {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            state.puts.fetch_add(1, Ordering::SeqCst);
            state.mimes.lock().unwrap().insert(
                key.clone(),
                headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .into(),
            );
            objects.insert(key, bytes.to_vec());
            (StatusCode::OK, Vec::new())
        }
        Method::DELETE => {
            state.deletes.fetch_add(1, Ordering::SeqCst);
            state.objects.lock().unwrap().remove(&key);
            (StatusCode::NO_CONTENT, Vec::new())
        }
        Method::GET | Method::HEAD => {
            let objects = state.objects.lock().unwrap();
            let Some(bytes) = objects.get(&key) else { return StatusCode::NOT_FOUND.into_response() };
            let etag = format!("\"{}\"", memoswish_core::ids::sha256_hex(bytes));
            let params: HashMap<_, _> =
                reqwest::Url::parse(&format!("http://localhost{uri}")).unwrap().query_pairs().into_owned().collect();
            if params.get("versionId").is_some_and(|id| id != "null") {
                return StatusCode::NOT_FOUND.into_response();
            }
            if headers.get("if-match").is_some_and(|value| value.to_str().ok() != Some(etag.as_str())) {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            let mime =
                state.mimes.lock().unwrap().get(&key).cloned().unwrap_or_else(|| "application/octet-stream".into());
            let mut response = axum::response::Response::builder()
                .header("ETag", etag)
                .header("x-amz-version-id", "null")
                .header("Content-Type", mime);
            if method == Method::GET
                && let Some(range) = headers.get("range")
            {
                let range = range
                    .to_str()
                    .ok()
                    .and_then(|value| http_range_header::parse_range_header(value).ok())
                    .and_then(|ranges| ranges.validate(bytes.len() as u64).ok())
                    .filter(|ranges| ranges.len() == 1);
                let Some(range) = range.and_then(|ranges| ranges.into_iter().next()) else {
                    return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
                };
                let (start, end) = (*range.start(), *range.end());
                response = response
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header("Content-Range", format!("bytes {start}-{end}/{}", bytes.len()))
                    .header("Content-Length", end - start + 1);
                return response.body(axum::body::Body::from(bytes[start as usize..=end as usize].to_vec())).unwrap();
            }
            return response
                .header("Content-Length", bytes.len())
                .body(if method == Method::HEAD {
                    axum::body::Body::empty()
                } else {
                    axum::body::Body::from(bytes.clone())
                })
                .unwrap();
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, Vec::new()),
    })
    .into_response()
}

#[test]
#[ignore = "integration: requires isolated PostgreSQL, disposable Redis, psql"]
fn horizontal_bootstrap_and_role_isolation() {
    run_pg_test(|owner| async move {
        let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let objects = Objects::default();
        let app = axum::Router::new().fallback(object).with_state(objects.clone());
        let mock = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let path = std::env::temp_dir().join(format!("s26a-no-local-{}", memoswish_core::ids::new_id()));
        let mut cfg = Config {
            db_max_connections: Some(1),
            profile: Profile::Horizontal,
            role: Role::Api,
            mode: DeploymentMode::MultiTenant,
            database_url: Some(fixture.database_url()),
            data_dir: path.clone(),
            jwt_secret: Some("shared-synthetic-deployment-secret".into()),
            seed_demo: false,
            registration_open: true,
            ..Default::default()
        };
        cfg.tts.auto_detect_espeak = false;
        cfg.privacy = memoswish_protocol::PrivacyPolicy {
            hosted: false,
            ..memoswish_protocol::examples::sample_privacy_policy()
        };
        cfg.privacy.purpose_versions.insert("external_tts".into(), "speech-v1".into());
        cfg.object_store.backend = "s3".into();
        cfg.tts.default_engine = "provider".into();
        cfg.tts.http.push(memoswish_media::tts::http::HttpTtsConfig {
            id: "provider".into(),
            endpoint: format!("{endpoint}/speech"),
            ..Default::default()
        });
        cfg.ai.base_url = Some(format!("{endpoint}/v1"));
        cfg.ai.api_key = Some("synthetic-explanation-key".into());
        cfg.object_store.s3.endpoint = endpoint;
        cfg.object_store.s3.access_key_id = "test".into();
        cfg.object_store.s3.secret_access_key = "test".into();
        #[cfg(feature = "mcp-oauth")]
        {
            cfg.oauth.enabled = true;
            cfg.oauth.issuer = "https://roles.example".into();
            cfg.oauth.public_base_url = cfg.oauth.issuer.clone();
            cfg.oauth.mcp_resource = "https://roles.example/mcp".into();
            cfg.oauth.pre_registered_clients.push(memoswish_auth::oauth_config::PreRegisteredClient {
                client_id: "deployment-client".into(),
                client_name: "Deployment".into(),
                redirect_uris: vec!["http://127.0.0.1/callback".into()],
                scope: "content:read".into(),
            });
        }
        cfg.admission.backend = "redis".into();
        cfg.admission.redis_url = Some(crate::test_environment::var("MEMOSWISH_TEST_REDIS_URL").unwrap());
        assert!(Daemon::start(cfg.clone()).await.is_err(), "runtime cannot initialize an empty schema");
        crate::migrate(cfg.clone()).await.unwrap();
        let original = objects.objects.lock().unwrap().get("/learntok/shared/deployment-v1.sha256").unwrap().clone();
        let mut changed = cfg.clone();
        changed.smtp.host = "smtp.example.com".into();
        changed.smtp.from = "sender@example.com".into();
        assert!(Daemon::start(changed).await.is_err(), "SMTP configuration must participate in shared identity");
        // 模拟密码字段引入前的安装，升级不得重新解释旧配置或重写既有身份。
        {
            let mut stored = objects.objects.lock().unwrap();
            stored.remove("/learntok/shared/deployment-v3.password.sha256");
            stored.remove("/learntok/shared/deployment-v3.password-origin.sha256");
        }
        assert!(Daemon::start(cfg.clone()).await.is_err());
        let mut changed = cfg.clone();
        changed.password_profile = crate::PasswordProfile::Disabled;
        assert!(crate::migrate(changed).await.is_err());
        crate::migrate(cfg.clone()).await.unwrap();
        assert_eq!(objects.objects.lock().unwrap().get("/learntok/shared/deployment-v1.sha256").unwrap(), &original);
        for burst in [true, false] {
            let mut changed = cfg.clone();
            if burst {
                changed.mcp.rate_limit_burst = 121;
            } else {
                changed.mcp.rate_limit_per_sec = 5.0;
            }
            assert!(Daemon::start(changed).await.is_err(), "MCP limits must participate in shared identity");
        }
        // 旧 v1 marker 升级必须由 migrator 完成，不能删除永久身份绕过。
        {
            let mut stored = objects.objects.lock().unwrap();
            stored.remove("/learntok/shared/deployment-v2.admission.sha256");
            stored.remove("/learntok/shared/deployment-v2.origin.sha256");
        }
        assert!(Daemon::start(cfg.clone()).await.is_err());
        let mut nondefault = cfg.clone();
        nondefault.mcp.rate_limit_per_sec = 5.0;
        assert!(crate::migrate(nondefault).await.is_err());
        crate::migrate(cfg.clone()).await.unwrap();
        assert_eq!(objects.objects.lock().unwrap().get("/learntok/shared/deployment-v1.sha256").unwrap(), &original);
        let put_count = objects.puts.load(Ordering::SeqCst);
        // 模拟对象提交成功但 SQL/完成标识尚未持久化的崩溃边界。
        let partial = fixture.repository(2).await.unwrap();
        sqlx::query("DELETE FROM bgm_tracks").execute(partial.pool()).await.unwrap();
        #[cfg(feature = "mcp-oauth")]
        sqlx::query("DELETE FROM oauth_clients").execute(partial.pool()).await.unwrap();
        objects.objects.lock().unwrap().remove("/learntok/shared/deployment-v1.sha256");
        partial.pool().close().await;
        let mut conflicting = cfg.clone();
        conflicting.jwt_secret = Some("different-synthetic-deployment-secret".into());
        assert!(
            crate::migrate(conflicting).await.is_err(),
            "partial bootstrap must reject a different permanent configuration before shared writes"
        );
        assert_eq!(put_count, objects.puts.load(Ordering::SeqCst));
        crate::migrate(cfg.clone()).await.unwrap();
        assert_eq!(
            put_count + 1,
            objects.puts.load(Ordering::SeqCst),
            "bootstrap resumes existing BGM without rewriting it"
        );
        let put_count = objects.puts.load(Ordering::SeqCst);
        crate::migrate(cfg.clone()).await.unwrap();
        assert_eq!(put_count, objects.puts.load(Ordering::SeqCst));
        // S26a 部分引导没有完成或 v2 marker；冲突升级必须零写入，原配置仍可恢复。
        let partial = fixture.repository(2).await.unwrap();
        sqlx::query("DELETE FROM bgm_tracks").execute(partial.pool()).await.unwrap();
        #[cfg(feature = "mcp-oauth")]
        sqlx::query("DELETE FROM oauth_clients").execute(partial.pool()).await.unwrap();
        partial.pool().close().await;
        {
            let mut stored = objects.objects.lock().unwrap();
            stored.remove("/learntok/shared/deployment-v1.sha256");
            stored.remove("/learntok/shared/deployment-v2.admission.sha256");
        }
        let before_conflict = objects.objects.lock().unwrap().clone();
        let deletes = objects.deletes.load(Ordering::SeqCst);
        let mut conflicting = cfg.clone();
        conflicting.jwt_secret = Some("different-synthetic-deployment-secret".into());
        assert!(crate::migrate(conflicting).await.is_err());
        assert_eq!(objects.puts.load(Ordering::SeqCst), put_count, "legacy conflict must perform zero PUTs");
        assert_eq!(objects.deletes.load(Ordering::SeqCst), deletes, "legacy conflict must perform zero DELETEs");
        assert_eq!(*objects.objects.lock().unwrap(), before_conflict);
        // 仅 MCP 额度不同不会改变 v1 指纹，也必须在发布任何永久对象前拒绝。
        for burst in [true, false] {
            let mut nondefault = cfg.clone();
            if burst {
                nondefault.mcp.rate_limit_burst = 121;
            } else {
                nondefault.mcp.rate_limit_per_sec = 5.0;
            }
            let error = crate::migrate(nondefault).await.unwrap_err();
            assert!(format!("{error:#}").contains("legacy deployment requires default MCP limits"));
            assert_eq!(objects.puts.load(Ordering::SeqCst), put_count, "legacy MCP conflict must perform zero PUTs");
            assert_eq!(
                objects.deletes.load(Ordering::SeqCst),
                deletes,
                "legacy MCP conflict must perform zero DELETEs"
            );
            assert_eq!(*objects.objects.lock().unwrap(), before_conflict);
        }
        crate::migrate(cfg.clone()).await.unwrap();
        assert_eq!(
            objects.puts.load(Ordering::SeqCst),
            put_count + 2,
            "resume only publishes admission and completion"
        );
        assert_eq!(objects.objects.lock().unwrap().get("/learntok/shared/deployment-v1.sha256"), Some(&original));
        let put_count = objects.puts.load(Ordering::SeqCst);
        crate::migrate(cfg.clone()).await.unwrap();
        assert_eq!(objects.puts.load(Ordering::SeqCst), put_count);
        // 新版自定义额度安装逐一中断永久 marker 发布，重启仍沿用同一来源和身份。
        let default_objects = objects.objects.lock().unwrap().clone();
        let mut custom = cfg.clone();
        custom.mcp.rate_limit_burst = 121;
        custom.mcp.rate_limit_per_sec = 5.0;
        custom.smtp.host = "smtp.example.com".into();
        custom.smtp.from = "sender@example.com".into();
        let markers = [
            "/learntok/shared/deployment-v3.password-origin.sha256",
            "/learntok/shared/deployment-v2.origin.sha256",
            "/learntok/shared/deployment-v1.config.sha256",
            "/learntok/shared/deployment-v2.admission.sha256",
            "/learntok/shared/deployment-v3.password.sha256",
            "/learntok/shared/deployment-v1.sha256",
        ];
        for (index, failed_key) in markers.iter().enumerate() {
            {
                let mut stored = objects.objects.lock().unwrap();
                for key in markers {
                    stored.remove(key);
                }
            }
            *objects.fail_put.lock().unwrap() = Some((*failed_key).into());
            assert!(crate::migrate(custom.clone()).await.is_err(), "publication failure must stop bootstrap");
            *objects.fail_put.lock().unwrap() = None;
            let interrupted = objects.objects.lock().unwrap().clone();
            for (published, key) in markers.iter().enumerate() {
                assert_eq!(interrupted.contains_key(*key), published < index, "publication order at {failed_key}");
            }
            if index > 0 {
                let puts = objects.puts.load(Ordering::SeqCst);
                let deletes = objects.deletes.load(Ordering::SeqCst);
                for mut conflicting in [cfg.clone(), custom.clone()] {
                    // 第二个冲突保持额度不变，仅改变 v1 身份，覆盖来源发布后的最早边界。
                    if conflicting.mcp.rate_limit_burst == custom.mcp.rate_limit_burst {
                        conflicting.jwt_secret = Some("different-synthetic-deployment-secret".into());
                    }
                    assert!(crate::migrate(conflicting).await.is_err());
                    assert_eq!(objects.puts.load(Ordering::SeqCst), puts);
                    assert_eq!(objects.deletes.load(Ordering::SeqCst), deletes);
                    assert_eq!(*objects.objects.lock().unwrap(), interrupted);
                }
            }
            crate::migrate(custom.clone()).await.unwrap();
            let completed = objects.objects.lock().unwrap().clone();
            for key in &markers[..index] {
                assert_eq!(completed.get(*key), interrupted.get(*key), "restart must preserve permanent identity");
            }
            let puts = objects.puts.load(Ordering::SeqCst);
            crate::migrate(custom.clone()).await.unwrap();
            let restarted = Daemon::start(custom.clone()).await.unwrap();
            restarted.shutdown().await;
            assert_eq!(objects.puts.load(Ordering::SeqCst), puts, "completed custom install restarts without writes");
            assert_eq!(*objects.objects.lock().unwrap(), completed);
        }
        *objects.objects.lock().unwrap() = default_objects;
        let put_count = objects.puts.load(Ordering::SeqCst);
        let api = Daemon::start(cfg.clone()).await.unwrap();
        let probe = api
            .state
            .as_ref()
            .unwrap()
            .health
            .router()
            .oneshot(axum::http::Request::get("/readyz").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(probe.status(), StatusCode::OK, "real PostgreSQL/S3 mock/throwaway Redis role readiness");
        let account = api
            .services()
            .auth
            .register_session(&memoswish_protocol::RegisterRequest {
                email: "roles@example.com".into(),
                password: "password123".into(),
                display_name: "Roles".into(),
                tenant_name: None,
            })
            .await
            .unwrap();
        let tenant = api.services().auth.session_memberships(&account.access_token).await.unwrap()[0].tenant_id.clone();
        let account = api.services().auth.select_session_workspace(&account.access_token, &tenant).await.unwrap();
        let p = api.services().auth.authenticate(Some(&account.access_token)).await.unwrap();
        assert_eq!(p.via, "session");
        // 不制造 owner，使用真实注册的当前凭据和成员世代。
        let repository = fixture.repository(1).await.unwrap();
        let deck = memoswish_protocol::examples::sample_deck();
        repository.insert_deck(&p.tenant_id, &deck).await.unwrap();
        let mut card = memoswish_protocol::examples::sample_card();
        card.deck_id = deck.id;
        card.language = "en".into();
        card.tts = None;
        card.bgm = None;
        repository.insert_card(&p.tenant_id, &card).await.unwrap();
        // 通过真实认证的 REST 与 MCP 路径触达共享服务，配置的解释提供者必须保持零调用。
        let app = crate::auth_defenses::test_router(api.state.as_ref().unwrap().clone());
        let requests = [
            (format!("/v1/cards/{}/explain", card.id), serde_json::json!({}), StatusCode::SERVICE_UNAVAILABLE),
            (
                "/mcp".into(),
                serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                    "params":{"name":"card_explain","arguments":{"card_id":card.id}}}),
                StatusCode::OK,
            ),
        ];
        for (uri, body, expected_status) in requests {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::post(&uri)
                        .header("Host", "localhost")
                        .header("Authorization", format!("Bearer {}", account.access_token))
                        .header("Content-Type", "application/json")
                        .body(axum::body::Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status, "{uri}");
            let body = axum::body::to_bytes(response.into_body(), 65536).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if uri == "/mcp" {
                assert_eq!(body["result"]["isError"], true, "{body}");
                assert_eq!(body["result"]["content"][0]["text"], "[temporarily_unavailable] temporarily unavailable");
            } else {
                assert_eq!(
                    body,
                    serde_json::json!({"code":"temporarily_unavailable","message":"temporarily unavailable"})
                );
            }
            assert_eq!(objects.explanation_providers.load(Ordering::SeqCst), 0, "{uri}");
        }
        let options =
            memoswish_media::SynthesizeOptions { text: Some("Role isolation sentence".into()), ..Default::default() };
        assert!(matches!(
            api.services().submit_tts(&p, "missing-purpose", std::slice::from_ref(&card.id), &options).await,
            Err(memoswish_core::CoreError::Forbidden(_))
        ));
        assert_eq!(objects.providers.load(Ordering::SeqCst), 0);
        for (kind, version, value) in [
            ("notice", "notice-v1", ""),
            ("terms", "terms-v1", ""),
            ("age", "notice-v1", "example-region"),
            ("external_tts", "speech-v1", ""),
        ] {
            let current = api.services().auth.privacy_state(&p).await.unwrap();
            api.services()
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
        let accepted =
            api.services().submit_tts(&p, "s26a-job", std::slice::from_ref(&card.id), &options).await.unwrap();
        assert!(api.services().recover_speech().is_err());
        assert!(api.services().recover_imports().is_err());
        assert!(api.services().import_apkg(&p, vec![], Default::default()).await.is_err());
        assert_eq!(objects.puts.load(Ordering::SeqCst), put_count, "API cannot bootstrap or execute uploads");
        assert_eq!(objects.deletes.load(Ordering::SeqCst), 0);
        assert_eq!(objects.providers.load(Ordering::SeqCst), 0);
        assert!(!accepted.items.is_empty());
        // 启动恢复同样必须在 claim eligibility 内拒绝未知 payload。
        sqlx::query("UPDATE background_jobs SET payload=$1 WHERE kind='tts_synthesis'")
            .bind(sqlx::types::Json(serde_json::json!({"version":999})))
            .execute(repository.pool())
            .await
            .unwrap();
        cfg.role = Role::Worker;
        let worker = Daemon::start(cfg.clone()).await.unwrap();
        // 非空发现现在立即 eligible；以扫描凭据释放及业务页许可归还观察启动交接完成。
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let unfinished: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM background_jobs j JOIN maintenance_tasks m ON m.id=j.id AND m.partition_id=j.tenant_id WHERE m.task_kind IN ('import_recovery','speech_recovery','attachment_recovery') AND j.state='running'",
                )
                .fetch_one(repository.pool())
                .await
                .unwrap();
                let pages_drained = [
                    memoswish_core::maintenance::TaskKind::ImportRecovery,
                    memoswish_core::maintenance::TaskKind::SpeechRecovery,
                    memoswish_core::maintenance::TaskKind::AttachmentRecovery,
                ]
                .into_iter()
                .all(|kind| memoswish_application::Services::maintenance_work_permit(kind).is_ok());
                if unfinished == 0 && pages_drained {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let probe = worker
            .state
            .as_ref()
            .unwrap()
            .health
            .router()
            .oneshot(axum::http::Request::get("/readyz").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(probe.status(), StatusCode::OK, "worker readiness uses actual role dependencies");
        // 旧同步入口只在 API 受理，等待独立 worker 提交；覆盖 APKG 媒体与 DeckPack。
        let apkg = import_support::zip(vec![
            (
                "collection.anki2",
                import_support::database("basic", "Question<img src='x.png'>\u{1f}Answer", &[0]).await,
            ),
            ("media", br#"{"0":"x.png"}"#.to_vec()),
            ("0", b"\x89PNG\r\n\x1a\nimage".to_vec()),
        ]);
        for is_apkg in [true, false] {
            let services = api.services().clone();
            let principal = p.clone();
            let bytes = apkg.clone();
            let before_puts = objects.puts.load(Ordering::SeqCst);
            let before_decks = repository.list_decks(&p.tenant_id).await.unwrap().len();
            let mut wait = tokio::spawn(async move {
                if is_apkg {
                    services
                        .import_apkg(&principal, bytes, Default::default())
                        .await
                        .map(|report| assert_eq!(report.media_imported, 1))
                } else {
                    services
                        .import_deck_pack(&principal, memoswish_protocol::examples::sample_deck_pack())
                        .await
                        .map(|_| ())
                }
            });
            let pending = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if wait.is_finished() {
                        panic!("API import ended before staging (APKG={is_apkg}): {:?}", (&mut wait).await);
                    }
                    let page = api.services().content.import_repository().pending_imports(None).await.unwrap();
                    if let Some((tenant, id)) = page.into_iter().next() {
                        break (tenant, id);
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(pending.0, p.tenant_id);
            let attempts: i64 = sqlx::query_scalar("SELECT attempts FROM background_jobs WHERE tenant_id=$1 AND id=$2")
                .bind(&pending.0)
                .bind(&pending.1)
                .fetch_one(repository.pool())
                .await
                .unwrap();
            assert_eq!(attempts, 0, "API cannot claim imports");
            assert!(!wait.is_finished());
            assert_eq!(objects.puts.load(Ordering::SeqCst), before_puts);
            assert_eq!(repository.list_decks(&p.tenant_id).await.unwrap().len(), before_decks);
            assert!(api.services().content.cleanup_import(&pending.0, &pending.1).await.is_err());
            if is_apkg {
                for (kind, payload) in
                    [("future_import", serde_json::json!({})), ("content_import", serde_json::json!({"version":999}))]
                {
                    sqlx::query("UPDATE background_jobs SET kind=$3,payload=$4 WHERE tenant_id=$1 AND id=$2")
                        .bind(&pending.0)
                        .bind(&pending.1)
                        .bind(kind)
                        .bind(sqlx::types::Json(payload))
                        .execute(repository.pool())
                        .await
                        .unwrap();
                    assert!(
                        tokio::time::timeout(
                            std::time::Duration::from_millis(100),
                            worker.services().content.drive_import(&pending.0, &pending.1)
                        )
                        .await
                        .is_err()
                    );
                    let attempts: i64 =
                        sqlx::query_scalar("SELECT attempts FROM background_jobs WHERE tenant_id=$1 AND id=$2")
                            .bind(&pending.0)
                            .bind(&pending.1)
                            .fetch_one(repository.pool())
                            .await
                            .unwrap();
                    assert_eq!(attempts, 0);
                    assert_eq!(objects.puts.load(Ordering::SeqCst), before_puts);
                    assert_eq!(objects.deletes.load(Ordering::SeqCst), 0);
                    assert_eq!(objects.providers.load(Ordering::SeqCst), 0);
                    assert_eq!(objects.explanation_providers.load(Ordering::SeqCst), 0);
                }
                sqlx::query("UPDATE background_jobs SET kind='content_import',payload=$3 WHERE tenant_id=$1 AND id=$2")
                    .bind(&pending.0)
                    .bind(&pending.1)
                    .bind(sqlx::types::Json(serde_json::json!({})))
                    .execute(repository.pool())
                    .await
                    .unwrap();
            }
            crate::maintenance_scheduler::due_for_test(&cfg).await.unwrap();
            worker.services().recover_imports().unwrap().await.unwrap().unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(10), wait).await.unwrap().unwrap().unwrap();
            assert_eq!(repository.list_decks(&p.tenant_id).await.unwrap().len(), before_decks + 1);
            if is_apkg {
                assert!(objects.puts.load(Ordering::SeqCst) > before_puts, "only worker uploads import media");
            }
        }
        // 未知 payload 在 SQL claim eligibility 内拒绝；不得先领取再放行/标记成功。
        sqlx::query("UPDATE background_jobs SET payload=$1 WHERE kind='tts_synthesis'")
            .bind(sqlx::types::Json(serde_json::json!({"version":999})))
            .execute(repository.pool())
            .await
            .unwrap();
        // 一页结束后显式跨过周期边界；不在生产启动时重置持久游标或到期时间。
        for _ in 0..2 {
            crate::maintenance_scheduler::due_for_test(&cfg).await.unwrap();
            worker.services().recover_speech().unwrap().await.unwrap().unwrap();
        }
        assert_eq!(objects.providers.load(Ordering::SeqCst), 0);
        let attempts: i64 =
            sqlx::query_scalar("SELECT CAST(SUM(attempts) AS BIGINT) FROM background_jobs WHERE kind='tts_synthesis'")
                .fetch_one(repository.pool())
                .await
                .unwrap();
        assert_eq!(attempts, 0);
        sqlx::query("UPDATE background_jobs SET payload=$1 WHERE kind='tts_synthesis'")
            .bind(sqlx::types::Json(serde_json::json!({})))
            .execute(repository.pool())
            .await
            .unwrap();
        // 同步调用仍等待既有响应形状；实际 provider 仅在独立 worker 的恢复任务内运行。
        let before_requesters: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tts_requesters WHERE tenant_id=$1")
            .bind(&p.tenant_id)
            .fetch_one(repository.pool())
            .await
            .unwrap();
        let media = api.services().media.clone();
        let principal = p.clone();
        let wait = tokio::spawn(async move {
            media.synthesize(&principal, "Role isolation sentence", "en", &Default::default()).await
        });
        // 等待 API 持久受理后再领取有界页面，避免测试扫描早于请求入库。
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tts_requesters WHERE tenant_id=$1")
                    .bind(&p.tenant_id)
                    .fetch_one(repository.pool())
                    .await
                    .unwrap();
                if count > before_requesters {
                    break;
                }
                assert!(!wait.is_finished(), "API synthesis must wait for worker execution");
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // 一页结束后显式跨过周期边界；不在生产启动时重置持久游标或到期时间。
        for _ in 0..2 {
            crate::maintenance_scheduler::due_for_test(&cfg).await.unwrap();
            worker.services().recover_speech().unwrap().await.unwrap().unwrap();
        }
        wait.await.unwrap().unwrap();
        assert_eq!(objects.providers.load(Ordering::SeqCst), 1);
        let result = api.services().tts_submission_status(&p, "s26a-job").await.unwrap();
        assert!(result.complete);
        assert_eq!(
            result.items[0].receipt.as_ref().unwrap().disposition,
            memoswish_protocol::tts::TtsDisposition::Attached
        );
        // API 已受理的工作在撤回后保持待处理，由 worker 复核并产生持久终态。
        let options = memoswish_media::SynthesizeOptions {
            text: Some("Withdrawn role isolation sentence".into()),
            ..Default::default()
        };
        api.services().submit_tts(&p, "withdrawn", std::slice::from_ref(&card.id), &options).await.unwrap();
        let services = api.services().clone();
        let principal = p.clone();
        let before_decks = repository.list_decks(&p.tenant_id).await.unwrap().len();
        let wait = tokio::spawn(async move {
            services
                .import_deck_pack_with_identity(
                    &principal,
                    memoswish_protocol::examples::sample_deck_pack(),
                    true,
                    Some("withdrawn-import".into()),
                    None,
                )
                .await
        });
        let pending = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(item) = repository.pending_imports(None).await.unwrap().into_iter().next() {
                    break item;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let current = api.services().auth.privacy_state(&p).await.unwrap();
        api.services()
            .auth
            .update_privacy(
                &p,
                &memoswish_protocol::PrivacyUpdate {
                    expected_revision: current.revision,
                    kind: "external_tts".into(),
                    version: "speech-v1".into(),
                    decision: false,
                    value: String::new(),
                },
            )
            .await
            .unwrap();
        assert!(!api.services().tts_submission_status(&p, "withdrawn").await.unwrap().complete);
        assert_eq!(repository.import_operation(&pending.0, &pending.1).await.unwrap().outcome, "pending");
        let before_puts = objects.puts.load(Ordering::SeqCst);
        assert!(api.services().recover_speech().is_err());
        assert!(api.services().recover_imports().is_err());
        crate::maintenance_scheduler::due_for_test(&cfg).await.unwrap();
        let recovery_error = worker.services().recover_imports().unwrap().await.unwrap().unwrap_err();
        assert!(matches!(recovery_error, memoswish_core::CoreError::Internal(_)));
        let schedule_error: Option<String> = sqlx::query_scalar(
            "SELECT j.error FROM background_jobs j JOIN maintenance_tasks m ON m.id=j.id AND m.partition_id=j.tenant_id WHERE m.task_kind='import_recovery'",
        )
        .fetch_one(repository.pool())
        .await
        .unwrap();
        assert_eq!(schedule_error.as_deref(), Some("maintenance page failed"));
        // 一页结束后显式跨过周期边界；不在生产启动时重置持久游标或到期时间。
        for _ in 0..2 {
            crate::maintenance_scheduler::due_for_test(&cfg).await.unwrap();
            worker.services().recover_speech().unwrap().await.unwrap().unwrap();
        }
        assert!(tokio::time::timeout(std::time::Duration::from_secs(10), wait).await.unwrap().unwrap().is_err());
        assert_eq!(repository.import_operation(&pending.0, &pending.1).await.unwrap().outcome, "failed");
        assert_eq!(repository.list_decks(&p.tenant_id).await.unwrap().len(), before_decks);
        let terminal = api.services().tts_submission_status(&p, "withdrawn").await.unwrap();
        assert!(terminal.complete);
        assert_eq!(
            terminal.items[0].receipt.as_ref().unwrap().disposition,
            memoswish_protocol::tts::TtsDisposition::Failed
        );
        assert_eq!(objects.providers.load(Ordering::SeqCst), 1);
        assert_eq!(objects.puts.load(Ordering::SeqCst), before_puts);
        // 政策差异必须在任何安装写入前拒绝，不能由 API/worker 回滚当前政策。
        for role in [Role::Api, Role::Worker, Role::Maintenance, Role::Migrator] {
            let mut changed = cfg.clone();
            changed.role = role;
            changed.privacy.notice_version = "notice-v2".into();
            assert!(Daemon::start(changed).await.is_err());
            let body: String = sqlx::query_scalar("SELECT body FROM privacy_deployment_policy WHERE id=1")
                .fetch_one(repository.pool())
                .await
                .unwrap();
            assert_eq!(serde_json::from_str::<memoswish_protocol::PrivacyPolicy>(&body).unwrap(), cfg.privacy);
            assert_eq!(objects.puts.load(Ordering::SeqCst), before_puts);
        }
        repository.pool().close().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(worker.serve_http(listener, None, std::future::pending()).await.is_err());
        cfg.role = Role::Worker;
        let worker_stdio = Daemon::start(cfg.clone()).await.unwrap();
        assert!(
            worker_stdio.serve_stdio(Some(&account.access_token), tokio::io::empty(), tokio::io::sink()).await.is_err()
        );
        // 实际 HTTP 擦除入口必须只接受 SQL 责任，不能在 API 中触发外部清理。
        let api_state = api.state.as_ref().unwrap().clone();
        let response = crate::auth_defenses::test_router(api_state.clone())
            .oneshot(
                axum::http::Request::post("/v1/workspace/delete")
                    .header("Authorization", format!("Bearer {}", account.access_token))
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(serde_json::json!({"confirmed_tenant_id":p.tenant_id}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(objects.deletes.load(Ordering::SeqCst), 0);
        let work = api_state.repo.erasure_page("", 100).await.unwrap().remove(0);
        assert_ne!(work.progress, "complete");
        cfg.role = Role::Maintenance;
        let maintenance = Daemon::start(cfg.clone()).await.unwrap();
        let probe = maintenance
            .state
            .as_ref()
            .unwrap()
            .health
            .router()
            .oneshot(axum::http::Request::get("/readyz").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(probe.status(), StatusCode::OK, "maintenance readiness uses actual role dependencies");
        assert!(maintenance.services().recover_speech().is_err());
        assert!(maintenance.services().recover_imports().is_err());
        crate::account::finish(maintenance.state.as_ref().unwrap(), &work.job).await.unwrap();
        assert_eq!(api_state.repo.erasure_work(&work.job.id).await.unwrap().unwrap().progress, "complete");
        assert!(objects.deletes.load(Ordering::SeqCst) > 0);
        assert!(objects.objects.lock().unwrap().contains_key("/learntok/shared/deployment-v1.sha256"));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(maintenance.serve_http(listener, None, std::future::pending()).await.is_err());
        cfg.role = Role::Api;
        cfg.jwt_secret = Some("different-synthetic-deployment-secret".into());
        assert!(Daemon::start(cfg).await.is_err(), "replica keys must match bootstrap identity");
        assert!(!path.exists(), "horizontal replicas cannot generate local installation state");
        api.shutdown().await;
        mock.abort();
        let _ = mock.await;
        fixture.cleanup().await;
    });
}
