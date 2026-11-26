//! 未自动播种的新账户，真实 Router 完成草稿、发布、首卡及报告纠正。
use super::*;
fn authenticated_get(uri: &str, token: &str) -> Request<Body> {
    Request::get(uri).header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn p31_raw_legacy_import_budgets_survive_rest_adapters() {
    let dir = std::env::temp_dir().join(format!("memoswish-p31-wire-{}", memoswish_core::ids::new_id()));
    let st = AppState::build(Config { data_dir: dir.clone(), seed_demo: false, ..Config::default() }).await.unwrap();
    let app = crate::auth_defenses::test_router(st.clone());
    for path in ["/v1/decks/import", "/v1/decks/import/portable", "/v1/content/import"] {
        let mut pack: Value = serde_json::from_str(include_str!(
            "../../../../../compatibility/history/2.13.0/protocol/fixtures/deck-pack.json"
        ))
        .unwrap();
        assert!(pack["deck"].get("revision").is_none());
        pack["cards"] = json!([]);
        pack["deck"]["card_count"] = json!(0);
        pack["deck"]["description"] = json!("");
        let base = serde_json::to_vec(&pack).unwrap().len();
        // 旧 REST 路由保留 Axum 的 2 MiB 原始传输上限；便携和严格入口允许完整 8 MiB content。
        let limit =
            if path == "/v1/decks/import" { 2 * 1024 * 1024 } else { memoswish_core::imports::IMPORT_CONTENT_BYTES };
        pack["deck"]["description"] = json!("x".repeat(limit - base));
        assert_eq!(serde_json::to_vec(&pack).unwrap().len(), limit);
        for excess in [false, true] {
            if excess {
                let text = format!("{}x", pack["deck"]["description"].as_str().unwrap());
                pack["deck"]["description"] = json!(text);
            }
            let portable = json!({"version":"2.0","content":pack,"media":[]});
            let input = match path {
                "/v1/decks/import" => pack.clone(),
                "/v1/content/import" => json!({"pack":portable,"idempotency_key":"raw-strict"}),
                _ => portable,
            };
            let (status, _, body) = send(&app, post_json(path, &input, None)).await;
            assert_eq!(status.is_success(), !excess, "{path}: {status}: {}", String::from_utf8_lossy(&body));
            if excess {
                let expected =
                    if path == "/v1/decks/import" { StatusCode::PAYLOAD_TOO_LARGE } else { StatusCode::BAD_REQUEST };
                assert_eq!(status, expected);
            }
        }
    }
    st.services.operations.close();
    st.services.operations.wait().await;
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}
async fn command(app: &Router, path: &str, input: Value, token: &str) -> Value {
    let (status, headers, body) = send(app, post_json(path, &input, Some(token))).await;
    assert!(status.is_success(), "{path}: {status}: {}", String::from_utf8_lossy(&body));
    if path.starts_with("/v1/content/") {
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }
    serde_json::from_slice(&body).unwrap()
}
#[tokio::test]
async fn p31_fresh_account_authors_publishes_reports_and_restarts() {
    let dir = std::env::temp_dir().join(format!("memoswish-p31-{}", memoswish_core::ids::new_id()));
    let cfg = Config {
        mode: DeploymentMode::MultiTenant,
        default_plan: "free".into(),
        data_dir: dir.clone(),
        registration_open: true,
        seed_demo: false,
        ..Config::default()
    };
    let st = AppState::build(cfg.clone()).await.unwrap();
    let app = crate::auth_defenses::test_router(st.clone());
    let auth = command(
        &app,
        "/v1/auth/register",
        json!({"email":"author@example.org","password":"test-long-password","display_name":"Author"}),
        "",
    )
    .await;
    let token = auth["access_token"].as_str().unwrap();
    let (_, _, bytes) = send(&app, authenticated_get("/v1/decks", token)).await;
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), json!([]));
    let deck = command(&app, "/v1/content/decks", json!({"title":"My topic","language":"en-US"}), token).await;
    let input = json!({"card":{"deck_id":deck["id"],"front":{"title":"Question"},"back":{"title":"Answer"}},"provenance":{"method":"manual"}});
    let card = command(&app, "/v1/content/cards", input.clone(), token).await;
    assert_eq!(card["content"]["publication"], "draft");
    let (_, _, bytes) = send(&app, authenticated_get("/v1/feed?request_id=draft-empty&limit=1", token)).await;
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["items"], json!([]));
    let id = card["id"].as_str().unwrap();
    let report = command(
        &app,
        &format!("/v1/content/cards/{id}/reports"),
        json!({"observed_revision":1,"text":"Please correct the answer"}),
        token,
    )
    .await;
    let mut edited = input;
    edited["card"]["id"] = card["id"].clone();
    edited["card"]["expected_revision"] = json!(1);
    edited["card"]["back"]["title"] = json!("Corrected answer");
    edited["publish"] = json!(true);
    edited["report_id"] = report["id"].clone();
    let updated = command(&app, "/v1/content/cards", edited.clone(), token).await;
    assert_eq!(updated["revision"], 2);
    assert_eq!(updated["content"]["publication"], "published");
    assert_eq!(send(&app, post_json("/v1/content/cards", &edited, Some(token))).await.0, StatusCode::CONFLICT);
    let (_, _, bytes) = send(&app, authenticated_get("/v1/feed?request_id=published-first&limit=1", token)).await;
    let issued: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(issued["items"][0]["card"]["id"], card["id"]);
    let report_path = format!("/v1/content/cards/{id}/reports");
    let (_, _, bytes) = send(&app, authenticated_get(&report_path, token)).await;
    let reports: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reports[0]["corrected_revision"], 2);
    assert_eq!(reports[0]["observed_revision"], 1);
    let install_path = "/v1/content/starters/learning-basics-v1/install";
    let first = command(&app, install_path, json!({"idempotency_key":"starter-first"}), token).await;
    let replay = command(&app, install_path, json!({"idempotency_key":"starter-first"}), token).await;
    assert_eq!(first, replay);
    st.services.operations.close();
    st.services.operations.wait().await;
    drop(app);
    crate::runtime::drain_test_state(&st).await;
    let restarted = AppState::build(cfg).await.unwrap();
    let app = crate::auth_defenses::test_router(restarted.clone());
    let (_, _, bytes) = send(&app, authenticated_get(&format!("/v1/cards/{id}"), token)).await;
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["back"]["title"], "Corrected answer");
    let replay = command(&app, install_path, json!({"idempotency_key":"starter-first"}), token).await;
    assert_eq!(first, replay);
    #[cfg(feature = "commercial-quota")]
    {
        let p = restarted.services.auth.authenticate(Some(token)).await.unwrap();
        assert_eq!(restarted.services.quota.card_write_limit(&p.tenant_id).await.unwrap(), Some(2000));
        restarted
            .repo
            .add_usage(&p.tenant_id, "card_writes", &memoswish_auth::quota::current_period(), 2000)
            .await
            .unwrap();
        assert!(matches!(
            restarted
                .services
                .publish_card(&p, id, memoswish_protocol::PublicationCommand { expected_revision: 2, publish: false })
                .await,
            Err(memoswish_core::CoreError::QuotaExceeded(_))
        ));
        let card = restarted.repo.get_card(&p.tenant_id, id).await.unwrap().unwrap();
        assert_eq!(card.revision, 2);
        assert!(memoswish_core::content_lifecycle::published(&card));
    }
    restarted.services.operations.close();
    restarted.services.operations.wait().await;
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st, &restarted]).await;
}

#[tokio::test]
async fn p31_additive_routes_reject_invalid_commands_and_keep_private_responses() {
    let (app, st, dir) = app(DeploymentMode::SingleUser).await;
    for path in [
        "/v1/content/cards",
        "/v1/content/decks",
        "/v1/content/cards/missing/publication",
        "/v1/content/cards/missing/reports",
        "/v1/content/decks/missing",
        "/v1/content/starters/learning-basics-v1/install",
        "/v1/content/import",
        "/v1/content/import/apkg",
    ] {
        let (status, headers, bytes) = send(&app, post_json(path, &json!({}), None)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {}", String::from_utf8_lossy(&bytes));
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert!(serde_json::from_slice::<memoswish_protocol::ApiError>(&bytes).is_ok());
    }
    for (method, path) in [
        ("GET", "/v1/content/starters"),
        ("GET", "/v1/content/cards/missing/reports"),
        ("GET", "/v1/content/cards/missing/revisions"),
    ] {
        let (status, headers, _) =
            send(&app, Request::builder().method(method).uri(path).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn p31_flagged_mcp_generation_is_draft_and_claims_cannot_forge_observations() {
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let p = memoswish_core::Principal::local_owner("single_user");
    let deck = st
        .services
        .create_deck(
            &p,
            memoswish_content::NewDeck {
                title: "Agent".into(),
                description: String::new(),
                language: "en".into(),
                tags: vec![],
            },
        )
        .await
        .unwrap();
    let app = crate::auth_defenses::test_router(st.clone());
    let args = json!({"content_lifecycle":true,"cards":[{"deck_id":deck.id,"front":{"title":"Agent output"}}]});
    let (_, _, bytes) = send(
        &app,
        post_json(
            "/mcp",
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"card_upsert","arguments":args}}),
            None,
        ),
    )
    .await;
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(response["error"].is_null(), "{response}");
    let cards = st.services.content.list_cards(&p, Some(&deck.id), 50, 0).await.unwrap();
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].content.as_ref().unwrap().publication, "draft");
    assert_eq!(cards[0].content.as_ref().unwrap().observed_generation, None);
    let (_,_,bytes)=send(&app,post_json("/mcp",&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"material_slice","arguments":{"deck_id":deck.id,"text":"Term :: Definition","commit":true,"content_lifecycle":true}}}),None)).await;
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(response["error"].is_null(), "{response}");
    let cards = st.services.content.list_cards(&p, Some(&deck.id), 50, 0).await.unwrap();
    assert!(
        cards.iter().any(|c| c.content.as_ref().unwrap().observed_generation.as_deref() == Some("builtin-heuristic"))
    );
    assert!(cards.iter().all(|c| !memoswish_core::content_lifecycle::published(c)));
    st.services.operations.close();
    st.services.operations.wait().await;
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn p31_strict_apkg_import_defaults_to_draft_and_retries_original_identity() {
    use base64::Engine;
    let _guard = APKG_TEST.lock().await;
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let app = crate::auth_defenses::test_router(st.clone());
    let input = json!({"apkg":{"apkg_base64":base64::engine::general_purpose::STANDARD.encode(apkg_support::basic().await),"request_id":"strict-apkg"}});
    let result = command(&app, "/v1/content/import/apkg", input.clone(), "").await;
    let replay = command(&app, "/v1/content/import/apkg", input, "").await;
    assert_eq!(result, replay);
    let id = result["deck"]["id"].as_str().unwrap();
    let p = memoswish_core::Principal::local_owner("single_user");
    let cards = st.services.content.list_cards(&p, Some(id), 50, 0).await.unwrap();
    assert!(!cards.is_empty());
    assert!(cards.iter().all(|c| !memoswish_core::content_lifecycle::published(c)));
    assert_eq!(st.services.stats_for_deck(&p, Some(id)).await.unwrap().total_cards, 0);
    st.services.operations.close();
    st.services.operations.wait().await;
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn p31_strict_portable_import_preserves_private_media_and_draft_status() {
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let p = memoswish_core::Principal::local_owner("single_user");
    let input = memoswish_protocol::ContentImport {
        pack: memoswish_protocol::examples::sample_portable_deck_pack(),
        idempotency_key: "strict-portable".into(),
        publish: false,
    };
    let deck = st.services.import_authored_content(&p, input.clone(), None).await.unwrap();
    let replay = st.services.import_authored_content(&p, input, None).await.unwrap();
    assert_eq!(deck, replay);
    assert_eq!(st.services.stats_for_deck(&p, Some(&deck.id)).await.unwrap().total_cards, 0);
    let cards = st.services.content.list_cards(&p, Some(&deck.id), 50, 0).await.unwrap();
    assert!(cards.iter().all(|c| !memoswish_core::content_lifecycle::published(c)));
    st.services.operations.close();
    st.services.operations.wait().await;
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn p31_read_scopes_cannot_read_drafts_or_bypass_them_through_media() {
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let p = memoswish_core::Principal::local_owner("single_user");
    let viewer = memoswish_core::Principal {
        scopes: Some(vec!["content:read".into(), "feedback:write".into(), "feed:read".into(), "media:read".into()]),
        ..p.clone()
    };
    let deck = st
        .services
        .create_authored_deck(
            &p,
            memoswish_content::NewDeck {
                title: "Private".into(),
                description: String::new(),
                language: "en-US".into(),
                tags: vec![],
            },
        )
        .await
        .unwrap();
    let save = memoswish_protocol::CardSave {
        card: serde_json::from_value(json!({"deck_id":deck.id,"front":{"title":"Private draft"}})).unwrap(),
        publish: false,
        provenance: None,
        report_id: None,
    };
    assert!(st.services.save_card(&viewer, save.clone()).await.is_err());
    let card = st.services.save_card(&p, save).await.unwrap();
    assert!(st.services.get_card(&viewer, &card.id).await.is_err());
    assert!(st.services.list_cards(&viewer, Some(&deck.id), 50, 0).await.unwrap().is_empty());
    assert!(st.services.content_revisions(&viewer, &card.id, u64::from(u32::MAX) + 1, 50).await.is_err());
    assert!(
        st.services
            .report_content(
                &viewer,
                &card.id,
                &memoswish_protocol::ReportCreate {
                    observed_revision: card.revision,
                    text: "Unseen draft".into(),
                    sources: vec![]
                }
            )
            .await
            .is_err()
    );
    let voiced =
        st.services.synthesize_cards(&p, std::slice::from_ref(&card.id), &Default::default()).await.unwrap().remove(0);
    let key = voiced.tts.as_ref().unwrap().audio.key.clone();
    let repo = st.services.content.import_repository();
    let store = st.services.media.store();
    for surface in ["content", "media"] {
        assert!(
            memoswish_application::asset_delivery::read(repo.as_ref(), store.as_ref(), &viewer, &key, surface, None)
                .await
                .is_err()
        );
    }
    let published = st
        .services
        .publish_card(
            &p,
            &card.id,
            memoswish_protocol::PublicationCommand { expected_revision: voiced.revision, publish: true },
        )
        .await
        .unwrap();
    assert_eq!(st.services.get_card(&viewer, &card.id).await.unwrap().revision, published.revision);
    assert!(
        !memoswish_application::asset_delivery::read(repo.as_ref(), store.as_ref(), &viewer, &key, "media", None)
            .await
            .unwrap()
            .bytes
            .is_empty()
    );
    st.services.operations.close();
    st.services.operations.wait().await;
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn p31_strict_editor_roundtrips_rich_faces_above_half_mib_and_full_retry_key() {
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let app = crate::auth_defenses::test_router(st.clone());
    let deck = command(&app, "/v1/content/decks", json!({"title":"Rich authoring","language":"zh-CN"}), "").await;
    let blocks = vec![json!({"type":"text","text":"字".repeat(8000)}); 32];
    let mut input = json!({"card":{"deck_id":deck["id"],"front":{"title":"Question","blocks":blocks},"back":{"title":"Answer","blocks":blocks},"tags":["retained"],"attributes":{"source":"retained"}}});
    assert!(serde_json::to_vec(&input).unwrap().len() > 512 * 1024);
    let original = command(&app, "/v1/content/cards", input.clone(), "").await;
    input["card"]["id"] = original["id"].clone();
    input["card"]["expected_revision"] = original["revision"].clone();
    input["card"]["front"]["title"] = json!("Corrected title");
    input["publish"] = json!(true);
    let saved = command(&app, "/v1/content/cards", input.clone(), "").await;
    assert_eq!(saved["front"]["blocks"], original["front"]["blocks"]);
    assert_eq!(saved["back"], original["back"]);
    assert_eq!(saved["attributes"], original["attributes"]);
    let key = "k".repeat(128);
    let p = memoswish_core::Principal::local_owner("single_user");
    let before =
        st.repo.get_usage(&p.tenant_id, "card_writes", &memoswish_auth::quota::current_period()).await.unwrap();
    let published = st
        .services
        .publish_card(
            &p,
            saved["id"].as_str().unwrap(),
            memoswish_protocol::PublicationCommand { expected_revision: 2, publish: false },
        )
        .await
        .unwrap();
    assert_eq!(published.revision, 3);
    assert_eq!(
        st.repo.get_usage(&p.tenant_id, "card_writes", &memoswish_auth::quota::current_period()).await.unwrap(),
        before + 1
    );
    let first = st.services.install_starter(&p, "learning-basics-v1", &key, None).await.unwrap();
    let replay = st.services.install_starter(&p, "learning-basics-v1", &key, None).await.unwrap();
    assert_eq!(first, replay);
    assert!(st.services.install_starter(&p, "learning-basics-v1", &"k".repeat(129), None).await.is_err());
    st.services.operations.close();
    st.services.operations.wait().await;
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn p31_optional_mcp_flags_keep_legacy_publication_and_strict_defaults() {
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let p = memoswish_core::Principal::local_owner("single_user");
    let deck = st
        .services
        .create_deck(
            &p,
            memoswish_content::NewDeck {
                title: "Optional flags".into(),
                description: String::new(),
                language: "en".into(),
                tags: vec![],
            },
        )
        .await
        .unwrap();
    let app = crate::auth_defenses::test_router(st.clone());
    for tool in ["card_upsert", "material_slice"] {
        for lifecycle in [None, Some(Value::Null), Some(json!(false)), Some(json!(true))] {
            for publish in [None, Some(Value::Null), Some(json!(false)), Some(json!(true))] {
                let mut args = if tool == "card_upsert" {
                    json!({"auto_tts":false,"cards":[{"deck_id":deck.id,"front":{"title":"Agent output"}}]})
                } else {
                    json!({"auto_tts":false,"deck_id":deck.id,"text":"Term :: Definition","commit":true})
                };
                if let Some(value) = &lifecycle {
                    args["content_lifecycle"] = value.clone();
                }
                if let Some(value) = &publish {
                    args["publish"] = value.clone();
                }
                let (status, _, bytes) = send(
                    &app,
                    post_json(
                        "/mcp",
                        &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}}),
                        None,
                    ),
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                let response: Value = serde_json::from_slice(&bytes).unwrap();
                assert!(response["error"].is_null(), "{response}");
                assert_ne!(response["result"]["isError"], true, "{response}");
                let result: Value =
                    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
                let cards = if tool == "card_upsert" { &result } else { &result["cards"] };
                let cards: Vec<Card> = serde_json::from_value(cards.clone()).unwrap();
                assert_eq!(cards.len(), 1);
                let strict = lifecycle == Some(json!(true));
                assert_eq!(
                    memoswish_core::content_lifecycle::published(&cards[0]),
                    !strict || publish == Some(json!(true))
                );
                assert_eq!(cards[0].content.is_some(), strict);
            }
        }
    }
    st.services.operations.close();
    st.services.operations.wait().await;
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn p31_authoring_routes_share_fail_closed_admission_before_decoding() {
    struct Blocked;
    #[async_trait::async_trait]
    impl memoswish_core::rate_limit::RateLimiter for Blocked {
        async fn check(&self, _: &str, _: f64) -> memoswish_core::CoreResult<()> {
            Err(memoswish_core::CoreError::Unavailable("admission backend unavailable".into()))
        }
    }
    let (mut st, root) = app_state(DeploymentMode::SingleUser).await;
    st.services.limiter = std::sync::Arc::new(Blocked);
    let app = crate::auth_defenses::test_router(st.clone());
    for path in [
        "/v1/content/cards",
        "/v1/content/decks",
        "/v1/content/decks/missing",
        "/v1/content/cards/missing/publication",
        "/v1/content/cards/missing/reports",
        "/v1/content/starters/learning-basics-v1/install",
        "/v1/content/import",
        "/v1/content/import/apkg",
    ] {
        let (status, _, bytes) = send(&app, post_json(path, &json!({}), None)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["code"], "temporarily_unavailable");
    }
    crate::runtime::drain_background(&st).await;
    drop(app);
    crate::runtime::cleanup_test_app(root, &[&st]).await;
}
