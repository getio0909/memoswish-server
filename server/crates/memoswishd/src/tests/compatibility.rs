//! 历史请求经当前真实路由，响应再交给冻结 Dart 消费者。
use super::*;

#[path = "compatibility_boundaries.rs"]
mod boundaries;

fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

async fn wire(minor: u64) {
    let (app, st, dir) = app(DeploymentMode::SingleUser).await;
    let id = format!("2.{minor}.0");
    let mut responses = serde_json::Map::new();
    for (name, uri) in [("server-info", "/v1/server-info"), ("deck", "/v1/decks")] {
        let (status, _, bytes) = send(&app, get(uri)).await;
        assert_eq!(status, StatusCode::OK);
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        responses.insert(name.into(), if name == "deck" { value[0].clone() } else { value });
    }
    let uri = if minor >= 5 { "/v1/feed?request_id=compatibility&limit=1" } else { "/v1/feed?limit=1" };
    let (status, _, bytes) = send(&app, get(uri)).await;
    assert_eq!(status, StatusCode::OK);
    let page: Value = serde_json::from_slice(&bytes).unwrap();
    if minor >= 5 {
        assert_eq!(send(&app, get(uri)).await.2, bytes, "lost page response must replay");
    }
    responses.insert("feed-page".into(), page.clone());
    responses.insert("card".into(), page["items"][0]["card"].clone());
    let mut batch = if let Ok(path) = crate::test_environment::var("MEMOSWISH_COMPAT_REQUESTS") {
        let requests: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        requests[&id]["feedback"].clone()
    } else {
        serde_json::from_str(
            &std::fs::read_to_string(
                root().join(format!("compatibility/history/{id}/protocol/fixtures/feedback-batch.json")),
            )
            .unwrap(),
        )
        .unwrap()
    };
    batch["session_id"] = page["session_id"].clone();
    batch["events"].as_array_mut().unwrap().truncate(1);
    batch["events"][0]["card_id"] = page["items"][0]["card"]["id"].clone();
    batch["events"][0]["slot"] = page["items"][0]["slot"].clone();
    batch["events"][0]["event_id"] = json!(format!("compatibility-{minor}"));
    // 会话和时间绑定本次投递，保留历史编码器的字段集合与未知归因。
    batch["sent_at"] = page["generated_at"].clone();
    batch["events"][0]["shown_at"] = page["generated_at"].clone();
    assert!(batch["events"][0].get("delivery_id").is_none(), "historical unknown attribution must remain unknown");
    let before: LearningStats = serde_json::from_slice(&send(&app, get("/v1/stats")).await.2).unwrap();
    let (status, _, bytes) = send(&app, post_json("/v1/feedback", &batch, None)).await;
    assert_eq!(status, StatusCode::OK);
    let ack: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ack["accepted"], 1);
    responses.insert("feedback-ack".into(), ack);
    let (_, _, bytes) = send(&app, post_json("/v1/feedback", &batch, None)).await;
    let duplicate: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(duplicate["duplicates"], 1, "lost feedback response must not apply twice");
    let after: LearningStats = serde_json::from_slice(&send(&app, get("/v1/stats")).await.2).unwrap();
    assert_eq!(
        after.total_exposures,
        before.total_exposures + 1,
        "duplicate feedback cannot apply a second learning effect"
    );
    let (status, _, bytes) = send(&app, get("/v1/usage")).await;
    assert_eq!(status, StatusCode::OK);
    let usage: memoswish_auth::quota::UsageSnapshot = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(usage.tenant_id, "local");
    assert!(!usage.metrics.is_empty());
    let (status, _, bytes) =
        send(&app, post_json("/v1/decks", &json!({"title":"Compatibility","language":"en"}), None)).await;
    assert_eq!(status, StatusCode::CREATED);
    let deck: Deck = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(deck.title, "Compatibility");
    let (status, _, bytes) = send(&app, get("/v1/cards/unknown")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    responses.insert("api-error".into(), serde_json::from_slice(&bytes).unwrap());
    let (auth_app, auth_st, auth_dir) = super::app(DeploymentMode::MultiTenant).await;
    let mut old_requests: Value = if let Ok(path) = crate::test_environment::var("MEMOSWISH_COMPAT_REQUESTS") {
        serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()[&id].clone()
    } else {
        json!({"register": {"email":"learner@example.com","password":"fixture-password","display_name":"Learner","tenant_name":"Workspace"},
            "login": {"email":"learner@example.com","password":"fixture-password"}})
    };
    if minor >= 15 && old_requests.get("password-reset").is_none() {
        old_requests["password-reset"] = json!({"email":"learner@example.com"});
    }
    let (status, _, bytes) = send(&auth_app, post_json("/v1/auth/register", &old_requests["register"], None)).await;
    assert_eq!(status, StatusCode::OK, "historical register must remain accepted");
    let registered: Value = serde_json::from_slice(&bytes).unwrap();
    let (status, _, bytes) = send(&auth_app, post_json("/v1/auth/login", &old_requests["login"], None)).await;
    assert_eq!(status, StatusCode::OK);
    let authenticated: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(authenticated["user"]["user_id"], registered["user"]["user_id"]);
    responses.insert("auth-response".into(), authenticated);
    if minor >= 20 {
        let command = old_requests.get("favorite").cloned().unwrap_or_else(
            || json!({"operation_id":"compatibility-favorite","desired_state":false,"expected_revision":0}),
        );
        let card = page["items"][0]["card"]["id"].as_str().unwrap();
        let (status, _, bytes) = send(&app, post_json(&format!("/v1/library/{card}/favorite"), &command, None)).await;
        assert_eq!(status, StatusCode::OK);
        responses.insert("favorite-state".into(), serde_json::from_slice(&bytes).unwrap());
        for (uri, key) in [("/v1/library?limit=1", "library-page"), ("/v1/history?limit=1", "review-history-page")] {
            let (status, _, bytes) = send(&app, get(uri)).await;
            assert_eq!(status, StatusCode::OK);
            responses.insert(key.into(), serde_json::from_slice(&bytes).unwrap());
        }
    }
    if minor >= 14 {
        let command = old_requests
            .get("explain")
            .cloned()
            .unwrap_or_else(|| json!({"request_id":"compatibility-explanation","locale":"en-US"}));
        let card = page["items"][0]["card"]["id"].as_str().unwrap();
        let (status, _, bytes) = send(&app, post_json(&format!("/v1/cards/{card}/explain"), &command, None)).await;
        assert_eq!(status, StatusCode::OK);
        let explanation: CardExplanation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(explanation.operation.as_ref().unwrap().request_id, "compatibility-explanation");
        responses.insert("card-explanation".into(), serde_json::from_slice(&bytes).unwrap());
        let (status, _, bytes) = send(&app, get("/v1/explanations/compatibility-explanation")).await;
        assert_eq!(status, StatusCode::OK);
        responses.insert("explain-operation".into(), serde_json::from_slice(&bytes).unwrap());
        let evidence = old_requests
            .get("explain_reconcile")
            .cloned()
            .unwrap_or_else(|| json!({"input_tokens":10,"output_tokens":2}));
        let (status, _, bytes) =
            send(&app, post_json("/v1/explanations/compatibility-explanation/reconcile", &evidence, None)).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["code"], "conflict");
    }
    if minor >= 15 {
        let (status, _, bytes) =
            send(&auth_app, post_json("/v1/auth/password/reset", &old_requests["password-reset"], None)).await;
        assert_eq!(status, StatusCode::OK);
        responses.insert("password-request-accepted".into(), serde_json::from_slice(&bytes).unwrap());
        let (status, _, bytes) = send(&auth_app, post_json("/v1/auth/sessions", &old_requests["login"], None)).await;
        assert_eq!(status, StatusCode::OK);
        let session: Value = serde_json::from_slice(&bytes).unwrap();
        let request = Request::get("/v1/account/password")
            .header(header::AUTHORIZATION, format!("Bearer {}", session["access_token"].as_str().unwrap()))
            .body(Body::empty())
            .unwrap();
        let (status, _, bytes) = send(&auth_app, request).await;
        assert_eq!(status, StatusCode::OK);
        responses.insert("password-status".into(), serde_json::from_slice(&bytes).unwrap());
        if minor >= 19 {
            let request = Request::get("/v1/account/access/sessions?limit=1")
                .header(header::AUTHORIZATION, format!("Bearer {}", session["access_token"].as_str().unwrap()))
                .body(Body::empty())
                .unwrap();
            let (status, _, bytes) = send(&auth_app, request).await;
            assert_eq!(status, StatusCode::OK);
            let page: memoswish_protocol::AccessPage = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(page.items.len(), 1);
            assert_eq!(page.items[0].current, Some(true));
            responses.insert("access-page".into(), serde_json::from_slice(&bytes).unwrap());
            responses.insert("access-summary".into(), serde_json::to_value(&page.items[0]).unwrap());
        }
    }
    if minor >= 16 {
        let mut policy = memoswish_protocol::examples::sample_privacy_policy();
        policy.hosted = false;
        policy.purpose_versions.insert("diagnostics".into(), "diagnostics-v1".into());
        let st = AppState::build(Config { data_dir: dir.join("diagnostics"), privacy: policy, ..Default::default() })
            .await
            .unwrap();
        let principal = st.services.auth.authenticate(None).await.unwrap();
        let diagnostic_app = crate::api::router(st.clone());
        let mut report: Value = if let Ok(path) = crate::test_environment::var("MEMOSWISH_COMPAT_REQUESTS") {
            serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()[&id]["diagnostic"].clone()
        } else {
            serde_json::from_slice(
                &std::fs::read(
                    root().join(format!("compatibility/history/{id}/protocol/fixtures/diagnostic-report.json")),
                )
                .unwrap(),
            )
            .unwrap()
        };
        report["captured_at_ms"] = json!(chrono::Utc::now().timestamp_millis() - 1000);
        assert_eq!(
            send(&diagnostic_app, post_json("/v1/diagnostics/reports", &report, None)).await.0,
            StatusCode::FORBIDDEN
        );
        for (kind, version, value) in [
            ("notice", "notice-v1", ""),
            ("terms", "terms-v1", ""),
            ("age", "notice-v1", "example-region"),
            ("diagnostics", "diagnostics-v1", ""),
        ] {
            let state = st.services.privacy_state(&principal).await.unwrap();
            st.services
                .update_privacy(
                    &principal,
                    &memoswish_protocol::PrivacyUpdate {
                        expected_revision: state.revision,
                        kind: kind.into(),
                        version: version.into(),
                        value: value.into(),
                        decision: true,
                    },
                )
                .await
                .unwrap();
        }
        report["privacy_revision"] = json!(st.services.privacy_state(&principal).await.unwrap().revision);
        let (status, _, bytes) = send(&diagnostic_app, post_json("/v1/diagnostics/reports", &report, None)).await;
        assert_eq!(status, StatusCode::OK);
        responses.insert("diagnostic-receipt".into(), serde_json::from_slice(&bytes).unwrap());
        crate::runtime::drain_test_state(&st).await;
    }
    if minor >= 22 {
        let inputs: Value = if let Ok(path) = crate::test_environment::var("MEMOSWISH_COMPAT_REQUESTS") {
            serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()[&id].clone()
        } else {
            json!({"retention": memoswish_protocol::RetentionCommand {expected_revision:0,desired_retention:Some(Some(0.85))}, "card-control": memoswish_protocol::CardControlCommand {expected_revision:0,action:memoswish_protocol::CardControlAction::Bury}})
        };
        let (status, _, bytes) = send(&app, post_json("/v1/learning/preferences", &inputs["retention"], None)).await;
        assert_eq!(status, StatusCode::OK);
        responses.insert("learner-preferences".into(), serde_json::from_slice(&bytes).unwrap());
        let card_id = page["items"][0]["card"]["id"].as_str().unwrap();
        let path = format!("/v1/learning/cards/{card_id}/control");
        let (status, _, bytes) = send(&app, post_json(&path, &inputs["card-control"], None)).await;
        assert_eq!(status, StatusCode::OK);
        responses.insert("learner-card-control".into(), serde_json::from_slice(&bytes).unwrap());
        let (status, _, bytes) = send(&app, get("/v1/learning/hidden")).await;
        assert_eq!(status, StatusCode::OK);
        responses.insert("hidden-cards-page".into(), serde_json::from_slice(&bytes).unwrap());
    }
    if minor >= 17 {
        let mut save = if let Ok(path) = crate::test_environment::var("MEMOSWISH_COMPAT_REQUESTS") {
            serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()[&id]["author-save"].clone()
        } else {
            memoswish_protocol::examples::all_fixtures().into_iter().find(|(name, _)| *name == "card-save").unwrap().1
        };
        save["card"]["deck_id"] = json!(deck.id);
        let (status, _, bytes) = send(&app, post_json("/v1/content/cards", &save, None)).await;
        assert_eq!(status, StatusCode::OK);
        let card: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(card["content"]["publication"], "draft");
        responses.insert("content-metadata".into(), card["content"].clone());
        responses.insert("content-provenance".into(), card["content"]["provenance"].clone());
        let mut publish = if let Ok(path) = crate::test_environment::var("MEMOSWISH_COMPAT_REQUESTS") {
            serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()[&id]["author-publish"]
                .clone()
        } else {
            json!({"expected_revision":1,"publish":true})
        };
        publish["expected_revision"] = card["revision"].clone();
        let uri = format!("/v1/content/cards/{}/publication", card["id"].as_str().unwrap());
        let (status, _, bytes) = send(&app, post_json(&uri, &publish, None)).await;
        assert_eq!(status, StatusCode::OK);
        let published: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(published["content"]["publication"], "published");
        let mut report = if let Ok(path) = crate::test_environment::var("MEMOSWISH_COMPAT_REQUESTS") {
            serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()[&id]["author-report"]
                .clone()
        } else {
            json!({"observed_revision":1,"text":"Correction request","sources":[]})
        };
        report["observed_revision"] = card["revision"].clone();
        let (status, _, bytes) = send(
            &app,
            post_json(&format!("/v1/content/cards/{}/reports", card["id"].as_str().unwrap()), &report, None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        responses.insert("content-report".into(), serde_json::from_slice(&bytes).unwrap());
        let (_, _, bytes) =
            send(&app, get(&format!("/v1/content/cards/{}/revisions", card["id"].as_str().unwrap()))).await;
        responses.insert("card-revision".into(), serde_json::from_slice::<Value>(&bytes).unwrap()[0].clone());
        let (_, _, bytes) = send(&app, get("/v1/content/starters")).await;
        responses.insert("starter-deck".into(), serde_json::from_slice::<Value>(&bytes).unwrap()[0].clone());
    }
    crate::runtime::cleanup_test_app(auth_dir, &[&auth_st]).await;
    if minor >= 13 {
        let pack = if let Ok(path) = crate::test_environment::var("MEMOSWISH_COMPAT_REQUESTS") {
            let encoded: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            encoded[&id]["portable-pack"].clone()
        } else {
            serde_json::from_str(
                &std::fs::read_to_string(
                    root().join("compatibility/history/2.13.0/protocol/fixtures/portable-deck-pack.json"),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let (status, _, bytes) = send(&app, post_json("/v1/decks/import/portable", &pack, None)).await;
        assert_eq!(status, StatusCode::CREATED);
        let deck: Deck = serde_json::from_slice(&bytes).unwrap();
        let (status, _, bytes) = send(&app, get(&format!("/v1/decks/{}/export/portable", deck.id))).await;
        assert_eq!(status, StatusCode::OK);
        let returned: Value = serde_json::from_slice(&bytes).unwrap();
        // 冻结输入的图片引用多于音频，最短包内身份依次为 A、B；其他字段必须逐项相等。
        let mut expected_media = pack["media"].clone();
        expected_media[0]["id"] = json!("A");
        expected_media[1]["id"] = json!("B");
        assert_eq!(returned["media"], expected_media);
        let portable: memoswish_protocol::PortableDeckPack = serde_json::from_value(returned.clone()).unwrap();
        memoswish_content::deckpack::validate(&portable).unwrap();
        responses.insert("portable-deck-pack".into(), returned);
    }
    if let Ok(path) = crate::test_environment::var("MEMOSWISH_COMPAT_RESPONSES") {
        // 每个检查点独有输出，测试并行时不共享文件写入。
        std::fs::write(std::path::Path::new(&path).join(format!("{id}.json")), serde_json::to_vec(&responses).unwrap())
            .unwrap();
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

macro_rules! cases { ($($name:ident => $minor:expr),*) => { $(
    #[tokio::test] async fn $name() { wire($minor).await; }
)* }; }
cases!(compatibility_wire_2_1 => 1, compatibility_wire_2_2 => 2, compatibility_wire_2_3 => 3,
    compatibility_wire_2_4 => 4, compatibility_wire_2_5 => 5, compatibility_wire_2_6 => 6,
    compatibility_wire_2_7 => 7, compatibility_wire_2_8 => 8, compatibility_wire_2_9 => 9,
    compatibility_wire_2_10 => 10, compatibility_wire_2_11 => 11, compatibility_wire_2_12 => 12, compatibility_wire_2_13 => 13, compatibility_wire_2_14 => 14, compatibility_wire_2_15 => 15, compatibility_wire_2_16 => 16, compatibility_wire_2_17 => 17, compatibility_wire_2_18 => 18, compatibility_wire_2_19 => 19, compatibility_wire_2_20 => 20, compatibility_wire_2_21 => 21, compatibility_wire_2_22 => 22);

#[test]
fn compatibility_adapter_requests_use_actual_producer_types() {
    let deck: memoswish_content::NewDeck =
        serde_json::from_value(json!({"title":"Compatibility","language":"en","future":true})).unwrap();
    assert_eq!(deck.title, "Compatibility");
    assert!(serde_json::from_value::<memoswish_content::NewDeck>(json!({"title":42,"language":"en"})).is_err());
    let options: memoswish_content::apkg::ApkgOptions = serde_json::from_value(json!({})).unwrap();
    assert!(options.title.is_none() && options.language.is_none());
    let report = memoswish_content::apkg::ApkgReport {
        deck: memoswish_protocol::examples::sample_deck(),
        notes_read: 1,
        cards_imported: 1,
        media_imported: 0,
        audio_omitted: 0,
        warnings: vec![],
        warnings_truncated: false,
    };
    assert!(serde_json::to_value(report).unwrap()["warnings"].is_array());
    let metric: memoswish_auth::quota::UsageMetricEntry =
        serde_json::from_value(json!({"metric":"tts_chars","used":3,"limit":null})).unwrap();
    assert_eq!(metric.held, 0);
    assert_eq!(metric.uncertain, 0);
    assert!(
        serde_json::from_value::<memoswish_auth::quota::UsageMetricEntry>(
            json!({"metric":"tts_chars","used":-1,"limit":null})
        )
        .is_err()
    );
    let snapshot = memoswish_auth::quota::UsageSnapshot {
        tenant_id: "tenant".into(),
        plan: "free".into(),
        period: "2026-11".into(),
        metrics: vec![metric],
    };
    assert_eq!(serde_json::to_value(snapshot).unwrap()["metrics"][0]["held"], 0);
}
