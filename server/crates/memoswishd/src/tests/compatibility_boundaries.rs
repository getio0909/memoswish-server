//! 真实公开生产者与适配器参数的定向兼容回归。
use super::*;

fn assert_keys(value: &Value, expected: &[&str]) {
    let actual: std::collections::BTreeSet<_> = value.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(actual, expected.iter().copied().collect(), "export field whitelist changed");
}

#[tokio::test]
async fn compatibility_legacy_export_whitelists_and_excludes_credentials() {
    let dir = std::env::temp_dir().join(format!("memoswish-compat-export-{}", memoswish_core::ids::new_id()));
    let st = AppState::build(Config {
        mode: DeploymentMode::MultiTenant,
        data_dir: dir.clone(),
        registration_open: true,
        seed_demo: false,
        ..Config::default()
    })
    .await
    .unwrap();
    let owner = st
        .services
        .auth
        .register(&memoswish_protocol::RegisterRequest {
            email: "export@example.com".into(),
            password: "compatibility-password".into(),
            display_name: "Export".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let p = st.services.auth.authenticate(Some(&owner.access_token)).await.unwrap();
    let member = memoswish_core::repo::UserRecord {
        id: memoswish_core::ids::new_id(),
        tenant_id: p.tenant_id.clone(),
        email: "member@example.com".into(),
        display_name: "Member".into(),
        password_hash: "COMPAT_PASSWORD_SENTINEL".into(),
        role: memoswish_core::Role::Learner,
        created_at: chrono::Utc::now(),
    };
    st.repo.insert_user(&member).await.unwrap();
    let member_auth = st.services.auth.interactive_response(&member).await.unwrap();
    let full = st.services.auth.create_api_token(&p, "full", vec!["account:export".into()], None).await.unwrap();
    let summary = st
        .services
        .auth
        .create_api_token(&p, "summary", vec!["feed:read".into(), "content:read".into()], None)
        .await
        .unwrap();
    let opaque = st
        .services
        .auth
        .login_session(&memoswish_protocol::LoginRequest {
            email: "export@example.com".into(),
            password: "compatibility-password".into(),
        })
        .await
        .unwrap();
    let user = st.repo.get_user(&p.tenant_id, &p.user_id).await.unwrap().unwrap();
    let pool = sqlx::SqlitePool::connect(&st.config.database_url()).await.unwrap();
    let hashes: Vec<String> = sqlx::query_scalar("SELECT token_hash FROM api_tokens").fetch_all(&pool).await.unwrap();
    assert_eq!(hashes.len(), 2);
    for (user, version) in [(&p.user_id, "owner-purpose"), (&member.id, "member-purpose")] {
        let record = memoswish_protocol::PrivacyRecord {
            kind: "external_ai".into(),
            version: version.into(),
            decision: false,
            value: String::new(),
            recorded_at: 1,
            evidence: "self_assertion".into(),
        };
        sqlx::query("INSERT INTO privacy_purposes(tenant_id,user_id,body) VALUES($1,$2,$3)")
            .bind(&p.tenant_id)
            .bind(user)
            .bind(serde_json::to_string(&vec![record]).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO learner_preferences(tenant_id,user_id,desired_retention) VALUES($1,$2,$3)")
            .bind(&p.tenant_id)
            .bind(user)
            .bind(if user == &p.user_id { 0.8 } else { 0.7 })
            .execute(&pool)
            .await
            .unwrap();
    }
    let deck = memoswish_protocol::examples::sample_deck();
    let card = memoswish_protocol::examples::sample_card();
    st.repo.insert_deck_with_cards(&p.tenant_id, &deck, std::slice::from_ref(&card)).await.unwrap();
    let member_principal = st.services.auth.authenticate(Some(&member_auth.access_token)).await.unwrap();
    for (principal, operation) in [(&p, "owner-favorite"), (&member_principal, "member-favorite")] {
        st.services
            .set_favorite(
                principal,
                &card.id,
                &memoswish_protocol::FavoriteCommand {
                    operation_id: operation.into(),
                    desired_state: true,
                    expected_revision: 0,
                },
            )
            .await
            .unwrap();
    }
    let app = crate::auth_defenses::test_router(st.clone());
    let summary_keys = ["tenant_id", "user", "stats", "decks", "usage", "exported_at"];
    let tables: &[(&str, &[&str])] = &[
        ("privacy_purposes", &["user_id", "body"]),
        ("diagnostic_reports", &["report_id", "body", "created_at_ms", "expires_at_ms"]),
        ("users", &["id", "tenant_id", "email", "display_name", "role", "created_at"]),
        ("api_tokens", &["id", "name", "user_id", "scopes", "created_at", "expires_at", "last_used_at", "revoked"]),
        ("usage_counters", &["metric", "period", "amount"]),
        ("content_imports", &["id", "user_id", "outcome", "result"]),
        ("content_reports", &["user_id", "body"]),
        ("personal_favorites", &["user_id", "card_id", "starred", "revision"]),
        ("favorite_operations", &["user_id", "operation_id", "command", "receipt"]),
        (
            "memory_states",
            &[
                "user_id",
                "card_id",
                "stability",
                "difficulty",
                "reps",
                "lapses",
                "exposures",
                "last_review",
                "due",
                "starred",
                "last_rating",
            ],
        ),
        ("feedback_events", &["user_id", "session_id", "rating", "body", "received_at", "application_provenance"]),
        ("feed_sessions", &["id", "user_id", "next_slot", "recent_card_ids", "created_at", "updated_at"]),
        ("feed_deliveries", &["user_id", "session_id", "slot", "delivery_id", "body"]),
        ("learner_preferences", &["user_id", "desired_retention", "revision", "epoch", "issuance_seq"]),
        (
            "learner_card_controls",
            &["user_id", "card_id", "suspended", "buried_until_ms", "revision", "last_issued_seq"],
        ),
        ("oidc_attempts", &["provider", "user_id", "expires_at"]),
        ("oidc_handoffs", &["provider", "user_id", "expires_at"]),
        ("recent_authentication", &["user_id", "expires_at"]),
        ("auth_browser_sessions", &["user_id", "expires_at", "auth_time", "auth_method"]),
        ("oauth_grants", &["id", "user_id", "client_id", "expires_at", "revoked", "metadata"]),
    ];
    for (token, is_full, is_owner) in [
        (&summary.plaintext, false, true),
        (&full.plaintext, true, true),
        (&owner.access_token, true, true),
        (&member_auth.access_token, true, false),
    ] {
        let (status, _, body) = send(
            &app,
            Request::get("/v1/account/export")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let data: Value = serde_json::from_slice(&body).unwrap();
        let mut keys = summary_keys.to_vec();
        if is_full {
            keys.extend([
                "tenant",
                "scope",
                "assets",
                "cards",
                "content_revisions",
                "bgm_tracks",
                "federated_identities",
            ]);
            keys.extend(["identity_status", "oauth_token_metadata", "oauth_code_metadata", "oauth_request_metadata"]);
            keys.extend(tables.iter().map(|(name, _)| *name));
        }
        assert_keys(&data, &keys);
        assert_keys(&data["user"], &["user_id", "tenant_id", "display_name", "role"]);
        if is_full {
            if is_owner {
                let mut expected: Value = serde_json::from_str(&serde_json::to_string(&card).unwrap()).unwrap();
                memoswish_core::assets::clear_historical_delivery_urls(&mut expected);
                assert_eq!(data["content_revisions"], json!([expected]));
            } else {
                assert_eq!(data["content_revisions"], json!([]));
            }
            assert_eq!(data["content_reports"], json!([]));
            assert_eq!(data["scope"], if is_owner { "tenant" } else { "member" });
            assert_eq!(data["privacy_purposes"].as_array().unwrap().len(), 1);
            assert_eq!(
                data["privacy_purposes"][0]["user_id"],
                if is_owner { p.user_id.as_str() } else { member.id.as_str() }
            );
            assert_eq!(
                data["privacy_purposes"][0]["body"][0]["version"],
                if is_owner { "owner-purpose" } else { "member-purpose" }
            );
            assert_eq!(data["users"].as_array().unwrap().len(), if is_owner { 2 } else { 1 });
            assert_eq!(data["api_tokens"].as_array().unwrap().len(), if is_owner { 2 } else { 0 });
            let preferences = data["learner_preferences"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let retention = row["desired_retention"].as_str().unwrap().parse::<f64>().unwrap();
                    (row["user_id"].as_str().unwrap(), retention)
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            let mut expected = std::collections::BTreeMap::from([(member.id.as_str(), 0.7)]);
            if is_owner {
                expected.insert(p.user_id.as_str(), 0.8);
            }
            assert_eq!(preferences, expected);
            if !is_owner {
                assert_eq!(data["users"][0]["id"], member.id);
                assert!(!data.to_string().contains("export@example.com"));
            }
            assert_eq!(data["personal_favorites"].as_array().unwrap().len(), 1);
            assert_eq!(
                data["personal_favorites"][0]["user_id"],
                if is_owner { p.user_id.as_str() } else { member.id.as_str() }
            );
            assert_eq!(data["favorite_operations"].as_array().unwrap().len(), 1);
            assert_eq!(
                data["favorite_operations"][0]["operation_id"],
                if is_owner { "owner-favorite" } else { "member-favorite" }
            );
            for (table, columns) in tables {
                for row in data[table].as_array().unwrap() {
                    assert_keys(row, columns);
                }
            }
        }
        let raw = String::from_utf8(body).unwrap();
        for secret in [
            "password_hash",
            "token_hash",
            "access_hash",
            "refresh_hash",
            "assurance_hash",
            "csrf_hash",
            "encrypted",
            "COMPAT_PASSWORD_SENTINEL",
            &user.password_hash,
            &full.plaintext,
            &summary.plaintext,
            &owner.access_token,
            &member_auth.access_token,
            &opaque.access_token,
            &opaque.refresh_token,
        ]
        .into_iter()
        .chain(hashes.iter().map(String::as_str))
        {
            assert!(!raw.contains(secret), "legacy export contains a credential field or sentinel");
        }
    }
    let (status, _, body) = send(
        &app,
        post_json(
            "/v1/workspace/transfer-ownership",
            &json!({"successor_user_id":member.id}),
            Some(&owner.access_token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
    assert_eq!(st.repo.get_user(&p.tenant_id, &member.id).await.unwrap().unwrap().role, memoswish_core::Role::Owner);
    pool.close().await;
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn compatibility_bgm_and_supplied_queries_reach_actual_producers() {
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let app = crate::auth_defenses::test_router(st.clone());
    let (status, headers, body) = send(&app, get("/v1/bgm")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    let raw: Value = serde_json::from_slice(&body).unwrap();
    let tracks: Vec<memoswish_protocol::BgmTrack> = serde_json::from_value(raw.clone()).unwrap();
    assert!(!tracks.is_empty());
    assert_eq!(serde_json::from_str::<Value>(&serde_json::to_string(&tracks).unwrap()).unwrap(), raw);
    for track in &tracks {
        assert!(!track.id.is_empty() && !track.title.is_empty());
        assert!(track.duration_ms > 0 && track.asset.bytes > 0);
        assert!(track.asset.url.starts_with("/assets/shared/"));
        assert_eq!(track.asset.sha256.len(), 64);
    }
    let (status, _, body) = send(&app, get("/v1/usage")).await;
    assert_eq!(status, StatusCode::OK);
    let usage: memoswish_auth::quota::UsageSnapshot = serde_json::from_slice(&body).unwrap();
    assert_eq!(usage.tenant_id, "local");
    assert_eq!(usage.metrics.len(), 3);

    let (status, _, body) = send(&app, get("/v1/feed?limit=1")).await;
    assert_eq!(status, StatusCode::OK);
    let page: FeedPage = serde_json::from_slice(&body).unwrap();
    let card = &page.items[0].card;
    let (status, _, body) = send(&app, get(&format!("/v1/cards/{}", card.id))).await;
    assert_eq!(status, StatusCode::OK);
    // 同一卡片在 feed 与内容端点使用不同授权 surface，其余字段必须完整保持。
    let mut expected = card.clone();
    expected.tts.as_mut().unwrap().audio.url =
        expected.tts.as_ref().unwrap().audio.url.replace("surface=feed", "surface=content");
    let bgm = &mut expected.bgm.as_mut().unwrap().track.asset;
    bgm.url = bgm.url.replace("surface=feed", "surface=content");
    assert_eq!(serde_json::from_slice::<Card>(&body).unwrap(), expected);
    let (status, _, body) = send(&app, get(&format!("/v1/decks/{}/cards", card.deck_id))).await;
    assert_eq!(status, StatusCode::OK);
    let all: Vec<Card> = serde_json::from_slice(&body).unwrap();
    assert!(all.len() >= 2);
    let (status, _, body) = send(&app, get(&format!("/v1/decks/{}/cards?limit=1&offset=1", card.deck_id))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_slice::<Vec<Card>>(&body).unwrap(), all[1..2]);
    let (status, _, body) = send(&app, get(&format!("/v1/decks/{}/cards?limit=1&offset=9999", card.deck_id))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(serde_json::from_slice::<Vec<Card>>(&body).unwrap().is_empty());
    assert_eq!(
        send(&app, get(&format!("/v1/decks/{}/cards?limit=invalid&offset=1", card.deck_id))).await.0,
        StatusCode::BAD_REQUEST
    );

    let mut feedback = memoswish_protocol::examples::sample_feedback_batch();
    feedback.session_id = page.session_id.clone();
    feedback.events.truncate(1);
    let event = &mut feedback.events[0];
    event.card_id = card.id.clone();
    event.slot = page.items[0].slot;
    event.delivery_id = page.items[0].delivery_id.clone();
    event.shown_at = page.generated_at;
    event.double_tapped = true;
    let (status, _, body) = send(&app, post_json("/v1/feedback", &serde_json::to_value(feedback).unwrap(), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_slice::<FeedbackAck>(&body).unwrap().accepted, 1);
    for (deck, expected) in [(card.deck_id.as_str(), 1), ("unknown-deck", 0)] {
        let (status, _, body) = send(&app, get(&format!("/v1/stats?deck_id={deck}"))).await;
        assert_eq!(status, StatusCode::OK);
        let stats: LearningStats = serde_json::from_slice(&body).unwrap();
        assert_eq!(stats.seen_cards, expected);
        assert_eq!(stats.starred_cards, expected);
        let (status, _, body) = send(&app, get(&format!("/v1/starred?deck_id={deck}"))).await;
        assert_eq!(status, StatusCode::OK);
        let starred: Vec<Card> = serde_json::from_slice(&body).unwrap();
        assert_eq!(starred.len(), expected as usize);
        if expected == 1 {
            assert_eq!(starred[0].id, card.id);
        }
    }
    crate::runtime::drain_background(&st).await;
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn compatibility_catch_all_methods_keep_error_contract() {
    let (st, dir) = app_state(DeploymentMode::SingleUser).await;
    let app = crate::auth_defenses::test_router(st.clone());
    for method in ["GET", "POST", "DELETE"] {
        let (status, headers, body) =
            send(&app, Request::builder().method(method).uri("/v1/compatibility/unknown").body(Body::empty()).unwrap())
                .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(headers[header::CONTENT_TYPE], "application/json");
        let error: memoswish_protocol::ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.code, "not_found");
        assert!(!error.message.is_empty());
    }
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn compatibility_session_routes_issue_rotate_list_and_revoke() {
    use memoswish_protocol::{MembershipSummary, SessionInfo, SessionResponse, UserProfile};
    let (app, st, dir) = app(DeploymentMode::MultiTenant).await;
    let registration =
        json!({"email":"compatibility@example.com","password":"compatibility-password","display_name":"Compatibility"});
    let (status, headers, body) = send(&app, post_json("/v1/auth/sessions/register", &registration, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let registered: SessionResponse = serde_json::from_slice(&body).unwrap();
    assert!(registered.workspace.is_none());
    let (status, headers, body) = send(
        &app,
        post_json(
            "/v1/auth/sessions",
            &json!({"email":registration["email"],"password":registration["password"]}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let login: SessionResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(login.account, registered.account);
    let (status, headers, body) = send(
        &app,
        Request::get("/v1/account/memberships")
            .header(header::AUTHORIZATION, format!("Bearer {}", login.access_token))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let memberships: Vec<MembershipSummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(memberships.len(), 1);
    let (status, headers, body) = send(
        &app,
        post_json(
            "/v1/auth/sessions/workspace",
            &json!({"tenant_id":memberships[0].tenant_id}),
            Some(&login.access_token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let workspace: SessionResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(workspace.workspace.as_ref().unwrap().tenant_id, memberships[0].tenant_id);
    let (status, _, body) = send(
        &app,
        Request::get("/v1/me")
            .header(header::AUTHORIZATION, format!("Bearer {}", workspace.access_token))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_slice::<UserProfile>(&body).unwrap().user_id, login.account.user_id);
    let (status, headers, body) =
        send(&app, post_json("/v1/auth/sessions/refresh", &json!({"refresh_token":workspace.refresh_token}), None))
            .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let rotated: SessionResponse = serde_json::from_slice(&body).unwrap();
    assert_ne!(rotated.access_token, workspace.access_token);
    assert_eq!(rotated.session_id, workspace.session_id);
    let (status, headers, body) = send(
        &app,
        Request::get("/v1/auth/sessions")
            .header(header::AUTHORIZATION, format!("Bearer {}", login.access_token))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    let sessions: Vec<SessionInfo> = serde_json::from_slice(&body).unwrap();
    assert!(sessions.iter().any(|s| s.session_id == rotated.session_id && !s.revoked));
    let (status, headers, body) = send(
        &app,
        Request::delete(format!("/v1/auth/sessions/{}", rotated.session_id))
            .header(header::AUTHORIZATION, format!("Bearer {}", registered.access_token))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert!(body.is_empty());
    assert_eq!(
        send(&app, post_json("/v1/auth/sessions/refresh", &json!({"refresh_token":rotated.refresh_token}), None))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, headers, body) = send(
        &app,
        Request::delete("/v1/auth/sessions/current")
            .header(header::AUTHORIZATION, format!("Bearer {}", registered.access_token))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert!(body.is_empty());
    assert_eq!(
        send(&app, post_json("/v1/auth/sessions/refresh", &json!({"refresh_token":registered.refresh_token}), None))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn compatibility_legacy_password_auth_and_deck_creation_contract() {
    let (app, st, dir) = app(DeploymentMode::MultiTenant).await;
    let registration =
        json!({"email":"legacy@example.com","password":"compatibility-password","display_name":"Legacy"});
    let (status, _, body) = send(&app, post_json("/v1/auth/register", &registration, None)).await;
    assert_eq!(status, StatusCode::OK);
    let registered: memoswish_protocol::AuthResponse = serde_json::from_slice(&body).unwrap();
    let (status, _, body) = send(
        &app,
        post_json("/v1/auth/login", &json!({"email":registration["email"],"password":registration["password"]}), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let login: memoswish_protocol::AuthResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(login.user.user_id, registered.user.user_id);
    let (status, _, body) = send(
        &app,
        Request::post("/v1/auth/refresh")
            .header(header::AUTHORIZATION, format!("Bearer {}", login.access_token))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let refreshed: memoswish_protocol::AuthResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(refreshed.user.user_id, login.user.user_id);
    let (status, _, body) = send(
        &app,
        post_json(
            "/v1/auth/account-sessions",
            &json!({"email":registration["email"],"password":registration["password"]}),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let account: memoswish_protocol::AccountSessionResponse = serde_json::from_slice(&body).unwrap();
    let (status, _, body) = send(
        &app,
        post_json(
            "/v1/auth/account-sessions/workspace",
            &json!({"tenant_id":refreshed.user.tenant_id}),
            Some(&account.access_token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let selected: memoswish_protocol::AuthResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(selected.user.user_id, login.user.user_id);
    assert_eq!(selected.user.tenant_id, refreshed.user.tenant_id);
    let (status, _, body) = send(
        &app,
        post_json("/v1/decks", &json!({"title":"Compatibility","language":"en"}), Some(&refreshed.access_token)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let deck: Deck = serde_json::from_slice(&body).unwrap();
    assert_eq!(deck.title, "Compatibility");
    assert_eq!(deck.language, "en");
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}
