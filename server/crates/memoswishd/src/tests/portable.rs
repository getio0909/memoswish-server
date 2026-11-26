//! 跨实例、跨租户的真实路由验收；字节来自有效 PNG 与 PCM WAV。
use super::*;
use base64::Engine;
use memoswish_core::assets::{card_asset_slots_mut, card_assets};

async fn instance() -> (AppState, std::path::PathBuf, String, memoswish_core::Principal) {
    let dir = std::env::temp_dir().join(format!("s18b-{}", memoswish_core::ids::new_id()));
    let st = AppState::build(Config {
        data_dir: dir.clone(),
        mode: DeploymentMode::MultiTenant,
        registration_open: true,
        seed_demo: false,
        ..Config::default()
    })
    .await
    .unwrap();
    let user = st
        .services
        .auth
        .register(&memoswish_protocol::RegisterRequest {
            email: "portable@example.com".into(),
            password: "password123".into(),
            display_name: "Portable".into(),
            tenant_name: None,
        })
        .await
        .unwrap();
    let token = user.access_token;
    let p = st.services.auth.authenticate(Some(&token)).await.unwrap();
    (st, dir, token, p)
}
fn request(uri: &str, token: &str) -> Request<Body> {
    Request::get(uri).header(header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap()
}
fn import(pack: &Value, token: &str, key: &str) -> Request<Body> {
    Request::post("/v1/decks/import/portable")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", key)
        .body(Body::from(pack.to_string()))
        .unwrap()
}

#[tokio::test]
async fn portable_media_cross_instance_restart_and_replay() {
    let (a, adir, atoken, ap) = instance().await;
    let (mut b, bdir, btoken, bp) = instance().await;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    b.services.media = memoswish_media::MediaService::new(
        b.repo.clone(),
        b.store.clone(),
        b.services.quota.clone(),
        vec![std::sync::Arc::new(CountingTts(calls.clone()))],
        "portable-test",
    )
    .unwrap();
    assert_ne!(ap.tenant_id, bp.tenant_id);
    let png = base64::engine::general_purpose::STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=")
        .unwrap();
    let wav = memoswish_media::wav::encode_wav(&[0.0; 80], 8000);
    let image =
        a.store.put(&format!("{}imports/image.png", ap.asset_prefix()), png.clone(), "image/png").await.unwrap();
    let audio =
        a.store.put(&format!("{}imports/audio.wav", ap.asset_prefix()), wav.clone(), "audio/wav").await.unwrap();
    let mut content = memoswish_protocol::examples::sample_deck_pack();
    let mut card = memoswish_protocol::examples::sample_rich_card();
    card.revision = 7;
    card.tts = memoswish_protocol::examples::sample_media_card().tts;
    card.bgm = memoswish_protocol::examples::sample_media_card().bgm;
    let track = &mut card.bgm.as_mut().unwrap().track;
    track.duration_ms = 10;
    track.loop_end_ms = 10;
    track.pcm = Some(memoswish_media::wav::pcm_info(&wav).unwrap());
    card.deck_id = content.deck.id.clone();
    card.visual.image = Some(image.clone());
    card.front.blocks.push(memoswish_protocol::ContentBlock::Image { asset: image.clone(), alt: "正面".into() });
    card.back.blocks.push(memoswish_protocol::ContentBlock::Image { asset: image.clone(), alt: "背面".into() });
    for (_, asset) in card_asset_slots_mut(&mut card) {
        *asset = if asset.mime.starts_with("image/") { image.clone() } else { audio.clone() };
    }
    let mut second = card.clone();
    second.id = memoswish_core::ids::new_id();
    second.tts.as_mut().unwrap().alignment_quality = Some(memoswish_protocol::AlignmentQuality::Unknown);
    second.bgm.as_mut().unwrap().track.provenance.as_mut().unwrap().attribution = "Another declared artist".into();
    content.cards = vec![card.clone(), second];
    content.deck.card_count = 2;
    a.repo.insert_deck_with_cards(&ap.tenant_id, &content.deck, &content.cards).await.unwrap();
    let arouter = crate::api::router(a.clone());
    let brouter = crate::api::router(b.clone());
    let uri = format!("/v1/decks/{}/export/portable", content.deck.id);
    let (status, _, bytes) = send(&arouter, request(&uri, &atoken)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&bytes));
    let pack: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(pack["version"], "2.2");
    assert_eq!(pack["content"]["version"], "1.2");
    let mut old_reader = pack.clone();
    old_reader["version"] = json!("2.1");
    old_reader["content"]["version"] = json!("1.1");
    assert_eq!(send(&brouter, import(&old_reader, &btoken, "old-format-media")).await.0, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(pack["media"].as_array().unwrap().len(), 2);
    assert_eq!(pack["content"]["cards"][0]["revision"], 7);
    assert!(!String::from_utf8(bytes).unwrap().contains(&ap.asset_prefix()));
    a.store.put(&image.key, b"corrupt".to_vec(), "image/png").await.unwrap();
    assert_ne!(send(&arouter, request(&uri, &atoken)).await.0, StatusCode::OK);
    a.store.delete(&image.key).await.unwrap();
    assert_ne!(send(&arouter, request(&uri, &atoken)).await.0, StatusCode::OK);
    a.store.put(&image.key, png.clone(), "image/png").await.unwrap();
    let mut invalid_final = pack.clone();
    invalid_final["content"]["cards"] = json!(
        (0..201)
            .map(|i| {
                let mut c = pack["content"]["cards"][0].clone();
                c["id"] = json!(format!("c{i}"));
                c
            })
            .collect::<Vec<_>>()
    );
    invalid_final["content"]["deck"]["card_count"] = json!(201);
    invalid_final["content"]["cards"][200]["front"]["title"] = json!("");
    assert_eq!(send(&brouter, import(&invalid_final, &btoken, "invalid-final")).await.0, StatusCode::BAD_REQUEST);
    assert!(b.repo.pending_imports(None).await.unwrap().is_empty());
    assert_eq!(b.repo.held_import_usage(&bp.tenant_id, &memoswish_auth::quota::current_period()).await.unwrap(), 0);
    assert!(b.store.list_prefix(&bp.asset_prefix()).await.unwrap().is_empty());
    let historical = send(&brouter, post_json("/v1/decks/import", &pack, Some(&btoken))).await;
    assert!(!historical.0.is_success());
    let mut corrupt = pack.clone();
    corrupt["media"][0]["sha256"] = json!("0".repeat(64));
    let invalid = send(&brouter, import(&corrupt, &btoken, "bad-before-put")).await;
    assert_eq!(invalid.0, StatusCode::BAD_REQUEST);
    assert!(b.repo.list_decks(&bp.tenant_id).await.unwrap().is_empty());
    let writer =
        b.services.auth.create_api_token(&bp, "Content only", vec!["content:write".into()], None).await.unwrap();
    assert_eq!(send(&brouter, import(&pack, &writer.plaintext, "missing-media-scope")).await.0, StatusCode::FORBIDDEN);
    let mut empty = pack.clone();
    empty["media"] = json!([]);
    empty["content"]["cards"] = json!([]);
    empty["content"]["deck"]["card_count"] = json!(0);
    assert_eq!(
        send(&brouter, import(&empty, &writer.plaintext, "empty-without-media-scope")).await.0,
        StatusCode::CREATED
    );
    let (first, second) = tokio::join!(
        send(&brouter, import(&pack, &btoken, "portable")),
        send(&brouter, import(&pack, &btoken, "portable"))
    );
    assert_eq!(first.0, StatusCode::CREATED, "{}", String::from_utf8_lossy(&first.2));
    assert_eq!(second.0, first.0);
    assert_eq!(first.2, second.2);
    let deck: Deck = serde_json::from_slice(&first.2).unwrap();
    let mut changed = pack.clone();
    changed["content"]["deck"]["title"] = json!("Changed");
    assert_eq!(send(&brouter, import(&changed, &btoken, "portable")).await.0, StatusCode::CONFLICT);
    a.services.operations.close();
    a.services.operations.wait().await;
    drop(arouter);
    crate::runtime::cleanup_test_app(&adir, &[&a]).await;
    b.services.operations.close();
    b.services.operations.wait().await;
    drop(brouter);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    crate::runtime::drain_test_state(&b).await;
    drop(b);
    let b = AppState::build(Config {
        data_dir: bdir.clone(),
        mode: DeploymentMode::MultiTenant,
        registration_open: true,
        seed_demo: false,
        ..Config::default()
    })
    .await
    .unwrap();
    let router = crate::api::router(b.clone());
    let (status, _, bytes) = send(&router, request(&format!("/v1/decks/{}/cards", deck.id), &btoken)).await;
    assert_eq!(status, StatusCode::OK);
    let cards: Vec<Card> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(cards.len(), 2);
    for (index, imported) in cards.iter().enumerate() {
        assert_eq!(
            imported.tts.as_ref().unwrap().alignment_quality,
            Some(if index == 0 {
                memoswish_protocol::AlignmentQuality::Estimated
            } else {
                memoswish_protocol::AlignmentQuality::Unknown
            })
        );
        assert_eq!(imported.tts.as_ref().unwrap().provenance, card.tts.as_ref().unwrap().provenance);
        let mut expected_rights = card.bgm.as_ref().unwrap().track.provenance.clone();
        if index == 1 {
            expected_rights.as_mut().unwrap().attribution = "Another declared artist".into();
        }
        assert_eq!(imported.bgm.as_ref().unwrap().track.provenance, expected_rights);
        assert_eq!(imported.bgm.as_ref().unwrap().track.pcm, card.bgm.as_ref().unwrap().track.pcm);
        assert_ne!(imported.id, card.id);
        assert_eq!(imported.revision, 1);
        assert_eq!(imported.content.as_ref().unwrap().provenance.source_revision, Some(7));
        assert_eq!(imported.tts.as_ref().unwrap().words, card.tts.as_ref().unwrap().words);
        assert_eq!(imported.bgm.as_ref().unwrap().track.license, card.bgm.as_ref().unwrap().track.license);
        assert_eq!(imported.ducking, card.ducking);
        for asset in card_assets(imported) {
            assert!(asset.key.starts_with(&bp.asset_prefix()));
            assert_eq!(
                send(&router, request(&asset.url, &btoken)).await.2,
                if asset.mime == "image/png" { png.clone() } else { wav.clone() }
            );
            assert_eq!(send(&router, request(&asset.url, &atoken)).await.0, StatusCode::UNAUTHORIZED);
        }
    }
    assert_eq!(cards[0].bgm.as_ref().unwrap().track.id, cards[1].bgm.as_ref().unwrap().track.id);
    assert_ne!(cards[0].bgm.as_ref().unwrap().track.id, card.bgm.as_ref().unwrap().track.id);
    assert_eq!(send(&router, import(&pack, &btoken, "portable")).await.2, first.2);
    let stats = b.repo.list_bgm(&bp.tenant_id).await.unwrap();
    assert!(stats.iter().all(|t| t.id != cards[0].bgm.as_ref().unwrap().track.id));
    assert_eq!(
        b.repo.get_usage(&bp.tenant_id, "card_writes", &memoswish_auth::quota::current_period()).await.unwrap(),
        2
    );
    b.services.operations.close();
    b.services.operations.wait().await;
    drop(router);
    crate::runtime::cleanup_test_app(bdir, &[&b]).await;
}

#[tokio::test]
async fn portable_export_rechecks_original_token_after_media_read() {
    let (mut st, dir, _, p) = instance().await;
    let mut content = memoswish_protocol::examples::sample_deck_pack();
    let image =
        st.store.put(&format!("{}imports/one.png", p.asset_prefix()), b"abc".to_vec(), "image/png").await.unwrap();
    content.cards[0].tts = None;
    content.cards[0].bgm = None;
    content.cards[0].visual.image = Some(image);
    st.repo.insert_deck_with_cards(&p.tenant_id, &content.deck, &content.cards).await.unwrap();
    let token = st.services.auth.create_api_token(&p, "Read export", vec!["content:read".into()], None).await.unwrap();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let store = std::sync::Arc::new(DeliveryBarrier {
        inner: st.store.clone(),
        entered: entered.clone(),
        release: release.clone(),
    });
    st.services.media = memoswish_media::MediaService::new(
        st.repo.clone(),
        store,
        st.services.quota.clone(),
        vec![std::sync::Arc::new(memoswish_media::tts::placeholder::PlaceholderTts)],
        "placeholder",
    )
    .unwrap();
    let app = crate::api::router(st.clone());
    let id = content.deck.id;
    let worker =
        tokio::spawn(
            async move { send(&app, request(&format!("/v1/decks/{id}/export/portable"), &token.plaintext)).await },
        );
    entered.notified().await;
    assert!(!worker.is_finished());
    st.repo.revoke_api_token(&p.tenant_id, &token.record.id).await.unwrap();
    release.notify_one();
    assert_eq!(worker.await.unwrap().0, StatusCode::UNAUTHORIZED);
    st.services.operations.close();
    st.services.operations.wait().await;
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}

#[tokio::test]
async fn portable_near_content_bound_roundtrips_and_rejects_plus_one_before_effects() {
    use memoswish_content::deckpack::{CONTENT_BYTES, DOCUMENT_BYTES};
    use memoswish_core::imports::{PORTABLE_SNAPSHOT_BYTES, json_bytes};
    let (a, adir, atoken, ap) = instance().await;
    let (b, bdir, btoken, bp) = instance().await;
    assert_ne!(ap.tenant_id, bp.tenant_id);
    let png = base64::engine::general_purpose::STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=")
        .unwrap();
    let mut image =
        a.store.put(&format!("{}imports/i.png", ap.asset_prefix()), png.clone(), "image/png").await.unwrap();
    image.url.clear();
    let mut content = memoswish_protocol::examples::sample_deck_pack();
    content.deck.id = "d".into();
    content.deck.created_at = chrono::DateTime::UNIX_EPOCH;
    content.exported_at = chrono::DateTime::UNIX_EPOCH;
    content.cards.truncate(1);
    content.deck.card_count = 1;
    let card = &mut content.cards[0];
    card.id = "c".into();
    card.created_at = chrono::DateTime::UNIX_EPOCH;
    card.updated_at = chrono::DateTime::UNIX_EPOCH;
    card.deck_id = content.deck.id.clone();
    card.tts = None;
    card.bgm = None;
    card.visual.image = None;
    for face in [&mut card.front, &mut card.back] {
        face.blocks = vec![memoswish_protocol::ContentBlock::Image { asset: image.clone(), alt: String::new() }; 32];
    }
    // 大正文单独放在无附件卡片，避免此边界回归重复触发另列的导出读放大问题。
    let mut padding_card = card.clone();
    padding_card.id = "p".into();
    padding_card.front.blocks.clear();
    padding_card.back.blocks.clear();
    padding_card.attributes.insert("padding".into(), "".into());
    content.cards.push(padding_card);
    content.deck.card_count = 2;
    let size = json_bytes(&content, CONTENT_BYTES).unwrap();
    content.cards[1].attributes.insert("padding".into(), "x".repeat(CONTENT_BYTES - 512 - size).into());
    assert_eq!(json_bytes(&content, CONTENT_BYTES).unwrap(), CONTENT_BYTES - 512);
    a.repo.insert_deck_with_cards(&ap.tenant_id, &content.deck, &content.cards).await.unwrap();
    let arouter = crate::api::router(a.clone());
    let brouter = crate::api::router(b.clone());
    let exported = send(&arouter, request(&format!("/v1/decks/{}/export/portable", content.deck.id), &atoken)).await;
    assert_eq!(exported.0, StatusCode::OK, "{}", String::from_utf8_lossy(&exported.2));
    let pack: memoswish_protocol::PortableDeckPack = serde_json::from_slice(&exported.2).unwrap();
    assert_eq!(pack.media.len(), 1);
    // 同一个有界源包曾因目标身份增长超过旧 8 MiB 卡片准入而被拒绝。
    let work = b.services.content.prepare_portable_deck_pack(&bp, pack.clone()).unwrap();
    assert!(json_bytes(&work.cards, PORTABLE_SNAPSHOT_BYTES).unwrap() > CONTENT_BYTES);
    assert!(work.identity_expansion_bytes > 0);
    let mut exact = pack.clone();
    let size = json_bytes(&exact.content, CONTENT_BYTES).unwrap();
    let padding = exact.content.cards[1].attributes["padding"].as_str().unwrap().len();
    exact.content.cards[1].attributes.insert("padding".into(), "x".repeat(padding + CONTENT_BYTES - size).into());
    assert_eq!(json_bytes(&exact.content, CONTENT_BYTES).unwrap(), CONTENT_BYTES);
    assert!(json_bytes(&exact, DOCUMENT_BYTES).is_ok());
    assert_eq!(exact.content.deck.id, "d");
    assert!(exact.content.cards.iter().all(|card| card.id.len() <= 1));
    assert_eq!(exact.content.exported_at, chrono::DateTime::UNIX_EPOCH);
    let mut over = exact.clone();
    let padding = over.content.cards[1].attributes["padding"].as_str().unwrap().len();
    over.content.cards[1].attributes.insert("padding".into(), "x".repeat(padding + 1).into());
    assert_eq!(
        send(&brouter, import(&serde_json::to_value(over).unwrap(), &btoken, "over-content")).await.0,
        StatusCode::BAD_REQUEST
    );
    assert!(b.repo.pending_imports(None).await.unwrap().is_empty());
    assert!(b.repo.list_decks(&bp.tenant_id).await.unwrap().is_empty());
    assert_eq!(b.repo.held_import_usage(&bp.tenant_id, &memoswish_auth::quota::current_period()).await.unwrap(), 0);
    assert_eq!(
        b.repo.get_usage(&bp.tenant_id, "card_writes", &memoswish_auth::quota::current_period()).await.unwrap(),
        0
    );
    assert!(b.store.list_prefix(&bp.asset_prefix()).await.unwrap().is_empty());
    for (key, pack) in [("near-content", pack), ("exact-content", exact)] {
        let imported = send(&brouter, import(&serde_json::to_value(&pack).unwrap(), &btoken, key)).await;
        assert_eq!(imported.0, StatusCode::CREATED, "{}", String::from_utf8_lossy(&imported.2));
        let deck: Deck = serde_json::from_slice(&imported.2).unwrap();
        assert_eq!(deck.id.len(), 36);
        assert_ne!(deck.created_at, chrono::DateTime::UNIX_EPOCH);
        let again = send(&brouter, request(&format!("/v1/decks/{}/export/portable", deck.id), &btoken)).await;
        assert_eq!(again.0, StatusCode::OK, "{}", String::from_utf8_lossy(&again.2));
        let again: memoswish_protocol::PortableDeckPack = serde_json::from_slice(&again.2).unwrap();
        assert_eq!(again.media, pack.media);
        assert!(json_bytes(&again.content, CONTENT_BYTES).is_ok());
        assert!(
            json_bytes(&again.content, CONTENT_BYTES).unwrap() <= json_bytes(&pack.content, CONTENT_BYTES).unwrap()
        );
        let cards = b.services.content.list_cards(&bp, Some(&deck.id), 2, 0).await.unwrap();
        let card = cards.iter().find(|card| !card_assets(card).is_empty()).unwrap();
        let assets = card_assets(card);
        assert_eq!(assets.len(), 64);
        assert!(assets.iter().all(|asset| asset.key == assets[0].key));
        let rendered = memoswish_application::asset_delivery::render_card(card.clone(), "content");
        let url = &card_assets(&rendered)[0].url;
        let delivered = send(&brouter, request(url, &btoken)).await;
        assert_eq!(delivered.0, StatusCode::OK);
        assert_eq!(delivered.2, png);
        assert_eq!(send(&brouter, request(url, &atoken)).await.0, StatusCode::UNAUTHORIZED);
    }
    a.services.operations.close();
    a.services.operations.wait().await;
    b.services.operations.close();
    b.services.operations.wait().await;
    drop(arouter);
    drop(brouter);
    crate::runtime::drain_test_state(&a).await;
    crate::runtime::cleanup_test_app(adir, &[&a]).await;
    crate::runtime::cleanup_test_app(bdir, &[&b]).await;
}

struct CountingTts(std::sync::Arc<std::sync::atomic::AtomicUsize>);
#[async_trait::async_trait]
impl memoswish_core::tts::TtsEngine for CountingTts {
    fn id(&self) -> &str {
        "portable-test"
    }
    fn voices(&self) -> Vec<memoswish_core::tts::VoiceInfo> {
        vec![]
    }
    async fn synthesize(
        &self,
        _: &memoswish_core::tts::TtsRequest,
    ) -> memoswish_core::CoreResult<memoswish_core::tts::TtsOutput> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(memoswish_core::CoreError::internal("portable import must not synthesize audio"))
    }
}

#[tokio::test]
async fn portable_import_privacy_retention_and_erasure() {
    use memoswish_core::imports::ImportAuthority;
    let (mut st, dir, token, p) = instance().await;
    let policy = memoswish_protocol::examples::sample_privacy_policy();
    st.repo.privacy_install_policy(&policy).await.unwrap();
    st.services.auth = st.services.auth.clone().with_privacy_policy(policy).unwrap();
    let pack = memoswish_protocol::examples::sample_portable_deck_pack();
    let raw = serde_json::to_value(&pack).unwrap();
    let app = crate::api::router(st.clone());
    assert_eq!(send(&app, import(&raw, &token, "privacy")).await.0, StatusCode::FORBIDDEN);
    assert!(st.repo.pending_imports(None).await.unwrap().is_empty());
    assert!(st.store.list_prefix(&p.asset_prefix()).await.unwrap().is_empty());
    let mut state = st.services.auth.privacy_state(&p).await.unwrap();
    for (kind, version, value) in
        [("notice", "notice-v1", ""), ("terms", "terms-v1", ""), ("age", "notice-v1", "example-region")]
    {
        state = st
            .services
            .auth
            .update_privacy(
                &p,
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
    // 嵌入媒体不调用外部提供者，拒绝全部可选用途仍允许本地导入。
    assert!(state.purpose_records.is_empty());
    let credential = st.services.auth.import_credential(&p, Some(&token)).unwrap();
    let authority = ImportAuthority::capture(&p, Some(credential));
    let work = st.services.content.prepare_portable_deck_pack(&p, pack).unwrap();
    assert!(!work.auto_tts);
    let staged = st.repo.accept_import(&authority, "staged", &"f".repeat(64), &work, None, 2).await.unwrap();
    let claim = st.repo.claim_import(&p.tenant_id, &staged.id, 30_000).await.unwrap().unwrap();
    let retention = memoswish_storage::retention::RetentionPolicy {
        version: 1,
        api_metadata_after_expiry_seconds: 0,
        failed_tts_payload_after_schedule_seconds: 0,
    };
    memoswish_storage::retention::sweep(&st.config.database_url(), &p.tenant_id, &retention, 100, true).await.unwrap();
    let retained = st.repo.import_execution(&p.tenant_id, &claim).await.unwrap();
    assert_eq!(serde_json::to_value(&retained.work).unwrap(), serde_json::to_value(&work).unwrap());
    let period = memoswish_auth::quota::current_period();
    assert_eq!(st.repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), work.cards.len() as i64);
    let result = send(&app, import(&raw, &token, "privacy")).await;
    assert_eq!(result.0, StatusCode::CREATED, "{}", String::from_utf8_lossy(&result.2));
    memoswish_storage::retention::sweep(&st.config.database_url(), &p.tenant_id, &retention, 100, true).await.unwrap();
    assert_eq!(send(&app, import(&raw, &token, "privacy")).await.2, result.2);
    st.services
        .auth
        .update_privacy(
            &p,
            &memoswish_protocol::PrivacyUpdate {
                expected_revision: state.revision,
                kind: "age".into(),
                version: "notice-v1".into(),
                decision: false,
                value: "underage".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(send(&app, import(&raw, &token, "privacy")).await.0, StatusCode::FORBIDDEN);
    // 已持久受理的便携任务同样在提交事务中复核资格。
    assert!(matches!(st.repo.commit_import(&p.tenant_id, &claim).await, Err(memoswish_core::CoreError::Forbidden(_))));
    let response =
        send(&app, post_json("/v1/workspace/delete", &json!({"confirmed_tenant_id":p.tenant_id}), Some(&token))).await;
    crate::account_tests::assert_erasure_response(&st, response.0).await;
    assert!(st.store.list_prefix(&p.asset_prefix()).await.unwrap().is_empty());
    assert_eq!(st.repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), 0);
    assert!(st.repo.import_execution(&p.tenant_id, &claim).await.is_err());
    assert_eq!(send(&app, import(&raw, &token, "privacy")).await.0, StatusCode::UNAUTHORIZED);
    st.services.operations.close();
    st.services.operations.wait().await;
    drop(app);
    crate::runtime::cleanup_test_app(dir, &[&st]).await;
}
