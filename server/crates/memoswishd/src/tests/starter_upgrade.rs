//! 用改名前发布的固定包植入安装回执，重启后由当前 HTTP 入口重放。
use super::*;
use memoswish_core::{ids::sha256_hex, imports::ImportAuthority};

const STARTER: &str = "learning-basics-v1";
const BASE_PACK: &str = include_str!("../../../memoswish-content/tests/fixtures/learning-basics-v1.json");

async fn replay(cfg: Config) {
    // 不启动维护调度，确保重启后的首个 HTTP 重试实际处理待提交回执。
    let before = AppState::assemble(cfg.clone()).await.unwrap();
    let owner = before.services.auth.authenticate(None).await.unwrap();
    let authority = ImportAuthority::capture(&owner, None);
    let writer =
        before.services.auth.create_api_token(&owner, "Other authority", vec!["*".into()], None).await.unwrap();
    let wire: Value = serde_json::from_str(BASE_PACK).unwrap();
    let fingerprint = sha256_hex(format!(r#"["deckpack",{BASE_PACK},false]"#).as_bytes());
    let mut receipts = Vec::new();
    for key in ["pending", "committed"] {
        let stored_key = format!("starter:{}", sha256_hex(key.as_bytes()));
        let work = before.services.content.prepare_deck_pack(&owner, &wire, false).unwrap();
        let op = before.repo.accept_import(&authority, &stored_key, &fingerprint, &work, Some(6), 2).await.unwrap();
        assert_eq!(op.outcome, "pending");
        if key == "committed" {
            let result = before.services.content.drive_import("local", &op.id).await.unwrap();
            assert_eq!(result.outcome, "committed");
        }
        receipts.push((key, stored_key, op.id, work.deck));
    }
    let period = memoswish_auth::quota::current_period();
    assert_eq!(before.repo.get_usage("local", "card_writes", &period).await.unwrap(), 3);
    assert_eq!(before.repo.held_import_usage("local", &period).await.unwrap(), 3);
    crate::runtime::drain_test_state(&before).await;
    drop(before);

    let st = AppState::assemble(cfg.clone()).await.unwrap();
    let app = crate::api::router(st.clone());
    let path = format!("/v1/content/starters/{STARTER}/install");
    assert_eq!(serde_json::to_string(&memoswish_content::starter::pack(STARTER).unwrap()).unwrap(), BASE_PACK);
    for (key, stored_key, operation_id, deck) in receipts {
        let body = json!({"idempotency_key":key});
        let (status, _, _) = send(&app, post_json(&path, &body, Some(&writer.plaintext))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let mut changed = wire.clone();
        changed["deck"]["title"] = json!("Changed request");
        let mut request = post_json("/v1/decks/import", &changed, None);
        request.headers_mut().insert("Idempotency-Key", stored_key.parse().unwrap());
        let (status, _, _) = send(&app, request).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(st.repo.import_operation("local", &operation_id).await.unwrap().outcome, key);
        for _ in 0..2 {
            let (status, _, bytes) = send(&app, post_json(&path, &body, None)).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&bytes));
            assert_eq!(serde_json::from_slice::<Deck>(&bytes).unwrap(), deck);
        }
        assert_eq!(st.repo.import_operation("local", &operation_id).await.unwrap().outcome, "committed");
    }
    assert_eq!(st.repo.list_decks("local").await.unwrap().len(), 2);
    assert_eq!(st.repo.get_usage("local", "card_writes", &period).await.unwrap(), 6);
    assert_eq!(st.repo.held_import_usage("local", &period).await.unwrap(), 0);
    drop(app);
    crate::runtime::cleanup_test_app(cfg.data_dir, &[&st]).await;
}

fn config() -> Config {
    Config {
        data_dir: std::env::temp_dir().join(format!("starter-upgrade-{}", memoswish_core::ids::new_id())),
        seed_demo: false,
        ..Config::default()
    }
}

#[tokio::test]
async fn sqlite_starter_upgrade_replays_pending_and_committed() {
    replay(config()).await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
fn postgres_starter_upgrade_replays_pending_and_committed() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        replay(Config { database_url: Some(fixture.database_url()), db_max_connections: Some(2), ..config() }).await;
        fixture.cleanup().await;
    });
}
