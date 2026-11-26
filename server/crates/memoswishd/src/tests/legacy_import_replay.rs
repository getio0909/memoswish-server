//! 先以 2.13 迁移和冻结字节植入有效 pending/committed 记录，再升级并通过两个真实传输重放。
use super::*;
use memoswish_core::{Principal, imports::ImportAuthority};

fn cases() -> Vec<Value> {
    let reference: Value =
        serde_json::from_str(include_str!("../../../memoswish-content/tests/fixtures/legacy-identities-213.json"))
            .unwrap();
    reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["name"].as_str().unwrap().ends_with("-text"))
        .cloned()
        .collect()
}

macro_rules! legacy_database {
    ($name:ident, $pool:ty, $migrations:literal) => {
        async fn $name(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            let through = |head| sqlx::migrate::Migrator {
                migrations: full.iter().filter(|m| m.version <= head).cloned().collect::<Vec<_>>().into(),
                ..sqlx::migrate::Migrator::DEFAULT
            };
            through(8).run(pool).await.unwrap();
            sqlx::raw_sql("INSERT INTO tenants VALUES('local','Local','self_hosted','2026-11-01T00:00:00Z'); INSERT INTO users VALUES('usr_local','local','local@memoswish.invalid','Owner','','owner','2026-11-01T00:00:00Z');").execute(pool).await.unwrap();
            through(27).run(pool).await.unwrap();
            let authority = ImportAuthority::capture(&Principal::local_owner("single_user"), None);
            for case in cases() {
                for mcp in [false, true] {
                    for committed in [false, true] {
                        let key = format!("{}-{mcp}-{committed}", case["name"].as_str().unwrap());
                        let pack: Value = serde_json::from_str(case["serialized"].as_str().unwrap()).unwrap();
                        let content = if case["format"] == "deckpack" { &pack } else { &pack["content"] };
                        let mut deck = content["deck"].clone();
                        deck["id"] = json!(&key);
                        let mut cards = content["cards"].as_array().unwrap().clone();
                        for (index, card) in cards.iter_mut().enumerate() {
                            card["id"] = json!(format!("{key}-{index}"));
                            card["deck_id"] = json!(&key);
                            card["revision"] = json!(1);
                        }
                        let work = json!({"deck":deck,"cards":cards,"media":[],"result":deck,"auto_tts":false});
                        let outcome = if committed { "committed" } else { "pending" };
                        sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,state,max_attempts,available_at_ms) VALUES('local',$1,'content_import',$1,'{}','usr_local',0,$2,5,0)")
                            .bind(&key).bind(if committed {"succeeded"} else {"queued"}).execute(pool).await.unwrap();
                        sqlx::query("INSERT INTO content_imports(tenant_id,id,user_id,fingerprint,authority_id,authority,work,outcome,result) VALUES('local',$1,'usr_local',$2,$3,$4,$5,$6,$7)")
                            .bind(&key).bind(case["fingerprint"].as_str().unwrap()).bind(authority.identity().unwrap())
                            .bind(serde_json::to_string(&authority).unwrap()).bind(work.to_string()).bind(outcome)
                            .bind(committed.then(||deck.to_string())).execute(pool).await.unwrap();
                        sqlx::query("INSERT INTO quota_operations VALUES('local',$1,'card_writes',$2,$3,$4)")
                            .bind(&key).bind(memoswish_auth::quota::current_period()).bind(cards.len() as i64)
                            .bind(if committed {"committed"} else {"reserved"}).execute(pool).await.unwrap();
                        if committed {
                            let deck: Deck = serde_json::from_value(deck).unwrap();
                            sqlx::query("INSERT INTO decks(id,tenant_id,title,description,language,tags,created_at) VALUES($1,'local',$2,$3,$4,$5,$6)")
                                .bind(&deck.id).bind(&deck.title).bind(&deck.description).bind(&deck.language)
                                .bind(sqlx::types::Json(&deck.tags)).bind(deck.created_at).execute(pool).await.unwrap();
                            for card in cards {
                                let typed: Card = serde_json::from_value(card.clone()).unwrap();
                                sqlx::query("INSERT INTO cards(id,tenant_id,deck_id,template,revision,body,created_at,updated_at) VALUES($1,'local',$2,$3,1,$4,$5,$6)")
                                    .bind(&typed.id).bind(&typed.deck_id).bind(&typed.template).bind(sqlx::types::Json(card))
                                    .bind(typed.created_at).bind(typed.updated_at).execute(pool).await.unwrap();
                            }
                        }
                    }
                }
            }
            sqlx::query("INSERT INTO usage_counters VALUES('local','card_writes',$1,4)")
                .bind(memoswish_auth::quota::current_period()).execute(pool).await.unwrap();
            let latest: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(latest,27);
        }
    };
}
legacy_database!(seed_sqlite, sqlx::SqlitePool, "../../crates/memoswish-storage/migrations/sqlite");
#[cfg(feature = "postgres")]
legacy_database!(seed_postgres, sqlx::PgPool, "../../crates/memoswish-storage/migrations/postgres");

async fn replay(cfg: Config) -> AppState {
    let st = AppState::build(cfg.clone()).await.unwrap();
    let app = crate::api::router(st.clone());
    let p = st.services.auth.authenticate(None).await.unwrap();
    assert_eq!(p, Principal::local_owner("single_user"));
    let writer = st.services.auth.create_api_token(&p, "Other authority", vec!["*".into()], None).await.unwrap();
    for case in cases() {
        for mcp in [false, true] {
            for committed in [false, true] {
                let key = format!("{}-{mcp}-{committed}", case["name"].as_str().unwrap());
                let portable = case["format"] == "portable-deckpack";
                let baseline: Value = serde_json::from_str(case["serialized"].as_str().unwrap()).unwrap();
                let mut expected =
                    if portable { baseline["content"]["deck"].clone() } else { baseline["deck"].clone() };
                expected["id"] = json!(&key);
                let request = |pack: Value, token: Option<&str>, auto_tts: bool| {
                    if mcp {
                        let tool = if portable { "deck_import_portable" } else { "deck_import" };
                        let mut args = json!({"pack":pack,"request_id":key});
                        if !portable {
                            args["auto_tts"] = json!(auto_tts);
                        }
                        post_json(
                            "/mcp",
                            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}}),
                            token,
                        )
                    } else {
                        let path = if portable { "/v1/decks/import/portable" } else { "/v1/decks/import" };
                        let mut req = post_json(path, &pack, token);
                        req.headers_mut().insert("Idempotency-Key", key.parse().unwrap());
                        req
                    }
                };
                for null_revision in [true, false, true, false] {
                    let mut input = case["input"].clone();
                    if null_revision {
                        let content = if portable { &mut input["content"] } else { &mut input };
                        content["deck"]["revision"] = Value::Null;
                    }
                    let (status, _, bytes) = send(&app, request(input, None, false)).await;
                    assert!(status.is_success(), "{key}: {}", String::from_utf8_lossy(&bytes));
                    let mut result: Value = serde_json::from_slice(&bytes).unwrap();
                    if mcp {
                        assert!(result["error"].is_null(), "{result}");
                        assert_ne!(result["result"]["isError"], true, "{result}");
                        result =
                            serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
                    }
                    assert_eq!(result, expected);
                    let operation = st.repo.import_operation("local", &key).await.unwrap();
                    assert_eq!(operation.id, key);
                    assert_eq!(operation.outcome, "committed");
                    assert_eq!(operation.result, Some(expected.clone()));
                }
                let mut changed = case["input"].clone();
                let content = if portable { &mut changed["content"] } else { &mut changed };
                content["deck"]["title"] = json!("Changed request");
                let mut negatives =
                    vec![request(changed, None, false), request(case["input"].clone(), Some(&writer.plaintext), false)];
                if mcp && !portable {
                    negatives.push(request(case["input"].clone(), None, true));
                }
                for req in negatives {
                    let (status, _, bytes) = send(&app, req).await;
                    if mcp {
                        let response: Value = serde_json::from_slice(&bytes).unwrap();
                        assert!(response["error"].is_object() || response["result"]["isError"] == true, "{response}");
                        assert!(String::from_utf8_lossy(&bytes).contains("conflict"), "{response}");
                    } else {
                        assert_eq!(status, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&bytes));
                    }
                }
            }
        }
    }
    assert_eq!(st.repo.list_decks("local").await.unwrap().len(), 8);
    let period = memoswish_auth::quota::current_period();
    assert_eq!(st.repo.get_usage("local", "card_writes", &period).await.unwrap(), 8);
    assert_eq!(st.repo.held_import_usage("local", &period).await.unwrap(), 0);
    assert!(st.repo.pending_imports(None).await.unwrap().is_empty());
    st.services.operations.close();
    st.services.operations.wait().await;
    drop(app);
    crate::runtime::drain_test_state(&st).await;
    drop(st);
    let restarted = AppState::build(cfg).await.unwrap();
    assert_eq!(restarted.repo.list_decks("local").await.unwrap().len(), 8);
    assert_eq!(restarted.repo.get_usage("local", "card_writes", &period).await.unwrap(), 8);
    restarted.services.operations.close();
    restarted.services.operations.wait().await;
    restarted
}

#[tokio::test]
async fn p31_legacy_sqlite_import_upgrade_replays_rest_and_mcp() {
    let dir = std::env::temp_dir().join(format!("p31-legacy-{}", memoswish_core::ids::new_id()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let url = format!("sqlite://{}", dir.join("learntok.db").display());
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            url.parse::<sqlx::sqlite::SqliteConnectOptions>().unwrap().create_if_missing(true).foreign_keys(true),
        )
        .await
        .unwrap();
    seed_sqlite(&pool).await;
    pool.close().await;
    let restarted = replay(Config { data_dir: dir.clone(), seed_demo: false, ..Config::default() }).await;
    crate::runtime::cleanup_test_app(dir, &[&restarted]).await;
}

#[cfg(feature = "postgres")]
#[test]
#[ignore = "integration: requires MEMOSWISH_TEST_POSTGRES_URL and psql"]
fn p31_legacy_postgres_import_upgrade_replays_rest_and_mcp() {
    memoswish_storage::pg_test_support::run_pg_test(|owner| async move {
        let fixture = owner.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
        let pool =
            sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&fixture.database_url()).await.unwrap();
        seed_postgres(&pool).await;
        let url = fixture.database_url();
        pool.close().await;
        let dir = std::env::temp_dir().join(format!("p31-legacy-pg-{}", memoswish_core::ids::new_id()));
        let restarted = replay(Config {
            database_url: Some(url),
            data_dir: dir.clone(),
            seed_demo: false,
            db_max_connections: Some(2),
            ..Config::default()
        })
        .await;
        fixture.cleanup().await;
        crate::runtime::cleanup_test_app(dir, &[&restarted]).await;
    });
}
