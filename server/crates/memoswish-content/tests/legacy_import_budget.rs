//! 旧封套在原 S18 字节边界导入，服务端来源增量不得挤占调用方内容预算。
use memoswish_content::ContentService;
use memoswish_core::{
    Principal,
    imports::{IMPORT_CONTENT_BYTES, ImportAuthority, PORTABLE_SNAPSHOT_BYTES},
    repo::{Repository, TenantRecord, UserRecord},
};
use memoswish_storage::sqlite::SqliteRepository;
use std::sync::Arc;

// 只从冻结的 2.13 原始 JSON 形状填充，禁止通过当前 Rust 模型生成旧线输入。
fn raw_legacy_pack(count: usize) -> serde_json::Value {
    let mut pack: serde_json::Value =
        serde_json::from_str(include_str!("../../../../compatibility/history/2.13.0/protocol/fixtures/deck-pack.json"))
            .unwrap();
    assert!(pack["deck"].get("revision").is_none());
    pack["version"] = "1.0".into();
    pack["deck"]["id"] = memoswish_core::ids::new_id().into();
    pack["deck"]["card_count"] = count.into();
    let timestamp = "9999-12-31T23:59:59.999999999Z";
    pack["deck"]["created_at"] = timestamp.into();
    let mut card = pack["cards"][0].clone();
    assert!(card.get("content").is_none());
    card["revision"] = 7.into();
    card.as_object_mut().unwrap().remove("tts");
    card.as_object_mut().unwrap().remove("bgm");
    card["visual"].as_object_mut().unwrap().remove("image");
    card["attributes"] = serde_json::json!({"padding":""});
    let cards: Vec<_> = (0..count)
        .map(|_| {
            let mut card = card.clone();
            card["id"] = memoswish_core::ids::new_id().into();
            card["deck_id"] = pack["deck"]["id"].clone();
            card["created_at"] = timestamp.into();
            card["updated_at"] = timestamp.into();
            card
        })
        .collect();
    pack["cards"] = cards.into();
    pack
}

fn legacy_pack(bytes: usize) -> serde_json::Value {
    let mut pack = raw_legacy_pack(500);
    let base = serde_json::to_vec(&pack).unwrap().len();
    let padding = bytes - base;
    for (i, card) in pack["cards"].as_array_mut().unwrap().iter_mut().enumerate() {
        card["attributes"]["padding"] = "x".repeat(padding / 500 + usize::from(i < padding % 500)).into();
    }
    assert_eq!(serde_json::to_vec(&pack).unwrap().len(), bytes);
    pack
}

fn portable_wire(content: serde_json::Value) -> serde_json::Value {
    let mut wire: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../compatibility/history/2.13.0/protocol/fixtures/portable-deck-pack.json"
    ))
    .unwrap();
    wire["content"] = content;
    wire["media"] = serde_json::json!([]);
    wire
}

async fn legacy_service() -> (Arc<dyn Repository>, ContentService, Principal) {
    let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
    let service = ContentService::new(repo.clone());
    let p = Principal::local_owner("test");
    repo.upsert_tenant(&TenantRecord {
        id: p.tenant_id.clone(),
        name: "Legacy".into(),
        plan: "self_hosted".into(),
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    repo.insert_user(&UserRecord {
        id: p.user_id.clone(),
        tenant_id: p.tenant_id.clone(),
        email: "legacy@example.invalid".into(),
        display_name: "Legacy".into(),
        password_hash: String::new(),
        role: memoswish_core::Role::Owner,
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    (repo, service, p)
}

async fn legacy_import_at_boundary(portable: bool, remaining: usize) {
    let (repo, service, p) = legacy_service().await;
    let pack = legacy_pack(IMPORT_CONTENT_BYTES - remaining);
    assert!(pack["cards"].as_array().unwrap().iter().all(|c| c.get("content").is_none()));
    let source: Vec<memoswish_protocol::Card> = serde_json::from_value(pack["cards"].clone()).unwrap();
    let work = if portable {
        service.prepare_portable_deck_pack(&p, portable_wire(pack))
    } else {
        service.prepare_deck_pack(&p, pack, false)
    }
    .unwrap();
    assert!(work.provenance_expansion_bytes > 100_000);
    let size = memoswish_core::imports::json_bytes(&work.cards, PORTABLE_SNAPSHOT_BYTES).unwrap();
    assert!(size > IMPORT_CONTENT_BYTES);
    assert!(size <= work.cards_byte_limit().unwrap());
    let authority = ImportAuthority::capture(&p, None);
    let fingerprint = "a".repeat(64);
    let mut missing = work.clone();
    missing.provenance_expansion_bytes = 0;
    assert!(repo.accept_import(&authority, "missing-allowance", &fingerprint, &missing, None, 2).await.is_err());
    let mut forged = work.clone();
    forged.provenance_expansion_bytes = PORTABLE_SNAPSHOT_BYTES;
    assert!(repo.accept_import(&authority, "forged-allowance", &fingerprint, &forged, None, 2).await.is_err());
    let mut oversized = work.clone();
    let excess = oversized.cards_byte_limit().unwrap() - size + 1;
    let padding = oversized.cards[0].attributes["padding"].as_str().unwrap().to_owned();
    oversized.cards[0].attributes.insert("padding".into(), format!("{padding}{}", "x".repeat(excess)).into());
    assert!(repo.accept_import(&authority, "oversized-work", &fingerprint, &oversized, None, 2).await.is_err());
    let operation = repo.accept_import(&authority, "legacy-import", &fingerprint, &work, None, 2).await.unwrap();
    let claim = repo.claim_import(&p.tenant_id, &operation.id, 120_000).await.unwrap().unwrap();
    let resumed = repo.import_execution(&p.tenant_id, &claim).await.unwrap();
    assert_eq!(resumed.work.provenance_expansion_bytes, work.provenance_expansion_bytes);
    assert_eq!(repo.commit_import(&p.tenant_id, &claim).await.unwrap().outcome, "committed");
    for (original, imported) in source.iter().zip(&work.cards) {
        let saved = repo.get_card(&p.tenant_id, &imported.id).await.unwrap().unwrap();
        let metadata = saved.content.unwrap();
        assert_eq!(metadata.publication, "published");
        assert_eq!(metadata.provenance.source_id.as_deref(), Some(original.id.as_str()));
        assert_eq!(metadata.provenance.source_revision, Some(7));
        assert_eq!(metadata.provenance.source_publication_claim.as_deref(), Some("published"));
        assert_eq!(saved.revision, 1);
        assert_ne!(saved.id, original.id);
        assert_eq!(saved.attributes, original.attributes);
    }
    assert_eq!(repo.feed_summary(&p.tenant_id, &p.user_id, None).await.unwrap().total_cards, 500);
    let oversized = legacy_pack(IMPORT_CONTENT_BYTES + 1);
    assert!(service.prepare_deck_pack(&p, oversized.clone(), false).is_err());
    assert!(service.prepare_portable_deck_pack(&p, portable_wire(oversized)).is_err());
}

#[tokio::test]
async fn legacy_1_0_near_content_boundary() {
    legacy_import_at_boundary(false, 1024).await;
}

#[tokio::test]
async fn legacy_1_0_exact_content_boundary() {
    legacy_import_at_boundary(false, 0).await;
}

#[tokio::test]
async fn legacy_2_0_near_content_boundary() {
    legacy_import_at_boundary(true, 1024).await;
}

#[tokio::test]
async fn legacy_2_0_exact_content_boundary() {
    legacy_import_at_boundary(true, 0).await;
}

#[tokio::test]
async fn provenance_budget_survives_destination_publication_choice() {
    let repo = Arc::new(SqliteRepository::in_memory().await.unwrap());
    let service = ContentService::new(repo);
    let mut pack = memoswish_protocol::examples::sample_deck_pack();
    for card in &mut pack.cards {
        card.content = None;
    }
    let mut work = service.prepare_deck_pack(&Principal::local_owner("test"), pack, false).unwrap();
    assert!(work.provenance_expansion_bytes > 0);
    let published_limit = work.cards_byte_limit().unwrap();
    for card in &mut work.cards {
        card.content.as_mut().unwrap().publication = "draft".into();
    }
    assert_eq!(work.cards_byte_limit().unwrap(), published_limit);
    work.provenance_expansion_bytes += 1;
    assert!(work.cards_byte_limit().is_err());
}

#[tokio::test]
async fn raw_legacy_long_source_identity_is_explicit_digest_in_both_formats() {
    let (repo, service, p) = legacy_service().await;
    for (index, source) in ["x".repeat(16_384), "汉".repeat(6000), "sha256:literal-source".into(), "x".repeat(1024)]
        .into_iter()
        .enumerate()
    {
        for portable in [false, true] {
            let mut wire = raw_legacy_pack(1);
            wire["cards"][0]["id"] = source.clone().into();
            let work = if portable {
                service.prepare_portable_deck_pack(&p, portable_wire(wire))
            } else {
                service.prepare_deck_pack(&p, wire, false)
            }
            .unwrap();
            let provenance = &work.cards[0].content.as_ref().unwrap().provenance;
            memoswish_core::content_lifecycle::validate_provenance(provenance).unwrap();
            assert_eq!(provenance.source_id_is_digest, source.len() > 1024);
            let expected = if source.len() > 1024 {
                format!("sha256:{}", memoswish_core::ids::sha256_hex(source.as_bytes()))
            } else {
                source.clone()
            };
            assert_eq!(provenance.source_id.as_ref(), Some(&expected));
            assert_eq!(provenance.source_revision, Some(7));
            assert_ne!(work.cards[0].id, source);
            assert_eq!(work.cards[0].revision, 1);
            assert!(serde_json::to_vec(provenance).unwrap().len() <= 16_384);
            work.cards_byte_limit().unwrap();
            let authority = ImportAuthority::capture(&p, None);
            let operation = repo
                .accept_import(&authority, &format!("source-{index}-{portable}"), &"c".repeat(64), &work, None, 2)
                .await
                .unwrap();
            let claim = repo.claim_import(&p.tenant_id, &operation.id, 120_000).await.unwrap().unwrap();
            let resumed = repo.import_execution(&p.tenant_id, &claim).await.unwrap();
            assert_eq!(resumed.work.cards[0].content, work.cards[0].content);
            assert_eq!(repo.commit_import(&p.tenant_id, &claim).await.unwrap().outcome, "committed");
            let saved = repo.get_card(&p.tenant_id, &work.cards[0].id).await.unwrap().unwrap();
            assert_eq!(saved.content, work.cards[0].content);
        }
    }
}
