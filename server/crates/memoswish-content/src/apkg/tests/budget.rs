//! 旧 APKG 正文预算与服务端元数据分账，覆盖真实解析及持久恢复。
use super::*;
use memoswish_core::imports::{IMPORT_CONTENT_BYTES, ImportAuthority, PORTABLE_SNAPSHOT_BYTES, json_bytes};

async fn database() -> Vec<u8> {
    let bytes = support::database("basic", "Question\x1fAnswer", &vec![0; 500]).await;
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    conn.deserialize(None, sqlx::sqlite::SqliteOwnedBuf::try_from(bytes.as_slice()).unwrap(), false).await.unwrap();
    sqlx::query("UPDATE notes SET guid = ?").bind("g".repeat(15_909)).execute(&mut conn).await.unwrap();
    conn.serialize(None).await.unwrap().to_vec()
}

// 冻结旧线字段集合，新增当前模型字段不得悄悄改变旧 APKG 预算的回归基准。
fn legacy_cards(cards: &[Card]) -> Vec<serde_json::Value> {
    let shape: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../compatibility/history/2.13.0/protocol/fixtures/card-rich.json"
    ))
    .unwrap();
    assert!(shape.get("content").is_none());
    cards
        .iter()
        .map(|card| {
            let current = serde_json::to_value(card).unwrap();
            let fields: serde_json::Map<_, _> = shape
                .as_object()
                .unwrap()
                .keys()
                .filter_map(|key| current.get(key).map(|value| (key.clone(), value.clone())))
                .collect();
            serde_json::Value::Object(fields)
        })
        .collect()
}

#[tokio::test]
async fn apkg_reviewer_near_limit_survives_admission_recovery_and_publication_choice() {
    let _guard = IMPORT_TEST.lock().await;
    let bytes = support::zip(vec![("collection.anki2", database().await), ("media", b"{}".to_vec())]);
    for publish in [true, false] {
        let (svc, repo, _) = service().await;
        let p = Principal::local_owner("test");
        let prepared = svc.prepare_apkg(&p, bytes.clone(), ApkgOptions::default()).await.unwrap();
        let mut work = prepared.work().unwrap();
        assert_eq!(prepared.card_count(), 500);
        let legacy = legacy_cards(&work.cards);
        assert_eq!(legacy[0]["attributes"]["anki"]["guid"].as_str().unwrap().len(), 15_909);
        let legacy_size = json_bytes(&legacy, IMPORT_CONTENT_BYTES).unwrap();
        assert!(IMPORT_CONTENT_BYTES - legacy_size < 10_000);
        let expanded_size = json_bytes(&work.cards, PORTABLE_SNAPSHOT_BYTES).unwrap();
        assert!(expanded_size > IMPORT_CONTENT_BYTES);
        assert_eq!(work.provenance_expansion_bytes, expanded_size - legacy_size);
        assert_eq!(work.provenance_expansion_bytes, 68_000);
        let published_limit = work.cards_byte_limit().unwrap();
        if !publish {
            for card in &mut work.cards {
                card.content.as_mut().unwrap().publication = "draft".into();
            }
        }
        assert_eq!(work.cards_byte_limit().unwrap(), published_limit);
        let authority = ImportAuthority::capture(&p, None);
        let fingerprint = "a".repeat(64);
        let mut invalid = work.clone();
        invalid.provenance_expansion_bytes = 0;
        assert!(repo.accept_import(&authority, "missing-allowance", &fingerprint, &invalid, None, 2).await.is_err());
        invalid.provenance_expansion_bytes = PORTABLE_SNAPSHOT_BYTES;
        assert!(repo.accept_import(&authority, "forged-allowance", &fingerprint, &invalid, None, 2).await.is_err());
        let op = repo.accept_import(&authority, "near-limit", &fingerprint, &work, None, 2).await.unwrap();
        drop(prepared);
        let claim = repo.claim_import(&p.tenant_id, &op.id, 120_000).await.unwrap().unwrap();
        let resumed = repo.import_execution(&p.tenant_id, &claim).await.unwrap();
        assert_eq!(resumed.work.provenance_expansion_bytes, work.provenance_expansion_bytes);
        assert_eq!(
            json_bytes(&resumed.work.cards, published_limit).unwrap(),
            json_bytes(&work.cards, published_limit).unwrap()
        );
        assert_eq!(repo.commit_import(&p.tenant_id, &claim).await.unwrap().outcome, "committed");
        for (index, original) in work.cards.iter().enumerate() {
            let saved = repo.get_card(&p.tenant_id, &original.id).await.unwrap().unwrap();
            assert_eq!(saved.attributes, original.attributes);
            assert_eq!(saved.content, original.content);
            let metadata = saved.content.unwrap();
            assert_eq!(metadata.publication, if publish { "published" } else { "draft" });
            assert_eq!(metadata.provenance.method, "import");
            assert_eq!(metadata.provenance.source_id, Some(format!("anki:{}", 200 + index)));
            assert_eq!(saved.revision, 1);
        }
        assert_eq!(
            repo.feed_summary(&p.tenant_id, &p.user_id, None).await.unwrap().total_cards,
            if publish { 500 } else { 0 }
        );
    }
}

// 固定时钟只用于精确边界；先读取真实 SQLite 集合，再进入相同准备逻辑。
async fn prepare_at_boundary(bytes: &[u8], legacy_array_size: usize) -> CoreResult<PreparedApkg> {
    let now = "2026-11-11T00:00:00.123456789Z".parse().unwrap();
    let mut collection = collection::read(bytes).await.unwrap();
    let p = Principal::local_owner("test");
    let probe = prepare(
        p.clone(),
        ApkgOptions::default(),
        BTreeMap::new(),
        collection::read(bytes).await.unwrap(),
        sha256_hex(bytes),
        (
            IMPORTS.try_acquire().unwrap(),
            memoswish_core::observability::Slot::new(
                memoswish_core::observability::noop(),
                memoswish_core::observability::AdmissionClass::Import,
            ),
        ),
        now,
    )
    .unwrap();
    let size = json_bytes(&legacy_cards(&probe.cards), IMPORT_CONTENT_BYTES).unwrap();
    drop(probe);
    // 单独一张卡补足余量，GUID 仍低于原 256 KiB 字段上限。
    let note = collection.notes.get(&100).unwrap();
    collection.notes.insert(
        101,
        collection::Note {
            id: 101,
            mid: note.mid,
            guid: format!("{}{}", note.guid, "g".repeat(legacy_array_size - size)),
            tags: note.tags.clone(),
            fields: note.fields.clone(),
        },
    );
    collection.cards[0].nid = 101;
    prepare(
        p,
        ApkgOptions::default(),
        BTreeMap::new(),
        collection,
        sha256_hex(bytes),
        (
            IMPORTS.try_acquire().unwrap(),
            memoswish_core::observability::Slot::new(
                memoswish_core::observability::noop(),
                memoswish_core::observability::AdmissionClass::Import,
            ),
        ),
        now,
    )
}

#[tokio::test]
async fn apkg_exact_legacy_array_budget_and_oversized_content() {
    let _guard = IMPORT_TEST.lock().await;
    let bytes = database().await;
    let (svc, repo, _) = service().await;
    let p = Principal::local_owner("test");
    let authority = ImportAuthority::capture(&p, None);
    let fingerprint = "b".repeat(64);
    for excess in [0, 1] {
        let prepared = prepare_at_boundary(&bytes, IMPORT_CONTENT_BYTES + excess).await.unwrap();
        let work = prepared.work().unwrap();
        assert_eq!(
            json_bytes(&legacy_cards(&work.cards), PORTABLE_SNAPSHOT_BYTES).unwrap(),
            IMPORT_CONTENT_BYTES + excess
        );
        let result = repo.accept_import(&authority, &format!("boundary-{excess}"), &fingerprint, &work, None, 2).await;
        if excess == 0 {
            let op = result.unwrap();
            assert_eq!(svc.drive_import(&p.tenant_id, &op.id).await.unwrap().outcome, "committed");
        } else {
            assert!(result.is_err());
        }
    }
    // 旧规范化总量不含数组括号及逗号；超出一字节仍在准备阶段拒绝。
    let error = prepare_at_boundary(&bytes, IMPORT_CONTENT_BYTES + 502).await.err().unwrap();
    assert!(error.to_string().contains("normalized APKG cards exceed 8 MiB"), "{error}");
}
