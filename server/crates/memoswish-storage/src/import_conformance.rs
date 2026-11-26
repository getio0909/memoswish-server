//! 持久导入在独立连接、故障回滚、租约接管及原始凭据撤销下的双库验收。
use memoswish_core::{CoreError, Principal, assets::*, imports::*, repo::*};
use memoswish_protocol::{CardFace, ContentBlock};

pub(crate) async fn authority(repo: &impl Repository) -> (ImportAuthority, String) {
    let mut p = crate::asset_conformance::seed(repo).await;
    let id = memoswish_core::ids::new_id();
    let hash = memoswish_core::ids::sha256_hex(id.as_bytes());
    let scopes = vec!["*".into()];
    repo.issue_api_token(&ApiTokenRecord {
        id: id.clone(),
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        name: "Import".into(),
        token_hash: hash.clone(),
        generations: p.credential_generations().unwrap(),
        scopes: scopes.clone(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    })
    .await
    .unwrap();
    p.via = "api_token".into();
    p.scopes = Some(scopes);
    (ImportAuthority::capture(&p, Some(ImportCredential { token_hash: Some(hash), expires_at: None })), id)
}
fn work(media: usize) -> ImportWork {
    let mut deck = memoswish_protocol::examples::sample_deck();
    deck.id = memoswish_core::ids::new_id();
    deck.card_count = 2;
    let cards = (0..2)
        .map(|_| {
            let mut c = memoswish_protocol::examples::sample_card();
            c.revision = 1;
            c.id = memoswish_core::ids::new_id();
            c.deck_id = deck.id.clone();
            c.tts = None;
            c.bgm = None;
            c.visual.image = None;
            c.front = CardFace::simple("Import", "");
            c.back = CardFace::simple("Back", "");
            c
        })
        .collect();
    let mut w = ImportWork {
        result: serde_json::to_value(&deck).unwrap(),
        deck,
        cards,
        media: vec![],
        auto_tts: false,
        identity_expansion_bytes: 0,
        provenance_expansion_bytes: 0,
    };
    for i in 0..media {
        let asset = memoswish_protocol::AssetRef {
            key: format!("tenants/placeholder/imports/image-{i}"),
            url: String::new(),
            mime: "image/png".into(),
            bytes: 3,
            sha256: memoswish_core::ids::sha256_hex(b"abc"),
        };
        for c in &mut w.cards {
            c.front.blocks.push(ContentBlock::Image { asset: asset.clone(), alt: String::new() });
        }
        w.media.push(ImportMedia { asset, bytes: b"abc".to_vec() });
    }
    w
}
pub(crate) fn owned_work(p: &Principal, media: usize) -> ImportWork {
    let mut w = work(media);
    for m in &mut w.media {
        m.asset.key = m.asset.key.replacen("tenants/placeholder/", &p.asset_prefix(), 1);
    }
    for c in &mut w.cards {
        for (_, a) in card_asset_slots_mut(c) {
            a.key = a.key.replacen("tenants/placeholder/", &p.asset_prefix(), 1);
        }
    }
    w
}
fn fingerprint() -> String {
    "a".repeat(64)
}

async fn portable_identity_bounds(repo: &impl Repository) {
    let (a, _) = authority(repo).await;
    let p = a.principal();
    let mut w = owned_work(&p, 1);
    w.cards.truncate(1);
    w.deck.card_count = 1;
    w.result = serde_json::to_value(&w.deck).unwrap();
    let card = &mut w.cards[0];
    for face in [&mut card.front, &mut card.back] {
        face.blocks = vec![ContentBlock::Image { asset: w.media[0].asset.clone(), alt: String::new() }; 32];
    }
    let mut source = w.cards.clone();
    source[0].id = "c".into();
    source[0].deck_id = "d".into();
    for (_, asset) in card_asset_slots_mut(&mut source[0]) {
        asset.key = "m0".into();
    }
    source[0].attributes.insert("padding".into(), "".into());
    let base = json_bytes(&source, IMPORT_CONTENT_BYTES).unwrap();
    source[0].attributes.insert("padding".into(), "x".repeat(IMPORT_CONTENT_BYTES - base).into());
    assert_eq!(json_bytes(&source, IMPORT_CONTENT_BYTES).unwrap(), IMPORT_CONTENT_BYTES);
    w.cards[0].attributes = source[0].attributes.clone();
    let size = json_bytes(&w.cards, PORTABLE_SNAPSHOT_BYTES).unwrap();
    assert!(size > IMPORT_CONTENT_BYTES);
    w.identity_expansion_bytes = size - IMPORT_CONTENT_BYTES;
    assert_eq!(w.cards_byte_limit().unwrap(), size);
    // 缺字段的旧工作继续解码为零额度，不能借便携修复扩大全局限制。
    let mut old = serde_json::to_value(&w).unwrap();
    old.as_object_mut().unwrap().remove("identity_expansion_bytes");
    old.as_object_mut().unwrap().remove("provenance_expansion_bytes");
    let legacy: ImportWork = serde_json::from_value(old).unwrap();
    assert_eq!(legacy.identity_expansion_bytes, 0);
    assert_eq!(legacy.provenance_expansion_bytes, 0);
    assert!(repo.accept_import(&a, "legacy-bound", &fingerprint(), &legacy, None, 2).await.is_err());
    let mut over = w.clone();
    over.cards[0]
        .attributes
        .insert("padding".into(), format!("{}x", source[0].attributes["padding"].as_str().unwrap()).into());
    assert!(repo.accept_import(&a, "portable-over", &fingerprint(), &over, None, 2).await.is_err());
    over.identity_expansion_bytes = PORTABLE_SNAPSHOT_BYTES;
    assert!(repo.accept_import(&a, "forged-bound", &fingerprint(), &over, None, 2).await.is_err());
    assert!(repo.pending_imports(None).await.unwrap().is_empty());
    assert_eq!(repo.held_import_usage(&p.tenant_id, &chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(), 0);
    assert!(repo.list_decks(&p.tenant_id).await.unwrap().is_empty());
    // 两库均在原正文和身份预算已满时，单独持久化来源增量并恢复执行。
    w.cards[0].content = Some(memoswish_protocol::ContentMetadata {
        observed_generation: None,
        publication: "published".into(),
        provenance: memoswish_protocol::ContentProvenance {
            method: "import".into(),
            source_id: Some("c".into()),
            source_revision: Some(7),
            ..Default::default()
        },
    });
    w.provenance_expansion_bytes = json_bytes(&w.cards, PORTABLE_SNAPSHOT_BYTES).unwrap() - size;
    assert!(w.provenance_expansion_bytes > 0);
    assert_eq!(w.cards_byte_limit().unwrap(), size + w.provenance_expansion_bytes);
    let mut missing = w.clone();
    missing.provenance_expansion_bytes = 0;
    assert!(repo.accept_import(&a, "missing-provenance-bound", &fingerprint(), &missing, None, 2).await.is_err());
    let op = repo.accept_import(&a, "portable-exact", &fingerprint(), &w, None, 2).await.unwrap();
    let claim = repo.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
    let resumed = repo.import_execution(&p.tenant_id, &claim).await.unwrap();
    assert_eq!(resumed.work.identity_expansion_bytes, w.identity_expansion_bytes);
    assert_eq!(resumed.work.provenance_expansion_bytes, w.provenance_expansion_bytes);
    let attempt = repo.begin_import_upload(&p.tenant_id, &claim, 0, "bounds-store").await.unwrap();
    repo.record_upload(&p.tenant_id, &attempt, &ObjectVersion::Unversioned).await.unwrap();
    repo.select_import_upload(&p.tenant_id, &claim, 0, &attempt.id).await.unwrap();
    repo.commit_import(&p.tenant_id, &claim).await.unwrap();
    let snapshot = repo.portable_snapshot(&a, &w.deck.id).await.unwrap();
    let assets = card_assets(&snapshot.cards[0]);
    assert_eq!(assets.len(), 64);
    assert!(assets.iter().all(|asset| asset.key == attempt.key));
    let delivery =
        repo.asset_delivery(&p, &attempt.key, memoswish_core::Permission::ContentRead).await.unwrap().unwrap();
    assert_eq!(repo.asset_reference_count(&p.tenant_id, &delivery.asset_id).await.unwrap(), 64);
}
async fn portable_read_authority(repo: &impl Repository) {
    let (mut a, old) = authority(repo).await;
    let w = owned_work(&a.principal, 0);
    repo.insert_deck_with_cards(&a.principal.tenant_id, &w.deck, &w.cards).await.unwrap();
    let token = memoswish_core::ids::new_id();
    let hash = memoswish_core::ids::sha256_hex(token.as_bytes());
    a.principal.scopes = Some(vec!["content:read".into()]);
    a.token_hash = Some(hash.clone());
    repo.issue_api_token(&ApiTokenRecord {
        id: token.clone(),
        tenant_id: a.principal.tenant_id.clone(),
        user_id: a.principal.user_id.clone(),
        name: "Read only".into(),
        token_hash: hash,
        generations: a.principal.credential_generations().unwrap(),
        scopes: a.principal.scopes.clone().unwrap(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    })
    .await
    .unwrap();
    let snapshot = repo.portable_snapshot(&a, &w.deck.id).await.unwrap();
    assert_eq!(snapshot.cards, w.cards);
    repo.revalidate_portable_export(&a).await.unwrap();
    let mut large = w.clone();
    large.deck.id = memoswish_core::ids::new_id();
    large.deck.card_count = 500;
    large.cards = (0..500)
        .map(|_| {
            let mut c = w.cards[0].clone();
            c.id = memoswish_core::ids::new_id();
            c.deck_id = large.deck.id.clone();
            c
        })
        .collect();
    repo.insert_deck_with_cards(&a.principal.tenant_id, &large.deck, &large.cards).await.unwrap();
    assert_eq!(repo.portable_snapshot(&a, &large.deck.id).await.unwrap().cards.len(), 500);
    let mut extra = large.cards[0].clone();
    extra.id = memoswish_core::ids::new_id();
    repo.insert_card(&a.principal.tenant_id, &extra).await.unwrap();
    assert!(matches!(repo.portable_snapshot(&a, &large.deck.id).await, Err(CoreError::Unsupported(_))));
    assert!(repo.accept_import(&a, "denied", &fingerprint(), &w, None, 2).await.is_err());
    let mut foreign = a.clone();
    foreign.principal.tenant_id.push('x');
    assert!(repo.portable_snapshot(&foreign, &w.deck.id).await.is_err());
    repo.revoke_api_token(&a.principal.tenant_id, &token).await.unwrap();
    assert!(repo.revalidate_portable_export(&a).await.is_err());
    assert!(repo.portable_snapshot(&a, &w.deck.id).await.is_err());
    assert!(repo.get_deck(&a.principal.tenant_id, &w.deck.id).await.unwrap().is_some());
    repo.revoke_api_token(&a.principal.tenant_id, &old).await.unwrap();
}

async fn portable_reexport_bounds(repo: &impl Repository) {
    let (a, _) = authority(repo).await;
    let p = a.principal();
    let mut w = owned_work(&p, 1);
    w.cards.truncate(1);
    w.deck.card_count = 1;
    let card = &mut w.cards[0];
    for face in [&mut card.front, &mut card.back] {
        face.blocks = vec![ContentBlock::Image { asset: w.media[0].asset.clone(), alt: String::new() }; 32];
    }
    let mut source = memoswish_protocol::DeckPack {
        version: "1.0".into(),
        deck: w.deck.clone(),
        cards: w.cards.clone(),
        exported_at: chrono::DateTime::UNIX_EPOCH,
    };
    source.deck.id = "d".into();
    source.deck.created_at = chrono::DateTime::UNIX_EPOCH;
    source.cards[0].id.clear();
    source.cards[0].deck_id = "d".into();
    source.cards[0].created_at = chrono::DateTime::UNIX_EPOCH;
    source.cards[0].updated_at = chrono::DateTime::UNIX_EPOCH;
    for (_, asset) in card_asset_slots_mut(&mut source.cards[0]) {
        asset.key = "A".into();
    }
    source.cards[0].attributes.insert("padding".into(), "".into());
    let base = json_bytes(&source, IMPORT_CONTENT_BYTES).unwrap();
    source.cards[0].attributes.insert("padding".into(), "x".repeat(IMPORT_CONTENT_BYTES - base).into());
    assert_eq!(json_bytes(&source, IMPORT_CONTENT_BYTES).unwrap(), IMPORT_CONTENT_BYTES);
    w.cards[0].attributes = source.cards[0].attributes.clone();
    w.result = serde_json::to_value(&w.deck).unwrap();
    w.identity_expansion_bytes = json_bytes(&w.cards, PORTABLE_SNAPSHOT_BYTES).unwrap()
        - json_bytes(&source.cards, IMPORT_CONTENT_BYTES).unwrap();
    let op = repo.accept_import(&a, "reexport-exact", &fingerprint(), &w, None, 2).await.unwrap();
    let claim = repo.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
    assert_eq!(
        repo.import_execution(&p.tenant_id, &claim).await.unwrap().work.identity_expansion_bytes,
        w.identity_expansion_bytes
    );
    let attempt = repo.begin_import_upload(&p.tenant_id, &claim, 0, "reexport-store").await.unwrap();
    repo.record_upload(&p.tenant_id, &attempt, &ObjectVersion::Unversioned).await.unwrap();
    repo.select_import_upload(&p.tenant_id, &claim, 0, &attempt.id).await.unwrap();
    repo.commit_import(&p.tenant_id, &claim).await.unwrap();
    let mut exported = repo.portable_snapshot(&a, &w.deck.id).await.unwrap();
    assert_ne!(exported.deck.id, source.deck.id);
    assert_ne!(exported.cards[0].id, source.cards[0].id);
    assert!(card_assets(&exported.cards[0]).iter().all(|asset| asset.key == attempt.key));
    let media_ids = portable_export_content(&mut exported);
    assert_eq!(media_ids[&attempt.key], "A");
    assert_eq!(json_bytes(&exported, IMPORT_CONTENT_BYTES).unwrap(), IMPORT_CONTENT_BYTES);
    assert_eq!(exported, source);
    exported.cards[0]
        .attributes
        .insert("padding".into(), format!("{}x", source.cards[0].attributes["padding"].as_str().unwrap()).into());
    assert!(json_bytes(&exported, IMPORT_CONTENT_BYTES).is_err());
}

async fn legacy_assets(repo: &impl Repository) {
    for case in [
        "valid",
        "sha256",
        "bytes",
        "mime",
        "foreign",
        "uploads",
        "missing",
        "removed",
        "changed-sha256",
        "changed-bytes",
        "changed-mime",
    ] {
        let (a, _) = authority(repo).await;
        let p = a.principal();
        let mut legacy = owned_work(&p, 1);
        legacy.media.clear();
        if matches!(case, "foreign" | "uploads") {
            for card in &mut legacy.cards {
                for (_, asset) in card_asset_slots_mut(card) {
                    asset.key = if case == "foreign" {
                        format!("tenants/{}-extra/imports/image-0", p.tenant_id)
                    } else {
                        format!("{}uploads/fabricated", p.asset_prefix())
                    };
                }
            }
        }
        repo.insert_deck_with_cards(&p.tenant_id, &legacy.deck, &legacy.cards).await.unwrap();
        let mut w = owned_work(&p, 0);
        for card in &mut w.cards {
            card.front.blocks = legacy.cards[0].front.blocks.clone();
            for (_, asset) in card_asset_slots_mut(card) {
                match case {
                    "sha256" => asset.sha256 = "b".repeat(64),
                    "bytes" => asset.bytes += 1,
                    "mime" => asset.mime = "image/jpeg".into(),
                    "missing" => asset.key.push_str("-missing"),
                    _ => {}
                }
            }
        }
        let accepted = repo.accept_import(&a, case, &fingerprint(), &w, None, 2).await;
        let period = chrono::Utc::now().format("%Y-%m").to_string();
        if !matches!(case, "valid" | "removed") && !case.starts_with("changed-") {
            assert!(matches!(accepted, Err(CoreError::Forbidden(_))), "case: {case}");
            assert_eq!(repo.list_decks(&p.tenant_id).await.unwrap().len(), 1);
            assert_eq!(repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), 0);
            assert_eq!(repo.get_usage(&p.tenant_id, "card_writes", &period).await.unwrap(), 0);
            continue;
        }
        let op = accepted.unwrap();
        let claim = repo.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
        // 准入时的旧卡片证据不能替代最终提交时的证据。
        if case == "removed" || case.starts_with("changed-") {
            for card in &legacy.cards {
                assert!(repo.delete_card(&p.tenant_id, &card.id).await.unwrap());
            }
            if case.starts_with("changed-") {
                for card in &mut legacy.cards {
                    card.id = memoswish_core::ids::new_id();
                    for (_, asset) in card_asset_slots_mut(card) {
                        match case {
                            "changed-sha256" => asset.sha256 = "b".repeat(64),
                            "changed-bytes" => asset.bytes += 1,
                            "changed-mime" => asset.mime = "image/jpeg".into(),
                            _ => unreachable!(),
                        }
                    }
                    repo.insert_card(&p.tenant_id, card).await.unwrap();
                }
            }
            assert!(matches!(repo.commit_import(&p.tenant_id, &claim).await, Err(CoreError::Forbidden(_))));
            assert!(repo.get_deck(&p.tenant_id, &w.deck.id).await.unwrap().is_none());
            assert_eq!(repo.import_operation(&p.tenant_id, &op.id).await.unwrap().outcome, "pending");
            assert_eq!(repo.get_usage(&p.tenant_id, "card_writes", &period).await.unwrap(), 0);
            repo.fail_import(&p.tenant_id, &claim).await.unwrap();
            continue;
        }
        let receipt = repo.commit_import(&p.tenant_id, &claim).await.unwrap();
        assert_eq!(receipt.result, Some(w.result.clone()));
        let replay = repo.accept_import(&a, case, &fingerprint(), &w, None, 2).await.unwrap();
        let lookup = repo.lookup_import(&a, case, &fingerprint()).await.unwrap().unwrap();
        for observed in [replay, lookup] {
            assert_eq!(observed.id, receipt.id);
            assert_eq!(observed.outcome, "committed");
            assert_eq!(observed.result, receipt.result);
        }
        for card in &w.cards {
            assert_eq!(repo.get_card(&p.tenant_id, &card.id).await.unwrap(), Some(card.clone()));
        }
        let key = &card_assets(&w.cards[0])[0].key;
        assert!(repo.asset_delivery(&p, key, memoswish_core::Permission::ContentRead).await.unwrap().is_none());
        assert_eq!(repo.list_decks(&p.tenant_id).await.unwrap().len(), 2);
        assert_eq!(repo.get_usage(&p.tenant_id, "card_writes", &period).await.unwrap(), 2);
        assert_eq!(repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), 0);
    }
}
async fn replay_and_quota(repo: &impl Repository, other: &impl Repository) {
    let (a, _) = authority(repo).await;
    let p = a.principal();
    let w = work(0);
    let hash = fingerprint();
    let barrier = tokio::sync::Barrier::new(2);
    let (first, second) = tokio::join!(
        async {
            barrier.wait().await;
            repo.accept_import(&a, "same", &hash, &w, Some(2), 2).await
        },
        async {
            barrier.wait().await;
            other.accept_import(&a, "same", &hash, &w, Some(2), 2).await
        }
    );
    let op = first.unwrap();
    assert_eq!(repo.import_status(&a, "same").await.unwrap().unwrap().outcome, "pending");
    assert_eq!(op.id, second.unwrap().id);
    assert!(matches!(
        repo.accept_import(&a, "same", &"b".repeat(64), &w, Some(2), 2).await,
        Err(CoreError::Conflict(_))
    ));
    let period = chrono::Utc::now().format("%Y-%m").to_string();
    assert_eq!(repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), 2);
    assert!(repo.try_add_usage(&p.tenant_id, "card_writes", &period, 1, 2).await.unwrap().is_none());
    assert!(matches!(
        other.accept_import(&a, "quota", &hash, &work(0), Some(2), 2).await,
        Err(CoreError::QuotaExceeded(_))
    ));
    let c = repo.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
    assert!(other.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().is_none());
    let receipt = repo.commit_import(&p.tenant_id, &c).await.unwrap();
    assert_eq!(receipt.result, Some(w.result));
    let status = other.import_status(&a, "same").await.unwrap().unwrap();
    assert_eq!(status.outcome, "committed");
    assert!(status.result.is_none());
    assert_eq!(repo.get_usage(&p.tenant_id, "card_writes", &period).await.unwrap(), 2);
    assert_eq!(repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), 0);
    assert!(repo.commit_import(&p.tenant_id, &c).await.is_err());
    assert_eq!(other.lookup_import(&a, "same", &hash).await.unwrap().unwrap().result, receipt.result);
    assert_eq!(repo.list_decks(&p.tenant_id).await.unwrap().len(), 1);
    let (mut foreign, _) = authority(repo).await;
    foreign.principal.tenant_id = p.tenant_id.clone();
    assert!(repo.lookup_import(&foreign, "same", &hash).await.is_err());
    assert!(repo.import_status(&foreign, "same").await.is_err());
    let alternate = memoswish_core::ids::new_id();
    let alternate_hash = memoswish_core::ids::sha256_hex(alternate.as_bytes());
    repo.issue_api_token(&ApiTokenRecord {
        id: alternate,
        tenant_id: p.tenant_id.clone(),
        user_id: p.user_id.clone(),
        name: "Alternate status credential".into(),
        token_hash: alternate_hash.clone(),
        generations: p.credential_generations().unwrap(),
        scopes: p.scopes.clone().unwrap(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked: false,
    })
    .await
    .unwrap();
    let mut changed = a.clone();
    changed.token_hash = Some(alternate_hash);
    assert!(repo.import_status(&changed, "same").await.unwrap().is_none());
    let (_, token) = authority(repo).await;
    assert!(!repo.revoke_api_token(&p.tenant_id, &token).await.unwrap());
}
async fn reservations_race(repo: &impl Repository, other: &impl Repository) {
    let (a, _) = authority(repo).await;
    let hash = fingerprint();
    let w = work(0);
    let period = chrono::Utc::now().format("%Y-%m").to_string();
    let w2 = work(0);
    let (i, j) = tokio::join!(
        repo.accept_import(&a, "first", &hash, &w, Some(2), 2),
        other.accept_import(&a, "second", &hash, &w2, Some(2), 2)
    );
    assert_eq!([i.is_ok(), j.is_ok()].into_iter().filter(|v| *v).count(), 1);
    let (b, _) = authority(repo).await;
    let (i, j) = tokio::join!(
        repo.accept_import(&b, "import", &hash, &w, Some(2), 2),
        other.try_add_usage(&b.principal.tenant_id, "card_writes", &period, 1, 2)
    );
    assert_ne!(i.is_ok(), j.unwrap().is_some());
    let (d, _) = authority(repo).await;
    for key in ["one", "two"] {
        repo.accept_import(&d, key, &hash, &work(0), None, 2).await.unwrap();
    }
    assert!(matches!(
        repo.accept_import(&d, "three", &hash, &work(0), None, 2).await,
        Err(CoreError::QuotaExceeded(_))
    ));
    assert!(repo.accept_import(&d, "one", &hash, &work(0), None, 2).await.is_ok());
}
async fn authority_revocation(repo: &impl Repository) {
    for reason in ["token", "membership", "tenant"] {
        let (a, id) = authority(repo).await;
        let p = a.principal();
        let op = repo.accept_import(&a, "revoke", &fingerprint(), &work(0), None, 2).await.unwrap();
        let c = repo.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
        match reason {
            "token" => {
                repo.revoke_api_token(&p.tenant_id, &id).await.unwrap();
            }
            "membership" => {
                repo.membership_remove(&p.tenant_id, &p.user_id).await.unwrap();
            }
            _ => {
                repo.account_erase(&p.tenant_id, &p.user_id, true).await.unwrap();
            }
        }
        assert!(repo.import_status(&a, "revoke").await.is_err());
        assert!(repo.commit_import(&p.tenant_id, &c).await.is_err());
        if reason == "tenant" {
            assert!(matches!(repo.fail_import(&p.tenant_id, &c).await, Err(CoreError::Conflict(_))));
        } else {
            repo.fail_import(&p.tenant_id, &c).await.unwrap();
        }
        assert_eq!(repo.import_operation(&p.tenant_id, &op.id).await.unwrap().outcome, "failed");
        assert!(repo.list_decks(&p.tenant_id).await.unwrap().is_empty());
    }
}
macro_rules! fault_suite {
    ($repo:ty,$pool:ty,$expire:expr,$trigger:expr,$drop:expr,$migrations:literal) => {
 async fn oauth_cases(repo:&$repo) {
    use memoswish_core::oauth::*;
    for change in ["revoke","token_expiry","client_expiry"] {
        let (mut authority,_)=authority(repo).await;let p=&mut authority.principal;let now=chrono::Utc::now().timestamp();
        let client=OAuthClient{id:memoswish_core::ids::new_id(),name:"Imports".into(),redirect_uris:vec!["http://127.0.0.1/callback".into()],grant_types:vec!["authorization_code".into()],scopes:vec!["content:write".into()],auth_method:"none".into(),secret_hash:None,created_at:now,expires_at:now+3600};repo.oauth_register(&client).await.unwrap();
        let grant=OAuthGrant{generations:p.credential_generations().unwrap(),id:memoswish_core::ids::new_id(),tenant_id:p.tenant_id.clone(),user_id:p.user_id.clone(),client_id:client.id.clone(),resource:"https://learn.example/mcp".into(),scopes:client.scopes.clone(),expires_at:now+3600};
        let token=OAuthToken{hash:memoswish_core::ids::new_id(),grant:grant.clone(),scopes:client.scopes.clone(),kind:"access".into(),expires_at:now+600};
        sqlx::query("INSERT INTO oauth_grants(id,tenant_id,user_id,client_id,expires_at,metadata) VALUES($1,$2,$3,$4,$5,$6)").bind(&grant.id).bind(&grant.tenant_id).bind(&grant.user_id).bind(&grant.client_id).bind(grant.expires_at).bind(serde_json::to_string(&grant).unwrap()).execute(repo.pool()).await.unwrap();
        sqlx::query("INSERT INTO oauth_tokens(hash,tenant_id,grant_id,kind,expires_at,body) VALUES($1,$2,$3,'access',$4,$5)").bind(&token.hash).bind(&grant.tenant_id).bind(&grant.id).bind(token.expires_at).bind(serde_json::to_string(&token).unwrap()).execute(repo.pool()).await.unwrap();
        p.via="mcp_oauth".into();p.scopes=Some(client.scopes.clone());authority.token_hash=Some(token.hash.clone());
        let op=repo.accept_import(&authority,"oauth",&fingerprint(),&work(0),None,2).await.unwrap();let claim=repo.claim_import(&grant.tenant_id,&op.id,30_000).await.unwrap().unwrap();
        match change {"revoke"=>{repo.oauth_revoke(&grant.tenant_id,&grant.id).await.unwrap();},"token_expiry"=>{sqlx::query("UPDATE oauth_tokens SET expires_at=0 WHERE hash=$1").bind(&token.hash).execute(repo.pool()).await.unwrap();},_=>{sqlx::query("UPDATE oauth_clients SET expires_at=0 WHERE id=$1").bind(&client.id).execute(repo.pool()).await.unwrap();}}
        assert!(repo.commit_import(&grant.tenant_id,&claim).await.is_err());repo.fail_import(&grant.tenant_id,&claim).await.unwrap();assert!(repo.list_decks(&grant.tenant_id).await.unwrap().is_empty());
    }
 }

        async fn session_cases(repo:&$repo) {
    use memoswish_core::session::*;
    for change in ["rotate","logout","all","expiry","legacy","role","epoch","rejoin"] {
        let (mut a,_)=authority(repo).await;let mut p=a.principal();let now=chrono::Utc::now().timestamp();
        let family=SessionFamily{id:memoswish_core::ids::new_id(),user_id:p.user_id.clone(),generation:0,provenance:"password".into(),auth_time:now-10,expires_at:now+3600,revoked:false};
        let credential=crate::session_conformance::credential(&family,Some((p.tenant_id.clone(),0)));repo.session_issue(&family,&credential,None).await.unwrap();
        p.via="session".into();p.scopes=None;p.session_access_hash=Some(credential.access_hash.clone());
        if change=="legacy" {p.via="jwt".into();p.session_access_hash=None;p.legacy_issued_at=Some(now-10);}
        a=ImportAuthority::capture(&p,Some(ImportCredential{token_hash:None,expires_at:Some(now+600)}));
        let op=repo.accept_import(&a,"original-capability",&fingerprint(),&work(0),None,2).await.unwrap();let claim=repo.claim_import(&p.tenant_id,&op.id,30_000).await.unwrap().unwrap();
        match change {
            "rotate"=>{repo.session_rotate(&credential.refresh_hash,&memoswish_core::ids::new_id(),&memoswish_core::ids::new_id(),&memoswish_core::ids::new_id(),600).await.unwrap();},
            "logout"=>{repo.session_revoke(&credential.access_hash,&family.id).await.unwrap();},
            "all"|"legacy"=>{let mut root_family=family.clone();root_family.id=memoswish_core::ids::new_id();let root=crate::session_conformance::credential(&root_family,None);repo.session_issue(&root_family,&root,None).await.unwrap();repo.session_revoke_all(&root.access_hash).await.unwrap();},
            "expiry"=>{sqlx::query("UPDATE app_session_credentials SET expires_at=0 WHERE access_hash=$1").bind(&credential.access_hash).execute(repo.pool()).await.unwrap();},
            "role"=>{sqlx::query("UPDATE tenant_memberships SET role='learner' WHERE tenant_id=$1 AND user_id=$2").bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();},
            "epoch"=>{sqlx::query("UPDATE account_auth_epochs SET generation=1 WHERE user_id=$1").bind(&p.user_id).execute(repo.pool()).await.unwrap();},
            _=>{repo.membership_remove(&p.tenant_id,&p.user_id).await.unwrap();repo.membership_join(&p.tenant_id,&p.user_id,memoswish_core::Role::Owner).await.unwrap();},
        }
        assert!(repo.import_execution(&p.tenant_id,&claim).await.is_err());assert!(repo.commit_import(&p.tenant_id,&claim).await.is_err());repo.fail_import(&p.tenant_id,&claim).await.unwrap();assert!(repo.list_decks(&p.tenant_id).await.unwrap().is_empty());
    }
 }
 async fn lifecycle_interactions(repo:&$repo) {
    use memoswish_core::lifecycle::{AccountAuthority,DeleteWorkspace,LifecycleRepo};
    use memoswish_core::erasure::ErasureRepo;
    use memoswish_core::identity::IdentityRepo;
    for mode in ["delete","leave","legacy-owner","legacy-member"] {
        let (a,_)=authority(repo).await;
        let mut p=a.principal();p.via="single_user".into();p.scopes=None;
        let (peer,_)=authority(repo).await;
        let peer_work=work(0);
        let peer_op=repo.accept_import(&peer,"peer-import",&fingerprint(),&peer_work,None,2).await.unwrap();
        let w=owned_work(&p,1);
        let staged=repo.accept_import(&a,"private-staging",&fingerprint(),&w,None,2).await.unwrap();
        let claim=repo.claim_import(&p.tenant_id,&staged.id,30_000).await.unwrap().unwrap();
        let upload=repo.begin_import_upload(&p.tenant_id,&claim,0,"store").await.unwrap();
        let mut committed_work=work(0);committed_work.auto_tts=true;
        let committed=repo.accept_import(&a,"private-receipt",&fingerprint(),&committed_work,None,2).await.unwrap();
        let committed_claim=repo.claim_import(&p.tenant_id,&committed.id,30_000).await.unwrap().unwrap();
        repo.commit_import(&p.tenant_id,&committed_claim).await.unwrap();
        let personal=repo.export_personal(&AccountAuthority::Workspace(p.clone())).await.unwrap();
        assert_eq!(personal.workspaces[0].data["content_imports"].len(),2);
        assert_eq!(personal.workspaces[0].data["import_followups"].len(),2);
        let personal_json=serde_json::to_string(&personal).unwrap();
        for secret in ["token_hash","authority",a.token_hash.as_deref().unwrap(),&peer_op.id] {assert!(!personal_json.contains(secret));}
        let shared=repo.export_workspace(&p).await.unwrap();
        assert_eq!(shared.data["content_imports"].len(),2);
        assert_eq!(shared.data["import_followups"].len(),2);
        let exported=serde_json::to_string(&shared).unwrap();
        for secret in ["token_hash","authority","work",a.token_hash.as_deref().unwrap(),&peer_op.id] {assert!(!exported.contains(secret));}
        if matches!(mode,"leave"|"legacy-member") {
            repo.membership_join(&p.tenant_id,&peer.principal.user_id,memoswish_core::Role::Owner).await.unwrap();
            if mode=="leave" {repo.leave_workspace(&p).await.unwrap();} else {sqlx::query("UPDATE tenant_memberships SET role='admin' WHERE tenant_id=$1 AND user_id=$2").bind(&p.tenant_id).bind(&p.user_id).execute(repo.pool()).await.unwrap();repo.account_erase(&p.tenant_id,&p.user_id,false).await.unwrap();}
            assert_eq!(repo.list_decks(&p.tenant_id).await.unwrap().len(),1);
        } else {
            let erased=if mode=="delete" {repo.delete_workspace(&p,&DeleteWorkspace{confirmed_tenant_id:p.tenant_id.clone()}).await.unwrap()} else {repo.account_erase(&p.tenant_id,&p.user_id,true).await.unwrap()};
            let erasure_claim=repo.claim_erasure(&erased.id,"test",30_000).await.unwrap().unwrap();
            let objects=repo.erasure_objects(&erasure_claim,("",""),100).await.unwrap();
            assert!(objects.iter().any(|o|o.id==upload.id && o.version==ObjectVersion::Unknown));
            assert!(repo.complete_erasure(&erasure_claim).await.is_err());
            // 晚到精确回执仍归原 S19 清理责任，擦除不能将未知对象当作完成。
            repo.record_upload(&p.tenant_id,&upload,&ObjectVersion::VersionId("late-version".into())).await.unwrap();
            let objects=repo.erasure_objects(&erasure_claim,("",""),100).await.unwrap();
            assert!(objects.iter().any(|o|o.id==upload.id && o.version==ObjectVersion::VersionId("late-version".into())));
        }
        let rows:Vec<(String,String,Option<String>)>=sqlx::query_as("SELECT authority,work,result FROM content_imports WHERE tenant_id=$1").bind(&p.tenant_id).fetch_all(repo.pool()).await.unwrap();
        assert_eq!(rows.len(),2);assert!(rows.iter().all(|r|r==&("{}".into(),"{}".into(),None)));
        assert!(repo.import_followups(&p.tenant_id,&committed.id).await.unwrap().is_empty());
        assert_eq!(repo.held_import_usage(&p.tenant_id,&chrono::Utc::now().format("%Y-%m").to_string()).await.unwrap(),0);
        assert!(repo.commit_import(&p.tenant_id,&claim).await.is_err());
        assert_eq!(repo.import_operation(&peer.principal.tenant_id,&peer_op.id).await.unwrap().outcome,"pending");
    }
 }
 async fn followup_receipts_survive_credential_revocation(repo:&$repo) {
    use memoswish_core::{tts::*,lifecycle::LifecycleRepo};
    for attached in [false,true] {
        let (authority,token)=authority(repo).await;
        let mut p=authority.principal();p.session_access_hash=authority.token_hash.as_ref().map(|h|format!("api:{h}"));
        let mut w=work(0);w.auto_tts=true;w.cards.truncate(1);w.deck.card_count=1;w.result=serde_json::to_value(&w.deck).unwrap();
        let op=repo.accept_import(&authority,"canonical-followup",&fingerprint(),&w,None,2).await.unwrap();
        let claim=repo.claim_import(&p.tenant_id,&op.id,30_000).await.unwrap().unwrap();repo.commit_import(&p.tenant_id,&claim).await.unwrap();
        let request_id=format!("import:{}:{}",op.id,w.cards[0].id);
        let target=SpeechSubmissionTarget{card_id:w.cards[0].id.clone(),revision:1,work:SpeechWork{ provenance: None,privacy:None,engine:"test".into(),namespace:"config".into(),request:TtsRequest{text:"abc".into(),language:"en".into(),voice:"default".into(),speed:1.0},amount:3,legacy_output:None}};
        let submission=repo.submit_speech(&p,&request_id,&fingerprint(),&[target],None).await.unwrap();
        let item=&submission.items[0].item_id;
        if attached {
            let speech=repo.speech_request(&p.tenant_id,item).await.unwrap();
            let claim=repo.claim_speech(&p.tenant_id,&speech.synthesis_id,30_000).await.unwrap().unwrap();repo.begin_provider(&p.tenant_id,&claim).await.unwrap();
            let spec=AssetSpec{mime:"audio/mpeg".into(),size:3,sha256:memoswish_core::ids::sha256_hex(b"abc")};
            let metadata=SpeechMetadata{ alignment_quality: None, audio_kind: None, provenance: None,extension:"mp3".into(),duration_ms:100,words:vec![]};
            repo.materialize_speech(&p.tenant_id,&claim,b"abc",&spec,&metadata,false).await.unwrap();
            let (upload,_)=repo.speech_upload(&p.tenant_id,&speech.synthesis_id).await.unwrap().unwrap();
            let claim=repo.claim_speech(&p.tenant_id,&upload,30_000).await.unwrap().unwrap();
            let attempt=repo.begin_upload(&p.tenant_id,&claim,"store").await.unwrap();repo.record_upload(&p.tenant_id,&attempt,&ObjectVersion::Unversioned).await.unwrap();repo.publish_speech(&p.tenant_id,&claim,&attempt.id).await.unwrap();
            repo.resolve_speech_attachment(&p.tenant_id,item).await.unwrap();
        }
        repo.revoke_api_token(&p.tenant_id,&token).await.unwrap();
        assert!(repo.speech_submission(&p,&request_id,None).await.is_err());
        repo.import_followup(&p.tenant_id,&op.id,&w.cards[0].id,"failed").await.unwrap();
        let current: String=sqlx::query_scalar("SELECT outcome FROM import_followups WHERE tenant_id=$1 AND import_id=$2").bind(&p.tenant_id).bind(&op.id).fetch_one(repo.pool()).await.unwrap();
        assert_eq!(current,if attached {"succeeded"} else {"running"});
        if !attached {
            repo.resolve_speech_attachment(&p.tenant_id,item).await.unwrap();
            repo.import_followup(&p.tenant_id,&op.id,&w.cards[0].id,"failed").await.unwrap();
        }
        assert!(repo.import_followups(&p.tenant_id,&op.id).await.unwrap().is_empty());
        assert_eq!(repo.import_operation(&p.tenant_id,&op.id).await.unwrap().result,Some(w.result));
        let mut reader=p;reader.via="single_user".into();reader.scopes=None;reader.session_access_hash=None;
        let exported=repo.export_workspace(&reader).await.unwrap();
        assert_eq!(exported.data["import_followups"][0]["outcome"],if attached {"succeeded"} else {"failed"});
    }
 }
 async fn upgrade(pool:&$pool) {
    use crate::foundation_conformance::{through,LEGACY_DATA};
    let full=sqlx::migrate!($migrations);through(&full,8).run(pool).await.unwrap();sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();through(&full,25).run(pool).await.unwrap();
    sqlx::raw_sql("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES('foundation','s18-preserved','tts','s18-preserved','{}','account',7,3,100); INSERT INTO quota_operations VALUES('foundation','s18-preserved','card_writes','2026-11',17,'reserved');").execute(pool).await.unwrap();
    let before:String=sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id='foundation' LIMIT 1").fetch_one(pool).await.unwrap();
    let mut broken=through(&full,26);let index=broken.migrations.len()-1;let m=&broken.migrations[index];let version=m.version;let sql=format!("{}\nSELECT * FROM s18_injected_missing_table;",m.sql);broken.migrations.to_mut()[index]=sqlx::migrate::Migration::new(version,"injected failure".into(),sqlx::migrate::MigrationType::Simple,sql.into(),false);
    assert!(broken.run(pool).await.is_err());let last:i64=sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();assert_eq!(last,25);assert!(sqlx::query("SELECT id FROM content_imports").fetch_all(pool).await.is_err());
    full.run(pool).await.unwrap();full.run(pool).await.unwrap();let after:String=sqlx::query_scalar("SELECT CAST(body AS TEXT) FROM cards WHERE tenant_id='foundation' LIMIT 1").fetch_one(pool).await.unwrap();assert_eq!(before,after);let held:i64=sqlx::query_scalar("SELECT amount FROM quota_operations WHERE tenant_id='foundation' AND operation_id='s18-preserved'").fetch_one(pool).await.unwrap();assert_eq!(held,17);
 }

 async fn unsupported_job_headers(repo: &$repo) {
    let (a, _) = authority(repo).await;
    let p = a.principal();
    let w = owned_work(&p, 1);
    let op = repo.accept_import(&a, "unsupported-job", &fingerprint(), &w, None, 2).await.unwrap();
    let period = chrono::Utc::now().format("%Y-%m").to_string();
    let staged: String = sqlx::query_scalar("SELECT work FROM content_imports WHERE tenant_id=$1 AND id=$2")
        .bind(&p.tenant_id).bind(&op.id).fetch_one(repo.pool()).await.unwrap();
    for (kind, payload) in [
        ("future_import", serde_json::json!({})),
        ("content_import", serde_json::json!({"version":999})),
    ] {
        for attempts in [0_i64, 5] {
            sqlx::query("UPDATE background_jobs SET kind=$3,payload=$4,attempts=$5 WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&op.id).bind(kind).bind(sqlx::types::Json(payload.clone())).bind(attempts)
                .execute(repo.pool()).await.unwrap();
            assert!(repo.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().is_none());
            let current: (String, i64, Option<String>) = sqlx::query_as("SELECT state,attempts,token FROM background_jobs WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&op.id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(current, ("queued".into(), attempts, None));
            let remaining: String = sqlx::query_scalar("SELECT work FROM content_imports WHERE tenant_id=$1 AND id=$2")
                .bind(&p.tenant_id).bind(&op.id).fetch_one(repo.pool()).await.unwrap();
            assert_eq!(remaining, staged);
            assert_eq!(repo.import_operation(&p.tenant_id, &op.id).await.unwrap().outcome, "pending");
            assert_eq!(repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), 2);
            assert!(repo.list_decks(&p.tenant_id).await.unwrap().is_empty());
        }
    }
    sqlx::query("UPDATE background_jobs SET kind='content_import',payload=$3,attempts=0 WHERE tenant_id=$1 AND id=$2")
        .bind(&p.tenant_id).bind(&op.id).bind(sqlx::types::Json(serde_json::json!({}))).execute(repo.pool()).await.unwrap();
    let claim = repo.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
    assert_eq!(repo.import_execution(&p.tenant_id, &claim).await.unwrap().work.media.len(), 1);
    repo.fail_import(&p.tenant_id, &claim).await.unwrap();
    assert_eq!(repo.held_import_usage(&p.tenant_id, &period).await.unwrap(), 0);
 }

 async fn fault_cases(repo: &$repo, other: &$repo) {
            let (a, _) = authority(repo).await;
            let p = a.principal();
            let mut w = owned_work(&p, 2);
            w.media[1].asset.mime="audio/wav".into();
            for c in &mut w.cards {
                c.front.blocks.truncate(1);
                c.back.blocks.push(ContentBlock::Image{asset:w.media[0].asset.clone(),alt:"Back".into()});
                c.visual.image=Some(w.media[0].asset.clone());
                c.tts=memoswish_protocol::examples::sample_card().tts;
                c.tts.as_mut().unwrap().audio=w.media[1].asset.clone();
                c.bgm=memoswish_protocol::examples::sample_card().bgm;
                c.bgm.as_mut().unwrap().track.asset=w.media[1].asset.clone();
            }
            let op = repo.accept_import(&a, "media", &fingerprint(), &w, None, 2).await.unwrap();
            let old = repo.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
            let first = repo.begin_import_upload(&p.tenant_id, &old, 0, "store").await.unwrap();
            repo.record_upload(&p.tenant_id, &first, &ObjectVersion::VersionId("null".into())).await.unwrap();
            repo.select_import_upload(&p.tenant_id, &old, 0, &first.id).await.unwrap();
            let late = repo.begin_import_upload(&p.tenant_id, &old, 1, "store").await.unwrap();
            sqlx::query($expire).bind(&p.tenant_id).bind(&op.id).execute(repo.pool()).await.unwrap();
            let current = other.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
            assert!(repo.select_import_upload(&p.tenant_id, &old, 1, &late.id).await.is_err());
            let selected = other.begin_import_upload(&p.tenant_id, &current, 0, "store").await.unwrap();
            assert_eq!(selected.id, first.id);
            let second = other.begin_import_upload(&p.tenant_id, &current, 1, "store").await.unwrap();
            assert_ne!(late.key, second.key);
            other.record_upload(&p.tenant_id, &second, &ObjectVersion::Unversioned).await.unwrap();
            other.select_import_upload(&p.tenant_id, &current, 1, &second.id).await.unwrap();
            sqlx::raw_sql($trigger).execute(repo.pool()).await.unwrap();
            assert!(other.commit_import(&p.tenant_id, &current).await.is_err());
            assert!(repo.list_decks(&p.tenant_id).await.unwrap().is_empty());
            assert!(
                repo.asset_intent(&p.tenant_id, &first.intent_id).await.unwrap().unwrap().published_attempt.is_none()
            );
            assert!(repo.import_operation(&p.tenant_id, &op.id).await.unwrap().result.is_none());
            assert!(repo.import_cleanup(&p.tenant_id, &op.id, "store").await.unwrap().is_empty());
            sqlx::raw_sql($drop).execute(repo.pool()).await.unwrap();
            let receipt = other.commit_import(&p.tenant_id, &current).await.unwrap();
            assert_eq!(receipt.outcome, "committed");
            for (index,asset) in [&first, &second].into_iter().enumerate() {
                let delivery =
                    repo.asset_delivery(&p, &asset.key, memoswish_core::Permission::ContentRead).await.unwrap().unwrap();
                assert_eq!(repo.asset_reference_count(&p.tenant_id, &delivery.asset_id).await.unwrap(), if index==0 {6} else {4});
            }
            assert!(repo.pending_imports(None).await.unwrap().contains(&(p.tenant_id.clone(), op.id.clone())));
            assert!(repo.import_cleanup(&p.tenant_id, &op.id, "store").await.unwrap().is_empty());
            repo.record_upload(&p.tenant_id, &late, &ObjectVersion::VersionId("late".into())).await.unwrap();
            assert!(repo.import_cleanup(&p.tenant_id, &op.id, "foreign-store").await.unwrap().is_empty());
            let cleanup = repo.import_cleanup(&p.tenant_id, &op.id, "store").await.unwrap();
            assert_eq!(cleanup.len(), 1);
            assert_eq!(cleanup[0].id, late.id);
            assert_eq!(repo.import_cleanup(&p.tenant_id, &op.id, "store").await.unwrap()[0].id, late.id);
            repo.record_asset_cleaned(&p.tenant_id, &cleanup[0]).await.unwrap();
            assert!(repo.import_cleanup(&p.tenant_id, &op.id, "store").await.unwrap().is_empty());
            let (b, _) = authority(repo).await;
            let pending = repo.accept_import(&b, "month", &fingerprint(), &work(0), None, 2).await.unwrap();
            sqlx::query("UPDATE quota_operations SET period='2000-01' WHERE tenant_id=$1 AND operation_id=$2")
                .bind(&b.principal.tenant_id)
                .bind(&pending.id)
                .execute(repo.pool())
                .await
                .unwrap();
            let c = repo.claim_import(&b.principal.tenant_id, &pending.id, 30_000).await.unwrap().unwrap();
            repo.commit_import(&b.principal.tenant_id, &c).await.unwrap();
            assert_eq!(repo.get_usage(&b.principal.tenant_id, "card_writes", "2000-01").await.unwrap(), 2);
        }
    };
}
#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use crate::sqlite::SqliteRepository;
    #[tokio::test]
    async fn sqlite_portable_identity_bounds() {
        let repo = SqliteRepository::in_memory().await.unwrap();
        portable_identity_bounds(&repo).await;
        portable_reexport_bounds(&repo).await;
        repo.pool().close().await;
    }
    fault_suite!(
        SqliteRepository,
        sqlx::SqlitePool,
        "UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2",
        "CREATE TRIGGER reject_import BEFORE UPDATE OF result ON content_imports WHEN NEW.outcome='committed' BEGIN SELECT RAISE(ABORT,'injected result failure'); END;",
        "DROP TRIGGER reject_import;",
        "./migrations/sqlite"
    );
    #[tokio::test]
    async fn sqlite_import_legacy_assets() {
        let repo = SqliteRepository::in_memory().await.unwrap();
        legacy_assets(&repo).await;
        portable_read_authority(&repo).await;
        repo.pool().close().await;
    }
    #[tokio::test]
    async fn sqlite_import_populated_upgrade() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        upgrade(&pool).await;
        pool.close().await;
    }
    #[tokio::test]
    async fn sqlite_import_conformance_and_restart() {
        let path = std::env::temp_dir().join(format!("memoswish-import-{}.db", memoswish_core::ids::new_id()));
        let url = format!("sqlite://{}", path.display());
        let repo = SqliteRepository::connect_test(&url).await.unwrap();
        let other = SqliteRepository::connect_test(&url).await.unwrap();
        replay_and_quota(&repo, &other).await;
        reservations_race(&repo, &other).await;
        authority_revocation(&repo).await;
        unsupported_job_headers(&repo).await;
        fault_cases(&repo, &other).await;
        followup_receipts_survive_credential_revocation(&repo).await;
        lifecycle_interactions(&repo).await;
        session_cases(&repo).await;
        oauth_cases(&repo).await;
        let (a, _) = authority(&repo).await;
        let w = work(0);
        let op = repo.accept_import(&a, "restart", &fingerprint(), &w, None, 2).await.unwrap();
        let completed_work = work(0);
        let completed =
            repo.accept_import(&a, "restart-receipt", &fingerprint(), &completed_work, None, 2).await.unwrap();
        let claim = repo.claim_import(&a.principal.tenant_id, &completed.id, 30_000).await.unwrap().unwrap();
        let saved_receipt = repo.commit_import(&a.principal.tenant_id, &claim).await.unwrap();
        let source_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM content_imports").fetch_one(repo.pool()).await.unwrap();
        assert!(std::fs::metadata(format!("{}-wal", path.display())).unwrap().len() > 32);
        let restored = path.with_extension("restored.db");
        // close 不保证 SQLite worker 已完成最后一次 checkpoint；复用 C13 的一致快照原语。
        // VACUUM INTO 的完成点同时覆盖主库和 WAL，不能直接复制主文件。
        sqlx::query("VACUUM INTO $1").bind(restored.to_str().unwrap()).execute(repo.pool()).await.unwrap();
        repo.pool().close().await;
        other.pool().close().await;
        let repo = SqliteRepository::connect_test(&format!("sqlite://{}", restored.display())).await.unwrap();
        let restored_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM content_imports").fetch_one(repo.pool()).await.unwrap();
        assert_eq!(restored_count, source_count);
        let pending = repo.import_operation(&a.principal.tenant_id, &op.id).await.unwrap();
        assert_eq!(pending.id, op.id);
        assert_eq!(pending.outcome, op.outcome);
        assert_eq!(pending.outcome, "pending");
        assert!(pending.result.is_none());
        let restored_receipt = repo.import_operation(&a.principal.tenant_id, &completed.id).await.unwrap();
        assert_eq!(restored_receipt.id, saved_receipt.id);
        assert_eq!(restored_receipt.outcome, saved_receipt.outcome);
        assert_eq!(restored_receipt.result, saved_receipt.result);
        assert_eq!(restored_receipt.result, Some(completed_work.result));
        assert_eq!(repo.lookup_import(&a, "restart-receipt", &fingerprint()).await.unwrap().unwrap().id, completed.id);
        let c = repo.claim_import(&a.principal.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
        let receipt = repo.commit_import(&a.principal.tenant_id, &c).await.unwrap();
        assert_eq!(receipt.result, Some(w.result));
        assert_eq!(repo.lookup_import(&a, "restart", &fingerprint()).await.unwrap().unwrap().id, op.id);
        repo.pool().close().await;
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(restored).unwrap();
    }
}
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use crate::postgres::PostgresRepository;
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_portable_identity_bounds() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let f = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let repo = f.repository(2).await.unwrap();
            portable_identity_bounds(&repo).await;
            portable_reexport_bounds(&repo).await;
            repo.pool().close().await;
            f.cleanup().await;
        });
    }
    fault_suite!(
        PostgresRepository,
        sqlx::PgPool,
        "UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND id=$2",
        "CREATE FUNCTION reject_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected result failure'; END $$; CREATE TRIGGER reject_import BEFORE UPDATE OF result ON content_imports FOR EACH ROW EXECUTE FUNCTION reject_import();",
        "DROP TRIGGER reject_import ON content_imports; DROP FUNCTION reject_import();",
        "./migrations/postgres"
    );
    #[test]
    #[ignore = "integration: requires PostgreSQL, pg_dump and pg_restore"]
    fn postgres_import_pending_cold_restore() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let url = crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap();
            let f = test.fixture(&url).await;
            let repo = f.repository(2).await.unwrap();
            let (a, _) = authority(&repo).await;
            let w = work(0);
            let op = repo.accept_import(&a, "cold-restore", &fingerprint(), &w, None, 2).await.unwrap();
            repo.pool().close().await;
            let dump = std::env::temp_dir().join(format!("memoswish-s18-{}.dump", memoswish_core::ids::new_id()));
            struct Dump(std::path::PathBuf);
            impl Drop for Dump {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(&self.0);
                }
            }
            let dump = Dump(dump);
            let backup = std::process::Command::new("pg_dump")
                .args(["--dbname", &url])
                .args(["--format=custom", "--no-owner", "--no-acl", "--schema", &f.schema, "--file"])
                .arg(&dump.0)
                .output()
                .expect("pg_dump is required");
            assert!(backup.status.success(), "pending import schema backup failed");
            assert!(
                f.schema.starts_with("learntok_test_")
                    && f.schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            );
            let admin =
                sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(f.options()).await.unwrap();
            sqlx::query(&format!("DROP SCHEMA {} CASCADE", f.schema)).execute(&admin).await.unwrap();
            admin.close().await;
            let restore = std::process::Command::new("pg_restore")
                .args(["--no-owner", "--no-acl", "--exit-on-error", "--dbname"])
                .arg(&url)
                .arg(&dump.0)
                .output()
                .expect("pg_restore is required");
            assert!(restore.status.success(), "pending import schema restore failed");
            let repo = f.repository(2).await.unwrap();
            assert_eq!(repo.lookup_import(&a, "cold-restore", &fingerprint()).await.unwrap().unwrap().id, op.id);
            let claim = repo.claim_import(&a.principal.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
            let receipt = repo.commit_import(&a.principal.tenant_id, &claim).await.unwrap();
            assert_eq!(receipt.result, Some(w.result));
            assert_eq!(repo.list_decks(&a.principal.tenant_id).await.unwrap().len(), 1);
            repo.pool().close().await;
            f.cleanup().await;
        });
    }
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_import_credential_expiry_after_row_lock() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let f = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let repo = f.repository(2).await.unwrap();
            let writer = f.repository(1).await.unwrap();
            let (a, token) = authority(&repo).await;
            let op = repo.accept_import(&a, "lock-expiry", &fingerprint(), &work(0), None, 2).await.unwrap();
            let claim = repo.claim_import(&a.principal.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
            let mut tx = repo.pool().begin().await.unwrap();
            sqlx::query("SELECT id FROM api_tokens WHERE id=$1 FOR UPDATE")
                .bind(&token)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(writer.pool()).await.unwrap();
            let tenant = a.principal.tenant_id.clone();
            let task = tokio::spawn(async move {
                let result = writer.commit_import(&tenant, &claim).await;
                writer.pool().close().await;
                result
            });
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let waiting: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",
                    )
                    .bind(pid)
                    .fetch_one(repo.pool())
                    .await
                    .unwrap();
                    if waiting {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            sqlx::query("UPDATE api_tokens SET expires_at=clock_timestamp()-interval '1 millisecond' WHERE id=$1")
                .bind(&token)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            assert!(task.await.unwrap().is_err());
            assert!(repo.list_decks(&a.principal.tenant_id).await.unwrap().is_empty());
            repo.pool().close().await;
            f.cleanup().await;
        });
    }
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_import_legacy_assets() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let f = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let repo = f.repository(2).await.unwrap();
            legacy_assets(&repo).await;
            repo.pool().close().await;
            f.cleanup().await;
        });
    }
    #[test]
    #[ignore = "integration: requires PostgreSQL"]
    fn postgres_import_conformance_and_restart() {
        crate::pg_test_support::run_pg_test(|test| async move {
            let f = test.fixture(&crate::test_environment::var("MEMOSWISH_TEST_POSTGRES_URL").unwrap()).await;
            let raw = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(f.options()).await.unwrap();
            upgrade(&raw).await;
            raw.close().await;
            let repo = f.repository(2).await.unwrap();
            let other = f.repository(2).await.unwrap();
            replay_and_quota(&repo, &other).await;
            reservations_race(&repo, &other).await;
            authority_revocation(&repo).await;
            unsupported_job_headers(&repo).await;
            fault_cases(&repo, &other).await;
            followup_receipts_survive_credential_revocation(&repo).await;
            lifecycle_interactions(&repo).await;
            session_cases(&repo).await;
            oauth_cases(&repo).await;
            let (a, _) = authority(&repo).await;
            let w = work(0);
            let op = repo.accept_import(&a, "restart", &fingerprint(), &w, None, 2).await.unwrap();
            repo.pool().close().await;
            other.pool().close().await;
            let repo = f.repository(2).await.unwrap();
            let c = repo.claim_import(&a.principal.tenant_id, &op.id, 30_000).await.unwrap().unwrap();
            assert_eq!(repo.commit_import(&a.principal.tenant_id, &c).await.unwrap().result, Some(w.result));
            repo.pool().close().await;
            f.cleanup().await;
        });
    }
}
