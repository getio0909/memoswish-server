//! 在仓储调用屏障上暂停，覆盖无媒体和最后一个去重槽位，时钟不依赖墙钟。
use super::*;
use memoswish_core::{
    repo::{AuthRepo, ContentRepo},
    store::ObjectStore,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;

struct QueryGate {
    stage: &'static str,
    ordinal: usize,
    visits: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
}
tokio::task_local! { static QUERY_GATE: Arc<QueryGate>; }

pub(super) async fn wait_at(stage: &str) {
    if let Ok(gate) = QUERY_GATE.try_with(Arc::clone)
        && gate.stage == stage
        && gate.visits.fetch_add(1, Ordering::SeqCst) == gate.ordinal
    {
        gate.entered.add_permits(1);
        gate.release.acquire().await.unwrap().forget();
    }
}

#[tokio::test]
async fn export_deadline_covers_snapshot_duplicate_selection_and_final_revalidation() {
    for (stage, ordinal, media) in [("snapshot", 0, false), ("select", 1, true), ("revalidate", 0, false)] {
        let f = crate::tests::fixture(None, None).await;
        let p = Principal::local_owner("test");
        let deck = memoswish_protocol::examples::sample_deck();
        f.repo.insert_deck(&p.tenant_id, &deck).await.unwrap();
        if media {
            let asset =
                f.store.put("tenants/local/imports/repeated.png", b"image".to_vec(), "image/png").await.unwrap();
            let mut card = memoswish_protocol::examples::sample_card();
            card.deck_id = deck.id.clone();
            card.tts = None;
            card.bgm = None;
            card.visual.image = Some(asset.clone());
            card.front.blocks = vec![memoswish_protocol::ContentBlock::Image { asset, alt: "重复引用".into() }];
            f.repo.insert_card(&p.tenant_id, &card).await.unwrap();
        }
        let mut exports = Vec::new();
        let mut gates = Vec::new();
        for _ in 0..2 {
            let gate = Arc::new(QueryGate {
                stage,
                ordinal,
                visits: AtomicUsize::new(0),
                entered: Semaphore::new(0),
                release: Semaphore::new(0),
            });
            let services = f.services.clone();
            let p = p.clone();
            let id = deck.id.clone();
            let task_gate = gate.clone();
            exports.push(tokio::spawn(
                QUERY_GATE.scope(task_gate, async move { services.export_portable_deck(&p, &id, None).await }),
            ));
            gate.entered.acquire().await.unwrap().forget();
            gates.push(gate);
        }
        assert_eq!(PORTABLE_WORK.available_permits(), 0);
        assert!(
            f.services
                .export_portable_deck(&p, &deck.id, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("capacity exhausted")
        );
        tokio::time::pause();
        tokio::time::advance(asset_delivery::DELIVERY_DEADLINE + std::time::Duration::from_millis(1)).await;
        for task in exports {
            assert!(task.await.unwrap().unwrap_err().to_string().contains("export deadline exceeded"), "{stage}");
        }
        assert_eq!(PORTABLE_WORK.available_permits(), 2);
        tokio::time::resume();
        let pack = f.services.export_portable_deck(&p, &deck.id, None).await.unwrap();
        assert_eq!(pack.media.len(), usize::from(media));
    }
}

#[tokio::test]
async fn export_final_authorization_is_retained_and_cancellation_releases_permit() {
    let f = crate::tests::fixture(None, None).await;
    let p = Principal::local_owner("test");
    let deck = memoswish_protocol::examples::sample_deck();
    f.repo.insert_deck(&p.tenant_id, &deck).await.unwrap();
    let gate = Arc::new(QueryGate {
        stage: "revalidate",
        ordinal: 0,
        visits: AtomicUsize::new(0),
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let token = f.services.auth.create_api_token(&p, "export", vec!["content:read".into()], None).await.unwrap();
    let principal = f.services.auth.authenticate(Some(&token.plaintext)).await.unwrap();
    let credential = ImportCredential {
        token_hash: Some(memoswish_core::ids::sha256_hex(token.plaintext.as_bytes())),
        expires_at: None,
    };
    let services = f.services.clone();
    let id = deck.id.clone();
    let task =
        tokio::spawn(QUERY_GATE.scope(gate.clone(), async move {
            services.export_portable_deck(&principal, &id, Some(credential)).await
        }));
    gate.entered.acquire().await.unwrap().forget();
    f.repo.revoke_api_token(&p.tenant_id, &token.record.id).await.unwrap();
    gate.release.add_permits(1);
    assert!(task.await.unwrap().is_err());
    assert_eq!(PORTABLE_WORK.available_permits(), 2);
    let services = f.services.clone();
    let id = deck.id.clone();
    let gate = Arc::new(QueryGate {
        stage: "snapshot",
        ordinal: 0,
        visits: AtomicUsize::new(0),
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let cancelled =
        tokio::spawn(QUERY_GATE.scope(gate.clone(), async move { services.export_portable_deck(&p, &id, None).await }));
    gate.entered.acquire().await.unwrap().forget();
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    assert_eq!(PORTABLE_WORK.available_permits(), 2);
}
