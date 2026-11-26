//! 测量元数据路径、区间放大及最终凭据屏障，保留旧缓冲路径回归。
use super::*;
use memoswish_core::Principal;
use memoswish_core::asset_read::{BLOCK_BYTES, ObjectReader, ReadIdentity};
use memoswish_core::store::{ObjectStore, StoredObject};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

struct CountingStore {
    inner: Arc<dyn ObjectStore>,
    reads: Arc<Mutex<Vec<(u64, usize)>>>,
    corrupt: Arc<AtomicBool>,
    pause: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
struct CountingReader {
    inner: Box<dyn ObjectReader>,
    reads: Arc<Mutex<Vec<(u64, usize)>>>,
    corrupt: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl ObjectReader for CountingReader {
    fn metadata(&self) -> &ReadIdentity {
        self.inner.metadata()
    }
    async fn read_at(&mut self, offset: u64, length: usize) -> memoswish_core::CoreResult<Vec<u8>> {
        self.reads.lock().unwrap().push((offset, length));
        let mut bytes = self.inner.read_at(offset, length).await?;
        if self.corrupt.load(Ordering::SeqCst) && offset == BLOCK_BYTES as u64 {
            bytes[0] ^= 1;
        }
        Ok(bytes)
    }
}
#[async_trait::async_trait]
impl ObjectStore for CountingStore {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn namespace(&self) -> memoswish_core::CoreResult<String> {
        self.inner.namespace()
    }
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
    async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        mime: &str,
    ) -> memoswish_core::CoreResult<memoswish_protocol::AssetRef> {
        self.inner.put(key, bytes, mime).await
    }
    async fn get(&self, key: &str) -> memoswish_core::CoreResult<Option<StoredObject>> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> memoswish_core::CoreResult<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> memoswish_core::CoreResult<()> {
        self.inner.delete(key).await
    }
    async fn read_legacy(&self, key: &str, limit: u64) -> memoswish_core::CoreResult<Option<StoredObject>> {
        self.inner.read_legacy(key, limit).await
    }
    async fn open_legacy(&self, key: &str, size: u64) -> memoswish_core::CoreResult<Option<Box<dyn ObjectReader>>> {
        let reader = self.inner.open_legacy(key, size).await?;
        if self.pause.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        Ok(reader.map(|inner| {
            Box::new(CountingReader { inner, reads: self.reads.clone(), corrupt: self.corrupt.clone() })
                as Box<dyn ObjectReader>
        }))
    }
}

async fn fixture(
    trusted: bool,
) -> (AppState, std::path::PathBuf, Arc<CountingStore>, memoswish_protocol::AssetRef, Principal) {
    let dir = std::env::temp_dir().join(format!("p39-stream-{}", memoswish_core::ids::new_id()));
    let mut st =
        AppState::build(Config { data_dir: dir.clone(), seed_demo: false, ..Default::default() }).await.unwrap();
    let p = Principal::local_owner("test");
    let deck = memoswish_protocol::examples::sample_deck();
    st.repo.insert_deck(&p.tenant_id, &deck).await.unwrap();
    let asset =
        st.store.put("tenants/local/imports/stream.png", vec![b'x'; 3 * BLOCK_BYTES + 17], "image/png").await.unwrap();
    let mut card = memoswish_protocol::examples::sample_card();
    card.deck_id = deck.id;
    card.tts = None;
    card.bgm = None;
    card.visual.image = Some(asset.clone());
    st.repo.insert_card(&p.tenant_id, &card).await.unwrap();
    if trusted {
        memoswish_application::asset_delivery::verify(
            st.repo.as_ref(),
            st.store.as_ref(),
            &p,
            &asset.key,
            "content",
            Some(&card.id),
            1024,
        )
        .await
        .unwrap();
    }
    let store = Arc::new(CountingStore {
        inner: st.store.clone(),
        reads: Arc::new(Mutex::new(vec![])),
        corrupt: Arc::new(AtomicBool::new(false)),
        pause: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    st.store = store.clone();
    (st, dir, store, asset, p)
}
fn url(asset: &memoswish_protocol::AssetRef) -> String {
    format!("/assets/{}?delivery=1&surface=content&owner={}", asset.key, memoswish_protocol::examples::sample_card().id)
}

#[tokio::test]
async fn streaming_metadata_conditions_and_aligned_ranges_measure_payload_reads() {
    let (st, dir, store, asset, _) = fixture(true).await;
    let app = crate::auth_defenses::test_router(st);
    let etag = format!("\"{}\"", asset.sha256);
    for condition in [etag.clone(), format!("\"other\", W/{etag}"), "*".into()] {
        let (status, _, body) = send(
            &app,
            Request::get(url(&asset))
                .header(header::IF_NONE_MATCH, condition)
                .header(header::RANGE, "bytes=0-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert!(body.is_empty());
    }
    let (status, h, body) =
        send(&app, Request::head(url(&asset)).header(header::RANGE, "bytes=0-1").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h[header::CONTENT_LENGTH], asset.bytes.to_string());
    assert!(body.is_empty());
    assert!(store.reads.lock().unwrap().is_empty(), "304 and HEAD must not consume payload");
    for (range, expected) in [
        ("bytes=0-0", vec![(0, BLOCK_BYTES)]),
        ("bytes=65535-65536", vec![(0, BLOCK_BYTES), (BLOCK_BYTES as u64, BLOCK_BYTES)]),
        ("bytes=-1", vec![(3 * BLOCK_BYTES as u64, 17)]),
    ] {
        store.reads.lock().unwrap().clear();
        let (status, _, body) = send(
            &app,
            Request::get(url(&asset))
                .header(header::RANGE, range)
                .header(header::IF_RANGE, &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body.len(), if range.contains("65535") { 2 } else { 1 });
        assert_eq!(*store.reads.lock().unwrap(), expected);
    }
    for range in ["bytes=-0", "bytes=3-2", "bytes=9999999-", "bytes=0-1,3-4", "bytes=18446744073709551616-"] {
        assert_eq!(
            send(&app, Request::get(url(&asset)).header(header::RANGE, range).body(Body::empty()).unwrap()).await.0,
            StatusCode::RANGE_NOT_SATISFIABLE
        );
    }
    let (status, _, body) = send(
        &app,
        Request::get(url(&asset))
            .header(header::RANGE, "bytes=0-0")
            .header(header::IF_RANGE, format!("W/{etag}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len() as u64, asset.bytes);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn streaming_legacy_verification_resumes_without_inventing_publication() {
    let (st, dir, _, asset, p) = fixture(false).await;
    let app = crate::auth_defenses::test_router(st.clone());
    let etag = format!("\"{}\"", asset.sha256);
    let request = || Request::get(url(&asset)).header(header::IF_NONE_MATCH, &etag).body(Body::empty()).unwrap();
    assert_eq!(send(&app, request()).await.0, StatusCode::OK);
    for index in 1..=4 {
        let manifest = memoswish_application::asset_delivery::verify(
            st.repo.as_ref(),
            st.store.as_ref(),
            &p,
            &asset.key,
            "content",
            Some(&memoswish_protocol::examples::sample_card().id),
            1,
        )
        .await
        .unwrap();
        assert_eq!(manifest.blocks.len(), index);
        assert_eq!(manifest.verified, index == 4);
    }
    assert_eq!(send(&app, request()).await.0, StatusCode::NOT_MODIFIED);
    assert!(st.repo.asset_delivery(&p, &asset.key, memoswish_core::Permission::ContentRead).await.unwrap().is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn streaming_late_corruption_aborts_before_corrupt_block() {
    use http_body_util::BodyExt;
    let (st, dir, store, asset, _) = fixture(true).await;
    store.corrupt.store(true, Ordering::SeqCst);
    let app = crate::auth_defenses::test_router(st);
    let rejected = app
        .clone()
        .oneshot(Request::get(url(&asset)).header(header::RANGE, "bytes=65536-65536").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        rejected.status(),
        StatusCode::CONFLICT,
        "a corrupt first selected block must fail before success headers"
    );
    let response = app.oneshot(get(&url(&asset))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(first.len(), BLOCK_BYTES);
    assert!(body.frame().await.unwrap().is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn streaming_final_credential_check_covers_get_range_head_and_304() {
    let (st, dir, store, asset, p) = fixture(true).await;
    let app = crate::auth_defenses::test_router(st.clone());
    let etag = format!("\"{}\"", asset.sha256);
    for (method, condition) in [
        ("GET", None),
        ("HEAD", None),
        ("GET", Some(("range", "bytes=0-0"))),
        ("GET", Some(("if-none-match", etag.as_str()))),
    ] {
        let token = st.services.auth.create_api_token(&p, "stream", vec!["content:read".into()], None).await.unwrap();
        store.pause.store(true, Ordering::SeqCst);
        let mut request = Request::builder()
            .method(method)
            .uri(url(&asset))
            .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext));
        if let Some((name, value)) = condition {
            request = request.header(name, value);
        }
        let app = app.clone();
        let waiting = tokio::spawn(async move { send(&app, request.body(Body::empty()).unwrap()).await });
        store.entered.notified().await;
        st.repo.revoke_api_token(&p.tenant_id, &token.record.id).await.unwrap();
        store.release.notify_one();
        assert_eq!(waiting.await.unwrap().0, StatusCode::UNAUTHORIZED);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn streaming_admitted_response_finishes_after_token_revocation() {
    use http_body_util::BodyExt;
    let (st, dir, store, asset, p) = fixture(true).await;
    let token = st.services.auth.create_api_token(&p, "admitted", vec!["content:read".into()], None).await.unwrap();
    let app = crate::auth_defenses::test_router(st.clone());
    let response = app
        .oneshot(
            Request::get(url(&asset))
                .header(header::AUTHORIZATION, format!("Bearer {}", token.plaintext))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(store.reads.lock().unwrap().len() <= 2, "channel capacity bounds lookahead before consumption");
    st.repo.revoke_api_token(&p.tenant_id, &token.record.id).await.unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.len() as u64, asset.bytes);
    assert_eq!(memoswish_core::ids::sha256_hex(&bytes), asset.sha256);
    assert_eq!(store.reads.lock().unwrap().len(), 4);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn streaming_original_attachment_deleted_during_metadata_open_rejects_304() {
    let (st, dir, store, asset, p) = fixture(true).await;
    store.pause.store(true, Ordering::SeqCst);
    let app = crate::auth_defenses::test_router(st.clone());
    let request = Request::head(url(&asset))
        .header(header::IF_NONE_MATCH, format!("\"{}\"", asset.sha256))
        .body(Body::empty())
        .unwrap();
    let waiting = tokio::spawn(async move { send(&app, request).await });
    store.entered.notified().await;
    assert!(st.repo.delete_card(&p.tenant_id, &memoswish_protocol::examples::sample_card().id).await.unwrap());
    store.release.notify_one();
    assert_eq!(waiting.await.unwrap().0, StatusCode::NOT_FOUND);
    assert!(store.reads.lock().unwrap().is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}
