//! 应用边界的执行顺序、取消所有权与失败回归。

use super::*;
use async_trait::async_trait;
use memoswish_auth::RateLimiter;
use memoswish_auth::{AuthConfig, Unlimited};
use memoswish_content::apkg::ApkgOptions;
use memoswish_core::imports::ImportRepo;
use memoswish_core::privacy::PrivacyRepo;
use memoswish_core::repo::{AuthRepo, ContentRepo};
use memoswish_core::store::{ObjectStore, StoredObject};
use memoswish_core::tts::{TtsEngine, TtsOutput, TtsRequest, VoiceInfo};
use memoswish_core::{CoreError, Role};
use memoswish_feed::FeedConfig;
use memoswish_media::tts::placeholder::PlaceholderTts;
use memoswish_protocol::{AssetRef, DeploymentMode};
use memoswish_storage::{LocalDiskStore, sqlite::SqliteRepository};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Semaphore;

#[path = "../../memoswish-content/tests/support/mod.rs"]
mod support;

static APKG_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(super) struct Gate {
    entered: Semaphore,
    release: Semaphore,
}
impl Gate {
    fn new() -> Self {
        Self { entered: Semaphore::new(0), release: Semaphore::new(0) }
    }
    async fn pause(&self) {
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
    }
    async fn reached(&self, count: u32) {
        self.entered.acquire_many(count).await.unwrap().forget();
    }
}

struct TestQuota {
    metered: Unlimited,
    calls: Mutex<Vec<(Metric, u64)>>,
    gate: Option<Arc<Gate>>,
    reject: AtomicBool,
}
#[async_trait]
impl QuotaPolicy for TestQuota {
    fn name(&self) -> &'static str {
        "application-test"
    }
    async fn consume(&self, p: &Principal, metric: Metric, amount: u64) -> CoreResult<()> {
        self.calls.lock().unwrap().push((metric, amount));
        if metric == Metric::CardWrites {
            if let Some(gate) = &self.gate {
                gate.pause().await;
            }
            if self.reject.load(Ordering::SeqCst) {
                return Err(CoreError::QuotaExceeded("injected quota rejection".into()));
            }
        }
        self.metered.consume(p, metric, amount).await
    }
    async fn card_write_limit(&self, _tenant: &str) -> CoreResult<Option<i64>> {
        if let Some(gate) = &self.gate {
            gate.pause().await;
        }
        if self.reject.load(Ordering::SeqCst) {
            return Err(CoreError::QuotaExceeded("injected quota rejection".into()));
        }
        Ok(None)
    }
    async fn snapshot(&self, p: &Principal) -> CoreResult<UsageSnapshot> {
        self.metered.snapshot(p).await
    }
}

pub(super) struct TestStore {
    inner: LocalDiskStore,
    gate: Option<Arc<Gate>>,
    fail_put: AtomicBool,
    puts: AtomicUsize,
}
#[async_trait]
impl ObjectStore for TestStore {
    fn kind(&self) -> &'static str {
        "application-test"
    }
    fn namespace(&self) -> CoreResult<String> {
        self.inner.namespace()
    }
    async fn read_legacy(&self, key: &str, limit: u64) -> CoreResult<Option<StoredObject>> {
        self.inner.read_legacy(key, limit).await
    }
    fn url_for(&self, key: &str) -> String {
        self.inner.url_for(key)
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        let asset = self.inner.put(key, bytes, mime).await?;
        if let Some(gate) = &self.gate {
            gate.pause().await;
        }
        if self.fail_put.load(Ordering::SeqCst) {
            return Err(CoreError::internal("injected failure after PUT"));
        }
        Ok(asset)
    }
    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> CoreResult<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> CoreResult<()> {
        self.inner.delete(key).await
    }
}

pub(super) struct Fixture {
    pub(super) services: Services,
    pub(super) repo: Arc<SqliteRepository>,
    quota: Arc<TestQuota>,
    pub(super) store: Arc<TestStore>,
    dir: std::path::PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
pub(super) async fn fixture(quota_gate: Option<Arc<Gate>>, put_gate: Option<Arc<Gate>>) -> Fixture {
    fixture_storage(quota_gate, put_gate, false).await
}

async fn fixture_storage(quota_gate: Option<Arc<Gate>>, put_gate: Option<Arc<Gate>>, durable: bool) -> Fixture {
    let dir = std::env::temp_dir().join(format!("memoswish-application-{}", memoswish_core::ids::new_id()));
    std::fs::create_dir_all(&dir).unwrap();
    // 持久恢复夹具的 schema 和业务状态随文件保留，不依赖单个内存连接的寿命。
    let repo = Arc::new(if durable {
        SqliteRepository::connect(&format!("sqlite://{}", dir.join("recovery.db").display())).await.unwrap()
    } else {
        SqliteRepository::in_memory().await.unwrap()
    });
    let store = Arc::new(TestStore {
        inner: LocalDiskStore::new(dir.clone(), "/assets"),
        gate: put_gate,
        fail_put: AtomicBool::new(false),
        puts: AtomicUsize::new(0),
    });
    let quota = Arc::new(TestQuota {
        metered: Unlimited::metered(repo.clone()),
        calls: Mutex::new(Vec::new()),
        gate: quota_gate,
        reject: AtomicBool::new(false),
    });
    let auth = AuthService::new(
        repo.clone(),
        AuthConfig {
            mode: DeploymentMode::SingleUser,
            jwt_secret: "a".repeat(32),
            jwt_ttl_secs: 3600,
            registration_open: false,
            default_plan: "self_hosted".into(),
        },
    )
    .unwrap();
    auth.bootstrap_local().await.unwrap();
    let services = Services {
        operations: Default::default(),
        auth,
        content: ContentService::new(repo.clone()).with_import_store(store.clone()),
        media: MediaService::new(
            repo.clone(),
            store.clone(),
            quota.clone(),
            vec![Arc::new(PlaceholderTts)],
            "placeholder",
        )
        .unwrap(),
        feed: FeedService::new(
            repo.clone(),
            FeedConfig::default(),
            std::sync::Arc::new(|| memoswish_protocol::examples::sample_feed_page().generated_at),
        )
        .unwrap(),
        quota: quota.clone(),
        limiter: Arc::new(RateLimiter::new(1000, 100.0)),
    };
    Fixture { services, repo, quota, store, dir }
}

async fn image_package() -> Vec<u8> {
    support::zip(vec![
        ("collection.anki2", support::database("basic", "Question<img src='x.png'>\x1fAnswer", &[0]).await),
        ("media", br#"{"0":"x.png"}"#.to_vec()),
        ("0", b"\x89PNG\r\n\x1a\nimage".to_vec()),
    ])
}

#[tokio::test]
async fn apkg_validation_permissions_and_quota_precede_side_effects() {
    let _guard = APKG_TEST.lock().await;
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let valid = support::basic().await;
    for (bytes, options) in [
        (b"invalid zip".to_vec(), ApkgOptions::default()),
        (valid.clone(), ApkgOptions { title: Some(" ".into()), language: None }),
    ] {
        assert!(f.services.import_apkg(&p, bytes, options).await.is_err());
    }
    let mut learner = p.clone();
    learner.role = Role::Learner;
    assert!(matches!(
        f.services.import_apkg(&learner, valid, ApkgOptions::default()).await,
        Err(CoreError::Forbidden(_))
    ));
    let image = image_package().await;
    let mut scoped = p.clone();
    scoped.scopes = Some(vec!["content:write".into()]);
    assert!(matches!(
        f.services.import_apkg(&scoped, image.clone(), ApkgOptions::default()).await,
        Err(CoreError::Forbidden(_))
    ));
    assert!(f.quota.calls.lock().unwrap().is_empty());
    f.quota.reject.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.services.import_apkg(&p, image, ApkgOptions::default()).await,
        Err(CoreError::QuotaExceeded(_))
    ));
    assert!(f.quota.calls.lock().unwrap().is_empty());
    assert_eq!(f.repo.get_usage("local", "card_writes", &memoswish_auth::quota::current_period()).await.unwrap(), 0);
    assert_eq!(f.store.puts.load(Ordering::SeqCst), 0);
    assert!(f.services.list_decks(&p).await.unwrap().is_empty());
    // 拒绝后两个准备都能持有许可，且不能跨租户提交准备包。
    let first = f.services.content.prepare_apkg(&p, support::basic().await, ApkgOptions::default()).await.unwrap();
    let second = f.services.content.prepare_apkg(&p, support::basic().await, ApkgOptions::default()).await.unwrap();
    let mut other = p.clone();
    other.tenant_id = "other".into();
    assert!(matches!(f.services.content.commit_apkg(&other, first).await, Err(CoreError::Forbidden(_))));
    drop(second);
}

#[tokio::test]
async fn apkg_outer_cancellation_retains_permits_through_accounting_upload_and_cleanup() {
    let _guard = APKG_TEST.lock().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for fail_put in [false, true] {
            let accounting = Arc::new(Gate::new());
            let upload = Arc::new(Gate::new());
            let f = fixture(Some(accounting.clone()), Some(upload.clone())).await;
            f.store.fail_put.store(fail_put, Ordering::SeqCst);
            f.store.inner.put("tenants/local/keep.png", vec![1], "image/png").await.unwrap();
            let p = Principal::local_owner("test");
            let bytes = image_package().await;
            let start = || {
                let services = f.services.clone();
                let p = p.clone();
                let bytes = bytes.clone();
                tokio::spawn(async move { services.import_apkg(&p, bytes, ApkgOptions::default()).await })
            };
            let first = start();
            let second = start();
            accounting.reached(2).await;
            first.abort();
            assert!(first.await.unwrap_err().is_cancelled());
            assert_eq!(
                f.services.import_apkg(&p, bytes.clone(), ApkgOptions::default()).await.unwrap_err().code(),
                "quota_exceeded"
            );
            assert_eq!(f.store.puts.load(Ordering::SeqCst), 0);
            accounting.release.add_permits(2);
            upload.reached(2).await;
            second.abort();
            assert!(second.await.unwrap_err().is_cancelled());
            assert_eq!(
                f.services.import_apkg(&p, bytes.clone(), ApkgOptions::default()).await.unwrap_err().code(),
                "quota_exceeded"
            );
            upload.release.add_permits(2);
            // 通过真实准备重新持有两个许可，等待后台责任结束，避免以延时推断完成。
            let mut recovered = Vec::new();
            while recovered.len() < 2 {
                match f.services.content.prepare_apkg(&p, bytes.clone(), ApkgOptions::default()).await {
                    Ok(prepared) => recovered.push(prepared),
                    Err(CoreError::QuotaExceeded(_)) => tokio::task::yield_now().await,
                    Err(error) => panic!("unexpected preparation failure: {error}"),
                }
            }
            drop(recovered);
            let decks = f.services.list_decks(&p).await.unwrap();
            assert_eq!(decks.len(), if fail_put { 0 } else { 2 });
            let assets = f.store.inner.list_prefix("tenants/local/").await.unwrap();
            assert_eq!(assets.len(), 3);
            assert!(f.store.exists("tenants/local/keep.png").await.unwrap());
            assert!(f.quota.calls.lock().unwrap().is_empty());
            assert_eq!(
                f.repo.get_usage("local", "card_writes", &memoswish_auth::quota::current_period()).await.unwrap(),
                if fail_put { 0 } else { 2 }
            );
            assert_eq!(
                f.repo.held_import_usage("local", &memoswish_auth::quota::current_period()).await.unwrap(),
                if fail_put { 2 } else { 0 }
            );
        }
    })
    .await
    .expect("detached application imports did not finish");
}

struct FailingTts {
    calls: AtomicUsize,
}
#[async_trait]
impl TtsEngine for FailingTts {
    fn id(&self) -> &str {
        "fail-second"
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn synthesize(&self, request: &TtsRequest) -> CoreResult<TtsOutput> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            return Err(CoreError::internal("injected second TTS failure"));
        }
        PlaceholderTts.synthesize(request).await
    }
}

#[tokio::test]
async fn composite_mutations_preserve_sequential_tts_partial_effects_and_accounting() {
    let mut f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let engine = Arc::new(FailingTts { calls: AtomicUsize::new(0) });
    f.services.media =
        MediaService::new(f.repo.clone(), f.store.clone(), f.quota.clone(), vec![engine.clone()], "fail-second")
            .unwrap();
    let deck = f
        .services
        .create_deck(
            &p,
            NewDeck { title: "Ordering".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let drafts = slice_material(&deck.id, "First :: One\nSecond :: Two\nThird :: Three", 10);
    let assignment: BgmAssignment = serde_json::from_value(serde_json::json!({"track_id":"missing"})).unwrap();
    assert!(f.services.upsert_cards(&p, drafts, true, &SynthesizeOptions::default(), Some(&assignment)).await.is_err());
    assert_eq!(engine.calls.load(Ordering::SeqCst), 2);
    let cards = f.services.list_cards(&p, Some(&deck.id), 10, 0).await.unwrap();
    assert_eq!(cards.len(), 3);
    for card in &cards {
        assert_eq!(card.tts.is_some(), card.front.title == "First");
        assert!(card.bgm.is_none());
    }
    assert_eq!(f.quota.calls.lock().unwrap()[0], (Metric::CardWrites, 3));
    let mut invalid = slice_material(&deck.id, "Invalid :: Card", 1);
    invalid[0].deck_id = "missing".into();
    assert!(f.services.upsert_cards(&p, invalid, false, &SynthesizeOptions::default(), None).await.is_err());
    assert_eq!(f.quota.calls.lock().unwrap().last().unwrap(), &(Metric::CardWrites, 1));
    let mut other = p.clone();
    other.tenant_id = "other".into();
    assert_eq!(f.services.get_card(&other, &cards[0].id).await.unwrap_err().code(), "not_found");
}

struct PausedTts(Arc<Gate>);

#[async_trait]
impl TtsEngine for PausedTts {
    fn id(&self) -> &str {
        "paused"
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn synthesize(&self, request: &TtsRequest) -> CoreResult<TtsOutput> {
        self.0.pause().await;
        PlaceholderTts.synthesize(request).await
    }
}

#[tokio::test]
async fn tts_preparation_cannot_publish_over_edits_bgm_or_deletion() {
    for mutation in ["edit", "bgm", "delete"] {
        let mut f = fixture(None, None).await;
        let p = Principal::local_owner("test");
        let gate = Arc::new(Gate::new());
        f.services.media = MediaService::new(
            f.repo.clone(),
            f.store.clone(),
            f.quota.clone(),
            vec![Arc::new(PausedTts(gate.clone()))],
            "paused",
        )
        .unwrap();
        let deck = f
            .services
            .create_deck(
                &p,
                NewDeck { title: "CAS".into(), description: String::new(), language: "en".into(), tags: vec![] },
            )
            .await
            .unwrap();
        let mut draft = slice_material(&deck.id, "Before :: Answer", 1).remove(0);
        let card = f.services.content.upsert_cards(&p, vec![draft.clone()]).await.unwrap().remove(0);
        let media = f.services.media.clone();
        let task_p = p.clone();
        let card_id = card.id.clone();
        let task =
            tokio::spawn(async move { media.synthesize_card(&task_p, &card_id, &SynthesizeOptions::default()).await });
        gate.reached(1).await;
        match mutation {
            "edit" => {
                draft.id = Some(card.id.clone());
                draft.expected_revision = Some(card.revision);
                draft.front.title = "After".into();
                f.services.content.upsert_cards(&p, vec![draft]).await.unwrap();
            }
            "bgm" => {
                f.services.content.attach_bgm_batch(&p, &[(card.id.clone(), Some(card.revision))], None).await.unwrap();
            }
            _ => f.services.delete_card_if_revision(&p, &card.id, Some(card.revision)).await.unwrap(),
        }
        gate.release.add_permits(1);
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.code(), if mutation == "delete" { "not_found" } else { "conflict" });
        let current = f.repo.get_card(&p.tenant_id, &card.id).await.unwrap();
        if mutation == "delete" {
            assert!(current.is_none());
        } else {
            let current = current.unwrap();
            assert!(current.tts.is_none());
            assert_eq!(current.revision, card.revision + 1);
        }
    }
}

#[tokio::test]
async fn bgm_batches_conflict_atomically_and_large_decks_fail_explicitly() {
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    f.services.media.ensure_builtin_bgm().await.unwrap();
    let deck = f
        .services
        .create_deck(
            &p,
            NewDeck { title: "Batch".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let cards = f.services.content.upsert_cards(&p, slice_material(&deck.id, "One :: 1\nTwo :: 2", 2)).await.unwrap();
    let assignment: BgmAssignment = serde_json::from_value(serde_json::json!({
        "track_id":"bgm_focus_pad", "expected_revisions": {cards[0].id.clone(): cards[0].revision, cards[1].id.clone(): cards[1].revision + 1}
    })).unwrap();
    assert!(matches!(
        f.services.assign_bgm(&p, Some(&deck.id), vec![], &assignment).await,
        Err(CoreError::Conflict(_))
    ));
    assert_eq!(f.services.list_cards(&p, Some(&deck.id), 500, 0).await.unwrap(), cards);
    let mut large_deck = deck;
    large_deck.id = memoswish_core::ids::new_id();
    let many: Vec<_> = (0..501)
        .map(|_| {
            let mut card = cards[0].clone();
            card.id = memoswish_core::ids::new_id();
            card.deck_id = large_deck.id.clone();
            card
        })
        .collect();
    f.repo.insert_deck_with_cards(&p.tenant_id, &large_deck, &many).await.unwrap();
    let mut assignment = assignment;
    assignment.expected_revisions.clear();
    assert!(matches!(
        f.services.assign_bgm(&p, Some(&large_deck.id), vec![], &assignment).await,
        Err(CoreError::Invalid(_))
    ));
    assert!(
        f.repo.list_cards(&p.tenant_id, Some(&large_deck.id), 501, 0).await.unwrap().iter().all(|c| c.bgm.is_none())
    );
}

#[tokio::test]
async fn bgm_mutations_preserve_content_read_and_write_permissions() {
    let f = fixture(None, None).await;
    let owner = Principal::local_owner("test");
    f.services.media.ensure_builtin_bgm().await.unwrap();
    let deck = f
        .services
        .create_deck(
            &owner,
            NewDeck { title: "Scopes".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let cards =
        f.services.content.upsert_cards(&owner, slice_material(&deck.id, "One :: 1\nTwo :: 2", 2)).await.unwrap();
    let ids: Vec<_> = cards.iter().map(|c| c.id.clone()).collect();
    let assignment: BgmAssignment = serde_json::from_value(serde_json::json!({"track_id":"bgm_focus_pad"})).unwrap();
    let mut token = Principal::local_owner("api_token");
    token.role = Role::Editor;
    token.scopes = Some(vec!["content:write".into()]);
    for deck_id in [None, Some(deck.id.as_str())] {
        let error = f.services.assign_bgm(&token, deck_id, ids.clone(), &assignment).await.unwrap_err();
        assert!(matches!(error, CoreError::Forbidden(_)));
        assert!(error.to_string().contains("content:read"));
        assert_eq!(f.services.list_cards(&owner, Some(&deck.id), 10, 0).await.unwrap(), cards);
    }
    token.scopes.as_mut().unwrap().push("content:read".into());
    let assigned = f.services.assign_bgm(&token, None, ids.clone(), &assignment).await.unwrap();
    for (before, after) in cards.iter().zip(&assigned) {
        assert_eq!(after.revision, before.revision + 1);
        assert_eq!(after.bgm.as_ref().unwrap().track.id, assignment.track_id);
        assert_eq!(after.front, before.front);
    }
    let targets: Vec<_> = assigned.iter().map(|c| (c.id.clone(), Some(c.revision))).collect();
    for scope in ["content:write", "content:read"] {
        token.scopes = Some(vec![scope.into()]);
        for binding in [assigned[0].bgm.clone(), None] {
            assert!(matches!(
                f.services.content.attach_bgm_batch(&token, &targets, binding).await,
                Err(CoreError::Forbidden(_))
            ));
            assert_eq!(f.services.list_cards(&owner, Some(&deck.id), 10, 0).await.unwrap(), assigned);
        }
    }
    token.scopes = Some(vec!["content:read".into(), "content:write".into()]);
    let removed = f.services.content.attach_bgm_batch(&token, &targets, None).await.unwrap();
    for (before, after) in assigned.iter().zip(removed) {
        assert_eq!(after.revision, before.revision + 1);
        assert!(after.bgm.is_none());
    }
}

#[tokio::test]
async fn tts_mutations_preserve_content_read_and_write_permissions() {
    let f = fixture(None, None).await;
    let owner = Principal::local_owner("test");
    let deck = f
        .services
        .create_deck(
            &owner,
            NewDeck { title: "Scopes".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let card =
        f.services.content.upsert_cards(&owner, slice_material(&deck.id, "One :: 1", 1)).await.unwrap().remove(0);
    let track = memoswish_protocol::examples::sample_card().tts.unwrap();
    let mut token = Principal::local_owner("api_token");
    token.role = Role::Editor;
    for scope in ["content:write", "content:read"] {
        token.scopes = Some(vec![scope.into()]);
        assert!(matches!(
            f.services.content.attach_tts(&token, &card.id, card.revision, track.clone()).await,
            Err(CoreError::Forbidden(_))
        ));
        assert_eq!(f.services.get_card(&owner, &card.id).await.unwrap(), card);
    }
    token.scopes = Some(vec!["content:write".into(), "tts:generate".into()]);
    let error = f
        .services
        .synthesize_cards(&token, std::slice::from_ref(&card.id), &SynthesizeOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(error, CoreError::Forbidden(_)));
    assert!(error.to_string().contains("content:read"));
    assert_eq!(f.store.puts.load(Ordering::SeqCst), 0);
    assert!(f.quota.calls.lock().unwrap().is_empty());
    assert_eq!(f.services.get_card(&owner, &card.id).await.unwrap(), card);
    token.scopes = Some(vec!["content:read".into(), "content:write".into()]);
    let attached = f.services.content.attach_tts(&token, &card.id, card.revision, track.clone()).await.unwrap();
    assert_eq!(attached.tts, Some(track));
    assert_eq!(attached.revision, card.revision + 1);
    token.scopes.as_mut().unwrap().push("tts:generate".into());
    // 持久恢复必须持有真实凭据摘要，成功路径不能再用只有 scope 的伪造主体。
    let issued =
        f.services.auth.create_api_token(&owner, "S17 scope test", token.scopes.clone().unwrap(), None).await.unwrap();
    token = f.services.auth.authenticate(Some(&issued.plaintext)).await.unwrap();
    token.role = Role::Editor;
    let synthesized = f.services.synthesize_cards(&token, &[card.id], &SynthesizeOptions::default()).await.unwrap();
    assert!(synthesized[0].tts.is_some());
    assert_eq!(synthesized[0].revision, attached.revision + 1);
}

#[tokio::test]
async fn composite_media_preserves_explicit_preconditions() {
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    f.services.media.ensure_builtin_bgm().await.unwrap();
    let deck = f
        .services
        .create_deck(
            &p,
            NewDeck { title: "Preconditions".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let mut draft = slice_material(&deck.id, "One :: 1", 1).remove(0);
    let card = f.services.content.upsert_cards(&p, vec![draft.clone()]).await.unwrap().remove(0);
    draft.id = Some(card.id.clone());
    draft.expected_revision = Some(card.revision);
    let options: SynthesizeOptions =
        serde_json::from_value(serde_json::json!({"expected_revisions":{card.id.clone():1}})).unwrap();
    assert!(matches!(
        f.services.upsert_cards(&p, vec![draft.clone()], true, &options, None).await,
        Err(CoreError::Conflict(_))
    ));
    let current = f.services.get_card(&p, &card.id).await.unwrap();
    assert_eq!(current.revision, 2);
    assert!(current.tts.is_none());
    draft.expected_revision = Some(2);
    let assignment: BgmAssignment = serde_json::from_value(
        serde_json::json!({"track_id":"bgm_focus_pad", "expected_revisions":{card.id.clone():2}}),
    )
    .unwrap();
    assert!(matches!(
        f.services.upsert_cards(&p, vec![draft], false, &SynthesizeOptions::default(), Some(&assignment)).await,
        Err(CoreError::Conflict(_))
    ));
    let current = f.services.get_card(&p, &card.id).await.unwrap();
    assert_eq!(current.revision, 3);
    assert!(current.bgm.is_none());
}

#[tokio::test]
async fn tts_disconnect_and_shutdown_retain_provider_put_publication_and_attachment() {
    for phase in ["provider", "put"] {
        let gate = Arc::new(Gate::new());
        let mut f = fixture(None, if phase == "put" { Some(gate.clone()) } else { None }).await;
        if phase == "provider" {
            f.services.media = MediaService::new(
                f.repo.clone(),
                f.store.clone(),
                f.quota.clone(),
                vec![Arc::new(PausedTts(gate.clone()))],
                "paused",
            )
            .unwrap();
        }
        let p = Principal::local_owner("test");
        let deck = f
            .services
            .create_deck(
                &p,
                NewDeck { title: "Drain".into(), description: String::new(), language: "en".into(), tags: vec![] },
            )
            .await
            .unwrap();
        let card = f
            .services
            .content
            .upsert_cards(&p, slice_material(&deck.id, "Before :: Answer", 1))
            .await
            .unwrap()
            .remove(0);
        let (services, principal, id) = (f.services.clone(), p.clone(), card.id.clone());
        let waiter =
            tokio::spawn(
                async move { services.synthesize_cards(&principal, &[id], &SynthesizeOptions::default()).await },
            );
        gate.reached(1).await;
        waiter.abort();
        let _ = waiter.await;
        f.services.operations.close();
        assert!(f.services.recover_speech().is_err());
        assert!(f.repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap().tts.is_none());
        let drain = f.services.operations.wait();
        tokio::pin!(drain);
        tokio::select! {biased;_= &mut drain=>panic!("blocked synthesis still owns application responsibility"),_=tokio::task::yield_now()=>{}}
        gate.release.add_permits(1);
        drain.await;
        let current = f.repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap();
        assert!(current.tts.is_some());
        assert_eq!(current.revision, card.revision + 1);
        let snapshot = f.services.usage(&p).await.unwrap();
        let tts = snapshot.metrics.iter().find(|v| v.metric == "tts_chars").unwrap();
        assert!(tts.used > 0);
        assert_eq!(tts.held, 0);
    }
}

struct LateTts {
    calls: AtomicUsize,
    gate: Arc<Gate>,
}
#[async_trait]
impl TtsEngine for LateTts {
    fn id(&self) -> &str {
        "late"
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn synthesize(&self, _: &TtsRequest) -> CoreResult<TtsOutput> {
        let first = self.calls.fetch_add(1, Ordering::SeqCst) == 0;
        if first {
            self.gate.pause().await;
        }
        Ok(TtsOutput {
            alignment_quality: None,
            audio_kind: None,
            provenance: None,
            audio: if first { b"old".to_vec() } else { b"new".to_vec() },
            mime: "audio/mpeg".into(),
            extension: "mp3".into(),
            duration_ms: 100,
            words: vec![],
        })
    }
}
#[tokio::test]
async fn late_provider_cannot_materialize_or_charge_after_another_service_publishes() {
    let f = fixture(None, None).await;
    let gate = Arc::new(Gate::new());
    let engine = Arc::new(LateTts { calls: AtomicUsize::new(0), gate: gate.clone() });
    let a = MediaService::new(f.repo.clone(), f.store.clone(), f.quota.clone(), vec![engine.clone()], "late").unwrap();
    let b = MediaService::new(f.repo.clone(), f.store.clone(), f.quota.clone(), vec![engine.clone()], "late").unwrap();
    let p = Principal::local_owner("test");
    let captured = p.clone();
    let old = tokio::spawn(async move { a.synthesize(&captured, "abc", "en", &SynthesizeOptions::default()).await });
    gate.reached(1).await;
    sqlx::query("UPDATE background_jobs SET lease_until_ms=0 WHERE tenant_id=$1 AND kind='tts_synthesis'")
        .bind(&p.tenant_id)
        .execute(f.repo.pool())
        .await
        .unwrap();
    let winner = b.synthesize(&p, "abc", "en", &SynthesizeOptions::default()).await.unwrap();
    assert_eq!(winner.audio.sha256, memoswish_core::ids::sha256_hex(b"new"));
    gate.release.add_permits(1);
    assert!(old.await.unwrap().is_err());
    assert_eq!(b.synthesize(&p, "abc", "en", &SynthesizeOptions::default()).await.unwrap(), winner);
    let snapshot = f.services.usage(&p).await.unwrap();
    let q = snapshot.metrics.iter().find(|q| q.metric == "tts_chars").unwrap();
    assert_eq!((q.used, q.held), (3, 0));
    assert_eq!(engine.calls.load(Ordering::SeqCst), 2);
    let evidence: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tts_provider_attempts WHERE tenant_id=$1 AND outcome='uncertain'")
            .bind(&p.tenant_id)
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
    assert_eq!(evidence, 1);
}

#[tokio::test]
async fn durable_submission_disconnect_shutdown_and_recovery_preserve_receipts() {
    let gate = Arc::new(Gate::new());
    let mut f = fixture(None, None).await;
    f.services.media = MediaService::new(
        f.repo.clone(),
        f.store.clone(),
        f.quota.clone(),
        vec![Arc::new(PausedTts(gate.clone()))],
        "paused",
    )
    .unwrap();
    let p = Principal::local_owner("test");
    let deck = f
        .services
        .create_deck(
            &p,
            NewDeck { title: "Submission".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let card =
        f.services.content.upsert_cards(&p, slice_material(&deck.id, "Before :: Answer", 1)).await.unwrap().remove(0);
    let control = crate::OperationControl::default();
    let result = control
        .scope(f.services.submit_tts(
            &p,
            "lost-response",
            std::slice::from_ref(&card.id),
            &SynthesizeOptions::default(),
        ))
        .await
        .unwrap();
    assert!(!result.complete);
    gate.reached(1).await;
    control.cancel();
    // 提交响应已经可以丢弃；停止准入并等待真正持有 provider 的工作排空。
    f.services.operations.close();
    assert!(
        f.services
            .submit_tts(&p, "closed", std::slice::from_ref(&card.id), &SynthesizeOptions::default())
            .await
            .is_err()
    );
    gate.release.add_permits(1);
    f.services.operations.wait().await;
    // 恢复使用新的应用排空域，不新增租约或时间常量。
    let mut restarted = f.services.clone();
    restarted.operations = Default::default();
    restarted.recover_speech().unwrap().await.unwrap().unwrap();
    let terminal = restarted.tts_submission_status(&p, "lost-response").await.unwrap();
    assert!(terminal.complete);
    assert_eq!(terminal.items[0].receipt.as_ref().unwrap().disposition, memoswish_protocol::TtsDisposition::Attached);
    let attached = f.repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap();
    assert_eq!(attached.revision, card.revision + 1);
    f.repo.delete_card(&p.tenant_id, &card.id).await.unwrap();
    // 当前默认引擎已改变、卡片已删除，原命令仍须返回原始映射和事实。
    restarted.media = MediaService::new(
        f.repo.clone(),
        f.store.clone(),
        f.quota.clone(),
        vec![Arc::new(PlaceholderTts)],
        "placeholder",
    )
    .unwrap();
    assert_eq!(
        restarted
            .submit_tts(&p, "lost-response", std::slice::from_ref(&card.id), &SynthesizeOptions::default())
            .await
            .unwrap(),
        terminal
    );
    assert!(matches!(
        restarted
            .submit_tts(
                &p,
                "lost-response",
                std::slice::from_ref(&card.id),
                &SynthesizeOptions { voice: Some("changed".into()), ..Default::default() }
            )
            .await,
        Err(CoreError::Conflict(_))
    ));
    restarted.operations.close();
    restarted.operations.wait().await;
}

struct SubmissionQuota {
    inner: Arc<dyn QuotaPolicy>,
    admission: Arc<Gate>,
}
#[async_trait]
impl QuotaPolicy for SubmissionQuota {
    fn name(&self) -> &'static str {
        "submission-test"
    }
    async fn consume(&self, p: &Principal, metric: Metric, amount: u64) -> CoreResult<()> {
        self.inner.consume(p, metric, amount).await
    }
    async fn snapshot(&self, p: &Principal) -> CoreResult<UsageSnapshot> {
        self.inner.snapshot(p).await
    }
    async fn tts_limit(&self, tenant: &str) -> CoreResult<Option<i64>> {
        self.admission.pause().await;
        self.inner.tts_limit(tenant).await
    }
}

#[tokio::test]
async fn submission_outer_cancellation_during_admission_retains_the_entire_batch() {
    let mut f = fixture(None, None).await;
    let gate = Arc::new(Gate::new());
    f.services.media = MediaService::new(
        f.repo.clone(),
        f.store.clone(),
        Arc::new(SubmissionQuota { inner: f.quota.clone(), admission: gate.clone() }),
        vec![Arc::new(PlaceholderTts)],
        "placeholder",
    )
    .unwrap();
    let p = Principal::local_owner("test");
    let deck = f
        .services
        .create_deck(
            &p,
            NewDeck { title: "Admission".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let cards =
        f.services.content.upsert_cards(&p, slice_material(&deck.id, "One :: Answer\nTwo :: Answer", 2)).await.unwrap();
    assert_eq!(cards.len(), 2);
    let ids: Vec<_> = cards.iter().map(|c| c.id.clone()).collect();
    let services = f.services.clone();
    let principal = p.clone();
    let target_ids = ids.clone();
    let waiter = tokio::spawn(async move {
        services.submit_tts(&principal, "disconnected-admission", &target_ids, &SynthesizeOptions::default()).await
    });
    gate.reached(1).await;
    waiter.abort();
    let _ = waiter.await;
    f.services.operations.close();
    gate.release.add_permits(1);
    f.services.operations.wait().await;
    let accepted = f.services.tts_submission_status(&p, "disconnected-admission").await.unwrap();
    assert_eq!(accepted.items.len(), 2);
    assert!(!accepted.complete);
    let mut resumed = f.services.clone();
    resumed.operations = Default::default();
    resumed.recover_speech().unwrap().await.unwrap().unwrap();
    let terminal = resumed.tts_submission_status(&p, "disconnected-admission").await.unwrap();
    assert!(terminal.complete);
    for (item, card) in terminal.items.iter().zip(&cards) {
        assert_eq!(item.card_id, card.id);
        assert_eq!(item.receipt.as_ref().unwrap().resulting_revision, Some(card.revision + 1));
    }
    resumed.operations.close();
    resumed.operations.wait().await;
}

#[tokio::test]
async fn durable_deckpack_replays_and_rejects_late_invalid_cards_without_effects() {
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let pack = memoswish_protocol::examples::sample_deck_pack();
    for invalid in [0, 200, 499] {
        let mut bad = pack.clone();
        bad.cards = vec![bad.cards[0].clone(); 500];
        bad.cards[invalid].front.title.clear();
        assert!(
            f.services
                .import_deck_pack_with_identity(&p, bad, false, Some(format!("bad-{invalid}")), None)
                .await
                .is_err()
        );
        assert!(f.services.list_decks(&p).await.unwrap().is_empty());
        assert_eq!(f.store.puts.load(Ordering::SeqCst), 0);
        assert!(f.services.usage(&p).await.unwrap().metrics.iter().all(|m| m.used == 0 && m.held == 0));
    }
    let mut version = pack.clone();
    version.version = "2.0".into();
    assert!(f.services.import_deck_pack(&p, version).await.is_err());
    let mut oversized = pack.clone();
    oversized.deck.description = "x".repeat(8 * 1024 * 1024);
    assert!(f.services.import_deck_pack(&p, oversized).await.is_err());
    let (a, b) = tokio::join!(
        f.services.import_deck_pack_with_identity(&p, pack.clone(), false, Some("replay".into()), None),
        f.services.import_deck_pack_with_identity(&p, pack.clone(), false, Some("replay".into()), None)
    );
    let a = a.unwrap();
    assert_eq!(a, b.unwrap());
    assert_eq!(f.services.list_decks(&p).await.unwrap().len(), 1);
    assert_eq!(f.services.usage(&p).await.unwrap().metrics.iter().find(|m| m.metric == "card_writes").unwrap().used, 1);
    assert_eq!(
        f.services.import_deck_pack_with_identity(&p, pack.clone(), false, Some("replay".into()), None).await.unwrap(),
        a
    );
    assert!(matches!(
        f.services.import_deck_pack_with_identity(&p, pack.clone(), true, Some("replay".into()), None).await,
        Err(CoreError::Conflict(_))
    ));
    let mut changed = pack;
    changed.deck.title.push('!');
    assert!(matches!(
        f.services.import_deck_pack_with_identity(&p, changed, false, Some("replay".into()), None).await,
        Err(CoreError::Conflict(_))
    ));
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn deckpack_legacy_image_export_import_delivery_and_replay() {
    use memoswish_core::assets::{AssetRepo, card_assets};
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let asset = f.store.inner.put("tenants/local/imports/legacy.png", b"abc".to_vec(), "image/png").await.unwrap();
    let mut pack = memoswish_protocol::examples::sample_deck_pack();
    let original = &mut pack.cards[0];
    original.tts = None;
    original.bgm = None;
    original.visual.image = Some(asset.clone());
    original.front.blocks.push(memoswish_protocol::ContentBlock::Image { asset: asset.clone(), alt: String::new() });
    f.repo.insert_deck_with_cards(&p.tenant_id, &pack.deck, &pack.cards).await.unwrap();
    let exported = f.services.export_deck(&p, &pack.deck.id).await.unwrap();
    let imported = f
        .services
        .import_deck_pack_with_identity(&p, exported.clone(), false, Some("legacy-image".into()), None)
        .await
        .unwrap();
    assert_ne!(imported.id, pack.deck.id);
    let cards = f.repo.list_cards(&p.tenant_id, Some(&imported.id), 10, 0).await.unwrap();
    assert_eq!(cards.len(), 1);
    assert_ne!(cards[0].id, pack.cards[0].id);
    for reference in card_assets(&cards[0]) {
        assert_eq!(reference.key, asset.key);
        assert!(reference.url.is_empty());
    }
    // 删除旧卡片后，新卡片仍可通过 S20 桥接读取，重放不需要再次授权已提交输入。
    assert!(f.repo.delete_card(&p.tenant_id, &pack.cards[0].id).await.unwrap());
    let object = asset_delivery::read(f.repo.as_ref(), f.store.as_ref(), &p, &asset.key, "content", Some(&cards[0].id))
        .await
        .unwrap();
    assert_eq!(object.bytes, b"abc");
    assert_eq!(object.mime, "image/png");
    assert_eq!(
        f.services
            .import_deck_pack_with_identity(&p, exported, false, Some("legacy-image".into()), None)
            .await
            .unwrap(),
        imported
    );
    assert!(f.repo.asset_delivery(&p, &asset.key, memoswish_core::Permission::ContentRead).await.unwrap().is_none());
    for table in ["asset_records", "asset_upload_intents", "asset_upload_attempts", "asset_references"] {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}")).fetch_one(f.repo.pool()).await.unwrap();
        assert_eq!(count, 0);
    }
    assert_eq!(f.store.puts.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.repo.get_usage(&p.tenant_id, "card_writes", &memoswish_auth::quota::current_period()).await.unwrap(),
        1
    );
    f.services.operations.close();
    f.services.operations.wait().await;
}

struct ImportFailingTts {
    calls: AtomicUsize,
}

#[tokio::test]
async fn import_response_and_recovery_progress_while_synthesis_is_paused() {
    use memoswish_core::imports::ImportAuthority;
    let mut f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let gate = Arc::new(Gate::new());
    f.services.media = MediaService::new(
        f.repo.clone(),
        f.store.clone(),
        f.quota.clone(),
        vec![Arc::new(PausedTts(gate.clone()))],
        "paused",
    )
    .unwrap();
    let pack = memoswish_protocol::examples::sample_deck_pack();
    let fingerprint = memoswish_content::imports::fingerprint("deckpack", &pack, true).unwrap();
    let authority = ImportAuthority::capture(&p, None);
    let services = f.services.clone();
    let caller = p.clone();
    let input = pack.clone();
    let response = tokio::spawn(async move {
        services.import_deck_pack_with_identity(&caller, input, true, Some("paused-import".into()), None).await
    });
    gate.reached(1).await;
    // provider 屏障保持关闭；响应必须只等待持久交接。
    let deck = tokio::time::timeout(std::time::Duration::from_secs(5), response).await.unwrap().unwrap().unwrap();
    let first = f.repo.lookup_import(&authority, "paused-import", &fingerprint).await.unwrap().unwrap();
    let first_card = f.repo.list_cards(&p.tenant_id, Some(&deck.id), 10, 0).await.unwrap().remove(0);
    let first_id = format!("import:{}:{}", first.id, first_card.id);
    let initial = f.services.tts_submission_status(&p, &first_id).await.unwrap();
    assert!(!initial.complete);
    let mut submissions = vec![first_id.clone()];
    let mut imports = Vec::new();
    // 两个后续导入只持久接收，由同一扫描页恢复，不能等待第一个合成。
    for key in ["recover-after-paused-1", "recover-after-paused-2"] {
        let mut pending_pack = pack.clone();
        pending_pack.cards[0].front.title = key.into();
        let fingerprint = memoswish_content::imports::fingerprint("deckpack", &pending_pack, true).unwrap();
        let work = f.services.content.prepare_deck_pack(&p, pending_pack, true).unwrap();
        let op = f.repo.accept_import(&authority, key, &fingerprint, &work, None, 2).await.unwrap();
        submissions.push(format!("import:{}:{}", op.id, work.cards[0].id));
        imports.push(op.id);
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), f.services.recover_imports().unwrap())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    gate.reached(2).await;
    for id in &imports {
        assert_eq!(f.repo.import_operation(&p.tenant_id, id).await.unwrap().outcome, "committed");
    }
    for id in &submissions {
        let status = f.services.tts_submission_status(&p, id).await.unwrap();
        assert!(!status.complete);
        assert_eq!(status.items.len(), 1);
    }
    assert_eq!(
        f.services.import_deck_pack_with_identity(&p, pack, true, Some("paused-import".into()), None).await.unwrap(),
        deck
    );
    assert_eq!(f.services.tts_submission_status(&p, &first_id).await.unwrap(), initial);
    f.services.operations.close();
    let drain = f.services.operations.wait();
    tokio::pin!(drain);
    tokio::select! {
        biased;
        _ = &mut drain => panic!("paused synthesis must retain tracked execution ownership"),
        _ = tokio::task::yield_now() => {},
    }
    gate.release.add_permits(3);
    drain.await;
    for id in &submissions {
        let status = f.services.tts_submission_status(&p, id).await.unwrap();
        assert!(status.complete);
        assert_eq!(status.items[0].receipt.as_ref().unwrap().disposition, memoswish_protocol::TtsDisposition::Attached);
    }
    assert_eq!(
        f.services.tts_submission_status(&p, &first_id).await.unwrap().items[0].item_id,
        initial.items[0].item_id
    );
    assert_eq!(f.services.usage(&p).await.unwrap().metrics.iter().find(|m| m.metric == "card_writes").unwrap().used, 3);
}

#[tokio::test]
async fn recovery_admission_failure_records_page_error_and_preserves_cursor_for_retry() {
    use memoswish_core::{imports::ImportAuthority, maintenance::*};
    for failure_index in [0, 1] {
        let f = fixture(None, None).await;
        let p = Principal::local_owner("test");
        let pack = memoswish_protocol::examples::sample_deck_pack();
        let fingerprint = memoswish_content::imports::fingerprint("deckpack", &pack, false).unwrap();
        let mut ids = Vec::new();
        for key in ["admission-1", "admission-2"] {
            let work = f.services.content.prepare_deck_pack(&p, pack.clone(), false).unwrap();
            let op = f
                .repo
                .accept_import(&ImportAuthority::capture(&p, None), key, &fingerprint, &work, None, 2)
                .await
                .unwrap();
            ids.push(op.id);
        }
        ids.sort();
        // 在游标更新时失败，已插入的单项接纳也必须回滚；哨兵不得进入持久错误。
        sqlx::raw_sql(&format!(
            "CREATE TRIGGER fail_recovery_admission BEFORE UPDATE OF cursor ON maintenance_tasks \
             WHEN NEW.task_kind='import_recovery' AND NEW.cursor LIKE '%{}%' \
             BEGIN SELECT RAISE(ABORT,'private-admission-sentinel'); END",
            ids[failure_index]
        ))
        .execute(f.repo.pool())
        .await
        .unwrap();
        let error = f.services.recover_imports().unwrap().await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "maintenance page failed");
        let task = TaskRegistration::system(TaskKind::ImportRecovery).id().unwrap();
        let schedule: (String, Option<String>) =
            sqlx::query_as("SELECT state,error FROM background_jobs WHERE tenant_id='' AND id=$1")
                .bind(&task)
                .fetch_one(f.repo.pool())
                .await
                .unwrap();
        assert_eq!(schedule, ("queued".into(), Some("maintenance page failed".into())));
        let cursor: String = sqlx::query_scalar("SELECT cursor FROM maintenance_tasks WHERE id=$1")
            .bind(&task)
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
        let expected = if failure_index == 0 { vec![] } else { vec![p.tenant_id.clone(), ids[0].clone()] };
        assert_eq!(serde_json::from_str::<Vec<String>>(&cursor).unwrap(), expected);
        let admissions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM maintenance_admissions WHERE task_id=$1")
            .bind(&task)
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
        assert_eq!(admissions, failure_index as i64);
        assert_eq!(f.repo.import_operation(&p.tenant_id, &ids[failure_index]).await.unwrap().outcome, "pending");
        sqlx::raw_sql("DROP TRIGGER fail_recovery_admission").execute(f.repo.pool()).await.unwrap();
        sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE tenant_id='' AND id=$1")
            .bind(&task)
            .execute(f.repo.pool())
            .await
            .unwrap();
        f.services.recover_imports().unwrap().await.unwrap().unwrap();
        let error: Option<String> =
            sqlx::query_scalar("SELECT error FROM background_jobs WHERE tenant_id='' AND id=$1")
                .bind(&task)
                .fetch_one(f.repo.pool())
                .await
                .unwrap();
        assert_eq!(error, None);
        for id in ids {
            assert_eq!(f.repo.import_operation(&p.tenant_id, &id).await.unwrap().outcome, "committed");
        }
        f.services.operations.close();
        f.services.operations.wait().await;
    }
}
#[async_trait]
impl TtsEngine for ImportFailingTts {
    fn id(&self) -> &str {
        "import-failure"
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn synthesize(&self, request: &TtsRequest) -> CoreResult<TtsOutput> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request.text.contains("Second import card") {
            return Err(CoreError::internal("injected import TTS failure"));
        }
        PlaceholderTts.synthesize(request).await
    }
}

#[tokio::test]
async fn recovery_execution_failure_records_page_error_and_retries_next_cycle() {
    use memoswish_core::{imports::ImportAuthority, maintenance::*};
    let mut f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let pack = memoswish_protocol::examples::sample_deck_pack();
    let fingerprint = memoswish_content::imports::fingerprint("deckpack", &pack, false).unwrap();
    let work = f.services.content.prepare_deck_pack(&p, pack, false).unwrap();
    let op = f
        .repo
        .accept_import(&ImportAuthority::capture(&p, None), "execution-failure", &fingerprint, &work, None, 2)
        .await
        .unwrap();
    // 准入成功后执行器拒绝，失败不能抹掉已经提交的游标或持久责任。
    f.services.content = f.services.content.clone().with_import_execution(false);
    let error = f.services.recover_imports().unwrap().await.unwrap().unwrap_err();
    assert_eq!(error.to_string(), "maintenance page failed");
    let task = TaskRegistration::system(TaskKind::ImportRecovery).id().unwrap();
    let (cursor, error): (String, Option<String>) = sqlx::query_as(
        "SELECT m.cursor,j.error FROM maintenance_tasks m JOIN background_jobs j ON j.id=m.id AND j.tenant_id='' WHERE m.id=$1"
    ).bind(&task).fetch_one(f.repo.pool()).await.unwrap();
    assert_eq!(serde_json::from_str::<Vec<String>>(&cursor).unwrap(), vec![p.tenant_id.clone(), op.id.clone()]);
    assert_eq!(error.as_deref(), Some("maintenance page failed"));
    assert_eq!(f.repo.import_operation(&p.tenant_id, &op.id).await.unwrap().outcome, "pending");
    f.services.content = f.services.content.clone().with_import_execution(true);
    // 空页完成当前周期后，下一周期仍能使用原导入身份执行。
    for _ in 0..2 {
        sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE tenant_id='' AND id=$1")
            .bind(&task)
            .execute(f.repo.pool())
            .await
            .unwrap();
        f.services.recover_imports().unwrap().await.unwrap().unwrap();
    }
    assert_eq!(f.repo.import_operation(&p.tenant_id, &op.id).await.unwrap().outcome, "committed");
    let admissions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM maintenance_admissions WHERE task_id=$1 AND item_id=$2")
            .bind(&task)
            .bind(&op.id)
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
    assert_eq!(admissions, 2);
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn import_speech_failure_keeps_original_receipt_and_foreign_assets_never_authorize() {
    let mut f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let engine = Arc::new(ImportFailingTts { calls: AtomicUsize::new(0) });
    f.services.media =
        MediaService::new(f.repo.clone(), f.store.clone(), f.quota.clone(), vec![engine.clone()], "import-failure")
            .unwrap();
    let mut pack = memoswish_protocol::examples::sample_deck_pack();
    pack.cards.push(pack.cards[0].clone());
    pack.cards[1].front.title = "Second import card".into();
    let deck = f
        .services
        .import_deck_pack_with_identity(&p, pack.clone(), true, Some("tts-result".into()), None)
        .await
        .unwrap();
    assert_eq!(deck.card_count, 2);
    f.services.operations.close();
    f.services.operations.wait().await;
    f.services.operations = Default::default();
    for _ in 0..6 {
        // 同时推进失败语音的业务期限，再继续原有终态和计量断言。
        sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE state='queued' AND (work_scope='maintenance' OR (tenant_id=$1 AND kind='tts_synthesis'))")
            .bind(&p.tenant_id)
            .execute(f.repo.pool())
            .await
            .unwrap();
        if let Err(error) = f.services.recover_speech().unwrap().await.unwrap() {
            // 已知 provider 失败必须上报脱敏页错误，原回执与计量断言仍保留。
            assert_eq!(error.to_string(), "maintenance page failed");
        }
        f.services.recover_imports().unwrap().await.unwrap().unwrap();
    }
    let attempts = engine.calls.load(Ordering::SeqCst);
    assert!(attempts >= 2);
    assert_eq!(
        f.services
            .import_deck_pack_with_identity(&p, pack.clone(), true, Some("tts-result".into()), None)
            .await
            .unwrap(),
        deck
    );
    assert_eq!(engine.calls.load(Ordering::SeqCst), attempts);
    let outcomes: Vec<String> = sqlx::query_scalar("SELECT outcome FROM import_followups ORDER BY outcome")
        .fetch_all(f.repo.pool())
        .await
        .unwrap();
    assert_eq!(outcomes, vec!["failed", "succeeded"]);
    let mut asset = memoswish_protocol::examples::sample_tts_asset();
    asset.key = "tenants/local-extra/uploads/fabricated".into();
    pack.cards[0].front.blocks.push(memoswish_protocol::ContentBlock::Image { asset, alt: String::new() });
    assert!(matches!(
        f.services.import_deck_pack_with_identity(&p, pack, false, Some("foreign".into()), None).await,
        Err(CoreError::Forbidden(_))
    ));
    assert_eq!(f.services.list_decks(&p).await.unwrap().len(), 1);
    assert_eq!(f.services.usage(&p).await.unwrap().metrics.iter().find(|m| m.metric == "card_writes").unwrap().used, 2);
    assert_eq!(f.repo.held_import_usage("local", &memoswish_auth::quota::current_period()).await.unwrap(), 0);
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn exhausted_import_releases_staging_and_replay_is_terminal_without_effects() {
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let pack = memoswish_protocol::examples::sample_deck_pack();
    let work = f.services.content.prepare_deck_pack(&p, pack.clone(), false).unwrap();
    let fingerprint = memoswish_content::imports::fingerprint("deckpack", &pack, false).unwrap();
    let a = memoswish_core::imports::ImportAuthority::capture(&p, None);
    let op = f.repo.accept_import(&a, "exhausted", &fingerprint, &work, None, 2).await.unwrap();
    sqlx::query("UPDATE background_jobs SET attempts=max_attempts WHERE tenant_id=$1 AND id=$2")
        .bind(&p.tenant_id)
        .bind(&op.id)
        .execute(f.repo.pool())
        .await
        .unwrap();
    assert!(f.repo.claim_import(&p.tenant_id, &op.id, 30_000).await.unwrap().is_none());
    assert_eq!(f.repo.import_operation(&p.tenant_id, &op.id).await.unwrap().outcome, "failed");
    assert!(matches!(
        f.services.import_deck_pack_with_identity(&p, pack, false, Some("exhausted".into()), None).await,
        Err(CoreError::Conflict(_))
    ));
    assert!(f.services.list_decks(&p).await.unwrap().is_empty());
    assert_eq!(f.store.puts.load(Ordering::SeqCst), 0);
    assert!(f.services.usage(&p).await.unwrap().metrics.iter().all(|m| m.used == 0 && m.held == 0));
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn import_auto_tts_recovers_after_content_commit_without_duplicate_attachment() {
    use memoswish_core::imports::ImportAuthority;
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let pack = memoswish_protocol::examples::sample_deck_pack();
    let work = f.services.content.prepare_deck_pack(&p, pack.clone(), true).unwrap();
    let fingerprint = memoswish_content::imports::fingerprint("deckpack", &pack, true).unwrap();
    let op = f
        .repo
        .accept_import(&ImportAuthority::capture(&p, None), "crash-before-tts", &fingerprint, &work, None, 2)
        .await
        .unwrap();
    // 模拟内容提交后、任何语音交接之前进程退出。
    f.services.content.drive_import(&p.tenant_id, &op.id).await.unwrap();
    assert_eq!(f.repo.import_followups(&p.tenant_id, &op.id).await.unwrap().len(), 1);
    assert!(f.repo.get_card(&p.tenant_id, &work.cards[0].id).await.unwrap().unwrap().tts.is_none());
    f.services.operations.close();
    f.services.operations.wait().await;
    let mut restarted = f.services.clone();
    restarted.operations = Default::default();
    restarted.recover_imports().unwrap().await.unwrap().unwrap();
    // 导入恢复只等待持久交接；断言合成完成前必须排空已登记的执行者。
    restarted.operations.close();
    restarted.operations.wait().await;
    restarted.operations = Default::default();
    restarted.recover_speech().unwrap().await.unwrap().unwrap();
    // 空页结束当前周期，下一周期以原身份读取后台已完成的挂载回执。
    for _ in 0..2 {
        sqlx::query("UPDATE background_jobs SET available_at_ms=0 WHERE work_scope='maintenance' AND state='queued'")
            .execute(f.repo.pool())
            .await
            .unwrap();
        restarted.recover_imports().unwrap().await.unwrap().unwrap();
    }
    let submission_id = format!("import:{}:{}", op.id, work.cards[0].id);
    let receipt = restarted.tts_submission_status(&p, &submission_id).await.unwrap();
    assert!(receipt.complete);
    assert_eq!(receipt.items[0].receipt.as_ref().unwrap().disposition, memoswish_protocol::TtsDisposition::Attached);
    assert!(f.repo.import_followups(&p.tenant_id, &op.id).await.unwrap().is_empty());
    let card = f.repo.get_card(&p.tenant_id, &work.cards[0].id).await.unwrap().unwrap();
    assert_eq!(card.revision, 2);
    assert!(card.tts.is_some());
    restarted.recover_imports().unwrap().await.unwrap().unwrap();
    restarted.recover_speech().unwrap().await.unwrap().unwrap();
    assert_eq!(restarted.tts_submission_status(&p, &submission_id).await.unwrap(), receipt);
    assert_eq!(f.repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap().revision, 2);
    assert_eq!(
        restarted.import_deck_pack_with_identity(&p, pack, true, Some("crash-before-tts".into()), None).await.unwrap(),
        work.deck
    );
    restarted.operations.close();
    restarted.operations.wait().await;
}

struct ImportExternalTts(AtomicUsize);
#[async_trait]
impl TtsEngine for ImportExternalTts {
    fn id(&self) -> &str {
        "import-external"
    }
    fn external_transfer(&self) -> bool {
        true
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn synthesize(&self, request: &TtsRequest) -> CoreResult<TtsOutput> {
        self.0.fetch_add(1, Ordering::SeqCst);
        PlaceholderTts.synthesize(request).await
    }
}

#[tokio::test]
async fn import_privacy_admission_and_withdrawn_followup_recovery() {
    use memoswish_core::imports::ImportAuthority;
    use memoswish_core::privacy::PrivacyRepo;
    let mut f = fixture(None, None).await;
    let p = Principal::local_owner("single_user");
    let mut policy = memoswish_protocol::examples::sample_privacy_policy();
    policy.purpose_versions.insert("external_tts".into(), "speech-v1".into());
    f.repo.privacy_install_policy(&policy).await.unwrap();
    f.services.auth = AuthService::new(
        f.repo.clone(),
        AuthConfig {
            mode: DeploymentMode::MultiTenant,
            jwt_secret: "a".repeat(32),
            jwt_ttl_secs: 3600,
            registration_open: false,
            default_plan: "free".into(),
        },
    )
    .unwrap()
    .with_privacy_policy(policy.clone())
    .unwrap();
    let engine = Arc::new(ImportExternalTts(AtomicUsize::new(0)));
    f.services.media =
        MediaService::new(f.repo.clone(), f.store.clone(), f.quota.clone(), vec![engine.clone()], "import-external")
            .unwrap()
            .with_privacy_policy(policy.clone());
    let pack = memoswish_protocol::examples::sample_deck_pack();
    assert!(matches!(f.services.import_deck_pack(&p, pack.clone()).await, Err(CoreError::Forbidden(_))));
    assert!(matches!(f.services.import_apkg(&p, vec![], ApkgOptions::default()).await, Err(CoreError::Forbidden(_))));
    let mut state = f.repo.privacy_state(&p.tenant_id, &p).await.unwrap();
    for (kind, version, value) in
        [("notice", "notice-v1", ""), ("terms", "terms-v1", ""), ("age", "notice-v1", "example-region")]
    {
        state = f
            .repo
            .privacy_update(
                &p.tenant_id,
                &p,
                &policy,
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
    assert!(matches!(
        f.services.import_deck_pack_with_media(&p, pack.clone(), true).await,
        Err(CoreError::Forbidden(_))
    ));
    assert!(f.repo.list_decks(&p.tenant_id).await.unwrap().is_empty());
    assert!(f.services.usage(&p).await.unwrap().metrics.iter().all(|m| m.used == 0 && m.held == 0));
    // 无外传的导入不要求语音用途授权。
    f.services.import_deck_pack(&p, pack.clone()).await.unwrap();
    state = f
        .repo
        .privacy_update(
            &p.tenant_id,
            &p,
            &policy,
            &memoswish_protocol::PrivacyUpdate {
                expected_revision: state.revision,
                kind: "external_tts".into(),
                version: "speech-v1".into(),
                decision: true,
                value: String::new(),
            },
        )
        .await
        .unwrap();
    let work = f.services.content.prepare_deck_pack(&p, pack.clone(), true).unwrap();
    let fingerprint = memoswish_content::imports::fingerprint("deckpack", &pack, true).unwrap();
    let mut authority = ImportAuthority::capture(&p, None);
    authority.privacy = f.services.media.default_tts_privacy(&p).await.unwrap();
    let op = f.repo.accept_import(&authority, "withdraw-before-followup", &fingerprint, &work, None, 2).await.unwrap();
    f.services.content.drive_import(&p.tenant_id, &op.id).await.unwrap();
    state = f
        .repo
        .privacy_update(
            &p.tenant_id,
            &p,
            &policy,
            &memoswish_protocol::PrivacyUpdate {
                expected_revision: state.revision,
                kind: "external_tts".into(),
                version: "speech-v1".into(),
                decision: false,
                value: String::new(),
            },
        )
        .await
        .unwrap();
    f.repo
        .privacy_update(
            &p.tenant_id,
            &p,
            &policy,
            &memoswish_protocol::PrivacyUpdate {
                expected_revision: state.revision,
                kind: "external_tts".into(),
                version: "speech-v1".into(),
                decision: true,
                value: String::new(),
            },
        )
        .await
        .unwrap();
    f.services.recover_imports().unwrap().await.unwrap().unwrap();
    assert_eq!(engine.0.load(Ordering::SeqCst), 0);
    assert!(f.repo.import_followups(&p.tenant_id, &op.id).await.unwrap().is_empty());
    assert!(f.repo.get_card(&p.tenant_id, &work.cards[0].id).await.unwrap().unwrap().tts.is_none());
    let outcome: String =
        sqlx::query_scalar("SELECT outcome FROM import_followups WHERE tenant_id=$1 AND import_id=$2")
            .bind(&p.tenant_id)
            .bind(&op.id)
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
    assert_eq!(outcome, "failed");
    // 重新授权仅允许新导入，不能复活旧交接。
    f.services.import_deck_pack_with_media(&p, pack, true).await.unwrap();
    f.services.recover_speech().unwrap().await.unwrap().unwrap();
    f.services.recover_imports().unwrap().await.unwrap().unwrap();
    f.services.operations.close();
    f.services.operations.wait().await;
    assert!(engine.0.load(Ordering::SeqCst) > 0);
}

fn explanation_policy() -> memoswish_core::explanations::ExplanationPolicy {
    memoswish_core::explanations::ExplanationPolicy {
        deployment_id: "test-deployment".into(),
        provider_account: "test-account".into(),
        pricing_version: "v1".into(),
        currency: "USD".into(),
        valid_until_ms: i64::MAX,
        input_rate: 1,
        output_rate: 1,
        rate_denominator: 1000,
        tenant_limit: 10_000,
        deployment_limit: 10_000,
        provider_limit: 10_000,
        unresolved_limit: 10_000,
        cache_entry_bytes: 16_384,
        cache_tenant_bytes: 32_768,
        cache_deployment_bytes: 65_536,
        cache_ttl_ms: 60_000,
    }
}
async fn explanation_card(f: &mut Fixture) -> memoswish_protocol::Card {
    let policy =
        memoswish_protocol::PrivacyPolicy { hosted: false, ..memoswish_protocol::examples::sample_privacy_policy() };
    f.repo.privacy_install_policy(&policy).await.unwrap();
    f.services.auth = f.services.auth.clone().with_privacy_policy(policy.clone()).unwrap();
    let p = Principal::local_owner("single_user");
    for (kind, version, value) in [
        ("notice", "notice-v1", ""),
        ("terms", "terms-v1", ""),
        ("age", "notice-v1", "example-region"),
        ("external_ai", "provider-policy-v1", ""),
    ] {
        let state = f.repo.privacy_state(&p.tenant_id, &p).await.unwrap();
        f.repo
            .privacy_update(
                &p.tenant_id,
                &p,
                &policy,
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
    let mut deck = memoswish_protocol::examples::sample_deck();
    deck.id = memoswish_core::ids::new_id();
    let mut card = memoswish_protocol::examples::sample_card();
    card.id = memoswish_core::ids::new_id();
    card.deck_id = deck.id.clone();
    f.repo.insert_deck_with_cards("local", &deck, std::slice::from_ref(&card)).await.unwrap();
    card
}

#[tokio::test]
async fn explanation_legacy_missing_budget_and_hosted_purpose_never_send() {
    use memoswish_protocol::{ExplainDisposition, ExplainRequest};
    let mut f = fixture(None, None).await;
    let card = explanation_card(&mut f).await;
    let p = Principal::local_owner("single_user");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cfg = memoswish_content::AiExplainConfig {
        base_url: Some(format!("http://{}", listener.local_addr().unwrap())),
        api_key: Some("SYNTHETIC_EXPLAIN_SECRET".into()),
        budget: Some(explanation_policy()),
        ..Default::default()
    };
    f.services.content = ContentService::new(f.repo.clone()).with_ai_config(cfg.clone());
    assert_eq!(
        f.services.explain_card(&p, &card.id, &ExplainRequest::default()).await.unwrap().provider,
        "builtin-heuristic"
    );
    let mut cfg = cfg;
    cfg.budget = None;
    f.services.content = ContentService::new(f.repo.clone()).with_ai_config(cfg.clone());
    let request = ExplainRequest { request_id: Some("budget-absent".into()), ..Default::default() };
    let text = f.services.explain_card(&p, &card.id, &request).await.unwrap();
    assert_eq!(text.operation.unwrap().disposition, ExplainDisposition::Local);
    cfg.budget = Some(explanation_policy());
    f.services.content = ContentService::new(f.repo.clone()).with_ai_config(cfg);
    // 新配置不把原先本地身份升级成付费重试。
    assert_eq!(f.services.explain_card(&p, &card.id, &request).await.unwrap().provider, "builtin-heuristic");
    let state = f.services.auth.privacy_state(&p).await.unwrap();
    f.services
        .auth
        .update_privacy(
            &p,
            &memoswish_protocol::PrivacyUpdate {
                expected_revision: state.revision,
                kind: "external_ai".into(),
                version: "provider-policy-v1".into(),
                decision: false,
                value: String::new(),
            },
        )
        .await
        .unwrap();
    let hosted = ExplainRequest { request_id: Some("hosted".into()), ..Default::default() };
    assert!(matches!(f.services.explain_card(&p, &card.id, &hosted).await, Err(CoreError::Forbidden(_))));
    f.services.auth = AuthService::new(
        f.repo.clone(),
        AuthConfig {
            mode: DeploymentMode::MultiTenant,
            jwt_secret: "a".repeat(32),
            jwt_ttl_secs: 3600,
            registration_open: false,
            default_plan: "self_hosted".into(),
        },
    )
    .unwrap()
    .with_privacy_policy(f.services.auth.privacy_policy().clone())
    .unwrap();
    assert!(matches!(f.services.explain_card(&p, &card.id, &hosted).await, Err(CoreError::Forbidden(_))));
    let paid: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations WHERE policy IS NOT NULL OR attempted<>0")
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
    assert_eq!(paid, 0);
    let holds: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM explanation_holds").fetch_one(f.repo.pool()).await.unwrap();
    assert_eq!(holds, 0);
    tokio::select! {biased;_=listener.accept()=>panic!("denied path sent externally"),_=tokio::task::yield_now()=>{}}
    let mut conflict = request;
    conflict.question = Some("changed".into());
    assert!(matches!(f.services.explain_card(&p, &card.id, &conflict).await, Err(CoreError::Conflict(_))));
    f.services.operations.close();
    assert!(f.services.explain_card(&p, &card.id, &hosted).await.is_err());
}

#[tokio::test]
async fn explanation_owner_survives_disconnect_settles_bad_text_and_never_retries() {
    use memoswish_protocol::{ExplainDisposition, ExplainRequest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut f = fixture(None, None).await;
    let card = explanation_card(&mut f).await;
    let p = Principal::local_owner("single_user");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.services.content = ContentService::new(f.repo.clone()).with_ai_config(memoswish_content::AiExplainConfig {
        base_url: Some(format!("http://{}", listener.local_addr().unwrap())),
        api_key: Some("synthetic".into()),
        budget: Some(explanation_policy()),
        ..Default::default()
    });
    let services = f.services.clone();
    let id = card.id.clone();
    let principal = p.clone();
    let request = ExplainRequest { request_id: Some("disconnect".into()), ..Default::default() };
    let command = request.clone();
    let caller = tokio::spawn(async move { services.explain_card(&principal, &id, &command).await });
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut raw = Vec::new();
    loop {
        let mut chunk = [0; 4096];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        raw.extend_from_slice(&chunk[..n]);
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let attempt_id: String = sqlx::query_scalar(
        "SELECT operation_id FROM explanation_requests WHERE tenant_id='local' AND request_id='disconnect'",
    )
    .fetch_one(f.repo.pool())
    .await
    .unwrap();
    assert!(String::from_utf8_lossy(&raw).to_ascii_lowercase().contains(&format!("x-client-request-id: {attempt_id}")));
    assert_eq!(
        f.services.explanation_operation(&p, "disconnect").await.unwrap().disposition,
        ExplainDisposition::Unresolved
    );
    caller.abort();
    let _ = caller.await;
    let body=serde_json::json!({"id":"chatcmpl-test","model":"gpt-4o-mini-2024-07-18","service_tier":"default","usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30},"choices":[{"finish_reason":"length","message":{"content":"broken"}}]}).to_string();
    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
    drop(stream);
    f.services.operations.close();
    f.services.operations.wait().await;
    assert_eq!(
        f.services.explanation_operation(&p, "disconnect").await.unwrap().disposition,
        ExplainDisposition::Settled
    );
    // 重启后的同一数据库和新 tracker 不重复发送，返回本地回退与已结算处置。
    let mut services = f.services.clone();
    services.operations = Default::default();
    let text = services.explain_card(&p, &card.id, &request).await.unwrap();
    assert_eq!(text.provider, "builtin-heuristic");
    assert_eq!(text.operation.unwrap().disposition, ExplainDisposition::Settled);
    let committed: i64 = sqlx::query_scalar(
        "SELECT CAST(SUM(committed) AS BIGINT) FROM explanation_accounts WHERE scope='deployment:test-deployment'",
    )
    .fetch_one(f.repo.pool())
    .await
    .unwrap();
    assert_eq!(committed, 2);
    tokio::select! {biased;_=listener.accept()=>panic!("paid request was resent"),_=tokio::task::yield_now()=>{}}
}

#[tokio::test]
async fn explanation_success_cache_is_subject_revision_and_locale_bound() {
    use memoswish_protocol::ExplainRequest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut f = fixture(None, None).await;
    let card = explanation_card(&mut f).await;
    let p = Principal::local_owner("single_user");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.services.content = ContentService::new(f.repo.clone()).with_ai_config(memoswish_content::AiExplainConfig {
        base_url: Some(format!("http://{}", listener.local_addr().unwrap())),
        api_key: Some("synthetic".into()),
        budget: Some(explanation_policy()),
        ..Default::default()
    });
    let responses = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 65536];
            assert!(stream.read(&mut bytes).await.unwrap() > 0);
            let body=serde_json::json!({"id":"chatcmpl-cache","model":"gpt-4o-mini-2024-07-18","service_tier":"default","usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30},"choices":[{"finish_reason":"stop","message":{"content":serde_json::json!({"summary":"Synthetic provider explanation","key_points":["one","two"],"analogy":"a useful analogy","follow_up_questions":[]}).to_string()}}]}).to_string();
            stream
                .write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                        .as_bytes(),
                )
                .await
                .unwrap();
        }
        listener
    });
    let mut request = ExplainRequest { request_id: Some("first".into()), ..Default::default() };
    let first = f.services.explain_card(&p, &card.id, &request).await.unwrap();
    assert!(first.provider.starts_with("openai:"));
    request.request_id = Some("second".into());
    let cached = f.services.explain_card(&p, &card.id, &request).await.unwrap();
    assert_eq!(cached.summary, first.summary);
    assert_eq!(cached.operation.unwrap().request_id, "second");
    request.request_id = Some("different-locale".into());
    request.locale = Some("zh-CN".into());
    let fresh = f.services.explain_card(&p, &card.id, &request).await.unwrap();
    assert!(fresh.provider.starts_with("openai:"));
    let listener = responses.await.unwrap();
    f.services.auth = AuthService::new(
        f.repo.clone(),
        AuthConfig {
            mode: DeploymentMode::MultiTenant,
            jwt_secret: "a".repeat(32),
            jwt_ttl_secs: 3600,
            registration_open: true,
            default_plan: "self_hosted".into(),
        },
    )
    .unwrap()
    .with_privacy_policy(f.services.auth.privacy_policy().clone())
    .unwrap();
    let replay = ExplainRequest { request_id: Some("first".into()), ..Default::default() };
    let cached = f.services.explain_card(&p, &card.id, &replay).await.unwrap();
    assert_eq!(cached.summary, first.summary);
    assert!(cached.provider.starts_with("openai:"));
    let state = f.services.auth.privacy_state(&p).await.unwrap();
    f.services
        .auth
        .update_privacy(
            &p,
            &memoswish_protocol::PrivacyUpdate {
                expected_revision: state.revision,
                kind: "external_ai".into(),
                version: "provider-policy-v1".into(),
                decision: false,
                value: String::new(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(f.services.explain_card(&p, &card.id, &replay).await, Err(CoreError::Forbidden(_))));
    let retained:i64=sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations WHERE result IS NOT NULL AND id IN(SELECT operation_id FROM explanation_requests WHERE request_id='first')").fetch_one(f.repo.pool()).await.unwrap();
    assert_eq!(retained, 0);
    let sends: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations WHERE attempted=1")
        .fetch_one(f.repo.pool())
        .await
        .unwrap();
    assert_eq!(sends, 2);
    tokio::select! {biased;_=listener.accept()=>panic!("cache replay sent externally"),_=tokio::task::yield_now()=>{}}
}

#[tokio::test]
async fn explanation_production_fallbacks_enforce_the_complete_result_ceiling() {
    use memoswish_protocol::ExplainRequest;
    let mut f = fixture(None, None).await;
    let mut card = explanation_card(&mut f).await;
    let p = Principal::local_owner("test");
    f.repo.delete_card("local", &card.id).await.unwrap();
    for id_bytes in [20_000, 16_100] {
        card.id = "x".repeat(id_bytes);
        f.repo.insert_card("local", &card).await.unwrap();
        if id_bytes == 16_100 {
            // 本地正文可容纳，但长请求身份使完整操作信封超限。
            f.services.content.explain_card(&p, &card.id, &ExplainRequest::default()).await.unwrap();
        }
        for mode in [DeploymentMode::SingleUser, DeploymentMode::MultiTenant] {
            f.services.auth = AuthService::new(
                f.repo.clone(),
                AuthConfig {
                    mode,
                    jwt_secret: "a".repeat(32),
                    jwt_ttl_secs: 3600,
                    registration_open: false,
                    default_plan: "self_hosted".into(),
                },
            )
            .unwrap();
            for request_id in [None, Some(format!("{id_bytes}-{mode:?}-{}", "r".repeat(100)))] {
                let request = ExplainRequest { request_id, ..Default::default() };
                memoswish_content::explain::validate_input(&card, &request).unwrap();
                let result = f.services.explain_card(&p, &card.id, &request).await;
                if id_bytes == 16_100 && request.request_id.is_none() {
                    assert!(serde_json::to_vec(&result.unwrap()).unwrap().len() <= 16_384);
                } else {
                    assert!(matches!(result, Err(CoreError::Invalid(_))));
                }
            }
        }
    }
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn explanation_withdrawal_during_provider_attempt_settles_without_publishing() {
    use memoswish_protocol::{ExplainDisposition, ExplainRequest, PrivacyUpdate};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut f = fixture(None, None).await;
    let card = explanation_card(&mut f).await;
    let p = Principal::local_owner("single_user");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.services.content = ContentService::new(f.repo.clone()).with_ai_config(memoswish_content::AiExplainConfig {
        base_url: Some(format!("http://{}", listener.local_addr().unwrap())),
        api_key: Some("synthetic".into()),
        budget: Some(explanation_policy()),
        ..Default::default()
    });
    let services = f.services.clone();
    let id = card.id.clone();
    let principal = p.clone();
    let request = ExplainRequest { request_id: Some("withdraw-in-flight".into()), ..Default::default() };
    let command = request.clone();
    let caller = tokio::spawn(async move { services.explain_card(&principal, &id, &command).await });
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut bytes = vec![0; 65536];
    assert!(stream.read(&mut bytes).await.unwrap() > 0);
    assert_eq!(
        f.services.explanation_operation(&p, "withdraw-in-flight").await.unwrap().disposition,
        ExplainDisposition::Unresolved
    );
    let state = f.services.auth.privacy_state(&p).await.unwrap();
    f.services
        .auth
        .update_privacy(
            &p,
            &PrivacyUpdate {
                expected_revision: state.revision,
                kind: "external_ai".into(),
                version: "provider-policy-v1".into(),
                decision: false,
                value: String::new(),
            },
        )
        .await
        .unwrap();
    let body = serde_json::json!({
        "id":"chatcmpl-withdraw", "model":"gpt-4o-mini-2024-07-18", "service_tier":"default",
        "usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30},
        "choices":[{"finish_reason":"stop","message":{"content":serde_json::json!({
            "summary":"Private explanation", "key_points":["One","Two"],
            "analogy":"An analogy", "follow_up_questions":["Why?"]
        }).to_string()}}]
    })
    .to_string();
    stream
        .write_all(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes(),
        )
        .await
        .unwrap();
    drop(stream);
    assert!(matches!(caller.await.unwrap(), Err(CoreError::Forbidden(_))));
    let operation = f.services.explanation_operation(&p, "withdraw-in-flight").await.unwrap();
    assert_eq!(operation.disposition, ExplainDisposition::Suppressed);
    let accounting = operation.accounting.unwrap();
    assert_eq!((accounting.attempts, accounting.committed_microcurrency, accounting.held_microcurrency), (1, 2, 0));
    let results: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations WHERE result IS NOT NULL OR authority<>'{}'")
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
    assert_eq!(results, 0);
    assert!(matches!(f.services.explain_card(&p, &card.id, &request).await, Err(CoreError::Forbidden(_))));
    let absent = ExplainRequest { request_id: Some("absent-purpose".into()), ..Default::default() };
    sqlx::query("DELETE FROM privacy_purposes WHERE tenant_id='local'").execute(f.repo.pool()).await.unwrap();
    assert!(matches!(f.services.explain_card(&p, &card.id, &absent).await, Err(CoreError::Forbidden(_))));
    tokio::select! {biased; _=listener.accept()=>panic!("withdrawn explanation was resent"),_=tokio::task::yield_now()=>{}}
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn explanation_nonexecuting_role_rejects_admission_settlement_and_recovery() {
    use memoswish_protocol::{ExplainReconcileRequest, ExplainRequest};
    let mut f = fixture(None, None).await;
    let card = explanation_card(&mut f).await;
    let p = Principal::local_owner("single_user");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.services.content = ContentService::new(f.repo.clone())
        .with_ai_config(memoswish_content::AiExplainConfig {
            base_url: Some(format!("http://{}", listener.local_addr().unwrap())),
            api_key: Some("synthetic".into()),
            budget: Some(explanation_policy()),
            ..Default::default()
        })
        .with_external_ai_execution(false);
    f.services.media = f.services.media.clone().with_execution(false);
    let request = ExplainRequest { request_id: Some("api-role".into()), ..Default::default() };
    assert!(matches!(f.services.explain_card(&p, &card.id, &request).await, Err(CoreError::Unavailable(_))));
    assert!(f.services.recover_explanations().is_err());
    let evidence =
        ExplainReconcileRequest { input_tokens: Some(1), output_tokens: Some(1), not_charged_reference_sha256: None };
    assert!(matches!(
        f.services.reconcile_explanation_request(&p, "api-role", &evidence).await,
        Err(CoreError::Unavailable(_))
    ));
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations").fetch_one(f.repo.pool()).await.unwrap();
    assert_eq!(count, 0);
    tokio::select! {biased; _=listener.accept()=>panic!("nonexecuting role sent a request"),_=tokio::task::yield_now()=>{}}
}

#[tokio::test]
async fn explicit_cancellation_at_tts_admission_barrier_prevents_reservation() {
    let mut f = fixture(None, None).await;
    let gate = Arc::new(Gate::new());
    f.services.media = MediaService::new(
        f.repo.clone(),
        f.store.clone(),
        Arc::new(SubmissionQuota { inner: f.quota.clone(), admission: gate.clone() }),
        vec![Arc::new(PlaceholderTts)],
        "placeholder",
    )
    .unwrap();
    let p = Principal::local_owner("test");
    let deck = f
        .services
        .create_deck(
            &p,
            NewDeck { title: "Cancel".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let card =
        f.services.content.upsert_cards(&p, slice_material(&deck.id, "One :: Answer", 1)).await.unwrap().remove(0);
    let control = crate::OperationControl::default();
    let owned_control = control.clone();
    let services = f.services.clone();
    let owner = p.clone();
    let id = card.id.clone();
    let task = tokio::spawn(async move {
        owned_control.scope(services.submit_tts(&owner, "explicit-cancel", &[id], &SynthesizeOptions::default())).await
    });
    gate.reached(1).await;
    control.cancel();
    gate.release.add_permits(1);
    assert!(matches!(task.await.unwrap(), Err(CoreError::Unavailable(_))));
    assert!(matches!(f.services.tts_submission_status(&p, "explicit-cancel").await, Err(CoreError::NotFound(_))));
    assert_eq!(f.repo.get_card(&p.tenant_id, &card.id).await.unwrap().unwrap().revision, card.revision);
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn import_status_is_read_only_and_original_authority_scoped() {
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let pack = memoswish_protocol::examples::sample_deck_pack();
    let first =
        f.services.import_deck_pack_with_identity(&p, pack.clone(), false, Some("lookup".into()), None).await.unwrap();
    let status = f.services.import_status(&p, "lookup", None).await.unwrap();
    assert_eq!(status["outcome"], "committed");
    let replay = f.services.import_deck_pack_with_identity(&p, pack, false, Some("lookup".into()), None).await.unwrap();
    assert_eq!(first.id, replay.id);
    let credential =
        memoswish_core::imports::ImportCredential { token_hash: Some("foreign-credential".into()), expires_at: None };
    assert!(matches!(f.services.import_status(&p, "lookup", Some(credential)).await, Err(CoreError::NotFound(_))));
    assert_eq!(f.services.list_decks(&p).await.unwrap().len(), 1);
}

#[tokio::test]
async fn explanation_explicit_cancel_before_acceptance_leaves_no_hold_or_attempt() {
    let mut f = fixture(None, None).await;
    let card = explanation_card(&mut f).await;
    let p = Principal::local_owner("single_user");
    let control = crate::OperationControl::default();
    control.cancel();
    let request =
        memoswish_protocol::ExplainRequest { request_id: Some("cancel-before-ai".into()), ..Default::default() };
    assert!(matches!(
        control.scope(f.services.explain_card(&p, &card.id, &request)).await,
        Err(CoreError::Unavailable(_))
    ));
    assert!(matches!(f.services.explanation_operation(&p, "cancel-before-ai").await, Err(CoreError::NotFound(_))));
    for table in ["explanation_operations", "explanation_holds"] {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}")).fetch_one(f.repo.pool()).await.unwrap();
        assert_eq!(count, 0);
    }
}

#[tokio::test]
async fn accepted_import_cancel_and_lost_waiter_recover_by_original_key_without_recharging() {
    let _guard = APKG_TEST.lock().await;
    let gate = Arc::new(Gate::new());
    let f = fixture(None, Some(gate.clone())).await;
    let p = Principal::local_owner("test");
    let bytes = support::zip(vec![
        ("collection.anki2", support::database("basic", "Question<img src='x.png'>\x1fAnswer", &[0]).await),
        ("media", br#"{"0":"x.png"}"#.to_vec()),
        ("0", b"\x89PNG\r\n\x1a\nimage".to_vec()),
    ]);
    let control = crate::OperationControl::default();
    let owned = control.clone();
    let services = f.services.clone();
    let owner = p.clone();
    let payload = bytes.clone();
    let waiter = tokio::spawn(async move {
        owned
            .scope(services.import_apkg_with_identity(
                &owner,
                payload,
                ApkgOptions::default(),
                Some("accepted-cancel".into()),
                None,
            ))
            .await
    });
    gate.reached(1).await;
    assert_eq!(f.services.import_status(&p, "accepted-cancel", None).await.unwrap()["outcome"], "pending");
    control.cancel();
    waiter.abort();
    let _ = waiter.await;
    gate.release.add_permits(1);
    f.services.operations.close();
    f.services.operations.wait().await;
    let mut resumed = f.services.clone();
    resumed.operations = Default::default();
    assert_eq!(resumed.import_status(&p, "accepted-cancel", None).await.unwrap()["outcome"], "committed");
    resumed
        .import_apkg_with_identity(&p, bytes, ApkgOptions::default(), Some("accepted-cancel".into()), None)
        .await
        .unwrap();
    assert_eq!(resumed.list_decks(&p).await.unwrap().len(), 1);
    assert_eq!(f.store.puts.load(Ordering::SeqCst), 1);
    assert_eq!(f.repo.get_usage("local", "card_writes", &memoswish_auth::quota::current_period()).await.unwrap(), 1);
}

#[tokio::test]
async fn strict_authoring_cancel_before_acceptance_never_charges_or_changes_content() {
    use memoswish_protocol::{CardSave, PublicationCommand, ReportCreate};
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let deck = f
        .services
        .create_authored_deck(
            &p,
            NewDeck { title: "Private drafts".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let draft = slice_material(&deck.id, "Question :: Answer", 1).remove(0);
    let saved = f
        .services
        .save_card(&p, CardSave { card: draft.clone(), publish: false, provenance: None, report_id: None })
        .await
        .unwrap();
    let used = f.services.usage(&p).await.unwrap();
    let control = OperationControl::default();
    control.cancel();
    for publish in [false, true] {
        assert!(matches!(
            control
                .scope(
                    f.services
                        .save_card(&p, CardSave { card: draft.clone(), publish, provenance: None, report_id: None })
                )
                .await,
            Err(CoreError::Unavailable(_))
        ));
        for method in ["agent", "heuristic"] {
            assert!(matches!(
                control.scope(f.services.save_generated_cards(&p, vec![draft.clone()], publish, method)).await,
                Err(CoreError::Unavailable(_))
            ));
        }
    }
    assert!(matches!(
        control
            .scope(f.services.publish_card(
                &p,
                &saved.id,
                PublicationCommand { expected_revision: saved.revision, publish: true }
            ))
            .await,
        Err(CoreError::Unavailable(_))
    ));
    assert!(matches!(
        control
            .scope(f.services.report_content(
                &p,
                &saved.id,
                &ReportCreate { observed_revision: saved.revision, text: "Check this answer".into(), sources: vec![] }
            ))
            .await,
        Err(CoreError::Unavailable(_))
    ));
    assert_eq!(f.services.get_card(&p, &saved.id).await.unwrap(), saved);
    assert_eq!(f.services.list_cards(&p, Some(&deck.id), 10, 0).await.unwrap().len(), 1);
    assert_eq!(f.services.usage(&p).await.unwrap(), used);
    assert!(f.services.content_reports(&p, &saved.id, 0, 10).await.unwrap().is_empty());
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn strict_authoring_cancel_during_accounting_and_disconnect_keep_atomic_save_publish() {
    use memoswish_protocol::CardSave;
    let gate = Arc::new(Gate::new());
    let f = fixture(Some(gate.clone()), None).await;
    let p = Principal::local_owner("test");
    let deck = f
        .services
        .create_authored_deck(
            &p,
            NewDeck { title: "Accepted save".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let draft = slice_material(&deck.id, "Question :: Answer", 1).remove(0);
    let control = OperationControl::default();
    let owned = control.clone();
    let services = f.services.clone();
    let owner = p.clone();
    let waiter = tokio::spawn(async move {
        owned
            .scope(
                services.save_card(&owner, CardSave { card: draft, publish: true, provenance: None, report_id: None }),
            )
            .await
    });
    gate.reached(1).await;
    assert_eq!(*control.subscribe().borrow(), "accepting");
    control.cancel();
    waiter.abort();
    let _ = waiter.await;
    f.services.operations.close();
    gate.release.add_permits(1);
    f.services.operations.wait().await;
    let cards = f.services.list_cards(&p, Some(&deck.id), 10, 0).await.unwrap();
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].content.as_ref().unwrap().publication, "published");
    assert_eq!(*control.subscribe().borrow(), "accepted");
    let usage = f.services.usage(&p).await.unwrap();
    let writes = usage.metrics.iter().find(|m| m.metric == "card_writes").unwrap();
    assert_eq!((writes.used, writes.held), (1, 0));
}

#[tokio::test]
async fn cancelled_pending_import_recovers_under_maintenance_authority() {
    use memoswish_core::maintenance::{TaskKind, TaskRegistration};
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    sqlx::raw_sql("CREATE TRIGGER reject_cancelled_import BEFORE UPDATE OF result ON content_imports WHEN NEW.outcome='committed' BEGIN SELECT RAISE(ABORT,'injected commit failure'); END;")
        .execute(f.repo.pool()).await.unwrap();
    let control = OperationControl::default();
    let pack = memoswish_protocol::examples::sample_deck_pack();
    assert!(matches!(
        control
            .scope(f.services.import_deck_pack_with_identity(
                &p,
                pack.clone(),
                false,
                Some("cancelled-pending".into()),
                None,
            ))
            .await,
        Err(CoreError::Unavailable(_))
    ));
    assert_eq!(*control.subscribe().borrow(), "accepted");
    control.cancel();
    assert_eq!(f.services.import_status(&p, "cancelled-pending", None).await.unwrap()["outcome"], "pending");
    let usage = f.services.usage(&p).await.unwrap();
    let writes = usage.metrics.iter().find(|m| m.metric == "card_writes").unwrap();
    assert_eq!((writes.used, writes.held), (0, 1));
    f.services.operations.close();
    f.services.operations.wait().await;
    let (id, state, attempts): (String, String, i64) =
        sqlx::query_as("SELECT id,state,attempts FROM background_jobs WHERE tenant_id=$1 AND kind='content_import'")
            .bind(&p.tenant_id)
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
    assert_eq!((state, attempts), ("queued".into(), 1));
    assert!(f.repo.claim_import(&p.tenant_id, &id, 120_000).await.unwrap().is_none());
    // SQL 失败已经提交业务节流；模拟间隔经过后再重启维护执行。
    sqlx::raw_sql("DROP TRIGGER reject_cancelled_import; UPDATE background_jobs SET available_at_ms=0,lease_until_ms=0 WHERE work_scope='tenant' AND state IN ('queued','running');")
        .execute(f.repo.pool()).await.unwrap();
    let mut restarted = f.services.clone();
    restarted.operations = Default::default();
    restarted.recover_imports().unwrap().await.unwrap().unwrap();
    assert_eq!(restarted.import_status(&p, "cancelled-pending", None).await.unwrap()["outcome"], "committed");
    let task = TaskRegistration::system(TaskKind::ImportRecovery).id().unwrap();
    let admissions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM maintenance_admissions WHERE task_id=$1")
        .bind(task)
        .fetch_one(f.repo.pool())
        .await
        .unwrap();
    assert_eq!(admissions, 1);
    restarted.import_deck_pack_with_identity(&p, pack, false, Some("cancelled-pending".into()), None).await.unwrap();
    assert_eq!(restarted.list_decks(&p).await.unwrap().len(), 1);
    let usage = restarted.usage(&p).await.unwrap();
    let writes = usage.metrics.iter().find(|m| m.metric == "card_writes").unwrap();
    assert_eq!((writes.used, writes.held), (1, 0));
    restarted.operations.close();
    restarted.operations.wait().await;
}

#[tokio::test]
async fn authored_import_cancellation_before_acceptance_releases_all_preparation_without_hold() {
    let _guard = APKG_TEST.lock().await;
    for apkg in [false, true] {
        let gate = Arc::new(Gate::new());
        let f = fixture(Some(gate.clone()), None).await;
        let control = OperationControl::default();
        let owned = control.clone();
        let services = f.services.clone();
        let bytes = if apkg { support::basic().await } else { vec![] };
        let waiter = tokio::spawn(async move {
            owned
                .scope(async {
                    let p = Principal::local_owner("test");
                    if apkg {
                        services
                            .import_authored_apkg(
                                &p,
                                bytes,
                                memoswish_protocol::ContentApkgImport {
                                    apkg: memoswish_protocol::ApkgImportRequest {
                                        request_id: Some("cancel-authored".into()),
                                        apkg_base64: String::new(),
                                        title: None,
                                        language: None,
                                    },
                                    publish: false,
                                },
                                None,
                            )
                            .await
                            .map(|_| ())
                    } else {
                        services
                            .import_authored_content(
                                &p,
                                memoswish_protocol::ContentImport {
                                    pack: memoswish_protocol::examples::sample_portable_deck_pack(),
                                    idempotency_key: "cancel-authored".into(),
                                    publish: true,
                                },
                                None,
                            )
                            .await
                            .map(|_| ())
                    }
                })
                .await
        });
        gate.reached(1).await;
        control.cancel();
        gate.release.add_permits(1);
        assert!(matches!(waiter.await.unwrap(), Err(CoreError::Unavailable(_))));
        let p = Principal::local_owner("test");
        assert!(f.services.list_decks(&p).await.unwrap().is_empty());
        let usage = f.services.usage(&p).await.unwrap();
        let writes = usage.metrics.iter().find(|m| m.metric == "card_writes").unwrap();
        assert_eq!((writes.used, writes.held), (0, 0));
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_imports").fetch_one(f.repo.pool()).await.unwrap();
        assert_eq!(count, 0);
        f.services.operations.close();
        f.services.operations.wait().await;
        if apkg {
            let prepared =
                f.services.content.prepare_apkg(&p, support::basic().await, ApkgOptions::default()).await.unwrap();
            drop(prepared);
        }
    }
}

#[tokio::test]
async fn bgm_disconnect_after_put_keeps_owned_publication_and_immutable_replay() {
    use base64::Engine;
    use memoswish_core::bgm::BgmPublicationRepo;
    let gate = Arc::new(Gate::new());
    let f = fixture(None, Some(gate.clone())).await;
    let service = f.services.clone();
    let wav = memoswish_media::wav::encode_wav(&[0.2; 80], 8000);
    let encoded = base64::engine::general_purpose::STANDARD.encode(wav);
    let control = crate::OperationControl::default();
    let inherited = control.clone();
    let task = tokio::spawn(async move {
        inherited
            .scope(async move {
                service
                    .upload_bgm(
                        &Principal::local_owner("test"),
                        BgmUpload {
                            provenance: None,
                            expected_revision: None,
                            title: "Owned BGM",
                            moods: vec![],
                            energy: 0.4,
                            bpm: 90,
                            audio_base64: &encoded,
                            license: "CC0",
                        },
                    )
                    .await
            })
            .await
    });
    gate.entered.acquire().await.unwrap().forget();
    assert_eq!(*control.subscribe().borrow(), "accepted");
    control.cancel();
    task.abort();
    let _ = task.await;
    let pending = f.repo.pending_bgm(None, 100).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert!(f.repo.bgm_stage(&pending[0].0, &pending[0].1).await.unwrap().is_some());
    f.services.operations.close();
    gate.release.add_permits(1);
    f.services.operations.wait().await;
    let result = f.repo.bgm_result(&pending[0].0, &pending[0].1).await.unwrap().unwrap();
    assert!(f.repo.bgm_stage(&pending[0].0, &pending[0].1).await.unwrap().is_none());
    assert_eq!(f.repo.bgm_result(&pending[0].0, &pending[0].1).await.unwrap().unwrap(), result);
    assert_eq!(f.store.puts.load(Ordering::SeqCst), 1);
    assert_eq!(f.services.list_bgm(&Principal::local_owner("test")).await.unwrap().len(), 1);
}

// 已取消调用不接纳 BGM；持久接受后的断连由原发布回归覆盖。
#[tokio::test]
async fn cancelled_bgm_preparation_accepts_no_publication() {
    use memoswish_core::bgm::BgmPublicationRepo;
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    f.services.media.ensure_builtin_bgm().await.unwrap();
    let control = crate::OperationControl::default();
    control.cancel();
    let command = memoswish_protocol::BgmClip {
        request_id: "cancelled-bgm".into(),
        track_id: "bgm_focus_pad".into(),
        start_frame: 0,
        end_frame: 100,
        title: None,
    };
    assert!(matches!(control.scope(f.services.clip_bgm(&p, &command)).await, Err(CoreError::Unavailable(_))));
    assert!(matches!(
        control.scope(f.services.generate_bgm(&p, "Cancelled", vec![], 0.4, 90)).await,
        Err(CoreError::Unavailable(_))
    ));
    assert!(f.repo.pending_bgm(None, 100).await.unwrap().is_empty());
    assert_eq!(*control.subscribe().borrow(), "preparing");
    f.services.operations.close();
    f.services.operations.wait().await;
}

// 重放沿用既有责任，同时向本次取消和进度控制报告接受状态。
#[tokio::test]
async fn bgm_replay_reports_existing_acceptance() {
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    f.services.media.ensure_builtin_bgm().await.unwrap();
    let command = memoswish_protocol::BgmClip {
        request_id: "accepted-replay".into(),
        track_id: "bgm_focus_pad".into(),
        start_frame: 0,
        end_frame: 100,
        title: None,
    };
    let first = f.services.clip_bgm(&p, &command).await.unwrap();
    let control = crate::OperationControl::default();
    let replay = control.scope(f.services.clip_bgm(&p, &command)).await.unwrap();
    assert_eq!(first, replay);
    assert_eq!(*control.subscribe().borrow(), "accepted");
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn hf11_empty_suffix_wraps_once_and_stops_when_peer_wins_reclaim() {
    use memoswish_core::{imports::ImportAuthority, maintenance::*};
    let f = fixture(None, None).await;
    let p = Principal::local_owner("test");
    let pack = memoswish_protocol::examples::sample_deck_pack();
    let work = f.services.content.prepare_deck_pack(&p, pack.clone(), false).unwrap();
    let fingerprint = memoswish_content::imports::fingerprint("deckpack", &pack, false).unwrap();
    let operation = f
        .repo
        .accept_import(&ImportAuthority::capture(&p, None), "hf11-wrap", &fingerprint, &work, None, 2)
        .await
        .unwrap();
    let id = f.repo.register_maintenance(&TaskRegistration::system(TaskKind::ImportRecovery)).await.unwrap();
    let first = f.repo.claim_maintenance(&id, "first").await.unwrap().unwrap();
    let (page, failed) = f.services.admit_scheduled_page(first).await.unwrap();
    assert!(!failed);
    assert_eq!(page.len(), 1);
    for expected_cycle in [1, 2] {
        let suffix = f.repo.claim_maintenance(&id, "suffix").await.unwrap().unwrap();
        let (page, failed) = f.services.admit_scheduled_page(suffix).await.unwrap();
        assert!(!failed);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].item.id, operation.id);
        let cycle: i64 = sqlx::query_scalar("SELECT cycle FROM maintenance_tasks WHERE id=$1")
            .bind(&id)
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
        assert_eq!(cycle, expected_cycle, "unresolved responsibility permits only one wrap per invocation");
    }
    let suffix = f.repo.claim_maintenance(&id, "loser").await.unwrap().unwrap();
    // 夹具模拟 peer 在完成提交后抢先领取；真实双池 claim 竞态由共享 conformance 覆盖。
    sqlx::raw_sql("CREATE TRIGGER peer_wins_hf11 AFTER UPDATE OF state ON background_jobs WHEN NEW.work_scope='maintenance' AND NEW.state='queued' AND NEW.id LIKE 'maintenance:import_recovery:%' BEGIN UPDATE background_jobs SET state='running',token='peer-token',worker='peer',lease_until_ms=NEW.available_at_ms+300000 WHERE tenant_id='' AND id=NEW.id; END;")
        .execute(f.repo.pool()).await.unwrap();
    let (page, failed) = f.services.admit_scheduled_page(suffix).await.unwrap();
    assert!(!failed);
    assert!(page.is_empty());
    let owner: (String, String) =
        sqlx::query_as("SELECT token,worker FROM background_jobs WHERE tenant_id='' AND id=$1")
            .bind(&id)
            .fetch_one(f.repo.pool())
            .await
            .unwrap();
    assert_eq!(owner, ("peer-token".into(), "peer".into()));
    let admissions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM maintenance_admissions WHERE task_id=$1")
        .bind(&id)
        .fetch_one(f.repo.pool())
        .await
        .unwrap();
    assert_eq!(admissions, 3);
    f.services.operations.close();
    f.services.operations.wait().await;
}

#[tokio::test]
async fn hf11_cancelled_scanner_waiter_retains_business_permit_until_shutdown_drain() {
    use memoswish_core::maintenance::*;
    let f = fixture(None, None).await;
    let gate = Arc::new(Gate::new());
    let mut services = f.services.clone();
    services.media = MediaService::new(
        f.repo.clone(),
        f.store.clone(),
        f.quota.clone(),
        vec![Arc::new(PausedTts(gate.clone()))],
        "paused",
    )
    .unwrap();
    let p = Principal::local_owner("test");
    let deck = services
        .create_deck(
            &p,
            NewDeck { title: "HF11".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let card =
        services.content.upsert_cards(&p, slice_material(&deck.id, "Handoff :: Answer", 1)).await.unwrap().remove(0);
    services
        .media
        .submit_tts(&p, "hf11-cancel", std::slice::from_ref(&card.id), &SynthesizeOptions::default())
        .await
        .unwrap();
    let task = services.recover_scheduled(TaskKind::SpeechRecovery).unwrap();
    gate.reached(1).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(Services::maintenance_work_permit(TaskKind::SpeechRecovery).is_err());
    let independent = Services::maintenance_work_permit(TaskKind::AttachmentRecovery).unwrap();
    drop(independent);
    services.operations.close();
    let drain = services.operations.wait();
    tokio::pin!(drain);
    assert!(matches!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(drain.as_mut().poll(cx))).await,
        std::task::Poll::Pending
    ));
    gate.release.add_permits(1);
    drain.await;
    assert!(Services::maintenance_work_permit(TaskKind::SpeechRecovery).is_ok());
}

struct Hf11FirstFailure(AtomicUsize);
#[async_trait]
impl TtsEngine for Hf11FirstFailure {
    fn id(&self) -> &str {
        "hf11-first-failure"
    }
    fn voices(&self) -> Vec<VoiceInfo> {
        vec![]
    }
    async fn synthesize(&self, request: &TtsRequest) -> CoreResult<TtsOutput> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(CoreError::Unavailable("injected first item failure".into()));
        }
        PlaceholderTts.synthesize(request).await
    }
}

#[tokio::test]
async fn hf11_business_failure_does_not_skip_other_admitted_items() {
    use memoswish_core::{maintenance::*, tts::SpeechRepo};
    let f = fixture_storage(None, None, true).await;
    let p = Principal::local_owner("test");
    let engine = Arc::new(Hf11FirstFailure(AtomicUsize::new(0)));
    let mut services = f.services.clone();
    services.media =
        MediaService::new(f.repo.clone(), f.store.clone(), f.quota.clone(), vec![engine.clone()], engine.id()).unwrap();
    let deck = services
        .create_deck(
            &p,
            NewDeck { title: "HF11".into(), description: String::new(), language: "en".into(), tags: vec![] },
        )
        .await
        .unwrap();
    let cards = services
        .content
        .upsert_cards(&p, slice_material(&deck.id, "First :: Answer\nSecond :: Answer", 2))
        .await
        .unwrap();
    assert_eq!(cards.len(), 2);
    services
        .media
        .submit_tts(
            &p,
            "hf11-page-failure",
            &cards.iter().map(|card| card.id.clone()).collect::<Vec<_>>(),
            &SynthesizeOptions::default(),
        )
        .await
        .unwrap();
    assert!(services.recover_scheduled(TaskKind::SpeechRecovery).unwrap().await.unwrap().is_err());
    assert_eq!(
        engine.0.load(Ordering::SeqCst),
        2,
        "one failed business item cannot starve the rest of its admitted page"
    );
    let published: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tts_requesters WHERE outcome='published'")
        .fetch_one(f.repo.pool())
        .await
        .unwrap();
    assert_eq!(published, 1);
    let failed: String = sqlx::query_scalar(
        "SELECT id FROM background_jobs WHERE tenant_id=$1 AND kind='tts_synthesis' AND state='queued'",
    )
    .bind(&p.tenant_id)
    .fetch_one(f.repo.pool())
    .await
    .unwrap();
    assert!(f.repo.claim_speech(&p.tenant_id, &failed, 120_000).await.unwrap().is_none());
    assert_eq!(engine.0.load(Ordering::SeqCst), 2);
    let task = TaskRegistration::system(TaskKind::SpeechRecovery).id().unwrap();
    assert!(f.repo.claim_maintenance(&task, "too-soon").await.unwrap().is_none());
    services.operations.close();
    services.operations.wait().await;
    f.repo.pool().close().await;
}

#[tokio::test]
async fn explanation_configured_models_charge_policy_rates_and_mismatches_keep_holds() {
    use memoswish_content::explain::ReasoningEffort;
    use memoswish_protocol::{ExplainDisposition, ExplainRequest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for (model, effort, returned_model, accepted) in [
        ("gpt-4o-mini", None, "gpt-4o-mini", true),
        ("gpt-4o-mini", None, "gpt-4o-mini-2024-07-18", true),
        ("gpt-4o-mini-2024-07-18", None, "gpt-4o-mini-2024-07-18", true),
        ("gpt-6-luna", None, "gpt-6-luna", true),
        ("gpt-6-luna", Some(ReasoningEffort::Low), "gpt-6-luna", true),
        ("operator/custom-model", Some(ReasoningEffort::Low), "operator/custom-model", true),
        ("gpt-6-luna", Some(ReasoningEffort::Low), "gpt-4o-mini", false),
        ("gpt-6-luna", None, "gpt-6-luna-snapshot", false),
        ("operator/custom-model", None, "operator/custom-model-snapshot", false),
        ("gpt-4o-mini", None, "gpt-4o-mini-evil", false),
        ("gpt-4o-mini", None, "gpt-4o", false),
        ("gpt-4o-mini", None, "gpt-4o-mini-2024-07-18-evil", false),
        ("gpt-4o-mini", None, "gpt-4o-mini-2099-01-01", false),
        ("gpt-4o-mini-2024-07-18", None, "gpt-4o-mini", false),
        ("gpt-4o-mini-2024-07-18", None, "gpt-4o-mini-2099-01-01", false),
        ("gpt-4o-mini-evil", None, "gpt-4o-mini-2024-07-18", false),
    ] {
        let mut f = fixture(None, None).await;
        let card = explanation_card(&mut f).await;
        let p = Principal::local_owner("single_user");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut policy = explanation_policy();
        policy.input_rate = 7;
        policy.output_rate = 19;
        policy.rate_denominator = 10;
        policy.tenant_limit = 200_000;
        policy.deployment_limit = 200_000;
        policy.provider_limit = 200_000;
        policy.unresolved_limit = 200_000;
        f.services.content = ContentService::new(f.repo.clone()).with_ai_config(memoswish_content::AiExplainConfig {
            base_url: Some(format!("http://{}", listener.local_addr().unwrap())),
            api_key: Some("AI1_CREDENTIAL_SENTINEL".into()),
            model: model.into(),
            reasoning_effort: effort,
            budget: Some(policy),
        });
        let provider = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let body = loop {
                let mut chunk = [0; 4096];
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&chunk[..n]);
                if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                    let length: usize =
                        header.lines().find_map(|line| line.strip_prefix("content-length: ")).unwrap().parse().unwrap();
                    if raw.len() >= end + 4 + length {
                        break serde_json::from_slice::<serde_json::Value>(&raw[end + 4..]).unwrap();
                    }
                }
            };
            assert_eq!(body["model"], model);
            assert_eq!(body.get("reasoning_effort"), effort.map(|value| serde_json::json!(value)).as_ref());
            let response = serde_json::json!({
                "id":"chatcmpl-ai1", "model":returned_model, "service_tier":"default",
                "usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30},
                "choices":[{"finish_reason":"stop","message":{"content":serde_json::json!({
                    "summary":"Configured model explanation", "key_points":["First","Second"],
                    "analogy":"Synthetic analogy", "follow_up_questions":[]
                }).to_string()}}]
            })
            .to_string();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                        response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            listener
        });
        let request = ExplainRequest { request_id: Some("ai1-rates".into()), ..Default::default() };
        let result = f.services.explain_card(&p, &card.id, &request).await.unwrap();
        let operation = result.operation.unwrap();
        let accounting = operation.accounting.unwrap();
        assert_eq!(accounting.attempts, 1);
        if accepted {
            assert_eq!(result.summary, "Configured model explanation");
            assert_eq!(operation.disposition, ExplainDisposition::Settled);
            assert_eq!(result.provider, format!("openai:{model}"));
            assert_eq!(accounting.committed_microcurrency, 33);
            assert_eq!(accounting.held_microcurrency, 0);
            assert_eq!((accounting.input_tokens, accounting.output_tokens), (Some(20), Some(10)));
        } else {
            assert_eq!(operation.disposition, ExplainDisposition::Unresolved);
            assert_eq!(result.provider, "builtin-heuristic");
            assert_eq!(accounting.committed_microcurrency, 0);
            assert!(accounting.held_microcurrency > 0);
            assert_eq!((accounting.input_tokens, accounting.output_tokens), (None, None));
        }
        let published: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM explanation_operations WHERE tenant_id=$1 AND result IS NOT NULL")
                .bind(&p.tenant_id)
                .fetch_one(f.repo.pool())
                .await
                .unwrap();
        assert_eq!(published, i64::from(accepted));
        let accounts: Vec<(i64, i64)> =
            sqlx::query_as("SELECT committed, held FROM explanation_accounts").fetch_all(f.repo.pool()).await.unwrap();
        assert_eq!(accounts.len(), 3);
        for (committed, held) in accounts {
            assert_eq!(committed, accounting.committed_microcurrency);
            assert_eq!(held, accounting.held_microcurrency);
        }
        let listener = provider.await.unwrap();
        let replay = f.services.explain_card(&p, &card.id, &request).await.unwrap();
        assert_eq!(replay.provider, result.provider);
        assert_eq!(replay.summary, result.summary);
        let replay_operation = replay.operation.unwrap();
        assert_eq!(replay_operation.disposition, operation.disposition);
        let replay_accounting = replay_operation.accounting.unwrap();
        assert_eq!(replay_accounting.committed_microcurrency, accounting.committed_microcurrency);
        assert_eq!(replay_accounting.held_microcurrency, accounting.held_microcurrency);
        assert_eq!(replay_accounting.attempts, 1);
        tokio::select! {
            biased;
            _ = listener.accept() => panic!("explanation replay resent provider request"),
            _ = tokio::task::yield_now() => {}
        }
        f.services.operations.close();
        f.services.operations.wait().await;
        f.repo.pool().close().await;
    }
}

#[tokio::test]
async fn hf13_memory_survives_connection_replacement_after_paused_time() {
    let repo = SqliteRepository::in_memory().await.unwrap();
    let connection = repo.pool().acquire().await.unwrap();
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(1801)).await;
    // 等待 SQLite 线程时使用真实时钟，避免虚拟时间自动跨过 acquire deadline。
    tokio::time::resume();
    connection.close().await.unwrap();
    assert_eq!(repo.pool().size(), 0);
    let _: i64 = sqlx::query_scalar("SELECT count(*) FROM cards").fetch_one(repo.pool()).await.unwrap();
}
