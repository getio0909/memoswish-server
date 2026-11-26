//! 有界格式适配、安全边界与失败补偿测试。

use super::*;
use async_trait::async_trait;
use memoswish_core::Role;
use memoswish_core::repo::Repository;
use memoswish_core::store::StoredObject;
use memoswish_protocol::ContentBlock;
use memoswish_storage::sqlite::SqliteRepository;
use sqlx::{Connection, SqliteConnection};
use std::sync::Mutex;

#[path = "../../tests/support/mod.rs"]
mod support;

mod budget;
mod descriptors;
mod raw_names;

static IMPORT_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn converter() -> convert::Converter {
    convert::Converter::default()
}

#[test]
fn apkg_literal_comparisons_follow_html_tag_opening_rules() {
    let mut converter = converter();
    for (html, latex) in [(r"\(0 < x < 1\)", "0 < x < 1"), (r#"<span style="color:red">\(x < y\)</span>"#, "x < y")] {
        let face = converter.face(html, "fallback", true).unwrap();
        assert_eq!(face.blocks, [ContentBlock::Math { latex: latex.into(), display: false }]);
    }
    assert_eq!(converter.face("a < b", "fallback", true).unwrap().title, "a < b");
    assert_eq!(converter.face("a <b", "fallback", true).unwrap().title, "a");
    assert!(convert::check_html_budget(&"< ".repeat(ApkgLimits::HTML_MARKERS)).is_ok());
    assert!(convert::check_html_budget(&"< ".repeat(ApkgLimits::HTML_MARKERS + 1)).is_err());
    for html in ["<!DOCTYPE html>text", "<?instruction>text", "</p>text"] {
        assert!(convert::check_html_budget(html).is_ok());
    }
    assert!(convert::check_html_budget(&format!("a <b {}", " a".repeat(65))).is_err());
}

#[test]
fn apkg_simple_tables_use_first_row_as_header() {
    let mut converter = converter();
    let face = converter
        .face(
            "before<table><tr><td>1</td><td>23</td></tr><tr><td>12</td><td>3</td></tr></table>after",
            "fallback",
            true,
        )
        .unwrap();
    assert_eq!(
        face.blocks,
        [
            ContentBlock::text("before"),
            ContentBlock::Table { header: vec!["1".into(), "23".into()], rows: vec![vec!["12".into(), "3".into()]] },
            ContentBlock::text("after"),
        ]
    );
    assert!(converter.warnings.messages.is_empty());
}

#[test]
fn apkg_tables_preserve_explicit_headers_and_inline_text() {
    let mut converter = converter();
    let face = converter.face(
        "<table><thead><tr><th><b>Name</b></th><th>Value</th></tr></thead><tbody><tr><td>A &amp; B</td><td>1<br>2</td></tr></tbody></table>",
        "fallback", true,
    ).unwrap();
    assert_eq!(
        face.blocks,
        [ContentBlock::Table {
            header: vec!["Name".into(), "Value".into()],
            rows: vec![vec!["A & B".into(), "1\n2".into()]],
        }]
    );
}

#[test]
fn apkg_irregular_tables_preserve_cell_and_row_separators() {
    let mut converter = converter();
    for html in [
        "<table><tr><td>1</td><td>23</td></tr><tr><td>4</td></tr></table>",
        "<table><tr><td colspan='2'>1</td><td>23</td></tr><tr><td>4</td></tr></table>",
        "<table><tr><td rowspan='2'>1</td><td>23</td></tr><tr><td>4</td></tr></table>",
    ] {
        let face = converter.face(html, "fallback", true).unwrap();
        assert_eq!(face.blocks, [ContentBlock::text("1 \\| 23\n\n4")]);
        assert!(converter.warnings.messages.last().unwrap().contains("table"));
    }
}

#[test]
fn apkg_repeated_media_hashes_each_source_filename_once() {
    let mut converter = converter();
    let mut bytes = vec![0; ApkgLimits::MEDIA];
    bytes[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    let expected_hash = sha256_hex(&bytes);
    converter.media.insert("图 片.png".into(), bytes.clone());
    converter.media.insert("same-content.png".into(), bytes);
    let html = r#"<img src="图%20片.png" alt="encoded"><img src="图 片.png" alt="direct">"#.repeat(6);
    for _ in 0..ApkgLimits::CARDS {
        for _ in 0..2 {
            let face = converter.face(&html, "fallback", true).unwrap();
            assert_eq!(face.blocks.len(), 12);
            for (i, block) in face.blocks.iter().enumerate() {
                let ContentBlock::Image { asset, alt } = block else { panic!("expected image") };
                assert_eq!(asset.sha256, expected_hash);
                assert_eq!(alt, if i % 2 == 0 { "encoded" } else { "direct" });
            }
        }
    }
    assert_eq!(converter.media_hashes.get("图 片.png"), Some(&1));
    assert_eq!(converter.media_hashes.len(), 1);
    assert_eq!(converter.resolved.len(), 1);
    assert_eq!(converter.uploads.len(), 1);
    converter.face("<img src='same-content.png'>", "fallback", true).unwrap();
    assert_eq!(converter.media_hashes.get("same-content.png"), Some(&1));
    assert_eq!(converter.uploads.len(), 1);
    // 已缓存图片也必须先做歧义校验，不能绕过编码文件名冲突。
    converter.media.insert("图%20片.png".into(), b"GIF89aimage".to_vec());
    assert!(converter.face(&html, "fallback", true).unwrap_err().to_string().contains("ambiguous"));
}

#[test]
fn apkg_table_dimensions_and_subtree_budgets_are_bounded() {
    let mut converter = converter();
    let html = format!("<table>{}</table>", "<tr><td>x</td></tr>".repeat(101));
    let face = converter.face(&html, "fallback", true).unwrap();
    assert!(matches!(&face.blocks[0], ContentBlock::Table { header, rows } if header.len() == 1 && rows.len() == 100));
    let html = format!("<table>{}</table>", "<tr><td>x</td></tr>".repeat(102));
    assert!(converter.face(&html, "fallback", true).unwrap_err().to_string().contains("100 data rows"));
    let html = format!("<table><tr>{}</tr></table>", "<td>x</td>".repeat(20));
    let face = converter.face(&html, "fallback", true).unwrap();
    assert!(matches!(&face.blocks[0], ContentBlock::Table { header, rows } if header.len() == 20 && rows.is_empty()));
    let html = format!("<table><tr>{}</tr></table>", "<td>x</td>".repeat(21));
    assert!(converter.face(&html, "fallback", true).unwrap_err().to_string().contains("20 columns"));
    let html = format!("<table><tr><td>{}</td></tr></table>", "界".repeat(8000));
    assert!(converter.face(&html, "fallback", true).is_ok());
    let html = format!("<table><tr><td>{}</td></tr></table>", "界".repeat(8001));
    assert!(converter.face(&html, "fallback", true).unwrap_err().to_string().contains("8000 characters"));
    let html = format!("<table><tr><td>{}x{}</td></tr></table>", "<span>".repeat(64), "</span>".repeat(64));
    assert!(converter.face(&html, "fallback", true).unwrap_err().to_string().contains("node or nesting budget"));
}

#[test]
fn apkg_rich_tables_preserve_media_math_and_filtered_content() {
    let mut converter = converter();
    converter.media.insert("x.png".into(), b"\x89PNG\r\n\x1a\nimage".to_vec());
    let face = converter.face(
        r#"<table><tr><td><img src="x.png"></td><td>\(x < y\)[sound:a.mp3]<script>evil()</script></td></tr></table>"#,
        "fallback", true,
    ).unwrap();
    assert_eq!(face.blocks.iter().filter(|b| matches!(b, ContentBlock::Image { .. })).count(), 1);
    assert!(face.blocks.contains(&ContentBlock::Math { latex: "x < y".into(), display: false }));
    assert!(text(&face).contains(r"\|"));
    assert!(!text(&face).contains("evil"));
    assert!(!text(&face).contains("a.mp3"));
    assert!(converter.audio.contains("a.mp3"));
    let face = converter
        .face(
            "<table><tr><td>outer<table><tr><td>inner</td><td>value</td></tr></table></td><td>end</td></tr></table>",
            "fallback",
            true,
        )
        .unwrap();
    assert!(text(&face).contains("outer"));
    assert!(text(&face).contains("end"));
    assert!(face.blocks.contains(&ContentBlock::Table { header: vec!["inner".into(), "value".into()], rows: vec![] }));
}

#[tokio::test]
async fn apkg_tables_and_literal_comparisons_roundtrip_through_import() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, repo, _) = service().await;
    let p = Principal::local_owner("test");
    let db = support::database(
        "basic",
        concat!(r"\(0 < x < 1\)<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>23</td></tr></table>", "\x1fBack"),
        &[0],
    )
    .await;
    let bytes = support::zip(vec![("collection.anki2", db), ("media", b"{}".to_vec())]);
    let prepared = svc.prepare_apkg(&p, bytes, ApkgOptions::default()).await.unwrap();
    let expected = prepared.cards[0].front.blocks.clone();
    assert!(expected.contains(&ContentBlock::Math { latex: "0 < x < 1".into(), display: false }));
    assert!(expected.contains(&ContentBlock::Table {
        header: vec!["A".into(), "B".into()],
        rows: vec![vec!["1".into(), "23".into()]]
    }));
    let report = svc.commit_apkg(&p, prepared).await.unwrap();
    let cards = repo.list_cards(&p.tenant_id, Some(&report.deck.id), 500, 0).await.unwrap();
    assert_eq!(cards[0].front.blocks, expected);
}

#[derive(Default)]
struct PutBarrier {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[derive(Default)]
struct MemoryStore {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    fail_put: bool,
    put_barrier: Option<Arc<PutBarrier>>,
}
#[async_trait]
impl ObjectStore for MemoryStore {
    fn kind(&self) -> &'static str {
        "memory-test"
    }
    fn namespace(&self) -> CoreResult<String> {
        Ok("memory-test".into())
    }
    fn url_for(&self, key: &str) -> String {
        format!("/assets/{key}")
    }
    async fn put(&self, key: &str, bytes: Vec<u8>, mime: &str) -> CoreResult<AssetRef> {
        if let Some(barrier) = &self.put_barrier {
            barrier.entered.notify_one();
            barrier.release.notified().await;
        }
        self.objects.lock().unwrap().insert(key.into(), bytes.clone());
        if self.fail_put {
            return Err(CoreError::internal("injected PUT failure after writing"));
        }
        Ok(AssetRef {
            key: key.into(),
            url: self.url_for(key),
            mime: mime.into(),
            bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        })
    }
    async fn get(&self, key: &str) -> CoreResult<Option<StoredObject>> {
        Ok(self.objects.lock().unwrap().get(key).map(|b| StoredObject { bytes: b.clone(), mime: "image/png".into() }))
    }
    async fn exists(&self, key: &str) -> CoreResult<bool> {
        Ok(self.objects.lock().unwrap().contains_key(key))
    }
    async fn delete(&self, key: &str) -> CoreResult<()> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
}

async fn service() -> (ContentService, Arc<dyn Repository>, Arc<MemoryStore>) {
    let repo: Arc<dyn Repository> = Arc::new(SqliteRepository::in_memory().await.unwrap());
    repo.upsert_tenant(&memoswish_core::repo::TenantRecord {
        id: "local".into(),
        name: "Local test".into(),
        plan: "self_hosted".into(),
        created_at: memoswish_protocol::examples::sample_deck().created_at,
    })
    .await
    .unwrap();
    repo.insert_user(&memoswish_core::repo::UserRecord {
        id: "usr_local".into(),
        tenant_id: "local".into(),
        email: "local@example.com".into(),
        display_name: "Owner".into(),
        password_hash: String::new(),
        role: Role::Owner,
        created_at: chrono::Utc::now(),
    })
    .await
    .unwrap();
    let store = Arc::new(MemoryStore::default());
    (ContentService::new(repo.clone()).with_import_store(store.clone()), repo, store)
}

fn text(face: &memoswish_protocol::CardFace) -> String {
    face.blocks.iter().filter_map(ContentBlock::speakable_text).collect::<Vec<_>>().join(" ")
}

#[tokio::test]
async fn apkg_basic_and_reversed_roundtrip() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, repo, _) = service().await;
    let p = Principal::local_owner("test");
    let bytes = support::basic().await;
    let prepared = svc.prepare_apkg(&p, bytes, ApkgOptions::default()).await.unwrap();
    assert_eq!(prepared.cards.len(), 1);
    assert!(text(&prepared.cards[0].front).contains("Question"));
    assert!(text(&prepared.cards[0].back).contains("Answer"));
    assert_eq!(prepared.cards[0].tags, ["biology::cells", "test"]);
    assert_eq!(prepared.cards[0].attributes["anki"]["note_id"], "100");
    let report = svc.commit_apkg(&p, prepared).await.unwrap();
    assert_eq!(report.deck.title, "Biology::Cells");
    assert_eq!(report.deck.language, "und");
    assert_eq!(repo.get_deck(&p.tenant_id, &report.deck.id).await.unwrap().unwrap().card_count, 1);
    let bytes = support::zip(vec![
        ("collection.anki21", support::database("reversed", "Front\x1fBack", &[0, 1]).await),
        ("media", b"{}".to_vec()),
    ]);
    let prepared = svc
        .prepare_apkg(&p, bytes, ApkgOptions { title: Some("Reverse".into()), language: Some("en".into()) })
        .await
        .unwrap();
    assert_eq!(prepared.card_count(), 2);
    assert_eq!(text(&prepared.cards[1].front), "Back");
    assert_eq!(text(&prepared.cards[1].back), "Front");
    assert_eq!(prepared.report.deck.title, "Reverse");
    assert_eq!(prepared.cards[1].language, "en");
}

#[tokio::test]
async fn apkg_cloze_hints_nesting_multiple_and_repeated_indices() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, _, _) = service().await;
    let p = Principal::local_owner("test");
    let db = support::database(
        "cloze",
        "{{c1::Paris::city}} and {{c1::France}} / {{c2,3::outer {{c3::inner}}}}\x1fExtra",
        &[0, 1, 2],
    )
    .await;
    let prepared = svc
        .prepare_apkg(
            &p,
            support::zip(vec![("collection.anki2", db), ("media", b"{}".to_vec())]),
            ApkgOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(prepared.cards.len(), 3);
    assert_eq!(prepared.cards[0].template, "cloze");
    assert!(text(&prepared.cards[0].front).contains("city"));
    assert!(!text(&prepared.cards[0].front).contains("Paris"));
    assert!(text(&prepared.cards[0].front).contains("outer inner"));
    assert!(text(&prepared.cards[0].back).contains("Paris"));
    assert!(text(&prepared.cards[0].back).contains("Extra"));
    assert!(!text(&prepared.cards[1].front).contains("outer"));
    assert!(convert::cloze("{{c1::bad", 1, false, 0).is_err());
}

#[tokio::test]
async fn apkg_cloze_preserves_mathjax_inside_and_outside_deletions() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, _, _) = service().await;
    let p = Principal::local_owner("test");
    for (field, question, answer, front_math, back_math) in [
        (r"{{c1::Paris}} \(a^{b^{c}}\)", r"[...] \(a^{b^{c}}\)", r"Paris \(a^{b^{c}}\)", 1, 1),
        (r"{{c1::\(a^{b^{c}}\)}}", "[...]", r"\(a^{b^{c}}\)", 0, 1),
        (r"{{c1::\[a^{b^{c}}\]::formula}}", "[formula]", r"\[a^{b^{c}}\]", 0, 1),
        (r"\[x^{y^{z}} = {{c1::a}}\]", r"\[x^{y^{z}} = [...]\]", r"\[x^{y^{z}} = a\]", 1, 1),
        (r"\[x = {{c1::a^{b}}}\]", r"\[x = [...]}\]", r"\[x = a^{b}\]", 1, 1),
        (r"\({{c2::x + {{c1::y}}}}\)", r"\(x + [...]\)", r"\(x + y\)", 1, 1),
        (
            r"{{c1::\(a^{b^{c}}\) + \(d^{e^{f}}\)}} }} {{literal}}",
            "[...] }} {{literal}}",
            r"\(a^{b^{c}}\) + \(d^{e^{f}}\) }} {{literal}}",
            0,
            2,
        ),
        (r"{{c1::\(unclosed}}", "[...]", r"\(unclosed", 0, 0),
        (r"{{c1::\( a \]}} b", "[...] b", r"\( a \] b", 0, 0),
        (r"{{c1::\( a {{c2::b}} \frac{1}{\sqrt{2}} \)}} c", "[...] c", r"\( a b \frac{1}{\sqrt{2}} \) c", 0, 1),
    ] {
        assert_eq!(convert::cloze(field, 1, false, 0).unwrap(), (question.into(), true));
        assert_eq!(convert::cloze(field, 1, true, 0).unwrap(), (answer.into(), true));
        let db = support::database("cloze", &format!("{field}\x1fExtra"), &[0]).await;
        let prepared = svc
            .prepare_apkg(
                &p,
                support::zip(vec![("collection.anki2", db), ("media", b"{}".to_vec())]),
                ApkgOptions::default(),
            )
            .await
            .unwrap();
        let card = &prepared.cards[0];
        for (face, expected) in [(&card.front, front_math), (&card.back, back_math)] {
            assert_eq!(face.blocks.iter().filter(|b| matches!(b, ContentBlock::Math { .. })).count(), expected);
        }
        assert!(!text(&card.front).contains("Paris"));
    }
}

#[tokio::test]
async fn apkg_html_media_audio_math_and_tenant_isolation() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, repo, store) = service().await;
    let p = Principal::local_owner("test");
    let field = r#"<div>Fish &amp; chips<br>&lt;b&gt;literal&lt;/b&gt;<script>evil()</script><style>bad</style><img src="图%20片.png"><img src="图 片.png">[sound:voice.mp3] \(x^2\) \[y\] [$]z[/$] [$$]w[/$$] [latex]$a$[/latex]</div>"#;
    let db = support::database("basic", &format!("{field}\x1fBack"), &[0]).await;
    let bytes = support::zip(vec![
        ("collection.anki2", db),
        ("media", r#"{"7":"图 片.png","9":"voice.mp3"}"#.as_bytes().to_vec()),
        ("7", b"\x89PNG\r\n\x1a\nimage".to_vec()),
        ("9", b"audio".to_vec()),
    ]);
    let prepared = svc.prepare_apkg(&p, bytes.clone(), ApkgOptions::default()).await.unwrap();
    assert_eq!(prepared.report.media_imported, 1);
    assert_eq!(prepared.report.audio_omitted, 1);
    let card = &prepared.cards[0];
    let txt = text(&card.front);
    assert!(txt.contains("Fish & chips"));
    assert!(!txt.contains("evil()"));
    assert!(!txt.contains("voice.mp3"));
    assert!(!txt.contains("<b>"));
    assert_eq!(card.front.blocks.iter().filter(|b| matches!(b, ContentBlock::Math { .. })).count(), 5);
    let report = svc.commit_apkg(&p, prepared).await.unwrap();
    let cards = repo.list_cards(&p.tenant_id, Some(&report.deck.id), 500, 0).await.unwrap();
    let asset = cards[0].front.blocks.iter().find_map(ContentBlock::asset).unwrap();
    assert!(asset.key.starts_with("tenants/local/uploads/"));
    assert!(asset.url.is_empty());
    assert!(repo.asset_delivery(&p, &asset.key, memoswish_core::Permission::ContentRead).await.unwrap().is_some());
    assert!(store.exists(&asset.key).await.unwrap());
    let mut other = p.clone();
    other.tenant_id = "other".into();
    assert!(repo.get_deck(&other.tenant_id, &report.deck.id).await.unwrap().is_none());
    let prepared = svc.prepare_apkg(&other, bytes, ApkgOptions::default()).await.unwrap();
    assert!(
        prepared.cards[0].front.blocks.iter().find_map(ContentBlock::asset).unwrap().key.starts_with("tenants/other/")
    );
    assert!(svc.commit_apkg(&p, prepared).await.is_err());
}

#[tokio::test]
async fn apkg_permissions_invalid_content_and_bounds() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, repo, _) = service().await;
    let p = Principal::local_owner("test");
    let mut learner = p.clone();
    learner.role = Role::Learner;
    assert!(svc.prepare_apkg(&learner, support::basic().await, ApkgOptions::default()).await.is_err());
    let mut scoped = p.clone();
    scoped.scopes = Some(vec!["content:write".into()]);
    let prepared = svc.prepare_apkg(&scoped, support::basic().await, ApkgOptions::default()).await.unwrap();
    assert!(svc.commit_apkg(&scoped, prepared).await.is_ok());
    let db = support::database("basic", "<img src='x.gif'>\x1fBack", &[0]).await;
    let bytes = support::zip(vec![
        ("collection.anki2", db),
        ("media", br#"{"0":"x.gif"}"#.to_vec()),
        ("0", b"GIF89aimage".to_vec()),
    ]);
    let err = svc.prepare_apkg(&scoped, bytes, ApkgOptions::default()).await.err().unwrap();
    assert_eq!(err.code(), "forbidden");
    for (kind, fields, ords) in [
        ("basic", "[sound:only.mp3]\x1fBack", vec![0]),
        ("conditional", "Front\x1fBack", vec![0]),
        ("cloze", "{{c1::broken\x1fBack", vec![0]),
        ("cloze", "{{c1::answer}}\x1fBack", vec![2]),
        ("basic", "bad count", vec![0]),
    ] {
        let bytes = support::zip(vec![
            ("collection.anki2", support::database(kind, fields, &ords).await),
            ("media", b"{}".to_vec()),
        ]);
        assert!(svc.prepare_apkg(&p, bytes, ApkgOptions::default()).await.is_err());
    }
    let over_field = format!("{}\x1fBack", "x".repeat(ApkgLimits::FIELD + 1));
    let db = support::database("basic", &over_field, &[0]).await;
    assert!(
        svc.prepare_apkg(
            &p,
            support::zip(vec![("collection.anki2", db), ("media", b"{}".to_vec())]),
            ApkgOptions::default()
        )
        .await
        .is_err()
    );
    let db = support::database("basic", "Front\x1fBack", &vec![0; 501]).await;
    assert!(
        svc.prepare_apkg(
            &p,
            support::zip(vec![("collection.anki2", db), ("media", b"{}".to_vec())]),
            ApkgOptions::default()
        )
        .await
        .is_err()
    );
    assert_eq!(repo.list_decks(&p.tenant_id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn apkg_rollback_and_failed_put_cleanup_only_owned_assets() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, repo, store) = service().await;
    let p = Principal::local_owner("test");
    let bytes = support::zip(vec![
        ("collection.anki2", support::database("reversed", "<img src='x.png'>\x1fBack", &[0, 1]).await),
        ("media", br#"{"0":"x.png"}"#.to_vec()),
        ("0", b"\x89PNG\r\n\x1a\nimage".to_vec()),
    ]);
    let prepared = svc.prepare_apkg(&p, bytes.clone(), ApkgOptions::default()).await.unwrap();
    let deck_id = prepared.report.deck.id.clone();
    let first_id = prepared.cards[0].id.clone();
    let collision_deck = svc
        .create_deck(
            &p,
            crate::NewDeck {
                title: "Existing".into(),
                description: String::new(),
                language: "en-US".into(),
                tags: vec![],
            },
        )
        .await
        .unwrap();
    let mut collision = prepared.cards[1].clone();
    collision.deck_id = collision_deck.id;
    repo.insert_card(&p.tenant_id, &collision).await.unwrap();
    store.objects.lock().unwrap().insert("tenants/local/keep.png".into(), vec![1]);
    assert!(svc.commit_apkg(&p, prepared).await.is_err());
    assert!(repo.get_deck(&p.tenant_id, &deck_id).await.unwrap().is_none());
    assert!(repo.get_card(&p.tenant_id, &first_id).await.unwrap().is_none());
    assert_eq!(store.objects.lock().unwrap().len(), 2);
    assert_eq!(repo.unresolved_assets(None, 100).await.unwrap().len(), 1);
    let failing = Arc::new(MemoryStore { fail_put: true, ..Default::default() });
    let svc = svc.with_import_store(failing.clone());
    let prepared = svc.prepare_apkg(&p, bytes, ApkgOptions::default()).await.unwrap();
    let id = prepared.report.deck.id.clone();
    assert!(svc.commit_apkg(&p, prepared).await.is_err());
    assert!(repo.get_deck(&p.tenant_id, &id).await.unwrap().is_none());
    assert_eq!(failing.objects.lock().unwrap().len(), 1);
    assert!(repo.unresolved_assets(None, 100).await.unwrap().iter().any(|(_, i)| i.published_attempt.is_none()));
}

#[tokio::test]
async fn apkg_legacy_selection_and_modern_detection() {
    let valid = support::database("basic", "Front\x1fBack", &[0]).await;
    let package = archive::read(support::zip(vec![
        ("collection.anki2", b"dummy".to_vec()),
        ("collection.anki21", valid.clone()),
        ("media", b"{}".to_vec()),
    ]))
    .unwrap();
    assert_eq!(package.database, valid);
    let package = archive::read(support::zip(vec![
        ("collection.anki21", valid.clone()),
        ("media", b"{}".to_vec()),
        ("meta", vec![8, 2]),
    ]))
    .unwrap();
    assert_eq!(package.database, valid);
    for extra in [vec![("collection.anki21b", vec![1])], vec![("meta", vec![8, 3])], vec![("meta", vec![8, 99])]] {
        let mut entries = vec![("collection.anki2", valid.clone()), ("media", b"{}".to_vec())];
        entries.extend(extra);
        assert!(
            archive::read(support::zip(entries)).err().unwrap().to_string().contains("Support older Anki versions")
        );
    }
    for meta in [vec![8, 2], vec![8], vec![]] {
        assert!(
            archive::read(support::zip(vec![
                ("collection.anki2", valid.clone()),
                ("media", b"{}".to_vec()),
                ("meta", meta)
            ]))
            .is_err()
        );
    }
}

#[test]
fn apkg_rejects_cloaked_local_headers_for_every_entry() {
    use std::io::Cursor;
    use zip::ZipArchive;

    let bytes = support::zip(vec![
        ("collection.anki2", b"database payload".to_vec()),
        ("media", br#"{"0":"picture.png"}"#.to_vec()),
        ("0", b"media payload".to_vec()),
    ]);
    let package = archive::read(bytes.clone()).unwrap();
    assert_eq!(package.database, b"database payload");
    assert_eq!(package.media["picture.png"], b"media payload");

    for i in 0..3 {
        let mut zip = ZipArchive::new(Cursor::new(&bytes)).unwrap();
        let entry = zip.by_index(i).unwrap();
        let local = entry.header_start() as usize;
        let central_name = entry.name().unwrap().into_owned();
        // 只改本地头，中央目录及载荷保持原样；覆盖数据库、映射和媒体条目。
        for (field, offset) in
            [("filename", 30), ("compressed size", 18), ("uncompressed size", 22), ("compression method", 8)]
        {
            let mut cloaked = bytes.clone();
            cloaked[local + offset] ^= 1;
            let mut central = ZipArchive::new(Cursor::new(&cloaked)).unwrap();
            assert_eq!(central.by_index(i).unwrap().name().unwrap(), central_name);
            let error = archive::read(cloaked).err().unwrap().to_string();
            assert!(error.contains("header inconsistency") && error.contains(field), "entry {i}, {field}: {error}");
        }
    }
}

#[test]
fn apkg_zip_security_and_size_limits() {
    assert!(archive::read(b"not a zip".to_vec()).is_err());
    assert!(archive::read(vec![0; ApkgLimits::ARCHIVE + 1]).is_err());
    for name in ["../escape", "/absolute", "C:drive", "back\\slash", "a/b", ".."] {
        assert!(archive::read(support::zip(vec![(name, vec![1])])).is_err());
    }
    for (name, size) in [
        ("0", ApkgLimits::MEDIA + 1),
        ("collection.anki2", ApkgLimits::DATABASE + 1),
        ("media", ApkgLimits::MANIFEST + 1),
        ("meta", 4097),
    ] {
        assert!(archive::read(support::zip(vec![(name, vec![0; size])])).is_err());
    }
    let names: Vec<_> = (0..4097).map(|i| i.to_string()).collect();
    assert!(archive::read(support::zip(names.iter().map(|n| (n.as_str(), vec![])).collect())).is_err());
    let entries: Vec<_> = (0..17).map(|i| (names[i].as_str(), vec![0; ApkgLimits::MEDIA])).collect();
    assert!(archive::read(support::zip(entries)).is_err());
}

#[tokio::test]
async fn apkg_rejects_sqlite_sidecar_entries() {
    let db = support::database("basic", "Front\x1fBack", &[0]).await;
    // WAL 声明 512 字节页，与集合页尺寸不同；必须在交给 SQLite 之前拒绝。
    let mut wal = vec![0; 32 + 24 + 512];
    wal[..4].copy_from_slice(&0x377f0682_u32.to_be_bytes());
    wal[4..8].copy_from_slice(&3_007_000_u32.to_be_bytes());
    wal[8..12].copy_from_slice(&512_u32.to_be_bytes());
    assert_ne!(&db[16..18], &512_u16.to_be_bytes());
    for collection in ["collection.anki2", "collection.anki21"] {
        for suffix in ["-wal", "-shm", "-journal", "-WAL"] {
            let name = format!("{collection}{suffix}");
            let result = archive::read(support::zip(vec![
                (collection, db.clone()),
                ("media", b"{}".to_vec()),
                (&name, wal.clone()),
            ]));
            assert!(result.err().unwrap().to_string().contains("SQLite sidecar"));
        }
    }
}

#[tokio::test]
async fn apkg_collection_is_private_read_only_memory_without_wal() {
    let db = support::database("basic", "Front\x1fBack", &[0]).await;
    let mut conn = collection::open_read_only(&db).await.unwrap();
    let databases = sqlx::query("PRAGMA database_list").fetch_all(&mut conn).await.unwrap();
    assert_eq!(databases.len(), 1);
    assert_eq!(sqlx::Row::get::<String, _>(&databases[0], "file"), "");
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode").fetch_one(&mut conn).await.unwrap();
    assert_eq!(journal, "memory");
    let query_only: i64 = sqlx::query_scalar("PRAGMA query_only").fetch_one(&mut conn).await.unwrap();
    assert_eq!(query_only, 1);
    // 即使关闭查询保护，反序列化数据库仍由 SQLite 的只读标志保护。
    sqlx::query("PRAGMA query_only = OFF").execute(&mut conn).await.unwrap();
    for statement in ["DELETE FROM notes", "CREATE TABLE injected(value)"] {
        let error = sqlx::query(statement).execute(&mut conn).await.unwrap_err();
        assert_eq!(error.as_database_error().unwrap().code().as_deref(), Some("8"));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes").fetch_one(&mut conn).await.unwrap();
    assert_eq!(count, 1);
    let mut wal_db = db.clone();
    wal_db[18] = 2;
    assert!(collection::open_read_only(&wal_db).await.err().unwrap().to_string().contains("WAL"));
    wal_db[18] = 1;
    wal_db[19] = 2;
    assert!(collection::open_read_only(&wal_db).await.err().unwrap().to_string().contains("WAL"));
}

#[tokio::test]
async fn apkg_media_map_and_database_validation() {
    let db = support::database("basic", "Front\x1fBack", &[0]).await;
    for manifest in
        [br#"{"0":"x","0":"y"}"#.as_slice(), br#"{"0":"x","1":"x"}"#, br#"{"../x":"x"}"#, br#"{"0":"missing"}"#, b"bad"]
    {
        assert!(
            archive::read(support::zip(vec![("collection.anki2", db.clone()), ("media", manifest.to_vec())])).is_err()
        );
    }
    assert!(collection::read(b"bad").await.is_err());
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    sqlx::raw_sql(
        "CREATE VIEW col AS SELECT '{}' AS models, '{}' AS decks; CREATE TABLE notes(id); CREATE TABLE cards(id);",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    let db = conn.serialize(None).await.unwrap();
    assert!(collection::read(&db).await.is_err());
}

#[test]
fn apkg_rejects_duplicate_symlink_crc_and_truncated_archives() {
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    let bytes = support::zip(vec![("0", vec![1]), ("1", vec![2])]);
    let mut duplicate = bytes.clone();
    // 将第二条中央目录与本地记录的名字改为第一条，保留长度和全部校验信息。
    for i in 0..duplicate.len() - 46 {
        if &duplicate[i..i + 4] == b"PK\x01\x02" && duplicate[i + 46] == b'1' {
            duplicate[i + 46] = b'0';
        }
        if &duplicate[i..i + 4] == b"PK\x03\x04" && duplicate[i + 30] == b'1' {
            duplicate[i + 30] = b'0';
        }
    }
    assert!(archive::read(duplicate).err().unwrap().to_string().contains("duplicate"));
    for cut in [1, 10, bytes.len() / 2] {
        assert!(archive::read(bytes[..bytes.len() - cut].to_vec()).is_err());
    }
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.add_symlink("0", "../escape", SimpleFileOptions::default()).unwrap();
    assert!(archive::read(zip.finish().unwrap().into_inner()).is_err());
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("collection.anki2", SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored))
        .unwrap();
    zip.write_all(b"unique-CRC-test-payload").unwrap();
    zip.start_file("media", SimpleFileOptions::default()).unwrap();
    zip.write_all(b"{}").unwrap();
    let mut bytes = zip.finish().unwrap().into_inner();
    let offset = bytes.windows(b"unique-CRC-test-payload".len()).position(|b| b == b"unique-CRC-test-payload").unwrap();
    bytes[offset] ^= 1;
    assert!(archive::read(bytes).is_err());
}

#[tokio::test]
async fn apkg_dom_depth_missing_media_math_fallback_and_output_limits() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, _, _) = service().await;
    let p = Principal::local_owner("test");
    let db = support::database(
        "basic",
        "Question<img src='missing.png'> [latex]\\documentclass{article}x[/latex] \\(unclosed\x1fAnswer",
        &[0],
    )
    .await;
    let prepared = svc
        .prepare_apkg(
            &p,
            support::zip(vec![("collection.anki2", db), ("media", b"{}".to_vec())]),
            ApkgOptions::default(),
        )
        .await
        .unwrap();
    assert!(prepared.report.warnings.len() >= 3);
    assert!(
        prepared.cards[0]
            .front
            .blocks
            .iter()
            .any(|b| matches!(b,ContentBlock::Code { language, .. } if language == "latex"))
    );
    drop(prepared);
    let mut converter = convert::Converter {
        media: BTreeMap::new(),
        uploads: BTreeMap::new(),
        warnings: Warnings::default(),
        audio: BTreeSet::new(),
        prefix: String::new(),
        ..Default::default()
    };
    assert!(converter.face(&format!("{}text{}", "<div>".repeat(70), "</div>".repeat(70)), "fallback", true).is_err());
    assert!(converter.face(&"x".repeat(8000 * 33), "fallback", true).is_err());
    let face = converter.face(&"x".repeat(16001), "fallback", true).unwrap();
    assert_eq!(face.blocks.len(), 3);
    assert_eq!(face.title.chars().count(), 200);
    let face = converter.face(&format!("{}*", "x".repeat(7999)), "fallback", true).unwrap();
    assert_eq!(face.blocks.len(), 2);
    assert_eq!(face.blocks[1], ContentBlock::text("\\*"));
    assert_eq!(converter.face("&lt;b&gt;literal&lt;/b&gt;", "fallback", true).unwrap().title, "<b>literal</b>");
    let mut warnings = Warnings::default();
    for _ in 0..101 {
        warnings.push("w".repeat(2000));
    }
    assert_eq!(warnings.messages.len(), 100);
    assert_eq!(warnings.messages[0].chars().count(), 1024);
    assert!(warnings.truncated);
}

#[tokio::test]
async fn apkg_concurrent_import_budget_and_detached_commit() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, repo, _) = service().await;
    let barrier = Arc::new(PutBarrier::default());
    let store = Arc::new(MemoryStore { put_barrier: Some(barrier.clone()), ..Default::default() });
    let svc = svc.with_import_store(store.clone());
    let p = Principal::local_owner("test");
    let bytes = support::basic().await;
    let media_bytes = support::zip(vec![
        ("collection.anki2", support::database("basic", "Question<img src='x.png'>\x1fAnswer", &[0]).await),
        ("media", br#"{"0":"x.png"}"#.to_vec()),
        ("0", b"\x89PNG\r\n\x1a\nimage".to_vec()),
    ]);
    let first = svc.prepare_apkg(&p, media_bytes, ApkgOptions::default()).await.unwrap();
    assert_eq!(first.report.media_imported, 1);
    let asset_key = first.cards[0].front.blocks.iter().find_map(ContentBlock::asset).unwrap().key.clone();
    let second = svc.prepare_apkg(&p, bytes.clone(), ApkgOptions::default()).await.unwrap();
    let error = svc.prepare_apkg(&p, bytes, ApkgOptions::default()).await.err().unwrap();
    assert_eq!(error.code(), "quota_exceeded");
    let id = first.report.deck.id.clone();
    // 等真实提交进入上传屏障后丢弃等待者，确保取消发生在提交完成之前。
    {
        let commit = svc.commit_apkg(&p, first);
        tokio::pin!(commit);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::select! {
                result = &mut commit => panic!("commit completed before release: {result:?}"),
                _ = barrier.entered.notified() => {}
            }
        })
        .await
        .expect("commit did not enter the upload barrier");
    }
    assert!(repo.get_deck(&p.tenant_id, &id).await.unwrap().is_none());
    assert!(!store.exists(&asset_key).await.unwrap());
    assert_eq!(IMPORTS.available_permits(), 0, "cancelled waiter must not release the active commit permit");
    drop(second);
    assert_eq!(IMPORTS.available_permits(), 1);
    barrier.release.notify_one();
    // 两个许可均可重新取得，证明后台提交已结束并归还准入预算。
    let recovered = tokio::time::timeout(std::time::Duration::from_secs(5), IMPORTS.acquire_many(2))
        .await
        .expect("detached commit did not return its permit")
        .unwrap();
    drop(recovered);
    assert_eq!(IMPORTS.available_permits(), 2);
    let deck = repo.get_deck(&p.tenant_id, &id).await.unwrap().expect("detached import did not commit");
    assert_eq!(deck.card_count, 1);
    let cards = repo.list_cards(&p.tenant_id, Some(&id), 500, 0).await.unwrap();
    assert_eq!(cards.len(), 1);
    let published = &cards[0].front.blocks.iter().find_map(ContentBlock::asset).unwrap().key;
    assert_ne!(published, &asset_key);
    assert!(published.starts_with("tenants/local/uploads/"));
    assert!(store.exists(published).await.unwrap());
    assert!(!store.exists(&asset_key).await.unwrap());
}

#[tokio::test]
async fn apkg_rejects_generated_database_columns() {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    sqlx::raw_sql("CREATE TABLE col (models TEXT, decks TEXT);
        CREATE TABLE notes (id INTEGER, mid INTEGER, guid TEXT, tags TEXT, flds TEXT GENERATED ALWAYS AS (printf('%1000000000s','x')) VIRTUAL);
        CREATE TABLE cards (id INTEGER, nid INTEGER, did INTEGER, odid INTEGER, ord INTEGER);")
        .execute(&mut conn).await.unwrap();
    let bytes = conn.serialize(None).await.unwrap();
    let error = collection::read(&bytes).await.err().unwrap();
    assert!(error.to_string().contains("generated"));
}

#[tokio::test]
async fn apkg_rejects_shadowed_pragma_views_before_oversized_printf_runs() {
    for definition in [
        "DROP TABLE col; CREATE VIEW col AS SELECT printf('%2000000s','x') AS models, '{}' AS decks;",
        "DROP TABLE notes; CREATE VIEW notes AS SELECT 100 AS id, 10 AS mid, 'guid' AS guid,
         '' AS tags, printf('%2000000s','x') AS flds;",
        "DROP TABLE cards; CREATE VIEW cards AS SELECT printf('%2000000s','x') AS id,
         100 AS nid, 1 AS did, 0 AS odid, 0 AS ord;",
    ] {
        let db = support::database("basic", "Front\x1fBack", &[0]).await;
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        conn.deserialize(None, sqlx::sqlite::SqliteOwnedBuf::try_from(db.as_slice()).unwrap(), false).await.unwrap();
        sqlx::raw_sql(
            "CREATE TABLE pragma_table_list (schema TEXT, name TEXT, type TEXT);
             INSERT INTO pragma_table_list VALUES ('main','col','table'), ('main','notes','table'), ('main','cards','table');",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        sqlx::raw_sql(definition).execute(&mut conn).await.unwrap();
        let bytes = conn.serialize(None).await.unwrap();
        let error = collection::read(&bytes).await.err().unwrap();
        assert!(error.to_string().contains("ordinary col, notes and cards tables"), "{error}");
    }
}

#[tokio::test]
async fn apkg_rejects_virtual_tables_and_collection_triggers() {
    for definition in [
        "DROP TABLE col; CREATE VIRTUAL TABLE col USING fts5(models, decks);",
        "CREATE TRIGGER col_trigger AFTER UPDATE ON col BEGIN SELECT 1; END;",
        "CREATE TRIGGER notes_trigger AFTER INSERT ON notes BEGIN SELECT 1; END;",
        "CREATE TRIGGER cards_trigger AFTER DELETE ON cards BEGIN SELECT 1; END;",
    ] {
        let db = support::database("basic", "Front\x1fBack", &[0]).await;
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        conn.deserialize(None, sqlx::sqlite::SqliteOwnedBuf::try_from(db.as_slice()).unwrap(), false).await.unwrap();
        sqlx::raw_sql(definition).execute(&mut conn).await.unwrap();
        let bytes = conn.serialize(None).await.unwrap();
        let error = collection::read(&bytes).await.err().unwrap();
        assert!(error.to_string().contains(if definition.starts_with("DROP") { "ordinary" } else { "triggers" }));
    }
}

#[tokio::test]
async fn apkg_sql_guards_reject_oversized_stored_values_and_invalid_types() {
    for (update, value, message) in [
        ("UPDATE col SET models = ?", format!("\0{}", "界".repeat(ApkgLimits::MANIFEST / 3)), "metadata must be text"),
        (
            "UPDATE notes SET guid = ?",
            format!("\0{}", "x".repeat(ApkgLimits::FIELD)),
            "note column type or byte length",
        ),
        ("UPDATE notes SET tags = ?", "界".repeat(ApkgLimits::FIELD / 3 + 1), "note column type or byte length"),
        ("UPDATE notes SET mid = ?", "x".repeat(ApkgLimits::FIELD + 1), "note column type or byte length"),
        ("UPDATE cards SET ord = ?", "x".repeat(ApkgLimits::FIELD + 1), "card columns must contain integers"),
    ] {
        let db = support::database("basic", "Front\x1fBack", &[0]).await;
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        conn.deserialize(None, sqlx::sqlite::SqliteOwnedBuf::try_from(db.as_slice()).unwrap(), false).await.unwrap();
        sqlx::query(update).bind(value).execute(&mut conn).await.unwrap();
        let bytes = conn.serialize(None).await.unwrap();
        let error = collection::read(&bytes).await.err().unwrap();
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[test]
fn apkg_rejects_adversarial_html_before_tree_construction() {
    let mut converter = convert::Converter {
        media: BTreeMap::new(),
        uploads: BTreeMap::new(),
        warnings: Warnings::default(),
        audio: BTreeSet::new(),
        prefix: String::new(),
        ..Default::default()
    };
    for html in ["<div>".repeat(50_000), "<b><i><div/>".repeat(10_000), "<!--<".repeat(10_000)] {
        assert!(html.len() <= ApkgLimits::FIELD);
        let start = std::time::Instant::now();
        let error = converter.face(&html, "fallback", true).unwrap_err();
        let elapsed = start.elapsed();
        assert!(error.to_string().contains("pre-parse"));
        assert!(elapsed < std::time::Duration::from_millis(250), "HTML rejection took {elapsed:?}");
    }
    let html = "<div>".repeat(ApkgLimits::HTML_MARKERS);
    let start = std::time::Instant::now();
    let error = converter.face(&html, "fallback", true).unwrap_err();
    let elapsed = start.elapsed();
    assert!(error.to_string().contains("node or nesting budget"));
    assert!(elapsed < std::time::Duration::from_millis(250), "Bounded HTML parsing took {elapsed:?}");
    let face =
        converter.face(&format!("Question{}", "<br>".repeat(ApkgLimits::HTML_MARKERS)), "fallback", true).unwrap();
    assert_eq!(face.title, "Question");
    let error = converter.face(&"<br>".repeat(ApkgLimits::HTML_MARKERS + 1), "fallback", true).unwrap_err();
    assert!(error.to_string().contains("pre-parse"));
}

#[test]
fn apkg_html_attribute_and_byte_budget_boundaries() {
    let check = convert::check_html_budget;
    for attribute in [" disabled", " a = 'value'", " a=unquoted", " a=\" > = many spaces \"", " a=''b=''", " a/b/c"] {
        assert!(check(&format!("<p{}>Question</p>", attribute.repeat(10))).is_ok(), "{attribute}");
    }
    for attributes in [" a".repeat(64), " a=''".repeat(64)] {
        assert!(check(&format!("<p{attributes}>text")).is_ok());
        assert!(check(&format!("<p{attributes} b>text")).is_err());
    }
    // 无空格属性、斜杠、伪引号和等号开头的畸形属性均不能绕过计数。
    for attributes in [" a=''".repeat(65), " a/b".repeat(33), " /=' x".repeat(65), " a=x' b".repeat(65)] {
        assert!(check(&format!("<p{attributes}>text")).is_err(), "{attributes}");
    }
    assert!(check(&format!("<p {}>text", "a=''".repeat(65))).is_err());
    let equals = format!("<p a{}>", "=".repeat(64));
    assert!(check(&equals).is_ok());
    assert!(check(&equals.replacen('=', "==", 1)).is_err());
    assert!(check(&equals.repeat(32)).is_ok());
    assert!(check(&equals.repeat(33)).is_err());
    assert!(check(&format!("<p a='{}'>text", " > = ".repeat(100))).is_ok());
    let tag = format!("<p{}>", " a".repeat(64));
    assert!(check(&tag.repeat(32)).is_ok());
    assert!(check(&tag.repeat(33)).is_err());
    let tag = format!("<p a='{}'>", "x".repeat(ApkgLimits::HTML_TAG - 8));
    assert_eq!(tag.len(), ApkgLimits::HTML_TAG);
    assert!(check(&tag).is_ok());
    assert!(check(&tag.replacen("x", "xx", 1)).is_err());
    assert!(check(&tag.repeat(8)).is_ok());
    assert!(check(&tag.repeat(9)).is_err());
    assert!(check(&"x".repeat(ApkgLimits::HTML_FACE)).is_ok());
    assert!(check(&"x".repeat(ApkgLimits::HTML_FACE + 1)).is_err());
    // 标签中的小于号即使位于引号或注释内也保守拒绝；实体仍可正常使用。
    assert!(check("<p a='<p a=hidden>'>text").is_err());
    assert!(check("<!-- <p> -->text").is_err());
    assert!(check("<p a='&lt; &quot; >'>text</p>").is_ok());
}

#[test]
fn apkg_rejects_attribute_floods_within_250ms() {
    let mut converter = convert::Converter {
        media: BTreeMap::new(),
        uploads: BTreeMap::new(),
        warnings: Warnings::default(),
        audio: BTreeSet::new(),
        prefix: String::new(),
        ..Default::default()
    };
    for count in [10_000, 35_000] {
        let unique = (0..count).map(|i| format!(" a{i:04x}")).collect::<String>();
        for (kind, attributes) in [("boolean", unique), ("valued", " a='x'".repeat(count))] {
            let html = format!("<p{attributes}>Question</p>");
            assert!(html.len() <= ApkgLimits::FIELD);
            let start = std::time::Instant::now();
            let error = converter.face(&html, "fallback", true).unwrap_err();
            let elapsed = start.elapsed();
            assert!(error.to_string().contains("pre-parse"));
            assert!(elapsed < std::time::Duration::from_millis(250), "Attribute rejection took {elapsed:?}");
            eprintln!("Rejected {count} {kind} attributes ({} bytes) in {elapsed:?}", html.len());
        }
    }
    // 预算内最大属性总数仍会进入实际解析器，验证正常路径的耗时和正文保留。
    let attributes = (0..64).map(|i| format!(" a{i}='' ")).collect::<String>();
    let html = format!("{}Question", format!("<p{attributes}>").repeat(32));
    let start = std::time::Instant::now();
    assert_eq!(converter.face(&html, "fallback", true).unwrap().title, "Question");
    let elapsed = start.elapsed();
    assert!(elapsed < std::time::Duration::from_millis(250), "Bounded attribute parsing took {elapsed:?}");
    eprintln!("Parsed 2048 bounded attributes in {elapsed:?}");
}

#[tokio::test]
async fn apkg_attribute_flood_rejection_preserves_repository_and_media() {
    let _guard = IMPORT_TEST.lock().await;
    let (svc, repo, store) = service().await;
    let p = Principal::local_owner("test");
    let html = format!("<p{}>Question</p>\x1fAnswer", " a='x'".repeat(35_000));
    let db = support::database("basic", &html, &[0]).await;
    let bytes = support::zip(vec![("collection.anki2", db), ("media", b"{}".to_vec())]);
    let start = std::time::Instant::now();
    let error = svc.prepare_apkg(&p, bytes, ApkgOptions::default()).await.err().unwrap();
    let elapsed = start.elapsed();
    assert!(error.to_string().contains("pre-parse"));
    assert!(elapsed < std::time::Duration::from_millis(250), "Import rejection took {elapsed:?}");
    assert!(repo.list_decks(&p.tenant_id).await.unwrap().is_empty());
    assert!(store.objects.lock().unwrap().is_empty());
    eprintln!("Rejected APKG with 35000 attributes in {elapsed:?}");
}
