//! 旧版 Anki 包的准备、验证和事务提交。

mod archive;
mod collection;
mod convert;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use memoswish_core::ids::{new_id, sha256_hex};
use memoswish_core::store::{ObjectStore, validate_key};
use memoswish_core::{CoreError, CoreResult, Permission, Principal};
use memoswish_protocol::{AssetRef, Card, Deck};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::ContentService;
use crate::validate::validate_card;

/// 所有入口共享的导入资源预算。
pub struct ApkgLimits;
impl ApkgLimits {
    pub const ARCHIVE: usize = 10 * 1024 * 1024;
    pub const ENTRIES: usize = 4096;
    pub const EXPANDED: usize = 128 * 1024 * 1024;
    pub const DATABASE: usize = 32 * 1024 * 1024;
    pub const MEDIA: usize = 8 * 1024 * 1024;
    pub const MANIFEST: usize = 1024 * 1024;
    pub const FIELD: usize = 256 * 1024;
    pub const RENDERED_FACE: usize = 1024 * 1024;
    pub const HTML_MARKERS: usize = 1024;
    pub const HTML_FACE: usize = 256 * 1024;
    pub const HTML_TAG: usize = 4096;
    pub const HTML_TAG_BYTES: usize = 32 * 1024;
    pub const HTML_TAG_ATTRIBUTES: usize = 64;
    pub const HTML_ATTRIBUTES: usize = 2048;
    pub const CARDS: usize = 500;
    pub const NORMALIZED: usize = 8 * 1024 * 1024;
    pub const WARNINGS: usize = 100;
}
static IMPORTS: Semaphore = Semaphore::const_new(2);

/// 可选的目标卡组标题与语言。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ApkgOptions {
    pub title: Option<String>,
    pub language: Option<String>,
}

/// 导入结果；音频按唯一源文件计数，警告采用有界列表。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkgReport {
    pub deck: Deck,
    pub notes_read: usize,
    pub cards_imported: usize,
    pub media_imported: usize,
    pub audio_omitted: usize,
    pub warnings: Vec<String>,
    pub warnings_truncated: bool,
}

#[derive(Default)]
struct Warnings {
    messages: Vec<String>,
    truncated: bool,
}
impl Warnings {
    fn push(&mut self, message: impl Into<String>) {
        if self.messages.len() < ApkgLimits::WARNINGS {
            let message = message.into();
            let shortened: String = message.chars().take(1024).collect();
            self.truncated |= shortened.len() < message.len();
            self.messages.push(shortened);
        } else {
            self.truncated = true;
        }
    }
}
struct MediaUpload {
    asset: AssetRef,
    bytes: Vec<u8>,
}

/// 已完成全部校验的租户绑定导入；内部数据不可由调用方构造或修改。
pub struct PreparedApkg {
    tenant_id: String,
    cards: Vec<Card>,
    uploads: BTreeMap<String, MediaUpload>,
    report: ApkgReport,
    provenance_expansion_bytes: usize,
    _permit: SemaphorePermit<'static>,
    _slot: memoswish_core::observability::Slot,
}
impl PreparedApkg {
    pub fn work(&self) -> CoreResult<memoswish_core::imports::ImportWork> {
        Ok(memoswish_core::imports::ImportWork {
            deck: self.report.deck.clone(),
            cards: self.cards.clone(),
            media: self
                .uploads
                .values()
                .map(|m| memoswish_core::imports::ImportMedia { asset: m.asset.clone(), bytes: m.bytes.clone() })
                .collect(),
            result: serde_json::to_value(&self.report).map_err(CoreError::internal)?,
            auto_tts: false,
            identity_expansion_bytes: 0,
            provenance_expansion_bytes: self.provenance_expansion_bytes,
        })
    }
    pub fn card_count(&self) -> u64 {
        self.cards.len() as u64
    }
    pub fn needs_media(&self) -> bool {
        !self.uploads.is_empty()
    }
}

fn invalid(error: impl std::fmt::Display) -> CoreError {
    CoreError::invalid(format!("invalid APKG: {error}"))
}

impl ContentService {
    /// 在受限工作线程中解析整包；在任何配额扣减或持久化前校验输出。
    pub async fn prepare_apkg(&self, p: &Principal, bytes: Vec<u8>, options: ApkgOptions) -> CoreResult<PreparedApkg> {
        p.require(Permission::ContentWrite)?;
        if bytes.len() > ApkgLimits::ARCHIVE {
            return Err(CoreError::invalid("APKG upload exceeds 10 MiB"));
        }
        use memoswish_core::observability::{AdmissionClass, AdmissionOutcome, Slot};
        let permit = IMPORTS.try_acquire().map_err(|_| {
            self.observer.admission(AdmissionClass::Import, AdmissionOutcome::Rejected);
            CoreError::QuotaExceeded("two APKG imports are already active; retry later".into())
        })?;
        self.observer.admission(AdmissionClass::Import, AdmissionOutcome::Accepted);
        let slot = Slot::new(self.observer.clone(), AdmissionClass::Import);
        let p = p.clone();
        // 工作任务持有许可，调用方取消不会提前释放阻塞工作占用的并发预算。
        tokio::spawn(async move {
            let budget = crate::processing::WorkBudget::default();
            let archive_budget = budget.clone();
            let hash = sha256_hex(&bytes);
            let package = tokio::task::spawn_blocking(move || archive_budget.scope(|| archive::read(bytes)))
                .await
                .map_err(CoreError::internal)??;
            let collection = collection::read_budget(&package.database, budget.clone()).await?;
            tokio::task::spawn_blocking(move || {
                budget.scope(|| prepare(p, options, package.media, collection, hash, (permit, slot), Utc::now()))
            })
            .await
            .map_err(CoreError::internal)?
        })
        .await
        .map_err(CoreError::internal)?
    }

    /// 上传本次导入的图片，再原子写入卡组与卡片；普通失败时清理本次对象。
    pub async fn commit_apkg(&self, p: &Principal, prepared: PreparedApkg) -> CoreResult<ApkgReport> {
        p.require(Permission::ContentWrite)?;
        if p.tenant_id != prepared.tenant_id {
            return Err(CoreError::Forbidden("prepared import belongs to another tenant".into()));
        }
        if prepared.needs_media() {
            p.require(Permission::MediaWrite)?;
        }
        let service = self.clone();
        let p = p.clone();
        tokio::spawn(async move {
            let work = prepared.work()?;
            let authority = memoswish_core::imports::ImportAuthority::capture(&p, None);
            let key = new_id();
            let fingerprint = crate::imports::fingerprint("apkg", &work, false)?;
            let op = service
                .repo
                .accept_import(&authority, &key, &fingerprint, &work, None, service.import_staging_limit)
                .await?;
            let result = crate::imports::import_result(service.drive_import(&p.tenant_id, &op.id).await?)?;
            drop(prepared);
            serde_json::from_value(result).map_err(CoreError::internal)
        })
        .await
        .map_err(CoreError::internal)?
    }

    /// 注入已有对象存储，仅用于导入图片。
    pub fn with_import_store(mut self, store: Arc<dyn ObjectStore>) -> Self {
        self.import_store = Some(store);
        self
    }
}

// 显式传入时间，便于按固定序列化长度验证旧字节边界。
fn prepare(
    p: Principal,
    options: ApkgOptions,
    media: BTreeMap<String, Vec<u8>>,
    collection: collection::Collection,
    hash: String,
    admission: (SemaphorePermit<'static>, memoswish_core::observability::Slot),
    now: DateTime<Utc>,
) -> CoreResult<PreparedApkg> {
    let (permit, slot) = admission;
    let import_id = new_id();
    let prefix = format!("{}imports/{import_id}/", p.asset_prefix());
    validate_key(&format!("{prefix}placeholder"))?;
    let mut converter = convert::Converter { media, prefix, ..Default::default() };
    let source_decks: BTreeSet<_> = collection.cards.iter().map(|c| if c.odid > 0 { c.odid } else { c.did }).collect();
    let default_title = if source_decks.len() == 1 {
        collection
            .decks
            .get(&source_decks.first().unwrap().to_string())
            .map(|d| d.name.as_str())
            .unwrap_or("Anki import")
    } else {
        "Anki import"
    };
    let title = options.title.as_deref().unwrap_or(default_title).trim();
    let language = options.language.as_deref().unwrap_or("und").trim();
    if title.is_empty() || title.chars().count() > 200 || language.is_empty() || language.len() > 64 {
        return Err(CoreError::invalid("APKG title must be 1 to 200 characters; language must be 1 to 64 bytes"));
    }
    let deck = Deck {
        revision: Some(1),
        id: new_id(),
        title: title.into(),
        description: "Imported from Anki".into(),
        language: language.into(),
        tags: vec![],
        card_count: collection.cards.len() as u32,
        created_at: now,
    };
    let mut cards = Vec::new();
    let mut normalized = 0usize;
    let mut provenance_expansion_bytes = 0;
    let mut used_notes = BTreeSet::new();
    for source in &collection.cards {
        crate::processing::checkpoint(1)?;
        let note = &collection.notes[&source.nid];
        used_notes.insert(note.id);
        let model = &collection.models[&note.mid.to_string()];
        let template_ord = if model.kind == 1 { 0 } else { source.ord };
        let template = model
            .tmpls
            .iter()
            .find(|t| t.ord == template_ord)
            .ok_or_else(|| CoreError::invalid("Anki card ordinal has no template"))?;
        let active = source.ord.checked_add(1).ok_or_else(|| CoreError::invalid("invalid Cloze ordinal"))?;
        let question = convert::render(&template.qfmt, model, note, "", active, false)?;
        let answer = convert::render(&template.afmt, model, note, &question, active, true)?;
        let front = converter.face(&question, &format!("Anki card {}", note.id), true)?;
        let back = converter.face(&answer, "", false)?;
        let did = if source.odid > 0 { source.odid } else { source.did };
        let source_deck =
            collection.decks.get(&did.to_string()).ok_or_else(|| CoreError::invalid("card references missing deck"))?;
        let attributes = json!({"anki": {"note_id": note.id.to_string(), "guid": note.guid,
            "notetype_id": note.mid.to_string(), "notetype_name": model.name, "card_id": source.id.to_string(),
            "ordinal": source.ord, "deck_id": did.to_string(), "deck_name": source_deck.name,
            "original_deck_id": source.odid.to_string(), "filtered_deck_id": source.did.to_string(), "package_sha256": hash}});
        let mut card = Card {
            content: None,
            id: new_id(),
            deck_id: deck.id.clone(),
            template: if model.kind == 1 { "cloze" } else { "basic" }.into(),
            language: deck.language.clone(),
            front,
            back,
            tags: note.tags.split_whitespace().map(str::to_string).collect::<BTreeSet<_>>().into_iter().collect(),
            attributes: attributes.as_object().unwrap().clone(),
            tts: None,
            bgm: None,
            ducking: Default::default(),
            visual: Default::default(),
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        validate_card(&card)?;
        // 旧规范化预算只计调用方内容；服务端发布及来源封套另计持久额度。
        let legacy_entry = memoswish_core::imports::input_value(&card)?;
        let legacy_bytes =
            memoswish_core::imports::input_json_bytes(&legacy_entry, ApkgLimits::NORMALIZED - normalized)
                .map_err(|_| CoreError::invalid("normalized APKG cards exceed 8 MiB"))?;
        normalized += legacy_bytes;
        card.content = Some(memoswish_protocol::ContentMetadata {
            observed_generation: None,
            publication: "published".into(),
            provenance: memoswish_protocol::ContentProvenance {
                method: "import".into(),
                source_id: Some(format!("anki:{}", source.id)),
                ..Default::default()
            },
        });
        let expanded_bytes = memoswish_core::imports::json_bytes(
            &card,
            legacy_bytes + memoswish_core::imports::IMPORT_PROVENANCE_BYTES_PER_CARD,
        )?;
        provenance_expansion_bytes += expanded_bytes - legacy_bytes;
        cards.push(card);
    }
    if used_notes.len() < collection.notes.len() {
        converter
            .warnings
            .push(format!("{} notes without source cards were omitted.", collection.notes.len() - used_notes.len()));
    }
    if !converter.uploads.is_empty() {
        p.require(Permission::MediaWrite)?;
    }
    let report = ApkgReport {
        deck,
        notes_read: collection.notes.len(),
        cards_imported: cards.len(),
        media_imported: converter.uploads.len(),
        audio_omitted: converter.audio.len(),
        warnings: converter.warnings.messages,
        warnings_truncated: converter.warnings.truncated,
    };
    Ok(PreparedApkg {
        tenant_id: p.tenant_id,
        cards,
        uploads: converter.uploads,
        report,
        provenance_expansion_bytes,
        _permit: permit,
        _slot: slot,
    })
}

/// JSON 传输复用现有解码依赖，在分配前约束 base64 包络。
pub fn decode_base64_request(encoded: &str) -> CoreResult<Vec<u8>> {
    use base64::Engine;
    if encoded.len() > ApkgLimits::ARCHIVE.div_ceil(3) * 4 {
        return Err(CoreError::invalid("APKG exceeds 10 MiB"));
    }
    base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|_| CoreError::invalid("invalid APKG base64"))
}

/// 开发工具直接调用同一解析器；不建立仓储、不执行 PUT 或持久提交。
#[cfg(feature = "fuzzing")]
pub async fn fuzz_prepare(bytes: &[u8]) -> CoreResult<()> {
    if bytes.len() > ApkgLimits::ARCHIVE {
        return Err(CoreError::invalid("APKG exceeds archive limit"));
    }
    let permit = IMPORTS.try_acquire().map_err(|_| CoreError::Unavailable("APKG capacity exhausted".into()))?;
    let budget = crate::processing::WorkBudget::default();
    let hash = sha256_hex(bytes);
    let package = budget.scope(|| archive::read(bytes.to_vec()))?;
    let collection = collection::read_budget(&package.database, budget.clone()).await?;
    budget.scope(|| {
        prepare(
            Principal::local_owner("fuzz"),
            ApkgOptions::default(),
            package.media,
            collection,
            hash,
            (
                permit,
                memoswish_core::observability::Slot::new(
                    memoswish_core::observability::noop(),
                    memoswish_core::observability::AdmissionClass::Import,
                ),
            ),
            Utc::now(),
        )
    })?;
    Ok(())
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_cloze(input: &str) -> CoreResult<(String, bool)> {
    crate::processing::WorkBudget::default().scope(|| convert::cloze(input, 1, false, 0))
}
