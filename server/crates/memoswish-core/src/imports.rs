//! 导入的持久输入、原始授权证据与原子提交端口。
use crate::{CoreError, CoreResult, Principal, assets::UploadAttempt, jobs::JobClaim};
use async_trait::async_trait;
use memoswish_protocol::{AssetRef, Card, Deck, DeckPack};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportCredential {
    pub token_hash: Option<String>,
    pub expires_at: Option<i64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportAuthority {
    pub principal: Principal,
    // Principal 的会话字段不参与通用序列化，持久工作显式保存原始摘要。
    pub session_hash: Option<String>,
    pub token_hash: Option<String>,
    pub expires_at: Option<i64>,
    // 用途证据不参与重试身份，撤回后不能替换原始受理修订。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<ImportPrivacy>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPrivacy {
    pub policy: memoswish_protocol::PrivacyPolicy,
    pub revision: i64,
}
impl ImportAuthority {
    pub fn capture(p: &Principal, credential: Option<ImportCredential>) -> Self {
        let credential = credential.unwrap_or_default();
        Self {
            principal: p.clone(),
            session_hash: p.session_access_hash.clone(),
            token_hash: credential.token_hash,
            expires_at: credential.expires_at,
            privacy: None,
        }
    }
    pub fn principal(&self) -> Principal {
        let mut p = self.principal.clone();
        p.session_access_hash = self.session_hash.clone();
        p
    }
    pub fn identity(&self) -> CoreResult<String> {
        let mut authority = self.clone();
        authority.privacy = None;
        serde_json::to_vec(&authority).map(|v| crate::ids::sha256_hex(&v)).map_err(CoreError::internal)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportMedia {
    pub asset: AssetRef,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportWork {
    pub deck: Deck,
    pub cards: Vec<Card>,
    pub media: Vec<ImportMedia>,
    pub result: serde_json::Value,
    pub auto_tts: bool,
    // 仅便携规范化记录实际身份扩展；旧持久工作与旧入口保持零额度。
    #[serde(default, skip_serializing_if = "is_zero")]
    pub identity_expansion_bytes: usize,
    // 来源规范化的实际增量单独计量，不占用调用方正文预算；旧持久工作默认为零。
    #[serde(default, skip_serializing_if = "is_zero")]
    pub provenance_expansion_bytes: usize,
}
fn is_zero(value: &usize) -> bool {
    *value == 0
}

pub const IMPORT_CONTENT_BYTES: usize = 8 * 1024 * 1024;
// 每卡最多两面各 32 张图及 visual/TTS/BGM；对象键上限为 512 字节。
// 新 UUID 最多三个，重置的两个时间戳每个最多 35 字节。
pub const PORTABLE_IDENTITY_BYTES_PER_CARD: usize =
    (2 * crate::content_validation::MAX_BLOCKS_PER_FACE + 3) * 512 + 3 * 36 + 2 * 35;
// 来源上限沿用既有 16 KiB；额外部分仅为服务端固定元数据封套。
pub const IMPORT_PROVENANCE_BYTES_PER_CARD: usize =
    16_384 + b",\"content\":{\"publication\":\"published\",\"provenance\":}".len();
pub const PORTABLE_SNAPSHOT_BYTES: usize =
    IMPORT_CONTENT_BYTES + 500 * (PORTABLE_IDENTITY_BYTES_PER_CARD + IMPORT_PROVENANCE_BYTES_PER_CARD) + 36 + 35;

/// 包内身份不携带数据库身份；最短表示避免导入重置字段挤占再次导出的正文预算。
/// 返回媒体键映射，供导出方同步改写已验证的媒体表；不得用它跳过源引用授权。
pub fn portable_export_content(content: &mut DeckPack) -> HashMap<String, String> {
    // JSON 中单字节且无需转义的全部字符；卡片与 BGM 身份允许空串。
    let alphabet: Vec<u8> = (b' '..=b'~').filter(|b| !b"\"\\".contains(b)).collect();
    let mut tracks = HashMap::new();
    let mut media = HashMap::new();
    for card in &content.cards {
        if let Some(bgm) = &card.bgm {
            *tracks.entry(bgm.track.id.clone()).or_insert(0usize) += 1;
        }
        for asset in crate::assets::card_assets(card) {
            *media.entry(asset.key.clone()).or_insert(0usize) += 1;
        }
    }
    let tracks = compact_ids(tracks, &alphabet, true);
    let media = compact_ids(media, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-", false);
    content.deck.id = if content.cards.is_empty() { String::new() } else { "d".into() };
    content.deck.created_at = chrono::DateTime::UNIX_EPOCH;
    content.exported_at = chrono::DateTime::UNIX_EPOCH;
    for (index, card) in content.cards.iter_mut().enumerate() {
        card.id = compact_id(index, &alphabet, true);
        card.deck_id = content.deck.id.clone();
        // 新封套保留观察到的源修订；目标导入仍从本地修订一开始。
        if content.version == "1.0" {
            card.revision = 1;
        }
        card.created_at = chrono::DateTime::UNIX_EPOCH;
        card.updated_at = chrono::DateTime::UNIX_EPOCH;
        if let Some(bgm) = &mut card.bgm {
            bgm.track.id = tracks[&bgm.track.id].clone();
        }
        for (_, asset) in crate::assets::card_asset_slots_mut(card) {
            asset.key = media[&asset.key].clone();
            asset.url.clear();
        }
    }
    media
}

fn compact_ids(counts: HashMap<String, usize>, alphabet: &[u8], empty: bool) -> HashMap<String, String> {
    let mut counts: Vec<_> = counts.into_iter().collect();
    // 高频身份优先使用短编码，保证重复引用的总字节数也不增长。
    counts.sort_by(|(a, ac), (b, bc)| bc.cmp(ac).then_with(|| a.cmp(b)));
    counts.into_iter().enumerate().map(|(index, (id, _))| (id, compact_id(index, alphabet, empty))).collect()
}

fn compact_id(mut index: usize, alphabet: &[u8], empty: bool) -> String {
    if empty {
        if index == 0 {
            return String::new();
        }
        index -= 1;
    }
    let mut id = Vec::new();
    loop {
        id.push(alphabet[index % alphabet.len()] as char);
        if index < alphabet.len() {
            break;
        }
        index = index / alphabet.len() - 1;
    }
    id.into_iter().rev().collect()
}

/// 精确计数且到上限即停止，避免为预算额外创建整包缓冲。
pub fn json_bytes(value: &impl Serialize, limit: usize) -> CoreResult<usize> {
    struct Budget {
        size: usize,
        limit: usize,
    }
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.size = self
                .size
                .checked_add(bytes.len())
                .filter(|n| *n <= self.limit)
                .ok_or_else(|| std::io::Error::other("JSON budget exceeded"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut budget = Budget { size: 0, limit };
    serde_json::to_writer(&mut budget, value).map_err(|_| CoreError::invalid("JSON exceeds byte budget"))?;
    Ok(budget.size)
}

/// 调用方预算只计原始线 JSON 值；必须在解码、补默认值和添加服务端字段之前调用。
/// 非 JSON 导入的解码器在生成来源元数据前提供原始规范化条目。
pub fn input_json_bytes(value: &serde_json::Value, limit: usize) -> CoreResult<usize> {
    json_bytes(value, limit)
}

/// 进程内类型化调用先形成真实 JSON 线值，避免 to_value 将 f32 提升成更长的 f64 表示。
/// 传输调用传入原始 Value；此处不会添加模型默认字段。
pub fn input_value(value: &impl Serialize) -> CoreResult<serde_json::Value> {
    let bytes = serde_json::to_vec(value).map_err(CoreError::internal)?;
    serde_json::from_slice(&bytes).map_err(CoreError::internal)
}

/// 传输适配器共用的先计量后解码入口，不能传入已经解码的当前模型。
pub fn decode_input<T: serde::de::DeserializeOwned>(value: serde_json::Value, limit: usize) -> CoreResult<T> {
    input_json_bytes(&value, limit)?;
    serde_json::from_value(value).map_err(|_| CoreError::invalid("invalid input JSON"))
}

impl ImportWork {
    /// 扩展额度分别覆盖实际新身份与来源增量，不能增加调用方正文预算。
    pub fn cards_byte_limit(&self) -> CoreResult<usize> {
        let maximum: usize = self
            .cards
            .iter()
            .map(|card| crate::assets::card_assets(card).iter().map(|a| a.key.len()).sum::<usize>() + 3 * 36 + 2 * 35)
            .sum();
        if self.identity_expansion_bytes > maximum {
            return Err(CoreError::invalid("invalid import identity expansion budget"));
        }
        let mut provenance_maximum = 0;
        for card in &self.cards {
            if let Some(metadata) = &card.content {
                crate::content_lifecycle::validate_provenance(&metadata.provenance)?;
                // 目标发布选择可以缩短封套，不能使规范化时已记录的额度失效。
                provenance_maximum +=
                    json_bytes(&metadata.provenance, 16_384)? + (IMPORT_PROVENANCE_BYTES_PER_CARD - 16_384);
            }
        }
        if self.provenance_expansion_bytes > provenance_maximum {
            return Err(CoreError::invalid("invalid import provenance expansion budget"));
        }
        Ok(IMPORT_CONTENT_BYTES + self.identity_expansion_bytes + self.provenance_expansion_bytes)
    }
}
#[derive(Debug, Clone)]
pub struct ImportOperation {
    pub id: String,
    pub outcome: String,
    pub result: Option<serde_json::Value>,
}
#[derive(Debug, Clone)]
pub struct ImportExecution {
    pub authority: ImportAuthority,
    pub work: ImportWork,
}
pub struct ImportFollowup {
    pub authority: ImportAuthority,
    pub card_id: String,
    pub revision: u32,
}
/// 维护发现仅返回持久任务身份；业务读写必须显式带租户。
#[async_trait]
pub trait ImportRepo: Send + Sync {
    /// 同一短事务获取有界内容快照；不在对象 IO 期间持有事务。
    async fn portable_snapshot(
        &self,
        authority: &ImportAuthority,
        deck_id: &str,
    ) -> CoreResult<memoswish_protocol::DeckPack>;
    /// 释放导出前复核原始凭据和当前内容读取权限，包含无媒体的包。
    async fn revalidate_portable_export(&self, authority: &ImportAuthority) -> CoreResult<()>;

    async fn accept_import(
        &self,
        authority: &ImportAuthority,
        key: &str,
        fingerprint: &str,
        work: &ImportWork,
        limit: Option<i64>,
        staging_limit: i64,
    ) -> CoreResult<ImportOperation>;
    async fn lookup_import(
        &self,
        authority: &ImportAuthority,
        key: &str,
        fingerprint: &str,
    ) -> CoreResult<Option<ImportOperation>>;
    /// 状态只读取身份和处置，不加载暂存输入或完整回执。
    async fn import_status(&self, authority: &ImportAuthority, key: &str) -> CoreResult<Option<ImportOperation>>;
    async fn import_operation(&self, tenant_id: &str, id: &str) -> CoreResult<ImportOperation>;
    async fn claim_import(&self, tenant_id: &str, id: &str, lease_ms: i64) -> CoreResult<Option<JobClaim>>;
    async fn heartbeat_import(&self, tenant_id: &str, claim: &JobClaim, lease_ms: i64) -> CoreResult<()>;
    async fn import_execution(&self, tenant_id: &str, claim: &JobClaim) -> CoreResult<ImportExecution>;
    async fn begin_import_upload(
        &self,
        tenant_id: &str,
        claim: &JobClaim,
        ordinal: i64,
        store_id: &str,
    ) -> CoreResult<UploadAttempt>;
    async fn select_import_upload(
        &self,
        tenant_id: &str,
        claim: &JobClaim,
        ordinal: i64,
        attempt_id: &str,
    ) -> CoreResult<()>;
    async fn commit_import(&self, tenant_id: &str, claim: &JobClaim) -> CoreResult<ImportOperation>;
    async fn retry_import(&self, tenant_id: &str, claim: &JobClaim) -> CoreResult<()>;
    async fn fail_import(&self, tenant_id: &str, claim: &JobClaim) -> CoreResult<()>;
    async fn pending_imports(&self, after: Option<(&str, &str)>) -> CoreResult<Vec<(String, String)>>;
    async fn import_cleanup(&self, tenant_id: &str, id: &str, store_id: &str) -> CoreResult<Vec<UploadAttempt>>;
    async fn retry_import_cleanup(&self, tenant_id: &str, id: &str, attempt: &UploadAttempt) -> CoreResult<()>;
    async fn import_followup(&self, tenant_id: &str, id: &str, card_id: &str, outcome: &str) -> CoreResult<bool>;
    async fn import_followups(&self, tenant_id: &str, id: &str) -> CoreResult<Vec<ImportFollowup>>;
    async fn held_import_usage(&self, tenant_id: &str, period: &str) -> CoreResult<i64>;
}
pub fn validate_request_id(key: &str) -> CoreResult<()> {
    if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(CoreError::invalid("import request identity must be 1..=128 printable ASCII bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod portable_tests {
    use super::*;

    #[test]
    fn legacy_persisted_import_work_retains_canonical_bytes() {
        let pack: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../compatibility/history/2.13.0/protocol/fixtures/deck-pack.json"
        ))
        .unwrap();
        let raw = serde_json::json!({
            "deck":pack["deck"], "cards":pack["cards"], "media":[],
            "result":pack["deck"], "auto_tts":false
        });
        let work: ImportWork = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(work.deck.revision, None);
        assert_eq!(work.provenance_expansion_bytes, 0);
        assert_eq!(
            serde_json::to_vec(&serde_json::to_value(work).unwrap()).unwrap(),
            serde_json::to_vec(&raw).unwrap()
        );
    }

    #[test]
    fn portable_compact_ids_cover_full_domain_and_prioritize_repeated_references() {
        let alphabet: Vec<_> = (b' '..=b'~').filter(|b| !b"\"\\".contains(b)).collect();
        let ids: std::collections::HashSet<_> = (0..500).map(|i| compact_id(i, &alphabet, true)).collect();
        assert_eq!(ids.len(), 500);
        assert!(ids.contains(""));
        assert_eq!(ids.iter().filter(|id| id.len() == 1).count(), 93);
        assert!(ids.iter().all(|id| serde_json::to_string(id).unwrap().len() == id.len() + 2));
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
        let counts = (0..4096).map(|i| (format!("source{i}"), if i == 4095 { 32_000 } else { 1 })).collect();
        let mapped = compact_ids(counts, alphabet, false);
        assert_eq!(mapped["source4095"].len(), 1);
        assert_eq!(mapped.values().collect::<std::collections::HashSet<_>>().len(), 4096);
        for id in mapped.values() {
            crate::assets::validate_asset_id(id).unwrap();
        }
    }

    #[test]
    fn portable_compaction_never_grows_minimal_source_identities_or_timestamps() {
        let mut pack = memoswish_protocol::examples::sample_deck_pack();
        pack.deck.id = "d".into();
        pack.deck.created_at = chrono::DateTime::UNIX_EPOCH;
        pack.exported_at = chrono::DateTime::UNIX_EPOCH;
        let card = pack.cards[0].clone();
        // 跨越一字节身份容量，包含大量共享媒体及 BGM 绑定。
        pack.cards = (0..500)
            .map(|i| {
                let mut c = card.clone();
                c.id = if i == 0 { String::new() } else { format!("{i}") };
                c.deck_id = "d".into();
                c.created_at = chrono::DateTime::UNIX_EPOCH;
                c.updated_at = chrono::DateTime::UNIX_EPOCH;
                c.bgm.as_mut().unwrap().track.id = if i > 100 { String::new() } else { format!("{i}") };
                for (_, asset) in crate::assets::card_asset_slots_mut(&mut c) {
                    asset.key = if i > 100 { "a".into() } else { format!("{i}") };
                    asset.url.clear();
                }
                c
            })
            .collect();
        pack.deck.card_count = 500;
        let before = json_bytes(&pack, IMPORT_CONTENT_BYTES).unwrap();
        portable_export_content(&mut pack);
        assert!(json_bytes(&pack, before).is_ok());
        assert_eq!(pack.cards[101].bgm.as_ref().unwrap().track.id, "");
        assert_eq!(pack.cards[101].bgm.as_ref().unwrap().track.id, pack.cards[499].bgm.as_ref().unwrap().track.id);
        for c in &pack.cards {
            crate::content_validation::validate_card(c).unwrap();
            assert_eq!(c.deck_id, pack.deck.id);
        }
        let compact = json_bytes(&pack, before).unwrap();
        portable_export_content(&mut pack);
        assert_eq!(json_bytes(&pack, before).unwrap(), compact);
        pack.version = "1.1".into();
        pack.cards[0].revision = 7;
        portable_export_content(&mut pack);
        assert_eq!(pack.cards[0].revision, 7);
    }

    #[test]
    fn portable_empty_deck_also_fits_exact_content_budget() {
        let mut pack = memoswish_protocol::examples::sample_deck_pack();
        pack.cards.clear();
        pack.deck.card_count = 0;
        pack.deck.id.clear();
        pack.deck.created_at = chrono::DateTime::UNIX_EPOCH;
        pack.exported_at = chrono::DateTime::UNIX_EPOCH;
        pack.deck.description.clear();
        let base = json_bytes(&pack, IMPORT_CONTENT_BYTES).unwrap();
        pack.deck.description = "x".repeat(IMPORT_CONTENT_BYTES - base);
        portable_export_content(&mut pack);
        assert_eq!(json_bytes(&pack, IMPORT_CONTENT_BYTES).unwrap(), IMPORT_CONTENT_BYTES);
    }
}
